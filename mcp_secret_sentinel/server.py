"""mcp-secret-sentinel — MCP entry point.

Wiring only: every tool delegates to core.py, which is pure stdlib and
unit-tested without the mcp package installed.

Works with both majors of the official Python SDK:

* mcp 2.x — ``mcp.server.mcpserver.MCPServer`` (FastMCP was renamed)
* mcp 1.x — ``mcp.server.fastmcp.FastMCP``

Run over stdio:  mcp-secret-sentinel  (or python -m mcp_secret_sentinel.server)
"""

# No "from __future__ import annotations" here: mcp 1.x before 1.9 inspects
# tool annotations with issubclass() and breaks on string annotations.
from typing import Any, Callable

try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _ServerClass
    from mcp.server.mcpserver.exceptions import ToolError

    SDK_MAJOR = 2
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _ServerClass
    from mcp.server.fastmcp.exceptions import ToolError

    SDK_MAJOR = 1

from mcp.types import ToolAnnotations

from . import __version__, core

INSTRUCTIONS = (
    "Secret Sentinel scans code for exposed credentials and never returns a "
    "secret in full: every finding is redacted. Run scan_git_staged before "
    "every commit and scan_git_range before every push, and scan any snippet "
    "with scan_text before writing it to a file. When a finding is reported, remove the literal and load it from "
    "the environment instead, and tell the user to rotate the credential if "
    "it was ever committed or shared."
)

# mcp 2.x reports our version in serverInfo; 1.x has no such argument and
# reports the SDK version instead.
_VERSION_KWARGS = {"version": __version__} if SDK_MAJOR >= 2 else {}

mcp = _ServerClass("mcp-secret-sentinel", instructions=INSTRUCTIONS, **_VERSION_KWARGS)

# Every tool only reads files or git objects: nothing is written, nothing
# leaves the machine. Clients use these hints to skip confirmation prompts.
_READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


def _call(fn: Callable[..., dict], *args: Any) -> dict:
    """Run a core function, turning its ValueErrors into MCP tool errors.

    core.py raises ValueError with an actionable message (missing path, not
    a git repository...). mcp 2.x hides the text of unexpected exceptions
    from the client, so it must be re-raised as a ToolError to reach the
    agent as an ``isError`` result it can act on.
    """
    try:
        return fn(*args)
    except ValueError as exc:
        raise ToolError(str(exc)) from None


@mcp.tool(annotations=_READ_ONLY)
def scan_text(text: str, source_name: str = "input") -> dict:
    """Scan a snippet of text or code for exposed secrets.

    Detects API keys (GitHub, OpenAI, Anthropic, NVIDIA, AWS, Stripe, Google,
    Twilio), Slack/Discord tokens and webhooks, JWTs, private key blocks,
    credentialed connection strings, generic password/secret/token
    assignments, and high-entropy strings — while skipping obvious
    placeholders (allowlist).

    Args:
        text: The raw text to scan (code, config, diff output, logs...).
        source_name: Label used in each finding's "file" field.

    Returns:
        {"clean": bool,
         "findings": [{"file", "line", "pattern", "severity", "redacted", "advice"}],
         "files_scanned": int, "summary": str}
        Secret values are ALWAYS redacted (first 4 chars + length); the full
        value is never included in the output.
    """
    return _call(core.scan_text, text, source_name)


@mcp.tool(annotations=_READ_ONLY)
def scan_file(path: str) -> dict:
    """Scan a single file for exposed secrets.

    Binary files (null-byte heuristic) and files larger than 5 MB are skipped
    and reported as such in the summary.

    Args:
        path: Absolute path to the file to scan.

    Returns:
        The standard redacted findings report (see scan_text). Returns an
        error result if the file does not exist.
    """
    return _call(core.scan_file, path)


@mcp.tool(annotations=_READ_ONLY)
def scan_directory(path: str, max_files: int = 500) -> dict:
    """Recursively scan a directory tree for exposed secrets.

    Automatically skips .git, node_modules, .venv/venv, __pycache__, dist,
    build, minified JS bundles, lockfiles, binaries, files over 5 MB, and
    simple patterns from the root .gitignore (best-effort: no negations, no
    ** globs).

    Args:
        path: Absolute path to the directory to scan.
        max_files: Stop after scanning this many files (default 500).

    Returns:
        The standard redacted findings report; finding paths are relative to
        the scanned root, using forward slashes.
    """
    return _call(core.scan_directory, path, max_files)


@mcp.tool(annotations=_READ_ONLY)
def scan_git_staged(repo_path: str) -> dict:
    """Scan ONLY the lines currently staged for commit (git diff --cached).

    This is the pre-commit checkpoint: it inspects exactly the content the
    next commit would publish, and reports the file and post-commit line
    number of every added secret. Local diff settings (external diff tools,
    textconv filters, prefixes, path quoting) are overridden, and git runs
    no configured programs.

    Args:
        repo_path: Absolute path to a git repository (or any path inside one).

    Returns:
        The standard redacted findings report. If nothing is staged the result
        is clean with an explanatory summary.
    """
    return _call(core.scan_git_staged, repo_path)


@mcp.tool(annotations=_READ_ONLY)
def scan_git_history(repo_path: str, max_commits: int = 50, all_branches: bool = False) -> dict:
    """Scan the lines added by the most recent commits (git log -p).

    Each finding is tagged with the short hash of the commit that introduced
    it. A secret that was later deleted is still reported — history retains
    it, so the credential must be rotated regardless.

    Args:
        repo_path: Absolute path to a git repository (or any path inside one).
        max_commits: How many commits back to inspect (default 50).
        all_branches: Walk every branch, tag and the stash instead of only
            the history of HEAD (default false).

    Returns:
        The standard redacted findings report, with a "commit" field on each
        finding.
    """
    return _call(core.scan_git_history, repo_path, max_commits, all_branches)


@mcp.tool(annotations=_READ_ONLY)
def scan_git_range(
    repo_path: str,
    base: str = "@{upstream}",
    head: str = "HEAD",
    max_commits: int = 200,
) -> dict:
    """Scan the commits in base..head: by default, what `git push` would send.

    Run this before pushing. With the defaults it scans every commit on the
    current branch that its upstream does not have yet. If the branch has no
    upstream, the error says so: pass the branch you will push to as base
    (for example "origin/main").

    Args:
        repo_path: Absolute path to a git repository (or any path inside one).
        base: Commits reachable from here are excluded (default "@{upstream}").
        head: Last commit to include (default "HEAD").
        max_commits: Scan at most this many of the newest commits in the range.

    Returns:
        The standard redacted findings report with a "commit" field on each
        finding, plus "commits_scanned" and "range".
    """
    return _call(core.scan_git_range, repo_path, base, head, max_commits)


@mcp.tool(annotations=_READ_ONLY)
def list_patterns() -> dict:
    """List the active secret detectors and allowlist rules.

    Returns:
        {"count": int,
         "patterns": [{"name", "severity", "advice"}],
         "entropy_detector": {...threshold and advice...},
         "allowlist_rules": [{"name", "description"}]}
        Raw regexes are intentionally not exposed.
    """
    return core.list_patterns()


def main() -> None:
    """Serve the tools over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
