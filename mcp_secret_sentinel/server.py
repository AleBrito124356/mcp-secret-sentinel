"""mcp-secret-sentinel — FastMCP entry point.

Wiring only: every tool delegates to core.py, which is pure stdlib and
unit-tested without the mcp package installed.

Run over stdio:  mcp-secret-sentinel  (or python -m mcp_secret_sentinel.server)
"""

from mcp.server.fastmcp import FastMCP

from . import core

mcp = FastMCP("mcp-secret-sentinel")


@mcp.tool()
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
    return core.scan_text(text, source_name)


@mcp.tool()
def scan_file(path: str) -> dict:
    """Scan a single file for exposed secrets.

    Binary files (null-byte heuristic) and files larger than 5 MB are skipped
    and reported as such in the summary.

    Args:
        path: Absolute path to the file to scan.

    Returns:
        The standard redacted findings report (see scan_text). Raises an error
        if the file does not exist.
    """
    return core.scan_file(path)


@mcp.tool()
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
    return core.scan_directory(path, max_files)


@mcp.tool()
def scan_git_staged(repo_path: str) -> dict:
    """Scan ONLY the lines currently staged for commit (git diff --cached).

    This is the pre-commit checkpoint: it inspects exactly the content the
    next commit would publish, and reports the file and post-commit line
    number of every added secret.

    Args:
        repo_path: Absolute path to a git repository (or any path inside one).

    Returns:
        The standard redacted findings report. If nothing is staged the result
        is clean with an explanatory summary.
    """
    return core.scan_git_staged(repo_path)


@mcp.tool()
def scan_git_history(repo_path: str, max_commits: int = 50) -> dict:
    """Scan the lines added by the most recent commits (git log -p).

    Each finding is tagged with the short hash of the commit that introduced
    it. A secret that was later deleted is still reported — history retains
    it, so the credential must be rotated regardless.

    Args:
        repo_path: Absolute path to a git repository (or any path inside one).
        max_commits: How many commits back to inspect (default 50).

    Returns:
        The standard redacted findings report, with a "commit" field on each
        finding.
    """
    return core.scan_git_history(repo_path, max_commits)


@mcp.tool()
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
    """Entry point for the console script."""
    mcp.run()


if __name__ == "__main__":
    main()
