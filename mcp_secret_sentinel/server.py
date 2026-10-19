"""mcp-secret-sentinel — MCP entry point.

Wiring only: every tool delegates to core.py / agents.py, which are pure
stdlib and unit-tested without the mcp package installed.

Works with both majors of the official Python SDK:

* mcp 2.x — ``mcp.server.mcpserver.MCPServer`` (FastMCP was renamed)
* mcp 1.x — ``mcp.server.fastmcp.FastMCP``

Scan tools declare typed results (TypedDicts), so SDKs that support
structured output publish an ``outputSchema`` and return
``structuredContent`` next to the JSON text.

Run over stdio:  mcp-secret-sentinel  (or python -m mcp_secret_sentinel.server)
"""

# No "from __future__ import annotations" here: mcp 1.x before 1.9 inspects
# tool annotations with issubclass() and breaks on string annotations.
import json
from typing import Any, Callable, Dict, List, Optional

# pydantic only accepts typing_extensions' TypedDict below Python 3.12; it is
# installed with mcp (through pydantic).
from typing_extensions import Literal, NotRequired, TypedDict

try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _ServerClass
    from mcp.server.mcpserver.exceptions import ToolError

    SDK_MAJOR = 2
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _ServerClass
    from mcp.server.fastmcp.exceptions import ToolError

    SDK_MAJOR = 1

from mcp.types import ToolAnnotations

from . import __version__, agents, core
from .config import discover

INSTRUCTIONS = (
    "Secret Sentinel scans code for exposed credentials and never returns a "
    "secret in full: every finding is redacted. Run scan_git_staged before "
    "every commit and scan_git_range before every push, and scan any snippet "
    "with scan_text before writing it to a file. Use redact_text before "
    "quoting logs, configs or command output that may hold credentials, and "
    "scan_agent_configs to audit MCP client configs for pasted API keys. When "
    "a finding is reported, remove the literal and load it from the "
    "environment instead, and tell the user to rotate the credential if it "
    "was ever committed or shared."
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


# ---------------------------------------------------------------------------
# Result types (published as outputSchema)
#
# Optional keys are NotRequired *and* nullable: mcp 2.x leaves an absent key
# absent, while mcp 1.x turns a TypedDict into a model whose absent keys
# serialize as null, which a non-nullable schema would reject client-side.
# ---------------------------------------------------------------------------


class Finding(TypedDict):
    file: str
    line: int
    pattern: str
    severity: Literal["critical", "high", "medium"]
    redacted: str
    advice: str
    commit: NotRequired[Optional[str]]


class FileCount(TypedDict):
    file: str
    findings: int


class ScanReport(TypedDict):
    clean: bool
    findings: List[Finding]
    files_scanned: int
    summary: str
    suppressed: NotRequired[Optional[int]]
    baselined: NotRequired[Optional[int]]
    truncated: NotRequired[Optional[bool]]
    total_findings: NotRequired[Optional[int]]
    counts_by_severity: NotRequired[Optional[Dict[str, int]]]
    counts_by_pattern: NotRequired[Optional[Dict[str, int]]]
    top_files: NotRequired[Optional[List[FileCount]]]


class RangeReport(ScanReport):
    commits_scanned: int
    range: str


class AgentFile(TypedDict):
    client: str
    scope: Literal["project", "user", "transcript"]
    path: str
    findings: int
    tracked_by_git: NotRequired[Optional[bool]]
    hint: NotRequired[Optional[str]]


class AgentReport(ScanReport):
    agent_files: List[AgentFile]


class Redaction(TypedDict):
    text: str
    redactions: int
    by_pattern: Dict[str, int]


def _call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run a core function, turning its ValueErrors into MCP tool errors.

    core.py raises ValueError with an actionable message (missing path, not
    a git repository, a broken config file...). mcp 2.x hides the text of
    unexpected exceptions from the client, so it must be re-raised as a
    ToolError to reach the agent as an ``isError`` result it can act on.
    """
    try:
        return fn(*args, **kwargs)
    except ValueError as exc:
        raise ToolError(str(exc)) from None


def _config_for(path: str) -> core.ScanConfig:
    """The project's .secret-sentinel.toml / baseline for a scanned path."""
    return _call(discover, path)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool(annotations=_READ_ONLY)
def scan_text(
    text: str, source_name: str = "input", max_findings: int = core.DEFAULT_MAX_FINDINGS
) -> ScanReport:
    """Scan a snippet of text or code for exposed secrets.

    64 detectors: GitHub/GitLab/npm/PyPI tokens; OpenAI, Anthropic, xAI,
    DeepSeek, Perplexity, OpenRouter, Groq, NVIDIA, Hugging Face, Replicate,
    Together, Cerebras, LangSmith, Langfuse, Pinecone, Firecrawl and Tavily
    keys; AWS (incl. Bedrock), Azure, Google, DigitalOcean, Cloudflare,
    Vercel, Supabase, Neon, PlanetScale, Fly.io, Databricks, Vault and
    Doppler credentials; Stripe, Square, Shopify, SendGrid, Resend,
    Mailchimp, Twilio, Slack, Discord, Telegram, Linear, Notion, Atlassian,
    Postman, Sentry, Grafana and PostHog tokens; JWTs, private and age keys,
    credentialed connection strings and URLs, generic password/secret/token
    assignments, plus high-entropy strings. Placeholders ($VAR, ${VAR},
    {{ templates }}, changeme, masked values...) are skipped, and a line
    carrying "secret-sentinel: ignore", "pragma: allowlist secret" or
    "gitleaks:allow" is counted in "suppressed" instead of reported.

    Args:
        text: The raw text to scan (code, config, diff output, logs...).
        source_name: Label used in each finding's "file" field.
        max_findings: List at most this many findings, most severe first
            (default 200, 0 = no limit). When capped, the result adds
            truncated, total_findings, counts_by_severity, counts_by_pattern
            and top_files.

    Returns:
        {"clean", "findings": [{"file", "line", "pattern", "severity",
        "redacted", "advice"}], "files_scanned", "summary"}. Secret values
        are ALWAYS redacted (at most 4 chars, never more than a quarter of
        the value, + length); the full value is never included.
    """
    return _call(core.scan_text, text, source_name, max_findings)


@mcp.tool(annotations=_READ_ONLY)
def redact_text(text: str) -> Redaction:
    """Return the text with every detected secret replaced by [REDACTED:<detector>].

    Use it before quoting logs, stack traces, configs, command output or
    diffs that may contain credentials, in the conversation, an issue, a
    commit message or a document. Everything that is not a secret is kept
    exactly as it was.

    Args:
        text: The text to clean.

    Returns:
        {"text": the redacted text, "redactions": how many secrets were
        replaced, "by_pattern": {detector name: count}}
    """
    return _call(core.redact_text, text)


@mcp.tool(annotations=_READ_ONLY)
def scan_file(path: str, max_findings: int = core.DEFAULT_MAX_FINDINGS) -> ScanReport:
    """Scan a single file for exposed secrets.

    UTF-8, UTF-16 and UTF-32 text is decoded by byte-order mark. Binary files
    (null-byte heuristic) and files larger than 5 MB are skipped and reported
    as such in the summary. The project's .secret-sentinel.toml and baseline
    apply.

    Args:
        path: Absolute path to the file to scan.
        max_findings: List at most this many findings, most severe first
            (default 200, 0 = no limit).

    Returns:
        The standard redacted findings report (see scan_text). Returns an
        error result if the file does not exist.
    """
    return _call(core.scan_file, path, max_findings, _config_for(path))


@mcp.tool(annotations=_READ_ONLY)
def scan_directory(
    path: str, max_files: int = 500, max_findings: int = core.DEFAULT_MAX_FINDINGS
) -> ScanReport:
    """Recursively scan a directory tree for exposed secrets.

    Inside a git repository the file list comes from git (tracked files plus
    untracked files no .gitignore excludes), so every ignore rule is
    honoured. Always skips .git, node_modules, virtualenvs, caches, dist,
    build, minified bundles, lockfiles, binaries, files over 5 MB and the
    paths the project's .secret-sentinel.toml excludes.

    Args:
        path: Absolute path to the directory to scan.
        max_files: Stop after scanning this many files (default 500).
        max_findings: List at most this many findings, most severe first
            (default 200, 0 = no limit).

    Returns:
        The standard redacted findings report; finding paths are relative to
        the scanned root, using forward slashes.
    """
    return _call(core.scan_directory, path, max_files, max_findings, _config_for(path))


@mcp.tool(annotations=_READ_ONLY)
def scan_git_staged(repo_path: str, max_findings: int = core.DEFAULT_MAX_FINDINGS) -> ScanReport:
    """Scan ONLY the lines currently staged for commit (git diff --cached).

    This is the pre-commit checkpoint: it inspects exactly the content the
    next commit would publish, and reports the file and post-commit line
    number of every added secret. Local diff settings (external diff tools,
    textconv filters, prefixes, path quoting) are overridden, and git runs
    no configured programs.

    Args:
        repo_path: Absolute path to a git repository (or any path inside one).
        max_findings: List at most this many findings, most severe first
            (default 200, 0 = no limit).

    Returns:
        The standard redacted findings report. If nothing is staged the result
        is clean with an explanatory summary.
    """
    return _call(core.scan_git_staged, repo_path, max_findings, _config_for(repo_path))


@mcp.tool(annotations=_READ_ONLY)
def scan_git_history(
    repo_path: str,
    max_commits: int = 50,
    all_branches: bool = False,
    max_findings: int = core.DEFAULT_MAX_FINDINGS,
) -> ScanReport:
    """Scan the lines added by the most recent commits (git log -p).

    Each finding is tagged with the short hash of the commit that introduced
    it. A secret that was later deleted is still reported — history retains
    it, so the credential must be rotated regardless.

    Args:
        repo_path: Absolute path to a git repository (or any path inside one).
        max_commits: How many commits back to inspect (default 50).
        all_branches: Walk every branch, tag and the stash instead of only
            the history of HEAD (default false).
        max_findings: List at most this many findings, most severe first
            (default 200, 0 = no limit).

    Returns:
        The standard redacted findings report, with a "commit" field on each
        finding.
    """
    return _call(
        core.scan_git_history, repo_path, max_commits, all_branches, max_findings, _config_for(repo_path)
    )


@mcp.tool(annotations=_READ_ONLY)
def scan_git_range(
    repo_path: str,
    base: str = "@{upstream}",
    head: str = "HEAD",
    max_commits: int = 200,
    max_findings: int = core.DEFAULT_MAX_FINDINGS,
) -> RangeReport:
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
        max_findings: List at most this many findings, most severe first
            (default 200, 0 = no limit).

    Returns:
        The standard redacted findings report with a "commit" field on each
        finding, plus "commits_scanned" and "range".
    """
    return _call(
        core.scan_git_range, repo_path, base, head, max_commits, max_findings, _config_for(repo_path)
    )


@mcp.tool(annotations=_READ_ONLY)
def scan_agent_configs(
    project_path: Optional[str] = None,
    include_user: bool = True,
    include_transcripts: bool = False,
    max_findings: int = core.DEFAULT_MAX_FINDINGS,
) -> AgentReport:
    """Audit AI agent and MCP client configuration files for hardcoded secrets.

    Checks the project's .mcp.json, .claude/settings*.json, .cursor/mcp.json,
    .vscode/mcp.json, .gemini/, .codex/ and other client configs, plus agent
    instruction files (CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules...),
    and the user-level configs of Claude Code, Claude Desktop, Cursor,
    VS Code, Cline, Windsurf, Gemini CLI, Codex, Kiro, Continue, Zed and
    others. Project files report whether git tracks them: a key in a
    tracked .mcp.json ships with the repository.

    Args:
        project_path: Absolute path to the project to audit (optional).
        include_user: Also scan configs in the user's home folder (default true).
        include_transcripts: Also scan the newest Claude Code / Codex session
            transcripts (default false; slower).
        max_findings: List at most this many findings, most severe first.

    Returns:
        The standard redacted report plus "agent_files": [{"client", "scope",
        "path", "findings", "tracked_by_git", "hint"}] for every file found.
    """
    return _call(
        agents.scan_agent_configs, project_path, include_user, include_transcripts, max_findings
    )


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


# ---------------------------------------------------------------------------
# Resources and prompts
# ---------------------------------------------------------------------------


@mcp.resource(
    "secret-sentinel://patterns",
    name="detectors",
    description="Every detector with its severity and remediation advice, plus the allowlist rules.",
    mime_type="application/json",
)
def patterns_resource() -> str:
    return json.dumps(core.list_patterns(), indent=2)


@mcp.prompt()
def pre_push_check(repo_path: str) -> str:
    """Check that nothing secret is about to be committed or pushed."""
    return (
        f"Before I commit and push in {repo_path}, check for exposed secrets with the "
        "secret-sentinel tools: run scan_git_staged, then scan_git_range (if the branch has "
        "no upstream, use base='origin/main' or the branch I will push to). For each finding, "
        "say where it is, what kind of credential it is and how to fix it: replace the "
        "literal with an environment variable, and rotate it if it is already in a commit. "
        "Finish with a clear verdict: safe to push, or not."
    )


@mcp.prompt()
def leak_response(what_leaked: str = "a credential", where: str = "a commit") -> str:
    """Walk through the response to a leaked secret, step by step."""
    return (
        f"{what_leaked} was exposed in {where}. Guide me through the response in this order, "
        "one step at a time, and wait for me to confirm each one:\n"
        "1. Rotate or revoke the credential at the provider first (the findings' advice says "
        "where). Removing it from the code does not make it safe: history and forks keep it.\n"
        "2. Check the provider's audit or usage logs for activity since the exposure.\n"
        "3. Replace the literal in the code with an environment variable or secrets manager "
        "lookup, and keep real values in an untracked .env file listed in .gitignore.\n"
        "4. If it was committed: decide with me whether to rewrite history (git filter-repo "
        "--replace-text) and force-push, knowing clones and forks may still have it.\n"
        "5. Prevent a repeat: install the pre-commit hook (mcp-secret-sentinel install-hook) "
        "and the agent hooks (mcp-secret-sentinel install-agent-hooks).\n"
        "Use scan_git_history on the repository to confirm what else may have leaked."
    )


@mcp.prompt()
def audit_agent_configs(project_path: str) -> str:
    """Audit this project's and this machine's AI agent configs for pasted API keys."""
    return (
        f"Run scan_agent_configs with project_path='{project_path}'. List every file with "
        "findings, flag the ones tracked by git first (they ship with the repository), and "
        "for each one show how to reference the secret from the environment instead of "
        "pasting it, using the hint in the result. Do not print any secret value."
    )


def main() -> None:
    """Serve the tools over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
