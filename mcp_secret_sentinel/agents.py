"""Find and scan the files AI coding agents and MCP clients keep secrets in.

MCP client configs hold an ``env`` block per server, and that is where API
keys get pasted: Claude Code (``.mcp.json``, ``~/.claude.json``), Claude
Desktop, Cursor, VS Code, Windsurf, Gemini CLI, Codex and others. Project
files such as ``.mcp.json`` are meant to be committed, so a literal key there
is one ``git push`` away from public. Agent instruction files (CLAUDE.md,
AGENTS.md...) are committed too and are read into every session. Session
transcripts are local, but whatever they contain was also sent to the model.

Everything here only reads files; findings are redacted like any scan.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from . import core

# Transcripts are append-only logs that grow past the normal 5 MB cap.
TRANSCRIPT_MAX_BYTES = 50 * 1024 * 1024
TRANSCRIPT_MAX_FILES = 200

_HINT_ENV_EXPANSION = (
    "Claude Code expands ${VAR} (and ${VAR:-default}) in .mcp.json: write "
    '"env": {"API_KEY": "${API_KEY}"} and export the value in your shell.'
)
_HINT_VSCODE = (
    'VS Code can prompt for the value once and store it securely: declare it under "inputs" '
    'and reference it as "${input:<id>}", or point "envFile" at an untracked .env file.'
)
_HINT_CURSOR = (
    'Reference the shell environment with "${env:API_KEY}" or load an untracked file with '
    '"envFile", instead of a literal value.'
)
_HINT_DESKTOP = (
    "This file is not committed, but any agent or extension that can read your home folder "
    "can read it, and dotfile backups copy it. Prefer a launcher or desktop extension that "
    "reads the key from the OS keychain or the environment."
)
_HINT_USER = (
    "User-level config: not in a repository, but readable by every tool running as you and "
    "copied by dotfile syncs. Keep the key in the environment or a secrets manager and "
    "reference it from the config."
)
_HINT_INSTRUCTIONS = (
    "Agent instruction files are committed and loaded into every session: never put "
    "credentials in them. Describe where the secret lives (an environment variable) instead."
)
_HINT_TRANSCRIPT = (
    "Session transcripts are local files, but this value was also sent to the model "
    "provider when the session ran. Rotate the credential and delete the transcript."
)


@dataclass(frozen=True)
class AgentFile:
    client: str
    scope: str  # "project" | "user" | "transcript"
    path: Path
    hint: str


def _app_data(home: Path, env: dict[str, str], platform: str) -> Path:
    """The per-user application config directory (%APPDATA%, Application
    Support or XDG_CONFIG_HOME)."""
    if platform.startswith("win"):
        return Path(env.get("APPDATA") or home / "AppData" / "Roaming")
    if platform == "darwin":
        return home / "Library" / "Application Support"
    return Path(env.get("XDG_CONFIG_HOME") or home / ".config")


def project_files(project: Path) -> list[AgentFile]:
    """Agent files that live in (and usually ship with) a repository."""
    p = project
    return [
        AgentFile("Claude Code", "project", p / ".mcp.json", _HINT_ENV_EXPANSION),
        AgentFile("Claude Code", "project", p / ".claude" / "settings.json", _HINT_ENV_EXPANSION),
        AgentFile("Claude Code", "project", p / ".claude" / "settings.local.json", _HINT_ENV_EXPANSION),
        AgentFile("Cursor", "project", p / ".cursor" / "mcp.json", _HINT_CURSOR),
        AgentFile("VS Code", "project", p / ".vscode" / "mcp.json", _HINT_VSCODE),
        AgentFile("VS Code", "project", p / ".vscode" / "settings.json", _HINT_VSCODE),
        AgentFile("Gemini CLI", "project", p / ".gemini" / "settings.json", _HINT_USER),
        AgentFile("Codex", "project", p / ".codex" / "config.toml", _HINT_USER),
        AgentFile("Windsurf", "project", p / ".windsurf" / "mcp.json", _HINT_USER),
        AgentFile("Amazon Q", "project", p / ".amazonq" / "mcp.json", _HINT_USER),
        AgentFile("Kiro", "project", p / ".kiro" / "settings" / "mcp.json", _HINT_USER),
        AgentFile("Roo Code", "project", p / ".roo" / "mcp.json", _HINT_USER),
        AgentFile("opencode", "project", p / "opencode.json", _HINT_USER),
        AgentFile("opencode", "project", p / "opencode.jsonc", _HINT_USER),
        AgentFile("Agent instructions", "project", p / "CLAUDE.md", _HINT_INSTRUCTIONS),
        AgentFile("Agent instructions", "project", p / "CLAUDE.local.md", _HINT_INSTRUCTIONS),
        AgentFile("Agent instructions", "project", p / "AGENTS.md", _HINT_INSTRUCTIONS),
        AgentFile("Agent instructions", "project", p / "GEMINI.md", _HINT_INSTRUCTIONS),
        AgentFile("Agent instructions", "project", p / ".cursorrules", _HINT_INSTRUCTIONS),
        AgentFile("Agent instructions", "project", p / ".windsurfrules", _HINT_INSTRUCTIONS),
        AgentFile("Agent instructions", "project", p / ".github" / "copilot-instructions.md", _HINT_INSTRUCTIONS),
    ]


def user_files(home: Path, env: dict[str, str] | None = None, platform: str | None = None) -> list[AgentFile]:
    """Agent and MCP client files in the user's home folder."""
    env = dict(os.environ) if env is None else env
    platform = sys.platform if platform is None else platform
    app = _app_data(home, env, platform)
    vscode_user = app / "Code" / "User"
    return [
        AgentFile("Claude Code", "user", home / ".claude.json", _HINT_USER),
        AgentFile("Claude Code", "user", home / ".claude" / "settings.json", _HINT_USER),
        AgentFile("Claude Code", "user", home / ".claude" / "CLAUDE.md", _HINT_INSTRUCTIONS),
        AgentFile("Claude Desktop", "user", app / "Claude" / "claude_desktop_config.json", _HINT_DESKTOP),
        AgentFile("Cursor", "user", home / ".cursor" / "mcp.json", _HINT_CURSOR),
        AgentFile("VS Code", "user", vscode_user / "mcp.json", _HINT_VSCODE),
        AgentFile("VS Code", "user", vscode_user / "settings.json", _HINT_VSCODE),
        AgentFile(
            "Cline",
            "user",
            vscode_user / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
            _HINT_USER,
        ),
        AgentFile("Windsurf", "user", home / ".codeium" / "windsurf" / "mcp_config.json", _HINT_USER),
        AgentFile("Gemini CLI", "user", home / ".gemini" / "settings.json", _HINT_USER),
        AgentFile("Codex", "user", home / ".codex" / "config.toml", _HINT_USER),
        AgentFile("Codex", "user", home / ".codex" / "AGENTS.md", _HINT_INSTRUCTIONS),
        AgentFile("Amazon Q", "user", home / ".aws" / "amazonq" / "mcp.json", _HINT_USER),
        AgentFile("Kiro", "user", home / ".kiro" / "settings" / "mcp.json", _HINT_USER),
        AgentFile("Continue", "user", home / ".continue" / "config.yaml", _HINT_USER),
        AgentFile("Continue", "user", home / ".continue" / "config.json", _HINT_USER),
        AgentFile("Zed", "user", Path(env.get("XDG_CONFIG_HOME") or home / ".config") / "zed" / "settings.json", _HINT_USER),
        AgentFile("opencode", "user", home / ".config" / "opencode" / "opencode.json", _HINT_USER),
        AgentFile("Goose", "user", home / ".config" / "goose" / "config.yaml", _HINT_USER),
        AgentFile("LM Studio", "user", home / ".lmstudio" / "mcp.json", _HINT_USER),
    ]


def transcript_files(home: Path, limit: int = TRANSCRIPT_MAX_FILES) -> list[AgentFile]:
    """The newest agent session transcripts (Claude Code, Codex)."""
    found: list[tuple[float, AgentFile]] = []
    for client, base in (("Claude Code", home / ".claude" / "projects"), ("Codex", home / ".codex" / "sessions")):
        if not base.is_dir():
            continue
        for path in base.rglob("*.jsonl"):
            try:
                found.append((path.stat().st_mtime, AgentFile(client, "transcript", path, _HINT_TRANSCRIPT)))
            except OSError:
                continue
    found.sort(key=lambda item: item[0], reverse=True)
    return [entry for _, entry in found[:limit]]


def _display(path: Path, home: Path, project: Path | None) -> str:
    for base, label in ((project, "."), (home, "~")):
        if base is None:
            continue
        try:
            return f"{label}/{path.relative_to(base).as_posix()}"
        except ValueError:
            continue
    return path.as_posix()


def _tracked(project: Path, path: Path) -> bool | None:
    """Whether git tracks *path* (None outside a repository or without git)."""
    try:
        proc = core._run_git(str(project), "ls-files", "--error-unmatch", "--", str(path))
    except ValueError:
        return None
    if proc.returncode == 0:
        return True
    return False if "did not match" in proc.stderr or "pathspec" in proc.stderr else None


def scan_agent_configs(
    project_path: str | None = None,
    include_user: bool = True,
    include_transcripts: bool = False,
    max_findings: int = core.DEFAULT_MAX_FINDINGS,
    home: str | None = None,
    config: core.ScanConfig = core.DEFAULT_CONFIG,
) -> dict:
    """Scan AI agent / MCP client configs, agent instruction files and,
    optionally, session transcripts for hardcoded secrets.

    Returns the standard redacted report plus ``agent_files``: one entry per
    file that exists (client, scope, path, findings, tracked_by_git for
    project files, and a remediation hint for files with findings).
    """
    core._check_max_findings(max_findings)
    home_dir = Path(home).expanduser() if home else Path.home()
    project = Path(project_path).expanduser().resolve() if project_path else None
    if project is not None and not project.is_dir():
        raise ValueError(f"Directory not found at {project_path} — pass an absolute project path.")
    if project is None and not include_user and not include_transcripts:
        raise ValueError("Nothing to scan: pass project_path, include_user or include_transcripts.")

    candidates: list[AgentFile] = []
    if project is not None:
        candidates += project_files(project)
    if include_user:
        # An explicit home (tests, another account) must not pick up this
        # process's %APPDATA% / XDG_CONFIG_HOME.
        candidates += user_files(home_dir, env={} if home else None)
    if include_transcripts:
        candidates += transcript_files(home_dir)

    collector = core._Collector(config)
    entries: list[dict] = []
    skipped = 0
    seen: set[Path] = set()
    for item in candidates:
        try:
            resolved = item.path.resolve()
            if resolved in seen or not item.path.is_file():
                continue
            seen.add(resolved)
            limit = TRANSCRIPT_MAX_BYTES if item.scope == "transcript" else core.MAX_FILE_BYTES
            if item.path.stat().st_size > limit:
                skipped += 1
                continue
            text, reason = core.decode_bytes(item.path.read_bytes())
        except OSError:
            skipped += 1
            continue
        if reason is not None:
            skipped += 1
            continue
        shown = _display(item.path, home_dir, project)
        before = len(collector.findings)
        core._scan_text_lines(text, shown, collector)
        found = len(collector.findings) - before
        entry = {"client": item.client, "scope": item.scope, "path": shown, "findings": found}
        if item.scope == "project" and project is not None:
            entry["tracked_by_git"] = _tracked(project, item.path)
        if found:
            entry["hint"] = item.hint
        entries.append(entry)

    result = collector.result(len(entries), max_findings)
    result["agent_files"] = entries
    if not entries:
        result["summary"] = "No agent or MCP client configuration files were found." + core._notes_suffix(result)
        return result
    exposed = [e for e in entries if e["findings"] and e.get("tracked_by_git")]
    if exposed:
        names = ", ".join(e["path"] for e in exposed)
        result["summary"] += (
            f" {len(exposed)} file(s) with findings are tracked by git ({names}): those secrets "
            "are pushed with the repository — rotate them, then reference environment variables."
        )
    if skipped:
        result["summary"] += f" [{skipped} file(s) skipped: unreadable, binary or oversized]"
    return result
