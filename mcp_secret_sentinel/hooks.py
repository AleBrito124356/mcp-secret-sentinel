"""Agent hooks: stop secrets at the moment an AI agent handles them.

``mcp-secret-sentinel hook`` reads one hook event as JSON on stdin and
answers on stdout. It speaks the Claude Code hook protocol (also used by
Codex) and Cursor's:

* before a tool runs (Claude/Codex ``PreToolUse``, Cursor
  ``beforeShellExecution`` / ``beforeMCPExecution``): deny a file write,
  edit, shell command or MCP call whose arguments contain a secret. Writes
  to files git ignores (a local ``.env``) and files outside any repository
  are allowed: that is where secrets belong.
* when a prompt is submitted (``UserPromptSubmit`` / ``beforeSubmitPrompt``):
  block a prompt that carries a secret before it reaches the model.
* after a tool ran (``PostToolUse``): replace every secret in the tool's
  output with ``[REDACTED:<detector>]`` so the model never sees it (``cat
  .env``, a Read of a config, a verbose log).
* before Cursor reads a file (``beforeReadFile``): deny reading a file
  that contains a secret.

Stdlib only, so a plugin can run it straight from its checkout. Findings
are always redacted, and anything unexpected fails open (exit 0, no
decision) rather than wedging the agent.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

from . import core
from .config import discover

DEFAULT_FAIL_ON = "high"
_RANK = {"critical": 0, "high": 1, "medium": 2}
_OWN_TOOL_MARKERS = ("secret-sentinel", "secret_sentinel")

# Claude Code tool name -> the tool_input fields that carry new content.
_CONTENT_FIELDS = {
    "Write": ("content",),
    "Edit": ("new_string",),
    "NotebookEdit": ("new_source",),
    "Bash": ("command",),
    "PowerShell": ("command",),  # Claude Code's shell tool on Windows
}
_FILE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_SHELL_TOOLS = {"Bash", "PowerShell"}
# Files that decide what the scanner reports. An agent the hook is guarding
# should not quietly loosen them, so edits to them ask the user first.
_GUARD_FILES = {".secret-sentinel.toml", ".secret-sentinel-baseline.json"}


def _strings(value) -> list[str]:
    """Every string inside a JSON value, depth first."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _tool_texts(tool_name: str, tool_input) -> list[str]:
    if not isinstance(tool_input, dict):
        return _strings(tool_input)
    if tool_name == "MultiEdit":
        return [e.get("new_string", "") for e in tool_input.get("edits", []) if isinstance(e, dict)]
    fields = _CONTENT_FIELDS.get(tool_name)
    if fields is not None:
        return [tool_input[f] for f in fields if isinstance(tool_input.get(f), str)]
    return _strings(tool_input)  # MCP and other tools: every argument


def _blocking(findings: list[dict], fail_on: str) -> list[dict]:
    threshold = _RANK[fail_on]
    return [f for f in findings if _RANK.get(f["severity"], 9) <= threshold]


def _describe(findings: list[dict], limit: int = 5) -> str:
    parts = [f"{f['pattern']} ({f['redacted']})" for f in findings[:limit]]
    if len(findings) > limit:
        parts.append(f"and {len(findings) - limit} more")
    return ", ".join(parts)


def _existing_dir(path: Path) -> Path | None:
    for candidate in (path, *path.parents):
        if candidate.is_dir():
            return candidate
    return None


def _secret_is_welcome(file_path: str, cwd: str | None) -> bool:
    """True for a write target where a secret is expected: a file git
    ignores, or a file outside every git work tree."""
    target = Path(file_path)
    if not target.is_absolute() and cwd:
        target = Path(cwd) / target
    base = _existing_dir(target.parent)
    if base is None:
        return False
    try:
        inside = core._run_git(str(base), "rev-parse", "--is-inside-work-tree")
        if inside.returncode != 0:
            # Only a definite "not a repository" means outside. Any other git
            # failure (dubious ownership, over-long paths) keeps the scan on.
            return "not a git repository" in inside.stderr.lower()
        if inside.stdout.strip() != "true":
            return True  # inside the .git directory itself
        # Without --no-index: a tracked file is never "ignored", so a committed
        # .env is still protected. Exit 1 (not ignored) and 128 (error) scan.
        ignored = core._run_git(str(base), "check-ignore", "-q", "--", str(target))
    except ValueError:  # git not installed: we cannot tell, so stay strict
        return False
    return ignored.returncode == 0


def _touches_scanner_config(file_path: str, texts: list[str]) -> bool:
    name = Path(file_path).name
    if name in _GUARD_FILES:
        return True
    return name == "pyproject.toml" and any("secret-sentinel" in t for t in texts)


class HookContext:
    def __init__(self, event: dict, fail_on: str):
        self.event = event
        self.fail_on = fail_on
        self.cwd = event.get("cwd") or (event.get("workspace_roots") or [None])[0]
        try:
            self.config = discover(self.cwd) if self.cwd else core.DEFAULT_CONFIG
        except ValueError:
            self.config = core.DEFAULT_CONFIG

    def scan(self, texts: list[str], source: str) -> list[dict]:
        findings: list[dict] = []
        for text in texts:
            if text:
                findings += core.scan_text(text, source, 0, self.config)["findings"]
        return _blocking(findings, self.fail_on)

    def excluded(self, file_path: str | None) -> bool:
        if not file_path:
            return False
        target = Path(file_path)
        if not target.is_absolute() and self.cwd:
            target = Path(self.cwd) / target
        return self.config.excludes_path(target)


# ---------------------------------------------------------------------------
# Claude Code / Codex
# ---------------------------------------------------------------------------


def _pre_tool_use(ctx: HookContext) -> dict | None:
    tool = ctx.event.get("tool_name") or ""
    if any(marker in tool for marker in _OWN_TOOL_MARKERS):
        return None  # our own scan/redact tools receive secrets on purpose
    tool_input = ctx.event.get("tool_input") or {}
    file_path = None
    if isinstance(tool_input, dict):
        file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    texts = _tool_texts(tool, tool_input)
    if tool in _FILE_TOOLS and file_path:
        if _touches_scanner_config(file_path, texts):
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": (
                        f"secret-sentinel: {Path(file_path).name} decides what the secret scanner "
                        "reports (excluded paths, allowlists, accepted findings). Confirm this change."
                    ),
                }
            }
        if ctx.excluded(file_path) or _secret_is_welcome(file_path, ctx.cwd):
            return None
    findings = ctx.scan(texts, file_path or tool)
    if not findings:
        return None
    if tool in _SHELL_TOOLS:
        fix = (
            "Do not put credentials in commands (they land in shell history and logs): "
            "read them from an environment variable, e.g. \"$API_KEY\"."
        )
    elif tool in _FILE_TOOLS:
        fix = (
            "Load the value from an environment variable or an untracked .env file "
            "(listed in .gitignore) instead of writing it into this tracked file."
        )
    else:
        fix = "Do not pass credentials to tools; reference them by environment variable name."
    reason = f"secret-sentinel blocked {tool or 'this tool call'}: it contains {_describe(findings)}. {fix}"
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _user_prompt_submit(ctx: HookContext) -> dict | None:
    findings = ctx.scan([ctx.event.get("prompt") or ""], "prompt")
    if not findings:
        return None
    return {
        "decision": "block",
        "reason": (
            f"secret-sentinel blocked this prompt: it contains {_describe(findings)}. "
            "Remove the value (rotate it if it was real) and refer to it by its "
            "environment variable name instead."
        ),
        # Keep the secret out of the block message and the transcript entry.
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
    }


def _redact_value(value, config: core.ScanConfig, counts: dict) -> object:
    if isinstance(value, str):
        redacted = core.redact_text(value, config)
        for name, n in redacted["by_pattern"].items():
            counts[name] = counts.get(name, 0) + n
        return redacted["text"]
    if isinstance(value, dict):
        return {k: _redact_value(v, config, counts) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v, config, counts) for v in value]
    return value


def _post_tool_use(ctx: HookContext) -> dict | None:
    tool = ctx.event.get("tool_name") or ""
    if any(marker in tool for marker in _OWN_TOOL_MARKERS):
        return None
    response = ctx.event.get("tool_response")
    if response is None:
        return None
    counts: dict[str, int] = {}
    redacted = _redact_value(copy.deepcopy(response), ctx.config, counts)
    if not counts:
        return None
    total = sum(counts.values())
    kinds = ", ".join(f"{n}x {name}" for name, n in counts.items())
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": redacted,
            "additionalContext": (
                f"secret-sentinel redacted {total} secret(s) from this {tool or 'tool'} output "
                f"({kinds}). The originals are real credentials: do not try to recover, print "
                "or copy them; reference them by environment variable name."
            ),
        }
    }


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------


def _cursor(ctx: HookContext, event_name: str) -> dict | None:
    e = ctx.event
    if event_name == "beforeSubmitPrompt":
        findings = ctx.scan([e.get("prompt") or ""], "prompt")
        if findings:
            return {
                "continue": False,
                "user_message": f"secret-sentinel blocked this prompt: it contains {_describe(findings)}.",
            }
        return {"continue": True}
    if event_name == "beforeShellExecution":
        findings = ctx.scan([e.get("command") or ""], "command")
    elif event_name == "beforeMCPExecution":
        tool = e.get("tool_name") or ""
        if any(marker in tool for marker in _OWN_TOOL_MARKERS):
            return {"permission": "allow"}
        raw = e.get("tool_input")
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            parsed = raw
        findings = ctx.scan(_strings(parsed), tool or "mcp")
    elif event_name == "beforeReadFile":
        if ctx.excluded(e.get("file_path")):
            return {"permission": "allow"}
        findings = ctx.scan([e.get("content") or ""], e.get("file_path") or "file")
    else:
        return None
    if not findings:
        return {"permission": "allow"}
    message = f"secret-sentinel: {_describe(findings)} found; use an environment variable instead."
    return {"permission": "deny", "user_message": message, "agent_message": message}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_HANDLERS = {
    "PreToolUse": _pre_tool_use,
    "UserPromptSubmit": _user_prompt_submit,
    "PostToolUse": _post_tool_use,
}
_CURSOR_EVENTS = {"beforeSubmitPrompt", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"}


def handle(event: dict, fail_on: str = DEFAULT_FAIL_ON) -> dict | None:
    """Decide on one hook event. Returns the JSON to print, or None for
    "no opinion" (the agent proceeds normally)."""
    name = event.get("hook_event_name") or ""
    ctx = HookContext(event, fail_on)
    if name in _HANDLERS:
        return _HANDLERS[name](ctx)
    if name in _CURSOR_EVENTS:
        return _cursor(ctx, name)
    return None


def run(stdin_text: str, fail_on: str = DEFAULT_FAIL_ON) -> str:
    """Hook entry point for the CLI: JSON in, JSON (or nothing) out."""
    stdin_text = stdin_text.lstrip("\ufeff")  # Windows shells may prepend a BOM
    try:
        event = json.loads(stdin_text) if stdin_text.strip() else {}
    except json.JSONDecodeError:
        return ""
    if not isinstance(event, dict):
        return ""
    decision = handle(event, fail_on)
    return json.dumps(decision) + "\n" if decision is not None else ""


# ---------------------------------------------------------------------------
# Installing hooks into an agent's settings
# ---------------------------------------------------------------------------

HOOK_COMMAND = "mcp-secret-sentinel hook"
# Anchored regexes (Claude Code treats a matcher with other characters than
# letters, digits, "_", "-", ",", " " and "|" as an unanchored regex).
_CLAUDE_EVENTS = {
    "PreToolUse": "^(Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell|mcp__.*)$",
    "UserPromptSubmit": None,
    "PostToolUse": "^(Read|Bash|PowerShell|Grep|WebFetch|mcp__.*)$",
}
_CURSOR_INSTALL = ("beforeSubmitPrompt", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile")
# How an installed sentinel hook command is recognised on reinstall: the CLI
# form or the plugin launcher, whatever the command prefix.
_OUR_COMMAND_RE = re.compile(r"mcp-secret-sentinel(?:\.exe)?\"?\s+hook\b|sentinel-hook\.sh|-m mcp_secret_sentinel hook\b")


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON ({exc}); fix it before installing hooks.") from None
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return data


def _ours(hook: object) -> bool:
    """True for one installed sentinel hook entry (never a whole group)."""
    return isinstance(hook, dict) and bool(_OUR_COMMAND_RE.search(str(hook.get("command", ""))))


def _without_ours(groups: list) -> list:
    """Claude Code matcher groups minus our own hook entries. Other hooks in
    a shared group stay; a group left empty is dropped."""
    kept = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
            kept.append(group)
            continue
        remaining = [h for h in group["hooks"] if not _ours(h)]
        if remaining:
            kept.append({**group, "hooks": remaining})
    return kept


def install_agent_hooks(agent: str, settings_path: Path, command: str = HOOK_COMMAND) -> Path:
    """Add (or refresh) the sentinel hooks in an agent's settings file,
    leaving every other setting and hook as it was."""
    data = _load_json(settings_path)
    if agent == "claude":
        hooks = data.setdefault("hooks", {})
        for event, matcher in _CLAUDE_EVENTS.items():
            group: dict = {"hooks": [{"type": "command", "command": command, "timeout": 30}]}
            if matcher:
                group = {"matcher": matcher, **group}
            hooks[event] = _without_ours(hooks.get(event, [])) + [group]
    elif agent == "cursor":
        data.setdefault("version", 1)
        hooks = data.setdefault("hooks", {})
        for event in _CURSOR_INSTALL:
            entries = [h for h in hooks.get(event, []) if not _ours(h)]
            hooks[event] = entries + [{"command": command}]
    else:
        raise ValueError(f"Unknown agent {agent!r}: use 'claude' or 'cursor'.")
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
    return settings_path


def settings_file(agent: str, scope: str, project: Path, home: Path) -> Path:
    if agent == "claude":
        if scope == "user":
            return home / ".claude" / "settings.json"
        return project / ".claude" / ("settings.local.json" if scope == "local" else "settings.json")
    if agent == "cursor":
        return (home if scope == "user" else project) / ".cursor" / "hooks.json"
    raise ValueError(f"Unknown agent {agent!r}: use 'claude' or 'cursor'.")
