"""Agent guardrails added in 0.3.0: hook decisions for Claude Code / Codex /
Cursor, the agent-config audit and redact_text.

Same golden rule as the rest of the suite: credential-shaped values are
assembled at runtime, and every decision is checked for raw secrets.
"""

import json
import os
import re
import subprocess
import sys

import pytest

from _fixtures import GENERIC_LINE, ROOT, SLACK_HOOK_LINE, STRIPE_LINE, STRIPE_SECRET, git, init_repo
from mcp_secret_sentinel import agents, core, hooks

JWT = "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "c2lnbmF0dXJlX3Rlc3Q"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    root = init_repo(tmp_path / "app")
    (root / ".gitignore").write_text(".env\n", encoding="utf-8")
    return root


def _clean(decision) -> str:
    text = json.dumps(decision)
    assert STRIPE_SECRET not in text
    return text


def _pre(repo, tool, tool_input):
    return hooks.handle(
        {"hook_event_name": "PreToolUse", "cwd": str(repo), "tool_name": tool, "tool_input": tool_input}
    )


# ---------------------------------------------------------------------------
# PreToolUse
# ---------------------------------------------------------------------------


def test_write_of_a_secret_into_a_tracked_file_is_denied(repo):
    decision = _pre(repo, "Write", {"file_path": str(repo / "billing.py"), "content": "import os\n" + STRIPE_LINE})
    output = decision["hookSpecificOutput"]
    assert output["hookEventName"] == "PreToolUse"
    assert output["permissionDecision"] == "deny"
    assert "Stripe live key" in output["permissionDecisionReason"]
    assert "environment variable" in output["permissionDecisionReason"]
    _clean(decision)


def test_write_to_a_gitignored_env_file_is_allowed(repo):
    assert _pre(repo, "Write", {"file_path": str(repo / ".env"), "content": "STRIPE=" + STRIPE_SECRET}) is None


def test_a_tracked_env_file_is_still_protected(repo):
    (repo / ".env").write_text("A=1\n", encoding="utf-8")
    git(repo, "add", "-f", ".env")
    decision = _pre(repo, "Write", {"file_path": str(repo / ".env"), "content": "STRIPE=" + STRIPE_SECRET})
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_write_outside_any_repository_is_allowed(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    loose = tmp_path / "loose"
    loose.mkdir()
    assert _pre(loose, "Write", {"file_path": str(loose / "notes.txt"), "content": STRIPE_LINE}) is None


def test_edit_and_multiedit_check_only_the_new_text(repo):
    target = str(repo / "app.py")
    assert _pre(repo, "Edit", {"file_path": target, "old_string": STRIPE_LINE, "new_string": "x = 1"}) is None
    denied = _pre(repo, "Edit", {"file_path": target, "old_string": "x = 1", "new_string": STRIPE_LINE})
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    multi = _pre(repo, "MultiEdit", {"file_path": target, "edits": [{"old_string": "a", "new_string": SLACK_HOOK_LINE}]})
    assert multi["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bash_command_with_a_secret_is_denied(repo):
    command = "curl -H 'Authorization: Bearer " + STRIPE_SECRET + "' https://api.stripe.com/v1/charges"
    decision = _pre(repo, "Bash", {"command": command})
    reason = decision["hookSpecificOutput"]["permissionDecisionReason"]
    assert "shell history" in reason
    _clean(decision)
    assert _pre(repo, "Bash", {"command": 'curl -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com'}) is None


def test_mcp_tool_arguments_are_checked_but_our_own_tools_are_not(repo):
    leak = _pre(repo, "mcp__slack__post_message", {"channel": "ops", "text": "key " + STRIPE_SECRET})
    assert leak["hookSpecificOutput"]["permissionDecision"] == "deny"
    own = _pre(repo, "mcp__plugin_secret-sentinel_secret-sentinel__scan_text", {"text": STRIPE_LINE})
    assert own is None


def test_medium_findings_pass_by_default_and_block_with_fail_on_medium(repo):
    event = {
        "hook_event_name": "PreToolUse",
        "cwd": str(repo),
        "tool_name": "Write",
        "tool_input": {"file_path": str(repo / "auth.md"), "content": "Bearer " + JWT},
    }
    assert hooks.handle(event) is None
    assert hooks.handle(event, fail_on="medium")["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_config_excluded_paths_are_allowed(repo):
    (repo / ".secret-sentinel.toml").write_text('exclude_paths = ["fixtures/**"]\n', encoding="utf-8")
    target = str(repo / "fixtures" / "keys.py")
    assert _pre(repo, "Write", {"file_path": target, "content": STRIPE_LINE}) is None


# ---------------------------------------------------------------------------
# UserPromptSubmit / PostToolUse
# ---------------------------------------------------------------------------


def test_prompt_with_a_secret_is_blocked_without_echoing_it(repo):
    decision = hooks.handle({"hook_event_name": "UserPromptSubmit", "cwd": str(repo), "prompt": "use " + STRIPE_SECRET})
    assert decision["decision"] == "block"
    assert decision["hookSpecificOutput"]["suppressOriginalPrompt"] is True
    _clean(decision)
    assert hooks.handle({"hook_event_name": "UserPromptSubmit", "cwd": str(repo), "prompt": "hello"}) is None


def test_tool_output_is_redacted_keeping_its_shape(repo):
    response = {"stdout": "OK=1\nSTRIPE=" + STRIPE_SECRET + "\n", "stderr": "", "interrupted": False, "isImage": False}
    decision = hooks.handle(
        {
            "hook_event_name": "PostToolUse",
            "cwd": str(repo),
            "tool_name": "Bash",
            "tool_input": {"command": "cat .env"},
            "tool_response": response,
        }
    )
    output = decision["hookSpecificOutput"]
    assert output["hookEventName"] == "PostToolUse"
    assert output["updatedToolOutput"] == {
        "stdout": "OK=1\nSTRIPE=[REDACTED:Stripe live key]\n",
        "stderr": "",
        "interrupted": False,
        "isImage": False,
    }
    assert "1 secret" in output["additionalContext"]
    _clean(decision)


def test_nested_read_output_is_redacted_and_clean_output_is_left_alone(repo):
    response = {"type": "text", "file": {"filePath": "/x/settings.py", "content": "a\n" + STRIPE_LINE, "numLines": 2}}
    event = {"hook_event_name": "PostToolUse", "cwd": str(repo), "tool_name": "Read", "tool_response": response}
    redacted = hooks.handle(event)["hookSpecificOutput"]["updatedToolOutput"]
    assert redacted["file"]["numLines"] == 2
    assert "[REDACTED:Stripe live key]" in redacted["file"]["content"]
    event["tool_response"] = {"type": "text", "file": {"content": "nothing here"}}
    assert hooks.handle(event) is None


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------


def test_cursor_events(repo):
    roots = [str(repo)]
    shell = hooks.handle({"hook_event_name": "beforeShellExecution", "workspace_roots": roots, "command": "echo " + STRIPE_SECRET})
    assert shell["permission"] == "deny" and "Stripe" in shell["agent_message"]
    prompt = hooks.handle({"hook_event_name": "beforeSubmitPrompt", "workspace_roots": roots, "prompt": STRIPE_LINE})
    assert prompt["continue"] is False
    read = hooks.handle({"hook_event_name": "beforeReadFile", "workspace_roots": roots, "file_path": "s.py", "content": STRIPE_LINE})
    assert read["permission"] == "deny"
    mcp_call = hooks.handle(
        {"hook_event_name": "beforeMCPExecution", "workspace_roots": roots, "tool_name": "post", "tool_input": json.dumps({"t": STRIPE_SECRET})}
    )
    assert mcp_call["permission"] == "deny"
    assert hooks.handle({"hook_event_name": "beforeShellExecution", "workspace_roots": roots, "command": "ls"}) == {"permission": "allow"}
    for decision in (shell, prompt, read, mcp_call):
        _clean(decision)


# ---------------------------------------------------------------------------
# The CLI entry point and installers
# ---------------------------------------------------------------------------


def test_run_ignores_garbage_and_strips_a_bom(repo):
    assert hooks.run("not json") == ""
    assert hooks.run("[1, 2]") == ""
    assert hooks.run("") == ""
    event = {"hook_event_name": "UserPromptSubmit", "cwd": str(repo), "prompt": STRIPE_SECRET}
    assert json.loads(hooks.run("﻿" + json.dumps(event)))["decision"] == "block"


def test_hook_command_over_a_real_pipe(repo):
    event = {"hook_event_name": "PreToolUse", "cwd": str(repo), "tool_name": "Bash", "tool_input": {"command": "export K=" + STRIPE_SECRET}}
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_secret_sentinel", "hook"],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert STRIPE_SECRET not in proc.stdout + proc.stderr


def test_install_claude_hooks_merges_and_is_idempotent(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}
    settings.write_text(json.dumps({"model": "opus", "hooks": {"PreToolUse": [other]}}), encoding="utf-8")
    hooks.install_agent_hooks("claude", settings)
    hooks.install_agent_hooks("claude", settings)
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["model"] == "opus"
    pre = data["hooks"]["PreToolUse"]
    assert pre[0] == other and len(pre) == 2
    assert pre[1]["matcher"] == hooks._CLAUDE_EVENTS["PreToolUse"]
    assert re.match(pre[1]["matcher"], "Write") and re.match(pre[1]["matcher"], "mcp__slack__post")
    assert not re.match(pre[1]["matcher"], "TodoWrite")
    assert pre[1]["hooks"][0]["command"] == hooks.HOOK_COMMAND
    assert len(data["hooks"]["UserPromptSubmit"]) == 1
    assert "matcher" not in data["hooks"]["UserPromptSubmit"][0]
    assert len(data["hooks"]["PostToolUse"]) == 1


def test_install_cursor_hooks(tmp_path):
    target = hooks.settings_file("cursor", "project", tmp_path, tmp_path / "home")
    hooks.install_agent_hooks("cursor", target)
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert set(data["hooks"]) == {"beforeSubmitPrompt", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"}


def test_install_refuses_broken_settings(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        hooks.install_agent_hooks("claude", settings)


def test_plugin_launcher_keeps_lf_line_endings():
    assert b"\r\n" not in (ROOT / "hooks" / "sentinel-hook.sh").read_bytes()
    assert "*.sh text eol=lf" in (ROOT / ".gitattributes").read_text(encoding="utf-8")


def test_plugin_hooks_file_matches_the_installer():
    plugin_hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    assert set(plugin_hooks) == set(hooks._CLAUDE_EVENTS)
    for event, matcher in hooks._CLAUDE_EVENTS.items():
        assert plugin_hooks[event][0].get("matcher") == matcher


# ---------------------------------------------------------------------------
# Agent config audit
# ---------------------------------------------------------------------------


def test_project_agent_configs(repo):
    (repo / ".mcp.json").write_text(
        '{"mcpServers": {"pay": {"command": "x", "env": {"STRIPE_KEY": "' + STRIPE_SECRET + '"}}}}\n',
        encoding="utf-8",
    )
    git(repo, "add", ".mcp.json")
    (repo / ".cursor").mkdir()
    (repo / ".cursor" / "mcp.json").write_text('{"env": {"KEY": "${env:STRIPE_KEY}"}}\n', encoding="utf-8")
    (repo / "CLAUDE.md").write_text("# Notes\n" + GENERIC_LINE + "\n", encoding="utf-8")

    result = agents.scan_agent_configs(str(repo), include_user=False)
    by_path = {e["path"]: e for e in result["agent_files"]}
    assert by_path["./.mcp.json"]["findings"] == 1
    assert by_path["./.mcp.json"]["tracked_by_git"] is True
    assert "${API_KEY}" in by_path["./.mcp.json"]["hint"]
    assert by_path["./.cursor/mcp.json"]["findings"] == 0
    assert "hint" not in by_path["./.cursor/mcp.json"]
    assert by_path["./CLAUDE.md"]["tracked_by_git"] is False
    assert {f["file"] for f in result["findings"]} == {"./.mcp.json", "./CLAUDE.md"}
    assert "tracked by git (./.mcp.json)" in result["summary"]
    assert STRIPE_SECRET not in json.dumps(result)


def test_user_configs_and_transcripts(tmp_path):
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text('{"env": {"K": "' + STRIPE_SECRET + '"}}', encoding="utf-8")
    desktop = agents._app_data(home, {}, sys.platform) / "Claude" / "claude_desktop_config.json"
    desktop.parent.mkdir(parents=True)
    desktop.write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    session = home / ".claude" / "projects" / "-work-app" / "abc.jsonl"
    session.parent.mkdir(parents=True)
    session.write_text(json.dumps({"message": {"content": "my key is " + STRIPE_SECRET}}) + "\n", encoding="utf-8")

    without = agents.scan_agent_configs(None, include_user=True, home=str(home))
    assert {e["client"] for e in without["agent_files"]} == {"Cursor", "Claude Desktop"}
    assert all(e["scope"] == "user" for e in without["agent_files"])
    assert without["agent_files"][0]["path"].startswith("~/")

    with_transcripts = agents.scan_agent_configs(None, include_user=False, include_transcripts=True, home=str(home))
    (entry,) = with_transcripts["agent_files"]
    assert entry["scope"] == "transcript" and entry["findings"] == 1
    assert "model provider" in entry["hint"]


def test_agent_audit_edge_cases(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = agents.scan_agent_configs(str(empty), include_user=False)
    assert result["clean"] and result["agent_files"] == []
    assert "No agent" in result["summary"]
    with pytest.raises(ValueError, match="Nothing to scan"):
        agents.scan_agent_configs(None, include_user=False)
    with pytest.raises(ValueError, match="Directory not found"):
        agents.scan_agent_configs(str(tmp_path / "missing"))


# ---------------------------------------------------------------------------
# redact_text
# ---------------------------------------------------------------------------


def test_redact_text_keeps_everything_but_the_secret():
    text = "line one\r\n" + STRIPE_LINE + "\r\n" + SLACK_HOOK_LINE + "\nlast"
    result = core.redact_text(text)
    assert result["redactions"] == 2
    assert result["text"] == (
        'line one\r\nstripe_key = "[REDACTED:Stripe live key]"\r\nHOOK_URL = "https://[REDACTED:Slack incoming webhook]"\nlast'
    )
    assert result["by_pattern"] == {"Stripe live key": 1, "Slack incoming webhook": 1}


def test_redact_text_respects_suppression_and_placeholders():
    text = STRIPE_LINE + "  # secret-sentinel: ignore\npassword = \"${DB_PASSWORD}\""
    assert core.redact_text(text) == {"text": text, "redactions": 0, "by_pattern": {}}


def test_redact_text_handles_several_secrets_on_one_line():
    line = "a=" + STRIPE_SECRET + " b=" + JWT
    result = core.redact_text(line)
    assert result["text"] == "a=[REDACTED:Stripe live key] b=[REDACTED:JSON Web Token]"
