"""Regression tests for the issues found reviewing 0.3.0 before release:
private key bodies in redaction, UTF-8 hook input on Windows, the
PowerShell tool, git failures, ignored folders, base64 after "=", baseline
locations, hook errors, the installer, and edits to the scanner's own config.

Same golden rule: credential-shaped values are assembled at runtime.
"""

import base64
import io
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from _fixtures import ROOT, SLACK_HOOK_LINE, STRIPE_LINE, STRIPE_SECRET, git, init_repo
from mcp_secret_sentinel import cli, core, hooks
from mcp_secret_sentinel import config as cfg

KEY_BODY = "MIIEowIBAAKCAQEA" + "x7Qp2Lm9Rt4Vb8Nk3Hs6Fd1Jw5Cy0Ga" * 3
PEM = (
    "-----BEGIN " + "RSA PRIVATE KEY-----\n"
    + KEY_BODY + "\n"
    + KEY_BODY[::-1] + "\n"
    + "-----END " + "RSA PRIVATE KEY-----\n"
)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    return init_repo(tmp_path / "app")


# ---------------------------------------------------------------------------
# 1. Private keys are redacted as whole blocks
# ---------------------------------------------------------------------------


def test_redaction_removes_the_whole_private_key_block():
    result = core.redact_text("before\n" + PEM + "after\n")
    assert result["text"] == "before\n[REDACTED:Private key material]\nafter\n"
    assert KEY_BODY not in result["text"] and KEY_BODY[::-1] not in result["text"]
    assert result["by_pattern"] == {"Private key material": 1}


def test_redaction_handles_json_escaped_keys_and_missing_footers():
    service_account = json.dumps({"type": "service_account", "private_key": PEM})
    redacted = core.redact_text(service_account)["text"]
    assert KEY_BODY not in redacted
    assert json.loads(redacted)["private_key"] == "[REDACTED:Private key material]\n"

    truncated = "-----BEGIN " + "PRIVATE KEY-----\n" + KEY_BODY + "\n(log cut here)"
    assert core.redact_text(truncated)["text"] == "[REDACTED:Private key material]"


def test_a_suppressed_key_header_keeps_its_block():
    fixture = "-----BEGIN " + "PRIVATE KEY-----  # secret-sentinel: ignore\nAAAA\n-----END PRIVATE KEY-----"
    assert core.redact_text(fixture)["text"] == fixture


def test_post_tool_use_redacts_a_key_file_read(repo):
    event = {
        "hook_event_name": "PostToolUse",
        "cwd": str(repo),
        "tool_name": "Bash",
        "tool_response": {"stdout": PEM, "stderr": "", "interrupted": False, "isImage": False},
    }
    output = hooks.handle(event)["hookSpecificOutput"]["updatedToolOutput"]
    assert output["stdout"] == "[REDACTED:Private key material]\n"


def test_baselining_one_private_key_does_not_accept_every_key(repo):
    (repo / "deploy_key").write_text(PEM, encoding="utf-8")
    run = cli.main(["baseline", str(repo)])
    assert run == 0
    (repo / "other_key").write_text(PEM.replace(KEY_BODY, KEY_BODY.lower()), encoding="utf-8")
    result = core.scan_directory(str(repo), config=cfg.discover(repo))
    assert [f["file"] for f in result["findings"]] == ["other_key"]
    assert result["baselined"] == 1


# ---------------------------------------------------------------------------
# 2-4, 8. Hook input, PowerShell, git failures, errors
# ---------------------------------------------------------------------------


def test_hook_reads_utf8_whatever_the_console_code_page(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    project = init_repo(tmp_path / "José" / "proyecto")
    event = {
        "hook_event_name": "PreToolUse",
        "cwd": str(project),
        "tool_name": "Write",
        "tool_input": {"file_path": str(project / "billing.py"), "content": STRIPE_LINE},
    }
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_secret_sentinel", "hook"],
        input=("﻿" + json.dumps(event, ensure_ascii=False)).encode("utf-8"),
        capture_output=True,
        env={**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "cp1252"},
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_powershell_commands_are_checked(repo):
    decision = hooks.handle(
        {
            "hook_event_name": "PreToolUse",
            "cwd": str(repo),
            "tool_name": "PowerShell",
            "tool_input": {"command": "$env:STRIPE = '" + STRIPE_SECRET + "'"},
        }
    )
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "shell history" in decision["hookSpecificOutput"]["permissionDecisionReason"]
    assert "PowerShell" in hooks._CLAUDE_EVENTS["PreToolUse"]
    assert "PowerShell" in hooks._CLAUDE_EVENTS["PostToolUse"]


@pytest.mark.parametrize(
    "stderr,welcome",
    [
        ("fatal: not a git repository (or any of the parent directories): .git", True),
        ("fatal: detected dubious ownership in repository at '//nas/share/app'", False),
        ("fatal: Filename too long", False),
    ],
)
def test_only_a_definite_not_a_repository_skips_the_scan(tmp_path, monkeypatch, stderr, welcome):
    monkeypatch.setattr(
        core, "_run_git", lambda *args: SimpleNamespace(returncode=128, stdout="", stderr=stderr)
    )
    assert hooks._secret_is_welcome(str(tmp_path / "x.py"), str(tmp_path)) is welcome


def test_hook_errors_never_block(monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(hooks, "run", boom)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"{}"), encoding="utf-8"))
    assert cli.main(["hook"]) == 1  # a non-blocking error, never 2 ("deny")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "not blocking" in captured.err


# ---------------------------------------------------------------------------
# 5. Ignored folders and nested repositories
# ---------------------------------------------------------------------------


def test_an_ignored_folder_is_walked_instead_of_called_clean(repo):
    (repo / ".gitignore").write_text("build-cache/\n", encoding="utf-8")
    (repo / "build-cache").mkdir()
    (repo / "build-cache" / "env.txt").write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    result = core.scan_directory(str(repo / "build-cache"))
    assert [f["file"] for f in result["findings"]] == ["env.txt"]
    assert "walked directly" in result["summary"]
    # From the repository root the ignore rule still applies.
    assert core.scan_directory(str(repo))["clean"]


def test_untracked_nested_repositories_are_walked(repo):
    nested = init_repo(repo / "vendor" / "tool")
    (nested / "settings.py").write_text(STRIPE_LINE + "\n", encoding="utf-8")
    result = core.scan_directory(str(repo))
    assert [f["file"] for f in result["findings"]] == ["vendor/tool/settings.py"]
    assert "nested repository" in result["summary"]


# ---------------------------------------------------------------------------
# 6, 12. Base64 placement and size
# ---------------------------------------------------------------------------


def test_base64_right_after_an_equals_sign_is_decoded():
    encoded = base64.b64encode(("stripe: " + STRIPE_SECRET).encode()).decode()
    for line in ("CONFIG_B64=" + encoded, "https://x.internal/cb?cfg=" + encoded):
        (finding,) = core.scan_text(line)["findings"]
        assert finding["pattern"] == "Stripe live key (base64)", line


def test_large_base64_blobs_are_decoded():
    big_pem = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + (KEY_BODY + "\n") * 40 + "-----END RSA PRIVATE KEY-----\n"
    encoded = base64.b64encode(big_pem.encode()).decode()
    assert len(encoded) > 4096
    (finding,) = core.scan_text("tls.key: " + encoded)["findings"]
    assert finding["pattern"] == "Private key material (base64)"


# ---------------------------------------------------------------------------
# 7. Baseline location
# ---------------------------------------------------------------------------


def test_baseline_goes_where_the_config_reads_it(repo, monkeypatch):
    (repo / ".secret-sentinel.toml").write_text('baseline = "sec/accepted.json"\n', encoding="utf-8")
    (repo / "sec").mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "billing.py").write_text(STRIPE_LINE + "\n", encoding="utf-8")
    monkeypatch.chdir(repo / "src")  # from a subfolder, too
    assert cli.main(["baseline", "."]) == 0
    assert (repo / "sec" / "accepted.json").is_file()
    assert not (repo / "src" / cfg.BASELINE_FILENAME).exists()
    assert cli.main(["scan", "."]) == 0


def test_without_config_the_baseline_lands_at_the_repository_root(repo, monkeypatch):
    (repo / "src").mkdir()
    (repo / "src" / "billing.py").write_text(STRIPE_LINE + "\n", encoding="utf-8")
    monkeypatch.chdir(repo / "src")
    assert cli.main(["baseline", "."]) == 0
    assert (repo / cfg.BASELINE_FILENAME).is_file()
    assert cli.main(["scan", str(repo)]) == 0


def test_a_missing_explicit_baseline_is_an_error(repo):
    (repo / ".secret-sentinel.toml").write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="Baseline not found"):
        cfg.load_config(repo / ".secret-sentinel.toml", baseline=repo / "nope.json")


# ---------------------------------------------------------------------------
# 9-10. Installer and the scanner's own config
# ---------------------------------------------------------------------------


def test_reinstall_keeps_other_hooks_that_share_a_group(tmp_path):
    settings = tmp_path / "settings.json"
    mine = {"type": "command", "command": "my-formatter"}
    shared = {"matcher": "Write", "hooks": [mine, {"type": "command", "command": "/opt/bin/mcp-secret-sentinel hook"}]}
    plugin = {"matcher": "Bash", "hooks": [{"type": "command", "command": 'sh "/p/hooks/sentinel-hook.sh"'}]}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [shared, plugin]}}), encoding="utf-8")
    hooks.install_agent_hooks("claude", settings)
    pre = json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    assert pre[0] == {"matcher": "Write", "hooks": [mine]}
    assert len(pre) == 2 and pre[1]["matcher"] == hooks._CLAUDE_EVENTS["PreToolUse"]


@pytest.mark.parametrize(
    "name,content",
    [
        (".secret-sentinel.toml", 'allowlist = ["."]\n'),
        (".secret-sentinel-baseline.json", '{"findings": []}'),
        ("pyproject.toml", '[tool.secret-sentinel]\ndisable = ["Stripe live key"]\n'),
    ],
)
def test_edits_to_the_scanner_config_ask_first(repo, name, content):
    decision = hooks.handle(
        {
            "hook_event_name": "PreToolUse",
            "cwd": str(repo),
            "tool_name": "Write",
            "tool_input": {"file_path": str(repo / name), "content": content},
        }
    )
    assert decision["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_ordinary_pyproject_edits_are_not_interrupted(repo):
    event = {
        "hook_event_name": "PreToolUse",
        "cwd": str(repo),
        "tool_name": "Edit",
        "tool_input": {"file_path": str(repo / "pyproject.toml"), "old_string": "0.1", "new_string": "0.2"},
    }
    assert hooks.handle(event) is None
