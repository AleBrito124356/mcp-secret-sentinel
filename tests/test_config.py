"""Project configuration, baselines, git-aware directory listing and the
commands added in 0.3.0 (init, baseline, redact, agents, install-agent-hooks).

Same golden rule: credential-shaped values are assembled at runtime.
"""

import json
import os
import subprocess
import sys

import pytest

from _fixtures import GENERIC_LINE, ROOT, SLACK_HOOK_LINE, STRIPE_LINE, STRIPE_SECRET, git, init_repo
from mcp_secret_sentinel import config as cfg
from mcp_secret_sentinel import core

ACME_TOKEN = "ac" + "me_" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
ACME_RULE = """
[[rules]]
name = "Acme internal token"
regex = 'acme_[a-f0-9]{32}'
severity = "critical"
advice = "Revoke it in the Acme console."
"""


def run_cli(*args, cwd, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "mcp_secret_sentinel", *args],
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"},
        timeout=120,
    )


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    root = init_repo(tmp_path / "project")
    (root / "src").mkdir()
    (root / "src" / "billing.py").write_text("import os\n" + STRIPE_LINE + "\n", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------


def test_custom_rules_disable_and_allowlist(project):
    (project / ".secret-sentinel.toml").write_text(
        'disable = ["JSON Web Token", "High-entropy string"]\nallowlist = ["^hunter2"]\n' + ACME_RULE,
        encoding="utf-8",
    )
    config = cfg.discover(project / "src")
    assert config.source == ".secret-sentinel.toml"
    assert config.patterns[0]["name"] == "Acme internal token"
    assert "JSON Web Token" not in {p["name"] for p in config.patterns}
    assert config.entropy is False

    found = core.scan_text("token: " + ACME_TOKEN + "\n" + GENERIC_LINE, config=config)
    assert [f["pattern"] for f in found["findings"]] == ["Acme internal token"]
    assert found["findings"][0]["severity"] == "critical"
    assert ACME_TOKEN not in json.dumps(found)


def test_pyproject_table_is_found_and_search_stops_at_the_repo_root(project, tmp_path):
    (tmp_path / ".secret-sentinel.toml").write_text('disable = ["JSON Web Token"]\n', encoding="utf-8")
    assert cfg.find_config(project / "src") is None  # the parent outside the repo is not used
    (project / "pyproject.toml").write_text(
        '[project]\nname = "x"\n\n[tool.secret-sentinel]\nexclude_paths = ["src/**"]\n', encoding="utf-8"
    )
    assert cfg.find_config(project / "src" / "billing.py") == (project / "pyproject.toml").resolve()
    assert cfg.discover(project).exclude_paths == ["src/**"]


@pytest.mark.parametrize(
    "body,message",
    [
        ("colour = 1\n", "unknown key"),
        ('disable = ["No such detector"]\n', "unknown detector"),
        ('allowlist = ["("]\n', "invalid regex"),
        ("exclude_paths = 3\n", "must be a list"),
        ('[[rules]]\nname = "x"\n', "'regex' is required"),
        ('[[rules]]\nname = "x"\nregex = "a"\nseverity = "low"\n', "'severity'"),
        ('[[rules]]\nname = "x"\nregex = "a"\ngroup = 2\n', "'group'"),
        ("not = [toml\n", "invalid TOML"),
    ],
)
def test_bad_configs_say_what_is_wrong(tmp_path, body, message):
    path = tmp_path / ".secret-sentinel.toml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        cfg.load_config(path)


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("tests/fixtures/**", "tests/fixtures/a/b.py", True),
        ("tests/fixtures/**", "tests/other.py", False),
        ("*.snap", "deep/dir/x.snap", True),
        ("/docs/*.md", "docs/a.md", True),
        ("/docs/*.md", "sub/docs/a.md", False),
        ("build/", "build/out/x.js", True),
        ("**/secrets.example.*", "a/b/secrets.example.yml", True),
        ("src/?.py", "src/ab.py", False),
    ],
)
def test_exclude_globs(pattern, path, expected):
    assert core.ScanConfig(exclude_paths=[pattern]).excludes(path) is expected


# ---------------------------------------------------------------------------
# Excludes in scans
# ---------------------------------------------------------------------------


def test_excludes_apply_to_directory_and_staged_scans(project):
    (project / "fixtures").mkdir()
    (project / "fixtures" / "keys.py").write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    (project / ".secret-sentinel.toml").write_text('exclude_paths = ["fixtures/**"]\n', encoding="utf-8")
    config = cfg.discover(project)

    tree = core.scan_directory(str(project), config=config)
    assert [f["file"] for f in tree["findings"]] == ["src/billing.py"]
    assert "1 file(s) excluded by .secret-sentinel.toml" in tree["summary"]

    git(project, "add", "-A")
    staged = core.scan_git_staged(str(project), config=config)
    assert [f["file"] for f in staged["findings"]] == ["src/billing.py"]


def test_directory_scan_uses_git_ignore_rules_exactly(project):
    (project / ".gitignore").write_text("*.log\n!keep.log\n", encoding="utf-8")
    (project / "nested").mkdir()
    (project / "nested" / ".gitignore").write_text("private/\n", encoding="utf-8")
    (project / "nested" / "private").mkdir()
    (project / "nested" / "private" / "x.py").write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    (project / "debug.log").write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    (project / "keep.log").write_text(GENERIC_LINE + "\n", encoding="utf-8")

    result = core.scan_directory(str(project))
    assert sorted(f["file"] for f in result["findings"]) == ["keep.log", "src/billing.py"]
    assert "file list from git" in result["summary"]


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


def test_fingerprints_are_stable_salted_and_never_the_value():
    first = core.fingerprint("Stripe live key", STRIPE_SECRET)
    assert first == core.fingerprint("Stripe live key", STRIPE_SECRET)
    assert first != core.fingerprint("Generic secret assignment", STRIPE_SECRET)
    assert STRIPE_SECRET not in first and len(first) == 32


def test_baseline_command_then_only_new_secrets_are_reported(project):
    written = run_cli("baseline", cwd=project)
    assert written.returncode == 0, written.stderr
    baseline_file = project / cfg.BASELINE_FILENAME
    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert [e["file"] for e in data["findings"]] == ["src/billing.py"]
    assert STRIPE_SECRET not in baseline_file.read_text(encoding="utf-8")

    accepted = run_cli("scan", "--format", "json", cwd=project)
    assert accepted.returncode == 0, accepted.stdout
    report = json.loads(accepted.stdout)
    assert report["clean"] and report["baselined"] == 1
    assert "accepted by the baseline" in report["summary"]

    (project / "src" / "notify.py").write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    fresh = json.loads(run_cli("scan", "--format", "json", cwd=project).stdout)
    assert [f["file"] for f in fresh["findings"]] == ["src/notify.py"]

    ignored = json.loads(run_cli("scan", "--no-config", "--format", "json", cwd=project).stdout)
    assert len(ignored["findings"]) == 2


def test_baseline_moves_with_the_code(project):
    run_cli("baseline", cwd=project)
    (project / "src" / "billing.py").write_text("\n\n\n# moved\n" + STRIPE_LINE + "\n", encoding="utf-8")
    assert json.loads(run_cli("scan", "--format", "json", cwd=project).stdout)["clean"]


def test_baseline_applies_to_staged_scans_and_redact(project):
    run_cli("baseline", cwd=project)
    git(project, "add", "-A")
    staged = core.scan_git_staged(str(project), config=cfg.discover(project))
    assert staged["clean"] and staged["baselined"] == 1
    assert "accepted by the baseline" in staged["summary"]
    assert core.redact_text(STRIPE_LINE, cfg.discover(project))["redactions"] == 0


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def test_init_writes_a_valid_starter(tmp_path):
    first = run_cli("init", cwd=tmp_path)
    assert first.returncode == 0
    assert cfg.load_config(tmp_path / cfg.CONFIG_FILENAME).source == cfg.CONFIG_FILENAME
    again = run_cli("init", cwd=tmp_path)
    assert again.returncode == 2 and "already exists" in again.stderr


def test_redact_command(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("start\n" + STRIPE_LINE + "\nend\n", encoding="utf-8")
    proc = run_cli("redact", str(log), cwd=tmp_path)
    assert proc.returncode == 0
    assert proc.stdout == 'start\nstripe_key = "[REDACTED:Stripe live key]"\nend\n'
    assert "1 secret(s) redacted" in proc.stderr
    piped = run_cli("redact", cwd=tmp_path, stdin=SLACK_HOOK_LINE)
    assert "[REDACTED:Slack incoming webhook]" in piped.stdout


def test_custom_rules_reach_the_cli_and_sarif(project):
    (project / ".secret-sentinel.toml").write_text(ACME_RULE, encoding="utf-8")
    (project / "src" / "acme.py").write_text('T = "' + ACME_TOKEN + '"\n', encoding="utf-8")
    proc = run_cli("scan", "--format", "sarif", cwd=project)
    assert proc.returncode == 1
    sarif = json.loads(proc.stdout)
    rules = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "secret-sentinel/acme-internal-token" in rules
    assert ACME_TOKEN not in proc.stdout


def test_explicit_config_flag(project, tmp_path):
    other = tmp_path / "strict.toml"
    other.write_text('disable = ["Stripe live key", "High-entropy string"]\n', encoding="utf-8")
    proc = run_cli("scan", "--config", str(other), "--format", "json", cwd=project)
    assert json.loads(proc.stdout)["clean"]
    broken = run_cli("scan", "--config", str(tmp_path / "missing.toml"), cwd=project)
    assert broken.returncode == 2


def test_agents_command(project):
    (project / ".mcp.json").write_text('{"env": {"K": "' + STRIPE_SECRET + '"}}\n', encoding="utf-8")
    text = run_cli("agents", "--no-user", cwd=project)
    assert text.returncode == 1
    assert "./.mcp.json  [Claude Code, project]  1 finding(s)" in text.stdout
    assert "How to fix:" in text.stdout
    data = json.loads(run_cli("agents", "--no-user", "--format", "json", cwd=project).stdout)
    assert data["agent_files"][0]["path"] == "./.mcp.json"
    assert STRIPE_SECRET not in text.stdout


def test_install_agent_hooks_command(project):
    proc = run_cli("install-agent-hooks", "--agent", "claude", "--scope", "local", cwd=project)
    assert proc.returncode == 0, proc.stderr
    settings = json.loads((project / ".claude" / "settings.local.json").read_text(encoding="utf-8"))
    assert set(settings["hooks"]) == {"PreToolUse", "UserPromptSubmit", "PostToolUse"}
