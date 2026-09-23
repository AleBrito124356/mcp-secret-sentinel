"""The command line, driven the way people and git hooks run it: as a
subprocess, checking exit codes and every output format."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from _fixtures import (
    GENERIC_LINE,
    GENERIC_VALUE,
    ROOT,
    SLACK_HOOK_LINE,
    SLACK_HOOK_SECRET,
    STRIPE_LINE,
    STRIPE_SECRET,
    git,
    init_repo,
)
from mcp_secret_sentinel import core

# A JWT is the one "medium" detector, used to test --fail-on thresholds.
JWT = "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "c2lnbmF0dXJlX3Rlc3Q"
RAW_SECRETS = [SLACK_HOOK_SECRET, STRIPE_SECRET, GENERIC_VALUE, JWT]


def run_cli(*args: str, cwd: Path, stdin: str | None = None, env: dict | None = None):
    full_env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8", **(env or {})}
    return subprocess.run(
        [sys.executable, "-m", "mcp_secret_sentinel", *args],
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=full_env,
        timeout=120,
    )


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "billing.py").write_text("import os\n" + STRIPE_LINE + "\n", encoding="utf-8")
    (root / "src" / "notify.py").write_text("x = 1\n\n" + SLACK_HOOK_LINE + "\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs" / "auth.md").write_text("Example header:\n\n    Bearer " + JWT + "\n", encoding="utf-8")
    (root / "clean").mkdir()
    (root / "clean" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Exit codes and thresholds
# ---------------------------------------------------------------------------


def test_exit_0_when_clean(project):
    proc = run_cli("scan", "clean", cwd=project)
    assert proc.returncode == 0, proc.stderr
    assert "Clean" in proc.stdout


def test_exit_1_with_findings_and_paths_relative_to_cwd(project):
    proc = run_cli("scan", "src", cwd=project)
    assert proc.returncode == 1
    assert "src/billing.py:2  [critical] Stripe live key" in proc.stdout
    assert "src/notify.py:3  [high] Slack incoming webhook" in proc.stdout
    for secret in RAW_SECRETS:
        assert secret not in proc.stdout


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "does-not-exist"],
        ["scan", "--max-findings", "-1"],
        ["scan", "--format", "xml"],
        ["scan", "--all-branches"],
        ["scan", "--staged", "a", "b"],
        ["scan", "--range", "main...HEAD"],
        ["scan", "--staged"],  # the project is not a git repository
        ["no-such-command"],
    ],
)
def test_exit_2_on_usage_errors(project, args):
    proc = run_cli(*args, cwd=project)
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    assert proc.stderr.strip()


def test_fail_on_threshold(project):
    assert run_cli("scan", "docs", cwd=project).returncode == 1  # medium JWT, default medium
    assert run_cli("scan", "docs", "--fail-on", "high", cwd=project).returncode == 0
    assert run_cli("scan", "src", "--fail-on", "critical", cwd=project).returncode == 1
    assert run_cli("scan", "src/notify.py", "--fail-on", "critical", cwd=project).returncode == 0


def test_threshold_counts_findings_beyond_max_findings(project):
    # The only critical finding sorts first; with --max-findings 1 the high
    # one is not listed but must still count for --fail-on high.
    proc = run_cli("scan", "src", "--max-findings", "1", "--fail-on", "high", "--format", "json", cwd=project)
    result = json.loads(proc.stdout)
    assert proc.returncode == 1
    assert result["truncated"] is True
    assert result["counts_by_severity"] == {"critical": 1, "high": 1}


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------


def test_json_output(project):
    proc = run_cli("scan", ".", "--format", "json", cwd=project)
    result = json.loads(proc.stdout)
    assert result["clean"] is False
    assert {f["file"] for f in result["findings"]} == {"src/billing.py", "src/notify.py", "docs/auth.md"}
    assert result["files_scanned"] == 4


def test_sarif_output_structure(project):
    proc = run_cli("scan", ".", "--format", "sarif", cwd=project)
    assert proc.returncode == 1
    sarif = json.loads(proc.stdout)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    (run,) = sarif["runs"]
    rules = run["tool"]["driver"]["rules"]
    assert rules and len({r["id"] for r in rules}) == len(rules) == len(core.PATTERNS) + 1
    rule_ids = [r["id"] for r in rules]
    assert len(run["results"]) == 3
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
        assert result["level"] in {"error", "warning"}
        (location,) = result["locations"]
        physical = location["physicalLocation"]
        assert physical["region"]["startLine"] >= 1
        assert physical["artifactLocation"]["uri"] in {"src/billing.py", "src/notify.py", "docs/auth.md"}
        assert result["partialFingerprints"]
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["secret-sentinel/json-web-token"] == "warning"
    assert levels["secret-sentinel/stripe-live-key"] == "error"
    for rule in rules:
        assert float(rule["properties"]["security-severity"]) > 0
        assert rule["help"]["text"]


def test_sarif_uri_is_percent_encoded(tmp_path):
    (tmp_path / "my notes").mkdir()
    (tmp_path / "my notes" / "deploy steps.md").write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    sarif = json.loads(run_cli("scan", ".", "--format", "sarif", cwd=tmp_path).stdout)
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "my%20notes/deploy%20steps.md"


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_no_raw_secret_in_any_format(project, fmt, tmp_path):
    out_file = tmp_path / f"report.{fmt}"
    proc = run_cli("scan", ".", "--format", fmt, cwd=project)
    to_file = run_cli("scan", ".", "--format", fmt, "-o", str(out_file), cwd=project)
    assert to_file.returncode == 1
    written = out_file.read_text(encoding="utf-8")
    for secret in RAW_SECRETS:
        assert secret not in proc.stdout
        assert secret not in written
        assert secret not in to_file.stderr


def test_output_file_leaves_stdout_empty_and_summary_on_stderr(project, tmp_path):
    report = tmp_path / "out.sarif"
    proc = run_cli("scan", ".", "--format", "sarif", "--output", str(report), cwd=project)
    assert proc.stdout == ""
    assert "Found 3 potential secret(s)" in proc.stderr
    assert json.loads(report.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_stdin(project):
    proc = run_cli("scan", "-", cwd=project, stdin="nothing\n" + GENERIC_LINE + "\n")
    assert proc.returncode == 1
    assert "<stdin>:2  [high] Generic secret assignment" in proc.stdout


def test_legacy_console_encoding_does_not_crash(project):
    proc = run_cli("scan", "src", cwd=project, env={"PYTHONIOENCODING": "cp437"})
    assert proc.returncode == 1
    assert "Stripe live key" in proc.stdout


def test_patterns_command(project):
    proc = run_cli("patterns", cwd=project)
    assert proc.returncode == 0
    assert f"{len(core.PATTERNS)} detectors" in proc.stdout
    assert "secret-sentinel: ignore" in proc.stdout
    info = json.loads(run_cli("patterns", "--format", "json", cwd=project).stdout)
    assert info["count"] == len(core.PATTERNS)


# ---------------------------------------------------------------------------
# Git modes
# ---------------------------------------------------------------------------


def test_staged_range_and_history_modes(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    repo = init_repo(tmp_path / "repo")
    git(repo, "remote", "add", "origin", str(remote))
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-q", "-m", "init")
    git(repo, "push", "-q", "-u", "origin", "main")

    assert run_cli("scan", "--range", cwd=repo).returncode == 0  # nothing to push

    (repo / "notify.py").write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    git(repo, "add", "notify.py")
    staged = run_cli("scan", "--staged", cwd=repo)
    assert staged.returncode == 1
    assert "notify.py:1  [high] Slack incoming webhook" in staged.stdout

    git(repo, "commit", "-q", "-m", "leak")
    sha = git(repo, "rev-parse", "--short", "HEAD").strip()
    pushed = run_cli("scan", "--range", cwd=repo)
    assert pushed.returncode == 1
    assert f"notify.py:1 @ {sha}" in pushed.stdout
    assert run_cli("scan", str(repo), "--range", "origin/main..HEAD", cwd=tmp_path).returncode == 1
    assert run_cli("scan", "--history", "1", cwd=repo).returncode == 1
    assert run_cli("scan", "--range", "HEAD", cwd=repo).returncode == 0


# ---------------------------------------------------------------------------
# install-hook: a real git commit is blocked, a clean one goes through
# ---------------------------------------------------------------------------


def _commit(repo: Path, message: str):
    return subprocess.run(
        ["git", "-c", "core.autocrlf=false", "commit", "-q", "-m", message],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        timeout=120,
    )


def test_install_hook_blocks_a_secret_and_allows_a_clean_commit(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    repo = init_repo(tmp_path / "repo")
    proc = run_cli("install-hook", cwd=repo)
    assert proc.returncode == 0, proc.stderr
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.is_file()
    assert hook.read_bytes().startswith(b"#!/bin/sh\n")  # LF endings for sh

    (repo / "config.py").write_text("import os\n" + STRIPE_LINE + "\n", encoding="utf-8")
    git(repo, "add", "config.py")
    blocked = _commit(repo, "add billing config")
    assert blocked.returncode != 0
    output = blocked.stdout + blocked.stderr
    assert "config.py:2  [critical] Stripe live key" in output
    assert STRIPE_SECRET not in output
    assert git(repo, "rev-list", "--all").strip() == ""  # nothing was committed

    (repo / "config.py").write_text("import os\nSTRIPE_KEY = os.environ['STRIPE_KEY']\n", encoding="utf-8")
    git(repo, "add", "config.py")
    allowed = _commit(repo, "billing config from the environment")
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr
    assert git(repo, "rev-list", "--count", "HEAD").strip() == "1"


def test_install_hook_respects_foreign_hooks(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    repo = init_repo(tmp_path / "repo")
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    foreign = "#!/bin/sh\necho lint\n"
    (hooks / "pre-commit").write_text(foreign, encoding="utf-8")

    refused = run_cli("install-hook", cwd=repo)
    assert refused.returncode == 2
    assert "--force" in refused.stderr
    assert (hooks / "pre-commit").read_text(encoding="utf-8") == foreign

    forced = run_cli("install-hook", "--force", "--fail-on", "high", cwd=repo)
    assert forced.returncode == 0, forced.stderr
    assert (hooks / "pre-commit.bak").read_text(encoding="utf-8") == foreign
    assert "--fail-on high" in (hooks / "pre-commit").read_text(encoding="utf-8")

    # Re-installing over our own hook needs no --force.
    assert run_cli("install-hook", cwd=repo).returncode == 0


def test_install_hook_follows_core_hooks_path(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    repo = init_repo(tmp_path / "repo")
    git(repo, "config", "core.hooksPath", ".githooks")
    assert run_cli("install-hook", str(repo), cwd=tmp_path).returncode == 0
    assert (repo / ".githooks" / "pre-commit").is_file()


def test_install_hook_outside_a_repository(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    proc = run_cli("install-hook", cwd=tmp_path)
    assert proc.returncode == 2
    assert "Not a git repository" in proc.stderr


# ---------------------------------------------------------------------------
# Bounded responses (core, shared by the MCP tools)
# ---------------------------------------------------------------------------


def test_max_findings_bounds_the_report():
    lines = ["pass" + f'word = "Zq{i:05d}Xw9Lp2Rt"' for i in range(3000)]
    lines += ["STRIPE = '" + STRIPE_SECRET + "'"]
    result = core.scan_text("\n".join(lines))

    assert result["truncated"] is True
    assert result["total_findings"] == 3001
    assert len(result["findings"]) == core.DEFAULT_MAX_FINDINGS
    assert result["findings"][0]["pattern"] == "Stripe live key"  # most severe first
    assert result["counts_by_severity"] == {"critical": 1, "high": 3000}
    assert sum(result["counts_by_pattern"].values()) == 3001
    assert result["top_files"] == [{"file": "input", "findings": 3001}]
    assert "listing the 200 most severe of 3001" in result["summary"]
    assert len(json.dumps(result, ensure_ascii=False).encode("utf-8")) < 100_000

    everything = core.scan_text("\n".join(lines), max_findings=0)
    assert len(everything["findings"]) == 3001
    assert "truncated" not in everything


def test_max_findings_rejects_negative_values():
    with pytest.raises(ValueError):
        core.scan_text("x", max_findings=-1)
