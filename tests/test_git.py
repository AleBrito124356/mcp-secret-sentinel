"""Git scanning against real temporary repositories.

These tests pin down that the git scans read the staged or committed text
itself, whatever the user's or the repository's git config says, and that
git never runs a configured program on our behalf.
"""

import json
import os
import stat
from pathlib import Path

import pytest

from _fixtures import (
    SLACK_HOOK_LINE,
    SLACK_HOOK_SECRET,
    STRIPE_LINE,
    TWILIO_KEY,
    git,
    init_repo,
)
from mcp_secret_sentinel import core


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    return init_repo(tmp_path / "repo")


def _marker_script(tmp_path: Path, name: str, output: str = "") -> tuple[Path, Path]:
    """A shell script that leaves a marker file behind when git runs it."""
    marker = tmp_path / f"{name}-RAN"
    script = tmp_path / f"{name}.sh"
    script.write_text(
        "#!/bin/sh\n" f"echo ran > '{marker.as_posix()}'\n" + (f"echo '{output}'\n" if output else ""),
        encoding="utf-8",
        newline="\n",
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script, marker


def _stage(repo: Path, rel: str, content: str) -> None:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="")
    git(repo, "add", "--", rel)


def _commit(repo: Path, rel: str, content: str, message: str) -> str:
    _stage(repo, rel, content)
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "--short", "HEAD").strip()


def _where(result: dict) -> list[tuple[str, int]]:
    return [(f["file"], f["line"]) for f in result["findings"]]


# ---------------------------------------------------------------------------
# Local config must not change what is scanned
# ---------------------------------------------------------------------------


def test_diff_external_is_ignored_and_never_executed(repo, tmp_path):
    script, marker = _marker_script(tmp_path, "external-diff")
    git(repo, "config", "diff.external", script.as_posix())
    _stage(repo, "notify.py", SLACK_HOOK_LINE + "\n")

    result = core.scan_git_staged(str(repo))

    assert _where(result) == [("notify.py", 1)]
    assert not marker.exists(), "git ran the configured external diff program"


def test_textconv_driver_is_ignored_and_never_executed(repo, tmp_path):
    script, marker = _marker_script(tmp_path, "textconv", output="nothing to see")
    git(repo, "config", "diff.hide.textconv", script.as_posix())
    _commit(repo, ".gitattributes", "*.cfg diff=hide\n", "attributes")
    _stage(repo, "app.cfg", "[billing]\n" + STRIPE_LINE + "\n")

    result = core.scan_git_staged(str(repo))

    assert _where(result) == [("app.cfg", 2)]
    assert not marker.exists(), "git ran the configured textconv filter"


@pytest.mark.parametrize("setting", ["diff.mnemonicPrefix", "diff.noprefix"])
def test_prefix_settings_do_not_change_paths(repo, setting):
    git(repo, "config", setting, "true")
    # A real top-level directory named "b" is what noprefix used to eat.
    _stage(repo, "b/notify.py", "import os\n" + SLACK_HOOK_LINE + "\n")

    assert _where(core.scan_git_staged(str(repo))) == [("b/notify.py", 2)]


def test_diff_relative_does_not_hide_other_directories(repo):
    git(repo, "config", "diff.relative", "true")
    (repo / "docs").mkdir()
    _stage(repo, "src/billing.py", STRIPE_LINE + "\n")

    # Scanning from a subdirectory still covers the whole repository.
    result = core.scan_git_staged(str(repo / "docs"))
    assert _where(result) == [("src/billing.py", 1)]


def test_non_ascii_path_is_reported_verbatim(repo):
    git(repo, "config", "core.quotePath", "true")
    _stage(repo, "configuración.py", SLACK_HOOK_LINE + "\n")

    assert _where(core.scan_git_staged(str(repo))) == [("configuración.py", 1)]


def test_path_with_spaces(repo):
    _stage(repo, "my notes/deploy steps.md", "x\n" + SLACK_HOOK_LINE + "\n")

    assert _where(core.scan_git_staged(str(repo))) == [("my notes/deploy steps.md", 2)]


def test_inter_hunk_context_config_keeps_line_numbers(repo):
    base = "".join(f"line {i}\n" for i in range(1, 11))
    _commit(repo, "a.txt", base, "base")
    git(repo, "config", "diff.interHunkContext", "10")
    lines = base.splitlines()
    lines[1] = "changed 2"
    lines[8] = SLACK_HOOK_LINE
    _stage(repo, "a.txt", "\n".join(lines) + "\n")

    assert _where(core.scan_git_staged(str(repo))) == [("a.txt", 9)]


# ---------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------


def test_added_line_that_looks_like_a_file_header(repo):
    _stage(repo, "a.txt", "++ counter\n" + SLACK_HOOK_LINE + "\n")

    assert _where(core.scan_git_staged(str(repo))) == [("a.txt", 2)]


def test_form_feed_and_crlf_do_not_shift_lines(repo):
    # After a split on \f or U+2028 the fragment starts with "+", which
    # str.splitlines() would have counted as one more added line.
    _stage(repo, "a.txt", "x = 1\f+ 1\r\ny = 2 +z\r\n" + SLACK_HOOK_LINE + "\r\n")

    assert _where(core.scan_git_staged(str(repo))) == [("a.txt", 3)]


def test_binary_files_are_named_in_the_summary(repo):
    (repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00" + SLACK_HOOK_LINE.encode())
    git(repo, "add", "logo.png")
    _stage(repo, "notes.txt", "hello\n")

    result = core.scan_git_staged(str(repo))
    assert result["clean"] is True
    assert "1 binary file(s) not scanned: logo.png" in result["summary"]


def test_unquote_git_path():
    assert core._unquote_git_path('"tab\\there.txt"') == "tab\there.txt"
    assert core._unquote_git_path('"quote\\"d"') == 'quote"d'
    assert core._unquote_git_path('"configuraci\\303\\263n.py"') == "configuración.py"
    assert core._unquote_git_path("plain.txt") == "plain.txt"


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


def test_root_commit_is_scanned_even_with_show_root_off(repo):
    git(repo, "config", "log.showRoot", "false")
    sha = _commit(repo, "config.ini", "twilio = " + TWILIO_KEY + "\n", "root")

    result = core.scan_git_history(str(repo))
    assert [(f["file"], f["line"], f["commit"]) for f in result["findings"]] == [
        ("config.ini", 1, sha)
    ]


def test_all_branches_reaches_commits_outside_head(repo):
    _commit(repo, "README.md", "hello\n", "init")
    git(repo, "checkout", "-q", "-b", "feature")
    sha = _commit(repo, "notify.py", SLACK_HOOK_LINE + "\n", "wip")
    git(repo, "checkout", "-q", "main")

    assert core.scan_git_history(str(repo))["clean"] is True
    result = core.scan_git_history(str(repo), all_branches=True)
    assert [(f["file"], f["commit"]) for f in result["findings"]] == [("notify.py", sha)]


# ---------------------------------------------------------------------------
# scan_git_range — what the next push would publish
# ---------------------------------------------------------------------------


@pytest.fixture
def pushed(tmp_path, monkeypatch):
    """A repository whose first commit is pushed to a local bare remote."""
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    work = init_repo(tmp_path / "work")
    git(work, "remote", "add", "origin", str(remote))
    pushed_sha = _commit(work, "config.ini", "twilio = " + TWILIO_KEY + "\n", "already public")
    git(work, "push", "-q", "-u", "origin", "main")
    return work, pushed_sha


def test_range_scans_only_unpushed_commits(pushed):
    work, pushed_sha = pushed
    new_sha = _commit(work, "notify.py", "import os\n" + SLACK_HOOK_LINE + "\n", "not pushed yet")

    result = core.scan_git_range(str(work))

    assert [(f["file"], f["line"], f["commit"]) for f in result["findings"]] == [
        ("notify.py", 2, new_sha)
    ]
    assert pushed_sha not in json.dumps(result)
    assert result["commits_scanned"] == 1
    assert result["range"] == "@{upstream}..HEAD"
    assert SLACK_HOOK_SECRET not in json.dumps(result)


def test_range_with_nothing_to_push(pushed):
    work, _ = pushed
    result = core.scan_git_range(str(work))
    assert result["clean"] is True
    assert result["commits_scanned"] == 0
    assert "Nothing to scan" in result["summary"]


def test_range_explicit_base_and_head(pushed):
    work, pushed_sha = pushed
    _commit(work, "notify.py", SLACK_HOOK_LINE + "\n", "second")
    result = core.scan_git_range(str(work), base=pushed_sha, head="HEAD~1")
    assert result["commits_scanned"] == 0

    result = core.scan_git_range(str(work), base="origin/main")
    assert result["commits_scanned"] == 1
    assert _where(result) == [("notify.py", 1)]


def test_range_without_upstream_explains_what_to_pass(repo):
    _commit(repo, "a.txt", "x\n", "local only")
    with pytest.raises(ValueError, match="origin/main"):
        core.scan_git_range(str(repo))


@pytest.mark.parametrize("bad", ["--output=/tmp/pwned", "-p", "", "no-such-branch"])
def test_range_rejects_bad_revisions(repo, bad):
    _commit(repo, "a.txt", "x\n", "init")
    with pytest.raises(ValueError):
        core.scan_git_range(str(repo), base=bad)


def test_range_max_commits_is_reported(pushed):
    work, _ = pushed
    for i in range(3):
        _commit(work, f"f{i}.txt", f"{i}\n", f"c{i}")
    result = core.scan_git_range(str(work), max_commits=2)
    assert result["commits_scanned"] == 2
    assert "only the newest 2 of 3 commits" in result["summary"]


def test_git_runs_without_inheriting_stdin(repo, monkeypatch):
    """Regression: an inherited stdin hung the MCP server on Windows."""
    seen = {}
    real_run = core.subprocess.run

    def spy(*args, **kwargs):
        seen["stdin"] = kwargs.get("stdin")
        return real_run(*args, **kwargs)

    monkeypatch.setattr(core.subprocess, "run", spy)
    core.scan_git_staged(str(repo))
    assert seen["stdin"] is core.subprocess.DEVNULL


def test_git_environment_drops_diff_program_overrides(monkeypatch):
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "evil")
    monkeypatch.setenv("GIT_DIFF_OPTS", "--unified=5")
    env = core._git_env()
    assert "GIT_EXTERNAL_DIFF" not in env and "GIT_DIFF_OPTS" not in env
    assert env["GIT_OPTIONAL_LOCKS"] == "0"
    assert os.environ["GIT_EXTERNAL_DIFF"] == "evil"  # caller's env untouched
