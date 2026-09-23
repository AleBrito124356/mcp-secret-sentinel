"""Command line for mcp-secret-sentinel.

    mcp-secret-sentinel                      run the MCP server over stdio
    mcp-secret-sentinel serve                (same, explicitly)
    mcp-secret-sentinel scan [PATH ...]      scan files, directories or stdin (-)
    mcp-secret-sentinel scan --staged        scan what the next commit would add
    mcp-secret-sentinel scan --range         scan what the next push would publish
    mcp-secret-sentinel scan --history N     scan the last N commits
    mcp-secret-sentinel install-hook [REPO]  block commits that add secrets
    mcp-secret-sentinel patterns             list detectors and allowlist rules

``scan`` exits 0 when clean, 1 when a finding reaches --fail-on, and 2 on
usage errors (bad arguments, a missing path, not a git repository). With no
arguments the console script still starts the stdio server, so existing MCP
client configurations keep working unchanged.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import stat
import sys
from pathlib import Path

from . import __version__, core

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

CLI_MAX_FILES = 5000
HOOK_MARKER = "# mcp-secret-sentinel pre-commit hook"
_FAIL_RANK = {"critical": 0, "high": 1, "medium": 2}


class UsageError(Exception):
    """A problem with how the command was called (exit status 2)."""


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _count(minimum: int):
    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"expected a whole number, got {text!r}") from None
        if value < minimum:
            raise argparse.ArgumentTypeError(f"must be at least {minimum}")
        return value

    return parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-secret-sentinel",
        description=(
            "Scan code for exposed secrets with redacted reports. Without a "
            "command, serve the MCP tools over stdio."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("serve", help="run the MCP server over stdio (the default with no command)")

    scan = sub.add_parser(
        "scan",
        help="scan paths, stdin, staged changes, a commit range or history",
        description=(
            "Scan for secrets. Exit status: 0 clean, 1 findings at or above "
            "--fail-on, 2 usage error."
        ),
    )
    scan.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help=(
            "files or directories to scan (default: .); '-' reads stdin. With "
            "--staged, --range or --history: the repository (default: .)"
        ),
    )
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument(
        "--staged", action="store_true", help="scan only the lines staged for the next commit"
    )
    mode.add_argument(
        "--range",
        dest="git_range",
        nargs="?",
        const="@{upstream}..HEAD",
        metavar="BASE..HEAD",
        help=(
            "scan the commits in BASE..HEAD; without a value, what the next "
            "push would publish (@{upstream}..HEAD)"
        ),
    )
    mode.add_argument(
        "--history", type=_count(1), metavar="N", help="scan the lines added by the last N commits"
    )
    scan.add_argument(
        "--all-branches", action="store_true", help="with --history: every branch, tag and the stash"
    )
    scan.add_argument(
        "--max-commits", type=_count(1), default=200, metavar="N",
        help="with --range: scan at most the N newest commits (default 200)",
    )
    scan.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text", help="report format (default text)"
    )
    scan.add_argument(
        "--fail-on", choices=tuple(_FAIL_RANK), default="medium",
        help="lowest severity that makes the exit status 1 (default medium: any finding)",
    )
    scan.add_argument(
        "--max-findings", type=_count(0), default=None, metavar="N",
        help=(
            f"list at most N findings, most severe first (default {core.DEFAULT_MAX_FINDINGS}, "
            "0 = no limit; SARIF lists everything unless this is set)"
        ),
    )
    scan.add_argument(
        "--max-files", type=_count(1), default=CLI_MAX_FILES, metavar="N",
        help=f"stop a directory scan after N files (default {CLI_MAX_FILES})",
    )
    scan.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")

    hook = sub.add_parser(
        "install-hook",
        help="install a git pre-commit hook that runs 'scan --staged'",
        description=(
            "Write .git/hooks/pre-commit (or the core.hooksPath equivalent) so "
            "that every commit is blocked while its staged lines contain a secret."
        ),
    )
    hook.add_argument("repo", nargs="?", default=".", help="repository (default: .)")
    hook.add_argument(
        "--force", action="store_true",
        help="replace a pre-commit hook written by another tool (it is kept as pre-commit.bak)",
    )
    hook.add_argument(
        "--fail-on", choices=tuple(_FAIL_RANK), default="medium",
        help="lowest severity that blocks the commit (default medium)",
    )

    patterns = sub.add_parser("patterns", help="list the detectors, allowlist rules and suppression markers")
    patterns.add_argument("--format", choices=("text", "json"), default="text")
    return parser


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _display_path(path: Path) -> str:
    """Forward-slash path relative to the working directory when possible
    (what SARIF consumers and editors expect), else absolute."""
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _rebase(result: dict, make_path) -> dict:
    for finding in result["findings"]:
        finding["file"] = make_path(finding["file"])
    return result


def _parse_range(value: str) -> tuple[str, str]:
    if "..." in value:
        raise UsageError(f"--range takes BASE..HEAD (two dots), got {value!r}")
    if ".." in value:
        base, head = value.split("..", 1)
        if not base:
            raise UsageError(f"--range is missing the base revision in {value!r}")
        return base, head or "HEAD"
    return value, "HEAD"


def run_scan(args: argparse.Namespace) -> dict:
    max_findings = args.max_findings
    if max_findings is None:
        max_findings = 0 if args.format == "sarif" else core.DEFAULT_MAX_FINDINGS

    git_mode = args.staged or args.git_range is not None or args.history is not None
    if args.all_branches and args.history is None:
        raise UsageError("--all-branches only applies to --history")
    if git_mode:
        if len(args.paths) > 1:
            raise UsageError("--staged, --range and --history take a single repository path")
        repo = args.paths[0] if args.paths else "."
        if args.staged:
            return core.scan_git_staged(repo, max_findings)
        if args.history is not None:
            return core.scan_git_history(repo, args.history, args.all_branches, max_findings)
        base, head = _parse_range(args.git_range)
        return core.scan_git_range(repo, base, head, args.max_commits, max_findings)

    results = []
    for raw in args.paths or ["."]:
        if raw == "-":
            results.append(core.scan_text(sys.stdin.read(), "<stdin>", 0))
            continue
        target = Path(raw).expanduser()
        if target.is_dir():
            result = core.scan_directory(str(target), args.max_files, 0)
            results.append(_rebase(result, lambda rel, base=target: _display_path(base / rel)))
        elif target.is_file():
            result = core.scan_file(str(target), 0)
            results.append(_rebase(result, lambda name: _display_path(Path(name))))
        else:
            raise UsageError(f"no such file or directory: {raw}")
    return core.merge_results(results, max_findings)


def _severities(result: dict) -> set[str]:
    if result.get("truncated"):
        return set(result["counts_by_severity"])
    return {f["severity"] for f in result["findings"]}


def exit_status(result: dict, fail_on: str) -> int:
    threshold = _FAIL_RANK[fail_on]
    if any(_FAIL_RANK[sev] <= threshold for sev in _severities(result)):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def format_text(result: dict) -> str:
    lines = []
    for f in result["findings"]:
        where = f"{f['file']}:{f['line']}"
        if "commit" in f:
            where += f" @ {f['commit']}"
        lines.append(f"{where}  [{f['severity']}] {f['pattern']}  {f['redacted']}")
        lines.append(f"    {f['advice']}")
    if lines:
        lines.append("")
    lines.append(result["summary"])
    return "\n".join(lines) + "\n"


def render(result: dict, fmt: str, ascii_only: bool) -> str:
    if fmt == "json":
        return json.dumps(result, indent=2, ensure_ascii=ascii_only) + "\n"
    if fmt == "sarif":
        from .sarif import to_sarif

        return json.dumps(to_sarif(result), indent=2, ensure_ascii=ascii_only) + "\n"
    return format_text(result)


# ---------------------------------------------------------------------------
# install-hook
# ---------------------------------------------------------------------------


def hook_script(python: str, fail_on: str) -> str:
    py = shlex.quote(Path(python).as_posix())
    command = f"scan --staged --fail-on {fail_on}"
    return (
        "#!/bin/sh\n"
        f"{HOOK_MARKER}, installed by 'mcp-secret-sentinel install-hook'.\n"
        "# Blocks the commit while its staged lines contain a secret (findings are redacted).\n"
        "# Skip once with 'git commit --no-verify'; delete this file to uninstall.\n"
        f"PY={py}\n"
        'if [ -x "$PY" ]; then\n'
        f'    exec "$PY" -m mcp_secret_sentinel {command}\n'
        "fi\n"
        "if command -v mcp-secret-sentinel >/dev/null 2>&1; then\n"
        f"    exec mcp-secret-sentinel {command}\n"
        "fi\n"
        'echo "secret-sentinel: scanner not found (was $PY). Reinstall the hook with '
        "'mcp-secret-sentinel install-hook' or commit with --no-verify.\" >&2\n"
        "exit 1\n"
    )


def install_hook(repo: str, force: bool = False, fail_on: str = "medium") -> Path:
    core._ensure_git_repo(repo)
    top = core._run_git(repo, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        raise UsageError(f"cannot find the work tree of {repo}: {top.stderr.strip()}")
    toplevel = top.stdout.strip()
    proc = core._run_git(toplevel, "rev-parse", "--git-path", "hooks")
    if proc.returncode != 0:
        raise UsageError(f"cannot locate the hooks directory: {proc.stderr.strip()}")
    hooks_dir = Path(proc.stdout.strip())
    if not hooks_dir.is_absolute():
        hooks_dir = Path(toplevel) / hooks_dir
    hooks_dir.mkdir(parents=True, exist_ok=True)
    target = hooks_dir / "pre-commit"

    if target.exists():
        existing = target.read_text(encoding="utf-8", errors="replace")
        if HOOK_MARKER not in existing:
            if not force:
                raise UsageError(
                    f"{target} already exists and was not written by mcp-secret-sentinel. "
                    "Re-run with --force to replace it (the old hook is kept as "
                    "pre-commit.bak), or call 'mcp-secret-sentinel scan --staged' from it."
                )
            target.replace(hooks_dir / "pre-commit.bak")

    target.write_text(hook_script(sys.executable, fail_on), encoding="utf-8", newline="\n")
    mode = target.stat().st_mode
    target.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


# ---------------------------------------------------------------------------
# patterns
# ---------------------------------------------------------------------------


def format_patterns(info: dict) -> str:
    lines = [f"{info['count']} detectors (+ entropy >= {info['entropy_detector']['threshold_bits_per_char']} bits/char):"]
    width = max(len(p["name"]) for p in info["patterns"])
    for p in info["patterns"]:
        lines.append(f"  {p['name']:<{width}}  {p['severity']}")
    lines.append("")
    lines.append("Allowlist rules:")
    for rule in info["allowlist_rules"]:
        lines.append(f"  {rule['name']}: {rule['description']}")
    lines.append("")
    markers = " / ".join(repr(m) for m in info["inline_suppression"]["markers"])
    lines.append(f"Inline suppression markers: {markers}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _serve() -> int:
    if sys.stdin.isatty():
        print(
            "mcp-secret-sentinel: serving MCP over stdio (Ctrl+C to stop). "
            "Run 'mcp-secret-sentinel --help' for the command line.",
            file=sys.stderr,
        )
    from .server import main as serve_main

    serve_main()
    return EXIT_CLEAN


def _write(text: str) -> None:
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except UnicodeEncodeError:  # a legacy console code page
        sys.stdout.buffer.write(text.encode(sys.stdout.encoding or "ascii", errors="replace"))
        sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv:
        return _serve()
    parser = build_parser()
    args = parser.parse_args(argv)  # exits with status 2 on bad arguments
    try:
        if args.command in (None, "serve"):
            return _serve()
        if args.command == "patterns":
            info = core.list_patterns()
            _write(json.dumps(info, indent=2) + "\n" if args.format == "json" else format_patterns(info))
            return EXIT_CLEAN
        if args.command == "install-hook":
            target = install_hook(args.repo, args.force, args.fail_on)
            _write(
                f"Installed the pre-commit hook at {target.as_posix()}.\n"
                "Commits are now blocked while their staged lines contain a secret "
                f"(severity {args.fail_on} or higher). Skip once with 'git commit --no-verify'.\n"
            )
            return EXIT_CLEAN

        result = run_scan(args)
        status = exit_status(result, args.fail_on)
        if args.output:
            Path(args.output).write_text(render(result, args.format, ascii_only=False), encoding="utf-8")
            print(result["summary"], file=sys.stderr)
        else:
            # JSON and SARIF on stdout are pure ASCII, so no console code page can break them.
            _write(render(result, args.format, ascii_only=args.format != "text"))
        return status
    except (UsageError, ValueError) as exc:
        print(f"mcp-secret-sentinel: error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
