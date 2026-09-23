"""End-to-end tests of the MCP server over real stdio.

The server is spawned as ``python -m mcp_secret_sentinel.server`` and driven
by the official SDK client (``stdio_client`` + ``ClientSession``), which
exists in both mcp 1.x and 2.x — so the same test proves the server works on
whichever major is installed. One server process serves every call; the
individual tests assert on the recorded results.

Skipped entirely when the mcp package is not installed.
"""

import json
import os
import sys
from importlib.metadata import version as dist_version

import pytest

pytest.importorskip("mcp")

import anyio  # noqa: E402  (installed with mcp)
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from _fixtures import (  # noqa: E402
    GENERIC_LINE,
    GENERIC_VALUE,
    ROOT,
    SLACK_HOOK_LINE,
    SLACK_HOOK_SECRET,
    STRIPE_LINE,
    STRIPE_SECRET,
    TWILIO_KEY,
    git,
    init_repo,
)

EXPECTED_TOOLS = {
    "scan_text",
    "scan_file",
    "scan_directory",
    "scan_git_staged",
    "scan_git_history",
    "scan_git_range",
    "list_patterns",
}
RAW_SECRETS = [GENERIC_VALUE, SLACK_HOOK_SECRET, STRIPE_SECRET, TWILIO_KEY]


def _attr(obj, camel: str, snake: str):
    """mcp 1.x exposes camelCase attributes, mcp 2.x snake_case ones."""
    return getattr(obj, camel) if hasattr(obj, camel) else getattr(obj, snake)


def _text(result) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


def _payload(result) -> dict:
    assert not _attr(result, "isError", "is_error"), _text(result)
    return json.loads(_text(result))


@pytest.fixture(scope="module")
def session(tmp_path_factory):
    work = tmp_path_factory.mktemp("stdio")

    secret_file = work / "settings.py"
    secret_file.write_text("DEBUG = True\n" + SLACK_HOOK_LINE + "\n", encoding="utf-8")

    tree = work / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "billing.py").write_text("import os\n" + STRIPE_LINE + "\n", encoding="utf-8")
    (tree / "README.md").write_text("# nothing to see\n", encoding="utf-8")

    staged = init_repo(work / "staged-repo")
    (staged / "notify.py").write_text("import os\n\n" + SLACK_HOOK_LINE + "\n", encoding="utf-8")
    git(staged, "add", "notify.py")

    history = init_repo(work / "history-repo")
    (history / "config.ini").write_text("[app]\ntwilio = " + TWILIO_KEY + "\n", encoding="utf-8")
    git(history, "add", "config.ini")
    git(history, "commit", "-q", "-m", "add config")

    ranged = init_repo(work / "range-repo")
    (ranged / "a.txt").write_text("hello\n", encoding="utf-8")
    git(ranged, "add", "a.txt")
    git(ranged, "commit", "-q", "-m", "base")
    (ranged / "notify.py").write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    git(ranged, "add", "notify.py")
    git(ranged, "commit", "-q", "-m", "unpushed")

    plain = work / "plain"
    plain.mkdir()

    calls = {
        "scan_text": ("scan_text", {"text": "x = 1\n" + GENERIC_LINE, "source_name": "snippet.py"}),
        "scan_file": ("scan_file", {"path": str(secret_file)}),
        "scan_directory": ("scan_directory", {"path": str(tree)}),
        "scan_git_staged": ("scan_git_staged", {"repo_path": str(staged)}),
        "scan_git_history": ("scan_git_history", {"repo_path": str(history), "max_commits": 5}),
        "scan_git_range": ("scan_git_range", {"repo_path": str(ranged), "base": "HEAD~1"}),
        "range_no_upstream": ("scan_git_range", {"repo_path": str(ranged)}),
        "scan_text_capped": (
            "scan_text",
            {"text": "\n".join([GENERIC_LINE, SLACK_HOOK_LINE, STRIPE_LINE]), "max_findings": 1},
        ),
        "list_patterns": ("list_patterns", {}),
        "missing_file": ("scan_file", {"path": str(work / "missing.txt")}),
        "not_a_repo": ("scan_git_staged", {"repo_path": str(plain)}),
    }

    env = _server_env(work)
    return anyio.run(_drive, ["-m", "mcp_secret_sentinel.server"], env, work, calls)


def _server_env(work) -> dict:
    return {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        # Keep git from walking up out of the temp dir into a real repository.
        "GIT_CEILING_DIRECTORIES": str(work),
    }


async def _drive(args: list, env: dict, work, calls: dict) -> dict:
    """Start the server with *args*, initialize, list tools, run *calls*."""
    params = StdioServerParameters(command=sys.executable, args=args, env=env, cwd=str(ROOT))
    with anyio.fail_after(90), open(work / "server-stderr.log", "a", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as client:
                init = await client.initialize()
                tools = await client.list_tools()
                results = {}
                for key, (name, arguments) in calls.items():
                    results[key] = await client.call_tool(name, arguments)
                return {"init": init, "tools": tools.tools, "results": results}


def test_initialize_reports_server_and_instructions(session):
    init = session["init"]
    info = _attr(init, "serverInfo", "server_info")
    assert info.name == "mcp-secret-sentinel"
    assert "scan_git_staged" in (init.instructions or "")


def test_lists_every_tool_with_read_only_annotations(session):
    tools = {tool.name: tool for tool in session["tools"]}
    assert set(tools) == EXPECTED_TOOLS
    for tool in tools.values():
        assert tool.description
        annotations = tool.annotations
        assert annotations is not None, tool.name
        assert _attr(annotations, "readOnlyHint", "read_only_hint") is True
        assert _attr(annotations, "destructiveHint", "destructive_hint") is False
        assert _attr(annotations, "openWorldHint", "open_world_hint") is False


def test_scan_text_over_stdio(session):
    payload = _payload(session["results"]["scan_text"])
    assert payload["clean"] is False
    (finding,) = payload["findings"]
    assert (finding["file"], finding["line"]) == ("snippet.py", 2)
    assert finding["pattern"] == "Generic secret assignment"


def test_scan_file_over_stdio(session):
    payload = _payload(session["results"]["scan_file"])
    (finding,) = payload["findings"]
    assert finding["line"] == 2
    assert finding["pattern"] == "Slack incoming webhook"


def test_scan_directory_over_stdio(session):
    payload = _payload(session["results"]["scan_directory"])
    assert payload["files_scanned"] == 2
    assert [f["file"] for f in payload["findings"]] == ["src/billing.py"]


def test_scan_git_staged_over_stdio(session):
    payload = _payload(session["results"]["scan_git_staged"])
    (finding,) = payload["findings"]
    assert (finding["file"], finding["line"]) == ("notify.py", 3)


def test_scan_git_history_over_stdio(session):
    payload = _payload(session["results"]["scan_git_history"])
    (finding,) = payload["findings"]
    assert (finding["file"], finding["line"]) == ("config.ini", 2)
    assert finding["commit"]


def test_scan_git_range_over_stdio(session):
    payload = _payload(session["results"]["scan_git_range"])
    (finding,) = payload["findings"]
    assert (finding["file"], finding["line"]) == ("notify.py", 1)
    assert payload["commits_scanned"] == 1
    no_upstream = session["results"]["range_no_upstream"]
    assert _attr(no_upstream, "isError", "is_error") is True
    assert "origin/main" in _text(no_upstream)


def test_max_findings_over_stdio(session):
    payload = _payload(session["results"]["scan_text_capped"])
    assert payload["truncated"] is True
    assert payload["total_findings"] == 3
    assert [f["pattern"] for f in payload["findings"]] == ["Stripe live key"]
    assert payload["counts_by_severity"] == {"critical": 1, "high": 2}


def test_console_entry_without_arguments_still_serves_mcp(tmp_path):
    """`mcp-secret-sentinel` with no arguments is what MCP client configs run:
    it must keep starting the stdio server now that the CLI exists."""
    calls = {"scan_text": ("scan_text", {"text": GENERIC_LINE})}
    session = anyio.run(_drive, ["-m", "mcp_secret_sentinel"], _server_env(tmp_path), tmp_path, calls)
    assert {tool.name for tool in session["tools"]} == EXPECTED_TOOLS
    assert _payload(session["results"]["scan_text"])["clean"] is False


def test_list_patterns_over_stdio(session):
    payload = _payload(session["results"]["list_patterns"])
    assert payload["count"] == len(payload["patterns"]) >= 18


def test_errors_come_back_as_tool_errors_with_the_reason(session):
    missing = session["results"]["missing_file"]
    assert _attr(missing, "isError", "is_error") is True
    assert "File not found" in _text(missing)
    not_repo = session["results"]["not_a_repo"]
    assert _attr(not_repo, "isError", "is_error") is True
    assert "Not a git repository" in _text(not_repo)


def test_no_raw_secret_crosses_the_wire(session):
    wire = "".join(_text(result) for result in session["results"].values())
    for secret in RAW_SECRETS:
        assert secret not in wire


def test_sdk_shim_matches_installed_major():
    from mcp_secret_sentinel import server

    assert server.SDK_MAJOR == int(dist_version("mcp").split(".")[0])
