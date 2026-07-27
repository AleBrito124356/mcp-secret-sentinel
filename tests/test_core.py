"""Tests for core.py — run with pytest; no mcp dependency required.

GOLDEN RULE honored throughout: no literal in this file carries a realistic
secret format. Every positive fixture is assembled at RUNTIME by string
concatenation, so secret scanners (including this repo's own final
verification grep) never match the test suite itself.
"""

import json
import string
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp_secret_sentinel import core  # noqa: E402  (path set up above)

# ---------------------------------------------------------------------------
# Runtime-built fixtures (concatenation only — see module docstring)
# ---------------------------------------------------------------------------

GH_CLASSIC = "gh" + "p_" + "A1b2C3d4" * 5
GH_OAUTH = "gh" + "o_" + "E5f6G7h8" * 5
GH_SERVER = "gh" + "s_" + "I9j0K1l2" * 5
GH_FINE = "github" + "_pat_" + "11AABBCC22DD" + "_" + "m3N4o5P6" * 6
OPENAI_KEY = "sk" + "-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2"
ANTHROPIC_KEY = "sk" + "-ant-" + "api03-Qq1Ww2Ee3Rr4Tt5Yy6Uu7"
NVIDIA_KEY = "nv" + "api-" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8"
AWS_KEY_ID = "AK" + "IA" + "J5QZK7M3N9P2R4T6"
AWS_DOC_KEY = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"  # AWS documentation sample
AWS_SECRET_VALUE = "wJalr" + "XUtnFEMIK7MDENG" + "bPxRfi" + "CYabcdKEY9"
AWS_SECRET_LINE = "aws" + "_secret_access_key = " + '"' + AWS_SECRET_VALUE + '"'
STRIPE_SECRET = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_RESTRICTED = "rk" + "_live_" + "8fD40IrMzmXEbtuU2aeq8ed1"
SLACK_TOKEN = "xo" + "xb-" + "1234567890-ABCdefGHIjkl"
SLACK_HOOK = (
    "https://"
    + "hooks."
    + "slack"
    + ".com/services/"
    + "T0A1B2C3D"
    + "/B9Z8Y7X6W"
    + "/"
    + "Qw9Rt8Yu7Io6Pl5Kj4Hg3Fd2"
)
DISCORD_HOOK = (
    "https://"
    + "discord"
    + ".com/api/web"
    + "hooks/"
    + "123456789012345678"
    + "/"
    + "aB3dE6gH9" * 4
)
GOOGLE_KEY = "AI" + "za" + "SyAbCdEfGhIjKlMnOpQrStUvWxYz0123456"
JWT_TOKEN = (
    "ey"
    + "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    + "."
    + "ey"
    + "JzdWIiOiIxMjM0NTY3ODkwIn0"
    + "."
    + "dGVzdF9z"
    + "aWdfZm9vYmFy"
)
PRIVATE_KEY_HEADER = "-----BEGIN RSA " + "PRIV" + "ATE KEY-----"
CONN_POSTGRES = "postgres" + "://dbadmin:" + "s3cr3tP4ss" + "@db.internal:5432/prod"
CONN_MYSQL = "mysql" + "://root:" + "t0pS3cret9" + "@10.0.0.5/app"
CONN_MONGO = "mongodb" + "+srv://appuser:" + "m0ng0P4wd7x" + "@cluster0.internal.net/db"
CONN_AMQP = "amqp" + "://svc:" + "gu3stP4ss77" + "@rabbit.internal:5672/"
CONN_REDIS = "redis" + "://:" + "r3d1sP4ssX9" + "@cache.internal:6379/0"
TWILIO_KEY = "SK" + "0123456789abcdef" * 2
TWILIO_SID = "AC" + "fedcba9876543210" * 2
GENERIC_VALUE = "hunter2plus7extra"
GENERIC_LINE = "pass" + 'word = "' + GENERIC_VALUE + '"'
ENV_VALUE = "sup3rS3cretV4l99"
ENV_LINE = "DB_PASSW" + "ORD=" + ENV_VALUE
ENTROPY_VALUE = string.ascii_uppercase + string.digits  # 36 distinct chars
ENTROPY_LINE = 'payload_blob = "' + ENTROPY_VALUE + '"'

# (case_id, line to scan, expected pattern name, sensitive value that must
#  never appear in the output)
POSITIVE_CASES = [
    ("github-classic", 'gh_auth = "' + GH_CLASSIC + '"', "GitHub token", GH_CLASSIC),
    ("github-oauth", 'value = "' + GH_OAUTH + '"', "GitHub token", GH_OAUTH),
    ("github-server", 'value = "' + GH_SERVER + '"', "GitHub token", GH_SERVER),
    ("github-fine-grained", 'value = "' + GH_FINE + '"', "GitHub fine-grained PAT", GH_FINE),
    ("openai", 'client = OpenAI(api_key="' + OPENAI_KEY + '")', "OpenAI API key", OPENAI_KEY),
    ("anthropic", 'cfg = "' + ANTHROPIC_KEY + '"', "Anthropic API key", ANTHROPIC_KEY),
    ("nvidia", 'nim = "' + NVIDIA_KEY + '"', "NVIDIA API key", NVIDIA_KEY),
    ("aws-key-id", 'aws_key = "' + AWS_KEY_ID + '"', "AWS access key ID", AWS_KEY_ID),
    ("aws-secret", AWS_SECRET_LINE, "AWS secret access key", AWS_SECRET_VALUE),
    ("stripe-live", 'stripe.api_key = "' + STRIPE_SECRET + '"', "Stripe live key", STRIPE_SECRET),
    ("stripe-restricted", 'key = "' + STRIPE_RESTRICTED + '"', "Stripe live key", STRIPE_RESTRICTED),
    ("slack-token", 'client = WebClient(bot="' + SLACK_TOKEN + '")', "Slack token", SLACK_TOKEN),
    ("slack-webhook", 'url = "' + SLACK_HOOK + '"', "Slack incoming webhook", SLACK_HOOK[8:]),
    ("discord-webhook", 'notify = "' + DISCORD_HOOK + '"', "Discord webhook", DISCORD_HOOK[8:]),
    ("google-api-key", 'maps = "' + GOOGLE_KEY + '"', "Google API key", GOOGLE_KEY),
    ("jwt", 'bearer = "' + JWT_TOKEN + '"', "JSON Web Token", JWT_TOKEN),
    ("private-key", PRIVATE_KEY_HEADER, "Private key material", PRIVATE_KEY_HEADER),
    ("conn-postgres", 'db = "' + CONN_POSTGRES + '"', "Connection string with credentials", CONN_POSTGRES),
    ("conn-mysql", 'db = "' + CONN_MYSQL + '"', "Connection string with credentials", CONN_MYSQL),
    ("conn-mongodb", 'db = "' + CONN_MONGO + '"', "Connection string with credentials", CONN_MONGO),
    ("conn-amqp", 'mq = "' + CONN_AMQP + '"', "Connection string with credentials", CONN_AMQP),
    ("conn-redis", 'cache = "' + CONN_REDIS + '"', "Connection string with credentials", CONN_REDIS),
    ("twilio-key", 'tw = "' + TWILIO_KEY + '"', "Twilio API key", TWILIO_KEY),
    ("twilio-sid", 'sid = "' + TWILIO_SID + '"', "Twilio account SID", TWILIO_SID),
    ("generic-assignment", GENERIC_LINE, "Generic secret assignment", GENERIC_VALUE),
    ("env-assignment", ENV_LINE, "Env-file secret assignment", ENV_VALUE),
]

NEGATIVE_CASES = [
    ("changeme", "pass" + 'word = "changeme"'),
    ("changeme-long", "pass" + 'word = "please-change-me-soon"'),
    ("your-here", "api" + '_key = "your-api-key-here"'),
    ("angle-brackets", 'secret = "<YOUR-SECRET-GOES-HERE>"'),
    ("template-var", 'token = "${API_TOKEN}"'),
    ("env-lookup-py", 'token = os.environ["API_TOKEN"]'),
    ("env-lookup-js", 'const token = "process.env.API_TOKEN"'),
    ("masked-x", 'secret = "XXXXXXXXXXXXXXXXXXXX"'),
    ("masked-stars", 'secret = "********************"'),
    ("masked-prefixed-token", 'gh = "' + "gh" + "p_" + "X" * 36 + '"'),
    ("example-domain", 'db = "' + "postgres" + "://user:pass@" + "example.com/db" + '"'),
    ("aws-doc-example-key", "doc sample key: " + AWS_DOC_KEY),
    ("too-short", "pass" + 'word = "abc123"'),
    ("placeholder", "api" + '_key = "placeholder-key-value"'),
    ("plain-code", "result = compute_totals(rows, options)"),
    ("plain-url", 'url = "https://api.github.com/repos/foo/bar"'),
]


# ---------------------------------------------------------------------------
# Pattern detection (positives)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case_id,line,expected,secret", POSITIVE_CASES, ids=[c[0] for c in POSITIVE_CASES]
)
def test_pattern_detects(case_id, line, expected, secret):
    result = core.scan_text(line, source_name="fixture")
    assert result["clean"] is False
    patterns = [f["pattern"] for f in result["findings"]]
    assert expected in patterns
    for finding in result["findings"]:
        assert finding["severity"] in {"critical", "high", "medium"}
        assert finding["file"] == "fixture"
        assert finding["line"] == 1
        assert finding["redacted"].endswith("chars)")
        assert finding["advice"]
    # Redaction guarantee: the sensitive value never appears in the output.
    assert secret not in json.dumps(result, ensure_ascii=False)


def test_anthropic_key_not_reported_as_openai():
    result = core.scan_text('cfg = "' + ANTHROPIC_KEY + '"')
    assert [f["pattern"] for f in result["findings"]] == ["Anthropic API key"]


def test_specific_pattern_wins_over_generic_and_entropy():
    # Var name contains "token" (generic keyword) and the value is a quoted
    # 20+ char string (entropy candidate) — still exactly one finding.
    result = core.scan_text('gh_token = "' + GH_CLASSIC + '"')
    assert [f["pattern"] for f in result["findings"]] == ["GitHub token"]


# ---------------------------------------------------------------------------
# Allowlist (negatives)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_id,line", NEGATIVE_CASES, ids=[c[0] for c in NEGATIVE_CASES])
def test_allowlist_negatives(case_id, line):
    result = core.scan_text(line)
    assert result["clean"] is True
    assert result["findings"] == []


def test_allowlist_rules_direct():
    assert core.allowlist_rule("short") == "too-short"
    assert core.allowlist_rule("X" * 20) == "masked"
    assert core.allowlist_rule("my-example-value-123") == "example"
    assert core.allowlist_rule("${SOME_TOKEN_VALUE}") == "template-variable"
    assert core.allowlist_rule("os.environ.get default") == "env-lookup"
    assert core.allowlist_rule(ENTROPY_VALUE) is None
    assert core.is_allowlisted(ENTROPY_VALUE) is False


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------


def test_shannon_entropy_math():
    assert core.shannon_entropy("") == 0.0
    assert core.shannon_entropy("aaaa") == 0.0
    assert core.shannon_entropy("ab") == 1.0
    assert core.shannon_entropy(ENTROPY_VALUE) > 4.5


def test_entropy_flags_random_assigned_string():
    result = core.scan_text(ENTROPY_LINE)
    assert result["clean"] is False
    (finding,) = result["findings"]
    assert finding["pattern"] == core.ENTROPY_PATTERN_NAME
    assert finding["severity"] == "medium"
    assert ENTROPY_VALUE not in json.dumps(result, ensure_ascii=False)


def test_entropy_ignores_low_entropy_long_string():
    result = core.scan_text('payload_blob = "' + "a" * 40 + '"')
    assert result["clean"] is True


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def test_redact_format():
    value = "abcdefghijklmnop"
    redacted = core.redact(value)
    assert redacted == "abcd…(16 chars)"
    assert value not in redacted


def test_all_findings_fully_redacted_in_combined_scan():
    text = "\n".join(line for _, line, _, _ in POSITIVE_CASES)
    result = core.scan_text(text)
    dumped = json.dumps(result, ensure_ascii=False)
    assert result["clean"] is False
    for _, _, _, secret in POSITIVE_CASES:
        assert secret not in dumped


# ---------------------------------------------------------------------------
# scan_file
# ---------------------------------------------------------------------------


def test_scan_file_reports_path_and_line(tmp_path):
    target = tmp_path / "settings.py"
    target.write_text("DEBUG = True\n" + 'hook = "' + SLACK_HOOK + '"\n', encoding="utf-8")
    result = core.scan_file(str(target))
    assert result["clean"] is False
    (finding,) = result["findings"]
    assert finding["line"] == 2
    assert finding["pattern"] == "Slack incoming webhook"
    assert Path(finding["file"]).name == "settings.py"


def test_scan_file_missing_raises():
    with pytest.raises(ValueError):
        core.scan_file(str(Path("definitely") / "missing.txt"))


def test_scan_file_skips_binary(tmp_path):
    blob = tmp_path / "data.bin"
    blob.write_bytes(b"\x00\x01\x02" + GH_CLASSIC.encode())
    result = core.scan_file(str(blob))
    assert result["clean"] is True
    assert result["files_scanned"] == 0
    assert "binary" in result["summary"].lower()


def test_scan_file_skips_oversized(tmp_path):
    big = tmp_path / "big.txt"
    big.write_bytes(b"a" * (core.MAX_FILE_BYTES + 1))
    result = core.scan_file(str(big))
    assert result["files_scanned"] == 0
    assert "5 MB" in result["summary"]


# ---------------------------------------------------------------------------
# scan_directory
# ---------------------------------------------------------------------------


def test_scan_directory_excludes_and_finds(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.py").write_text(
        'stripe_key = "' + STRIPE_SECRET + '"\n', encoding="utf-8"
    )
    nested = tmp_path / "node_modules" / "pkg"
    nested.mkdir(parents=True)
    (nested / "index.js").write_text('const k = "' + OPENAI_KEY + '";\n', encoding="utf-8")
    (tmp_path / "vendor.min.js").write_text('var k="' + OPENAI_KEY + '";\n', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"note": "' + GH_OAUTH + '"}\n', encoding="utf-8")
    (tmp_path / ".gitignore").write_text("private_dir/\n*.pem\n", encoding="utf-8")
    ignored_dir = tmp_path / "private_dir"
    ignored_dir.mkdir()
    (ignored_dir / "leak.txt").write_text(GH_SERVER + "\n", encoding="utf-8")
    (tmp_path / "server.pem").write_text(PRIVATE_KEY_HEADER + "\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\x00" + GH_CLASSIC.encode())

    result = core.scan_directory(str(tmp_path))
    assert result["clean"] is False
    assert {f["file"] for f in result["findings"]} == {"src/config.py"}
    assert result["files_scanned"] == 2  # src/config.py + .gitignore itself


def test_scan_directory_max_files(tmp_path):
    for i in range(5):
        (tmp_path / f"file{i}.txt").write_text("hello world\n", encoding="utf-8")
    result = core.scan_directory(str(tmp_path), max_files=2)
    assert result["files_scanned"] == 2
    assert "max_files" in result["summary"]


def test_scan_directory_missing_raises(tmp_path):
    with pytest.raises(ValueError):
        core.scan_directory(str(tmp_path / "nope"))


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> None:
    proc = subprocess.run(
        ["git", "-c", "core.autocrlf=false", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"git {' '.join(args)} failed: {proc.stderr}"


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "tester@example.com")
    _git(repo, "config", "user.name", "Test User")
    _git(repo, "config", "commit.gpgsign", "false")
    return repo


# ---------------------------------------------------------------------------
# scan_git_staged
# ---------------------------------------------------------------------------


def test_scan_git_staged_finds_added_secret(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "notify.py").write_text(
        "import os\n\n" + 'HOOK_URL = "' + SLACK_HOOK + '"\n', encoding="utf-8"
    )
    (repo / "clean.py").write_text("x = 1\n", encoding="utf-8")  # left unstaged
    _git(repo, "add", "notify.py")

    result = core.scan_git_staged(str(repo))
    assert result["clean"] is False
    (finding,) = result["findings"]
    assert finding["file"] == "notify.py"
    assert finding["line"] == 3
    assert finding["pattern"] == "Slack incoming webhook"
    assert SLACK_HOOK[8:] not in json.dumps(result, ensure_ascii=False)


def test_scan_git_staged_clean_when_nothing_staged(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")  # untracked only
    result = core.scan_git_staged(str(repo))
    assert result["clean"] is True
    assert result["files_scanned"] == 0


def test_scan_git_staged_clean_with_safe_staged_file(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "app.py").write_text("def main():\n    return 42\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    result = core.scan_git_staged(str(repo))
    assert result["clean"] is True
    assert result["files_scanned"] == 1


def test_scan_git_staged_rejects_non_repo(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(ValueError):
        core.scan_git_staged(str(plain))
    with pytest.raises(ValueError):
        core.scan_git_staged(str(tmp_path / "missing"))


# ---------------------------------------------------------------------------
# scan_git_history
# ---------------------------------------------------------------------------


def test_scan_git_history_finds_committed_secret(tmp_path):
    repo = _init_repo(tmp_path)
    config = repo / "config.ini"
    config.write_text("[app]\n" + "twilio = " + TWILIO_KEY + "\n", encoding="utf-8")
    _git(repo, "add", "config.ini")
    _git(repo, "commit", "-q", "-m", "add config")
    config.write_text("[app]\ntwilio = FIXED_LATER\n", encoding="utf-8")
    _git(repo, "add", "config.ini")
    _git(repo, "commit", "-q", "-m", "remove secret")

    result = core.scan_git_history(str(repo), max_commits=10)
    assert result["clean"] is False
    hits = [f for f in result["findings"] if f["pattern"] == "Twilio API key"]
    assert hits
    assert hits[0]["file"] == "config.ini"
    assert hits[0]["line"] == 2
    assert all("commit" in h for h in hits)
    assert TWILIO_KEY not in json.dumps(result, ensure_ascii=False)


def test_scan_git_history_empty_repo(tmp_path):
    repo = _init_repo(tmp_path)
    result = core.scan_git_history(str(repo))
    assert result["clean"] is True
    assert result["findings"] == []


# ---------------------------------------------------------------------------
# list_patterns and result shape
# ---------------------------------------------------------------------------


def test_list_patterns_structure():
    info = core.list_patterns()
    assert info["count"] == len(info["patterns"])
    assert info["count"] >= 18
    for entry in info["patterns"]:
        assert set(entry) == {"name", "severity", "advice"}  # no raw regexes
        assert entry["severity"] in {"critical", "high", "medium"}
        assert entry["advice"]
    assert info["entropy_detector"]["threshold_bits_per_char"] == 4.5
    assert info["entropy_detector"]["min_length"] == 20
    assert info["allowlist_rules"]
    for rule in info["allowlist_rules"]:
        assert rule["name"] and rule["description"]


def test_scan_text_clean_shape():
    result = core.scan_text("just some ordinary text\nnothing here\n")
    assert set(result) == {"clean", "findings", "files_scanned", "summary"}
    assert result["clean"] is True
    assert result["findings"] == []
    assert result["files_scanned"] == 1
    assert "clean" in result["summary"].lower()
