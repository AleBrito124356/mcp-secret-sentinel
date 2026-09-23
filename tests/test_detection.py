"""Detection coverage added in 0.2.0: modern token formats, placeholder
syntaxes, credentialed URLs, line numbering, encodings, virtualenv pruning,
inline suppression and redaction.

Same golden rule as the rest of the suite: every value that looks like a
credential is assembled at runtime by concatenation.
"""

import json

import pytest

from _fixtures import GENERIC_LINE, GENERIC_VALUE, ROOT, SLACK_HOOK_LINE, git, init_repo
from mcp_secret_sentinel import core

ALNUM40 = "Ab3dEf6hIj" + "9kLmN0pQr2" + "StU5vWx8yZ" + "a1BcD4eFg7"
HEX64 = "0123456789abcdef" * 4
BECH32 = "QPZRY9X8GF2TVDW0" + "S3JN54KHCE6MUA7L"

OPENAI_PROJECT = "sk" + "-proj-" + ALNUM40 + "_" + ALNUM40[:20] + "-" + ALNUM40[:12]
OPENAI_SVCACCT = "sk" + "-svcacct-" + ALNUM40
OPENAI_ADMIN = "sk" + "-admin-" + ALNUM40[:30] + "_" + ALNUM40[:8]
OPENROUTER = "sk" + "-or-v1-" + HEX64
GITHUB_U2S = "gh" + "u_" + ALNUM40[:36]
GITHUB_REFRESH = "gh" + "r_" + ALNUM40[:36]
GITLAB_PAT = "gl" + "pat-" + "aB3dE6gH9jK2mN5pQ8rS"
GITLAB_DEPLOY = "gl" + "dt-" + "Zx8Cv7Bn6Mm5Ll4Kk3Jj2"
NPM_TOKEN = "np" + "m_" + ALNUM40[:36]
PYPI_TOKEN = "py" + "pi-AgEIcHlwaS5vcmc" + ALNUM40 + ALNUM40
HF_TOKEN = "h" + "f_" + "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh"
TELEGRAM = "123456789" + ":" + "AA" + "H" + ALNUM40[:32]
SENDGRID = "S" + "G." + ALNUM40[:22] + "." + (ALNUM40 + "Qq9")[:43]
GOOGLE_OAUTH = "GOC" + "SPX-" + ALNUM40[:28]
SLACK_APP = "xa" + "pp-1-A0" + ALNUM40[:30]
SLACK_REFRESH = "xo" + "xe.xoxp-1-" + ALNUM40[:30]
GROQ = "gs" + "k_" + (ALNUM40 + ALNUM40)[:52]
DIGITALOCEAN = "do" + "p_v1_" + HEX64
SHOPIFY = "shp" + "at_" + HEX64[:32]
AGE_KEY = "AGE-SECRET" + "-KEY-1" + (BECH32 * 2)[:58]
AZURE_KEY = (ALNUM40 * 3)[:86] + "=="
AZURE_LINE = (
    "DefaultEndpointsProtocol=https;AccountName=acct;Account"
    + "Key="
    + AZURE_KEY
    + ";EndpointSuffix=core.windows.net"
)
AWS_TEMP_KEY = "AS" + "IA" + "J5QZK7M3N9P2R4T6"
URL_PASSWORD = "Pz8w" + "Q4rT7yU2"
CREDENTIAL_URL = "https://" + "deploy:" + URL_PASSWORD + "@nexus.internal.corp/repository/pypi"
TEMPLATED_HOST_PASSWORD = "Sup3r" + "S3cretPw9"
TEMPLATED_HOST_DSN = "postgres" + "://app:" + TEMPLATED_HOST_PASSWORD + "@${DB_HOST}:5432/app"
LOOKALIKE_PASSWORD = "Qz8v" + "N2kLp4Rt"
LOOKALIKE_HOST_DSN = "mysql" + "://root:" + LOOKALIKE_PASSWORD + "@db.examplecorp.net/prod"

# (case id, line, expected pattern, value that must never appear in output)
NEW_POSITIVES = [
    ("openai-project-yaml", "openai: " + OPENAI_PROJECT, "OpenAI API key", OPENAI_PROJECT),
    ("openai-svcacct", "key: " + OPENAI_SVCACCT, "OpenAI API key", OPENAI_SVCACCT),
    ("openai-admin", 'ADMIN = "' + OPENAI_ADMIN + '"', "OpenAI API key", OPENAI_ADMIN),
    ("openrouter", "OPENROUTER=" + OPENROUTER, "OpenRouter API key", OPENROUTER),
    ("github-u2s", "x: " + GITHUB_U2S, "GitHub token", GITHUB_U2S),
    ("github-refresh", "refresh: " + GITHUB_REFRESH, "GitHub token", GITHUB_REFRESH),
    ("gitlab-pat", "gitlab: " + GITLAB_PAT, "GitLab token", GITLAB_PAT),
    ("gitlab-deploy", "deploy_token: " + GITLAB_DEPLOY, "GitLab token", GITLAB_DEPLOY),
    ("npm", "//registry.npmjs.org/:_authToken=" + NPM_TOKEN, "npm access token", NPM_TOKEN),
    ("pypi", "password = " + PYPI_TOKEN, "PyPI API token", PYPI_TOKEN),
    ("huggingface", "hf: " + HF_TOKEN, "Hugging Face token", HF_TOKEN),
    ("telegram", 'bot = Bot("' + TELEGRAM + '")', "Telegram bot token", TELEGRAM),
    ("sendgrid", "sg: " + SENDGRID, "SendGrid API key", SENDGRID),
    ("google-oauth", "client_secret: " + GOOGLE_OAUTH, "Google OAuth client secret", GOOGLE_OAUTH),
    ("slack-app", "app: " + SLACK_APP, "Slack token", SLACK_APP),
    ("slack-refresh", "refresh: " + SLACK_REFRESH, "Slack token", SLACK_REFRESH),
    ("groq", "GROQ=" + GROQ, "Groq API key", GROQ),
    ("digitalocean", "do: " + DIGITALOCEAN, "DigitalOcean token", DIGITALOCEAN),
    ("shopify", "shop: " + SHOPIFY, "Shopify access token", SHOPIFY),
    ("age", AGE_KEY, "age secret key", AGE_KEY),
    ("azure-storage", AZURE_LINE, "Azure storage account key", AZURE_KEY),
    ("aws-temporary", "key: " + AWS_TEMP_KEY, "AWS access key ID", AWS_TEMP_KEY),
    ("url-credentials", "index-url = " + CREDENTIAL_URL, "URL with embedded credentials", URL_PASSWORD),
    (
        "dsn-templated-host",
        'DATABASE_URL = "' + TEMPLATED_HOST_DSN + '"',
        "Connection string with credentials",
        TEMPLATED_HOST_PASSWORD,
    ),
    (
        "dsn-example-lookalike-host",
        "url: " + LOOKALIKE_HOST_DSN,
        "Connection string with credentials",
        LOOKALIKE_PASSWORD,
    ),
]

PLACEHOLDER_NEGATIVES = [
    ("shell-var", "export DB_PASS" + "WORD=$VAULT_DB_PASSWORD"),
    ("shell-command", "API_TO" + "KEN=$(gcloud_auth_print_access_token)"),
    ("powershell-env", "pass" + 'word = "$env:DB_PASSWORD"'),
    ("cmd-env", "pass" + 'word = "%VAULT_DB_PASSWORD%"'),
    ("jinja", "pass" + 'word: "{{ vault_db_password }}"'),
    ("helm", "pass" + 'word: "{{ .Values.db.password }}"'),
    ("jinja-statement", "sec" + 'ret: "{% raw %}abcdefgh{% endraw %}"'),
    ("erb", "pass" + "word: \"<%= ENV['DB_PASSWORD'] %>\""),
    ("ruby-interpolation", "api" + "_key = \"#{ENV['API_KEY']}\""),
    ("python-percent", "pass" + 'word = "%(DB_PASSWORD)s"'),
    ("python-format", "pass" + 'word = "{db_password}"'),
    ("dsn-password-template", 'url = "' + "postgres" + '://app:${DB_PASSWORD}@db.internal:5432/app"'),
    ("dsn-reserved-host", 'url = "' + "postgres" + "://admin:" + "s3cr3tP4ssw0rd" + '@db.example.com/app"'),
    ("url-reserved-host", "https://" + "user:" + "hunter2hunter2" + "@git.example.org/repo.git"),
    ("url-token-template", "https://" + "ci:${CI_JOB_TOKEN}@gitlab.internal/group/repo.git"),
    ("prose-sk", "Use the sk-learn style estimator API for this."),
    ("code-getenv", 'API_SEC' + 'RET = os.getenv("API_SECRET")'),
    ("code-attribute", "DB_PASS" + "WORD = settings.DATABASE_PASSWORD"),
    ("code-subscript", "HOOK_SEC" + "RET = SLACK_HOOK[8:]"),
    ("code-concatenation", "sql = \"pass" + "word='\" + user_pwd + \"'\""),
]


@pytest.mark.parametrize(
    "case_id,line,expected,secret", NEW_POSITIVES, ids=[c[0] for c in NEW_POSITIVES]
)
def test_new_detectors(case_id, line, expected, secret):
    result = core.scan_text(line, source_name="fixture")
    assert [f["pattern"] for f in result["findings"]] == [expected]
    assert secret not in json.dumps(result, ensure_ascii=False)


@pytest.mark.parametrize("case_id,line", PLACEHOLDER_NEGATIVES, ids=[c[0] for c in PLACEHOLDER_NEGATIVES])
def test_placeholder_syntaxes_are_not_findings(case_id, line):
    result = core.scan_text(line)
    assert result["findings"] == [], result["findings"]


def test_allowlist_rule_names_for_new_placeholders():
    assert core.allowlist_rule("$VAULT_DB_PASSWORD") == "shell-variable"
    assert core.allowlist_rule("{{ vault_db_password }}") == "template-expression"
    assert core.allowlist_rule("%(DB_PASSWORD)s") == "format-placeholder"
    # A password that merely starts with "$" is still a password.
    assert core.allowlist_rule("$ecretP4ssw0rd") is None


def test_code_rule_is_narrow_and_only_for_generic_assignments():
    # A password with a bracket in it is still a password...
    assert core.scan_text("pass" + 'word = "Xk9(pq!2Lm"')["findings"]
    # ...and dot-separated vendor tokens are never mistaken for attribute paths.
    sendgrid = core.scan_text("sg: " + SENDGRID)["findings"]
    assert [f["pattern"] for f in sendgrid] == ["SendGrid API key"]
    assert core.allowlist_rule("settings.DB_PASSWORD") == "code-expression"
    assert core.allowlist_rule("settings.DB_PASSWORD", assignment=False) is None


def test_connection_string_redacts_only_the_password():
    result = core.scan_text("url: " + LOOKALIKE_HOST_DSN)
    (finding,) = result["findings"]
    assert finding["redacted"] == LOOKALIKE_PASSWORD[:3] + "…(12 chars)"


def test_new_detectors_have_distinct_names_and_advice():
    names = [p["name"] for p in core.PATTERNS]
    assert len(names) == len(set(names))
    for expected in {case[2] for case in NEW_POSITIVES}:
        assert expected in names
    info = core.list_patterns()
    assert info["count"] == len(core.PATTERNS) >= 30
    assert info["inline_suppression"]["markers"] == list(core.SUPPRESSION_MARKERS)
    assert {"shell-variable", "template-expression", "format-placeholder", "example-host"} <= {
        rule["name"] for rule in info["allowlist_rules"]
    }


# ---------------------------------------------------------------------------
# Line numbers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "separator", ["\f", "\v", "\x1c", "\x85", " ", " "], ids=repr
)
def test_unicode_separators_do_not_shift_line_numbers(separator):
    text = "x = 1" + separator + "y = 2\n" + GENERIC_LINE + "\n"
    (finding,) = core.scan_text(text)["findings"]
    assert finding["line"] == 2


def test_crlf_line_numbers():
    text = "a\r\nb\r\n\r\n" + GENERIC_LINE + "\r\n"
    (finding,) = core.scan_text(text)["findings"]
    assert finding["line"] == 4


# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "codec,prefix",
    [
        ("utf-16", b""),  # Python writes the BOM for plain "utf-16"
        ("utf-16-be", b"\xfe\xff"),
        ("utf-16-le", b""),  # no BOM at all
        ("utf-32", b""),
        ("utf-8-sig", b""),
    ],
)
def test_unicode_encodings_are_scanned(tmp_path, codec, prefix):
    target = tmp_path / "settings.ps1.txt"
    target.write_bytes(prefix + ("# config\r\n" + SLACK_HOOK_LINE + "\r\n").encode(codec))
    result = core.scan_file(str(target))
    assert result["files_scanned"] == 1
    assert [(f["pattern"], f["line"]) for f in result["findings"]] == [("Slack incoming webhook", 2)]


def test_utf8_bom_does_not_hide_a_first_line_assignment(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("DB_PASS" + "WORD=" + "sup3rS3cretV4l99\n", encoding="utf-8-sig")
    (finding,) = core.scan_file(str(env_file))["findings"]
    assert (finding["pattern"], finding["line"]) == ("Env-file secret assignment", 1)


def test_real_binaries_are_still_skipped(tmp_path):
    blob = tmp_path / "image.png"
    blob.write_bytes(bytes(range(256)) * 8 + SLACK_HOOK_LINE.encode())
    result = core.scan_file(str(blob))
    assert result["files_scanned"] == 0
    assert "binary" in result["summary"]


# ---------------------------------------------------------------------------
# Directory walking
# ---------------------------------------------------------------------------


def test_virtualenvs_are_skipped_under_any_name(tmp_path):
    for env_name, marker in [("env", "pyvenv.cfg"), ("py311", "pyvenv.cfg"), ("conda_env", "conda-meta")]:
        env = tmp_path / env_name
        (env / "Lib" / "site-packages" / "pkg").mkdir(parents=True)
        if marker == "conda-meta":
            (env / marker).mkdir()
        else:
            (env / marker).write_text("home = /usr/bin\n", encoding="utf-8")
        for i in range(30):
            (env / "Lib" / "site-packages" / "pkg" / f"m{i}.py").write_text("x = 1\n", encoding="utf-8")
        (env / "leak.py").write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    for cache in (".tox", ".nox", ".mypy_cache", ".pytest_cache"):
        (tmp_path / cache).mkdir()
        (tmp_path / cache / "leak.py").write_text(SLACK_HOOK_LINE + "\n", encoding="utf-8")
    # A plain folder that happens to be called "env" is project code.
    (tmp_path / "config" / "env").mkdir(parents=True)
    (tmp_path / "config" / "env" / "prod.py").write_text(GENERIC_LINE + "\n", encoding="utf-8")

    result = core.scan_directory(str(tmp_path), max_files=20)

    assert [f["file"] for f in result["findings"]] == ["config/env/prod.py"]
    assert result["files_scanned"] == 1
    assert "3 virtualenv/conda environment(s) skipped" in result["summary"]
    assert "max_files" not in result["summary"]


def test_utf16_file_inside_a_tree(tmp_path):
    (tmp_path / "profile.ps1").write_text("$hook = '" + "x" + "'\n" + SLACK_HOOK_LINE, encoding="utf-16")
    result = core.scan_directory(str(tmp_path))
    assert [f["file"] for f in result["findings"]] == ["profile.ps1"]


# ---------------------------------------------------------------------------
# Inline suppression
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "comment",
    ["  # secret-sentinel: ignore", "  // pragma: allowlist secret", "  # Secret-Sentinel:IGNORE (fixture)"],
)
def test_inline_suppression(comment):
    result = core.scan_text("a = 1\n" + GENERIC_LINE + comment + "\n" + SLACK_HOOK_LINE + "\n")
    assert [f["pattern"] for f in result["findings"]] == ["Slack incoming webhook"]
    assert result["suppressed"] == 1
    assert "1 finding(s) suppressed" in result["summary"]


def test_suppression_only_covers_its_own_line():
    result = core.scan_text("# secret-sentinel: ignore\n" + GENERIC_LINE + "\n")
    assert len(result["findings"]) == 1
    assert "suppressed" not in result


def test_suppression_applies_to_staged_lines(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    repo = init_repo(tmp_path / "repo")
    (repo / "fixtures.py").write_text(GENERIC_LINE + "  # pragma: allowlist secret\n", encoding="utf-8")
    git(repo, "add", "fixtures.py")
    result = core.scan_git_staged(str(repo))
    assert result["clean"] is True
    assert result["suppressed"] == 1


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Tr0ub4d!", "Tr…(8 chars)"),
        ("abcdefghijkl", "abc…(12 chars)"),
        ("abcdefghijklmnop", "abcd…(16 chars)"),
        ("x" * 100, "xxxx…(100 chars)"),
        ("abc", "…(3 chars)"),
    ],
)
def test_redaction_never_shows_more_than_a_quarter(value, expected):
    assert core.redact(value) == expected


def test_short_password_is_not_half_revealed():
    (finding,) = core.scan_text("pass" + 'word = "' + "Tr0ub4d!" + '"')["findings"]
    assert finding["redacted"] == "Tr…(8 chars)"
    assert GENERIC_VALUE not in finding["redacted"]


def test_long_lines_scan_in_linear_time():
    """Regression: the entropy candidate regex restarted at every position of
    a word run, so a 100,000-character minified line took over four minutes."""
    import time

    line = "x" * 200_000
    started = time.perf_counter()
    core.scan_text(line + "\n" + "a=" + line)
    assert time.perf_counter() - started < 5


# ---------------------------------------------------------------------------
# Dogfooding
# ---------------------------------------------------------------------------


def test_this_repository_scans_clean():
    result = core.scan_directory(str(ROOT), max_files=2000)
    assert result["clean"] is True, result["findings"]
