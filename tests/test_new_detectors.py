"""Detectors added in 0.3.0: AI providers, LLM tooling and cloud/SaaS tokens
whose leaks grew fastest in 2025 (GitGuardian, State of Secrets Sprawl 2026).

Formats come from the gitleaks, betterleaks and trufflehog rule sets. Same
golden rule as the rest of the suite: every credential-shaped value is
assembled at runtime by concatenation.
"""

import pytest

from mcp_secret_sentinel import core

ALNUM40 = "Ab3dEf6hIj" + "9kLmN0pQr2" + "StU5vWx8yZ" + "a1BcD4eFg7"
LOWER48 = ("ab3de6gh9j" * 5)[:48]
HEX = "0123456789abcdef"
HEX32 = HEX * 2
HEX64 = HEX * 4

XAI = "xa" + "i-" + (ALNUM40 * 2)[:80]
PERPLEXITY = "pp" + "lx-" + (ALNUM40 * 2)[:48]
REPLICATE = "r8" + "_" + ALNUM40[:37]
CEREBRAS = "cs" + "k-" + LOWER48
TOGETHER = "tg" + "p_v1_" + (ALNUM40 * 2)[:43]
LANGSMITH = "ls" + "v2_pt_" + HEX32 + "_" + HEX[:10]
LANGFUSE = "sk" + "-lf-" + "0123abcd-4567-89ab-cdef-0123456789ab"
PINECONE = "pc" + "sk_" + "Ab3dE" + "_" + (ALNUM40 * 2)[:63]
FIRECRAWL = "fc" + "-" + HEX32
TAVILY = "tv" + "ly-dev-" + ALNUM40[:32]
BEDROCK = "AB" + "SK" + (ALNUM40 * 4)[:120]
DEEPSEEK = "sk" + "-" + HEX32
SUPABASE_SECRET = "sb" + "_secret_" + ALNUM40[:31]
SUPABASE_PAT = "sb" + "p_" + (HEX * 3)[:40]
VERCEL = "vc" + "p_" + (ALNUM40 * 2)[:56]
CLOUDFLARE = "cf" + "ut_" + ALNUM40 + HEX[:8]
VAULT = "hv" + "s." + (ALNUM40 * 3)[:95]
DOPPLER = "dp" + ".pt." + ("abc123def4" * 5)[:43]
DATABRICKS = "da" + "pi" + HEX32
GRAFANA = "gl" + "sa_" + ALNUM40[:32] + "_" + HEX[:8]
SENTRY = "sn" + "tryu_" + HEX64
ATLASSIAN = "AT" + "ATT3" + (ALNUM40 * 5)[:186]
LINEAR = "li" + "n_api_" + ALNUM40
NOTION = "nt" + "n_" + "12345678901" + ALNUM40[:35]
POSTMAN = "PM" + "AK-" + (HEX * 2)[:24] + "-" + (HEX * 3)[:34]
PLANETSCALE = "ps" + "cale_tkn_" + ALNUM40
NEON = "na" + "pi_" + (ALNUM40 * 2)[:64]
FLY = "fo" + "1_" + (ALNUM40 * 2)[:43]
RESEND = "re" + "_" + "AbCd2345" + "_" + "AbCdEfGh2345678JkMnPqRsT"
MAILCHIMP = HEX32 + "-us" + "21"
POSTHOG = "ph" + "x_" + (ALNUM40 * 2)[:45]
SQUARE = "sq" + "0atp-" + ALNUM40[:22]

POSITIVES = [
    ("xai", "XAI_KEY: " + XAI, "xAI API key", XAI),
    ("perplexity", "key = " + PERPLEXITY, "Perplexity API key", PERPLEXITY),
    ("replicate", "r: " + REPLICATE, "Replicate API token", REPLICATE),
    ("cerebras", "c: " + CEREBRAS, "Cerebras API key", CEREBRAS),
    ("together", "t: " + TOGETHER, "Together AI API key", TOGETHER),
    ("langsmith", "LANGSMITH=" + LANGSMITH, "LangSmith API key", LANGSMITH),
    ("langfuse", "lf: " + LANGFUSE, "Langfuse secret key", LANGFUSE),
    ("pinecone", "pc: " + PINECONE, "Pinecone API key", PINECONE),
    ("firecrawl", 'FirecrawlApp(api_key="' + FIRECRAWL + '")', "Firecrawl API key", FIRECRAWL),
    ("tavily", "tavily: " + TAVILY, "Tavily API key", TAVILY),
    ("bedrock", "b: " + BEDROCK, "AWS Bedrock API key", BEDROCK),
    ("deepseek", "ds: " + DEEPSEEK, "DeepSeek API key", DEEPSEEK),
    ("supabase-secret", "s: " + SUPABASE_SECRET, "Supabase secret key", SUPABASE_SECRET),
    ("supabase-pat", "s: " + SUPABASE_PAT, "Supabase secret key", SUPABASE_PAT),
    ("vercel", "v: " + VERCEL, "Vercel token", VERCEL),
    ("cloudflare", "cf: " + CLOUDFLARE, "Cloudflare API token", CLOUDFLARE),
    ("vault", "VAULT_TOKEN=" + VAULT, "HashiCorp Vault token", VAULT),
    ("doppler", "d: " + DOPPLER, "Doppler token", DOPPLER),
    ("databricks", "db: " + DATABRICKS, "Databricks token", DATABRICKS),
    ("grafana", "g: " + GRAFANA, "Grafana token", GRAFANA),
    ("sentry", "s: " + SENTRY, "Sentry token", SENTRY),
    ("atlassian", "a: " + ATLASSIAN, "Atlassian API token", ATLASSIAN),
    ("linear", "l: " + LINEAR, "Linear API key", LINEAR),
    ("notion", "n: " + NOTION, "Notion integration token", NOTION),
    ("postman", "p: " + POSTMAN, "Postman API key", POSTMAN),
    ("planetscale", "ps: " + PLANETSCALE, "PlanetScale token", PLANETSCALE),
    ("neon", "n: " + NEON, "Neon API key", NEON),
    ("fly", "FLY_API_TOKEN: " + FLY, "Fly.io token", FLY),
    ("resend", "r: " + RESEND, "Resend API key", RESEND),
    ("mailchimp", "m: " + MAILCHIMP, "Mailchimp API key", MAILCHIMP),
    ("posthog", "p: " + POSTHOG, "PostHog personal API key", POSTHOG),
    ("square", "sq: " + SQUARE, "Square access token", SQUARE),
]


@pytest.mark.parametrize("case_id,line,expected,secret", POSITIVES, ids=[c[0] for c in POSITIVES])
def test_new_detectors(case_id, line, expected, secret):
    result = core.scan_text(line)
    assert [f["pattern"] for f in result["findings"]] == [expected], result
    assert secret not in str(result)


def test_publishable_keys_are_not_secrets():
    publishable = "sb" + "_publishable_" + ALNUM40[:31]
    assert core.scan_text("anon: " + publishable)["clean"]


@pytest.mark.parametrize(
    "line",
    [
        '"matcher": "^(Write|Edit|MultiEdit|NotebookEdit|Bash|mcp__.*)$"',
        'token_pattern = "(?:ghp|gho)_[A-Za-z0-9]{36}"',
        'api_key_regex: "[A-Za-z0-9_-]{40,64}"',
        'secret_format = "(sk|rk)_live_x9Qz7Lm3Pw"',
    ],
)
def test_regex_shaped_values_are_not_secrets(line):
    result = core.scan_text(line)
    assert result["clean"], result["findings"]
    assert core.allowlist_rule(line.split('"')[-2]) == "regex-pattern"


def test_plain_links_are_not_secrets_but_tokens_in_urls_still_are():
    docs = 'Changelog = "https://github.com/AleBrito124356/mcp-secret-sentinel/blob/main/CHANGELOG.md"'
    assert core.scan_text(docs)["clean"]
    with_query = 'callback = "https://api.internal.dev/v1/notify?k=' + ALNUM40 + 'Qz8"'
    assert not core.scan_text(with_query)["clean"]


@pytest.mark.parametrize(
    "value",
    [
        "C:\\Users\\Dev\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\bin\\Codex.exe",
        "C:/Users/Dev/AppData/Local/Programs/Microsoft VS Code/resources/app/out/cli.js",
        "\\\\fileserver\\Shared\\Tools\\QuickBuild\\x64\\Release\\agent.exe",
        "~/Library/Application Support/Claude/extensions/node_modules/srv/dist/index.js",
        "/usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
    ],
)
def test_long_paths_in_configs_are_not_secrets(value):
    assert core.scan_text('NODE_REPL_PATH = "' + value + '"')["clean"]


def test_base64_secret_starting_with_a_slash_is_still_judged():
    value = "/" + "Qx7+Lp2Mz9Rt4Vb8Nk3Hs6Fd1Jw5Cy0Ga=="
    assert core.allowlist_rule(value) is None


def test_regex_rule_never_hides_vendor_formats():
    assert core.allowlist_rule("^" + DEEPSEEK + "$", assignment=False) is None


def test_deepseek_shape_is_not_reported_as_openai():
    (finding,) = core.scan_text("k: " + DEEPSEEK)["findings"]
    assert finding["pattern"] == "DeepSeek API key"


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode()).decode()


def test_base64_encoded_secrets_are_decoded_and_reported():
    dsn_password = "Zq8" + "vN2kLp4Rt"
    dsn = "postgres" + "://app:" + dsn_password + "@db.internal:5432/app"
    manifest = "  DATABASE_URL: " + _b64(dsn)
    (finding,) = core.scan_text(manifest)["findings"]
    assert finding["pattern"] == "Connection string with credentials (base64)"
    assert "base64-encoded" in finding["advice"]
    assert dsn_password not in str(finding) and _b64(dsn) not in str(finding)

    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEow\n"
    (pem_finding,) = core.scan_text("tls.key: " + _b64(pem))["findings"]
    assert pem_finding["pattern"] == "Private key material (base64)"


def test_url_safe_base64_and_redaction_of_the_whole_run():
    import base64

    encoded = base64.urlsafe_b64encode(("token=" + LINEAR + "??>").encode()).decode().rstrip("=")
    result = core.redact_text("x: " + encoded + " end")
    assert result["text"] == "x: [REDACTED:Linear API key (base64)] end"


def test_base64_noise_is_not_reported():
    import base64

    plain = "auth: " + _b64("deploy:" + "not-a-known-format")  # user:pass has no detector
    binary = "png: " + base64.b64encode(bytes(range(256))).decode()
    identifier = "some_really_long_function_name_for_tests()"
    for line in (plain, binary, identifier):
        assert core.scan_text(line)["clean"], line


def test_every_detector_has_a_unique_name_and_actionable_advice():
    names = [p["name"] for p in core.PATTERNS]
    assert len(names) == len(set(names)) >= 64
    for pattern in core.PATTERNS:
        assert pattern["severity"] in core.SEVERITIES
        assert len(pattern["advice"]) > 30, pattern["name"]


def test_new_detectors_stay_linear_on_long_lines():
    import time

    line = "x = '" + "a" * 200_000 + "'"
    start = time.perf_counter()
    core.scan_text(line)
    assert time.perf_counter() - start < 5
