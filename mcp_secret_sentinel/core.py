"""Core scanning logic for mcp-secret-sentinel.

Pure Python stdlib — no third-party imports. All MCP wiring lives in
server.py and the command line in cli.py; everything testable lives here.

Detection layers, in order:

1. Specific regex detectors (``PATTERNS``) — vendor token formats, webhook
   URLs, private key markers, credentialed connection strings, and generic
   assignments in code and dotenv files.
2. A Shannon-entropy detector for quoted strings of 20+ characters assigned
   to variables, flagged at >= 4.5 bits/char when no specific pattern
   already claimed the same span.

Every candidate value passes through a documented allowlist of placeholder
heuristics before being reported. A line that carries an inline
``secret-sentinel: ignore`` (or detect-secrets' ``pragma: allowlist secret``)
comment is counted as suppressed instead of reported. Every reported finding
is redacted: at most the first 4 characters (a quarter of the value for
short secrets) plus the total length. The full secret value never appears in
any output produced by this module.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

MAX_FILE_BYTES = 5 * 1024 * 1024  # scan_file / scan_directory size cap (5 MB)
BINARY_SNIFF_BYTES = 8192          # null-byte heuristic window
ENTROPY_THRESHOLD = 4.5            # bits per character
ENTROPY_MIN_LENGTH = 20            # minimum candidate length
ALLOWLIST_MIN_LENGTH = 8           # values shorter than this are never reported
DEFAULT_MAX_FINDINGS = 200         # findings listed per report (0 = no limit)

ENTROPY_PATTERN_NAME = "High-entropy string"

_SEV_CRITICAL = "critical"
_SEV_HIGH = "high"
_SEV_MEDIUM = "medium"
_SEV_ORDER = {_SEV_CRITICAL: 0, _SEV_HIGH: 1, _SEV_MEDIUM: 2}
SEVERITIES = (_SEV_CRITICAL, _SEV_HIGH, _SEV_MEDIUM)

_ENTROPY_ADVICE = (
    "This looks like a random credential. If it is one, rotate it and load it "
    "from the environment; if it is a hash or a fixture, consider renaming the "
    "variable or replacing the value with an obvious placeholder."
)

# Inline suppression markers, matched anywhere on the line (usually in a
# trailing comment). The second and third are detect-secrets' and gitleaks'
# markers, so files already annotated for those tools need no changes.
SUPPRESSION_MARKERS = ("secret-sentinel: ignore", "pragma: allowlist secret", "gitleaks:allow")
_SUPPRESS_RE = re.compile(
    r"(?i)secret-sentinel:\s*ignore|pragma:\s*allowlist\s+secret|gitleaks:allow"
)

# Tokens made of [A-Za-z0-9_-] can end in "-" or "_", where \b does not fire
# before a quote or a space. This lookahead is the boundary they need.
_TOKEN_END = r"(?![A-Za-z0-9_-])"

# Documentation hosts reserved by RFC 2606 / RFC 6761. A password in a URL
# pointing at one of these is a documentation example, not a leak.
_RESERVED_HOST_RE = re.compile(
    r"(?i)^(?:[a-z0-9-]+\.)*(?:example\.(?:com|net|org)|[a-z0-9-]+\.(?:example|invalid))\.?$"
)


def _reserved_example_host(match: re.Match) -> str | None:
    """Context rule for credentialed URLs: skip documentation hosts only."""
    return "example-host" if _RESERVED_HOST_RE.match(match.group("host")) else None


# ---------------------------------------------------------------------------
# Specific detectors
#
# Each entry: name, compiled regex, severity, advice. Optional "group" points
# at the capture group holding the secret value (default: whole match). The
# allowlist and the redaction both apply to that value only. "assignment"
# marks the generic keyword detectors, which also get the code-expression
# allowlist rule. Optional "skip" is a context rule that receives the match
# and returns a rule name to drop it. Ordered specific-first: later, broader
# patterns are skipped when an earlier match already claimed the same span.
# ---------------------------------------------------------------------------

PATTERNS: list[dict] = [
    {
        "name": "GitHub token",
        # ghp_ personal, gho_ OAuth, ghu_ user-to-server, ghs_ server-to-server,
        # ghr_ refresh token.
        "regex": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Revoke the token in GitHub (Settings -> Developer settings, or the "
            "OAuth/GitHub App that issued it), then load it from an environment "
            "variable or a secrets manager."
        ),
    },
    {
        "name": "GitHub fine-grained PAT",
        "regex": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Revoke the fine-grained token in GitHub settings and rotate it; "
            "keep tokens out of source, in environment variables."
        ),
    },
    {
        "name": "GitLab token",
        # personal access, pipeline trigger, deploy and runner tokens
        "regex": re.compile(r"\b(?:glpat|glptt|gldt|glrt)-[A-Za-z0-9_-]{20,255}" + _TOKEN_END),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Revoke the token in GitLab (User settings -> Access tokens, or the "
            "project's CI/CD / repository settings) and store the replacement "
            "as a masked CI variable or environment variable."
        ),
    },
    {
        "name": "Anthropic API key",
        "regex": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,255}"),
        "severity": _SEV_HIGH,
        "advice": (
            "Rotate the key in the Anthropic Console and read it from the "
            "ANTHROPIC_API_KEY environment variable instead of hardcoding it."
        ),
    },
    {
        "name": "OpenRouter API key",
        "regex": re.compile(r"\bsk-or-v1-[a-f0-9]{64}\b"),
        "severity": _SEV_HIGH,
        "advice": (
            "Delete the key at openrouter.ai/keys and read the replacement from "
            "an environment variable such as OPENROUTER_API_KEY."
        ),
    },
    {
        "name": "xAI API key",
        "regex": re.compile(r"\bxai-[A-Za-z0-9_-]{70,120}" + _TOKEN_END),
        "severity": _SEV_HIGH,
        "advice": (
            "Revoke the key in the xAI console (console.x.ai) and read the "
            "replacement from the XAI_API_KEY environment variable."
        ),
    },
    {
        "name": "Perplexity API key",
        "regex": re.compile(r"\bpplx-[A-Za-z0-9]{48}\b"),
        "severity": _SEV_HIGH,
        "advice": (
            "Revoke the key in Perplexity's API settings and read the "
            "replacement from an environment variable such as PERPLEXITY_API_KEY."
        ),
    },
    {
        "name": "Replicate API token",
        "regex": re.compile(r"\br8_[A-Za-z0-9_-]{37}" + _TOKEN_END),
        "severity": _SEV_HIGH,
        "advice": (
            "Delete the token at replicate.com/account/api-tokens and read the "
            "replacement from REPLICATE_API_TOKEN."
        ),
    },
    {
        "name": "Cerebras API key",
        "regex": re.compile(r"\bcsk-[a-z0-9]{48}\b"),
        "severity": _SEV_HIGH,
        "advice": "Revoke the key in the Cerebras cloud console and load it from CEREBRAS_API_KEY.",
    },
    {
        "name": "Together AI API key",
        "regex": re.compile(r"\btgp_v1_[A-Za-z0-9_-]{43}" + _TOKEN_END),
        "severity": _SEV_HIGH,
        "advice": "Revoke the key in the Together AI dashboard and load it from TOGETHER_API_KEY.",
    },
    {
        "name": "LangSmith API key",
        "regex": re.compile(r"\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b"),
        "severity": _SEV_HIGH,
        "advice": (
            "Delete the key in LangSmith (Settings -> API Keys); traces can "
            "contain prompts and customer data. Load the replacement from LANGSMITH_API_KEY."
        ),
    },
    {
        "name": "Langfuse secret key",
        "regex": re.compile(r"\bsk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
        "severity": _SEV_HIGH,
        "advice": "Rotate the project keys in Langfuse settings and load them from LANGFUSE_SECRET_KEY.",
    },
    {
        "name": "Pinecone API key",
        "regex": re.compile(r"\bpcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63}\b"),
        "severity": _SEV_HIGH,
        "advice": "Delete the key in the Pinecone console (API Keys) and load it from PINECONE_API_KEY.",
    },
    {
        "name": "Firecrawl API key",
        "regex": re.compile(r"\bfc-[a-f0-9]{32}\b"),
        "severity": _SEV_HIGH,
        "advice": "Rotate the key in the Firecrawl dashboard and load it from FIRECRAWL_API_KEY.",
    },
    {
        "name": "Tavily API key",
        "regex": re.compile(r"\btvly-(?:dev-|prod-)?[A-Za-z0-9]{24,48}\b"),
        "severity": _SEV_HIGH,
        "advice": "Rotate the key at app.tavily.com and load it from TAVILY_API_KEY.",
    },
    {
        "name": "AWS Bedrock API key",
        "regex": re.compile(r"\bABSK[A-Za-z0-9+/]{109,269}={0,2}"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Revoke the Bedrock API key in the IAM console (it is tied to an IAM "
            "user) and switch to short-term credentials or an IAM role."
        ),
    },
    {
        "name": "DeepSeek API key",
        # 32 hex characters after sk-. Other OpenAI-compatible providers use
        # the same shape, so the advice does not assume the vendor.
        "regex": re.compile(r"\bsk-[a-f0-9]{32}\b"),
        "severity": _SEV_HIGH,
        "advice": (
            "This sk-<32 hex> key matches DeepSeek's format (and some other "
            "OpenAI-compatible providers). Revoke it in that provider's console "
            "and read the replacement from an environment variable."
        ),
    },
    {
        "name": "OpenAI API key",
        # Project (sk-proj-), service-account (sk-svcacct-) and admin
        # (sk-admin-) keys contain "-" and "_"; legacy user keys do not.
        "regex": re.compile(
            r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,255}" + _TOKEN_END
            + r"|(?!ant-)[A-Za-z0-9]{20,255}\b)"
        ),
        "severity": _SEV_HIGH,
        "advice": (
            "Rotate the key in the OpenAI dashboard and read it from the "
            "OPENAI_API_KEY environment variable instead of hardcoding it."
        ),
    },
    {
        "name": "Groq API key",
        "regex": re.compile(r"\bgsk_[A-Za-z0-9]{40,255}\b"),
        "severity": _SEV_HIGH,
        "advice": (
            "Delete the key in the Groq console and read the replacement from "
            "the GROQ_API_KEY environment variable."
        ),
    },
    {
        "name": "NVIDIA API key",
        "regex": re.compile(r"\bnvapi-[A-Za-z0-9_-]{20,255}"),
        "severity": _SEV_HIGH,
        "advice": (
            "Rotate the key at build.nvidia.com (or NGC) and export it as an "
            "environment variable instead of committing it."
        ),
    },
    {
        "name": "Hugging Face token",
        "regex": re.compile(r"\bhf_[A-Za-z0-9]{34,40}\b"),
        "severity": _SEV_HIGH,
        "advice": (
            "Invalidate the token at huggingface.co/settings/tokens and read the "
            "replacement from the HF_TOKEN environment variable."
        ),
    },
    {
        "name": "AWS access key ID",
        # AKIA: long-term IAM user keys; ASIA: temporary STS credentials.
        "regex": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Deactivate this access key in the AWS IAM console and rotate "
            "credentials. Prefer IAM roles or an AWS credentials profile over "
            "hardcoded keys."
        ),
    },
    {
        "name": "AWS secret access key",
        "regex": re.compile(
            r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{30,255})"
        ),
        "group": 1,
        "severity": _SEV_CRITICAL,
        "advice": (
            "Rotate the secret key in AWS IAM immediately and assume it is "
            "compromised. Use IAM roles or environment variables instead."
        ),
    },
    {
        "name": "Azure storage account key",
        "regex": re.compile(r"AccountKey=([A-Za-z0-9+/]{86}==)"),
        "group": 1,
        "severity": _SEV_CRITICAL,
        "advice": (
            "Rotate the storage account key in the Azure portal (Access keys) "
            "and switch to a managed identity or a SAS token read from the "
            "environment."
        ),
    },
    {
        "name": "Google API key",
        "regex": re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
        "severity": _SEV_HIGH,
        "advice": (
            "Regenerate the key in the Google Cloud Console and add "
            "application restrictions (HTTP referrer / IP) to the replacement."
        ),
    },
    {
        "name": "Google OAuth client secret",
        "regex": re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}" + _TOKEN_END),
        "severity": _SEV_HIGH,
        "advice": (
            "Reset the client secret in Google Cloud Console (APIs & Services -> "
            "Credentials) and load it from the environment."
        ),
    },
    {
        "name": "Stripe live key",
        "regex": re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\b"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Roll the key in the Stripe Dashboard (Developers -> API keys). "
            "Live keys grant access to real payment data."
        ),
    },
    {
        "name": "Shopify access token",
        "regex": re.compile(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b"),
        "severity": _SEV_HIGH,
        "advice": (
            "Rotate the token from the Shopify admin (Apps -> Develop apps) and "
            "keep the replacement in an environment variable."
        ),
    },
    {
        "name": "DigitalOcean token",
        "regex": re.compile(r"\bdo[opr]_v1_[a-f0-9]{64}\b"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Revoke the token in the DigitalOcean control panel (API -> Tokens); "
            "it can create and destroy infrastructure."
        ),
    },
    {
        "name": "SendGrid API key",
        # Issued as SG.<22>.<43>; the bounds are a little looser on purpose.
        "regex": re.compile(r"\bSG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{39,50}" + _TOKEN_END),
        "severity": _SEV_HIGH,
        "advice": (
            "Delete the key in SendGrid (Settings -> API Keys); a leaked key is "
            "used to send spam and phishing from your domain."
        ),
    },
    {
        "name": "npm access token",
        "regex": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Revoke the token with `npm token revoke` or on npmjs.com; with "
            "publish rights it can push malicious versions of your packages."
        ),
    },
    {
        "name": "PyPI API token",
        # Macaroons for pypi.org and test.pypi.org start with these base64 headers.
        "regex": re.compile(
            r"\bpypi-AgE(?:IcHlwaS5vcmc|NdGVzdC5weXBpLm9yZw)[A-Za-z0-9_-]{50,}" + _TOKEN_END
        ),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Remove the token in PyPI (Account settings -> API tokens) and "
            "publish with Trusted Publishing instead of a stored token."
        ),
    },
    {
        "name": "Supabase secret key",
        # New sb_secret_ keys and personal access tokens (sbp_). The
        # sb_publishable_ keys are meant to be public and are not reported.
        "regex": re.compile(r"\bsb_secret_[A-Za-z0-9_-]{31}" + _TOKEN_END + r"|\bsbp_[a-z0-9]{40}\b"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Revoke the key in the Supabase dashboard (Project Settings -> API "
            "Keys, or Account -> Access Tokens): secret keys bypass row level "
            "security. Keep them server-side, in environment variables."
        ),
    },
    {
        "name": "Vercel token",
        "regex": re.compile(r"\bvc[pika]_[A-Za-z0-9_-]{56}" + _TOKEN_END),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Revoke the token in Vercel (Account Settings -> Tokens, or the "
            "integration that issued it); it can redeploy and read project env vars."
        ),
    },
    {
        "name": "Cloudflare API token",
        "regex": re.compile(r"\bcf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8}\b"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Roll the token in the Cloudflare dashboard (My Profile -> API "
            "Tokens) and keep the replacement in CLOUDFLARE_API_TOKEN."
        ),
    },
    {
        "name": "HashiCorp Vault token",
        "regex": re.compile(
            r"\bhvs\.[A-Za-z0-9_-]{90,120}" + _TOKEN_END + r"|\bhvb\.[A-Za-z0-9_-]{138,300}" + _TOKEN_END
        ),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Revoke it with 'vault token revoke' and let the application "
            "authenticate through an auth method (AppRole, Kubernetes, OIDC)."
        ),
    },
    {
        "name": "Doppler token",
        "regex": re.compile(r"(?i)\bdp\.pt\.[a-z0-9]{43}\b"),
        "severity": _SEV_CRITICAL,
        "advice": "Revoke the token in the Doppler dashboard; it unlocks every secret it can read.",
    },
    {
        "name": "Databricks token",
        "regex": re.compile(r"\bdapi[a-f0-9]{32}(?:-\d)?\b"),
        "severity": _SEV_CRITICAL,
        "advice": "Revoke the token in Databricks (User Settings -> Developer -> Access tokens).",
    },
    {
        "name": "Grafana token",
        "regex": re.compile(r"\bglc_[A-Za-z0-9+/]{32,400}={0,3}|\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b"),
        "severity": _SEV_HIGH,
        "advice": "Delete the service account token or Cloud access policy token in Grafana and rotate it.",
    },
    {
        "name": "Sentry token",
        "regex": re.compile(
            r"\bsntryu_[a-f0-9]{64}\b|\bsntrys_eyJpYXQiO[A-Za-z0-9+/=]{20,500}_[A-Za-z0-9+/]{43}"
        ),
        "severity": _SEV_HIGH,
        "advice": "Revoke the token in Sentry (User or Organization Settings -> Auth Tokens).",
    },
    {
        "name": "Atlassian API token",
        "regex": re.compile(r"\bATATT3[A-Za-z0-9_=-]{186}"),
        "severity": _SEV_HIGH,
        "advice": "Revoke the token at id.atlassian.com (Security -> API tokens).",
    },
    {
        "name": "Linear API key",
        "regex": re.compile(r"\blin_api_[A-Za-z0-9]{40}\b"),
        "severity": _SEV_HIGH,
        "advice": "Revoke the key in Linear (Settings -> Security & access -> API) and load it from LINEAR_API_KEY.",
    },
    {
        "name": "Notion integration token",
        "regex": re.compile(r"\bntn_[0-9]{11}[A-Za-z0-9]{35}\b|\bsecret_[A-Za-z0-9]{43}\b"),
        "severity": _SEV_HIGH,
        "advice": "Refresh the integration secret at notion.so/my-integrations and load it from NOTION_TOKEN.",
    },
    {
        "name": "Postman API key",
        "regex": re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
        "severity": _SEV_HIGH,
        "advice": "Revoke the key in Postman (Settings -> API Keys); it reads your collections and environments.",
    },
    {
        "name": "PlanetScale token",
        "regex": re.compile(r"\bpscale_(?:tkn|oauth|pw)_[A-Za-z0-9_=.-]{32,64}"),
        "severity": _SEV_CRITICAL,
        "advice": "Revoke the service token or password in PlanetScale and rotate the database credentials.",
    },
    {
        "name": "Neon API key",
        "regex": re.compile(r"\bnapi_[A-Za-z0-9]{64}\b"),
        "severity": _SEV_CRITICAL,
        "advice": "Revoke the key in the Neon console (Account settings -> API keys).",
    },
    {
        "name": "Fly.io token",
        "regex": re.compile(r"\bfo1_[A-Za-z0-9_-]{43}" + _TOKEN_END + r"|\bfm[12][ar]?_[A-Za-z0-9+/]{100,}={0,3}"),
        "severity": _SEV_CRITICAL,
        "advice": "Revoke it with 'fly tokens revoke' (or in the dashboard); deploy tokens can ship code.",
    },
    {
        "name": "Resend API key",
        "regex": re.compile(r"\bre_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}\b"),
        "severity": _SEV_HIGH,
        "advice": "Delete the key in Resend (API Keys); it sends email from your verified domains.",
    },
    {
        "name": "Mailchimp API key",
        "regex": re.compile(r"\b[a-f0-9]{32}-us\d{1,2}\b"),
        "severity": _SEV_HIGH,
        "advice": "Disable the key in Mailchimp (Account -> Extras -> API keys) and create a new one.",
    },
    {
        "name": "PostHog personal API key",
        "regex": re.compile(r"\bphx_[A-Za-z0-9_-]{41,49}" + _TOKEN_END),
        "severity": _SEV_HIGH,
        "advice": "Revoke the personal API key in PostHog (Settings -> Personal API keys).",
    },
    {
        "name": "Square access token",
        "regex": re.compile(r"\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}" + _TOKEN_END),
        "severity": _SEV_CRITICAL,
        "advice": "Revoke the token in the Square Developer Dashboard; it can move real payments.",
    },
    {
        "name": "Slack token",
        # bot/user/app/config/refresh tokens and app-level xapp- tokens
        "regex": re.compile(r"\b(?:xox[abposre]|xoxe\.xox[bp]|xapp)-[A-Za-z0-9-]{10,255}"),
        "severity": _SEV_HIGH,
        "advice": (
            "Revoke the token from your Slack app management page and store "
            "the replacement in an environment variable."
        ),
    },
    {
        "name": "Slack incoming webhook",
        "regex": re.compile(
            r"\bhooks\.slack\.com/services/T[A-Za-z0-9_]{5,}/B[A-Za-z0-9_]{5,}/[A-Za-z0-9]{16,}"
        ),
        "severity": _SEV_HIGH,
        "advice": (
            "Anyone with this URL can post messages to your workspace. "
            "Regenerate the webhook in your Slack app settings and load the "
            "URL from an environment variable."
        ),
    },
    {
        "name": "Discord webhook",
        "regex": re.compile(
            r"\bdiscord(?:app)?\.com/api/webhooks/\d{10,25}/[A-Za-z0-9_-]{30,255}"
        ),
        "severity": _SEV_HIGH,
        "advice": (
            "Delete and recreate the webhook in the Discord channel settings; "
            "keep the URL in an environment variable."
        ),
    },
    {
        "name": "Telegram bot token",
        "regex": re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}" + _TOKEN_END),
        "severity": _SEV_HIGH,
        "advice": (
            "Revoke the token with @BotFather (/revoke) and read the new one "
            "from an environment variable."
        ),
    },
    {
        "name": "age secret key",
        "regex": re.compile(r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "This key decrypts everything encrypted to its recipient (sops, "
            "age). Generate a new identity, re-encrypt the secrets to it and "
            "remove this one from the repository."
        ),
    },
    {
        "name": "JSON Web Token",
        "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "severity": _SEV_MEDIUM,
        "advice": (
            "JWTs can carry live session credentials and personal data in the "
            "payload. Do not commit real tokens; generate short-lived fixtures "
            "at test time."
        ),
    },
    {
        "name": "Private key material",
        "regex": re.compile(
            r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)? ?PRIVATE KEY(?: BLOCK)?-----"
        ),
        # The matched value is the header, identical for every key: a baseline
        # entry must not accept every private key, so it is tied to the file.
        "fingerprint_per_file": True,
        "severity": _SEV_CRITICAL,
        "advice": (
            "Remove the key from the repository and rotate the key pair. If it "
            "was ever pushed, treat it as compromised — history retains it."
        ),
    },
    {
        "name": "Connection string with credentials",
        # The password is the reported value, so placeholders are judged on
        # the password alone: a templated or "example"-looking host no
        # longer hides a literal password.
        "regex": re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|amqps?|rediss?)://"
            r"[^\s:@/\"']*:([^\s@/\"']+)@(?P<host>[^\s\"'/:?#]*)"
        ),
        "group": 1,
        "skip": _reserved_example_host,
        "severity": _SEV_CRITICAL,
        "advice": (
            "Credentials embedded in connection URLs leak through logs and "
            "shell history. Move the URL to an environment variable and rotate "
            "the password."
        ),
    },
    {
        "name": "URL with embedded credentials",
        "regex": re.compile(
            r"\b(?:https?|ftps?|smtps?)://[^\s:@/\"']+:([^\s@/\"']+)@(?P<host>[^\s\"'/:?#]*)"
        ),
        "group": 1,
        "skip": _reserved_example_host,
        "severity": _SEV_HIGH,
        "advice": (
            "user:password@ in a URL (git remotes, package indexes, webhooks) "
            "is sent and logged in clear text. Use a credential helper or an "
            "environment variable, and rotate the password."
        ),
    },
    {
        "name": "Twilio API key",
        "regex": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        "severity": _SEV_HIGH,
        "advice": (
            "Revoke the API key in the Twilio Console and issue a new one "
            "stored outside source control."
        ),
    },
    {
        "name": "Twilio account SID",
        "regex": re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
        "severity": _SEV_MEDIUM,
        "advice": (
            "Account SIDs are identifiers rather than secrets, but paired with "
            "an auth token they grant API access. Avoid committing them next "
            "to credentials."
        ),
    },
    {
        "name": "Generic secret assignment",
        # keyword = "value" (quoted, value of 8+ chars). Group 1 is the quote
        # character, group 2 the value. Upper bound on the value keeps
        # backtracking linear on pathological lines.
        "regex": re.compile(
            r"(?i)(?:password|passwd|secret|api[_-]?key|token)[\"']?\s*[:=]\s*([\"'])((?:(?!\1).){8,512})\1"
        ),
        "group": 2,
        "assignment": True,
        "severity": _SEV_HIGH,
        "advice": (
            "Move the value to an environment variable or a secrets manager, "
            "and rotate it if it was ever a real credential."
        ),
    },
    {
        "name": "Env-file secret assignment",
        # dotenv-style UPPER_CASE=value lines without quotes. Uppercase-only
        # on purpose: it keeps false positives (e.g. `token = get_token()`)
        # out while still catching the classic committed `.env`.
        "regex": re.compile(
            r"^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)\s*=\s*([^\s\"'#]{8,512})"
        ),
        "group": 1,
        "assignment": True,
        "severity": _SEV_HIGH,
        "advice": (
            "This dotenv-style assignment looks like a real credential. Keep "
            "real values in an untracked .env file (listed in .gitignore) or a "
            "secrets manager, then rotate the value."
        ),
    },
]

# Quoted string of 20+ printable, space-free characters assigned to an
# identifier (bare or itself quoted, as in JSON keys). Candidates feed the
# entropy detector only. The lookbehind makes the identifier start at a word
# boundary. Without it, every position inside a long run of word characters
# was a new start, and the cost was quadratic: one 100,000-character line
# (a minified bundle) took over four minutes.
_ENTROPY_ASSIGN_RE = re.compile(
    r"[\"']?(?<![A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*[\"']?\s*[:=]\s*[\"']([^\"'\s]{20,2048})[\"']"
)

# ---------------------------------------------------------------------------
# Allowlist — placeholder heuristics that suppress a candidate value.
# Each rule: (name, human description, predicate). Order matters: the first
# matching rule wins and is reported by allowlist_rule().
# ---------------------------------------------------------------------------

_MASK_CHARS = set("Xx*.•…")  # X, x, *, ., bullet, ellipsis
_YOUR_HERE_RE = re.compile(r"(?i)your[-_][a-z0-9_-]*here")
# $VAR (upper case, so "$ecretPass" is still a password), $(command),
# PowerShell $env:VAR and cmd.exe %VAR%.
_SHELL_VAR_RE = re.compile(
    r"^(?:\$[A-Z_][A-Z0-9_]*|\$\(.*|\$env:[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$"
)
# Jinja / Ansible / Helm / Go templates / Mustache {{ }}, Jinja {% %},
# ERB and EJS <% %>, Ruby #{ } interpolation.
_TEMPLATE_EXPR_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|<%.*?%>|#\{[^}]*\}")
# Code, not a literal. Kept narrow so that a password with a bracket in it
# ("Xk9(pq!2Lm") is still a password:
#   os.getenv(          a call whose quoted argument cut the value short
#   get_secret()  HOOK[8:]  KEYS[0]     an argument-less call or simple subscript
#   settings.DB_PASSWORD                a dotted attribute path
#   ' + pwd + '         one side of a string concatenation
_CODE_EXPR_RE = re.compile(
    r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*[(\[]$"
    r"|^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\(\)|\[[\w:-]*\])$"
    r"|^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$"
    r"|^\s*['\"`]?\s*\+\s|\s\+\s*['\"`]?\s*$"
)
# A regular expression rather than a literal: anchored ^...$, a group with an
# alternation "(a|b)", a non-capturing/lookaround group "(?:", or a character
# class with a counted quantifier "[a-z]{32}". Hook matchers and token
# patterns in configs look random enough to trip the entropy check.
_REGEX_LIKE_RE = re.compile(r"^\^.*\$$|\(\?[:=!<]|\([^()\s]*\|[^()\s]*\)|\[[^\]\s]+\]\{\d+(?:,\d*)?\}")
# A plain link: no user:password@, no query string, no fragment. Long
# documentation URLs look random; webhook URLs that embed a token have their
# own detectors (Slack, Discord) or carry credentials the URL rules catch.
_PLAIN_URL_RE = re.compile(r"^https?://[^\s@?#]+$")
# A filesystem path: Windows drive or UNC, home- or dot-relative, or a
# /rooted path of plain segments. Long paths in agent configs look random.
# The /rooted form is strict (3+ short segments, no + or =) so that a
# base64 credential that happens to start with "/" is still judged.
_WIN_OR_RELATIVE_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\[^\\\s]|~[\\/]|\.{1,2}[\\/])[^\s\"'<>|?*]*$")
_POSIX_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._@-]{1,40}/){2,}[A-Za-z0-9._@-]{0,40}$")


def _looks_like_path(value: str) -> bool:
    return bool(_WIN_OR_RELATIVE_PATH_RE.match(value) or _POSIX_PATH_RE.match(value))
# Python %(name)s and str.format / f-string {name} as the whole value.
_FORMAT_PLACEHOLDER_RE = re.compile(r"^(?:%\([A-Za-z_][A-Za-z0-9_]*\)[sdirf]|\{[A-Za-z_][A-Za-z0-9_.\[\]'\"]*\})$")


def _mostly_masked(value: str) -> bool:
    """True when >= 80% of the characters are mask characters (X, x, *, .).

    Catches fully masked values and prefixed placeholders alike (a vendor
    token prefix followed by a run of X characters).
    """
    if not value:
        return True
    masked = sum(1 for c in value if c in _MASK_CHARS)
    return masked / len(value) >= 0.8


_ALLOWLIST: list[tuple[str, str, Callable[[str], bool]]] = [
    (
        "too-short",
        f"Values shorter than {ALLOWLIST_MIN_LENGTH} characters — too short to be a real credential.",
        lambda v: len(v) < ALLOWLIST_MIN_LENGTH,
    ),
    (
        "masked",
        "Values made up mostly (>= 80%) of mask characters such as X, x, *, or dots — already redacted placeholders, including vendor prefixes followed by X runs.",
        _mostly_masked,
    ),
    (
        "example",
        "Values containing 'example' in any case — vendor-documented sample keys (such as the AWS docs key ending in EXAMPLE). For credentialed URLs only the password is checked.",
        lambda v: "example" in v.lower(),
    ),
    (
        "placeholder",
        "Values containing the word 'placeholder'.",
        lambda v: "placeholder" in v.lower(),
    ),
    (
        "changeme",
        "Values containing 'changeme' / 'change-me' / 'change_me' — conventional fill-me-in markers.",
        lambda v: any(m in v.lower() for m in ("changeme", "change-me", "change_me")),
    ),
    (
        "your-x-here",
        "Fill-in-the-blank markers shaped like your-...-here (any case, hyphen or underscore separated).",
        lambda v: _YOUR_HERE_RE.search(v) is not None,
    ),
    (
        "angle-brackets",
        "Values wrapped in angle brackets — documentation-style placeholders.",
        lambda v: v.startswith("<") and v.endswith(">"),
    ),
    (
        "template-variable",
        "Values containing a ${...} template variable — the secret is injected elsewhere, not stored here.",
        lambda v: "${" in v,
    ),
    (
        "template-expression",
        "Values containing a template expression: {{ ... }} (Jinja, Ansible, Helm, Go templates), {% ... %}, <% ... %> (ERB/EJS) or #{...} (Ruby).",
        lambda v: _TEMPLATE_EXPR_RE.search(v) is not None,
    ),
    (
        "shell-variable",
        "Values that are only a variable reference: $UPPER_CASE_VAR, $(command), PowerShell $env:VAR or cmd %VAR%.",
        lambda v: _SHELL_VAR_RE.match(v) is not None,
    ),
    (
        "format-placeholder",
        "Values that are only a format placeholder: Python %(name)s or {name}.",
        lambda v: _FORMAT_PLACEHOLDER_RE.match(v) is not None,
    ),
    (
        "env-lookup",
        "Values referencing os.environ or process.env — an environment lookup is the fix, not the leak.",
        lambda v: "os.environ" in v or "process.env" in v,
    ),
    (
        "code-expression",
        "Generic assignments only: values that are code rather than a literal — a call or subscript (os.getenv(...), HOOK[8:]), a dotted attribute path (settings.DB_PASSWORD) or one side of a string concatenation (' + pwd + '). Never applied to vendor token formats, which can themselves contain dots.",
        lambda v: _CODE_EXPR_RE.search(v) is not None,
    ),
    (
        "regex-pattern",
        "Generic assignments only: values shaped like a regular expression — anchored ^...$, an alternation group (a|b), a (?: group, or a character class with a counted quantifier ([a-z]{32}). Hook matchers and token patterns are not credentials.",
        lambda v: _REGEX_LIKE_RE.search(v) is not None,
    ),
    (
        "plain-url",
        "Generic assignments only: a plain http(s) link with no user:password@, query string or fragment, such as a documentation URL.",
        lambda v: _PLAIN_URL_RE.match(v) is not None,
    ),
    (
        "file-path",
        "Generic assignments only: a filesystem path (C:\\..., \\\\server\\..., ~/..., ./..., or a /rooted path of plain segments), as found in agent and tool configs.",
        _looks_like_path,
    ),
]

# Rules that only make sense for the generic detectors (keyword assignments
# and the entropy fallback). A JWT or a SendGrid key is dot-separated and
# would otherwise pass for an attribute path.
_ASSIGNMENT_ONLY_RULES = {"code-expression", "regex-pattern", "plain-url", "file-path"}

# Rules that look at the surrounding match instead of the value alone.
_CONTEXT_RULES: list[tuple[str, str]] = [
    (
        "example-host",
        "Credentialed URLs whose host is a reserved documentation domain (example.com / .net / .org, *.example, *.invalid).",
    ),
]

ALLOWLIST_RULES: list[tuple[str, str]] = [(n, d) for n, d, _ in _ALLOWLIST] + _CONTEXT_RULES


def allowlist_rule(value: str, *, assignment: bool = True) -> str | None:
    """Return the name of the first allowlist rule matching *value*, else None.

    ``assignment=False`` leaves out the rules that only apply to generic
    keyword assignments (see _ASSIGNMENT_ONLY_RULES).
    """
    for name, _description, predicate in _ALLOWLIST:
        if not assignment and name in _ASSIGNMENT_ONLY_RULES:
            continue
        if predicate(value):
            return name
    return None


def is_allowlisted(value: str) -> bool:
    """True when *value* is a placeholder that must not be reported."""
    return allowlist_rule(value) is not None


# ---------------------------------------------------------------------------
# Scan configuration
#
# The defaults are the built-in detectors and nothing else. config.py builds
# a ScanConfig from a project's .secret-sentinel.toml (or the
# [tool.secret-sentinel] table of pyproject.toml): custom rules, disabled
# detectors, value allowlist regexes, excluded paths and a baseline of
# accepted findings.
# ---------------------------------------------------------------------------

# Fingerprints are salted and stretched, so a baseline file committed next to
# the code does not let anyone confirm a guessed short password cheaply.
_FINGERPRINT_ITERATIONS = 20_000


def fingerprint(pattern_name: str, value: str) -> str:
    """Stable, non-reversible id for one secret value seen by one detector.

    It ignores the file and line, so a baselined value stays accepted when
    the code around it moves. PBKDF2-SHA256 with the detector name as salt:
    never the value, never a fast hash of it.
    """
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        b"secret-sentinel/v1:" + pattern_name.encode("utf-8"),
        _FINGERPRINT_ITERATIONS,
    )
    return digest.hex()[:32]


def _glob_regex(pattern: str) -> re.Pattern:
    """Translate a path glob to a regex: ``**`` spans directories, ``*`` and
    ``?`` stay inside one path segment. A pattern without a slash matches the
    file name at any depth, as in .gitignore."""
    pattern = pattern.strip().replace("\\", "/")
    anchored = "/" in pattern.rstrip("/")
    pattern = pattern.lstrip("/")
    if pattern.endswith("/"):
        pattern += "**"
    out = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif char == "*":
            out.append("[^/]*")
            i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(char))
            i += 1
    body = "".join(out)
    prefix = "" if anchored else "(?:.*/)?"
    return re.compile(f"^{prefix}{body}(?:/.*)?$")


@dataclass
class ScanConfig:
    """What a scan looks for and what it accepts. ``ScanConfig()`` is the
    built-in behaviour."""

    patterns: list[dict] = field(default_factory=lambda: list(PATTERNS))
    entropy: bool = True
    allowlist: list[re.Pattern] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    baseline: frozenset[str] = frozenset()
    baseline_path: Path | None = None  # where this project's baseline lives (or would)
    root: Path | None = None     # directory the exclude globs are relative to
    source: str | None = None    # the config file this came from, if any
    fingerprints: bool = False   # add a "fingerprint" to each finding (for baselines)
    _exclude_res: list[re.Pattern] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._exclude_res = [_glob_regex(p) for p in self.exclude_paths if p.strip()]

    @property
    def is_default(self) -> bool:
        return self.source is None and not (
            self.allowlist or self.exclude_paths or self.baseline or not self.entropy
        ) and self.patterns == PATTERNS

    def excludes(self, rel_posix: str) -> bool:
        """True when a path relative to ``root`` matches an exclude glob."""
        return any(rx.match(rel_posix) for rx in self._exclude_res)

    def excludes_path(self, path: Path) -> bool:
        """``excludes`` for an absolute path; paths outside ``root`` never match."""
        if not self._exclude_res or self.root is None:
            return False
        try:
            rel = path.resolve().relative_to(self.root.resolve())
        except (ValueError, OSError):
            return False
        return self.excludes(rel.as_posix())

    def allowlisted(self, value: str) -> bool:
        return any(rx.search(value) for rx in self.allowlist)


DEFAULT_CONFIG = ScanConfig()


# ---------------------------------------------------------------------------
# Entropy & redaction
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Empirical Shannon entropy of *s* in bits per character.

    Computed over the string's own character distribution, so the maximum for
    a string with d distinct characters is log2(d). Practical consequence: a
    candidate needs at least 23 distinct characters to clear the 4.5 bits/char
    threshold — short or repetitive strings can never trigger the detector.
    """
    if not s:
        return 0.0
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in Counter(s).values())


def redact(value: str) -> str:
    """Redact a secret: a short prefix + ellipsis + total length.

    The prefix is at most 4 characters and never more than a quarter of the
    value, so an 8-character password shows 2 characters, not half of it.
    The full value never leaves the scanner in any form.
    """
    shown = min(4, len(value) // 4)
    return f"{value[:shown]}…({len(value)} chars)"


# ---------------------------------------------------------------------------
# Line / text scanning
# ---------------------------------------------------------------------------


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    return any(s < span[1] and span[0] < e for s, e in taken)


# Base64 (standard or URL-safe) runs long enough to hide a credential.
# Kubernetes Secret manifests, Docker auth entries, Basic auth headers and
# encoded PEM keys all store secrets this way. The lookarounds keep the run
# whole, so a token is never split into a fake base64 candidate.
# "=" may precede a run (KEY=<base64>, ?cfg=<base64>); 20,000 characters
# covers an encoded RSA-4096 PEM key.
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,20000}={0,2}(?![A-Za-z0-9+/=_-])")
_B64_NOTE = " It was base64-encoded: that hides it from a casual read, not from anyone who decodes it."


def _decode_b64(candidate: str) -> str | None:
    """The decoded text of a base64 run, or None when it is not printable
    UTF-8 text (binary data, an identifier, a hash)."""
    body = candidate.rstrip("=")
    if len(body) % 4 == 1:
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        if "-" in body or "_" in body:
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(padded, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not text or sum(ch.isprintable() or ch in "\r\n\t" for ch in text) < 0.95 * len(text):
        return None
    return text


def _pattern_hits(
    line: str,
    config: ScanConfig,
    taken: list[tuple[int, int]],
    examined: list[tuple[int, int]],
) -> list[dict]:
    """The regex detectors over one line. Claimed spans go to *taken*, whole
    matches the allowlist dropped go to *examined*."""
    hits: list[dict] = []
    for pat in config.patterns:
        for m in pat["regex"].finditer(line):
            group_index = pat.get("group", 0)
            value = m.group(group_index)
            if not value:
                continue
            span = m.span(group_index)
            if _overlaps(span, taken):
                continue  # a more specific detector already claimed this span
            skip = pat.get("skip")
            rule = allowlist_rule(value, assignment=pat.get("assignment", False))
            if (
                rule is not None
                or (skip is not None and skip(m))
                or config.allowlisted(value)
            ):
                examined.append(m.span())
                continue
            taken.append(span)
            hits.append(
                {
                    "pattern": pat["name"],
                    "severity": pat["severity"],
                    "advice": pat["advice"],
                    "value": value,
                    "span": span,
                    "per_file": pat.get("fingerprint_per_file", False),
                }
            )
    return hits


def _decoded_hits(line: str, config: ScanConfig, taken: list[tuple[int, int]]) -> list[dict]:
    """Decode base64 runs nobody claimed and run the regex detectors over
    the decoded text (one level deep, no entropy: decoded binary noise would
    look random). A hit keeps the decoded value, for redaction and baseline
    fingerprints, and the encoded run's span, so redact_text replaces the
    whole encoded run."""
    hits: list[dict] = []
    for m in _B64_RE.finditer(line):
        span = m.span()
        if _overlaps(span, taken):
            continue
        decoded = _decode_b64(m.group())
        if decoded is None:
            continue
        for inner_line in _split_lines(decoded):
            for hit in _pattern_hits(inner_line, config, [], []):
                hits.append(
                    {
                        **hit,
                        "pattern": hit["pattern"] + " (base64)",
                        "advice": hit["advice"] + _B64_NOTE,
                        "span": span,
                    }
                )
        if hits and hits[-1]["span"] == span:
            taken.append(span)
    return hits


def _scan_line(line: str, config: ScanConfig = DEFAULT_CONFIG) -> list[dict]:
    """Scan a single line; return raw hits: pattern, severity, advice, value
    and the value's span in the line."""
    taken: list[tuple[int, int]] = []
    # Whole matches a detector recognised but the allowlist dropped. The
    # entropy fallback must not re-flag them (for example the full URL of a
    # connection string whose password is a ${VAR}).
    examined: list[tuple[int, int]] = []
    hits = _pattern_hits(line, config, taken, examined)
    hits += _decoded_hits(line, config, taken)
    if not config.entropy:
        return hits
    # Entropy fallback — only for spans no specific pattern claimed.
    for m in _ENTROPY_ASSIGN_RE.finditer(line):
        value = m.group(1)
        span = m.span(1)
        if len(value) < ENTROPY_MIN_LENGTH or _overlaps(span, taken) or _overlaps(span, examined):
            continue
        if allowlist_rule(value) is not None or config.allowlisted(value):
            continue
        if shannon_entropy(value) >= ENTROPY_THRESHOLD:
            taken.append(span)
            hits.append(
                {
                    "pattern": ENTROPY_PATTERN_NAME,
                    "severity": _SEV_MEDIUM,
                    "advice": _ENTROPY_ADVICE,
                    "value": value,
                    "span": span,
                }
            )
    return hits


def _finding(source: str, line_no: int, hit: dict, commit: str | None = None) -> dict:
    entry = {
        "file": source,
        "line": line_no,
        "pattern": hit["pattern"],
        "severity": hit["severity"],
        "redacted": redact(hit["value"]),
        "advice": hit["advice"],
    }
    if commit is not None:
        entry["commit"] = commit
    return entry


class _Collector:
    """Accumulates findings, honouring inline suppression comments and the
    configured baseline."""

    def __init__(self, config: ScanConfig = DEFAULT_CONFIG) -> None:
        self.config = config
        self.findings: list[dict] = []
        self.suppressed = 0
        self.baselined = 0

    def scan(self, source: str, line_no: int, line: str, commit: str | None = None) -> None:
        hits = _scan_line(line, self.config)
        if not hits:
            return
        if _SUPPRESS_RE.search(line):
            self.suppressed += len(hits)
            return
        for hit in hits:
            fp = None
            if self.config.baseline or self.config.fingerprints:
                material = hit["value"]
                if hit.get("per_file"):
                    material += "\0" + str(source).replace("\\", "/").rsplit("/", 1)[-1]
                fp = fingerprint(hit["pattern"], material)
                if fp in self.config.baseline:
                    self.baselined += 1
                    continue
            entry = _finding(source, line_no, hit, commit)
            if self.config.fingerprints:
                entry["fingerprint"] = fp
            self.findings.append(entry)

    def result(self, files_scanned: int, max_findings: int | None) -> dict:
        return _build_result(
            self.findings, files_scanned, self.suppressed, max_findings, self.baselined
        )


def _split_lines(text: str) -> list[str]:
    """Split on "\\n" only, dropping a trailing "\\r" from each line.

    str.splitlines() also breaks on \\f, \\v, \\x1c-\\x1e, \\x85, U+2028 and
    U+2029, which neither git nor editors count as line breaks, so every
    such character would shift the reported line numbers.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def _scan_text_lines(text: str, source: str, collector: _Collector) -> None:
    for line_no, line in enumerate(_split_lines(text), start=1):
        collector.scan(source, line_no, line)


def _check_max_findings(max_findings: int | None) -> None:
    if max_findings is not None and max_findings < 0:
        raise ValueError("max_findings must be 0 (no limit) or a positive number.")


def _build_result(
    findings: list[dict],
    files_scanned: int,
    suppressed: int = 0,
    max_findings: int | None = None,
    baselined: int = 0,
) -> dict:
    """Assemble the standard report.

    With *max_findings* set (0 or None means no limit), only the most severe
    findings are listed. The result then says ``truncated: true`` and carries
    ``total_findings``, ``counts_by_severity``, ``counts_by_pattern`` and
    ``top_files``, so a noisy tree cannot flood the caller's context window
    and nothing is lost from the totals.
    """
    findings = sorted(
        findings,
        key=lambda f: (_SEV_ORDER.get(f["severity"], 9), str(f["file"]), f["line"]),
    )
    total = len(findings)
    if findings:
        counts = Counter(f["severity"] for f in findings)
        parts = ", ".join(f"{counts[sev]} {sev}" for sev in SEVERITIES if counts[sev])
        summary = (
            f"Found {total} potential secret(s) across {files_scanned} scanned "
            f"file(s): {parts}. Do NOT commit or push until these are removed or rotated."
        )
    else:
        summary = f"Clean — no secrets detected in {files_scanned} scanned file(s)."
    truncated = bool(max_findings) and total > max_findings
    result = {
        "clean": not findings,
        "findings": findings[:max_findings] if truncated else findings,
        "files_scanned": files_scanned,
        "summary": summary,
    }
    if suppressed:
        result["suppressed"] = suppressed
    if baselined:
        result["baselined"] = baselined
    result["summary"] += _notes_suffix(result)
    if truncated:
        by_file = Counter(str(f["file"]) for f in findings)
        by_severity = Counter(f["severity"] for f in findings)
        result["truncated"] = True
        result["total_findings"] = total
        result["counts_by_severity"] = {s: by_severity[s] for s in SEVERITIES if by_severity[s]}
        result["counts_by_pattern"] = dict(Counter(f["pattern"] for f in findings).most_common())
        result["top_files"] = [
            {"file": name, "findings": n} for name, n in by_file.most_common(10)
        ]
        result["summary"] += (
            f" [listing the {max_findings} most severe of {total}; see counts_by_severity, "
            "counts_by_pattern and top_files, or raise max_findings]"
        )
    return result


def _notes_suffix(result: dict) -> str:
    """The parenthetical suppression/baseline notes of a summary, so a caller
    that rewrites the summary can keep them."""
    notes = ""
    if result.get("suppressed"):
        notes += (
            f" ({result['suppressed']} finding(s) suppressed by inline ignore comments.)"
        )
    if result.get("baselined"):
        notes += f" ({result['baselined']} finding(s) accepted by the baseline.)"
    return notes


def merge_results(results: list[dict], max_findings: int | None = None) -> dict:
    """Combine several uncapped reports (for example one per CLI path) into
    one, keeping the bracketed notes (skipped files, max_files stops...) of
    each input summary."""
    findings = [f for r in results for f in r["findings"]]
    merged = _build_result(
        findings,
        sum(r["files_scanned"] for r in results),
        sum(r.get("suppressed", 0) for r in results),
        max_findings,
        sum(r.get("baselined", 0) for r in results),
    )
    for r in results:
        start = r["summary"].find(" [")
        if start != -1:
            merged["summary"] += r["summary"][start:]
    return merged


# ---------------------------------------------------------------------------
# Public API: text / file / directory
# ---------------------------------------------------------------------------


def scan_text(
    text: str,
    source_name: str = "input",
    max_findings: int = DEFAULT_MAX_FINDINGS,
    config: ScanConfig = DEFAULT_CONFIG,
) -> dict:
    """Scan a snippet of text for exposed secrets.

    Args:
        text: Raw text to scan (code, config, log output, ...).
        source_name: Label used in each finding's "file" field.
        max_findings: List at most this many findings, most severe first
            (0 = no limit); see _build_result for the summary fields added.

    Returns:
        {"clean": bool, "findings": [...], "files_scanned": 1, "summary": str}
        with every finding redacted, plus "suppressed" when inline comments
        silenced any finding.
    """
    _check_max_findings(max_findings)
    collector = _Collector(config)
    _scan_text_lines(text, source_name, collector)
    return collector.result(1, max_findings)


REDACTION_TEMPLATE = "[REDACTED:{pattern}]"
_PRIVATE_KEY = "Private key material"
# A whole private key block, header to footer, across real newlines or the
# literal "\n" escapes of a JSON string (service-account files). Without a
# footer, everything after the header goes: better too much than a key body.
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----"
    r".*?(?:-----END (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.S,
)


def _redact_key_blocks(text: str, counts: Counter) -> str:
    """Replace every private key block, unless the header's line carries an
    inline suppression marker."""

    def replace(m: re.Match) -> str:
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.start())
        if _SUPPRESS_RE.search(text[line_start : line_end if line_end != -1 else len(text)]):
            return m.group(0)
        counts[_PRIVATE_KEY] += 1
        return REDACTION_TEMPLATE.format(pattern=_PRIVATE_KEY)

    return _PEM_BLOCK_RE.sub(replace, text)


def redact_text(text: str, config: ScanConfig = DEFAULT_CONFIG) -> dict:
    """Return *text* with every detected secret replaced by a marker.

    For logs, stack traces, configs or diffs that have to be shared: with a
    model, in an issue, in chat. Each secret becomes ``[REDACTED:<detector>]``
    and everything else is left byte-for-byte as it was (line endings
    included). A private key goes as a whole block, header to footer, not
    just its header line. Lines with an inline suppression marker are left
    alone, like in a scan, and so are values the baseline accepts.

    Returns:
        {"text": str, "redactions": int, "by_pattern": {name: count}}
    """
    out: list[str] = []
    counts: Counter = Counter()
    if any(p["name"] == _PRIVATE_KEY for p in config.patterns):
        text = _redact_key_blocks(text, counts)
    for chunk in text.split("\n"):
        hits = _scan_line(chunk, config) if chunk else []
        if not hits or _SUPPRESS_RE.search(chunk):
            out.append(chunk)
            continue
        if config.baseline:
            hits = [h for h in hits if fingerprint(h["pattern"], h["value"]) not in config.baseline]
        line = chunk
        boundary = len(chunk) + 1
        for hit in sorted(hits, key=lambda h: h["span"][0], reverse=True):
            start, end = hit["span"]
            if end > boundary:
                continue  # several secrets inside one base64 run: replaced once
            line = line[:start] + REDACTION_TEMPLATE.format(pattern=hit["pattern"]) + line[end:]
            counts[hit["pattern"]] += 1
            boundary = start
        out.append(line)
    return {
        "text": "\n".join(out),
        "redactions": sum(counts.values()),
        "by_pattern": dict(counts.most_common()),
    }


# Byte-order marks, longest first (the UTF-32 LE mark starts with UTF-16 LE's).
_BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
)


def _bomless_utf16(head: bytes) -> str | None:
    """Recognise BOM-less UTF-16 text: mostly-ASCII text has a zero in every
    other byte, which is exactly what the null-byte heuristic trips on."""
    even, odd = head[0::2], head[1::2]
    if len(even) < 2 or len(odd) < 2:
        return None
    even_zero = even.count(0) / len(even)
    odd_zero = odd.count(0) / len(odd)
    if odd_zero >= 0.9 and even_zero <= 0.1:
        return "utf-16-le"
    if even_zero >= 0.9 and odd_zero <= 0.1:
        return "utf-16-be"
    return None


def decode_bytes(data: bytes) -> tuple[str | None, str | None]:
    """Decode file content for scanning: (text, None) or (None, skip reason).

    A byte-order mark decides the codec first (UTF-8, UTF-16, UTF-32), so
    UTF-16 files, such as the default output of Windows PowerShell 5.1's
    ``>`` and ``Out-File``, are scanned instead of being taken for binaries.
    Otherwise a null byte in the first 8 KiB marks a binary, unless the
    bytes look like BOM-less UTF-16.
    """
    for bom, codec in _BOMS:
        if data.startswith(bom):
            return data.decode(codec, errors="replace"), None
    head = data[:BINARY_SNIFF_BYTES]
    if b"\x00" in head:
        codec = _bomless_utf16(head)
        if codec is None:
            return None, "binary file (null byte detected)"
        return data.decode(codec, errors="replace"), None
    return data.decode("utf-8", errors="replace"), None


def _read_text_if_scannable(path: Path) -> tuple[str | None, str | None]:
    """Return (text, None) for scannable files, (None, reason) for skipped ones."""
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        return None, f"file exceeds the 5 MB scan limit ({size} bytes)"
    return decode_bytes(path.read_bytes())


def scan_file(
    path: str, max_findings: int = DEFAULT_MAX_FINDINGS, config: ScanConfig = DEFAULT_CONFIG
) -> dict:
    """Scan one file for exposed secrets.

    UTF-8, UTF-16 and UTF-32 text is decoded (by byte-order mark). Binary
    files (null-byte heuristic on the first 8 KiB) and files over 5 MB are
    skipped, reported via files_scanned=0 and an explanatory summary.

    Raises:
        ValueError: if the path does not point at an existing file.
    """
    _check_max_findings(max_findings)
    target = Path(path).expanduser()
    if not target.is_file():
        raise ValueError(
            f"File not found at {path} — pass an absolute path to an existing file."
        )
    text, skip_reason = _read_text_if_scannable(target)
    if skip_reason is not None:
        return {
            "clean": True,
            "findings": [],
            "files_scanned": 0,
            "summary": f"Skipped {target.name}: {skip_reason}. No text was scanned.",
        }
    collector = _Collector(config)
    _scan_text_lines(text, str(target), collector)
    return collector.result(1, max_findings)


# -- directory scanning ------------------------------------------------------

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    "__pypackages__",
}
LOCKFILE_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "bun.lockb"}


def _is_environment_dir(path: Path) -> bool:
    """A virtualenv or conda env under any name (env/, .env39/, py311/...)."""
    return (path / "pyvenv.cfg").is_file() or (path / "conda-meta").is_dir()


def _load_gitignore_patterns(root: Path) -> list[str]:
    """Best-effort .gitignore support (see _matches_gitignore for limits)."""
    patterns: list[str] = []
    gitignore = root / ".gitignore"
    if gitignore.is_file():
        try:
            for raw in _split_lines(gitignore.read_text(encoding="utf-8", errors="replace")):
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                patterns.append(line)
        except OSError:
            pass
    return patterns


def _matches_gitignore(rel_posix: str, name: str, is_dir: bool, patterns: list[str]) -> bool:
    """Best-effort match of a path against simple .gitignore patterns.

    Supported: plain names (matched against any path component), `*.ext`
    globs, `dir/` directory patterns, and `/anchored` root-relative patterns.
    Deliberately NOT supported (documented limitation): `!` negations,
    `**` recursive globs, and mid-path wildcard semantics. Only the root
    .gitignore is read — nested ones are ignored.
    """
    for pattern in patterns:
        dir_only = pattern.endswith("/")
        cleaned = pattern.rstrip("/")
        if dir_only and not is_dir:
            continue  # files under an ignored dir are handled by pruning the dir
        if cleaned.startswith("/"):
            candidates = [rel_posix]
            cleaned = cleaned.lstrip("/")
        else:
            candidates = [rel_posix, name]
        if any(fnmatch(candidate, cleaned) for candidate in candidates):
            return True
    return False


def _git_file_list(root: Path) -> list[str] | None:
    """Files under *root* that git would publish or could: tracked files plus
    untracked ones that no ignore rule excludes (every .gitignore level,
    negations, .git/info/exclude and the global excludes file). Paths are
    relative to *root*. None when *root* is not inside a git work tree."""
    try:
        inside = _run_git(str(root), "rev-parse", "--is-inside-work-tree")
    except ValueError:  # git is not installed
        return None
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return None
    proc = _run_git(str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if proc.returncode != 0:
        return None
    return sorted(dict.fromkeys(p for p in proc.stdout.split("\0") if p))


def _walk_file_list(root: Path) -> tuple[list[str], int]:
    """Fallback outside git: walk the tree, pruning excluded directories,
    environments and simple root-.gitignore patterns. Returns (paths
    relative to root, environments skipped)."""
    ignore_patterns = _load_gitignore_patterns(root)
    files: list[str] = []
    envs_skipped = 0
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        kept_dirs = []
        for dirname in sorted(dirnames):
            rel = (rel_dir / dirname).as_posix()
            if dirname in EXCLUDED_DIRS or _matches_gitignore(rel, dirname, True, ignore_patterns):
                continue
            if _is_environment_dir(Path(dirpath) / dirname):
                envs_skipped += 1
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in sorted(filenames):
            rel = (rel_dir / filename).as_posix()
            if not _matches_gitignore(rel, filename, False, ignore_patterns):
                files.append(rel)
    return files, envs_skipped


def _prune_git_list(root: Path, files: list[str]) -> tuple[list[str], int]:
    """Apply the same directory rules as the walk to a git file list:
    excluded directory names and environments under any name."""
    env_cache: dict[str, bool] = {}
    kept: list[str] = []
    envs: set[str] = set()
    for rel in files:
        parts = rel.split("/")
        if any(part in EXCLUDED_DIRS for part in parts[:-1]):
            continue
        env_dir = None
        for depth in range(1, len(parts)):
            prefix = "/".join(parts[:depth])
            if prefix not in env_cache:
                env_cache[prefix] = _is_environment_dir(root / prefix)
            if env_cache[prefix]:
                env_dir = prefix
                break
        if env_dir is not None:
            envs.add(env_dir)
            continue
        kept.append(rel)
    return kept, len(envs)


def scan_directory(
    path: str,
    max_files: int = 500,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    config: ScanConfig = DEFAULT_CONFIG,
) -> dict:
    """Recursively scan a directory tree for exposed secrets.

    Inside a git work tree the file list comes from git itself (tracked
    files plus untracked files no ignore rule excludes), so every
    .gitignore, negation and global exclude is honoured exactly. Outside
    git the tree is walked and only simple root-.gitignore patterns apply.

    Either way it skips: .git, node_modules, virtualenvs and conda envs
    under any name (detected by pyvenv.cfg / conda-meta), site-packages,
    __pycache__, tool caches (.tox, .nox, .mypy_cache, .pytest_cache,
    .ruff_cache), dist, build, minified JS bundles, lockfiles, binaries,
    files over 5 MB and paths the config excludes. Findings use
    forward-slash paths relative to *path*.

    Raises:
        ValueError: if the directory does not exist or max_files < 1.
    """
    root = Path(path).expanduser()
    if not root.is_dir():
        raise ValueError(
            f"Directory not found at {path} — pass an absolute path to an existing directory."
        )
    if max_files < 1:
        raise ValueError("max_files must be at least 1.")
    _check_max_findings(max_findings)

    git_files = _git_file_list(root)
    listing_note = None
    if git_files is not None and not git_files:
        # The folder was asked for explicitly but git lists nothing in it: it
        # is ignored (or empty). Walk it instead of calling it clean.
        git_files = None
        listing_note = "git lists no files here (the folder is ignored or empty), so it was walked directly"
    if git_files is not None:
        # Untracked nested repositories are listed as "dir/", submodules as a
        # bare path: git does not look inside either, so walk them.
        nested = [p.rstrip("/") for p in git_files if p.endswith("/") or (root / p).is_dir()]
        nested_set = set(nested)
        files, envs_skipped = _prune_git_list(
            root, [p for p in git_files if p.rstrip("/") not in nested_set]
        )
        for sub in nested:
            sub_files, sub_envs = _walk_file_list(root / sub)
            files += [f"{sub}/{f}" for f in sub_files]
            envs_skipped += sub_envs
        files.sort()
        listing_note = "file list from git: tracked and untracked files, every ignore rule honoured"
        if nested:
            listing_note += f"; {len(nested)} nested repository/submodule folder(s) walked"
    else:
        files, envs_skipped = _walk_file_list(root)

    collector = _Collector(config)
    scanned = 0
    skipped = 0
    excluded = 0
    truncated = False
    for rel in files:
        if scanned >= max_files:
            truncated = True
            break
        filename = rel.rsplit("/", 1)[-1]
        if filename.endswith(".min.js") or filename.endswith(".lock") or filename in LOCKFILE_NAMES:
            skipped += 1
            continue
        target = root / rel
        if config.excludes_path(target):
            excluded += 1
            continue
        if not target.is_file():
            continue  # deleted in the work tree, a submodule, a broken link
        try:
            text, skip_reason = _read_text_if_scannable(target)
        except OSError:
            skipped += 1
            continue
        if skip_reason is not None:
            skipped += 1
            continue
        scanned += 1
        _scan_text_lines(text, rel, collector)

    result = collector.result(scanned, max_findings)
    notes = []
    if skipped:
        notes.append(
            f"{skipped} file(s) skipped (binaries, oversized, lockfiles or minified)"
        )
    if excluded:
        notes.append(f"{excluded} file(s) excluded by {config.source or 'the config'}")
    if envs_skipped:
        notes.append(f"{envs_skipped} virtualenv/conda environment(s) skipped")
    if listing_note:
        notes.append(listing_note)
    if truncated:
        notes.append(f"stopped at max_files={max_files} — results may be incomplete")
    if notes:
        result["summary"] += " [" + "; ".join(notes) + "]"
    return result


# ---------------------------------------------------------------------------
# Git-based scanning
# ---------------------------------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_COMMIT_RE = re.compile(r"^commit ([0-9a-f]{6,40})\b")
_BINARY_RE = re.compile(r"^Binary files (.+) and (.+) differ$")

# Config that is forced on every git call. User and repository config must not
# change what we parse or make git run programs. Each entry is here for a reason:
#   core.quotePath=false     non-ASCII paths come out as UTF-8, not "\303\263"
#   core.fsmonitor=false     the fsmonitor hook is a configurable command
#   diff.noprefix / diff.mnemonicPrefix / diff.relative
#                            paths stay "b/<repo-relative path>" for the whole repo
#   diff.suppressBlankEmpty  an empty line is never a context line
#   diff.submodule=short     submodule changes stay one "Subproject commit" line
#   log.showSignature=false  verifying signatures runs gpg.program
#   log.showRoot=true        the root commit's additions are part of history
#   color.ui=false           no ANSI escapes in the output we parse
_GIT_CONFIG = (
    "core.quotePath=false",
    "core.fsmonitor=false",
    "diff.noprefix=false",
    "diff.mnemonicPrefix=false",
    "diff.relative=false",
    "diff.suppressBlankEmpty=false",
    "diff.submodule=short",
    "log.showSignature=false",
    "log.showRoot=true",
    "color.ui=false",
)

# Flags for every diff/log call: no external diff programs or textconv
# filters (diff.external, diff.<driver>.command/textconv would replace the
# text we scan with their own output), fixed prefixes, zero context.
_DIFF_FLAGS = (
    "--no-ext-diff",
    "--no-textconv",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--no-color",
    "-U0",
    "--inter-hunk-context=0",
)

# Environment variables that change diff output or start programs.
_GIT_ENV_DROP = ("GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS", "GIT_PAGER", "PAGER")


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV_DROP}
    # Read-only tool: never take optional locks (git diff may otherwise
    # rewrite the index to refresh stat data) and never prompt.
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _run_git(repo_path: str, *args: str) -> subprocess.CompletedProcess:
    repo = Path(repo_path).expanduser()
    if not repo.exists():
        raise ValueError(
            f"Path not found: {repo_path} — pass an absolute path to a git repository."
        )
    config_args: list[str] = []
    for item in _GIT_CONFIG:
        config_args += ["-c", item]
    try:
        return subprocess.run(
            ["git", *config_args, "-C", str(repo), *args],
            # Never inherit stdin: under an MCP stdio server it is the protocol
            # pipe. On Windows, duplicating that handle for the child blocks
            # while the server's reader thread is waiting on it (mcp 1.x hangs
            # forever), and a child must never consume protocol bytes anyway.
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_git_env(),
        )
    except FileNotFoundError:
        raise ValueError(
            "git executable not found on PATH — install Git to use the git scans."
        ) from None


def _ensure_git_repo(repo_path: str) -> None:
    proc = _run_git(repo_path, "rev-parse", "--is-inside-work-tree")
    if proc.returncode != 0:
        raise ValueError(
            f"Not a git repository at {repo_path} — pass an absolute path to a "
            f"git repository ({proc.stderr.strip()})."
        )


_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}
_OCTAL_ESCAPE_RE = re.compile(r"[0-3][0-7]{2}")


def _unquote_git_path(name: str) -> str:
    """Decode a path git printed in C-quoted form, such as "tab\\there.txt".

    With core.quotePath=false git still quotes names that contain control
    characters, double quotes or backslashes; octal escapes are raw bytes of
    the UTF-8 name.
    """
    if len(name) < 2 or name[0] != '"' or name[-1] != '"':
        return name
    body = name[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        char = body[i]
        if char == "\\" and i + 1 < len(body):
            if _OCTAL_ESCAPE_RE.match(body, i + 1):
                out.append(int(body[i + 1 : i + 4], 8))
                i += 4
                continue
            if body[i + 1] in _C_ESCAPES:
                out.append(_C_ESCAPES[body[i + 1]])
                i += 2
                continue
        out += char.encode("utf-8", errors="replace")
        i += 1
    return out.decode("utf-8", errors="replace")


def _diff_target(name: str) -> str | None:
    """Repo-relative path from the target side of a diff header, or None."""
    if name.endswith("\t"):  # git appends a tab when the name contains a space
        name = name[:-1]
    name = _unquote_git_path(name)
    if name == "/dev/null":
        return None
    return name[2:] if name.startswith("b/") else name


def _scan_diff(
    diff_text: str, config: ScanConfig = DEFAULT_CONFIG, toplevel: Path | None = None
) -> tuple[_Collector, set[str], list[str]]:
    """Scan unified diff output (git diff / git log -p, -U0), added lines only.

    A small state machine instead of prefix matching, so that file content
    can never be mistaken for a header:

    * header state (after ``diff --git`` or ``commit <hash>``): ``+++ b/…``
      names the file, ``Binary files … differ`` marks a skipped binary.
    * hunk state (after ``@@ -a,b +c,d @@``): exactly ``b`` removed and ``d``
      added lines follow, counted down from the hunk header. Every ``+`` line
      in that window is content, even when it reads ``+++ something``.

    Files the config excludes (globs relative to its root, resolved through
    the repository's *toplevel*) are skipped entirely.

    Returns (collector, files with additions, binary files skipped).
    """
    collector = _Collector(config)
    check_excludes = toplevel is not None and bool(config.exclude_paths)
    files_seen: set[str] = set()
    binaries: list[str] = []
    current_file: str | None = None
    current_commit: str | None = None
    in_header = False
    new_line = 0
    old_left = new_left = 0

    for raw in _split_lines(diff_text):
        if old_left > 0 or new_left > 0:  # inside a hunk
            tag = raw[:1]
            if tag == "+":
                if current_file is not None:
                    collector.scan(current_file, new_line, raw[1:], current_commit)
                new_line += 1
                new_left -= 1
                continue
            if tag == "-":
                old_left -= 1
                continue
            if tag == " ":  # context line (none expected with -U0, handled anyway)
                new_line += 1
                new_left -= 1
                old_left -= 1
                continue
            if tag == "\\":  # "\ No newline at end of file"
                continue
            old_left = new_left = 0  # malformed hunk: fall through to headers

        if raw.startswith("diff --git "):
            in_header = True
            current_file = None
        elif raw.startswith("commit "):
            match = _COMMIT_RE.match(raw)
            if match:
                current_commit = match.group(1)
                current_file = None
                in_header = True
        elif raw.startswith("@@"):
            match = _HUNK_RE.match(raw)
            if match:
                old_left = int(match.group(1)) if match.group(1) is not None else 1
                new_line = int(match.group(2))
                new_left = int(match.group(3)) if match.group(3) is not None else 1
                in_header = False
        elif in_header and raw.startswith("+++ "):
            current_file = _diff_target(raw[4:])
            if current_file is not None and check_excludes and config.excludes_path(toplevel / current_file):
                current_file = None
            if current_file is not None:
                files_seen.add(current_file)
        elif in_header and raw.startswith("Binary files "):
            match = _BINARY_RE.match(raw)
            if match:
                target = _diff_target(match.group(2))
                if target is not None and target not in binaries:
                    binaries.append(target)
        # everything else (index, mode, rename, --- lines) carries no content
    return collector, files_seen, binaries


def _binary_note(binaries: list[str]) -> str:
    if not binaries:
        return ""
    shown = ", ".join(binaries[:5]) + (", …" if len(binaries) > 5 else "")
    return f" [{len(binaries)} binary file(s) not scanned: {shown}]"


def _toplevel_for(repo_path: str, config: ScanConfig) -> Path | None:
    """The work tree root, needed only when the config excludes paths."""
    if not config.exclude_paths:
        return None
    proc = _run_git(repo_path, "rev-parse", "--show-toplevel")
    return Path(proc.stdout.strip()) if proc.returncode == 0 else None


def _has_commits(repo_path: str) -> bool:
    return _run_git(repo_path, "rev-parse", "--verify", "--quiet", "HEAD^{commit}").returncode == 0


def scan_git_staged(
    repo_path: str, max_findings: int = DEFAULT_MAX_FINDINGS, config: ScanConfig = DEFAULT_CONFIG
) -> dict:
    """Scan only the lines that `git diff --cached` would add — the exact
    content the next commit would publish.

    Findings carry the file path (repo-relative) and the post-commit line
    number of each added line. Local diff configuration (external diff tools,
    textconv filters, prefix settings, path quoting) is overridden, so what
    is scanned is always the staged text itself.

    Raises:
        ValueError: if the path is missing, not a git repository, or git is
        not installed.
    """
    _check_max_findings(max_findings)
    _ensure_git_repo(repo_path)
    proc = _run_git(repo_path, "diff", "--cached", *_DIFF_FLAGS)
    if proc.returncode != 0:
        raise ValueError(f"'git diff --cached' failed in {repo_path}: {proc.stderr.strip()}")
    if not proc.stdout.strip():
        return {
            "clean": True,
            "findings": [],
            "files_scanned": 0,
            "summary": (
                "No staged changes found — stage files with 'git add' and scan "
                "again before committing."
            ),
        }
    collector, files_seen, binaries = _scan_diff(proc.stdout, config, _toplevel_for(repo_path, config))
    result = collector.result(len(files_seen), max_findings)
    if collector.findings:
        result["summary"] += " Unstage the affected files and strip the secrets before committing."
    else:
        result["summary"] = (
            f"Staged changes are clean — {len(files_seen)} file(s) with additions "
            "scanned, no secrets in the added lines."
        ) + _notes_suffix(result)
    result["summary"] += _binary_note(binaries)
    return result


def scan_git_history(
    repo_path: str,
    max_commits: int = 50,
    all_branches: bool = False,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    config: ScanConfig = DEFAULT_CONFIG,
) -> dict:
    """Scan the lines added by the last *max_commits* commits.

    Each finding is tagged with the (short) commit hash that introduced it.
    Note that removing a secret in a later commit does NOT make it safe:
    history retains it, so rotation is always required.

    Args:
        all_branches: walk every ref (all branches, tags and the stash)
            instead of only the history of HEAD.

    Raises:
        ValueError: if the path is missing, not a git repository, git is not
        installed, or max_commits < 1.
    """
    _ensure_git_repo(repo_path)
    if max_commits < 1:
        raise ValueError("max_commits must be at least 1.")
    _check_max_findings(max_findings)
    if not all_branches and not _has_commits(repo_path):
        return {
            "clean": True,
            "findings": [],
            "files_scanned": 0,
            "summary": "Repository has no commits yet — history is empty.",
        }
    args = ["log", "-p", *_DIFF_FLAGS, f"-n{max_commits}", "--format=commit %h"]
    if all_branches:
        args.append("--all")
    proc = _run_git(repo_path, *args)
    if proc.returncode != 0:
        raise ValueError(f"'git log' failed in {repo_path}: {proc.stderr.strip()}")
    collector, files_seen, binaries = _scan_diff(proc.stdout, config, _toplevel_for(repo_path, config))
    result = collector.result(len(files_seen), max_findings)
    if collector.findings:
        result["summary"] += (
            " These additions live in commit history: removing the file now is "
            "NOT enough — rotate the affected credentials."
        )
    result["summary"] += _binary_note(binaries)
    return result


_UPSTREAM_HINT = (
    "The current branch has no upstream (it was never pushed with -u, or HEAD "
    "is detached). Pass the branch you are going to push to as base, for "
    "example base='origin/main'."
)


def _resolve_commit(repo_path: str, rev: str, role: str) -> str:
    """Resolve *rev* to a full commit hash, rejecting option-like input."""
    if not rev or rev.startswith("-") or any(c in rev for c in "\0\n\r"):
        raise ValueError(f"Invalid {role} revision {rev!r}: pass a branch, tag or commit.")
    proc = _run_git(repo_path, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
    if proc.returncode != 0:
        if re.search(r"@\{(?:u|upstream|push)\}", rev, re.IGNORECASE):
            raise ValueError(_UPSTREAM_HINT)
        raise ValueError(f"Unknown {role} revision {rev!r} in {repo_path}.")
    return proc.stdout.strip()


def scan_git_range(
    repo_path: str,
    base: str = "@{upstream}",
    head: str = "HEAD",
    max_commits: int = 200,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    config: ScanConfig = DEFAULT_CONFIG,
) -> dict:
    """Scan the commits in ``base..head`` — by default, what `git push`
    would publish: every commit on the current branch that its upstream
    does not have yet.

    Each finding is tagged with the commit that introduced it. The result
    adds ``commits_scanned`` and ``range`` to the standard report.

    Raises:
        ValueError: if the path is not a git repository, a revision does not
        exist (with a hint when there is no upstream), or max_commits < 1.
    """
    _ensure_git_repo(repo_path)
    if max_commits < 1:
        raise ValueError("max_commits must be at least 1.")
    _check_max_findings(max_findings)
    base_sha = _resolve_commit(repo_path, base, "base")
    head_sha = _resolve_commit(repo_path, head, "head")
    span = f"{base_sha}..{head_sha}"
    label = f"{base}..{head}"

    count_proc = _run_git(repo_path, "rev-list", "--count", span)
    if count_proc.returncode != 0:
        raise ValueError(f"'git rev-list' failed in {repo_path}: {count_proc.stderr.strip()}")
    total = int(count_proc.stdout.strip() or 0)
    if total == 0:
        return {
            "clean": True,
            "findings": [],
            "files_scanned": 0,
            "summary": f"Nothing to scan: {head} has no commits that {base} does not already have.",
            "commits_scanned": 0,
            "range": label,
        }

    proc = _run_git(
        repo_path, "log", "-p", *_DIFF_FLAGS, f"-n{max_commits}", "--format=commit %h", span
    )
    if proc.returncode != 0:
        raise ValueError(f"'git log' failed in {repo_path}: {proc.stderr.strip()}")
    collector, files_seen, binaries = _scan_diff(proc.stdout, config, _toplevel_for(repo_path, config))
    scanned = min(total, max_commits)
    result = collector.result(len(files_seen), max_findings)
    result["summary"] = f"{scanned} commit(s) in {label}: " + result["summary"]
    if collector.findings:
        result["summary"] += (
            " Rewrite or drop these commits before pushing, and rotate the "
            "affected credentials."
        )
    if total > scanned:
        result["summary"] += (
            f" [only the newest {scanned} of {total} commits were scanned — "
            "raise max_commits for the rest]"
        )
    result["summary"] += _binary_note(binaries)
    result["commits_scanned"] = scanned
    result["range"] = label
    return result


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------


def list_patterns() -> dict:
    """Describe the active detectors and allowlist rules.

    Raw regexes are intentionally not exposed — names, severities and advice
    are what a client agent needs to explain findings.
    """
    return {
        "count": len(PATTERNS),
        "patterns": [
            {"name": p["name"], "severity": p["severity"], "advice": p["advice"]}
            for p in PATTERNS
        ],
        "entropy_detector": {
            "name": ENTROPY_PATTERN_NAME,
            "severity": _SEV_MEDIUM,
            "threshold_bits_per_char": ENTROPY_THRESHOLD,
            "min_length": ENTROPY_MIN_LENGTH,
            "advice": _ENTROPY_ADVICE,
        },
        "allowlist_rules": [
            {"name": name, "description": description} for name, description in ALLOWLIST_RULES
        ],
        "inline_suppression": {
            "markers": list(SUPPRESSION_MARKERS),
            "description": (
                "A line containing one of these markers (usually in a trailing "
                "comment, case-insensitive) produces no findings; results count "
                "them in 'suppressed'."
            ),
        },
    }
