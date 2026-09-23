"""Core scanning logic for mcp-secret-sentinel.

Pure Python stdlib — no third-party imports. All MCP wiring lives in
server.py; everything testable lives here.

Detection layers, in order:

1. Specific regex detectors (``PATTERNS``) — vendor token formats, webhook
   URLs, private key markers, credentialed connection strings, and generic
   assignments in code and dotenv files.
2. A Shannon-entropy detector for quoted strings of 20+ characters assigned
   to variables, flagged at >= 4.5 bits/char when no specific pattern
   already claimed the same span.

Every candidate value passes through a documented allowlist of placeholder
heuristics before being reported, and every reported finding is redacted:
the first 4 characters plus the total length. The full secret value never
appears in any output produced by this module.
"""

from __future__ import annotations

import math
import os
import re
import subprocess
from collections import Counter
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

ENTROPY_PATTERN_NAME = "High-entropy string"

_SEV_CRITICAL = "critical"
_SEV_HIGH = "high"
_SEV_MEDIUM = "medium"
_SEV_ORDER = {_SEV_CRITICAL: 0, _SEV_HIGH: 1, _SEV_MEDIUM: 2}

_ENTROPY_ADVICE = (
    "This looks like a random credential. If it is one, rotate it and load it "
    "from the environment; if it is a hash or a fixture, consider renaming the "
    "variable or replacing the value with an obvious placeholder."
)

# ---------------------------------------------------------------------------
# Specific detectors
#
# Each entry: name, compiled regex, severity, advice. Optional "group" points
# at the capture group holding the secret value (default: whole match).
# Ordered specific-first: later, broader patterns are skipped when an earlier
# match already claimed the same span on the line.
# ---------------------------------------------------------------------------

PATTERNS: list[dict] = [
    {
        "name": "GitHub token",
        "regex": re.compile(r"\b(?:ghp|gho|ghs)_[A-Za-z0-9]{20,255}\b"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Revoke the token in GitHub -> Settings -> Developer settings -> "
            "Personal access tokens, then load it from an environment variable "
            "or a secrets manager."
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
        "name": "Anthropic API key",
        "regex": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,255}"),
        "severity": _SEV_HIGH,
        "advice": (
            "Rotate the key in the Anthropic Console and read it from the "
            "ANTHROPIC_API_KEY environment variable instead of hardcoding it."
        ),
    },
    {
        "name": "OpenAI API key",
        "regex": re.compile(r"\bsk-(?!ant-)[A-Za-z0-9]{20,255}\b"),
        "severity": _SEV_HIGH,
        "advice": (
            "Rotate the key in the OpenAI dashboard and read it from the "
            "OPENAI_API_KEY environment variable instead of hardcoding it."
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
        "name": "AWS access key ID",
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
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
        "name": "Stripe live key",
        "regex": re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\b"),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Roll the key in the Stripe Dashboard (Developers -> API keys). "
            "Live keys grant access to real payment data."
        ),
    },
    {
        "name": "Slack token",
        "regex": re.compile(r"\bxox[bp]-[A-Za-z0-9-]{10,255}"),
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
        "name": "Google API key",
        "regex": re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
        "severity": _SEV_HIGH,
        "advice": (
            "Regenerate the key in the Google Cloud Console and add "
            "application restrictions (HTTP referrer / IP) to the replacement."
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
        "severity": _SEV_CRITICAL,
        "advice": (
            "Remove the key from the repository and rotate the key pair. If it "
            "was ever pushed, treat it as compromised — history retains it."
        ),
    },
    {
        "name": "Connection string with credentials",
        "regex": re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|amqp|redis)://[^\s:@/\"']*:[^\s@/\"']+@[^\s\"']+"
        ),
        "severity": _SEV_CRITICAL,
        "advice": (
            "Credentials embedded in connection URLs leak through logs and "
            "shell history. Move the URL to an environment variable and rotate "
            "the password."
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
# entropy detector only.
_ENTROPY_ASSIGN_RE = re.compile(
    r"[\"']?[A-Za-z_][A-Za-z0-9_]*[\"']?\s*[:=]\s*[\"']([^\"'\s]{20,2048})[\"']"
)

# ---------------------------------------------------------------------------
# Allowlist — placeholder heuristics that suppress a candidate value.
# Each rule: (name, human description, predicate). Order matters: the first
# matching rule wins and is reported by allowlist_rule().
# ---------------------------------------------------------------------------

_MASK_CHARS = set("Xx*.•…")  # X, x, *, ., bullet, ellipsis
_YOUR_HERE_RE = re.compile(r"(?i)your[-_][a-z0-9_-]*here")


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
        "Values containing 'example' in any case — covers example.com / example.org domains and vendor-documented sample keys (such as the AWS docs key ending in EXAMPLE).",
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
        "env-lookup",
        "Values referencing os.environ or process.env — an environment lookup is the fix, not the leak.",
        lambda v: "os.environ" in v or "process.env" in v,
    ),
]

ALLOWLIST_RULES: list[tuple[str, str]] = [(n, d) for n, d, _ in _ALLOWLIST]


def allowlist_rule(value: str) -> str | None:
    """Return the name of the first allowlist rule matching *value*, else None."""
    for name, _description, predicate in _ALLOWLIST:
        if predicate(value):
            return name
    return None


def is_allowlisted(value: str) -> bool:
    """True when *value* is a placeholder that must not be reported."""
    return allowlist_rule(value) is not None


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
    """Redact a secret: first 4 characters + ellipsis + total length.

    The full value never leaves the scanner in any form.
    """
    return f"{value[:4]}…({len(value)} chars)"


# ---------------------------------------------------------------------------
# Line / text scanning
# ---------------------------------------------------------------------------


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    return any(s < span[1] and span[0] < e for s, e in taken)


def _scan_line(line: str) -> list[dict]:
    """Scan a single line; return raw hits: pattern, severity, advice, value."""
    hits: list[dict] = []
    taken: list[tuple[int, int]] = []
    for pat in PATTERNS:
        for m in pat["regex"].finditer(line):
            group_index = pat.get("group", 0)
            value = m.group(group_index)
            if not value:
                continue
            span = m.span(group_index)
            if _overlaps(span, taken):
                continue  # a more specific detector already claimed this span
            if allowlist_rule(value) is not None:
                continue
            taken.append(span)
            hits.append(
                {
                    "pattern": pat["name"],
                    "severity": pat["severity"],
                    "advice": pat["advice"],
                    "value": value,
                }
            )
    # Entropy fallback — only for spans no specific pattern claimed.
    for m in _ENTROPY_ASSIGN_RE.finditer(line):
        value = m.group(1)
        span = m.span(1)
        if len(value) < ENTROPY_MIN_LENGTH or _overlaps(span, taken):
            continue
        if allowlist_rule(value) is not None:
            continue
        if shannon_entropy(value) >= ENTROPY_THRESHOLD:
            taken.append(span)
            hits.append(
                {
                    "pattern": ENTROPY_PATTERN_NAME,
                    "severity": _SEV_MEDIUM,
                    "advice": _ENTROPY_ADVICE,
                    "value": value,
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


def _scan_text_lines(text: str, source: str, commit: str | None = None) -> list[dict]:
    findings: list[dict] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for hit in _scan_line(line):
            findings.append(_finding(source, line_no, hit, commit))
    return findings


def _build_result(findings: list[dict], files_scanned: int) -> dict:
    findings = sorted(
        findings,
        key=lambda f: (_SEV_ORDER.get(f["severity"], 9), str(f["file"]), f["line"]),
    )
    if findings:
        counts = Counter(f["severity"] for f in findings)
        parts = ", ".join(
            f"{counts[sev]} {sev}" for sev in (_SEV_CRITICAL, _SEV_HIGH, _SEV_MEDIUM) if counts[sev]
        )
        summary = (
            f"Found {len(findings)} potential secret(s) across {files_scanned} scanned "
            f"file(s): {parts}. Do NOT commit or push until these are removed or rotated."
        )
    else:
        summary = f"Clean — no secrets detected in {files_scanned} scanned file(s)."
    return {
        "clean": not findings,
        "findings": findings,
        "files_scanned": files_scanned,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Public API: text / file / directory
# ---------------------------------------------------------------------------


def scan_text(text: str, source_name: str = "input") -> dict:
    """Scan a snippet of text for exposed secrets.

    Args:
        text: Raw text to scan (code, config, log output, ...).
        source_name: Label used in each finding's "file" field.

    Returns:
        {"clean": bool, "findings": [...], "files_scanned": 1, "summary": str}
        with every finding redacted (first 4 chars + length).
    """
    findings = _scan_text_lines(text, source_name)
    return _build_result(findings, 1)


def _read_text_if_scannable(path: Path) -> tuple[str | None, str | None]:
    """Return (text, None) for scannable files, (None, reason) for skipped ones."""
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        return None, f"file exceeds the 5 MB scan limit ({size} bytes)"
    with open(path, "rb") as fh:
        head = fh.read(BINARY_SNIFF_BYTES)
    if b"\x00" in head:
        return None, "binary file (null byte detected)"
    return path.read_text(encoding="utf-8", errors="replace"), None


def scan_file(path: str) -> dict:
    """Scan one file for exposed secrets.

    Binary files (null-byte heuristic on the first 8 KiB) and files over 5 MB
    are skipped, reported via files_scanned=0 and an explanatory summary.

    Raises:
        ValueError: if the path does not point at an existing file.
    """
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
    findings = _scan_text_lines(text, str(target))
    return _build_result(findings, 1)


# -- directory scanning ------------------------------------------------------

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
}
LOCKFILE_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "bun.lockb"}


def _load_gitignore_patterns(root: Path) -> list[str]:
    """Best-effort .gitignore support (see _matches_gitignore for limits)."""
    patterns: list[str] = []
    gitignore = root / ".gitignore"
    if gitignore.is_file():
        try:
            for raw in gitignore.read_text(encoding="utf-8", errors="replace").splitlines():
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


def scan_directory(path: str, max_files: int = 500) -> dict:
    """Recursively scan a directory tree for exposed secrets.

    Skips: .git, node_modules, .venv/venv, __pycache__, dist, build,
    minified JS bundles, lockfiles, binaries, files over 5 MB, and anything
    matching simple root-.gitignore patterns (best-effort — no negations, no
    `**`). Findings use forward-slash paths relative to *path*.

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

    ignore_patterns = _load_gitignore_patterns(root)
    findings: list[dict] = []
    scanned = 0
    skipped = 0
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        kept_dirs = []
        for dirname in sorted(dirnames):
            rel = (rel_dir / dirname).as_posix()
            if dirname in EXCLUDED_DIRS or _matches_gitignore(rel, dirname, True, ignore_patterns):
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            if scanned >= max_files:
                truncated = True
                break
            rel = (rel_dir / filename).as_posix()
            if (
                filename.endswith(".min.js")
                or filename.endswith(".lock")
                or filename in LOCKFILE_NAMES
                or _matches_gitignore(rel, filename, False, ignore_patterns)
            ):
                skipped += 1
                continue
            try:
                text, skip_reason = _read_text_if_scannable(Path(dirpath) / filename)
            except OSError:
                skipped += 1
                continue
            if skip_reason is not None:
                skipped += 1
                continue
            scanned += 1
            findings.extend(_scan_text_lines(text, rel))
        if truncated:
            break

    result = _build_result(findings, scanned)
    notes = []
    if skipped:
        notes.append(
            f"{skipped} file(s) skipped (binaries, oversized, lockfiles, minified, or .gitignore matches)"
        )
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


def _scan_diff(diff_text: str) -> tuple[list[dict], set[str], list[str]]:
    """Scan unified diff output (git diff / git log -p, -U0), added lines only.

    A small state machine instead of prefix matching, so that file content
    can never be mistaken for a header:

    * header state (after ``diff --git`` or ``commit <hash>``): ``+++ b/…``
      names the file, ``Binary files … differ`` marks a skipped binary.
    * hunk state (after ``@@ -a,b +c,d @@``): exactly ``b`` removed and ``d``
      added lines follow, counted down from the hunk header. Every ``+`` line
      in that window is content, even when it reads ``+++ something``.

    Returns (findings, files with additions, binary files skipped).
    """
    findings: list[dict] = []
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
                    for hit in _scan_line(raw[1:]):
                        findings.append(_finding(current_file, new_line, hit, commit=current_commit))
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
            if current_file is not None:
                files_seen.add(current_file)
        elif in_header and raw.startswith("Binary files "):
            match = _BINARY_RE.match(raw)
            if match:
                target = _diff_target(match.group(2))
                if target is not None and target not in binaries:
                    binaries.append(target)
        # everything else (index, mode, rename, --- lines) carries no content
    return findings, files_seen, binaries


def _binary_note(binaries: list[str]) -> str:
    if not binaries:
        return ""
    shown = ", ".join(binaries[:5]) + (", …" if len(binaries) > 5 else "")
    return f" [{len(binaries)} binary file(s) not scanned: {shown}]"


def _has_commits(repo_path: str) -> bool:
    return _run_git(repo_path, "rev-parse", "--verify", "--quiet", "HEAD^{commit}").returncode == 0


def scan_git_staged(repo_path: str) -> dict:
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
    findings, files_seen, binaries = _scan_diff(proc.stdout)
    result = _build_result(findings, len(files_seen))
    if findings:
        result["summary"] += " Unstage the affected files and strip the secrets before committing."
    else:
        result["summary"] = (
            f"Staged changes are clean — {len(files_seen)} file(s) with additions "
            "scanned, no secrets in the added lines."
        )
    result["summary"] += _binary_note(binaries)
    return result


def scan_git_history(repo_path: str, max_commits: int = 50, all_branches: bool = False) -> dict:
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
    findings, files_seen, binaries = _scan_diff(proc.stdout)
    result = _build_result(findings, len(files_seen))
    if findings:
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
    findings, files_seen, binaries = _scan_diff(proc.stdout)
    scanned = min(total, max_commits)
    result = _build_result(findings, len(files_seen))
    result["summary"] = f"{scanned} commit(s) in {label}: " + result["summary"]
    if findings:
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
    }
