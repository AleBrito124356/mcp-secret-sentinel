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

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_COMMIT_RE = re.compile(r"^commit ([0-9a-f]{6,40})\b")


def _run_git(repo_path: str, *args: str) -> subprocess.CompletedProcess:
    repo = Path(repo_path).expanduser()
    if not repo.exists():
        raise ValueError(
            f"Path not found: {repo_path} — pass an absolute path to a git repository."
        )
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        raise ValueError(
            "git executable not found on PATH — install Git to use "
            "scan_git_staged / scan_git_history."
        ) from None


def _ensure_git_repo(repo_path: str) -> None:
    proc = _run_git(repo_path, "rev-parse", "--is-inside-work-tree")
    if proc.returncode != 0:
        raise ValueError(
            f"Not a git repository at {repo_path} — pass an absolute path to a "
            f"git repository ({proc.stderr.strip()})."
        )


def _scan_diff(diff_text: str) -> tuple[list[dict], set[str]]:
    """Scan unified diff output (-U0), added lines only.

    Tracks the current file from `+++ b/...` headers, the new-file line number
    from `@@` hunk headers, and — for `git log` output — the current commit
    from `commit <hash>` separator lines. Deletions never advance the line
    counter (correct for zero-context diffs).
    """
    findings: list[dict] = []
    files_seen: set[str] = set()
    current_file: str | None = None
    current_commit: str | None = None
    new_line = 0

    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            if target == "/dev/null":
                current_file = None
            else:
                current_file = target[2:] if target.startswith(("a/", "b/")) else target
                files_seen.add(current_file)
        elif raw.startswith("+"):
            if current_file is not None:
                for hit in _scan_line(raw[1:]):
                    findings.append(_finding(current_file, new_line, hit, commit=current_commit))
            new_line += 1
        elif raw.startswith("@@"):
            match = _HUNK_RE.match(raw)
            if match:
                new_line = int(match.group(1))
        elif raw.startswith("commit "):
            match = _COMMIT_RE.match(raw)
            if match:
                current_commit = match.group(1)
                current_file = None
        # everything else (deletions, headers) is irrelevant with -U0
    return findings, files_seen


def scan_git_staged(repo_path: str) -> dict:
    """Scan only the lines that `git diff --cached` would add — the exact
    content the next commit would publish.

    Findings carry the file path (repo-relative) and the post-commit line
    number of each added line.

    Raises:
        ValueError: if the path is missing, not a git repository, or git is
        not installed.
    """
    _ensure_git_repo(repo_path)
    proc = _run_git(repo_path, "diff", "--cached", "-U0", "--no-color")
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
    findings, files_seen = _scan_diff(proc.stdout)
    result = _build_result(findings, len(files_seen))
    if findings:
        result["summary"] += " Unstage the affected files and strip the secrets before committing."
    else:
        result["summary"] = (
            f"Staged changes are clean — {len(files_seen)} file(s) with additions "
            "scanned, no secrets in the added lines."
        )
    return result


def scan_git_history(repo_path: str, max_commits: int = 50) -> dict:
    """Scan the lines added by the last *max_commits* commits.

    Each finding is tagged with the (short) commit hash that introduced it.
    Note that removing a secret in a later commit does NOT make it safe:
    history retains it, so rotation is always required.

    Raises:
        ValueError: if the path is missing, not a git repository, git is not
        installed, or max_commits < 1.
    """
    _ensure_git_repo(repo_path)
    if max_commits < 1:
        raise ValueError("max_commits must be at least 1.")
    proc = _run_git(
        repo_path,
        "log",
        "-p",
        "-U0",
        "--no-color",
        f"-n{max_commits}",
        "--pretty=format:commit %h",
    )
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if "does not have any commits" in stderr or "bad default revision" in stderr:
            return {
                "clean": True,
                "findings": [],
                "files_scanned": 0,
                "summary": "Repository has no commits yet — history is empty.",
            }
        raise ValueError(f"'git log' failed in {repo_path}: {stderr}")
    findings, files_seen = _scan_diff(proc.stdout)
    result = _build_result(findings, len(files_seen))
    if findings:
        result["summary"] += (
            " These additions live in commit history: removing the file now is "
            "NOT enough — rotate the affected credentials."
        )
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
