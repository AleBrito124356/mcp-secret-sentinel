"""Project configuration and baselines.

A project tunes the scanner with ``.secret-sentinel.toml`` or with a
``[tool.secret-sentinel]`` table in ``pyproject.toml``::

    exclude_paths = ["tests/fixtures/**", "*.snap"]   # globs, relative to this file
    allowlist = ["^sk_test_", "-dummy-"]              # regexes matched against the value
    disable = ["JSON Web Token"]                      # detector names ("High-entropy string" too)
    baseline = ".secret-sentinel-baseline.json"       # accepted findings (optional)

    [[rules]]
    name = "Acme internal token"
    regex = 'acme_[A-Za-z0-9]{32}'
    severity = "high"        # critical | high | medium (default high)
    advice = "Revoke it in the Acme console."
    group = 0                # capture group holding the secret (default: whole match)

The file is looked up from the scanned path upwards, stopping at the
repository root. A baseline is a JSON list of non-reversible fingerprints
(see core.fingerprint) of findings someone reviewed and accepted; without a
``baseline`` key, ``.secret-sentinel-baseline.json`` at the project root is
used when it exists.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, core

CONFIG_FILENAME = ".secret-sentinel.toml"
BASELINE_FILENAME = ".secret-sentinel-baseline.json"
_KNOWN_KEYS = {"exclude_paths", "allowlist", "disable", "baseline", "rules"}
_RULE_KEYS = {"name", "regex", "severity", "advice", "group"}


def _load_toml(path: Path) -> dict:
    if sys.version_info >= (3, 11):
        import tomllib
    else:  # pragma: no cover - exercised on Python 3.10 only
        try:
            import tomli as tomllib
        except ImportError:
            raise ValueError(
                f"Reading {path.name} needs Python 3.11+ or the 'tomli' package."
            ) from None
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{path}: invalid TOML ({exc})") from None
    except OSError as exc:
        raise ValueError(f"Cannot read the configuration {path}: {exc.strerror or exc}") from None


def project_root(start: Path) -> Path | None:
    """The nearest ancestor of *start* (itself included) that holds .git."""
    current = start if start.is_dir() else start.parent
    for directory in (current, *current.parents):
        if (directory / ".git").exists():
            return directory
    return None


def find_config(start: str | Path) -> Path | None:
    """The config file that applies to *start*: the nearest
    .secret-sentinel.toml, or pyproject.toml with a [tool.secret-sentinel]
    table, searching upwards and stopping at the repository root."""
    begin = Path(start).expanduser().resolve()
    current = begin if begin.is_dir() else begin.parent
    for directory in (current, *current.parents):
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        pyproject = directory / "pyproject.toml"
        if pyproject.is_file():
            try:
                if "secret-sentinel" in _load_toml(pyproject).get("tool", {}):
                    return pyproject
            except ValueError:
                pass  # a broken pyproject.toml is not ours to report
        if (directory / ".git").exists():
            break
    return None


def _string_list(table: dict, key: str, path: Path) -> list[str]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{path}: '{key}' must be a list of strings.")
    return value


def _compile(pattern: str, where: str) -> re.Pattern:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"{where}: invalid regex {pattern!r} ({exc})") from None


def _custom_rules(table: dict, path: Path) -> list[dict]:
    rules = table.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError(f"{path}: 'rules' must be an array of tables ([[rules]]).")
    built = []
    for index, rule in enumerate(rules, start=1):
        where = f"{path}: rules[{index}]"
        if not isinstance(rule, dict):
            raise ValueError(f"{where} must be a table.")
        unknown = set(rule) - _RULE_KEYS
        if unknown:
            raise ValueError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}.")
        name, regex = rule.get("name"), rule.get("regex")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{where}: 'name' is required.")
        if not isinstance(regex, str) or not regex:
            raise ValueError(f"{where}: 'regex' is required.")
        severity = rule.get("severity", "high")
        if severity not in core.SEVERITIES:
            raise ValueError(f"{where}: 'severity' must be one of {', '.join(core.SEVERITIES)}.")
        compiled = _compile(regex, where)
        group = rule.get("group", 0)
        if not isinstance(group, int) or not 0 <= group <= compiled.groups:
            raise ValueError(f"{where}: 'group' must be between 0 and {compiled.groups}.")
        built.append(
            {
                "name": name.strip(),
                "regex": compiled,
                "group": group,
                "severity": severity,
                "advice": rule.get("advice")
                or "Custom rule from the project configuration: remove the value and rotate it.",
                "custom": True,
            }
        )
    return built


def read_baseline(path: Path) -> frozenset[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read the baseline {path}: {exc}") from None
    entries = data.get("findings", []) if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{path}: not a secret-sentinel baseline (no 'findings' list).")
    return frozenset(e["fingerprint"] for e in entries if isinstance(e, dict) and "fingerprint" in e)


def write_baseline(path: Path, findings: list[dict]) -> int:
    """Write the fingerprints of *findings* (scanned with fingerprints=True).
    File and line are kept only to help reviewers; matching ignores them."""
    entries = {}
    for f in findings:
        entries.setdefault(
            f["fingerprint"],
            {"fingerprint": f["fingerprint"], "pattern": f["pattern"], "file": str(f["file"]), "line": f["line"]},
        )
    data = {
        "version": 1,
        "generated_by": f"mcp-secret-sentinel {__version__}",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "findings": sorted(entries.values(), key=lambda e: (e["file"], e["line"], e["pattern"])),
    }
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
    return len(entries)


def load_config(path: str | Path, baseline: str | Path | None = None) -> core.ScanConfig:
    """Build a ScanConfig from a config file (and an explicit baseline path,
    which wins over the file's own)."""
    path = Path(path).expanduser().resolve()
    data = _load_toml(path)
    if path.name == "pyproject.toml":
        data = data.get("tool", {}).get("secret-sentinel", {})
    if not isinstance(data, dict):
        raise ValueError(f"{path}: the configuration must be a table.")
    unknown = set(data) - _KNOWN_KEYS
    if unknown:
        raise ValueError(
            f"{path}: unknown key(s) {', '.join(sorted(unknown))} "
            f"(known: {', '.join(sorted(_KNOWN_KEYS))})."
        )
    root = path.parent
    custom = _custom_rules(data, path)
    disabled = {name.lower() for name in _string_list(data, "disable", path)}
    known_names = {p["name"].lower() for p in core.PATTERNS} | {core.ENTROPY_PATTERN_NAME.lower()}
    unknown_names = disabled - known_names
    if unknown_names:
        raise ValueError(
            f"{path}: 'disable' names unknown detector(s): {', '.join(sorted(unknown_names))}. "
            "Run 'mcp-secret-sentinel patterns' for the list."
        )
    patterns = custom + [p for p in core.PATTERNS if p["name"].lower() not in disabled]
    allowlist = [_compile(rx, f"{path}: allowlist") for rx in _string_list(data, "allowlist", path)]

    if baseline is not None:
        baseline_path = Path(baseline).expanduser()
        if not baseline_path.is_file():
            raise ValueError(f"Baseline not found: {baseline}")
    elif "baseline" in data:
        if not isinstance(data["baseline"], str):
            raise ValueError(f"{path}: 'baseline' must be a path string.")
        baseline_path = root / data["baseline"]
    else:
        baseline_path = root / BASELINE_FILENAME

    return core.ScanConfig(
        patterns=patterns,
        entropy=core.ENTROPY_PATTERN_NAME.lower() not in disabled,
        allowlist=allowlist,
        exclude_paths=_string_list(data, "exclude_paths", path),
        baseline=read_baseline(baseline_path) if baseline_path.is_file() else frozenset(),
        baseline_path=baseline_path,
        root=root,
        source=path.name,
    )


def discover(start: str | Path | None, baseline: str | Path | None = None) -> core.ScanConfig:
    """The configuration for a scan of *start*: the nearest config file, or
    the built-in defaults plus the project's baseline file when there is one."""
    if start is None:
        return core.DEFAULT_CONFIG
    found = find_config(start)
    if found is not None:
        return load_config(found, baseline)
    baseline_path = Path(baseline).expanduser() if baseline is not None else default_baseline_path(start)
    if baseline_path.is_file():
        return core.ScanConfig(
            baseline=read_baseline(baseline_path),
            baseline_path=baseline_path,
            root=baseline_path.parent,
            source=baseline_path.name,
        )
    if baseline is not None:
        raise ValueError(f"Baseline not found: {baseline}")
    return core.DEFAULT_CONFIG


def default_baseline_path(start: str | Path) -> Path:
    """Where the baseline for *start* lives: the config's ``baseline`` path,
    else .secret-sentinel-baseline.json next to the config file or at the
    repository root (the scanned directory outside git)."""
    found = find_config(start)
    if found is not None:
        configured = load_config(found).baseline_path
        if configured is not None:
            return configured
    begin = Path(start).expanduser().resolve()
    root = project_root(begin) or (begin if begin.is_dir() else begin.parent)
    return root / BASELINE_FILENAME


STARTER_CONFIG = '''\
# mcp-secret-sentinel configuration. Every key is optional.
# Docs: https://github.com/AleBrito124356/mcp-secret-sentinel#project-configuration

# Paths never scanned (globs relative to this file; ** spans directories).
exclude_paths = [
    # "tests/fixtures/**",
]

# Values that are never reported (regexes searched in the secret value).
allowlist = [
    # "^sk_test_",
]

# Built-in detectors to turn off (names from 'mcp-secret-sentinel patterns').
disable = [
    # "High-entropy string",
]

# Accepted findings, written by 'mcp-secret-sentinel baseline'.
# baseline = ".secret-sentinel-baseline.json"

# Your own token formats.
# [[rules]]
# name = "Acme internal token"
# regex = 'acme_[A-Za-z0-9]{32}'
# severity = "high"
# advice = "Revoke it in the Acme console and load it from the environment."
'''
