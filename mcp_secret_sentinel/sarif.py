"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers.

Pure stdlib. The input is a standard scan report from core.py. Only redacted
values are used (the message, the fingerprint), so a SARIF file is as safe to
upload as the report itself.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import quote

from . import __version__, core

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/AleBrito124356/mcp-secret-sentinel"

# GitHub code scanning ranks security alerts by "security-severity" (0-10).
_LEVEL = {"critical": "error", "high": "error", "medium": "warning"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0"}


def rule_id(pattern_name: str) -> str:
    """Stable rule id for a detector name: "GitHub token" -> "secret-sentinel/github-token"."""
    slug = re.sub(r"[^a-z0-9]+", "-", pattern_name.lower()).strip("-")
    return f"secret-sentinel/{slug}"


def _rules() -> list[dict]:
    detectors = [
        {"name": p["name"], "severity": p["severity"], "advice": p["advice"]} for p in core.PATTERNS
    ]
    info = core.list_patterns()["entropy_detector"]
    detectors.append({"name": info["name"], "severity": info["severity"], "advice": info["advice"]})
    rules = []
    for det in detectors:
        rules.append(
            {
                "id": rule_id(det["name"]),
                "name": "".join(word.capitalize() for word in re.split(r"[^A-Za-z0-9]+", det["name"]) if word),
                "shortDescription": {"text": det["name"]},
                "fullDescription": {"text": f"{det['name']} committed to source."},
                "help": {"text": det["advice"]},
                "defaultConfiguration": {"level": _LEVEL[det["severity"]]},
                "properties": {
                    "tags": ["security", "secret"],
                    "security-severity": _SECURITY_SEVERITY[det["severity"]],
                    "precision": "medium" if det["severity"] == "medium" else "high",
                },
            }
        )
    return rules


def artifact_uri(path: str) -> str:
    """A SARIF artifact URI: relative paths stay relative (resolved against
    the checkout root by GitHub), absolute paths become file:// URIs."""
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate.as_uri()
    return quote(path.replace("\\", "/"), safe="/")


def to_sarif(result: dict) -> dict:
    """Convert a standard scan report into a SARIF 2.1.0 log with one run."""
    rules = _rules()
    index = {rule["id"]: i for i, rule in enumerate(rules)}
    results = []
    for finding in result["findings"]:
        rid = rule_id(finding["pattern"])
        fingerprint = hashlib.sha256(
            f"{rid}|{finding['file']}|{finding['redacted']}".encode("utf-8")
        ).hexdigest()
        entry = {
            "ruleId": rid,
            "ruleIndex": index[rid],
            "level": _LEVEL[finding["severity"]],
            "message": {
                "text": f"{finding['pattern']} ({finding['redacted']}). {finding['advice']}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri(str(finding["file"]))},
                        "region": {"startLine": max(1, int(finding["line"]))},
                    }
                }
            ],
            "partialFingerprints": {"secretSentinelFinding/v1": fingerprint},
            "properties": {"severity": finding["severity"]},
        }
        if "commit" in finding:
            entry["properties"]["commit"] = finding["commit"]
        results.append(entry)

    run_properties = {"summary": result["summary"], "filesScanned": result["files_scanned"]}
    for key in ("suppressed", "truncated", "total_findings"):
        if key in result:
            run_properties[key] = result[key]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-secret-sentinel",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "columnKind": "unicodeCodePoints",
                "properties": run_properties,
            }
        ],
    }
