"""Shared runtime-built fixtures and git helpers for the test suite.

Same golden rule as test_core.py: no literal here carries a realistic secret
format. Every value is assembled by concatenation at import time, so secret
scanners (including this project's own) never match the test sources.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

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
# What must never appear in any output: the URL minus its scheme.
SLACK_HOOK_SECRET = SLACK_HOOK[8:]
SLACK_HOOK_LINE = 'HOOK_URL = "' + SLACK_HOOK + '"'

GENERIC_VALUE = "hunter2plus7extra"
GENERIC_LINE = "pass" + 'word = "' + GENERIC_VALUE + '"'

STRIPE_SECRET = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_LINE = 'stripe_key = "' + STRIPE_SECRET + '"'

TWILIO_KEY = "SK" + "0123456789abcdef" * 2


def git(cwd: Path, *args: str) -> str:
    """Run git with a neutral config and fail the test on error."""
    proc = subprocess.run(
        ["git", "-c", "core.autocrlf=false", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.returncode == 0, f"git {' '.join(args)} failed: {proc.stderr}"
    return proc.stdout


def init_repo(path: Path) -> Path:
    """Create an empty repository with a local identity and no signing."""
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "tester@example.com")
    git(path, "config", "user.name", "Test User")
    git(path, "config", "commit.gpgsign", "false")
    return path
