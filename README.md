# mcp-secret-sentinel

<!-- mcp-name: io.github.AleBrito124356/mcp-secret-sentinel -->

[![tests](https://github.com/AleBrito124356/mcp-secret-sentinel/actions/workflows/tests.yml/badge.svg)](https://github.com/AleBrito124356/mcp-secret-sentinel/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-secret-sentinel)](https://pypi.org/project/mcp-secret-sentinel/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-secret-sentinel)](https://pypi.org/project/mcp-secret-sentinel/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**MCP server that scans code for exposed secrets — API keys, tokens, private keys and high-entropy strings — with placeholder-aware allowlisting and redacted reports.**

Secrets rarely leak through hackers; they leak through commits. An agent (or a human in a hurry) pastes a webhook URL into a config, stages it, pushes — and from that moment the credential is compromised, even if the next commit deletes it, because history keeps every added line. mcp-secret-sentinel gives an agent a pre-commit checkpoint: scan a snippet, a file, a whole tree, the staged diff, or recent history, and get back a severity-ranked, fully redacted report it can act on *before* anything leaves the machine. The full secret value never appears in the tool output, so it never enters the conversation transcript either.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `scan_text` | `text`, `source_name="input"` | Findings for a raw snippet (code, config, diff, logs) |
| `scan_file` | `path` | Findings for one file; skips binaries (null-byte heuristic) and files over 5 MB |
| `scan_directory` | `path`, `max_files=500` | Recursive scan; skips `.git`, `node_modules`, virtualenvs, `__pycache__`, `dist`, `build`, minified JS, lockfiles, and honors simple `.gitignore` patterns |
| `scan_git_staged` | `repo_path` | Scans only the lines added in `git diff --cached` — the exact content the next commit would publish |
| `scan_git_history` | `repo_path`, `max_commits=50` | Scans lines added by the last N commits, tagging each finding with its commit hash |
| `list_patterns` | — | Active detectors with severity and remediation advice, plus the allowlist rules |

All scan tools return the same shape:

```json
{
  "clean": false,
  "findings": [
    {
      "file": "config/notify.yaml",
      "line": 14,
      "pattern": "Slack incoming webhook",
      "severity": "high",
      "redacted": "hook…(77 chars)",
      "advice": "Anyone with this URL can post messages to your workspace. Regenerate the webhook in your Slack app settings and load the URL from an environment variable."
    }
  ],
  "files_scanned": 6,
  "summary": "Found 1 potential secret(s) across 6 scanned file(s): 1 high. Do NOT commit or push until these are removed or rotated."
}
```

### What it detects

Nineteen regex detectors: GitHub tokens (classic and fine-grained), OpenAI / Anthropic / NVIDIA / Google / Stripe (live) / Twilio keys, AWS access key IDs and secret access keys, Slack tokens and incoming webhooks, Discord webhooks, JWTs, private key blocks (RSA / EC / OPENSSH / PGP), database and queue connection strings with embedded credentials (Postgres, MySQL, MongoDB, AMQP, Redis), plus generic `password` / `secret` / `token`-style assignments in quoted code and in dotenv-style `UPPER_CASE=value` lines.

On top of the regexes, a Shannon-entropy detector flags quoted strings of 20+ characters assigned to variables whose empirical entropy reaches **4.5 bits/char** — the signature of random credential material — but only when no specific pattern already claimed that span.

### What it deliberately ignores (allowlist)

Each candidate value is checked against these placeholder heuristics before being reported:

- **Too short** — values under 8 characters are too short to be real credentials.
- **Masked** — values that are mostly (≥ 80%) `X`, `x`, `*`, or dots: already redacted by a human, including vendor prefixes followed by an `XXXX…` run.
- **`example`** — any value containing `example` (any case): covers `example.com` / `example.org` domains *and* vendor-documented sample keys, such as the AWS docs key ending in `EXAMPLE`.
- **`placeholder`**, **`changeme`** (also `change-me` / `change_me`) — conventional fill-me-in markers.
- **your-…-here** — fill-in-the-blank markers.
- **`<angle brackets>`** — documentation-style placeholders.
- **`${TEMPLATE_VARIABLES}`** — the secret is injected elsewhere, not stored here.
- **Environment lookups** — values referencing `os.environ` or `process.env`: an environment lookup is the fix, not the leak.

### Redaction guarantee

Every finding shows only the first 4 characters plus the total length — e.g. `"hook…(77 chars)"`. The full value never appears in the output, the transcript, or the logs. This is enforced in code (a single `redact()` choke point) and in the test suite, which asserts the raw values are absent from serialized results.

## How it works

```mermaid
flowchart TD
    A[Agent calls a scan tool] --> B{Source}
    B -->|scan_text / scan_file| C[Split into lines]
    B -->|scan_directory| D[Walk tree, skip .git, node_modules,<br/>binaries, lockfiles, .gitignore matches] --> C
    B -->|scan_git_staged / scan_git_history| E[git diff / git log with zero context,<br/>keep added lines only] --> C
    C --> F[19 regex detectors,<br/>specific patterns claim spans first]
    C --> G[Shannon entropy >= 4.5 bits/char<br/>on assigned strings of 20+ chars]
    F --> H{Allowlist check:<br/>placeholders, masked values,<br/>example domains, env lookups}
    G --> H
    H -->|placeholder| I[Dropped, not reported]
    H -->|real candidate| J[Redact: first 4 chars + length]
    J --> K[Report: file, line, pattern,<br/>severity, redacted, advice]
```

## Quickstart

No install needed — `uvx` fetches and runs it:

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "secret-sentinel": {
      "command": "uvx",
      "args": ["mcp-secret-sentinel"]
    }
  }
}
```

**Claude Code:**

```bash
claude mcp add secret-sentinel -- uvx mcp-secret-sentinel
```

Prefer a permanent install? `pip install mcp-secret-sentinel`, then use `mcp-secret-sentinel` as the command.

## Example session

> **User:** I'm about to push acme-app — make sure I'm not leaking anything.
>
> **Claude** calls `scan_git_staged(repo_path="C:/dev/acme-app")`:
>
> ```json
> {
>   "clean": false,
>   "findings": [
>     {
>       "file": "config/notify.yaml",
>       "line": 14,
>       "pattern": "Slack incoming webhook",
>       "severity": "high",
>       "redacted": "hook…(77 chars)",
>       "advice": "Anyone with this URL can post messages to your workspace. Regenerate the webhook in your Slack app settings and load the URL from an environment variable."
>     }
>   ],
>   "files_scanned": 6,
>   "summary": "Found 1 potential secret(s) across 6 scanned file(s): 1 high. Do NOT commit or push until these are removed or rotated. Unstage the affected files and strip the secrets before committing."
> }
> ```
>
> **Claude:** Hold the push — `config/notify.yaml` line 14 contains a real Slack webhook URL in the staged diff. Three steps:
> 1. Replace the literal URL with an environment lookup, e.g. `SLACK_WEBHOOK_URL`.
> 2. Regenerate the webhook in your Slack app settings — treat the current one as compromised.
> 3. Re-stage the file and I'll verify.
>
> **User:** Done — check again.
>
> **Claude** calls `scan_git_staged(...)` → `"clean": true, "summary": "Staged changes are clean — 6 file(s) with additions scanned, no secrets in the added lines."` — then `scan_git_history(repo_path="C:/dev/acme-app", max_commits=20)` → `"clean": true`.
>
> **Claude:** Clean — the staged changes and the last 20 commits contain no detectable secrets. Safe to push.

## Limitations

- **`.gitignore` support is best-effort**: plain names, `*.ext` globs, `dir/` and `/anchored` patterns from the *root* `.gitignore` only. No `!` negations, no `**` globs, no nested ignore files.
- **Entropy needs diversity**: empirical per-string entropy maxes out at log2(distinct characters), so a candidate needs at least 23 distinct characters to clear 4.5 bits/char. Short random strings are covered by the regex detectors instead.
- **Unquoted generic assignments** are only detected in dotenv-style `UPPER_CASE=value` lines — a deliberate trade against false positives in ordinary code.
- **Not a CI replacement**: dedicated scanners (gitleaks, trufflehog) with hundreds of rules belong in your pipeline. This server is the fast local checkpoint an agent can run *before* the commit exists.

## Development

```bash
git clone https://github.com/AleBrito124356/mcp-secret-sentinel
cd mcp-secret-sentinel
pip install -e ".[dev]"
python -m pytest
```

You can also run the server straight from the source tree with `python -m mcp_secret_sentinel.server`.

The test suite exercises every detector, the allowlist, entropy, redaction, directory walking, and real temporary git repositories — and never contains a realistic secret literal: every positive fixture is assembled at runtime by concatenation.

## Related MCP servers

Part of a family of small, dependency-light MCP servers:

- [mcp-decision-lab](https://github.com/AleBrito124356/mcp-decision-lab) — weighted decision matrices with sensitivity analysis
- [mcp-devils-advocate](https://github.com/AleBrito124356/mcp-devils-advocate) — stress-test a claim: devil's advocate, premortem, assumption audits
- [mcp-git-historian](https://github.com/AleBrito124356/mcp-git-historian) — churn hotspots, blame summaries, bus factor
- [mcp-memory-vault](https://github.com/AleBrito124356/mcp-memory-vault) — persistent memory with SQLite FTS5 search

## License

MIT
