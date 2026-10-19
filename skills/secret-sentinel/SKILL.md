---
name: secret-sentinel
description: Keeps API keys, tokens, passwords and private keys out of code, commits, prompts, logs and MCP configs, and walks through the fix when one leaks. Use before every commit or push, when writing config or .env files, when the user pastes or mentions a credential, before quoting logs or command output, when setting up MCP servers, or when a key was exposed. Uses the secret-sentinel MCP tools or CLI (64 detectors, base64-aware, local only, every finding redacted).
license: MIT
compatibility: Works with any agent that reads SKILL.md. Scanning needs the secret-sentinel MCP server or CLI (Python 3.10+); the remediation playbooks work without them.
metadata:
  version: "0.3.0"
  homepage: "https://github.com/AleBrito124356/mcp-secret-sentinel"
---

# Secret Sentinel

A leaked credential is compromised the moment it is pushed, pasted into a
prompt or printed into a log, even if the next commit deletes it. This skill
makes the agent check before those moments and fix things properly after.

## Ground rules (always)

1. **Never repeat a secret.** Not in replies, commit messages, code comments,
   summaries or tool arguments. Refer to it by kind and location: "the Stripe
   live key in `config/billing.py` line 12". Scanner output is already redacted
   (`sk_l…(32 chars)`); quote only that.
2. **Never write a real credential into a tracked file.** Put it in the
   environment or an untracked `.env` (listed in `.gitignore`) and read it from
   there. Writing to an ignored `.env` is fine; that is where it belongs.
3. **Rotation beats deletion.** Once a secret was committed, pushed, shared or
   sent to a model, removing it does not make it safe. Say so plainly and point
   to the rotation step.
4. **Do not try to "test" whether a found key works** by calling the provider.
   That is the owner's call, and it can trigger alerts or charges.

## Tools

Prefer the MCP tools when the `secret-sentinel` server is connected. Otherwise
use the CLI. Both run locally and never print a full secret.

| Need | MCP tool | CLI |
|---|---|---|
| Before a commit | `scan_git_staged` | `mcp-secret-sentinel scan --staged` |
| Before a push | `scan_git_range` (base `origin/main` if no upstream) | `mcp-secret-sentinel scan --range` |
| A file or tree | `scan_file`, `scan_directory` | `mcp-secret-sentinel scan PATH` |
| A snippet you are about to write | `scan_text` | `echo ... \| mcp-secret-sentinel scan -` |
| History (what already leaked) | `scan_git_history` | `mcp-secret-sentinel scan --history 200 --all-branches` |
| Clean a log or output before quoting it | `redact_text` | `mcp-secret-sentinel redact FILE` |
| MCP client configs, CLAUDE.md, AGENTS.md | `scan_agent_configs` | `mcp-secret-sentinel agents .` |

If neither is available, offer the one-time install (it downloads the package
from PyPI, so ask first): `uvx mcp-secret-sentinel scan .` runs it without
installing, `pipx install mcp-secret-sentinel` installs the CLI, and
`claude mcp add secret-sentinel -- uvx mcp-secret-sentinel` adds the MCP server
to Claude Code. Without a scanner, still apply the ground rules and the
checklists below.

## Workflows

### Before committing or pushing

1. Run the staged scan. If it is clean and a push follows, run the range scan.
2. For each finding, report file, line, detector and severity (from the
   redacted result), then fix it as in "Fixing a finding".
3. A finding in a commit that is not pushed yet: fix the file, then amend or
   rebase that commit so the secret is gone from every unpushed commit. Re-run
   the range scan to confirm.
4. Give a clear verdict: "safe to push" or "not safe to push, because ...".

### Writing code or config that needs a credential

Write the lookup, never the value:

- Python: `os.environ["STRIPE_API_KEY"]` (or `os.getenv` with an explicit error)
- Node/TS: `process.env.STRIPE_API_KEY`
- Go: `os.Getenv("STRIPE_API_KEY")`; Rust: `std::env::var("STRIPE_API_KEY")`
- Shell / CI: `"$STRIPE_API_KEY"`, set as a masked CI secret
- Docker / Compose: `env_file: .env` or `${STRIPE_API_KEY}`, not a literal
- Kubernetes: a Secret created out of band (`kubectl create secret ...`), or an
  external secrets operator. Base64 in a manifest is encoding, not protection:
  the scanner decodes it.

Then make sure `.env` is in `.gitignore`, and add a committed `.env.example`
with placeholder values (`STRIPE_API_KEY=your-key-here`).

### When the user pastes a credential

Do not echo it back. Tell them it is now in the conversation history (and the
provider's logs), recommend rotating it if it is a production credential, and
ask them to set it as an environment variable that you then reference by name.

### Before quoting logs, stack traces, configs or command output

Run `redact_text` (or `mcp-secret-sentinel redact`) on the text and quote the
result. Every secret becomes `[REDACTED:<detector>]`; everything else is kept.

### Setting up or reviewing MCP servers and agent configs

Run `scan_agent_configs` with the project path. Fix files that git tracks
first: a key in `.mcp.json` ships with the repository. Each client has its own
way to reference the environment; see `references/agent-configs.md`.

### Turning on the guardrails

Offer these once per project, and explain each before running it:

- `mcp-secret-sentinel install-hook`: a git pre-commit hook that blocks commits
  adding secrets.
- `mcp-secret-sentinel install-agent-hooks --agent claude` (or `cursor`): agent
  hooks that deny file writes, shell commands, MCP calls and prompts that carry
  a secret, and redact secrets from tool output before the model sees them.
- CI: the `AleBrito124356/mcp-secret-sentinel` GitHub Action, which uploads
  redacted SARIF to code scanning.
- A project can tune the scanner with `.secret-sentinel.toml` (custom rules,
  excluded paths, disabled detectors) and accept reviewed findings with
  `mcp-secret-sentinel baseline`.

## Fixing a finding

1. **Classify it.** Fixture or documentation example? Prefer a value that is
   obviously fake (`your-key-here`, `${API_KEY}`), or mark the line with
   `# secret-sentinel: ignore` and say why. Real credential? Continue.
2. **Remove the literal**, replacing it with an environment lookup (above).
3. **Rotate it if it ever left the machine**: committed, pushed, pasted, logged,
   or sent to a model. Provider steps are in `references/rotation.md`. The
   finding's `advice` field names the place to do it.
4. **Check for use** in the provider's audit or usage logs since the exposure.
5. **History**: if it was pushed, rewriting history is optional once the key is
   rotated, and never a substitute for rotation. When the user wants it, follow
   `references/history-cleanup.md` and confirm before any force-push.
6. **Prevent a repeat**: offer the guardrails above.

## Reading the scanner's output

- `severity`: `critical` (cloud, payments, infrastructure, private keys),
  `high` (API keys and tokens), `medium` (JWTs and high-entropy strings, which
  are worth a look but often harmless).
- `(base64)` in the detector name: the secret was found inside a base64 run.
- `suppressed` / `baselined`: findings silenced by inline comments or accepted
  in the baseline. Mention them if the user asks what was skipped.
- `truncated: true`: only the most severe findings are listed; the totals are in
  `counts_by_severity` and `top_files`.
