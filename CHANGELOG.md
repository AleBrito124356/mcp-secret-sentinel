# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-10-19

Agent guardrails: the scanner now sits where AI coding agents handle
secrets, not only at commit time.

### Added

- **Agent hooks** (`mcp-secret-sentinel hook`) for Claude Code, Codex and Cursor. `PreToolUse` denies `Write` / `Edit` / `MultiEdit` / `NotebookEdit` / `Bash` / `mcp__*` calls whose content, command or arguments carry a secret, with a redacted reason and the fix. Writes to git-ignored files (a local `.env`) and files outside any repository are allowed; a tracked `.env` is still protected. `UserPromptSubmit` blocks a prompt with a secret and sets `suppressOriginalPrompt`. `PostToolUse` returns `updatedToolOutput` with every secret in the tool's output replaced, keeping the output's shape. Cursor's `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` and `beforeSubmitPrompt` are handled too. Defaults to blocking `high` and above (`--fail-on`), honours config excludes, exempts the server's own tools and fails open on anything unexpected.
- `install-agent-hooks --agent claude|cursor [--scope project|local|user]` merges the hooks into the agent's settings, idempotently and without touching other hooks.
- **Claude Code plugin and marketplace** (`.claude-plugin/`): one `/plugin install` brings the skill, the hooks (run from the checkout by a POSIX launcher, stdlib only) and the MCP server (`uvx --from` the plugin directory).
- **Agent skill** (`skills/secret-sentinel/`, agentskills.io format): when to scan, how to write credential lookups, how to fix a finding, plus references for rotating 40+ credential types, cleaning git history and keeping keys out of each MCP client's config.
- **`scan_agent_configs`** tool and `agents` command: audits the MCP client and agent files of the project (`.mcp.json`, `.claude/settings*.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/`, `.codex/`, CLAUDE.md, AGENTS.md, .cursorrules...) and of the user (Claude Code, Claude Desktop, Cursor, VS Code, Cline, Windsurf, Gemini CLI, Codex, Kiro, Continue, Zed...), optionally session transcripts. Project files report whether git tracks them, and files with findings carry a client-specific hint for referencing the environment.
- **`redact_text`** tool and `redact` command: the text with every secret replaced by `[REDACTED:<detector>]`, everything else byte-for-byte (line endings included).
- **31 new detectors** (64 in total), from the gitleaks, betterleaks and trufflehog rule sets: xAI, DeepSeek-style `sk-<hex>`, Perplexity, Replicate, Together AI, Cerebras, AWS Bedrock API keys, LangSmith, Langfuse, Pinecone, Firecrawl, Tavily, Supabase (`sb_secret_`, `sbp_`), Vercel, Cloudflare, HashiCorp Vault, Doppler, Databricks, Grafana, Sentry, Atlassian, Linear, Notion, Postman, PlanetScale, Neon, Fly.io, Resend, Mailchimp, PostHog and Square.
- **Base64 decoding**: base64 runs (standard or URL-safe) that decode to printable text are scanned again, one level deep, so secrets in Kubernetes Secret manifests, Basic auth headers or encoded PEM keys are found. Findings are named `<detector> (base64)`, and `redact_text` masks the whole encoded run.
- **Project configuration**: `.secret-sentinel.toml` or `[tool.secret-sentinel]` in `pyproject.toml`, found upwards from the scanned path to the repository root, with `exclude_paths` (globs with `**`), `allowlist` regexes, `disable`d detectors and custom `[[rules]]`. Strict validation: unknown keys, detector names and bad regexes are errors. `init` writes a commented starter file. Applies to the CLI, the MCP tools and the hooks.
- **Baselines**: `baseline` records salted PBKDF2 fingerprints of reviewed findings; later scans report only new secrets and count the rest in `baselined`. Location-independent, so accepted values survive refactors. `scan --baseline FILE`, `--config FILE` and `--no-config` control it.
- **Structured output**: the scan tools declare typed results, so MCP SDK 1.10+ / 2.x publish an `outputSchema` and return `structuredContent`.
- MCP prompts `pre_push_check`, `leak_response` and `audit_agent_configs`, and a `secret-sentinel://patterns` resource.
- **GitHub Action** (`action.yml`): scans the tree or a commit range, uploads redacted SARIF to code scanning, writes the report to the job summary and fails on findings at or above `fail-on`.
- gitleaks' `gitleaks:allow` inline marker is honoured, like `secret-sentinel: ignore` and `pragma: allowlist secret`.
- Hardening from a pre-release review: `redact_text` (and the `PostToolUse` hook) removes a private key as a whole block, header to footer, including JSON-escaped keys and keys with no footer; the hook reads its event as UTF-8 regardless of the Windows code page, covers Claude Code's `PowerShell` tool, keeps scanning when git fails for a reason other than "not a repository", answers `"ask"` to edits of the scanner's own config and baseline, and exits 1 (never 2) on internal errors; `scan_directory` walks a folder git ignores and nested repositories instead of reporting them clean; base64 runs right after `=` and up to 20,000 characters are decoded; `baseline` writes where scans read it; reinstalling agent hooks keeps other hooks that share a matcher group; the action separates scan errors from findings and has a `use-config` input for untrusted pull requests.
- CI runs on Linux, Windows and macOS, Python 3.10 to 3.13, both MCP SDK majors, plus a self-scan with the action.

### Changed

- **`scan_directory` inside a git work tree lists files with git** (tracked plus untracked, not ignored), so every `.gitignore` level, negations, `.git/info/exclude` and the global excludes file are honoured exactly. Outside git it walks the tree as before.
- Three new allowlist rules for generic assignments and the entropy check: values shaped like a regular expression (hook matchers, token patterns), plain links without credentials, query or fragment, and filesystem paths (Windows, UNC, home-relative and plain /rooted paths), which a real audit of agent configs showed to be the main source of entropy false positives.
- The suppression note in summaries no longer lists the markers.
- Dependencies: `typing_extensions` (already installed with mcp) is declared, and `tomli` on Python 3.10 for the configuration file.

## [0.2.0] — 2026-09-23 (merged to main, never published to PyPI)

### Fixed

- **The server did not start on a fresh install.** The unpinned `mcp>=1.2.0` now resolves to mcp 2.x, which renamed `mcp.server.fastmcp.FastMCP` to `mcp.server.mcpserver.MCPServer`, so both `mcp-secret-sentinel` and `python -m mcp_secret_sentinel.server` crashed with `ModuleNotFoundError`. `server.py` now imports whichever class the installed SDK provides, and the dependency is `mcp>=1.7,<3`. The suite passes on mcp 1.7.0, 1.30.0 and 2.2.0.
- **The git tools hung forever under mcp 1.x on Windows.** git inherited the server's stdin, which is the MCP protocol pipe; duplicating that handle blocks while the SDK's reader thread waits on it. git now always runs with stdin closed.
- Tool errors (missing path, not a git repository) reach the agent with their message. mcp 2.x replaces the text of unexpected exceptions with a bare "Error executing tool", so core `ValueError`s are re-raised as `ToolError`.
- The README promised `uvx mcp-secret-sentinel`, `pip install mcp-secret-sentinel` and PyPI badges for a package that was never published. The install instructions now use the git URL, which works today.
- **`scan_git_staged` reported "no staged changes" for a staged secret when `diff.external` was configured (difftastic and similar), and git ran that external program.** Every git call now passes `--no-ext-diff --no-textconv` and fixed `a/`/`b/` prefixes, and forces `core.quotePath`, `core.fsmonitor`, `diff.noprefix`, `diff.mnemonicPrefix`, `diff.relative`, `diff.submodule`, `log.showSignature` and `log.showRoot` with `-c`. It also drops `GIT_EXTERNAL_DIFF`/`GIT_DIFF_OPTS` and takes no optional locks.
- File paths in git findings were wrong under `diff.mnemonicPrefix` (`i/notify.py`), under `diff.noprefix` (a real `b/` directory was dropped) and for non-ASCII names (`"b/configuraci\303\263n.py"`). C-quoted names are now decoded.
- An added line that started with `++ ` was taken as a new file header, and every finding after it got the wrong file and line. The diff parser is now a state machine that counts hunk lines.
- `diff.interHunkContext` merged hunks with context lines, and those lines shifted the reported line numbers. With `log.showRoot=false` the root commit was never scanned.
- **A literal password in a connection string was hidden when the host was templated or contained "example".** `postgres://app:<pw>@${DB_HOST}/app` and `mysql://root:<pw>@db.examplecorp.net/prod` came back clean. The allowlist now judges only the password, and only the reserved documentation hosts (`example.com/.net/.org`, `*.example`, `*.invalid`) are exempt.
- UTF-16 text files (the default output of Windows PowerShell 5.1's `>` / `Out-File`) were classed as binary and never scanned. Files are now decoded by byte-order mark (UTF-8, UTF-16, UTF-32) before the null-byte check, and BOM-less UTF-16 is recognised too. With a UTF-8 BOM, a first-line `KEY=value` assignment used to be missed.
- Line numbers drifted after `\f`, `\v`, `\x1c`-`\x1e`, `\x85`, U+2028 and U+2029, because `str.splitlines()` splits on them. Lines are now split on `\n` only.
- False positives on placeholder syntaxes: `$VAULT_DB_PASSWORD`, `$(command)`, `$env:VAR`, `%VAR%`, `{{ jinja }}`, `{% %}`, `<%= erb %>`, `#{ruby}`, `%(name)s` and `{name}`. For generic assignments only, the same applies to code: `API_SECRET = os.getenv("API_SECRET")`, `DB_PASSWORD = settings.DATABASE_PASSWORD` and string concatenation fragments.
- A virtualenv whose folder was not literally `.venv`/`venv` (such as `env/`) was walked and used up the whole `max_files` budget. Virtualenvs and conda envs are now found by `pyvenv.cfg` / `conda-meta`, and `site-packages`, `.tox`, `.nox`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache` and `__pypackages__` are skipped.
- Redaction showed the first 4 characters however short the secret, which is half of an 8-character password. It now shows `min(4, len // 4)` characters.
- **Scanning time was quadratic on long lines.** The entropy candidate regex restarted at every position inside a run of word characters, so a single 100,000-character line (a minified bundle not named `*.min.js`) took 261 s. The same line now takes 38 ms, and a 40,000-line benchmark went from 34 s to 4.5 s.

### Added

- `scan_git_range(repo_path, base="@{upstream}", head="HEAD", max_commits=200)` scans exactly what the next `git push` would publish, tags each finding with its commit, and adds `commits_scanned`/`range` to the report. When the branch has no upstream, the error says which `base` to pass. Revisions that start with `-` are rejected, so the argument can never become a git option.
- `scan_git_history(..., all_branches=True)` walks every branch, tag and the stash.
- 14 new detectors: OpenRouter, Groq, Hugging Face, GitLab (`glpat-`, `glptt-`, `gldt-`, `glrt-`), npm, PyPI, Telegram bot tokens, SendGrid, Google OAuth client secrets, Shopify, DigitalOcean, Azure storage account keys, `age` secret keys, and `user:password@` in http(s)/ftp/smtp URLs. Existing detectors were widened: OpenAI to project, service-account and admin keys (`sk-proj-`, `sk-svcacct-`, `sk-admin-`); GitHub to `ghu_`/`ghr_`; Slack to `xoxa/xoxo/xoxs/xoxr/xoxe/xapp`; AWS to `ASIA` temporary keys; and connection strings to MariaDB/`amqps`/`rediss`. That makes 33 detectors in total.
- Inline suppression: a line containing `secret-sentinel: ignore` or detect-secrets' `pragma: allowlist secret` produces no findings. Results report `"suppressed": N`, and `list_patterns` documents the markers.
- Binary files in a staged diff or in history are named in the summary instead of being skipped silently.
- **Command line** (`mcp_secret_sentinel/cli.py`, wired to the existing console script). With no arguments it still serves MCP over stdio, so client configs are unchanged. `scan [PATH…|-] [--staged | --range [BASE..HEAD] | --history N [--all-branches]] [--format text|json|sarif] [--fail-on critical|high|medium] [--max-findings N] [--max-files N] [-o FILE]` exits 0 when clean, 1 on findings at or above `--fail-on`, and 2 on usage errors. `patterns` lists the detectors, and `python -m mcp_secret_sentinel` works too.
- `install-hook [REPO] [--force] [--fail-on …]` writes a `pre-commit` hook (honouring `core.hooksPath`) that runs `scan --staged`. It never overwrites another tool's hook without `--force`, and then keeps a `.bak` copy. `.pre-commit-hooks.yaml` publishes the same check for the pre-commit framework (checked with `pre-commit try-repo`: fails on a staged key, passes when clean).
- SARIF 2.1.0 output (`mcp_secret_sentinel/sarif.py`) for GitHub code scanning. It has one rule per detector with `security-severity`, redacted messages, `startLine` locations, percent-encoded URIs and stable fingerprints, and it validates against the official SARIF schema.
- `max_findings` (default 200, `0` = no limit) on every scan function and MCP tool. A capped report lists the most severe findings and adds `truncated`, `total_findings`, `counts_by_severity`, `counts_by_pattern` and `top_files`. 3,000 hits used to produce a 1 MB tool result. **Behaviour change:** library callers who need every finding pass `max_findings=0`.
- Read-only tool annotations (`readOnlyHint`, `idempotentHint`, `destructiveHint=false`, `openWorldHint=false`) on every tool, and server instructions that tell the agent when to call which tool.
- `tests/test_server.py`: spawns the real server over stdio and drives every tool with the SDK's `ClientSession`, including error results and a check that no raw secret crosses the wire.
- The suite grew from 65 to 211 tests (`test_git.py`, `test_detection.py`, `test_cli.py`, `test_server.py`), and it passes on mcp 1.7.0, 1.30.0 and 2.2.0. A test scans this repository and requires it to be clean. 0.1.0 was not clean: it had 3 false positives in its own test file.

## [0.1.0] — 2026-07-26

### Added

- Six MCP tools: `scan_text`, `scan_file`, `scan_directory`, `scan_git_staged`, `scan_git_history` and `list_patterns`.
- Nineteen regex detectors (GitHub, OpenAI, Anthropic, NVIDIA, Google, Stripe, Twilio, AWS, Slack, Discord, JWTs, private key blocks, credentialed connection strings and generic/dotenv assignments), plus a Shannon-entropy detector at 4.5 bits/char for random-looking assigned strings.
- Placeholder-aware allowlist: too-short, masked, `example`, `placeholder`, `changeme`, `your-…-here`, `<angle brackets>`, `${TEMPLATE_VARS}` and environment lookups are never reported.
- Redaction guarantee enforced at a single `redact()` choke point: every finding shows only the first 4 characters plus the length, so the full secret never reaches the tool output, the transcript or the logs.
- Pre-commit checkpoint over git: `scan_git_staged` inspects exactly the lines the next commit would publish, and `scan_git_history` tags each finding with the commit that introduced it.
- Directory walking that skips `.git`, `node_modules`, virtualenvs, `__pycache__`, `dist`, `build`, minified bundles, lockfiles, binaries and files over 5 MB, honoring simple root `.gitignore` patterns.
- 65 tests covering every detector, the allowlist, entropy math, redaction, directory walking and real temporary git repositories — with no realistic secret literal anywhere in the suite (every positive fixture is assembled at runtime by concatenation).

[0.1.0]: https://github.com/AleBrito124356/mcp-secret-sentinel/releases/tag/v0.1.0
[0.3.0]: https://github.com/AleBrito124356/mcp-secret-sentinel/releases/tag/v0.3.0
