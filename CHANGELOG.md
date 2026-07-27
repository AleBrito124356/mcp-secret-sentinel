# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
