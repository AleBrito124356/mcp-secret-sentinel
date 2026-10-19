# Keeping API keys out of agent and MCP client configs

MCP servers usually need an API key, and the quickest setup pastes it into
the client's config file. Project-level files such as `.mcp.json` are meant
to be committed and shared, so a literal key there ships with the repository.
User-level files are not committed, but every tool running as the user can
read them, and dotfile backups copy them.

`scan_agent_configs` (CLI: `mcp-secret-sentinel agents .`) checks all of them
and says which files git tracks. Fix those first.

## Referencing the environment instead

| Client | File | How to avoid the literal |
|---|---|---|
| Claude Code | `.mcp.json`, `~/.claude.json` | `"env": {"API_KEY": "${API_KEY}"}`; `${VAR:-default}` also works. Export the variable in your shell profile or load it with a secrets manager. |
| Claude Code | `.claude/settings.json` `env` block | Keep secrets out of the shared `settings.json`; use your shell environment or the untracked `.claude/settings.local.json`. |
| VS Code (Copilot agent mode) | `.vscode/mcp.json` | Declare an `inputs` entry (`"password": true`) and reference it as `"${input:api-key}"`; VS Code prompts once and stores it securely. Or use `"envFile": "${workspaceFolder}/.env"`. |
| Cursor | `.cursor/mcp.json`, `~/.cursor/mcp.json` | `"${env:API_KEY}"` interpolation or an `envFile`. |
| Claude Desktop | `claude_desktop_config.json` | No variable expansion. Prefer a desktop extension whose sensitive settings go to the OS keychain, or a small launcher script that reads the key from the keychain or environment and then starts the server. |
| Codex, Gemini CLI, Windsurf, others | their config files | Use the client's environment forwarding where it exists; otherwise keep the key in the shell environment and start the client from that shell. |

## Agent instruction files

`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules` and
`.github/copilot-instructions.md` are committed and loaded into every session.
Never put credentials in them. Write where the secret lives instead:
"the API key is in the `STRIPE_API_KEY` environment variable".

## Session transcripts

Claude Code (`~/.claude/projects/`) and Codex (`~/.codex/sessions/`) keep
plaintext transcripts. A key that appears there was also sent to the model
provider. `scan_agent_configs` with `include_transcripts: true` finds them:
rotate the key, then delete the transcript file.

## Suspicious project settings

A cloned repository can ship `.claude/settings.json` or `.mcp.json` that
points the agent at another API endpoint (for example by setting
`ANTHROPIC_BASE_URL`) or starts unexpected MCP servers. Read those files
before trusting a new repository, and approve project MCP servers one by one.
