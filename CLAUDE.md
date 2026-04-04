# agentmask — Contributor Context

## What This Is

agentmask is an open-source secrets firewall for AI coding agents. It prevents Claude Code (and eventually other AI assistants) from reading, leaking, or committing secrets like API keys, tokens, passwords, and connection strings.

## Architecture — Three Reinforcing Layers

```
Layer 1: BLOCK (PreToolUse hooks)
  → Intercepts Read, Bash, Write, Edit tool calls
  → Pre-read checks: static patterns (.env, *.pem) + dynamic blocklist
  → Dynamic blocklist built by init scan + updated by post-scan at runtime
  → Blocks access BEFORE secrets enter the model's context
  → Blocks writing hardcoded secrets into source code
  → Scans staged files before git commit

Layer 2: REDIRECT (MCP server)
  → safe_read: returns file content with secrets redacted
  → env_names: lists .env variable names without values
  → scan_file: explicit security scan of any file
  → scan_staged: scan git staging area

Layer 3: INSTRUCT (.claude/rules/agentmask.md)
  → Behavioral rules telling the agent to prefer safe_read
  → Installed automatically by `agentmask init`
```

All three layers are necessary. Without Layer 1, secrets enter context. Without Layer 2, Claude gets stuck after a block. Without Layer 3, Claude repeatedly tries blocked operations.

## The Blocklist System

The key innovation is the **dynamic blocklist** (`.claude/agentmask-blocklist.json`):

1. `agentmask init` scans the entire repo using Tier 1 rules (zero false positives)
2. Every file containing a detected secret is added to the blocklist
3. Pre-read hook checks the blocklist on every Read call — blocked files never enter context
4. Post-scan hook catches secrets in files NOT in the blocklist (new/modified files) and auto-adds them
5. First read of a new secret file still leaks (unavoidable), but every subsequent read is blocked
6. `allow-path` removes entries from the blocklist (after secrets are fixed)
7. Re-running `agentmask init` rescans and rebuilds the blocklist

## Project Structure

```
src/
├── cli.ts                  # CLI entrypoint — Commander.js, 8 commands
├── cli/
│   ├── scan.ts             # `agentmask scan` — file/directory/staged scanning
│   ├── init.ts             # `agentmask init` — scans repo, builds blocklist, installs hooks + MCP + rules
│   ├── remove.ts           # `agentmask remove` — clean uninstall including blocklist
│   └── allowlist.ts        # `allow-path` (also removes from blocklist), `allow-value`
├── scanner/
│   ├── types.ts            # Rule, Finding, ScanResult, Config types
│   ├── rules.ts            # Detection rules: TIER1_RULES, TIER2_RULES, ALL_RULES, STOPWORDS
│   ├── entropy.ts          # Shannon entropy + secret classification heuristics
│   ├── file-patterns.ts    # Blocked path globs, binary detection, allowlists
│   ├── redact.ts           # Format-preserving redaction engine
│   ├── scanner.ts          # Core scan orchestrator: scanContent, scanFile
│   └── index.ts            # Barrel export
├── hooks/
│   ├── common.ts           # Hook I/O: readStdin, block(), allow(), safety timer
│   ├── blocklist.ts        # Dynamic blocklist: load, save, query, add, remove
│   ├── pre-read.ts         # Checks static patterns + dynamic blocklist → blocks or allows
│   ├── pre-bash.ts         # Blocks bash secret access + pre-commit scanning
│   ├── pre-write.ts        # Blocks writing hardcoded secrets to non-.env files
│   └── post-scan.ts        # Scans tool output, warns + auto-adds to blocklist
├── mcp/
│   └── server.ts           # MCP server with 4 tools (uses @modelcontextprotocol/sdk)
└── config/
    ├── loader.ts           # .agentmask.toml config loader + merging
    └── index.ts
```

## Key Design Decisions

- **TypeScript ESM** — same ecosystem as Claude Code and the MCP SDK
- **No binary dependencies** — pure Node.js, runs everywhere Claude Code runs
- **Graceful degradation** — hook crashes → exit 1 (allow), NEVER exit 2 (block). A bug in agentmask must never block the user's work.
- **Hooks use exit code 2 to block, 0 to allow** — this is Claude Code's hook contract
- **4-second safety timeout** on every hook (Claude Code's limit is 5s)
- **Init scan uses Tier 1 rules only** — zero false positives for blocklist building. Tier 2 generic rules are for reporting only.
- **Format-preserving redaction** for connection strings — `postgresql://****:****@host:5432/db` not just `[REDACTED]`
- **Pre-write hook skips .env files** — they're expected to contain secrets; blocking writes to them would break workflows
- **Post-scan warns AND auto-blocklists** — first read of a new secret file leaks (unavoidable), but every subsequent read is blocked

## Detection Engine

### Tier 1 (30 rules) — Provider-specific, zero false positives
Each has a known prefix or format: `AKIA*` (AWS), `ghp_*` (GitHub), `sk_live_*` (Stripe), `GOCSPX-*` (Google OAuth), `AIza*` (GCP), `xoxb-*` (Slack), `SG.*.*` (SendGrid), PEM headers, JWTs, connection strings, etc. **Used for blocklist building.**

### Tier 2 (1 rule) — Generic keyword→operator→value with entropy filtering
Catches `api_key = "high_entropy_value"` patterns. Uses Shannon entropy threshold (3.5 bits/char) and a stopword list to reduce false positives. **Used for reporting only, NOT for blocklist.**

### Adding a New Rule
Add to `TIER1_RULES` in `src/scanner/rules.ts`:
```ts
{
  id: "provider-secret-type",       // kebab-case, unique
  description: "Provider Secret",    // human-readable, shown in output
  regex: /pattern/,                  // must have a capture group for the secret
  keywords: ["prefix"],              // lowercase, used for fast pre-filtering
  secretGroup: 1,                    // which capture group is the secret value
  severity: "critical",              // critical | high | medium | low
}
```
Then add a test in `tests/rules.test.ts` with one positive and one negative case.

## Build & Test

```bash
npm install                         # install dependencies
npm run build                       # or: node node_modules/.bin/tsup
npm test                            # or: node node_modules/.bin/vitest run
```

Build output goes to `dist/`. The CLI entrypoint is `dist/cli.js`.

## Hook Protocol (Claude Code)

Hooks receive JSON on stdin:
```json
{
  "tool_name": "Read",
  "tool_input": { "file_path": ".env" },
  "cwd": "/path/to/project",
  "tool_response": "..." // only for PostToolUse
}
```

Exit codes:
- **0** — allow the operation. Stdout parsed as JSON for `hookSpecificOutput`.
- **2** — block the operation. Stderr shown to Claude as error message.
- **1** (or any other) — non-blocking warning. Operation proceeds.

## Config Format

`.agentmask.toml` at project root:
```toml
[scan]
blocked_paths = [".env.custom"]

[[allowlists]]
paths = ["tests/**"]
description = "Test files"

[[allowlists]]
stopwords = ["EXAMPLE_KEY"]
```

## Test Fixtures

`tests/fixtures/` contains intentional fake secrets for testing detection. These are allowlisted in `.gitleaks.toml`. When adding new test fixtures with secret-format strings, add the path to the gitleaks allowlist.

## What's NOT Built Yet

- HTTP hook mode (hooks call localhost MCP server instead of spawning process — would eliminate startup latency)
- Cursor / Copilot / other IDE support
- Secret validation (checking if a detected key is actually live)
- ML-based classification for reducing Tier 2 false positives
- CI/CD GitHub Actions workflow
- npm publish automation
- SessionStart hook to auto-rescan on new sessions
