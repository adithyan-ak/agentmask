# agentmask

Secrets never enter context. AI never misses a beat.

<p align="center">
  <img src="https://raw.githubusercontent.com/adithyan-ak/agentmask/main/agentmask.gif" alt="agentmask demo" width="720" />
</p>

agentmask prevents Claude Code, Cursor, and other AI coding assistants from reading, leaking, or committing your secrets. It works through three reinforcing layers:

1. **Block** — Hooks that prevent secret files from being read and secret values from being written
2. **Redirect** — An MCP server that provides redacted file access so the agent can still work
3. **Instruct** — Behavioral rules that teach the agent to prefer safe alternatives

## Quickstart

```bash
npm install -g agentmask
cd your-project
agentmask init
```

`init` scans your entire repository for secrets, builds a blocklist of every file containing them, and installs hooks + MCP server + behavioral rules for all detected IDEs. Secrets are blocked before they ever enter the AI's context.

agentmask auto-detects which IDEs are present (Claude Code, Cursor) and configures both. Use `--claude` or `--cursor` to target a specific IDE.

## What It Does

| Scenario | What Happens |
|----------|-------------|
| Claude tries to `Read .env` | **Blocked.** Static pattern match. Redirected to `safe_read`. |
| Claude tries to read `src/config.ts` (has hardcoded AWS key) | **Blocked.** Found by init scan, in blocklist. Redirected to `safe_read`. |
| Claude writes `sk_live_...` into source code | **Blocked.** Content scan catches it. Told to use env var instead. |
| Claude runs `cat .env` via Bash | **Blocked.** Command pattern match. |
| Claude runs `git commit` with secrets in staged files | **Blocked.** Pre-commit scan. Shown file:line of each secret. |
| Claude reads a new file with a secret (not yet in blocklist) | **Warned + auto-blocklisted.** First read leaks, every subsequent read is blocked. |
| Claude does normal coding (90%+ of operations) | **No effect.** Sub-50ms hook, completely invisible. |

## How It Works

```
agentmask init
    │
    ├── Scans entire repo for secrets (gitleaks 150+ rules + agentmask rules)
    ├── .agentmask/blocklist.json          ← files containing detected secrets (shared)
    ├── .claude/settings.local.json        ← Claude Code hooks
    ├── .cursor/hooks.json                 ← Cursor hooks
    ├── .claude/rules/agentmask.md         ← behavioral rules (Claude)
    ├── .cursor/rules/agentmask.mdc        ← behavioral rules (Cursor)
    ├── .mcp.json                          ← MCP server (Claude)
    └── .cursor/mcp.json                   ← MCP server (Cursor)
```

Only files for detected IDEs are created. The blocklist is shared.

**Layer 1 — Block (Hooks):**
PreToolUse hooks intercept every Read, Bash/Shell, Write, and Edit call. Pre-read checks two things: static file patterns (`.env`, `*.pem`, etc.) and the dynamic blocklist (files where secrets were found by the init scan or by post-scan at runtime). If matched, the operation is blocked and the agent receives guidance to use `safe_read`.

**Layer 2 — Redirect (MCP Server):**
When a read is blocked, the agent is directed to the `safe_read` MCP tool, which returns the file content with secrets replaced:

```
DATABASE_URL=[REDACTED:generic-api-key]
API_KEY=[REDACTED:stripe-access-token]
DEBUG=true          ← non-secret values kept as-is
PORT=3000           ← non-secret values kept as-is
```

**Layer 3 — Instruct (Rules):**
Behavioral rules teach the agent to prefer safe tools and never output raw secret values. Installed at `.claude/rules/agentmask.md` and `.cursor/rules/agentmask.mdc`.

## The Blocklist

The blocklist (`.agentmask/blocklist.json`) is the key to blocking secrets before they enter context:

- **Built at init time** — `agentmask init` scans every file in the repo using gitleaks (150+ provider-specific rules) plus agentmask's own scanner (password fields, connection strings, and provider prefixes gitleaks misses)
- **Updated at runtime** — if post-scan detects a secret in a file that wasn't in the blocklist, it's added automatically
- **Checked on every read** — pre-read hook looks up the file in the blocklist before allowing the read
- **Re-run `agentmask init`** anytime to rescan (e.g., after pulling new code)
- **`agentmask allow-path`** removes a file from the blocklist (after you've fixed the secret)

## Detection

Detection runs in two complementary passes on every scan, merged into a single unified list of findings:

**gitleaks (150+ rules):** provider-specific tokens (AWS, GitHub, Stripe, Google, GCP, Slack, SendGrid, Shopify, OpenAI, Anthropic, GitLab, Twilio…), PEM keys, JWTs, and a `generic-api-key` rule that catches high-entropy values assigned to variable names matching `key`/`token`/`secret`/`api`/`auth`/`client`. Auto-downloaded if not installed.

**agentmask (fills gitleaks gaps):** pure in-process TypeScript rules for patterns gitleaks's generic rule deliberately excludes:

- `password` / `passwd` / `pwd` field assignments in JSON, YAML, TOML, shell, compose, Makefiles, etc.
- SQL `PASSWORD 'value'` assignments (ALTER/CREATE USER, etc.)
- Connection strings with embedded credentials (`postgres://user:pass@host`, `mysql://`, `mongodb://`, `redis://`, `amqp://`)
- `whsec_…` webhook signing secrets
- `GOCSPX-…` Google OAuth client secrets

The agentmask scanner runs automatically alongside every gitleaks scan — no flags, no config. Common placeholders (`changeme`, `your-…`, `${VAR}`, `<password>`) are skipped to keep false positives low.

**Requires:** `gitleaks` (auto-installed) or `brew install gitleaks`. The agentmask scanner is pure TypeScript — no extra dependencies.

## Commands

```bash
agentmask init              # Scan repo, build blocklist, install for all detected IDEs
agentmask init --team       # Write to shared team settings (committed to git)
agentmask init --cursor     # Install for Cursor only
agentmask init --claude     # Install for Claude Code only
agentmask remove            # Remove everything cleanly (hooks, rules, MCP, blocklist)
agentmask remove --cursor   # Remove from Cursor only
agentmask scan [path]       # Scan files for secrets (report only)
agentmask scan --staged     # Scan git staged files
agentmask scan --json       # JSON output for CI/CD
agentmask allow-path "p"    # Allowlist a path + remove from blocklist
agentmask allow-value "v"   # Allowlist a specific value
agentmask serve             # Start the MCP server (called automatically)
```

## MCP Tools

When the MCP server is running, Claude Code has access to:

| Tool | Description |
|------|-------------|
| `safe_read` | Read a file with secrets redacted |
| `env_names` | List .env variable names and types without values |
| `scan_file` | Scan a file for secrets (explicit security review) |
| `scan_staged` | Scan git staging area before committing |

## Configuration

Create `.agentmask.toml` in your project root:

```toml
# Add custom blocked file patterns
[scan]
blocked_paths = [".env.custom", "**/my-secrets.yml"]

# Allowlist paths (e.g., test fixtures with dummy secrets)
[[allowlists]]
paths = ["tests/**", "**/*.test.ts", "fixtures/**"]
description = "Test files may contain dummy secrets"

# Allowlist specific values
[[allowlists]]
stopwords = ["EXAMPLE_KEY_12345"]
description = "Known test values"
```

## False Positives

If agentmask blocks something it shouldn't:

```bash
# Allowlist a path pattern (also removes from blocklist)
agentmask allow-path "tests/**"

# Allowlist a specific value
agentmask allow-value "EXAMPLE_KEY_12345"
```

These write to `.agentmask.toml` in your project root.

## What It Cannot Do

- **First read of a brand-new secret file** still enters context — post-scan catches it and blocklists it, so subsequent reads are blocked. This is unavoidable without reading every file before Claude does.
- **Cannot catch every bash command** that accesses secrets (covers `cat .env`, `printenv`, etc. but not `node -e "console.log(process.env.X)"`)
- **Cannot prevent Claude from saying a secret** in chat output (hooks only cover tool calls)
- **Cannot validate** whether a detected secret is real or dummy without network calls
- If agentmask crashes, it **degrades gracefully** — the operation proceeds (never blocks your work due to a bug)

## Graceful Degradation

agentmask is designed to never block your work due to its own failure:

- Hook crashes → exit code 1 → Claude Code treats as non-blocking warning
- MCP server crashes → Claude falls back to built-in Read/Write
- Malformed input → allow, don't block
- 4-second safety timeout on every hook (Claude Code's limit is 5s)

## Protected File Patterns

By default, agentmask blocks direct reading of these patterns (static, always active):

`.env`, `.env.*`, `credentials.json`, `serviceAccountKey.json`, `service-account*.json`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `.netrc`, `.npmrc`, `.pypirc`, `.docker/config.json`, `.kube/config`, `kubeconfig`, `.aws/credentials`, `.aws/config`, `.azure/credentials`, `.gcloud/*.json`, `secrets.yml`, `secrets.yaml`, `secrets.json`, `.htpasswd`

In addition, `agentmask init` scans all other files and blocklists any that contain secrets.

## License

MIT
