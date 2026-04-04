# agentmask

Mask your secrets from AI coding agents. One command. Zero friction.

agentmask prevents Claude Code (and other AI coding assistants) from reading, leaking, or committing your secrets. It works through three reinforcing layers:

1. **Block** — Hooks that prevent secret files from being read and secret values from being written
2. **Redirect** — An MCP server that provides redacted file access so the agent can still work
3. **Instruct** — Behavioral rules that teach the agent to prefer safe alternatives

## Quickstart

```bash
npm install -g agentmask
cd your-project
agentmask init
```

`init` scans your entire repository for secrets, builds a blocklist of every file containing them, and installs hooks + MCP server + behavioral rules. Secrets are blocked before they ever enter the AI's context.

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
    ├── Scans entire repo for secrets (Tier 1 rules — zero false positives)
    ├── .claude/agentmask-blocklist.json  ← files containing detected secrets
    ├── .claude/settings.local.json       ← PreToolUse + PostToolUse hooks
    ├── .claude/rules/agentmask.md        ← behavioral rules for Claude
    └── .mcp.json                         ← MCP server registration
```

**Layer 1 — Block (Hooks):**
PreToolUse hooks intercept every Read, Bash, Write, and Edit call. Pre-read checks two things: static file patterns (`.env`, `*.pem`, etc.) and the dynamic blocklist (files where secrets were found by the init scan or by post-scan at runtime). If matched, the operation is blocked and Claude receives guidance to use `safe_read`.

**Layer 2 — Redirect (MCP Server):**
When a read is blocked, Claude is directed to the `safe_read` MCP tool, which returns the file content with secrets replaced:

```
DATABASE_URL=postgresql://****:****@db.example.com:5432/myapp
API_KEY=[REDACTED:28_chars]
DEBUG=true          ← non-secret values kept as-is
PORT=3000           ← non-secret values kept as-is
```

**Layer 3 — Instruct (Rules):**
A `.claude/rules/agentmask.md` file teaches Claude to prefer safe tools and never output raw secret values.

## The Blocklist

The blocklist (`.claude/agentmask-blocklist.json`) is the key to blocking secrets before they enter context:

- **Built at init time** — `agentmask init` scans every file in the repo using Tier 1 rules (provider-specific patterns with zero false positives)
- **Updated at runtime** — if post-scan detects a secret in a file that wasn't in the blocklist, it's added automatically
- **Checked on every read** — pre-read hook looks up the file in the blocklist before allowing the read
- **Re-run `agentmask init`** anytime to rescan (e.g., after pulling new code)
- **`agentmask allow-path`** removes a file from the blocklist (after you've fixed the secret)

## Detection

Detection is powered by [gitleaks](https://github.com/gitleaks/gitleaks) — **150+ battle-tested rules** covering AWS, GitHub, Stripe, Google, GCP, Slack, SendGrid, Shopify, OpenAI, Anthropic, GitLab, Twilio, PEM keys, JWTs, database connection strings, and many more providers.

agentmask auto-downloads gitleaks if it's not already installed. No detection rules to maintain — when gitleaks updates, agentmask benefits automatically.

**Requires:** `gitleaks` (auto-installed) or `brew install gitleaks`

## Commands

```bash
agentmask init              # Scan repo, build blocklist, install hooks + MCP + rules
agentmask init --team       # Write to shared .claude/settings.json (committed to git)
agentmask remove            # Remove everything cleanly (hooks, rules, MCP, blocklist)
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

`.env`, `.env.*`, `credentials.json`, `serviceAccountKey.json`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa`, `id_ed25519`, `.netrc`, `.npmrc`, `.pypirc`, `.docker/config.json`, `.kube/config`, `.aws/credentials`, `.azure/credentials`, `.gcloud/*.json`, `secrets.yml`, `secrets.yaml`, `secrets.json`, `.htpasswd`

In addition, `agentmask init` scans all other files and blocklists any that contain secrets.

## License

MIT
