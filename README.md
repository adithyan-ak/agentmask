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

That's it. agentmask is now active. Claude Code will be blocked from reading `.env` files, prevented from writing hardcoded secrets, and warned when secrets appear in unexpected files.

## What It Does

| Scenario | What Happens |
|----------|-------------|
| Claude tries to `Read .env` | **Blocked.** Guided to use `safe_read` for a redacted view. |
| Claude writes `sk_live_...` into source code | **Blocked.** Told to use `process.env.STRIPE_KEY` instead. |
| Claude runs `cat .env` via Bash | **Blocked.** Redirected to safe_read. |
| Claude runs `git commit` with secrets in staged files | **Blocked.** Shown file:line of each leaked secret. |
| Claude reads a file that happens to contain an AWS key | **Warned.** Post-read advisory not to propagate the value. |
| Claude does normal coding (90%+ of operations) | **No effect.** Sub-50ms hook, completely invisible. |

## How It Works

```
agentmask init
    │
    ├── .claude/settings.local.json    ← PreToolUse + PostToolUse hooks
    ├── .claude/rules/agentmask.md     ← Behavioral rules for Claude
    └── .mcp.json                      ← MCP server registration
```

**Layer 1 — Block (Hooks):**
PreToolUse hooks intercept every Read, Bash, Write, and Edit call. They check file paths against blocked patterns and scan content for 30+ secret patterns. If a secret is detected, the operation is blocked (exit code 2) and Claude receives guidance on what to do instead.

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

## Detection

agentmask detects secrets using two tiers of rules:

**Tier 1 — Provider-specific (near-zero false positives):**
AWS keys (`AKIA...`), GitHub PATs (`ghp_...`), Stripe keys (`sk_live_...`), GCP keys (`AIza...`), Slack tokens, SendGrid, Shopify, OpenAI, Anthropic, Vercel, npm, PyPI, PEM private keys, JWTs, database connection strings, and more. 28 rules.

**Tier 2 — Generic keyword-anchored (entropy-filtered):**
Catches `api_key = "..."`, `password = "..."`, `client_secret: "..."` patterns where the value has high entropy. Filtered by a stopword list to reduce false positives.

## Commands

```bash
agentmask init              # Install hooks, MCP server, and rules
agentmask init --team       # Write to shared .claude/settings.json (committed to git)
agentmask remove            # Remove everything cleanly
agentmask scan [path]       # Scan files for secrets
agentmask scan --staged     # Scan git staged files
agentmask scan --json       # JSON output for CI/CD
agentmask allow-path "p"    # Allowlist a path pattern (e.g., "tests/**")
agentmask allow-value "v"   # Allowlist a specific value (e.g., "EXAMPLE_KEY")
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
stopwords = ["EXAMPLE_KEY_12345", "sk_live_test0000"]
description = "Known test values"
```

## False Positives

If agentmask blocks something it shouldn't:

```bash
# Allowlist a path pattern
agentmask allow-path "tests/**"

# Allowlist a specific value
agentmask allow-value "EXAMPLE_KEY_12345"
```

These write to `.agentmask.toml` in your project root.

## What It Cannot Do

- **Cannot unsee a secret** once a built-in Read returns it (PostToolUse can only warn, not redact)
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

By default, agentmask blocks direct reading of:

`.env`, `.env.*`, `credentials.json`, `serviceAccountKey.json`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa`, `id_ed25519`, `.netrc`, `.npmrc`, `.pypirc`, `.docker/config.json`, `.kube/config`, `.aws/credentials`, `.azure/credentials`, `.gcloud/*.json`, `secrets.yml`, `secrets.yaml`, `secrets.json`, `.htpasswd`

## License

MIT
