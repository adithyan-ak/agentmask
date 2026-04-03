import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { execSync } from "node:child_process";
import { isBlockedPath, DEFAULT_BLOCKED_PATTERNS } from "../scanner/file-patterns.js";

interface InitOptions {
  team?: boolean;
}

export async function runInit(options: InitOptions): Promise<void> {
  const cwd = process.cwd();

  // Find the agentmask binary path for hook commands
  const binPath = getBinPath();

  // 1. Install hooks into Claude Code settings
  const settingsDir = join(cwd, ".claude");
  mkdirSync(settingsDir, { recursive: true });

  const settingsFile = options.team
    ? join(settingsDir, "settings.json")
    : join(settingsDir, "settings.local.json");

  const settings = loadJSON(settingsFile);
  settings.hooks = mergeHooks(settings.hooks ?? {}, binPath);
  writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + "\n");
  console.log(
    `  Hooks installed → ${options.team ? ".claude/settings.json" : ".claude/settings.local.json"}`,
  );

  // 2. Install .claude/rules/agentmask.md
  const rulesDir = join(settingsDir, "rules");
  mkdirSync(rulesDir, { recursive: true });
  writeFileSync(join(rulesDir, "agentmask.md"), RULES_CONTENT);
  console.log("  Rules installed → .claude/rules/agentmask.md");

  // 3. Register MCP server in .mcp.json
  const mcpFile = join(cwd, ".mcp.json");
  const mcpConfig = loadJSON(mcpFile);
  mcpConfig.mcpServers = mcpConfig.mcpServers ?? {};
  mcpConfig.mcpServers.agentmask = {
    command: binPath,
    args: ["serve"],
  };
  writeFileSync(mcpFile, JSON.stringify(mcpConfig, null, 2) + "\n");
  console.log("  MCP server registered → .mcp.json");

  // 4. Scan for existing secret files
  const secretFiles = findSecretFiles(cwd);

  console.log("");
  console.log(
    `agentmask is active. ${secretFiles.length} secret file(s) protected.`,
  );
  if (secretFiles.length > 0) {
    for (const f of secretFiles.slice(0, 10)) {
      console.log(`  [protected] ${f}`);
    }
    if (secretFiles.length > 10) {
      console.log(`  ... and ${secretFiles.length - 10} more`);
    }
  }
}

function getBinPath(): string {
  // Try to find the agentmask binary
  try {
    const resolved = execSync("which agentmask", { encoding: "utf-8" }).trim();
    if (resolved) return resolved;
  } catch {
    // Not globally installed — use npx fallback
  }

  // Check if we're running from a local install
  const localBin = resolve("node_modules", ".bin", "agentmask");
  if (existsSync(localBin)) return localBin;

  // Fallback: use npx
  return "npx agentmask";
}

function mergeHooks(
  existing: Record<string, unknown>,
  binPath: string,
): Record<string, unknown> {
  const preToolUse = (existing.PreToolUse as unknown[]) ?? [];
  const postToolUse = (existing.PostToolUse as unknown[]) ?? [];

  // Remove any existing agentmask hooks to make init idempotent
  const cleanPre = filterOutAgentmask(preToolUse);
  const cleanPost = filterOutAgentmask(postToolUse);

  return {
    ...existing,
    PreToolUse: [
      ...cleanPre,
      {
        matcher: "Read",
        hooks: [
          {
            type: "command",
            command: `${binPath} hook pre-read`,
            timeout: 5,
          },
        ],
      },
      {
        matcher: "Bash",
        hooks: [
          {
            type: "command",
            command: `${binPath} hook pre-bash`,
            timeout: 5,
          },
        ],
      },
      {
        matcher: "Write|Edit",
        hooks: [
          {
            type: "command",
            command: `${binPath} hook pre-write`,
            timeout: 5,
          },
        ],
      },
    ],
    PostToolUse: [
      ...cleanPost,
      {
        matcher: "Read|Bash",
        hooks: [
          {
            type: "command",
            command: `${binPath} hook post-scan`,
            timeout: 5,
          },
        ],
      },
    ],
  };
}

function filterOutAgentmask(hooks: unknown[]): unknown[] {
  return hooks.filter((h: any) => {
    const innerHooks = h?.hooks ?? [];
    return !innerHooks.some((ih: any) =>
      typeof ih?.command === "string" && ih.command.includes("agentmask"),
    );
  });
}

function loadJSON(filePath: string): Record<string, any> {
  try {
    return JSON.parse(readFileSync(filePath, "utf-8"));
  } catch {
    return {};
  }
}

function findSecretFiles(cwd: string): string[] {
  const results: string[] = [];

  // Quick check for common secret files in project root
  const commonFiles = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    "credentials.json",
    "serviceAccountKey.json",
    ".npmrc",
    ".pypirc",
  ];

  for (const file of commonFiles) {
    if (existsSync(join(cwd, file))) {
      results.push(file);
    }
  }

  return results;
}

const RULES_CONTENT = `## agentmask — Secrets Protection Rules

These rules are enforced by agentmask hooks. Follow them to avoid
blocked operations and protect user secrets.

### Reading Sensitive Files
- When you need to read files that may contain secrets (.env,
  credentials.json, *.pem, *.key, etc.), use the
  \`mcp__agentmask__safe_read\` tool instead of the built-in Read tool.
- If a Read operation is blocked with a secrets warning, do NOT retry
  the Read. Use \`mcp__agentmask__safe_read\` to get a redacted view.
- To see what environment variables are defined without their values,
  use \`mcp__agentmask__env_names\`.

### Writing Code
- Never hardcode secret values (API keys, tokens, passwords,
  connection strings) in source code. Use environment variable
  references: process.env.VAR_NAME, os.environ["VAR_NAME"], etc.
- If a Write/Edit is blocked for containing a secret, rewrite the
  code to use environment variable references.

### Committing Code
- Before any git commit, run \`mcp__agentmask__scan_staged\` to verify
  no secrets are in staged files.
- If a git commit is blocked for containing secrets, fix the flagged
  files first, then retry the commit.

### General
- Never output raw secret values in your responses. Reference secrets
  by their variable name only (e.g., "your DATABASE_URL" not the
  actual connection string).
- When you see a [REDACTED:...] placeholder, do not attempt to
  discover the actual value. Work with the variable name.
`;
