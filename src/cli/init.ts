import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { execSync } from "node:child_process";
import { isBlockedPath, DEFAULT_BLOCKED_PATTERNS, isBinaryFile } from "../scanner/file-patterns.js";
import { scanContent } from "../scanner/scanner.js";
import { TIER1_RULES } from "../scanner/rules.js";
import { saveBlocklist, type BlocklistData } from "../hooks/blocklist.js";
import type { Finding } from "../scanner/types.js";

interface InitOptions {
  team?: boolean;
}

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".nuxt",
  "__pycache__", ".venv", "venv", ".tox", ".mypy_cache",
  "vendor", "target", ".idea", ".vscode",
  ".claude", ".agentmask",
]);

export async function runInit(options: InitOptions): Promise<void> {
  const cwd = process.cwd();
  const binPath = getBinPath();

  // === Step 1: Scan entire repo for secrets ===
  console.log("Scanning repository for secrets...");
  const { fileCount, findings, blocklist } = scanRepo(cwd);
  const blocklistEntryCount = Object.keys(blocklist.files).length;

  // Count static-blocked files
  const staticBlocked = findStaticBlockedFiles(cwd);

  console.log(`  Scanned ${fileCount} files.`);

  if (findings.length > 0) {
    console.log("");
    console.log(`  Found secrets in ${blocklistEntryCount} file(s):`);
    for (const f of findings.slice(0, 20)) {
      const relPath = relative(cwd, resolve(cwd, f.filePath));
      const severityTag = f.severity === "critical" ? "[CRIT]" : "[HIGH]";
      console.log(`    ${severityTag} ${relPath}:${f.line} — ${f.description}`);
    }
    if (findings.length > 20) {
      console.log(`    ... and ${findings.length - 20} more`);
    }
  }

  if (staticBlocked.length > 0) {
    console.log("");
    console.log("  Protected by default (static patterns):");
    for (const f of staticBlocked.slice(0, 10)) {
      console.log(`    [blocked] ${f}`);
    }
    if (staticBlocked.length > 10) {
      console.log(`    ... and ${staticBlocked.length - 10} more`);
    }
  }

  // === Step 2: Save blocklist ===
  const settingsDir = join(cwd, ".claude");
  mkdirSync(settingsDir, { recursive: true });
  saveBlocklist(cwd, blocklist);

  // === Step 3: Install hooks ===
  const settingsFile = options.team
    ? join(settingsDir, "settings.json")
    : join(settingsDir, "settings.local.json");

  const settings = loadJSON(settingsFile);
  settings.hooks = mergeHooks(settings.hooks ?? {}, binPath);
  writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + "\n");

  // === Step 4: Install rules ===
  const rulesDir = join(settingsDir, "rules");
  mkdirSync(rulesDir, { recursive: true });
  writeFileSync(join(rulesDir, "agentmask.md"), RULES_CONTENT);

  // === Step 5: Register MCP server ===
  const mcpFile = join(cwd, ".mcp.json");
  const mcpConfig = loadJSON(mcpFile);
  mcpConfig.mcpServers = mcpConfig.mcpServers ?? {};
  mcpConfig.mcpServers.agentmask = {
    command: binPath,
    args: ["serve"],
  };
  writeFileSync(mcpFile, JSON.stringify(mcpConfig, null, 2) + "\n");

  // === Summary ===
  const totalProtected = blocklistEntryCount + staticBlocked.length;
  console.log("");
  console.log(`  Hooks installed → ${options.team ? ".claude/settings.json" : ".claude/settings.local.json"}`);
  console.log("  Rules installed → .claude/rules/agentmask.md");
  console.log("  MCP server registered → .mcp.json");
  if (blocklistEntryCount > 0) {
    console.log(`  Blocklist saved → .claude/agentmask-blocklist.json (${blocklistEntryCount} file(s))`);
  }
  console.log("");
  console.log(`agentmask is active. ${totalProtected} file(s) protected.`);
  console.log("Re-run `agentmask init` anytime to rescan.");
}

/**
 * Scan the entire repo for secrets using Tier 1 rules only (zero false positives).
 */
function scanRepo(cwd: string): {
  fileCount: number;
  findings: Finding[];
  blocklist: BlocklistData;
} {
  const files = collectAllFiles(cwd);
  const allFindings: Finding[] = [];
  const blocklist: BlocklistData = { files: {} };

  for (const filePath of files) {
    let content: string;
    try {
      const buf = readFileSync(filePath);
      // Skip binary content (null bytes in first 8KB)
      if (buf.subarray(0, 8192).includes(0)) continue;
      // Limit to 1MB
      content = buf.subarray(0, 1024 * 1024).toString("utf-8");
    } catch {
      continue;
    }

    const relPath = relative(cwd, filePath);
    const findings = scanContent(content, relPath, TIER1_RULES);

    if (findings.length > 0) {
      allFindings.push(...findings);
      const secrets = [...new Set(findings.map((f) => f.description))];
      blocklist.files[relPath.replace(/\\/g, "/")] = {
        secrets,
        addedAt: new Date().toISOString(),
      };
    }
  }

  return { fileCount: files.length, findings: allFindings, blocklist };
}

/**
 * Collect all text files in the repo, respecting skip directories.
 */
function collectAllFiles(dir: string): string[] {
  const files: string[] = [];
  walkDir(dir, files, dir);
  return files;
}

function walkDir(dir: string, files: string[], rootDir: string): void {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.name.startsWith(".") && entry.name !== ".env" && dir === rootDir) {
      // Skip hidden dirs at root level (except check for .env files)
      if (entry.isDirectory()) continue;
    }

    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walkDir(fullPath, files, rootDir);
    } else if (entry.isFile()) {
      if (isBinaryFile(fullPath)) continue;
      // Don't scan files already covered by static blocklist
      if (isBlockedPath(fullPath, DEFAULT_BLOCKED_PATTERNS)) continue;
      files.push(fullPath);
    }
  }
}

/**
 * Find files in the project that match static blocked patterns.
 */
function findStaticBlockedFiles(cwd: string): string[] {
  const results: string[] = [];
  const commonFiles = [
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.staging", ".env.test",
    "credentials.json", "serviceAccountKey.json",
    ".npmrc", ".pypirc",
  ];

  for (const file of commonFiles) {
    if (existsSync(join(cwd, file))) {
      results.push(file);
    }
  }

  return results;
}

function getBinPath(): string {
  try {
    const resolved = execSync("which agentmask", { encoding: "utf-8" }).trim();
    if (resolved) return resolved;
  } catch {}

  const localBin = resolve("node_modules", ".bin", "agentmask");
  if (existsSync(localBin)) return localBin;

  return "npx agentmask";
}

function mergeHooks(
  existing: Record<string, unknown>,
  binPath: string,
): Record<string, unknown> {
  const preToolUse = (existing.PreToolUse as unknown[]) ?? [];
  const postToolUse = (existing.PostToolUse as unknown[]) ?? [];

  const cleanPre = filterOutAgentmask(preToolUse);
  const cleanPost = filterOutAgentmask(postToolUse);

  return {
    ...existing,
    PreToolUse: [
      ...cleanPre,
      {
        matcher: "Read",
        hooks: [{
          type: "command",
          command: `${binPath} hook pre-read`,
          timeout: 5,
        }],
      },
      {
        matcher: "Bash",
        hooks: [{
          type: "command",
          command: `${binPath} hook pre-bash`,
          timeout: 5,
        }],
      },
      {
        matcher: "Write|Edit",
        hooks: [{
          type: "command",
          command: `${binPath} hook pre-write`,
          timeout: 5,
        }],
      },
    ],
    PostToolUse: [
      ...cleanPost,
      {
        matcher: "Read|Bash",
        hooks: [{
          type: "command",
          command: `${binPath} hook post-scan`,
          timeout: 5,
        }],
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
