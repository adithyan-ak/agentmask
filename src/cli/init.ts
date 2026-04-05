import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { execSync } from "node:child_process";
import { getGitleaksBinary } from "../gitleaks/binary.js";
import { scanDir, type GitleaksFinding } from "../gitleaks/runner.js";
import { scanTier2Dir, mergeFindings } from "../scanner/tier2.js";
import { saveBlocklist, type BlocklistData } from "../hooks/blocklist.js";

interface InitOptions {
  team?: boolean;
}

export async function runInit(options: InitOptions): Promise<void> {
  const cwd = process.cwd();

  // === Step 0: Ensure gitleaks is available (auto-downloads if needed) ===
  const gitleaksBin = await getGitleaksBinary();

  // === Step 1: Scan entire repo for secrets ===
  console.log("Scanning repository for secrets...");
  const tier1Findings = await scanDir(cwd);
  const tier2Findings = scanTier2Dir(cwd);
  const findings = mergeFindings(tier1Findings, tier2Findings);
  const blocklist = buildBlocklist(findings, cwd);
  const blocklistEntryCount = Object.keys(blocklist.files).length;

  // Count static-blocked files
  const staticBlocked = findStaticBlockedFiles(cwd);

  if (findings.length > 0) {
    console.log("");
    console.log(`  Found secrets in ${blocklistEntryCount} file(s):`);
    for (const f of findings.slice(0, 20)) {
      const relPath = relative(cwd, f.File);
      const tag = f.Description.toLowerCase().includes("critical") ? "[CRIT]" : "[HIGH]";
      const source = f.RuleID.startsWith("agentmask-") ? " (agentmask)" : " (gitleaks)";
      console.log(`    ${tag} ${relPath}:${f.StartLine} — ${f.Description}${source}`);
    }
    if (findings.length > 20) {
      console.log(`    ... and ${findings.length - 20} more`);
    }
  } else {
    console.log("  No secrets found in source files.");
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
  const binPath = getAgentmaskBinPath();
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

function buildBlocklist(
  findings: GitleaksFinding[],
  cwd: string,
): BlocklistData {
  const blocklist: BlocklistData = { files: {} };

  for (const f of findings) {
    const relPath = relative(cwd, f.File).replace(/\\/g, "/");
    if (!blocklist.files[relPath]) {
      blocklist.files[relPath] = {
        secrets: [],
        addedAt: new Date().toISOString(),
      };
    }
    const entry = blocklist.files[relPath];
    if (!entry.secrets.includes(f.Description)) {
      entry.secrets.push(f.Description);
    }
  }

  return blocklist;
}

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

function getAgentmaskBinPath(): string {
  try {
    const resolved = execSync("which agentmask", { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();
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
      { matcher: "Read", hooks: [{ type: "command", command: `${binPath} hook pre-read`, timeout: 5 }] },
      { matcher: "Bash", hooks: [{ type: "command", command: `${binPath} hook pre-bash`, timeout: 5 }] },
      { matcher: "Write|Edit", hooks: [{ type: "command", command: `${binPath} hook pre-write`, timeout: 5 }] },
    ],
    PostToolUse: [
      ...cleanPost,
      { matcher: "Read|Bash", hooks: [{ type: "command", command: `${binPath} hook post-scan`, timeout: 5 }] },
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
