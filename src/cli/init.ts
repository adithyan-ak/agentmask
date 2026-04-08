import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { execSync } from "node:child_process";
import { getGitleaksBinary } from "../gitleaks/binary.js";
import { scanDir, type GitleaksFinding } from "../gitleaks/runner.js";
import { scanTier2Dir, mergeFindings } from "../scanner/tier2.js";
import { saveBlocklist, migrateBlocklistIfNeeded, type BlocklistData } from "../hooks/blocklist.js";
import { resolveTargets, loadJSON, RULES_CONTENT, type IdeTarget } from "../ide/targets.js";

interface InitOptions {
  team?: boolean;
  claude?: boolean;
  cursor?: boolean;
}

export async function runInit(options: InitOptions): Promise<void> {
  const cwd = process.cwd();

  // === Step 0: Ensure gitleaks is available (auto-downloads if needed) ===
  const gitleaksBin = await getGitleaksBinary();

  // === Step 1: Resolve IDE targets ===
  const targets = resolveTargets(cwd, options);

  // === Step 2: Scan entire repo for secrets ===
  console.log("");
  console.log("  ◇ Scanning repository for secrets...");
  const tier1Findings = await scanDir(cwd);
  const tier2Findings = scanTier2Dir(cwd);
  const findings = mergeFindings(tier1Findings, tier2Findings);
  const blocklist = buildBlocklist(findings, cwd);
  const blocklistEntryCount = Object.keys(blocklist.files).length;

  // Count static-blocked files
  const staticBlocked = findStaticBlockedFiles(cwd);

  console.log("");
  if (findings.length > 0) {
    console.log(boxTop(`Findings ── ${plural(findings.length, "secret")} · ${plural(blocklistEntryCount, "file")}`));
    console.log(boxEmpty());
    const shown = findings.slice(0, 5);
    const pathCol = Math.max(...shown.map((f) => `${relative(cwd, f.File)}:${f.StartLine}`.length)) + 3;
    for (const f of shown) {
      const loc = `${relative(cwd, f.File)}:${f.StartLine}`;
      console.log(boxLine(`HIGH  ${loc.padEnd(pathCol)}${shortDesc(f.Description)}`));
    }
    if (findings.length > 5) {
      console.log(boxEmpty());
      console.log(boxLine(`… and ${findings.length - 5} more (run \`agentmask scan\` for full report)`));
    }
    console.log(boxEmpty());
    console.log(boxBottom());
  } else {
    console.log(boxTop("Findings"));
    console.log(boxEmpty());
    console.log(boxLine("No secrets found ✔"));
    console.log(boxEmpty());
    console.log(boxBottom());
  }

  if (staticBlocked.length > 0) {
    console.log("");
    console.log(boxTop(`Blocked by pattern ── ${plural(staticBlocked.length, "file")}`));
    console.log(boxEmpty());
    console.log(boxLine(staticBlocked.slice(0, 5).join("    ")));
    if (staticBlocked.length > 5) {
      console.log(boxEmpty());
      console.log(boxLine(`… and ${staticBlocked.length - 5} more`));
    }
    console.log(boxEmpty());
    console.log(boxBottom());
  }

  // === Step 3: Save blocklist (shared, IDE-neutral) ===
  migrateBlocklistIfNeeded(cwd);
  mkdirSync(join(cwd, ".agentmask"), { recursive: true });
  saveBlocklist(cwd, blocklist);

  // === Step 4: Install for each IDE target ===
  const binPath = getAgentmaskBinPath();
  const installedIdes: string[] = [];

  for (const target of targets) {
    const settingsDir = join(cwd, target.settingsDir);
    mkdirSync(settingsDir, { recursive: true });

    // Hooks
    target.installHooks(cwd, binPath, options.team ?? false);

    // Rules
    const rulesDir = join(settingsDir, "rules");
    mkdirSync(rulesDir, { recursive: true });
    writeFileSync(
      join(settingsDir, target.rulesRelPath),
      target.formatRules(RULES_CONTENT),
    );

    // MCP
    const mcpFile = join(cwd, target.mcpConfigPath);
    mkdirSync(join(cwd, target.mcpConfigPath, ".."), { recursive: true });
    const mcpConfig = loadJSON(mcpFile);
    mcpConfig.mcpServers = mcpConfig.mcpServers ?? {};
    mcpConfig.mcpServers.agentmask = { command: binPath, args: ["serve"] };
    writeFileSync(mcpFile, JSON.stringify(mcpConfig, null, 2) + "\n");

    installedIdes.push(target.displayName);
  }

  // === Summary ===
  const totalProtected = blocklistEntryCount + staticBlocked.length;
  const hookPaths = targets.map((t) => getHookDisplayPath(t, options.team ?? false)).join(", ");
  const rulesPaths = targets.map((t) => `${t.settingsDir}/${t.rulesRelPath}`).join(", ");
  const mcpPaths = targets.map((t) => t.mcpConfigPath).join(", ");

  console.log("");
  console.log(boxTop(`Installed ── ${installedIdes.join(" + ")}`));
  console.log(boxEmpty());
  console.log(boxLine(`✔ Hooks       ${hookPaths}`));
  console.log(boxLine(`✔ Rules       ${rulesPaths}`));
  console.log(boxLine(`✔ MCP         ${mcpPaths}`));
  if (blocklistEntryCount > 0) {
    console.log(boxLine(`✔ Blocklist   ${plural(blocklistEntryCount, "file")}`));
  }
  if (options.team && targets.some((t) => t.name === "cursor")) {
    console.log(boxLine(`  (Cursor hooks are always shared)`));
  }
  console.log(boxEmpty());
  console.log(boxLine(`${plural(totalProtected, "file")} protected · agentmask is active`));
  console.log(boxEmpty());
  console.log(boxBottom());
  console.log("");
  console.log("  Re-run `agentmask init` to rescan.");
}

function getHookDisplayPath(target: IdeTarget, team: boolean): string {
  if (target.name === "claude") {
    return team ? ".claude/settings.json" : ".claude/settings.local.json";
  }
  return ".cursor/hooks.json";
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

// ── Box drawing helpers ──

const BOX_WIDTH = 72;

function boxTop(title: string): string {
  const label = ` ${title} `;
  const dashes = BOX_WIDTH - 2 - label.length;
  return `  ┌${label}${"─".repeat(Math.max(0, dashes))}┐`;
}

function boxBottom(): string {
  return `  └${"─".repeat(BOX_WIDTH - 2)}┘`;
}

function boxLine(content: string): string {
  const inner = `  ${content}`;
  const width = BOX_WIDTH - 2;
  if (inner.length > width) {
    return `  │${inner.slice(0, width - 1)}…│`;
  }
  return `  │${inner.padEnd(width)}│`;
}

function shortDesc(description: string): string {
  let s = description.replace(/^Found (?:a |an )?/i, "");
  const comma = s.indexOf(",");
  if (comma > 0) s = s.slice(0, comma);
  return s;
}

function boxEmpty(): string {
  return `  │${" ".repeat(BOX_WIDTH - 2)}│`;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}
