import { existsSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { deleteBlocklist } from "../hooks/blocklist.js";
import { allTargets } from "../ide/targets.js";

interface RemoveOptions {
  claude?: boolean;
  cursor?: boolean;
}

export async function runRemove(options?: RemoveOptions): Promise<void> {
  const cwd = process.cwd();

  // Default: remove from ALL known IDE locations
  const targets = (options?.claude || options?.cursor)
    ? allTargets().filter((t) =>
        (options.claude && t.name === "claude") ||
        (options.cursor && t.name === "cursor"),
      )
    : allTargets();

  for (const target of targets) {
    // Remove hooks
    target.removeHooks(cwd);
    console.log(`  Hooks removed from ${target.displayName}`);

    // Remove rules
    const rulesFile = join(cwd, target.settingsDir, target.rulesRelPath);
    if (existsSync(rulesFile)) {
      unlinkSync(rulesFile);
      console.log(`  Rules removed: ${target.settingsDir}/${target.rulesRelPath}`);
    }

    // Remove MCP server
    const mcpFile = join(cwd, target.mcpConfigPath);
    if (existsSync(mcpFile)) {
      try {
        const mcpConfig = JSON.parse(readFileSync(mcpFile, "utf-8"));
        if (mcpConfig.mcpServers?.agentmask) {
          delete mcpConfig.mcpServers.agentmask;
          if (Object.keys(mcpConfig.mcpServers).length === 0) {
            delete mcpConfig.mcpServers;
          }
          writeFileSync(mcpFile, JSON.stringify(mcpConfig, null, 2) + "\n");
          console.log(`  MCP server deregistered from ${target.mcpConfigPath}`);
        }
      } catch {}
    }
  }

  // Remove blocklist (shared, cleans both new and legacy paths)
  if (deleteBlocklist(cwd)) {
    console.log("  Blocklist removed");
  }

  console.log("\nagentmask has been removed.");
}
