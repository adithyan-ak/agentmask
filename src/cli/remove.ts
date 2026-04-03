import { existsSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";

export async function runRemove(): Promise<void> {
  const cwd = process.cwd();
  const settingsDir = join(cwd, ".claude");

  // Remove hooks from both settings files
  for (const filename of ["settings.local.json", "settings.json"]) {
    const settingsFile = join(settingsDir, filename);
    if (existsSync(settingsFile)) {
      try {
        const settings = JSON.parse(readFileSync(settingsFile, "utf-8"));
        if (settings.hooks) {
          settings.hooks.PreToolUse = filterOutAgentmask(
            settings.hooks.PreToolUse ?? [],
          );
          settings.hooks.PostToolUse = filterOutAgentmask(
            settings.hooks.PostToolUse ?? [],
          );

          // Clean up empty hook arrays
          if (settings.hooks.PreToolUse.length === 0)
            delete settings.hooks.PreToolUse;
          if (settings.hooks.PostToolUse.length === 0)
            delete settings.hooks.PostToolUse;
          if (Object.keys(settings.hooks).length === 0) delete settings.hooks;

          writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + "\n");
          console.log(`  Hooks removed from ${filename}`);
        }
      } catch {
        // File isn't valid JSON — skip
      }
    }
  }

  // Remove blocklist
  const blocklistFile = join(settingsDir, "agentmask-blocklist.json");
  if (existsSync(blocklistFile)) {
    unlinkSync(blocklistFile);
    console.log("  Blocklist removed: .claude/agentmask-blocklist.json");
  }

  // Remove rules file
  const rulesFile = join(settingsDir, "rules", "agentmask.md");
  if (existsSync(rulesFile)) {
    unlinkSync(rulesFile);
    console.log("  Rules removed: .claude/rules/agentmask.md");
  }

  // Remove MCP server from .mcp.json
  const mcpFile = join(cwd, ".mcp.json");
  if (existsSync(mcpFile)) {
    try {
      const mcpConfig = JSON.parse(readFileSync(mcpFile, "utf-8"));
      if (mcpConfig.mcpServers?.agentmask) {
        delete mcpConfig.mcpServers.agentmask;
        if (Object.keys(mcpConfig.mcpServers).length === 0) {
          delete mcpConfig.mcpServers;
        }
        writeFileSync(mcpFile, JSON.stringify(mcpConfig, null, 2) + "\n");
        console.log("  MCP server deregistered from .mcp.json");
      }
    } catch {
      // Not valid JSON — skip
    }
  }

  console.log("\nagentmask has been removed.");
}

function filterOutAgentmask(hooks: any[]): any[] {
  return hooks.filter((h: any) => {
    const innerHooks = h?.hooks ?? [];
    return !innerHooks.some(
      (ih: any) =>
        typeof ih?.command === "string" && ih.command.includes("agentmask"),
    );
  });
}
