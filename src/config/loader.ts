import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseTOML } from "smol-toml";
import type { AgentmaskConfig, AllowlistEntry } from "../scanner/types.js";

const CONFIG_FILENAMES = [".agentmask.toml", "agentmask.toml"];

/**
 * Load and merge configuration from project root and user home.
 */
export async function loadConfig(
  projectDir: string,
): Promise<AgentmaskConfig> {
  const projectConfig = await loadConfigFrom(projectDir);
  const homeConfig = await loadConfigFrom(
    join(process.env.HOME ?? "~", ".config", "agentmask"),
  );

  return mergeConfigs(homeConfig, projectConfig);
}

async function loadConfigFrom(dir: string): Promise<AgentmaskConfig> {
  for (const filename of CONFIG_FILENAMES) {
    try {
      const content = await readFile(join(dir, filename), "utf-8");
      return parseTOML(content) as unknown as AgentmaskConfig;
    } catch {
      // File doesn't exist or isn't valid TOML — skip
    }
  }
  return {};
}

function mergeConfigs(
  base: AgentmaskConfig,
  override: AgentmaskConfig,
): AgentmaskConfig {
  return {
    scan: {
      blocked_paths: [
        ...(base.scan?.blocked_paths ?? []),
        ...(override.scan?.blocked_paths ?? []),
      ],
    },
    rules: [...(base.rules ?? []), ...(override.rules ?? [])],
    allowlists: [...(base.allowlists ?? []), ...(override.allowlists ?? [])],
  };
}

/**
 * Get all allowlisted paths from config.
 */
export function getAllowlistedPaths(config: AgentmaskConfig): string[] {
  return (config.allowlists ?? []).flatMap((a: AllowlistEntry) => a.paths ?? []);
}

/**
 * Get all stopwords from config.
 */
export function getStopwords(config: AgentmaskConfig): string[] {
  return (config.allowlists ?? []).flatMap((a: AllowlistEntry) => a.stopwords ?? []);
}
