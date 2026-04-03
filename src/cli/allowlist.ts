import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseTOML, stringify as stringifyTOML } from "smol-toml";

const CONFIG_FILE = ".agentmask.toml";

interface Config {
  scan?: { blocked_paths?: string[] };
  allowlists?: Array<{
    paths?: string[];
    stopwords?: string[];
    description?: string;
  }>;
  [key: string]: unknown;
}

function loadOrCreateConfig(): Config {
  const configPath = join(process.cwd(), CONFIG_FILE);
  if (existsSync(configPath)) {
    try {
      return parseTOML(readFileSync(configPath, "utf-8")) as unknown as Config;
    } catch {
      return {};
    }
  }
  return {};
}

function saveConfig(config: Config): void {
  const configPath = join(process.cwd(), CONFIG_FILE);
  writeFileSync(configPath, stringifyTOML(config as any) + "\n");
}

export async function runAllowPath(pattern: string): Promise<void> {
  const config = loadOrCreateConfig();

  if (!config.allowlists) config.allowlists = [];

  // Check if this path is already allowlisted
  const existing = config.allowlists.find((a) =>
    a.paths?.includes(pattern),
  );
  if (existing) {
    console.log(`Path "${pattern}" is already allowlisted.`);
    return;
  }

  // Find or create a path allowlist entry
  let pathEntry = config.allowlists.find(
    (a) => a.paths && !a.stopwords,
  );
  if (!pathEntry) {
    pathEntry = { paths: [], description: "Allowlisted paths" };
    config.allowlists.push(pathEntry);
  }
  if (!pathEntry.paths) pathEntry.paths = [];
  pathEntry.paths.push(pattern);

  saveConfig(config);
  console.log(`Allowlisted path: "${pattern}"`);
  console.log(`Saved to ${CONFIG_FILE}`);
}

export async function runAllowValue(value: string): Promise<void> {
  const config = loadOrCreateConfig();

  if (!config.allowlists) config.allowlists = [];

  // Check if this value is already allowlisted
  const existing = config.allowlists.find((a) =>
    a.stopwords?.includes(value),
  );
  if (existing) {
    console.log(`Value "${value}" is already allowlisted.`);
    return;
  }

  // Find or create a stopwords allowlist entry
  let stopEntry = config.allowlists.find(
    (a) => a.stopwords && !a.paths,
  );
  if (!stopEntry) {
    stopEntry = { stopwords: [], description: "Allowlisted values" };
    config.allowlists.push(stopEntry);
  }
  if (!stopEntry.stopwords) stopEntry.stopwords = [];
  stopEntry.stopwords.push(value);

  saveConfig(config);
  console.log(`Allowlisted value: "${value}"`);
  console.log(`Saved to ${CONFIG_FILE}`);
}
