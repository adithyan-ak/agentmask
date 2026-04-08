import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";

// ── Types ──

export type IdeName = "claude" | "cursor";

export interface IdeTarget {
  name: IdeName;
  displayName: string;
  settingsDir: string;
  mcpConfigPath: string;
  rulesRelPath: string;
  hookFormat: string;
  shellMatcher: string;
  formatRules(content: string): string;
  installHooks(cwd: string, binPath: string, team: boolean): void;
  removeHooks(cwd: string): void;
}

// ── Shared utilities ──

export function loadJSON(filePath: string): Record<string, any> {
  try {
    return JSON.parse(readFileSync(filePath, "utf-8"));
  } catch {
    return {};
  }
}

export function filterOutAgentmask(hooks: unknown[]): unknown[] {
  return hooks.filter((h: any) => {
    // Claude format: nested hooks array with command field
    const innerHooks = h?.hooks ?? [];
    if (innerHooks.some((ih: any) =>
      typeof ih?.command === "string" && ih.command.includes("agentmask"),
    )) return false;
    // Cursor format: flat command field
    if (typeof h?.command === "string" && h.command.includes("agentmask")) return false;
    return true;
  });
}

// ── Rules content ──

export const RULES_CONTENT = `## agentmask — Secrets Protection Rules

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

// ── Claude Code target ──

export const claudeTarget: IdeTarget = {
  name: "claude",
  displayName: "Claude Code",
  settingsDir: ".claude",
  mcpConfigPath: ".mcp.json",
  rulesRelPath: "rules/agentmask.md",
  hookFormat: "claude",
  shellMatcher: "Bash",

  formatRules(content: string): string {
    return content;
  },

  installHooks(cwd: string, binPath: string, team: boolean): void {
    const settingsDir = join(cwd, ".claude");
    mkdirSync(settingsDir, { recursive: true });
    const filename = team ? "settings.json" : "settings.local.json";
    const settingsFile = join(settingsDir, filename);
    const settings = loadJSON(settingsFile);

    const existing = settings.hooks ?? {};
    const preToolUse = (existing.PreToolUse as unknown[]) ?? [];
    const postToolUse = (existing.PostToolUse as unknown[]) ?? [];

    const cleanPre = filterOutAgentmask(preToolUse);
    const cleanPost = filterOutAgentmask(postToolUse);

    settings.hooks = {
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

    writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + "\n");
  },

  removeHooks(cwd: string): void {
    const settingsDir = join(cwd, ".claude");
    for (const filename of ["settings.local.json", "settings.json"]) {
      const settingsFile = join(settingsDir, filename);
      if (!existsSync(settingsFile)) continue;
      try {
        const settings = JSON.parse(readFileSync(settingsFile, "utf-8"));
        if (!settings.hooks) continue;

        settings.hooks.PreToolUse = filterOutAgentmask(settings.hooks.PreToolUse ?? []);
        settings.hooks.PostToolUse = filterOutAgentmask(settings.hooks.PostToolUse ?? []);

        if (settings.hooks.PreToolUse.length === 0) delete settings.hooks.PreToolUse;
        if (settings.hooks.PostToolUse.length === 0) delete settings.hooks.PostToolUse;
        if (Object.keys(settings.hooks).length === 0) delete settings.hooks;

        writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + "\n");
      } catch {}
    }
  },
};

// ── Cursor target ──

export const cursorTarget: IdeTarget = {
  name: "cursor",
  displayName: "Cursor",
  settingsDir: ".cursor",
  mcpConfigPath: ".cursor/mcp.json",
  rulesRelPath: "rules/agentmask.mdc",
  hookFormat: "cursor",
  shellMatcher: "Shell",

  formatRules(content: string): string {
    return `---\nalwaysApply: true\n---\n${content}`;
  },

  installHooks(cwd: string, binPath: string, _team: boolean): void {
    const settingsDir = join(cwd, ".cursor");
    mkdirSync(settingsDir, { recursive: true });
    const hooksFile = join(settingsDir, "hooks.json");
    const config = loadJSON(hooksFile);

    config.version = 1;
    const existing = config.hooks ?? {};
    const preToolUse = filterOutAgentmask((existing.preToolUse as unknown[]) ?? []);
    const postToolUse = filterOutAgentmask((existing.postToolUse as unknown[]) ?? []);

    config.hooks = {
      ...existing,
      preToolUse: [
        ...preToolUse,
        { matcher: "Read", command: `${binPath} hook pre-read --format cursor` },
        { matcher: "Shell", command: `${binPath} hook pre-bash --format cursor` },
        { matcher: "Write|Edit", command: `${binPath} hook pre-write --format cursor` },
      ],
      postToolUse: [
        ...postToolUse,
        { matcher: "Read|Shell", command: `${binPath} hook post-scan --format cursor` },
      ],
    };

    writeFileSync(hooksFile, JSON.stringify(config, null, 2) + "\n");
  },

  removeHooks(cwd: string): void {
    const hooksFile = join(cwd, ".cursor", "hooks.json");
    if (!existsSync(hooksFile)) return;
    try {
      const config = JSON.parse(readFileSync(hooksFile, "utf-8"));
      if (!config.hooks) return;

      if (config.hooks.preToolUse) {
        config.hooks.preToolUse = filterOutAgentmask(config.hooks.preToolUse);
        if (config.hooks.preToolUse.length === 0) delete config.hooks.preToolUse;
      }
      if (config.hooks.postToolUse) {
        config.hooks.postToolUse = filterOutAgentmask(config.hooks.postToolUse);
        if (config.hooks.postToolUse.length === 0) delete config.hooks.postToolUse;
      }
      if (Object.keys(config.hooks).length === 0) delete config.hooks;

      writeFileSync(hooksFile, JSON.stringify(config, null, 2) + "\n");
    } catch {}
  },
};

// ── Detection ──

const ALL_TARGETS: IdeTarget[] = [claudeTarget, cursorTarget];

export function detectTargets(cwd: string): IdeTarget[] {
  const targets: IdeTarget[] = [claudeTarget];
  if (existsSync(join(cwd, ".cursor"))) {
    targets.push(cursorTarget);
  }
  return targets;
}

export function resolveTargets(
  cwd: string,
  flags: { claude?: boolean; cursor?: boolean },
): IdeTarget[] {
  if (flags.claude && flags.cursor) return [claudeTarget, cursorTarget];
  if (flags.claude) return [claudeTarget];
  if (flags.cursor) return [cursorTarget];
  return detectTargets(cwd);
}

export function allTargets(): IdeTarget[] {
  return ALL_TARGETS;
}
