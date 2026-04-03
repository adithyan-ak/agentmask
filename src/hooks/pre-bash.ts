import { readStdin, block, allow, startSafetyTimer } from "./common.js";
import { isBlockedPath, DEFAULT_BLOCKED_PATTERNS } from "../scanner/file-patterns.js";
import { scanContent } from "../scanner/scanner.js";
import { execSync } from "node:child_process";
import { resolve } from "node:path";

startSafetyTimer();

/**
 * Patterns that indicate direct reading of secret files via bash.
 */
const FILE_READ_PATTERNS = [
  // cat/head/tail/less/more/bat reading .env files
  /\b(?:cat|head|tail|less|more|bat)\s+.*\.env\b/,
  /\b(?:cat|head|tail|less|more|bat)\s+.*credentials\.json\b/,
  /\b(?:cat|head|tail|less|more|bat)\s+.*\.pem\b/,
  /\b(?:cat|head|tail|less|more|bat)\s+.*\.key\b/,
  /\b(?:cat|head|tail|less|more|bat)\s+.*id_rsa\b/,
  /\b(?:cat|head|tail|less|more|bat)\s+.*id_ed25519\b/,
  // sourcing .env files
  /\bsource\s+.*\.env\b/,
  /\.\s+.*\.env\b/,
];

/**
 * Patterns that indicate environment variable dump.
 */
const ENV_DUMP_PATTERNS = [
  /\bprintenv\b/,
  /^env$/,
  /^env\s/,
  /^set$/,
  /^export$/,
];

/**
 * Detect git commit commands so we can scan staged files.
 */
const GIT_COMMIT_PATTERN = /\bgit\s+commit\b/;

async function main() {
  const input = await readStdin();
  const command = input.tool_input?.command as string | undefined;

  if (!command) {
    allow();
    return;
  }

  // Category A: File reads of secret files
  for (const pattern of FILE_READ_PATTERNS) {
    if (pattern.test(command)) {
      block(
        `[agentmask] BLOCKED: This command would read a protected secret file.\n` +
          `Use mcp__agentmask__safe_read for a redacted view instead.`,
      );
    }
  }

  // Category B: Environment variable dumps
  for (const pattern of ENV_DUMP_PATTERNS) {
    if (pattern.test(command.trim())) {
      block(
        `[agentmask] BLOCKED: This command would expose environment variables that may contain secrets.\n` +
          `Use mcp__agentmask__env_names to see variable names without values.`,
      );
    }
  }

  // Category C: Git commit — scan staged files for secrets
  if (GIT_COMMIT_PATTERN.test(command)) {
    const cwd = input.cwd ?? process.cwd();
    const secretsInStaged = scanStagedFiles(cwd);
    if (secretsInStaged.length > 0) {
      const details = secretsInStaged
        .map((s) => `  ${s.filePath}:${s.line} — ${s.description} (${s.match})`)
        .join("\n");
      block(
        `[agentmask] BLOCKED: Secrets detected in staged files. Fix before committing.\n${details}\n\n` +
          `Remove the hardcoded secrets and use environment variable references instead.`,
      );
    }
  }

  allow();
}

function scanStagedFiles(
  cwd: string,
): Array<{ filePath: string; line: number; description: string; match: string }> {
  let stagedFiles: string[];
  try {
    const output = execSync("git diff --cached --name-only --diff-filter=ACMR", {
      cwd,
      encoding: "utf-8",
    });
    stagedFiles = output.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }

  const findings: Array<{
    filePath: string;
    line: number;
    description: string;
    match: string;
  }> = [];

  for (const file of stagedFiles) {
    // Get staged content (not working tree content)
    let content: string;
    try {
      content = execSync(`git show ":${file}"`, { cwd, encoding: "utf-8" });
    } catch {
      continue;
    }

    const fileFindings = scanContent(content, file);
    for (const f of fileFindings) {
      findings.push({
        filePath: f.filePath,
        line: f.line,
        description: f.description,
        match: f.match,
      });
    }
  }

  return findings;
}

main().catch(() => process.exit(1));
