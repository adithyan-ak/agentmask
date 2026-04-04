import { readStdin, block, allow, startSafetyTimer } from "./common.js";
import { scanStaged } from "../gitleaks/runner.js";

startSafetyTimer();

/**
 * Patterns that indicate direct reading of secret files via bash.
 */
const FILE_READ_PATTERNS = [
  /\b(?:cat|head|tail|less|more|bat)\s+.*\.env\b/,
  /\b(?:cat|head|tail|less|more|bat)\s+.*credentials\.json\b/,
  /\b(?:cat|head|tail|less|more|bat)\s+.*\.pem\b/,
  /\b(?:cat|head|tail|less|more|bat)\s+.*\.key\b/,
  /\b(?:cat|head|tail|less|more|bat)\s+.*id_rsa\b/,
  /\b(?:cat|head|tail|less|more|bat)\s+.*id_ed25519\b/,
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

  // Category C: Git commit — scan staged files with gitleaks
  if (GIT_COMMIT_PATTERN.test(command)) {
    const cwd = input.cwd ?? process.cwd();
    try {
      const findings = await scanStaged(cwd);
      if (findings.length > 0) {
        const details = findings
          .map((f) => `  ${f.File}:${f.StartLine} — ${f.Description}`)
          .join("\n");
        block(
          `[agentmask] BLOCKED: Secrets detected in staged files. Fix before committing.\n${details}\n\n` +
            `Remove the hardcoded secrets and use environment variable references instead.`,
        );
      }
    } catch {
      // gitleaks failed — allow the commit (graceful degradation)
    }
  }

  allow();
}

main().catch(() => process.exit(1));
