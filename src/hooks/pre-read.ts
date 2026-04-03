import { resolve, basename } from "node:path";
import { readStdin, block, allow, startSafetyTimer } from "./common.js";
import { isBlockedPath, DEFAULT_BLOCKED_PATTERNS } from "../scanner/file-patterns.js";
import { isInBlocklist } from "./blocklist.js";

startSafetyTimer();

async function main() {
  const input = await readStdin();
  const filePath = input.tool_input?.file_path as string | undefined;

  if (!filePath) {
    allow();
    return;
  }

  const cwd = input.cwd ?? process.cwd();
  const resolved = resolve(cwd, filePath);
  const name = basename(resolved);

  // Check 1: Static patterns (.env, *.pem, credentials.json, etc.)
  if (isBlockedPath(resolved, DEFAULT_BLOCKED_PATTERNS)) {
    block(
      `[agentmask] BLOCKED: "${name}" is a protected secret file.\n` +
        `Use mcp__agentmask__safe_read to get a redacted view of this file.\n` +
        `Use mcp__agentmask__env_names to see variable names without values.`,
    );
  }

  // Check 2: Dynamic blocklist (files where secrets were detected)
  const entry = isInBlocklist(filePath, cwd);
  if (entry) {
    const types = entry.secrets.join(", ");
    block(
      `[agentmask] BLOCKED: "${name}" contains detected secrets (${types}).\n` +
        `Use mcp__agentmask__safe_read to get a redacted view of this file.\n` +
        `To unblock after fixing: agentmask allow-path "${filePath}"`,
    );
  }

  allow();
}

main().catch(() => process.exit(1));
