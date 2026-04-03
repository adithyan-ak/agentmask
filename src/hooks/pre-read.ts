import { resolve, basename } from "node:path";
import { readStdin, block, allow, startSafetyTimer } from "./common.js";
import { isBlockedPath, DEFAULT_BLOCKED_PATTERNS } from "../scanner/file-patterns.js";

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

  if (isBlockedPath(resolved, DEFAULT_BLOCKED_PATTERNS)) {
    const name = basename(resolved);
    block(
      `[agentmask] BLOCKED: "${name}" is a protected secret file.\n` +
        `Use mcp__agentmask__safe_read to get a redacted view of this file.\n` +
        `Use mcp__agentmask__env_names to see variable names without values.`,
    );
  }

  allow();
}

main().catch(() => process.exit(1));
