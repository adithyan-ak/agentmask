import { readStdin, block, allow, startSafetyTimer } from "./common.js";
import { isBlockedPath, DEFAULT_BLOCKED_PATTERNS } from "../scanner/file-patterns.js";
import { scanContent } from "../scanner/scanner.js";

startSafetyTimer();

async function main() {
  const input = await readStdin();
  const filePath = input.tool_input?.file_path as string | undefined;

  if (!filePath) {
    allow();
    return;
  }

  // Don't scan writes TO secret files (they're expected to have secrets)
  if (isBlockedPath(filePath, DEFAULT_BLOCKED_PATTERNS)) {
    allow();
    return;
  }

  // Get the content being written
  const content =
    (input.tool_input?.content as string | undefined) ??
    (input.tool_input?.new_string as string | undefined);

  if (!content) {
    allow();
    return;
  }

  const findings = scanContent(content, filePath);

  if (findings.length > 0) {
    const details = findings
      .map((f) => `  Line ${f.line}: ${f.description} (${f.match})`)
      .join("\n");
    block(
      `[agentmask] BLOCKED: Detected ${findings.length} secret(s) in content being written to ${filePath}:\n` +
        `${details}\n\n` +
        `Use environment variable references instead of hardcoding secrets.\n` +
        `Example: process.env.API_KEY or os.environ["API_KEY"]`,
    );
  }

  allow();
}

main().catch(() => process.exit(1));
