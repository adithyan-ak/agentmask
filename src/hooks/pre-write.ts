import { readStdin, block, allow, startSafetyTimer } from "./common.js";
import { isBlockedPath, DEFAULT_BLOCKED_PATTERNS } from "../scanner/file-patterns.js";
import { scanContent } from "../gitleaks/runner.js";
import { scanTier2Content, mergeFindings } from "../scanner/tier2.js";
import { basename } from "node:path";

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

  try {
    const tier1 = await scanContent(content, basename(filePath)).catch(() => []);
    const tier2 = scanTier2Content(content, filePath);
    const findings = mergeFindings(tier1, tier2);

    if (findings.length > 0) {
      const details = findings
        .map((f) => `  Line ${f.StartLine}: ${f.Description}`)
        .join("\n");
      block(
        `[agentmask] BLOCKED: Detected ${findings.length} secret(s) in content being written to ${filePath}:\n` +
          `${details}\n\n` +
          `Use environment variable references instead of hardcoding secrets.\n` +
          `Example: process.env.API_KEY or os.environ["API_KEY"]`,
      );
    }
  } catch {
    // gitleaks failed — degrade gracefully, allow the write
  }

  allow();
}

main().catch(() => process.exit(1));
