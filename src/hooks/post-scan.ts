import { readStdin, allow, startSafetyTimer } from "./common.js";
import { scanContent } from "../gitleaks/runner.js";
import { scanTier2Content, mergeFindings } from "../scanner/tier2.js";
import { addToBlocklist } from "./blocklist.js";

startSafetyTimer();

const MAX_SCAN_LENGTH = 100 * 1024; // 100KB max for output scanning

async function main() {
  const input = await readStdin();
  const response = input.tool_response;

  if (!response || typeof response !== "string") {
    allow();
    return;
  }

  const toScan = response.length > MAX_SCAN_LENGTH
    ? response.slice(0, MAX_SCAN_LENGTH)
    : response;

  const filePath = (input.tool_input?.file_path as string) ?? "";

  try {
    const tier1 = await scanContent(toScan).catch(() => []);
    const tier2 = scanTier2Content(toScan, filePath || "output");
    const findings = mergeFindings(tier1, tier2);

    if (findings.length > 0) {
      const types = [...new Set(findings.map((f) => f.Description))];
      const cwd = input.cwd ?? process.cwd();

      // Add to blocklist so future reads are blocked
      if (filePath) {
        try {
          addToBlocklist(filePath, types, cwd);
        } catch {
          // Non-critical
        }
      }

      allow(
        `[agentmask] WARNING: The output above contains ${findings.length} detected secret(s): ${types.join(", ")}.\n` +
          `Do NOT repeat these values in your response, code, or commits. Reference by variable name only.\n` +
          `This file has been added to the blocklist — future reads will be blocked and redirected to safe_read.`,
      );
      return;
    }
  } catch {
    // gitleaks failed — degrade gracefully
  }

  allow();
}

main().catch(() => process.exit(1));
