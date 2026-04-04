import { resolve, relative } from "node:path";
import {
  scanDir,
  scanFile,
  scanStaged,
  type GitleaksFinding,
} from "../gitleaks/runner.js";

interface ScanOptions {
  staged?: boolean;
  json?: boolean;
}

export async function runScan(
  target: string | undefined,
  options: ScanOptions,
): Promise<void> {
  const cwd = process.cwd();

  let findings: GitleaksFinding[];

  if (options.staged) {
    findings = await scanStaged(cwd);
  } else {
    const targetPath = resolve(cwd, target ?? ".");
    findings = await scanDir(targetPath);
  }

  if (options.json) {
    printJSON(findings, cwd);
  } else {
    printHuman(findings, cwd);
  }

  process.exitCode = findings.length > 0 ? 1 : 0;
}

function printJSON(findings: GitleaksFinding[], cwd: string): void {
  const output = {
    findings: findings.map((f) => ({
      ruleId: f.RuleID,
      description: f.Description,
      file: relative(cwd, f.File),
      line: f.StartLine,
      entropy: f.Entropy,
    })),
    summary: {
      secretsFound: findings.length,
      filesAffected: new Set(findings.map((f) => f.File)).size,
    },
  };
  console.log(JSON.stringify(output, null, 2));
}

function printHuman(findings: GitleaksFinding[], cwd: string): void {
  if (findings.length === 0) {
    console.log("No secrets found.");
    return;
  }

  for (const f of findings) {
    const relPath = relative(cwd, f.File);
    console.log(`  [${f.RuleID}] ${relPath}:${f.StartLine} — ${f.Description}`);
  }

  const fileCount = new Set(findings.map((f) => f.File)).size;
  console.log("");
  console.log(`Found ${findings.length} secret(s) across ${fileCount} file(s).`);
}
