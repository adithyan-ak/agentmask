import { resolve, relative } from "node:path";
import { stat, readdir } from "node:fs/promises";
import { execSync } from "node:child_process";
import {
  scanFile,
  scanContent,
  isBlockedPath,
  isAllowlistedPath,
  isBinaryFile,
  DEFAULT_BLOCKED_PATTERNS,
} from "../scanner/index.js";
import { loadConfig, getAllowlistedPaths } from "../config/index.js";
import type { Finding, ScanResult } from "../scanner/types.js";

interface ScanOptions {
  staged?: boolean;
  json?: boolean;
}

export async function runScan(
  target: string | undefined,
  options: ScanOptions,
): Promise<void> {
  const cwd = process.cwd();
  const config = await loadConfig(cwd);
  const allowlistedPaths = getAllowlistedPaths(config);

  let filePaths: string[];

  if (options.staged) {
    filePaths = getStagedFiles(cwd);
  } else {
    const targetPath = resolve(cwd, target ?? ".");
    filePaths = await collectFiles(targetPath, allowlistedPaths);
  }

  const results: ScanResult[] = [];
  for (const fp of filePaths) {
    if (isAllowlistedPath(fp, allowlistedPaths)) continue;
    const result = await scanFile(fp);
    if (result.findings.length > 0) {
      results.push(result);
    }
  }

  // Also check for blocked paths in the scanned set
  const blockedPatterns = [
    ...DEFAULT_BLOCKED_PATTERNS,
    ...(config.scan?.blocked_paths ?? []),
  ];
  const blockedFiles = filePaths.filter(
    (fp) =>
      isBlockedPath(fp, blockedPatterns) &&
      !isAllowlistedPath(fp, allowlistedPaths),
  );

  if (options.json) {
    printJSON(results, blockedFiles, cwd);
  } else {
    printHuman(results, blockedFiles, cwd);
  }

  const hasFindings = results.some((r) => r.findings.length > 0);
  process.exitCode = hasFindings || blockedFiles.length > 0 ? 1 : 0;
}

function getStagedFiles(cwd: string): string[] {
  try {
    const output = execSync("git diff --cached --name-only --diff-filter=ACMR", {
      cwd,
      encoding: "utf-8",
    });
    return output
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((f) => resolve(cwd, f));
  } catch {
    console.error("Error: not a git repository or git not available.");
    process.exitCode = 1;
    return [];
  }
}

async function collectFiles(
  targetPath: string,
  allowlistedPaths: string[],
): Promise<string[]> {
  const s = await stat(targetPath);
  if (s.isFile()) return [targetPath];

  const files: string[] = [];
  await walkDir(targetPath, files, allowlistedPaths);
  return files;
}

async function walkDir(
  dir: string,
  files: string[],
  allowlistedPaths: string[],
): Promise<void> {
  const SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next",
    "__pycache__", ".venv", "venv", ".tox",
    "vendor", "target", ".idea", ".vscode",
  ]);

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = resolve(dir, entry.name);

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      await walkDir(fullPath, files, allowlistedPaths);
    } else if (entry.isFile()) {
      if (isBinaryFile(fullPath)) continue;
      if (isAllowlistedPath(fullPath, allowlistedPaths)) continue;
      files.push(fullPath);
    }
  }
}

function printJSON(
  results: ScanResult[],
  blockedFiles: string[],
  cwd: string,
): void {
  const output = {
    findings: results.flatMap((r) =>
      r.findings.map((f) => ({
        ...f,
        filePath: relative(cwd, f.filePath),
      })),
    ),
    blockedFiles: blockedFiles.map((f) => relative(cwd, f)),
    summary: {
      filesScanned: results.length,
      secretsFound: results.reduce((acc, r) => acc + r.findings.length, 0),
      blockedFilesFound: blockedFiles.length,
    },
  };
  console.log(JSON.stringify(output, null, 2));
}

function printHuman(
  results: ScanResult[],
  blockedFiles: string[],
  cwd: string,
): void {
  const totalFindings = results.reduce((acc, r) => acc + r.findings.length, 0);

  if (totalFindings === 0 && blockedFiles.length === 0) {
    console.log("No secrets found.");
    return;
  }

  // Print findings from content scanning
  for (const result of results) {
    for (const f of result.findings) {
      const relPath = relative(cwd, f.filePath);
      const severityTag = severityLabel(f.severity);
      console.log(
        `  ${severityTag} ${relPath}:${f.line} — ${f.description} (${f.match})`,
      );
    }
  }

  // Print blocked files
  if (blockedFiles.length > 0) {
    console.log("");
    console.log("Blocked secret files found:");
    for (const f of blockedFiles) {
      console.log(`  [blocked] ${relative(cwd, f)}`);
    }
  }

  console.log("");
  console.log(
    `Found ${totalFindings} secret(s) in content, ${blockedFiles.length} blocked file(s).`,
  );
}

function severityLabel(severity: string): string {
  switch (severity) {
    case "critical":
      return "[CRIT]";
    case "high":
      return "[HIGH]";
    case "medium":
      return "[MED] ";
    case "low":
      return "[LOW] ";
    default:
      return "[----]";
  }
}
