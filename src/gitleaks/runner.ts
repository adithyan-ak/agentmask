import { execSync, execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, unlinkSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { getGitleaksBinary } from "./binary.js";

/**
 * A single finding from gitleaks JSON output.
 */
export interface GitleaksFinding {
  RuleID: string;
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  File: string;
  Entropy: number;
  Fingerprint: string;
}

/**
 * Scan a directory for secrets.
 */
export async function scanDir(
  dirPath: string,
  options?: { configPath?: string },
): Promise<GitleaksFinding[]> {
  const bin = await getGitleaksBinary();
  const reportPath = tempPath("agentmask-report", ".json");

  try {
    const args = [
      "dir",
      dirPath,
      "--report-format", "json",
      "--report-path", reportPath,
      "--no-banner",
      "--exit-code", "0",
    ];
    if (options?.configPath) {
      args.push("--config", options.configPath);
    }

    execFileSync(bin, args, {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 60_000,
    });

    return readReport(reportPath);
  } finally {
    tryUnlink(reportPath);
  }
}

/**
 * Scan a single file for secrets.
 */
export async function scanFile(filePath: string): Promise<GitleaksFinding[]> {
  const bin = await getGitleaksBinary();
  const reportPath = tempPath("agentmask-report", ".json");

  try {
    execFileSync(bin, [
      "dir",
      filePath,
      "--report-format", "json",
      "--report-path", reportPath,
      "--no-banner",
      "--exit-code", "0",
    ], {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10_000,
    });

    return readReport(reportPath);
  } finally {
    tryUnlink(reportPath);
  }
}

/**
 * Scan arbitrary content by writing to a temp file.
 * Used by pre-write hook (scan content before it's written)
 * and post-scan hook (scan tool output).
 */
export async function scanContent(
  content: string,
  filename?: string,
): Promise<GitleaksFinding[]> {
  const bin = await getGitleaksBinary();
  const scanDir = join(tmpdir(), `agentmask-scan-${randomBytes(4).toString("hex")}`);
  const scanFile = join(scanDir, filename ?? "content.txt");
  const reportPath = tempPath("agentmask-report", ".json");

  try {
    mkdirSync(scanDir, { recursive: true });
    writeFileSync(scanFile, content);

    execFileSync(bin, [
      "dir",
      scanDir,
      "--report-format", "json",
      "--report-path", reportPath,
      "--no-banner",
      "--exit-code", "0",
    ], {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10_000,
    });

    return readReport(reportPath);
  } finally {
    tryUnlink(reportPath);
    try { rmSync(scanDir, { recursive: true, force: true }); } catch {}
  }
}

/**
 * Scan git staged files for secrets.
 */
export async function scanStaged(cwd: string): Promise<GitleaksFinding[]> {
  const bin = await getGitleaksBinary();
  const reportPath = tempPath("agentmask-report", ".json");

  try {
    execFileSync(bin, [
      "git",
      "--staged",
      "--report-format", "json",
      "--report-path", reportPath,
      "--no-banner",
      "--exit-code", "0",
    ], {
      cwd,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 30_000,
    });

    return readReport(reportPath);
  } finally {
    tryUnlink(reportPath);
  }
}

function readReport(reportPath: string): GitleaksFinding[] {
  try {
    const raw = readFileSync(reportPath, "utf-8");
    const findings = JSON.parse(raw);
    return Array.isArray(findings) ? findings : [];
  } catch {
    return [];
  }
}

function tempPath(prefix: string, ext: string): string {
  return join(tmpdir(), `${prefix}-${randomBytes(4).toString("hex")}${ext}`);
}

function tryUnlink(path: string): void {
  try { unlinkSync(path); } catch {}
}
