import { readFile, realpath } from "node:fs/promises";
import { TIER1_RULES, ALL_RULES, truncateSecret, isStopword } from "./rules.js";
import { shannonEntropy } from "./entropy.js";
import { isBinaryFile } from "./file-patterns.js";
import type { Finding, Rule, ScanResult } from "./types.js";

const MAX_FILE_SIZE = 1024 * 1024; // 1MB — scan first 1MB only
const MAX_LINE_LENGTH = 10_000; // Skip very long lines (minified code)

/**
 * Scan file content for secrets using all active rules.
 * By default uses only Tier 1 rules. Pass ALL_RULES for full scanning.
 */
export function scanContent(
  content: string,
  filePath: string,
  rules: Rule[] = TIER1_RULES,
): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");
  // Track found secrets to avoid duplicate findings on same line
  const seen = new Set<string>();

  for (const rule of rules) {
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      // Skip very long lines (likely minified — high false positive risk)
      if (line.length > MAX_LINE_LENGTH) continue;

      // Quick keyword pre-filter: skip lines that don't contain any keyword
      if (rule.keywords && rule.keywords.length > 0) {
        const lineLower = line.toLowerCase();
        const hasKeyword = rule.keywords.some((kw) => lineLower.includes(kw));
        if (!hasKeyword) continue;
      }

      const match = rule.regex.exec(line);
      if (!match) continue;

      const secretGroup = rule.secretGroup ?? 0;
      const secretValue = match[secretGroup] ?? match[0];

      // If rule has entropy threshold, check it
      if (rule.entropy !== undefined) {
        if (shannonEntropy(secretValue) < rule.entropy) continue;
      }

      // For Tier 2 rules, also check stopwords
      if (rule.id.startsWith("generic") && isStopword(secretValue)) continue;

      // Deduplicate: same rule + same line
      const key = `${rule.id}:${lineIdx}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        ruleId: rule.id,
        description: rule.description,
        filePath,
        line: lineIdx + 1,
        column: match.index + 1,
        match: truncateSecret(secretValue),
        redacted: `[REDACTED:${rule.id}]`,
        severity: rule.severity,
      });
    }
  }

  return findings;
}

/**
 * Scan a file on disk for secrets.
 * Resolves symlinks to check the real file path.
 */
export async function scanFile(
  filePath: string,
  rules?: Rule[],
): Promise<ScanResult> {
  if (isBinaryFile(filePath)) {
    return { filePath, findings: [], scannedAt: new Date().toISOString() };
  }

  // Resolve symlinks to get real path
  let resolvedPath = filePath;
  try {
    resolvedPath = await realpath(filePath);
  } catch {
    // If realpath fails, use original path
  }

  if (isBinaryFile(resolvedPath)) {
    return { filePath, findings: [], scannedAt: new Date().toISOString() };
  }

  let content: string;
  try {
    const buffer = await readFile(resolvedPath);

    // Skip files that look binary (null bytes in first 8KB)
    const sample = buffer.subarray(0, 8192);
    if (sample.includes(0)) {
      return { filePath, findings: [], scannedAt: new Date().toISOString() };
    }

    // Only scan first MAX_FILE_SIZE bytes
    content = buffer.subarray(0, MAX_FILE_SIZE).toString("utf-8");
  } catch {
    return { filePath, findings: [], scannedAt: new Date().toISOString() };
  }

  const findings = scanContent(content, filePath, rules);
  return { filePath, findings, scannedAt: new Date().toISOString() };
}

/**
 * Scan multiple files and aggregate results.
 */
export async function scanFiles(
  filePaths: string[],
  rules?: Rule[],
): Promise<ScanResult[]> {
  const results = await Promise.all(
    filePaths.map((fp) => scanFile(fp, rules)),
  );
  return results.filter((r) => r.findings.length > 0);
}
