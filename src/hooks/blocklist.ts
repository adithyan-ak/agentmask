import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync, renameSync } from "node:fs";
import { join, dirname, resolve } from "node:path";

/**
 * Dynamic blocklist — files where secrets have been detected.
 *
 * Built at init time by scanning the entire repo (gitleaks + agentmask).
 * Updated at runtime by post-scan when secrets are found in new files.
 * Checked by pre-read to block files before they enter context.
 *
 * Stored at .agentmask/blocklist.json (shared between IDEs).
 */

export interface BlocklistEntry {
  secrets: string[];
  addedAt: string;
}

export interface BlocklistData {
  /** Map of relative file path → entry */
  files: Record<string, BlocklistEntry>;
}

const BLOCKLIST_FILENAME = "blocklist.json";
const LEGACY_BLOCKLIST_PATH = ".claude/agentmask-blocklist.json";

export function getBlocklistPath(cwd: string): string {
  return join(cwd, ".agentmask", BLOCKLIST_FILENAME);
}

/**
 * Migrate blocklist from legacy .claude/ path to .agentmask/.
 * Called by init before saving a new blocklist.
 */
export function migrateBlocklistIfNeeded(cwd: string): void {
  const oldPath = join(cwd, LEGACY_BLOCKLIST_PATH);
  const newPath = getBlocklistPath(cwd);
  if (existsSync(oldPath) && !existsSync(newPath)) {
    mkdirSync(dirname(newPath), { recursive: true });
    renameSync(oldPath, newPath);
  }
}

export function loadBlocklist(cwd: string): BlocklistData {
  const filePath = getBlocklistPath(cwd);
  try {
    if (existsSync(filePath)) {
      return JSON.parse(readFileSync(filePath, "utf-8"));
    }
    // Fallback: check legacy path for users who haven't re-run init
    const legacyPath = join(cwd, LEGACY_BLOCKLIST_PATH);
    if (existsSync(legacyPath)) {
      return JSON.parse(readFileSync(legacyPath, "utf-8"));
    }
  } catch {
    // Corrupted — start fresh
  }
  return { files: {} };
}

export function saveBlocklist(cwd: string, data: BlocklistData): void {
  const filePath = getBlocklistPath(cwd);
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n");
}

/**
 * Check if a file path is in the dynamic blocklist.
 * Matches by exact relative path or by filename suffix.
 */
export function isInBlocklist(
  filePath: string,
  cwd: string,
): BlocklistEntry | undefined {
  const data = loadBlocklist(cwd);
  const normalized = filePath.replace(/\\/g, "/");

  // Try exact match
  if (data.files[normalized]) return data.files[normalized];

  // Try relative to cwd
  const resolved = resolve(cwd, filePath).replace(/\\/g, "/");
  const cwdNorm = cwd.replace(/\\/g, "/");
  const relative = resolved.startsWith(cwdNorm + "/")
    ? resolved.slice(cwdNorm.length + 1)
    : null;
  if (relative && data.files[relative]) return data.files[relative];

  // Try matching by suffix (handles absolute vs relative path differences)
  for (const [blockedPath, entry] of Object.entries(data.files)) {
    if (normalized.endsWith("/" + blockedPath) || normalized === blockedPath) {
      return entry;
    }
    if (resolved.endsWith("/" + blockedPath) || resolved === blockedPath) {
      return entry;
    }
  }

  return undefined;
}

/**
 * Add a file to the blocklist.
 */
export function addToBlocklist(
  filePath: string,
  secretDescriptions: string[],
  cwd: string,
): void {
  const data = loadBlocklist(cwd);
  const normalized = filePath.replace(/\\/g, "/");

  // Make path relative to cwd if possible
  const resolved = resolve(cwd, normalized).replace(/\\/g, "/");
  const cwdNorm = cwd.replace(/\\/g, "/");
  const key = resolved.startsWith(cwdNorm + "/")
    ? resolved.slice(cwdNorm.length + 1)
    : normalized;

  const existing = data.files[key];
  if (existing) {
    const newSecrets = secretDescriptions.filter(
      (s) => !existing.secrets.includes(s),
    );
    existing.secrets.push(...newSecrets);
    existing.addedAt = new Date().toISOString();
  } else {
    data.files[key] = {
      secrets: secretDescriptions,
      addedAt: new Date().toISOString(),
    };
  }

  saveBlocklist(cwd, data);
}

/**
 * Remove a file from the blocklist.
 */
export function removeFromBlocklist(filePath: string, cwd: string): boolean {
  const data = loadBlocklist(cwd);
  const normalized = filePath.replace(/\\/g, "/");

  // Try exact key
  if (data.files[normalized]) {
    delete data.files[normalized];
    saveBlocklist(cwd, data);
    return true;
  }

  // Try relative resolution
  const resolved = resolve(cwd, filePath).replace(/\\/g, "/");
  const cwdNorm = cwd.replace(/\\/g, "/");
  const relative = resolved.startsWith(cwdNorm + "/")
    ? resolved.slice(cwdNorm.length + 1)
    : null;
  if (relative && data.files[relative]) {
    delete data.files[relative];
    saveBlocklist(cwd, data);
    return true;
  }

  // Try suffix match
  for (const key of Object.keys(data.files)) {
    if (normalized.endsWith("/" + key) || normalized === key) {
      delete data.files[key];
      saveBlocklist(cwd, data);
      return true;
    }
  }

  return false;
}

/**
 * Delete the blocklist file entirely (both new and legacy paths).
 */
export function deleteBlocklist(cwd: string): boolean {
  let deleted = false;
  const filePath = getBlocklistPath(cwd);
  if (existsSync(filePath)) {
    unlinkSync(filePath);
    deleted = true;
  }
  const legacyPath = join(cwd, LEGACY_BLOCKLIST_PATH);
  if (existsSync(legacyPath)) {
    unlinkSync(legacyPath);
    deleted = true;
  }
  return deleted;
}
