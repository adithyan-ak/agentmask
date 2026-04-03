import { minimatch } from "minimatch";
import { basename, resolve } from "node:path";

/**
 * Default file patterns that should always be blocked from direct reading.
 * These files are known to contain secrets.
 */
export const DEFAULT_BLOCKED_PATTERNS: string[] = [
  // Environment files
  ".env",
  ".env.*",
  "**/.env",
  "**/.env.*",

  // Credential files
  "**/credentials.json",
  "**/serviceAccountKey.json",
  "**/service-account*.json",

  // Key files
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "**/*.pfx",

  // SSH keys
  "**/id_rsa",
  "**/id_ed25519",
  "**/id_ecdsa",
  "**/id_dsa",

  // Auth config files
  "**/.netrc",
  "**/.npmrc",
  "**/.pypirc",
  "**/.docker/config.json",
  "**/.kube/config",
  "**/kubeconfig",

  // Cloud provider credentials
  "**/.aws/credentials",
  "**/.aws/config",
  "**/.azure/credentials",
  "**/.gcloud/*.json",

  // Other
  "**/.htpasswd",
  "**/secrets.yml",
  "**/secrets.yaml",
  "**/secrets.json",
];

/**
 * Check if a file path matches any of the blocked patterns.
 */
export function isBlockedPath(
  filePath: string,
  blockedPatterns: string[] = DEFAULT_BLOCKED_PATTERNS,
): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  const base = basename(normalized);

  for (const pattern of blockedPatterns) {
    // Check against full path
    if (minimatch(normalized, pattern, { dot: true })) return true;
    // Check against just the filename (for patterns like ".env")
    if (minimatch(base, pattern, { dot: true })) return true;
  }

  return false;
}

/**
 * Check if a file path is in an allowlisted path.
 */
export function isAllowlistedPath(
  filePath: string,
  allowlistPatterns: string[],
): boolean {
  if (allowlistPatterns.length === 0) return false;
  const normalized = filePath.replace(/\\/g, "/");

  for (const pattern of allowlistPatterns) {
    if (minimatch(normalized, pattern, { dot: true })) return true;
  }

  return false;
}

/**
 * Check if a file is likely binary (should be skipped during scanning).
 */
export function isBinaryFile(filePath: string): boolean {
  const ext = filePath.split(".").pop()?.toLowerCase();
  return BINARY_EXTENSIONS.has(ext ?? "");
}

const BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "svg",
  "mp3", "mp4", "avi", "mov", "mkv", "wav", "flac",
  "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
  "exe", "dll", "so", "dylib", "bin",
  "pdf", "doc", "docx", "xls", "xlsx",
  "woff", "woff2", "ttf", "eot", "otf",
  "pyc", "pyo", "class", "o", "obj",
  "sqlite", "db", "sqlite3",
]);
