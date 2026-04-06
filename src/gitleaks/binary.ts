import { existsSync, mkdirSync, chmodSync, createWriteStream, unlinkSync } from "node:fs";
import { join } from "node:path";
import { execSync } from "node:child_process";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { extract } from "tar";

/**
 * Pinned gitleaks version. Update this when testing against a new release.
 */
const GITLEAKS_VERSION = "8.28.0";

/**
 * Where we cache the downloaded binary.
 */
const CACHE_DIR = join(
  process.env.HOME ?? process.env.USERPROFILE ?? "/tmp",
  ".agentmask",
  "bin",
);

/**
 * Find the gitleaks binary. Checks in order:
 * 1. System PATH (user already has it installed)
 * 2. Our cache directory (previously downloaded)
 * 3. Downloads it automatically
 */
export async function getGitleaksBinary(): Promise<string> {
  // 1. Check system PATH
  const systemBin = findInPath();
  if (systemBin) return systemBin;

  // 2. Check cache
  const cachedBin = join(CACHE_DIR, "gitleaks");
  if (existsSync(cachedBin)) return cachedBin;

  // 3. Download
  console.log(`gitleaks not found. Downloading v${GITLEAKS_VERSION}...`);
  await downloadGitleaks(cachedBin);
  return cachedBin;
}

/**
 * Check if gitleaks is available without downloading.
 */
export function isGitleaksAvailable(): boolean {
  if (findInPath()) return true;
  const cachedBin = join(CACHE_DIR, "gitleaks");
  return existsSync(cachedBin);
}

function findInPath(): string | null {
  try {
    const path = execSync("which gitleaks", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
    if (path && existsSync(path)) return path;
  } catch {
    // not in PATH
  }
  return null;
}

async function downloadGitleaks(destPath: string): Promise<void> {
  const { platform, arch } = getPlatformArch();
  const filename = `gitleaks_${GITLEAKS_VERSION}_${platform}_${arch}.tar.gz`;
  const url = `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${filename}`;

  mkdirSync(CACHE_DIR, { recursive: true });

  // Download to temp file
  const tmpTarball = join(CACHE_DIR, `gitleaks-download.tar.gz`);

  try {
    const response = await fetch(url, { redirect: "follow" });
    if (!response.ok || !response.body) {
      throw new Error(`Download failed: ${response.status} ${response.statusText}`);
    }

    // Write tarball to disk
    const fileStream = createWriteStream(tmpTarball);
    // @ts-ignore - Node.js ReadableStream from fetch is compatible
    await pipeline(response.body, fileStream);

    // Extract the gitleaks binary from the tarball
    await extract({
      file: tmpTarball,
      cwd: CACHE_DIR,
      filter: (path) => path === "gitleaks",
    });

    // Make executable
    chmodSync(destPath, 0o755);

    console.log(`  Downloaded gitleaks v${GITLEAKS_VERSION} → ${destPath}`);
  } finally {
    // Clean up tarball
    try {
      unlinkSync(tmpTarball);
    } catch {}
  }
}

function getPlatformArch(): { platform: string; arch: string } {
  const platform =
    process.platform === "darwin"
      ? "darwin"
      : process.platform === "linux"
        ? "linux"
        : process.platform === "win32"
          ? "windows"
          : process.platform;

  const arch =
    process.arch === "arm64"
      ? "arm64"
      : process.arch === "x64"
        ? "x64"
        : process.arch;

  return { platform, arch };
}
