import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import type { GitleaksFinding } from "../gitleaks/runner.js";
import { isBinaryFile } from "./file-patterns.js";

/**
 * Tier 2 scanner — complements gitleaks by catching patterns it misses.
 *
 * gitleaks is excellent at provider-specific tokens and its generic-api-key
 * rule keys on variable names like key/token/secret/api/auth/client. But it
 * misses:
 *   - password/passwd/pass fields with high-entropy values
 *   - connection strings with embedded credentials (postgres://u:p@host)
 *   - Provider prefixes without dedicated rules (whsec_, GOCSPX-)
 *
 * Tier 2 runs as a second pass over the same files gitleaks scanned,
 * producing GitleaksFinding-shaped objects that merge seamlessly into the
 * existing blocklist, hooks, and safe_read pipelines.
 */

export interface Tier2Rule {
  id: string;
  description: string;
  /** Regex with a capture group for the secret value. */
  regex: RegExp;
  /** Which capture group holds the secret value. Defaults to 1. */
  secretGroup?: number;
  /** Minimum Shannon entropy of the captured secret. */
  minEntropy?: number;
  /** Minimum length of the captured secret. */
  minLength?: number;
  /** Substrings that, if present in the secret, mark it as a false positive. */
  stopwords?: string[];
}

// Common placeholder values to skip across all rules.
const COMMON_STOPWORDS = [
  "example",
  "placeholder",
  "your-",
  "your_",
  "yourpassword",
  "changeme",
  "change_me",
  "xxxxxxxx",
  "password123", // still catches without, but keeps obvious dummies quiet in docs
  "<password>",
  "<secret>",
  "${",
  "{{",
];

export const TIER2_RULES: Tier2Rule[] = [
  {
    id: "agentmask-password-field",
    description: "Password field with high-entropy value",
    // Matches: password = "..."  "password": "..."  password: "..."  PGPASSWORD="..."
    // Key names: password, passwd, pass, pwd, db_pass, PGPASSWORD, vault_password, etc.
    regex:
      /(?:^|[\s,{\[(])["']?([A-Za-z0-9_]*(?:password|passwd|pwd|pass)[A-Za-z0-9_]*)["']?\s*[:=]\s*["']([^"'\n\r]{6,})["']/gim,
    secretGroup: 2,
    minLength: 6,
    stopwords: COMMON_STOPWORDS,
  },
  {
    id: "agentmask-password-field-unquoted",
    description: "Password field with high-entropy value",
    // Matches shell/env/YAML style: PGPASSWORD=value  password: value (no quotes)
    regex:
      /(?:^|\s)(?:export\s+)?([A-Za-z0-9_]*(?:password|passwd|pwd)[A-Za-z0-9_]*)\s*[:=]\s*([^\s"'#;,<>]{8,})/gim,
    secretGroup: 2,
    minLength: 8,
    minEntropy: 2.8,
    stopwords: COMMON_STOPWORDS,
  },
  {
    id: "agentmask-connection-string",
    description: "Connection string with embedded credentials",
    // postgres://user:pass@host, mysql://, mongodb://, redis://, amqp://
    regex:
      /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|amqps|rediss):\/\/[^:\s"'`]+:[^@\s"'`]+@[^\s"'`<>]+)/g,
    secretGroup: 1,
    minLength: 12,
    stopwords: ["user:pass@", "username:password@", "USER:PASS@", "<user>"],
  },
  {
    id: "agentmask-webhook-secret",
    description: "Webhook signing secret (whsec_)",
    regex: /\b(whsec_[A-Za-z0-9+/=_-]{16,})/g,
    secretGroup: 1,
    minLength: 20,
  },
  {
    id: "agentmask-google-oauth-secret",
    description: "Google OAuth client secret (GOCSPX-)",
    regex: /\b(GOCSPX-[A-Za-z0-9_-]{20,})/g,
    secretGroup: 1,
    minLength: 24,
  },
];

/**
 * Shannon entropy in bits per character.
 */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
  let h = 0;
  const len = s.length;
  for (const k in freq) {
    const p = freq[k] / len;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Scan a string of content for tier2 findings.
 * Returns GitleaksFinding-shaped objects for seamless interop.
 */
export function scanTier2Content(
  content: string,
  filePath: string,
): GitleaksFinding[] {
  const findings: GitleaksFinding[] = [];
  // Precompute line starts for line number lookup.
  const lineStarts: number[] = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "\n") lineStarts.push(i + 1);
  }

  const seen = new Set<string>();

  for (const rule of TIER2_RULES) {
    // Reset regex state (global flag).
    rule.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = rule.regex.exec(content)) !== null) {
      const secret = match[rule.secretGroup ?? 1];
      if (!secret) continue;
      if (rule.minLength && secret.length < rule.minLength) continue;
      if (rule.minEntropy && shannonEntropy(secret) < rule.minEntropy) continue;
      if (rule.stopwords) {
        const lower = secret.toLowerCase();
        if (rule.stopwords.some((sw) => lower.includes(sw.toLowerCase()))) {
          continue;
        }
      }

      // Dedupe by rule + secret within same file.
      const key = `${rule.id}:${secret}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const offset = match.index + match[0].indexOf(secret);
      const line = findLine(lineStarts, offset);
      const col = offset - lineStarts[line - 1] + 1;

      findings.push({
        RuleID: rule.id,
        Description: rule.description,
        StartLine: line,
        EndLine: line,
        StartColumn: col,
        EndColumn: col + secret.length,
        Match: match[0],
        Secret: secret,
        File: filePath,
        Entropy: shannonEntropy(secret),
        Fingerprint: `${filePath}:${rule.id}:${line}`,
      });
    }
  }

  return findings;
}

/**
 * Scan a single file.
 */
export function scanTier2File(filePath: string): GitleaksFinding[] {
  if (isBinaryFile(filePath)) return [];
  try {
    const stat = statSync(filePath);
    if (!stat.isFile()) return [];
    // Skip very large files.
    if (stat.size > 2 * 1024 * 1024) return [];
    const content = readFileSync(filePath, "utf-8");
    return scanTier2Content(content, filePath);
  } catch {
    return [];
  }
}

/**
 * Recursively scan a directory. Skips common vendor/build dirs and binaries.
 */
export function scanTier2Dir(dirPath: string): GitleaksFinding[] {
  const root = resolve(dirPath);
  const findings: GitleaksFinding[] = [];
  walk(root, findings);
  return findings;
}

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  ".next",
  ".nuxt",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
  ".idea",
  ".vscode",
  "target",
  ".gradle",
  ".cache",
]);

function walk(dir: string, findings: GitleaksFinding[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walk(full, findings);
    } else if (st.isFile()) {
      if (st.size > 2 * 1024 * 1024) continue;
      if (isBinaryFile(full)) continue;
      try {
        const content = readFileSync(full, "utf-8");
        const fileFindings = scanTier2Content(content, full);
        findings.push(...fileFindings);
      } catch {
        // unreadable / non-utf8 — skip
      }
    }
  }
}

function findLine(lineStarts: number[], offset: number): number {
  // Binary search for the last lineStart <= offset.
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1;
    if (lineStarts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1; // 1-indexed
}

/**
 * Merge tier1 (gitleaks) and tier2 findings, deduplicating by
 * file + line + secret.
 */
export function mergeFindings(
  tier1: GitleaksFinding[],
  tier2: GitleaksFinding[],
): GitleaksFinding[] {
  const seen = new Set<string>();
  const out: GitleaksFinding[] = [];
  for (const f of [...tier1, ...tier2]) {
    const key = `${f.File}:${f.StartLine}:${f.Secret}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}
