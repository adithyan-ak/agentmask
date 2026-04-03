/**
 * Calculate Shannon entropy of a string in bits per character.
 *
 * High entropy (>3.5) suggests random/generated strings (likely secrets).
 * Low entropy (<3.0) suggests natural language or simple values.
 *
 * Reference values:
 *   - "true" → ~1.5
 *   - "development" → ~3.3
 *   - "sk_live_FAKEEXAMPLEVALUE0000" → ~4.2
 *   - Random 40-char hex → ~4.0
 */
export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Classify a value as likely secret or likely safe based on heuristics.
 * Returns true if the value appears to be a secret.
 */
export function isLikelySecret(value: string, keyName?: string): boolean {
  const trimmed = value.trim();

  // Empty or very short values are not secrets
  if (trimmed.length < 8) return false;

  // Booleans and common config values are not secrets
  const lowerVal = trimmed.toLowerCase();
  if (SAFE_VALUES.has(lowerVal)) return false;

  // Pure numbers are not secrets
  if (/^\d+$/.test(trimmed)) return false;

  // Simple hostnames / URLs without credentials
  if (/^https?:\/\/[^:@]+$/.test(trimmed)) return false;

  // If key name suggests a secret, lower the entropy threshold
  const keySuggestsSecret = keyName
    ? SECRET_KEY_PATTERNS.some((p) => p.test(keyName))
    : false;

  const entropyThreshold = keySuggestsSecret ? 2.5 : 3.5;
  const entropy = shannonEntropy(trimmed);

  return entropy >= entropyThreshold;
}

const SECRET_KEY_PATTERNS = [
  /key$/i,
  /secret$/i,
  /token$/i,
  /password$/i,
  /passwd$/i,
  /credential/i,
  /auth/i,
  /api[_-]?key/i,
  /private/i,
  /signing/i,
  /encryption/i,
];

const SAFE_VALUES = new Set([
  "true",
  "false",
  "yes",
  "no",
  "on",
  "off",
  "null",
  "none",
  "undefined",
  "development",
  "production",
  "staging",
  "test",
  "testing",
  "local",
  "localhost",
  "debug",
  "info",
  "warn",
  "error",
  "verbose",
  "trace",
  "utf-8",
  "utf8",
  "ascii",
  "json",
  "text",
  "html",
  "xml",
  "csv",
  "utc",
  "gmt",
]);
