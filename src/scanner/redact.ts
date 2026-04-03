import { isLikelySecret } from "./entropy.js";
import { TIER1_RULES } from "./rules.js";

/**
 * Redact a connection string, preserving structure.
 *
 * Input:  postgresql://admin:s3cr3t@db.example.com:5432/myapp
 * Output: postgresql://****:****@db.example.com:5432/myapp
 */
export function redactConnectionString(connStr: string): string {
  // Match: protocol://user:password@rest
  const match = connStr.match(
    /^((?:postgresql|postgres|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\/)([^:]+):([^@]+)@(.+)$/i,
  );
  if (match) {
    return `${match[1]}****:****@${match[4]}`;
  }
  // Fallback: just redact the whole thing
  return "[REDACTED:connection_string]";
}

/**
 * Redact a single .env line, preserving key name and non-secret values.
 *
 * Returns the redacted line and whether it was redacted.
 */
export function redactEnvLine(line: string): { line: string; redacted: boolean } {
  const trimmed = line.trim();

  // Comments and blank lines pass through
  if (trimmed === "" || trimmed.startsWith("#")) {
    return { line, redacted: false };
  }

  // Parse KEY=VALUE (with optional export prefix and quotes)
  const envMatch = trimmed.match(
    /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*)/,
  );
  if (!envMatch) {
    return { line, redacted: false };
  }

  const [, key, separator, rawValue] = envMatch;

  // Strip surrounding quotes from value
  let value = rawValue;
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1);
  }

  // Check if it's a connection string
  if (/^(?:postgresql|postgres|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\//i.test(value)) {
    return {
      line: `${key}${separator}${redactConnectionString(value)}`,
      redacted: true,
    };
  }

  // Check if the value looks like a secret
  if (isLikelySecret(value, key)) {
    const len = value.length;
    return {
      line: `${key}${separator}[REDACTED:${len}_chars]`,
      redacted: true,
    };
  }

  // Safe value — keep as-is
  return { line, redacted: false };
}

/**
 * Redact all secrets in file content, returning the redacted content
 * and count of redactions made.
 */
export function redactContent(
  content: string,
  filePath: string,
): { content: string; redactionCount: number } {
  const isEnvFile = /(?:^|[\\/])\.env(?:\..+)?$/.test(filePath);

  if (isEnvFile) {
    return redactEnvContent(content);
  }

  // For non-env files, use rule-based redaction
  return redactWithRules(content);
}

function redactEnvContent(content: string): {
  content: string;
  redactionCount: number;
} {
  const lines = content.split("\n");
  let redactionCount = 0;
  const redactedLines = lines.map((line) => {
    const result = redactEnvLine(line);
    if (result.redacted) redactionCount++;
    return result.line;
  });

  return { content: redactedLines.join("\n"), redactionCount };
}

function redactWithRules(content: string): {
  content: string;
  redactionCount: number;
} {
  let redacted = content;
  let redactionCount = 0;

  for (const rule of TIER1_RULES) {
    const globalRegex = new RegExp(rule.regex.source, rule.regex.flags + (rule.regex.flags.includes("g") ? "" : "g"));
    redacted = redacted.replace(globalRegex, (fullMatch, ...groups) => {
      const secretGroup = rule.secretGroup ?? 1;
      const secret = groups[secretGroup - 1];
      if (!secret) return fullMatch;

      redactionCount++;

      if (rule.id === "connection-string") {
        return fullMatch.replace(secret, redactConnectionString(secret));
      }
      return fullMatch.replace(secret, `[REDACTED:${rule.id}]`);
    });
  }

  return { content: redacted, redactionCount };
}
