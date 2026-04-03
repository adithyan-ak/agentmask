import type { Rule } from "./types.js";

/**
 * Tier 1: Provider-specific rules with near-zero false positives.
 * These have distinctive prefixes or formats — if it matches, it's a secret.
 */
export const TIER1_RULES: Rule[] = [
  // === AWS ===
  {
    id: "aws-access-key",
    description: "AWS Access Key ID",
    regex: /(?:^|[^A-Za-z0-9])((?:AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?:$|[^A-Za-z0-9])/,
    keywords: ["akia", "agpa", "aroa", "aipa", "anpa", "anva", "asia"],
    secretGroup: 1,
    severity: "critical",
  },
  // === GitHub ===
  {
    id: "github-pat",
    description: "GitHub Personal Access Token",
    regex: /(?:^|[^A-Za-z0-9_])(ghp_[A-Za-z0-9_]{36,})(?:$|[^A-Za-z0-9_])/,
    keywords: ["ghp_"],
    secretGroup: 1,
    severity: "critical",
  },
  {
    id: "github-fine-grained-pat",
    description: "GitHub Fine-Grained Personal Access Token",
    regex: /(?:^|[^A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{22,})(?:$|[^A-Za-z0-9_])/,
    keywords: ["github_pat_"],
    secretGroup: 1,
    severity: "critical",
  },
  {
    id: "github-oauth",
    description: "GitHub OAuth Access Token",
    regex: /(?:^|[^A-Za-z0-9_])(gho_[A-Za-z0-9_]{36,})(?:$|[^A-Za-z0-9_])/,
    keywords: ["gho_"],
    secretGroup: 1,
    severity: "high",
  },
  {
    id: "github-app-token",
    description: "GitHub App Token",
    regex: /(?:^|[^A-Za-z0-9_])((?:ghu|ghr)_[A-Za-z0-9_]{36,})(?:$|[^A-Za-z0-9_])/,
    keywords: ["ghu_", "ghr_"],
    secretGroup: 1,
    severity: "high",
  },
  {
    id: "github-app-install-token",
    description: "GitHub App Installation Token",
    regex: /(?:^|[^A-Za-z0-9_])(ghs_[A-Za-z0-9_]{36,})(?:$|[^A-Za-z0-9_])/,
    keywords: ["ghs_"],
    secretGroup: 1,
    severity: "high",
  },
  // === Stripe ===
  {
    id: "stripe-live-secret",
    description: "Stripe Live Secret Key",
    regex: /(?:^|[^A-Za-z0-9_])([sr]k_live_[0-9a-zA-Z]{24,})(?:$|[^A-Za-z0-9_])/,
    keywords: ["sk_live_", "rk_live_"],
    secretGroup: 1,
    severity: "critical",
  },
  // === GCP ===
  {
    id: "gcp-api-key",
    description: "Google Cloud Platform API Key",
    regex: /(?:^|[^A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?:$|[^A-Za-z0-9_-])/,
    keywords: ["aiza"],
    secretGroup: 1,
    severity: "high",
  },
  // === Slack ===
  {
    id: "slack-bot-token",
    description: "Slack Bot Token",
    regex: /(?:^|[^A-Za-z0-9_-])(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})(?:$|[^A-Za-z0-9_-])/,
    keywords: ["xoxb-"],
    secretGroup: 1,
    severity: "high",
  },
  {
    id: "slack-user-token",
    description: "Slack User Token",
    regex: /(?:^|[^A-Za-z0-9_-])(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})(?:$|[^A-Za-z0-9_-])/,
    keywords: ["xoxp-"],
    secretGroup: 1,
    severity: "high",
  },
  {
    id: "slack-webhook",
    description: "Slack Webhook URL",
    regex: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24,})/,
    keywords: ["hooks.slack.com"],
    secretGroup: 1,
    severity: "high",
  },
  // === Twilio ===
  {
    id: "twilio-api-key",
    description: "Twilio API Key",
    regex: /(?:^|[^A-Za-z0-9])(SK[0-9a-fA-F]{32})(?:$|[^A-Za-z0-9])/,
    keywords: ["twilio", "sk"],
    secretGroup: 1,
    severity: "high",
  },
  // === SendGrid ===
  {
    id: "sendgrid-api-key",
    description: "SendGrid API Key",
    regex: /(?:^|[^A-Za-z0-9._-])(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})(?:$|[^A-Za-z0-9._-])/,
    keywords: ["sg."],
    secretGroup: 1,
    severity: "high",
  },
  // === Shopify ===
  {
    id: "shopify-token",
    description: "Shopify Access Token",
    regex: /(?:^|[^A-Za-z0-9_])(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32,})(?:$|[^A-Za-z0-9_])/,
    keywords: ["shpat_", "shpca_", "shppa_", "shpss_"],
    secretGroup: 1,
    severity: "high",
  },
  // === PEM Private Keys ===
  {
    id: "private-key",
    description: "Private Key (PEM format)",
    regex: /(-----BEGIN\s?(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)/,
    keywords: ["begin", "private key"],
    secretGroup: 1,
    severity: "critical",
  },
  // === JWT ===
  {
    id: "jwt",
    description: "JSON Web Token",
    regex: /(?:^|[^A-Za-z0-9_.-])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?:$|[^A-Za-z0-9_.-])/,
    keywords: ["eyj"],
    secretGroup: 1,
    severity: "high",
  },
  // === Supabase ===
  {
    id: "supabase-key",
    description: "Supabase Service Key",
    regex: /(?:^|[^A-Za-z0-9_])(sbp_[a-f0-9]{40})(?:$|[^A-Za-z0-9_])/,
    keywords: ["sbp_"],
    secretGroup: 1,
    severity: "high",
  },
  // === Vercel ===
  {
    id: "vercel-token",
    description: "Vercel API Token",
    regex: /(?:^|[^A-Za-z0-9_-])(vercel_[A-Za-z0-9_-]{24,})(?:$|[^A-Za-z0-9_-])/,
    keywords: ["vercel_"],
    secretGroup: 1,
    severity: "high",
  },
  // === OpenAI ===
  {
    id: "openai-api-key",
    description: "OpenAI API Key",
    regex: /(?:^|[^A-Za-z0-9_-])(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:$|[^A-Za-z0-9_-])/,
    keywords: ["sk-", "t3blbkfj"],
    secretGroup: 1,
    severity: "critical",
  },
  {
    id: "openai-api-key-v2",
    description: "OpenAI API Key (project-scoped)",
    regex: /(?:^|[^A-Za-z0-9_-])(sk-proj-[A-Za-z0-9_-]{40,})(?:$|[^A-Za-z0-9_-])/,
    keywords: ["sk-proj-"],
    secretGroup: 1,
    severity: "critical",
  },
  // === Anthropic ===
  {
    id: "anthropic-api-key",
    description: "Anthropic API Key",
    regex: /(?:^|[^A-Za-z0-9_-])(sk-ant-[a-zA-Z0-9_-]{90,})(?:$|[^A-Za-z0-9_-])/,
    keywords: ["sk-ant-"],
    secretGroup: 1,
    severity: "critical",
  },
  // === Mailchimp ===
  {
    id: "mailchimp-api-key",
    description: "Mailchimp API Key",
    regex: /(?:^|[^A-Za-z0-9_-])([a-f0-9]{32}-us[0-9]{1,2})(?:$|[^A-Za-z0-9_-])/,
    keywords: ["mailchimp", "-us"],
    secretGroup: 1,
    severity: "high",
  },
  // === Heroku ===
  {
    id: "heroku-api-key",
    description: "Heroku API Key",
    regex: /(?:^|[^A-Za-z0-9_-])([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:$|[^A-Za-z0-9_-])/i,
    keywords: ["heroku"],
    secretGroup: 1,
    severity: "medium",
    entropy: 3.0,
  },
  // === Datadog ===
  {
    id: "datadog-api-key",
    description: "Datadog API Key",
    regex: /(?:(?:datadog|dd)[_\s-]?(?:api[_\s-]?)?key[\s'"]*[:=][\s'"]*)([\da-f]{32})/i,
    keywords: ["datadog", "dd_api"],
    secretGroup: 1,
    severity: "high",
  },
  // === NPM ===
  {
    id: "npm-token",
    description: "npm Access Token",
    regex: /(?:^|[^A-Za-z0-9_-])(npm_[A-Za-z0-9]{36,})(?:$|[^A-Za-z0-9_-])/,
    keywords: ["npm_"],
    secretGroup: 1,
    severity: "high",
  },
  // === PyPI ===
  {
    id: "pypi-token",
    description: "PyPI API Token",
    regex: /(?:^|[^A-Za-z0-9_-])(pypi-[A-Za-z0-9_-]{50,})(?:$|[^A-Za-z0-9_-])/,
    keywords: ["pypi-"],
    secretGroup: 1,
    severity: "high",
  },
  // === Discord ===
  {
    id: "discord-bot-token",
    description: "Discord Bot Token",
    regex: /(?:^|[^A-Za-z0-9._-])([A-Za-z0-9]{24,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})(?:$|[^A-Za-z0-9._-])/,
    keywords: ["discord", "bot", "token"],
    secretGroup: 1,
    severity: "high",
    entropy: 4.0,
  },
  // === Connection Strings (treated as Tier 1 because the format is distinctive) ===
  {
    id: "connection-string",
    description: "Database Connection String with Credentials",
    regex: /((?:postgresql|postgres|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+)/i,
    keywords: ["://"],
    secretGroup: 1,
    severity: "critical",
  },
];

/**
 * Tier 2: Generic keyword-anchored rules.
 * These catch secrets without known prefixes by looking for
 * keyword → operator → high-entropy value patterns.
 *
 * Higher false positive rate than Tier 1 — filtered by entropy + stopwords.
 */
export const TIER2_RULES: Rule[] = [
  {
    id: "generic-secret",
    description: "Generic Secret Assignment",
    // Matches: KEYWORD (separator) OPERATOR (quotes/space) VALUE
    // Keyword must be preceded by word boundary context (not mid-identifier)
    regex: /(?:^|[^a-zA-Z])(?:api_?key|api_?secret|auth_?token|access_?key|access_?token|secret_?key|private_?key|client_?secret|app_?secret|signing_?key|encryption_?key|password|passwd|credential)[\s'"]*(?:=|:|=>)[\s'"]*([a-zA-Z0-9_\-/+=@!$%^&*.~]{10,150})/i,
    keywords: ["api_key", "api_secret", "apikey", "apisecret", "auth_token", "authtoken", "access_key", "accesskey", "access_token", "accesstoken", "secret_key", "secretkey", "private_key", "privatekey", "client_secret", "clientsecret", "app_secret", "appsecret", "signing_key", "signingkey", "encryption_key", "encryptionkey", "password", "passwd", "credential"],
    secretGroup: 1,
    severity: "medium",
    entropy: 3.5,
  },
];

/** All rules combined, Tier 1 first (higher precision). */
export const ALL_RULES: Rule[] = [...TIER1_RULES, ...TIER2_RULES];

/**
 * Stopwords — common programming terms that match generic patterns
 * but are NOT secrets. Used to filter Tier 2 false positives.
 */
export const STOPWORDS = new Set([
  "true", "false", "null", "none", "undefined", "nil",
  "primary", "secondary", "default", "required", "optional",
  "enabled", "disabled", "active", "inactive",
  "public", "private", "protected", "internal",
  "read", "write", "admin", "user", "guest", "root",
  "development", "production", "staging", "test", "testing", "local",
  "localhost", "example.com", "placeholder",
  "application", "json", "text/html", "text/plain",
  "bearer", "basic", "digest",
  "access_token", "refresh_token", "id_token",
  "content-type", "authorization", "accept",
  "utf-8", "utf8", "ascii", "base64",
  "index.html", "index.js", "index.ts",
  "package.json", "tsconfig.json",
  "node_modules", ".git", "dist", "build",
  "description", "repository", "homepage",
  "MIT", "Apache-2.0", "ISC", "BSD-3-Clause",
  "constructor", "prototype", "toString",
  "get", "set", "post", "put", "delete", "patch",
  "success", "error", "warning", "info", "debug",
  "created", "updated", "deleted",
  "process.env", "os.environ",
  "string", "number", "boolean", "object", "array",
  "function", "class", "interface", "type", "enum",
  "import", "export", "require", "module",
  "return", "const", "let", "var",
]);

/**
 * Check if a captured value is a stopword (likely false positive).
 */
export function isStopword(value: string): boolean {
  const lower = value.toLowerCase().trim();
  if (STOPWORDS.has(lower)) return true;
  // Also check common patterns: all same char, sequential, etc.
  if (/^(.)\1+$/.test(lower)) return true; // "aaaa..."
  if (/^(0123456789|abcdefghij|1234567890)/.test(lower)) return true;
  return false;
}

/**
 * Truncate a secret value for safe display.
 * Shows first 4 and last 4 chars for values > 12 chars, else shows first 4 + "..."
 */
export function truncateSecret(value: string): string {
  if (value.length <= 8) return "****";
  if (value.length <= 12) return value.slice(0, 4) + "...";
  return value.slice(0, 4) + "..." + value.slice(-4);
}
