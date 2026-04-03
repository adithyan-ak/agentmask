export { scanContent, scanFile, scanFiles } from "./scanner.js";
export { TIER1_RULES, TIER2_RULES, ALL_RULES, truncateSecret, isStopword, STOPWORDS } from "./rules.js";
export { shannonEntropy, isLikelySecret } from "./entropy.js";
export {
  isBlockedPath,
  isAllowlistedPath,
  isBinaryFile,
  DEFAULT_BLOCKED_PATTERNS,
} from "./file-patterns.js";
export { redactContent, redactEnvLine, redactConnectionString } from "./redact.js";
export type {
  Rule,
  Finding,
  ScanResult,
  BlockedPathConfig,
  AllowlistEntry,
  AgentmaskConfig,
} from "./types.js";
