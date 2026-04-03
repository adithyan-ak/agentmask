export {
  scanContent,
  scanFile,
  scanFiles,
  TIER1_RULES,
  TIER2_RULES,
  ALL_RULES,
  truncateSecret,
  isStopword,
  shannonEntropy,
  isLikelySecret,
  isBlockedPath,
  isAllowlistedPath,
  isBinaryFile,
  DEFAULT_BLOCKED_PATTERNS,
  redactContent,
  redactEnvLine,
  redactConnectionString,
} from "./scanner/index.js";

export type {
  Rule,
  Finding,
  ScanResult,
  BlockedPathConfig,
  AllowlistEntry,
  AgentmaskConfig,
} from "./scanner/index.js";

export { loadConfig, getAllowlistedPaths, getStopwords } from "./config/index.js";
