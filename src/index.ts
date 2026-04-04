// Gitleaks integration
export {
  getGitleaksBinary,
  isGitleaksAvailable,
  scanDir,
  scanFile,
  scanContent,
  scanStaged,
  type GitleaksFinding,
} from "./gitleaks/index.js";

// Blocklist
export {
  loadBlocklist,
  saveBlocklist,
  isInBlocklist,
  addToBlocklist,
  removeFromBlocklist,
} from "./hooks/blocklist.js";

// File patterns (static blocked paths)
export {
  isBlockedPath,
  isAllowlistedPath,
  DEFAULT_BLOCKED_PATTERNS,
} from "./scanner/file-patterns.js";

// Config
export { loadConfig, getAllowlistedPaths, getStopwords } from "./config/index.js";
