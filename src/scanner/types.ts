export interface Rule {
  id: string;
  description: string;
  regex: RegExp;
  keywords?: string[];
  secretGroup?: number;
  entropy?: number;
  severity: "critical" | "high" | "medium" | "low";
}

export interface Finding {
  ruleId: string;
  description: string;
  filePath: string;
  line: number;
  column: number;
  match: string;
  redacted: string;
  severity: "critical" | "high" | "medium" | "low";
}

export interface ScanResult {
  filePath: string;
  findings: Finding[];
  scannedAt: string;
}

export interface BlockedPathConfig {
  patterns: string[];
}

export interface AllowlistEntry {
  paths?: string[];
  stopwords?: string[];
  description?: string;
}

export interface AgentmaskConfig {
  scan?: {
    blocked_paths?: string[];
  };
  rules?: Array<{
    id: string;
    description: string;
    regex: string;
    keywords?: string[];
    severity?: string;
  }>;
  allowlists?: AllowlistEntry[];
}
