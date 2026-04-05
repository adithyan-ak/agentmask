import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  scanFile as gitleaksScanFile,
  scanStaged as gitleaksScanStaged,
  type GitleaksFinding,
} from "../gitleaks/runner.js";
import { scanTier2File, mergeFindings } from "../scanner/tier2.js";

export async function startServer(): Promise<void> {
  const server = new McpServer({
    name: "agentmask",
    version: "0.1.0",
  });

  // === safe_read tool ===
  server.tool(
    "safe_read",
    "Read a file with secrets redacted. Use this instead of the built-in Read tool for files that may contain secrets (.env, credentials, etc.).",
    { file_path: z.string().describe("Absolute or relative path to the file to read") },
    async ({ file_path }) => {
      try {
        const resolved = resolve(file_path);
        const content = await readFile(resolved, "utf-8");

        // Run gitleaks + tier2 on the file to find secrets
        const tier1 = await gitleaksScanFile(resolved);
        const tier2 = scanTier2File(resolved);
        const findings = mergeFindings(tier1, tier2);

        if (findings.length === 0) {
          return { content: [{ type: "text", text: content }] };
        }

        // Redact each finding's Secret value from the content
        let redacted = content;
        for (const f of findings) {
          if (f.Secret) {
            redacted = redacted.replaceAll(f.Secret, `[REDACTED:${f.RuleID}]`);
          }
        }

        const header = `# [agentmask] Redacted ${findings.length} secret(s). Reference by variable name only.\n\n`;
        return { content: [{ type: "text", text: header + redacted }] };
      } catch (err: any) {
        return {
          content: [{ type: "text", text: `Error reading file: ${err.message}` }],
          isError: true,
        };
      }
    },
  );

  // === env_names tool ===
  server.tool(
    "env_names",
    "List environment variable names from a .env file without exposing their values. Shows variable names and whether they contain detected secrets.",
    {
      file_path: z
        .string()
        .optional()
        .describe("Path to .env file (defaults to .env in current directory)"),
    },
    async ({ file_path }) => {
      try {
        const resolved = resolve(file_path ?? ".env");
        const content = await readFile(resolved, "utf-8");
        const findings = await gitleaksScanFile(resolved);

        // Build a set of lines that have secrets
        const secretLines = new Set(findings.map((f) => f.StartLine));

        const lines = content.split("\n");
        const entries: string[] = [];

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line || line.startsWith("#")) continue;

          const match = line.match(
            /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)/,
          );
          if (!match) continue;

          const [, key, rawValue] = match;
          let value = rawValue;
          if (
            (value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))
          ) {
            value = value.slice(1, -1);
          }

          const isSecret = secretLines.has(i + 1);
          const type = classifyValue(value, key);
          entries.push(
            `${key} (${type})${isSecret ? " [SECRET]" : ""} — line ${i + 1}`,
          );
        }

        return {
          content: [{
            type: "text",
            text: entries.length > 0 ? entries.join("\n") : "No environment variables found.",
          }],
        };
      } catch (err: any) {
        return {
          content: [{ type: "text", text: `Error: ${err.message}` }],
          isError: true,
        };
      }
    },
  );

  // === scan_file tool ===
  server.tool(
    "scan_file",
    "Scan a file for hardcoded secrets using gitleaks (150+ detection rules). Returns findings with rule ID, line number, and description.",
    { file_path: z.string().describe("Path to the file to scan") },
    async ({ file_path }) => {
      try {
        const resolved = resolve(file_path);
        const tier1 = await gitleaksScanFile(resolved);
        const tier2 = scanTier2File(resolved);
        const findings = mergeFindings(tier1, tier2);

        if (findings.length === 0) {
          return { content: [{ type: "text", text: "No secrets found." }] };
        }

        const output = findings
          .map((f) => `Line ${f.StartLine}: ${f.Description} (rule: ${f.RuleID})`)
          .join("\n");

        return {
          content: [{
            type: "text",
            text: `Found ${findings.length} secret(s):\n${output}`,
          }],
        };
      } catch (err: any) {
        return {
          content: [{ type: "text", text: `Error: ${err.message}` }],
          isError: true,
        };
      }
    },
  );

  // === scan_staged tool ===
  server.tool(
    "scan_staged",
    "Scan git staged files for secrets before committing. Uses gitleaks with 150+ detection rules.",
    {},
    async () => {
      try {
        const findings = await gitleaksScanStaged(process.cwd());

        if (findings.length === 0) {
          return {
            content: [{ type: "text", text: "No secrets found in staged files. Safe to commit." }],
          };
        }

        const report = findings
          .map((f) => `${f.File}:${f.StartLine} — ${f.Description} (rule: ${f.RuleID})`)
          .join("\n");

        return {
          content: [{
            type: "text",
            text: `Found ${findings.length} secret(s) in staged files:\n${report}\n\nFix these before committing.`,
          }],
        };
      } catch (err: any) {
        return {
          content: [{ type: "text", text: `Error: ${err.message}` }],
          isError: true,
        };
      }
    },
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

function classifyValue(value: string, key: string): string {
  const lowerKey = key.toLowerCase();
  const lowerVal = value.toLowerCase();

  if (/^(?:postgresql|postgres|mysql|mongodb|redis|amqp):\/\//i.test(value))
    return "connection_string";
  if (["true", "false", "yes", "no", "on", "off"].includes(lowerVal))
    return "boolean";
  if (/^\d+$/.test(value)) return "number";
  if (/^https?:\/\//.test(value)) return "url";
  if (/api[_-]?key/i.test(lowerKey)) return "api_key";
  if (/token/i.test(lowerKey)) return "token";
  if (/password|passwd/i.test(lowerKey)) return "password";
  if (/secret/i.test(lowerKey)) return "secret";

  return "string";
}
