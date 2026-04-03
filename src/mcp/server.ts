import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { execSync } from "node:child_process";
import { redactContent } from "../scanner/redact.js";
import { scanContent } from "../scanner/scanner.js";
import { isLikelySecret, shannonEntropy } from "../scanner/entropy.js";

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
        const { content: redacted, redactionCount } = redactContent(
          content,
          resolved,
        );

        const header =
          redactionCount > 0
            ? `# [agentmask] Redacted ${redactionCount} secret(s). Reference by variable name only.\n\n`
            : "";

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
    "List environment variable names from a .env file without exposing their values. Shows variable names, types (api_key, connection_string, boolean, number, etc.), and whether they appear to be secrets.",
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
        const lines = content.split("\n");
        const entries: Array<{
          name: string;
          type: string;
          is_secret: boolean;
          line: number;
        }> = [];

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

          entries.push({
            name: key,
            type: classifyValue(value, key),
            is_secret: isLikelySecret(value, key),
            line: i + 1,
          });
        }

        const output = entries
          .map(
            (e) =>
              `${e.name} (${e.type})${e.is_secret ? " [SECRET]" : ""} — line ${e.line}`,
          )
          .join("\n");

        return {
          content: [
            {
              type: "text",
              text: output || "No environment variables found.",
            },
          ],
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
    "Scan a file for hardcoded secrets. Returns findings with rule ID, line number, and severity.",
    { file_path: z.string().describe("Path to the file to scan") },
    async ({ file_path }) => {
      try {
        const resolved = resolve(file_path);
        const content = await readFile(resolved, "utf-8");
        const findings = scanContent(content, resolved);

        if (findings.length === 0) {
          return {
            content: [{ type: "text", text: "No secrets found." }],
          };
        }

        const output = findings
          .map(
            (f) =>
              `[${f.severity.toUpperCase()}] Line ${f.line}: ${f.description} (${f.match})`,
          )
          .join("\n");

        return {
          content: [
            {
              type: "text",
              text: `Found ${findings.length} secret(s):\n${output}`,
            },
          ],
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
    "Scan git staged files for secrets before committing. Returns findings or confirms staged files are clean.",
    {},
    async () => {
      try {
        const output = execSync(
          "git diff --cached --name-only --diff-filter=ACMR",
          { encoding: "utf-8" },
        );
        const files = output.trim().split("\n").filter(Boolean);

        if (files.length === 0) {
          return {
            content: [{ type: "text", text: "No staged files to scan." }],
          };
        }

        const allFindings: Array<{
          file: string;
          line: number;
          description: string;
          match: string;
          severity: string;
        }> = [];

        for (const file of files) {
          let content: string;
          try {
            content = execSync(`git show ":${file}"`, { encoding: "utf-8" });
          } catch {
            continue;
          }

          const findings = scanContent(content, file);
          for (const f of findings) {
            allFindings.push({
              file: f.filePath,
              line: f.line,
              description: f.description,
              match: f.match,
              severity: f.severity,
            });
          }
        }

        if (allFindings.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `Scanned ${files.length} staged file(s). No secrets found. Safe to commit.`,
              },
            ],
          };
        }

        const report = allFindings
          .map(
            (f) =>
              `[${f.severity.toUpperCase()}] ${f.file}:${f.line} — ${f.description} (${f.match})`,
          )
          .join("\n");

        return {
          content: [
            {
              type: "text",
              text: `Found ${allFindings.length} secret(s) in staged files:\n${report}\n\nFix these before committing.`,
            },
          ],
        };
      } catch (err: any) {
        return {
          content: [
            {
              type: "text",
              text: `Error scanning staged files: ${err.message}`,
            },
          ],
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

  // Connection string
  if (/^(?:postgresql|postgres|mysql|mongodb|redis|amqp):\/\//i.test(value))
    return "connection_string";

  // Boolean
  if (["true", "false", "yes", "no", "on", "off"].includes(lowerVal))
    return "boolean";

  // Number
  if (/^\d+$/.test(value)) return "number";

  // URL (without credentials)
  if (/^https?:\/\//.test(value)) return "url";

  // Key name hints
  if (/api[_-]?key/i.test(lowerKey)) return "api_key";
  if (/token/i.test(lowerKey)) return "token";
  if (/password|passwd/i.test(lowerKey)) return "password";
  if (/secret/i.test(lowerKey)) return "secret";
  if (/key$/i.test(lowerKey)) return "key";

  return "string";
}
