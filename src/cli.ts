import { Command } from "commander";
import { createRequire } from "node:module";
import { runScan } from "./cli/scan.js";
import { runInit } from "./cli/init.js";
import { runRemove } from "./cli/remove.js";
import { runAllowPath, runAllowValue } from "./cli/allowlist.js";

const require = createRequire(import.meta.url);
const { version } = require("../package.json");

const program = new Command();

program
  .name("agentmask")
  .description(
    "Mask your secrets from AI coding agents. One command. Zero friction.",
  )
  .version(version);

program
  .command("scan [path]")
  .description("Scan files for secrets")
  .option("--staged", "Scan git staged files only")
  .option("--json", "Output results as JSON")
  .action(async (path: string | undefined, options: { staged?: boolean; json?: boolean }) => {
    await runScan(path, options);
  });

program
  .command("init")
  .description("Install agentmask hooks and MCP server in the current project")
  .option("--team", "Write to shared .claude/settings.json instead of local")
  .action(async (options: { team?: boolean }) => {
    await runInit(options);
  });

program
  .command("remove")
  .description("Remove agentmask hooks, rules, and MCP registration")
  .action(async () => {
    await runRemove();
  });

program
  .command("allow-path <pattern>")
  .description("Add a path pattern to the allowlist (e.g., \"tests/**\")")
  .action(async (pattern: string) => {
    await runAllowPath(pattern);
  });

program
  .command("allow-value <value>")
  .description("Add a value to the stopword allowlist (e.g., \"EXAMPLE_KEY\")")
  .action(async (value: string) => {
    await runAllowValue(value);
  });

// Hook dispatch — called by Claude Code hooks
program
  .command("hook <type>")
  .description("Internal: handle a Claude Code hook event")
  .action(async (type: string) => {
    // Dynamic import to keep CLI startup fast for non-hook commands
    switch (type) {
      case "pre-read": {
        await import("./hooks/pre-read.js");
        break;
      }
      case "pre-bash": {
        await import("./hooks/pre-bash.js");
        break;
      }
      case "pre-write": {
        await import("./hooks/pre-write.js");
        break;
      }
      case "post-scan": {
        await import("./hooks/post-scan.js");
        break;
      }
      default:
        console.error(`Unknown hook type: ${type}`);
        process.exit(1);
    }
  });

// MCP server — called via .mcp.json
program
  .command("serve")
  .description("Start the agentmask MCP server (stdio)")
  .action(async () => {
    const { startServer } = await import("./mcp/server.js");
    await startServer();
  });

program.parse();
