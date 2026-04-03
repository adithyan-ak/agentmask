import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execSync } from "node:child_process";
import {
  mkdirSync,
  writeFileSync,
  existsSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { join, resolve } from "node:path";

const CLI = resolve("dist/cli.js");
const TEST_DIR = resolve("tests/integration-workspace");

function run(cmd: string, cwd = TEST_DIR): string {
  return execSync(cmd, { cwd, encoding: "utf-8", timeout: 10_000 });
}

function runMaybe(cmd: string, cwd = TEST_DIR): { stdout: string; stderr: string; code: number } {
  try {
    const stdout = execSync(cmd, { cwd, encoding: "utf-8", timeout: 10_000, stdio: ["pipe", "pipe", "pipe"] });
    return { stdout, stderr: "", code: 0 };
  } catch (err: any) {
    return { stdout: err.stdout ?? "", stderr: err.stderr ?? "", code: err.status ?? 1 };
  }
}

describe("Integration: agentmask init + scan", () => {
  beforeAll(() => {
    // Create a test workspace
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(TEST_DIR, { recursive: true });

    // Create test files
    writeFileSync(
      join(TEST_DIR, ".env"),
      [
        "DATABASE_URL=postgresql://admin:s3cr3t@db.example.com:5432/myapp",
        "API_KEY=sk_live_FAKEFAKEFAKEFAKEFAKEFAKE",
        "DEBUG=true",
        "PORT=3000",
      ].join("\n"),
    );

    writeFileSync(
      join(TEST_DIR, "app.ts"),
      [
        'import express from "express";',
        "const app = express();",
        "const port = process.env.PORT;",
        "app.listen(port);",
      ].join("\n"),
    );

    writeFileSync(
      join(TEST_DIR, "leaky.ts"),
      'const key = "AKIAIOSFODNN7EXAMPLE";',
    );

    // Init git repo for staged file tests
    try {
      run("git init");
      run("git add .");
    } catch {
      // git might not be available in all test environments
    }
  });

  afterAll(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("agentmask init creates all required files", () => {
    run(`node ${CLI} init`);

    expect(existsSync(join(TEST_DIR, ".claude", "settings.local.json"))).toBe(true);
    expect(existsSync(join(TEST_DIR, ".claude", "rules", "agentmask.md"))).toBe(true);
    expect(existsSync(join(TEST_DIR, ".mcp.json"))).toBe(true);

    // Check settings content
    const settings = JSON.parse(
      readFileSync(join(TEST_DIR, ".claude", "settings.local.json"), "utf-8"),
    );
    expect(settings.hooks.PreToolUse).toBeDefined();
    expect(settings.hooks.PostToolUse).toBeDefined();

    // Check MCP config
    const mcp = JSON.parse(
      readFileSync(join(TEST_DIR, ".mcp.json"), "utf-8"),
    );
    expect(mcp.mcpServers.agentmask).toBeDefined();
  });

  it("agentmask init is idempotent", () => {
    run(`node ${CLI} init`);
    run(`node ${CLI} init`);

    const settings = JSON.parse(
      readFileSync(join(TEST_DIR, ".claude", "settings.local.json"), "utf-8"),
    );
    // Should have exactly 3 PreToolUse entries, not 6
    expect(settings.hooks.PreToolUse).toHaveLength(3);
    expect(settings.hooks.PostToolUse).toHaveLength(1);
  });

  it("scan detects secrets in leaky file", () => {
    const result = runMaybe(`node ${CLI} scan leaky.ts`);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain("AWS Access Key");
  });

  it("scan finds no secrets in clean file", () => {
    const result = runMaybe(`node ${CLI} scan app.ts`);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("No secrets found");
  });

  it("scan --json returns structured output", () => {
    const result = runMaybe(`node ${CLI} scan leaky.ts --json`);
    const json = JSON.parse(result.stdout);
    expect(json.findings.length).toBeGreaterThan(0);
    expect(json.findings[0].ruleId).toBe("aws-access-key");
    expect(json.summary.secretsFound).toBeGreaterThan(0);
  });

  it("scan detects blocked .env files", () => {
    const result = runMaybe(`node ${CLI} scan .`);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain(".env");
  });

  it("scan --staged scans git staged files", () => {
    try {
      run("git add leaky.ts");
      const result = runMaybe(`node ${CLI} scan --staged`);
      expect(result.code).toBe(1);
      expect(result.stdout).toContain("AWS Access Key");
    } catch {
      // Skip if git not available
    }
  });

  it("allow-path adds to config", () => {
    run(`node ${CLI} allow-path "tests/**"`);
    expect(existsSync(join(TEST_DIR, ".agentmask.toml"))).toBe(true);

    const content = readFileSync(join(TEST_DIR, ".agentmask.toml"), "utf-8");
    expect(content).toContain("tests/**");
  });

  it("allow-value adds to config", () => {
    run(`node ${CLI} allow-value "EXAMPLE_KEY_12345"`);

    const content = readFileSync(join(TEST_DIR, ".agentmask.toml"), "utf-8");
    expect(content).toContain("EXAMPLE_KEY_12345");
  });

  it("agentmask remove cleans up everything", () => {
    run(`node ${CLI} remove`);

    const settings = JSON.parse(
      readFileSync(join(TEST_DIR, ".claude", "settings.local.json"), "utf-8"),
    );
    expect(settings.hooks).toBeUndefined();

    expect(
      existsSync(join(TEST_DIR, ".claude", "rules", "agentmask.md")),
    ).toBe(false);

    const mcp = JSON.parse(
      readFileSync(join(TEST_DIR, ".mcp.json"), "utf-8"),
    );
    expect(mcp.mcpServers?.agentmask).toBeUndefined();
  });
});

describe("Integration: Hook scenarios", () => {
  function hookCall(
    type: string,
    input: Record<string, unknown>,
  ): { code: number; stdout: string; stderr: string } {
    try {
      const stdout = execSync(
        `echo '${JSON.stringify(input)}' | node ${CLI} hook ${type}`,
        { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
      );
      return { code: 0, stdout, stderr: "" };
    } catch (err: any) {
      return {
        code: err.status ?? 1,
        stdout: err.stdout ?? "",
        stderr: err.stderr ?? "",
      };
    }
  }

  // Scenario A: Read .env → blocked → guidance to use safe_read
  it("Scenario A: Read .env is blocked with redirect guidance", () => {
    const result = hookCall("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: ".env" },
      cwd: "/tmp",
    });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("mcp__agentmask__safe_read");
    expect(result.stderr).toContain("mcp__agentmask__env_names");
  });

  // Scenario B: Read normal file → allowed
  it("Scenario B: Read normal file passes through", () => {
    const result = hookCall("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: "src/app.ts" },
      cwd: "/tmp",
    });
    expect(result.code).toBe(0);
  });

  // Scenario C: Read file with unexpected secret → warning
  it("Scenario C: Secret in unexpected file triggers warning", () => {
    const result = hookCall("post-scan", {
      tool_name: "Read",
      tool_input: { file_path: "utils.ts" },
      tool_response: 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";',
    });
    expect(result.code).toBe(0); // Allowed (can't block post-tool)
    expect(result.stdout).toContain("WARNING");
    expect(result.stdout).toContain("AWS Access Key");
  });

  // Scenario D: Write with hardcoded key → blocked
  it("Scenario D: Write with hardcoded secret is blocked", () => {
    const result = hookCall("pre-write", {
      tool_name: "Write",
      tool_input: {
        file_path: "config.ts",
        content: 'const stripe = new Stripe("sk_live_FAKEFAKEFAKEFAKEFAKEFAKE");',
      },
    });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("Stripe");
    expect(result.stderr).toContain("environment variable");
  });

  // Scenario E: Write clean code → allowed
  it("Scenario E: Write with env var reference passes through", () => {
    const result = hookCall("pre-write", {
      tool_name: "Write",
      tool_input: {
        file_path: "config.ts",
        content: "const stripe = new Stripe(process.env.STRIPE_KEY);",
      },
    });
    expect(result.code).toBe(0);
  });

  // Scenario F: Write to .env → allowed (expected to have secrets)
  it("Scenario F: Write to .env file is allowed", () => {
    const result = hookCall("pre-write", {
      tool_name: "Write",
      tool_input: {
        file_path: ".env",
        content: "STRIPE_KEY=sk_live_FAKEFAKEFAKEFAKEFAKEFAKE",
      },
    });
    expect(result.code).toBe(0);
  });

  // Scenario G: Bash cat .env → blocked
  it("Scenario G: Bash cat .env is blocked", () => {
    const result = hookCall("pre-bash", {
      tool_name: "Bash",
      tool_input: { command: "cat .env" },
    });
    expect(result.code).toBe(2);
  });

  // Scenario H: Bash printenv → blocked
  it("Scenario H: Bash printenv is blocked", () => {
    const result = hookCall("pre-bash", {
      tool_name: "Bash",
      tool_input: { command: "printenv" },
    });
    expect(result.code).toBe(2);
  });

  // Scenario I: Bash npm test → allowed
  it("Scenario I: Normal bash commands pass through", () => {
    const commands = [
      "npm test",
      "npm install express",
      "git status",
      "git log --oneline -5",
      "ls -la",
      "node script.js",
      "python manage.py migrate",
      "cargo build",
      "go test ./...",
      "make build",
    ];
    for (const cmd of commands) {
      const result = hookCall("pre-bash", {
        tool_name: "Bash",
        tool_input: { command: cmd },
      });
      expect(result.code, `Should allow: ${cmd}`).toBe(0);
    }
  });

  // Scenario J: Graceful degradation on malformed input
  it("Scenario J: Malformed input degrades gracefully", () => {
    const result = hookCall("pre-read", {});
    expect(result.code).toBe(0); // Allow, don't block

    const result2 = hookCall("pre-bash", { tool_input: {} });
    expect(result2.code).toBe(0);

    const result3 = hookCall("pre-write", { tool_input: { file_path: "x.ts" } });
    expect(result3.code).toBe(0); // No content → allow
  });

  // Scenario K: Edit (not just Write) with secret → blocked
  it("Scenario K: Edit with secret in new_string is blocked", () => {
    const result = hookCall("pre-write", {
      tool_name: "Edit",
      tool_input: {
        file_path: "db.ts",
        new_string: 'const url = "postgresql://admin:s3cr3t@db:5432/app";',
      },
    });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("Connection String");
  });
});
