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

// A Stripe key that gitleaks reliably detects
const TEST_SECRET = "sk_live_51OdEIJ2CtHluikFZ4aNJk8Q";

function run(cmd: string, cwd = TEST_DIR): string {
  return execSync(cmd, { cwd, encoding: "utf-8", timeout: 15_000 });
}

function runMaybe(cmd: string, cwd = TEST_DIR): { stdout: string; stderr: string; code: number } {
  try {
    const stdout = execSync(cmd, { cwd, encoding: "utf-8", timeout: 15_000, stdio: ["pipe", "pipe", "pipe"] });
    return { stdout, stderr: "", code: 0 };
  } catch (err: any) {
    return { stdout: err.stdout ?? "", stderr: err.stderr ?? "", code: err.status ?? 1 };
  }
}

describe("Integration: agentmask init + scan", () => {
  beforeAll(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(TEST_DIR, { recursive: true });

    writeFileSync(
      join(TEST_DIR, ".env"),
      [
        `STRIPE_KEY=${TEST_SECRET}`,
        "DEBUG=true",
        "PORT=3000",
      ].join("\n"),
    );

    writeFileSync(
      join(TEST_DIR, "app.ts"),
      "const port = process.env.PORT;\napp.listen(port);\n",
    );

    writeFileSync(
      join(TEST_DIR, "leaky.ts"),
      `const stripe = "${TEST_SECRET}";\n`,
    );
  });

  afterAll(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("agentmask init creates all required files", () => {
    run(`node ${CLI} init`);

    expect(existsSync(join(TEST_DIR, ".claude", "settings.local.json"))).toBe(true);
    expect(existsSync(join(TEST_DIR, ".claude", "rules", "agentmask.md"))).toBe(true);
    expect(existsSync(join(TEST_DIR, ".mcp.json"))).toBe(true);
    expect(existsSync(join(TEST_DIR, ".claude", "agentmask-blocklist.json"))).toBe(true);
  });

  it("agentmask init is idempotent", () => {
    run(`node ${CLI} init`);
    run(`node ${CLI} init`);

    const settings = JSON.parse(
      readFileSync(join(TEST_DIR, ".claude", "settings.local.json"), "utf-8"),
    );
    expect(settings.hooks.PreToolUse).toHaveLength(3);
    expect(settings.hooks.PostToolUse).toHaveLength(1);
  });

  it("init scan detects secrets and builds blocklist", () => {
    const blocklist = JSON.parse(
      readFileSync(join(TEST_DIR, ".claude", "agentmask-blocklist.json"), "utf-8"),
    );
    // leaky.ts should be in blocklist (has Stripe key)
    expect(blocklist.files["leaky.ts"]).toBeDefined();
  });

  it("scan detects secrets in leaky file", () => {
    const result = runMaybe(`node ${CLI} scan leaky.ts`);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain("stripe");
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
    expect(json.summary.secretsFound).toBeGreaterThan(0);
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
    expect(
      existsSync(join(TEST_DIR, ".claude", "agentmask-blocklist.json")),
    ).toBe(false);
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
        { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"], timeout: 10_000 },
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

  it("Scenario A: Read .env is blocked with redirect guidance", () => {
    const result = hookCall("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: ".env" },
      cwd: "/tmp",
    });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("mcp__agentmask__safe_read");
  });

  it("Scenario B: Read normal file passes through", () => {
    const result = hookCall("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: "src/app.ts" },
      cwd: "/tmp",
    });
    expect(result.code).toBe(0);
  });

  it("Scenario C: Post-scan detects secret in output and warns", () => {
    const result = hookCall("post-scan", {
      tool_name: "Read",
      tool_input: { file_path: "utils.ts" },
      tool_response: `const key = "${TEST_SECRET}";`,
    });
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("WARNING");
    expect(result.stdout).toContain("Stripe");
  });

  it("Scenario D: Write with hardcoded secret is blocked", () => {
    const result = hookCall("pre-write", {
      tool_name: "Write",
      tool_input: {
        file_path: "config.ts",
        content: `const stripe = new Stripe("${TEST_SECRET}");`,
      },
    });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("BLOCKED");
    expect(result.stderr).toContain("environment variable");
  });

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

  it("Scenario F: Write to .env file is allowed", () => {
    const result = hookCall("pre-write", {
      tool_name: "Write",
      tool_input: {
        file_path: ".env",
        content: `STRIPE_KEY=${TEST_SECRET}`,
      },
    });
    expect(result.code).toBe(0);
  });

  it("Scenario G: Bash cat .env is blocked", () => {
    const result = hookCall("pre-bash", {
      tool_name: "Bash",
      tool_input: { command: "cat .env" },
    });
    expect(result.code).toBe(2);
  });

  it("Scenario H: Normal bash commands pass through", () => {
    const commands = ["npm test", "git status", "ls -la", "node script.js"];
    for (const cmd of commands) {
      const result = hookCall("pre-bash", {
        tool_name: "Bash",
        tool_input: { command: cmd },
      });
      expect(result.code, `Should allow: ${cmd}`).toBe(0);
    }
  });

  it("Scenario I: Graceful degradation on malformed input", () => {
    const result = hookCall("pre-read", {});
    expect(result.code).toBe(0);
  });
});
