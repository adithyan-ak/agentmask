import { describe, it, expect } from "vitest";
import { execSync } from "node:child_process";
import { resolve } from "node:path";

const CLI = resolve("dist/cli.js");

// A Stripe key that gitleaks reliably detects
const TEST_SECRET = "sk_live_51OdEIJ2CtHluikFZ4aNJk8Q";

function runHook(
  type: string,
  input: Record<string, unknown>,
): { exitCode: number; stdout: string; stderr: string } {
  try {
    const stdout = execSync(
      `echo '${JSON.stringify(input)}' | node ${CLI} hook ${type}`,
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    return { exitCode: 0, stdout, stderr: "" };
  } catch (err: any) {
    return {
      exitCode: err.status ?? 1,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? "",
    };
  }
}

describe("pre-read hook", () => {
  it("blocks .env", () => {
    const result = runHook("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: ".env" },
      cwd: "/tmp",
    });
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("BLOCKED");
    expect(result.stderr).toContain("mcp__agentmask__safe_read");
  });

  it("blocks .env.local", () => {
    const result = runHook("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: ".env.local" },
      cwd: "/tmp",
    });
    expect(result.exitCode).toBe(2);
  });

  it("blocks credentials.json", () => {
    const result = runHook("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: "config/credentials.json" },
      cwd: "/tmp",
    });
    expect(result.exitCode).toBe(2);
  });

  it("allows normal source files", () => {
    const result = runHook("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: "src/index.ts" },
      cwd: "/tmp",
    });
    expect(result.exitCode).toBe(0);
  });

  it("allows package.json", () => {
    const result = runHook("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: "package.json" },
      cwd: "/tmp",
    });
    expect(result.exitCode).toBe(0);
  });
});

describe("pre-bash hook", () => {
  it("blocks cat .env", () => {
    const result = runHook("pre-bash", {
      tool_name: "Bash",
      tool_input: { command: "cat .env" },
    });
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("BLOCKED");
  });

  it("blocks printenv", () => {
    const result = runHook("pre-bash", {
      tool_name: "Bash",
      tool_input: { command: "printenv" },
    });
    expect(result.exitCode).toBe(2);
  });

  it("allows npm install", () => {
    const result = runHook("pre-bash", {
      tool_name: "Bash",
      tool_input: { command: "npm install express" },
    });
    expect(result.exitCode).toBe(0);
  });

  it("allows normal commands", () => {
    const commands = ["npm test", "git status", "ls -la", "node script.js"];
    for (const cmd of commands) {
      const result = runHook("pre-bash", {
        tool_name: "Bash",
        tool_input: { command: cmd },
      });
      expect(result.exitCode, `Should allow: ${cmd}`).toBe(0);
    }
  });
});

describe("pre-write hook", () => {
  it("blocks writing hardcoded Stripe key", () => {
    const result = runHook("pre-write", {
      tool_name: "Write",
      tool_input: {
        file_path: "payment.ts",
        content: `const stripe = new Stripe("${TEST_SECRET}");`,
      },
    });
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("BLOCKED");
    expect(result.stderr).toContain("Stripe");
  });

  it("allows clean code", () => {
    const result = runHook("pre-write", {
      tool_name: "Write",
      tool_input: {
        file_path: "config.ts",
        content: "const key = process.env.API_KEY;",
      },
    });
    expect(result.exitCode).toBe(0);
  });

  it("allows writing to .env files (they're expected to have secrets)", () => {
    const result = runHook("pre-write", {
      tool_name: "Write",
      tool_input: {
        file_path: ".env",
        content: `STRIPE_KEY=${TEST_SECRET}`,
      },
    });
    expect(result.exitCode).toBe(0);
  });
});

describe("post-scan hook", () => {
  it("warns about secrets in tool output", () => {
    const result = runHook("post-scan", {
      tool_name: "Read",
      tool_input: { file_path: "utils.ts" },
      tool_response: `const key = "${TEST_SECRET}";`,
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("WARNING");
    expect(result.stdout).toContain("Stripe");
  });

  it("passes clean output silently", () => {
    const result = runHook("post-scan", {
      tool_name: "Read",
      tool_input: { file_path: "index.ts" },
      tool_response: "const x = 42;",
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("");
  });
});

describe("graceful degradation", () => {
  it("handles malformed input without blocking", () => {
    const result = runHook("pre-read", { invalid: "data" });
    expect(result.exitCode).toBe(0);
  });

  it("handles empty stdin without blocking", () => {
    const result = runHook("pre-read", {});
    expect(result.exitCode).toBe(0);
  });
});
