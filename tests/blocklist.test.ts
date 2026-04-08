import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { execSync } from "node:child_process";
import {
  loadBlocklist,
  saveBlocklist,
  isInBlocklist,
  addToBlocklist,
  removeFromBlocklist,
  getBlocklistPath,
} from "../src/hooks/blocklist.js";

const TEST_DIR = resolve("tests/blocklist-workspace");
const CLI = resolve("dist/cli.js");

// A Stripe key that gitleaks reliably detects
const TEST_SECRET = "sk_live_51OdEIJ2CtHluikFZ4aNJk8Q";

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

describe("Blocklist module", () => {
  beforeEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(join(TEST_DIR, ".agentmask"), { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("loadBlocklist returns empty for nonexistent file", () => {
    const data = loadBlocklist(TEST_DIR);
    expect(data.files).toEqual({});
  });

  it("saveBlocklist + loadBlocklist round-trips", () => {
    const data = {
      files: {
        "src/config.ts": {
          secrets: ["Stripe Access Token"],
          addedAt: "2026-04-03T00:00:00.000Z",
        },
      },
    };
    saveBlocklist(TEST_DIR, data);
    const loaded = loadBlocklist(TEST_DIR);
    expect(loaded.files["src/config.ts"].secrets).toEqual(["Stripe Access Token"]);
  });

  it("addToBlocklist creates entry", () => {
    addToBlocklist("src/db.ts", ["Database Secret"], TEST_DIR);
    const data = loadBlocklist(TEST_DIR);
    expect(data.files["src/db.ts"]).toBeDefined();
  });

  it("addToBlocklist merges secrets for existing entry", () => {
    addToBlocklist("src/config.ts", ["Stripe Token"], TEST_DIR);
    addToBlocklist("src/config.ts", ["GitHub PAT"], TEST_DIR);
    const data = loadBlocklist(TEST_DIR);
    expect(data.files["src/config.ts"].secrets).toEqual(["Stripe Token", "GitHub PAT"]);
  });

  it("isInBlocklist finds entries", () => {
    addToBlocklist("src/config.ts", ["Stripe Token"], TEST_DIR);
    expect(isInBlocklist("src/config.ts", TEST_DIR)).toBeDefined();
    expect(isInBlocklist("src/other.ts", TEST_DIR)).toBeUndefined();
  });

  it("removeFromBlocklist removes entry", () => {
    addToBlocklist("src/config.ts", ["Stripe Token"], TEST_DIR);
    expect(removeFromBlocklist("src/config.ts", TEST_DIR)).toBe(true);
    expect(isInBlocklist("src/config.ts", TEST_DIR)).toBeUndefined();
  });
});

describe("Init scan + blocklist integration", () => {
  beforeEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("init scans repo and builds blocklist from secret-containing files", () => {
    writeFileSync(
      join(TEST_DIR, "config.ts"),
      `const stripe = "${TEST_SECRET}";\n`,
    );
    writeFileSync(
      join(TEST_DIR, "app.ts"),
      "const port = process.env.PORT;\n",
    );

    execSync(`node ${CLI} init`, { cwd: TEST_DIR, encoding: "utf-8", timeout: 15_000 });

    const blocklistPath = getBlocklistPath(TEST_DIR);
    expect(existsSync(blocklistPath)).toBe(true);

    const data = JSON.parse(readFileSync(blocklistPath, "utf-8"));
    expect(data.files["config.ts"]).toBeDefined();
    expect(data.files["app.ts"]).toBeUndefined();
  });

  it("pre-read blocks files found by init scan", () => {
    writeFileSync(
      join(TEST_DIR, "config.ts"),
      `const stripe = "${TEST_SECRET}";\n`,
    );
    execSync(`node ${CLI} init`, { cwd: TEST_DIR, encoding: "utf-8", timeout: 15_000 });

    const result = hookCall("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: "config.ts" },
      cwd: TEST_DIR,
    });
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("BLOCKED");
    expect(result.stderr).toContain("safe_read");
  });

  it("pre-read allows clean files after init scan", () => {
    writeFileSync(
      join(TEST_DIR, "app.ts"),
      "const port = process.env.PORT;\n",
    );
    execSync(`node ${CLI} init`, { cwd: TEST_DIR, encoding: "utf-8", timeout: 15_000 });

    const result = hookCall("pre-read", {
      tool_name: "Read",
      tool_input: { file_path: "app.ts" },
      cwd: TEST_DIR,
    });
    expect(result.code).toBe(0);
  });
});

describe("Post-scan auto-blocklist", () => {
  beforeEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(join(TEST_DIR, ".agentmask"), { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("post-scan adds file to blocklist when secrets are found", () => {
    const result = hookCall("post-scan", {
      tool_name: "Read",
      tool_input: { file_path: "src/utils.ts" },
      tool_response: `const key = "${TEST_SECRET}";`,
      cwd: TEST_DIR,
    });

    expect(result.code).toBe(0);
    expect(result.stdout).toContain("WARNING");
    expect(result.stdout).toContain("added to the blocklist");
  });

  it("post-scan does not touch blocklist for clean output", () => {
    const result = hookCall("post-scan", {
      tool_name: "Read",
      tool_input: { file_path: "src/clean.ts" },
      tool_response: "const x = 42;",
      cwd: TEST_DIR,
    });

    expect(result.code).toBe(0);
    const data = loadBlocklist(TEST_DIR);
    expect(data.files["src/clean.ts"]).toBeUndefined();
  });
});
