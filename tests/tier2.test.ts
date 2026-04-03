import { describe, it, expect } from "vitest";
import { scanContent } from "../src/scanner/scanner.js";
import { ALL_RULES, isStopword } from "../src/scanner/rules.js";

describe("Tier 2 Generic Rules", () => {
  it("detects api_key assignment with high entropy value", () => {
    const findings = scanContent(
      'api_key = "xK9mP2nQ4rS6tU8vW0yA1bC3dE5fG7hI"',
      "config.py",
      ALL_RULES,
    );
    expect(findings.some((f) => f.ruleId === "generic-secret")).toBe(true);
  });

  it("detects auth_token in JSON", () => {
    const findings = scanContent(
      '  "auth_token": "a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5"',
      "config.json",
      ALL_RULES,
    );
    expect(findings.some((f) => f.ruleId === "generic-secret")).toBe(true);
  });

  it("detects client_secret assignment", () => {
    const findings = scanContent(
      'client_secret = "a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5"',
      "config.ts",
      ALL_RULES,
    );
    expect(findings.some((f) => f.ruleId === "generic-secret")).toBe(true);
  });

  it("detects password assignment", () => {
    const findings = scanContent(
      'password = "Xk9$mP2nQ4!rS6tU8v"',
      "config.ts",
      ALL_RULES,
    );
    expect(findings.some((f) => f.ruleId === "generic-secret")).toBe(true);
  });

  it("does NOT flag low-entropy values", () => {
    const findings = scanContent(
      'api_key = "primary_key"',
      "config.ts",
      ALL_RULES,
    );
    expect(findings.some((f) => f.ruleId === "generic-secret")).toBe(false);
  });

  it("does NOT flag env var references", () => {
    const findings = scanContent(
      "const key = process.env.API_KEY",
      "config.ts",
      ALL_RULES,
    );
    expect(findings.some((f) => f.ruleId === "generic-secret")).toBe(false);
  });

  it("does NOT flag common config values", () => {
    const lines = [
      'const token = "access"',
      'const secret = "mode"',
    ];
    for (const line of lines) {
      const findings = scanContent(line, "config.ts", ALL_RULES);
      expect(
        findings.some((f) => f.ruleId === "generic-secret"),
        `False positive on: ${line}`,
      ).toBe(false);
    }
  });
});

describe("isStopword", () => {
  it("catches common programming terms", () => {
    expect(isStopword("true")).toBe(true);
    expect(isStopword("false")).toBe(true);
    expect(isStopword("null")).toBe(true);
    expect(isStopword("development")).toBe(true);
    expect(isStopword("production")).toBe(true);
  });

  it("catches repeated characters", () => {
    expect(isStopword("aaaaaaaaaa")).toBe(true);
    expect(isStopword("0000000000")).toBe(true);
  });

  it("does not flag real secrets", () => {
    expect(isStopword("a8f3b2c1d4e5")).toBe(false);
    expect(isStopword("xK9mP2nQ4rS6tU8v")).toBe(false);
  });
});

describe("Edge cases", () => {
  it("skips very long lines (minified code)", () => {
    const longLine = "a".repeat(15_000);
    const findings = scanContent(longLine, "bundle.min.js", ALL_RULES);
    expect(findings).toHaveLength(0);
  });

  it("handles empty content", () => {
    const findings = scanContent("", "empty.ts", ALL_RULES);
    expect(findings).toHaveLength(0);
  });

  it("handles content with only newlines", () => {
    const findings = scanContent("\n\n\n", "blank.ts", ALL_RULES);
    expect(findings).toHaveLength(0);
  });

  it("deduplicates findings on same line", () => {
    const findings = scanContent(
      'secret_key = "a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5"',
      "test.ts",
      ALL_RULES,
    );
    const genericFindings = findings.filter((f) => f.ruleId === "generic-secret");
    expect(genericFindings.length).toBeLessThanOrEqual(1);
  });
});
