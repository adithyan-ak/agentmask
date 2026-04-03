import { describe, it, expect } from "vitest";
import { truncateSecret } from "../src/scanner/rules.js";
import { scanContent } from "../src/scanner/scanner.js";
import { redactContent } from "../src/scanner/redact.js";
import { ALL_RULES } from "../src/scanner/rules.js";

describe("Security: agentmask never leaks full secrets", () => {
  const REAL_LOOKING_SECRETS = [
    { name: "AWS key", value: "AKIAIOSFODNN7EXAMPLE" },
    { name: "GitHub PAT", value: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234" },
    { name: "Stripe key", value: "sk_live_FAKEFAKEFAKEFAKEFAKEFAKE" },
    {
      name: "Connection string",
      value: "postgresql://admin:s3cr3t@db.example.com:5432/myapp",
    },
    { name: "JWT", value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" },
  ];

  it("truncateSecret never shows more than 8 chars of the original", () => {
    for (const { name, value } of REAL_LOOKING_SECRETS) {
      const truncated = truncateSecret(value);
      // The truncated version should not contain a substring of length > 8
      // from the middle of the original
      const middle = value.slice(4, -4);
      expect(
        truncated.includes(middle),
        `${name}: truncated output leaked middle of secret`,
      ).toBe(false);
    }
  });

  it("scanContent finding.match never contains full secret", () => {
    for (const { name, value } of REAL_LOOKING_SECRETS) {
      const findings = scanContent(`key = "${value}"`, "test.ts", ALL_RULES);
      for (const f of findings) {
        expect(
          f.match.includes(value),
          `${name}: finding.match leaked full secret`,
        ).toBe(false);
        // match should be <= 12 chars (4...4 + ellipsis)
        expect(f.match.length).toBeLessThanOrEqual(12);
      }
    }
  });

  it("redactContent removes all detected secrets from .env output", () => {
    const envContent = [
      "DATABASE_URL=postgresql://admin:s3cr3t@db.example.com:5432/myapp",
      "API_KEY=sk_live_FAKEFAKEFAKEFAKEFAKEFAKE",
      "DEBUG=true",
    ].join("\n");

    const result = redactContent(envContent, ".env");

    // Must not contain the actual password
    expect(result.content).not.toContain("s3cr3t");
    // Must not contain the actual API key
    expect(result.content).not.toContain("sk_live_FAKEFAKEFAKEFAKEFAKEFAKE");
    // Safe values should remain
    expect(result.content).toContain("DEBUG=true");
  });

  it("redactContent removes secrets from source files", () => {
    const code = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const result = redactContent(code, "config.ts");

    expect(result.content).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(result.content).toContain("[REDACTED:");
  });

  it("connection string redaction preserves host but removes credentials", () => {
    const envLine = "DB=postgresql://admin:hunter2@db.prod.example.com:5432/app";
    const result = redactContent(envLine, ".env");

    expect(result.content).not.toContain("admin");
    expect(result.content).not.toContain("hunter2");
    expect(result.content).toContain("db.prod.example.com:5432/app");
  });
});
