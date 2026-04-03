import { describe, it, expect } from "vitest";
import {
  redactConnectionString,
  redactEnvLine,
  redactContent,
} from "../src/scanner/redact.js";

describe("redactConnectionString", () => {
  it("redacts PostgreSQL credentials", () => {
    expect(
      redactConnectionString("postgresql://admin:s3cr3t@db.example.com:5432/myapp"),
    ).toBe("postgresql://****:****@db.example.com:5432/myapp");
  });

  it("redacts MongoDB+SRV credentials", () => {
    expect(
      redactConnectionString("mongodb+srv://user:hunter2@cluster.mongodb.net/prod"),
    ).toBe("mongodb+srv://****:****@cluster.mongodb.net/prod");
  });

  it("redacts Redis credentials", () => {
    expect(
      redactConnectionString("redis://default:mypassword@redis.example.com:6379"),
    ).toBe("redis://****:****@redis.example.com:6379");
  });

  it("falls back for unrecognized format", () => {
    expect(redactConnectionString("ftp://something")).toBe(
      "[REDACTED:connection_string]",
    );
  });
});

describe("redactEnvLine", () => {
  it("keeps comments unchanged", () => {
    expect(redactEnvLine("# This is a comment")).toEqual({
      line: "# This is a comment",
      redacted: false,
    });
  });

  it("keeps blank lines unchanged", () => {
    expect(redactEnvLine("")).toEqual({ line: "", redacted: false });
  });

  it("keeps non-secret values", () => {
    expect(redactEnvLine("DEBUG=true")).toEqual({
      line: "DEBUG=true",
      redacted: false,
    });
    expect(redactEnvLine("PORT=3000")).toEqual({
      line: "PORT=3000",
      redacted: false,
    });
    expect(redactEnvLine("NODE_ENV=development")).toEqual({
      line: "NODE_ENV=development",
      redacted: false,
    });
  });

  it("redacts connection strings with format preservation", () => {
    const result = redactEnvLine(
      "DATABASE_URL=postgresql://admin:s3cr3t@db.example.com:5432/myapp",
    );
    expect(result.redacted).toBe(true);
    expect(result.line).toBe(
      "DATABASE_URL=postgresql://****:****@db.example.com:5432/myapp",
    );
  });

  it("redacts high-entropy API keys", () => {
    const result = redactEnvLine(
      "API_KEY=sk_live_FAKEFAKEFAKEFAKEFAKEFAKE",
    );
    expect(result.redacted).toBe(true);
    expect(result.line).toMatch(/API_KEY=\[REDACTED:\d+_chars\]/);
  });

  it("handles quoted values", () => {
    const result = redactEnvLine(
      'SECRET_TOKEN="a8f3b2c1d4e5f6a7b8c9d0e1"',
    );
    expect(result.redacted).toBe(true);
  });

  it("handles export prefix", () => {
    const result = redactEnvLine(
      "export API_KEY=sk_live_FAKEFAKEFAKEFAKEFAKEFAKE",
    );
    expect(result.redacted).toBe(true);
  });
});

describe("redactContent", () => {
  it("redacts secrets in .env files", () => {
    const content = [
      "# Config",
      "DATABASE_URL=postgresql://admin:s3cr3t@db.example.com:5432/myapp",
      "DEBUG=true",
      "PORT=3000",
    ].join("\n");

    const result = redactContent(content, ".env");
    expect(result.redactionCount).toBe(1);
    expect(result.content).toContain("****:****@db.example.com");
    expect(result.content).toContain("DEBUG=true");
    expect(result.content).toContain("PORT=3000");
  });

  it("redacts secrets in source files", () => {
    const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const result = redactContent(content, "config.ts");
    expect(result.redactionCount).toBe(1);
    expect(result.content).toContain("[REDACTED:aws-access-key]");
  });
});
