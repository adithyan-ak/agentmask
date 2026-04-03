import { describe, it, expect } from "vitest";
import { TIER1_RULES } from "../src/scanner/rules.js";
import { scanContent } from "../src/scanner/scanner.js";

describe("Tier 1 Rules", () => {
  // === AWS ===
  describe("aws-access-key", () => {
    it("detects AWS access key", () => {
      const findings = scanContent('AWS_KEY="AKIAIOSFODNN7EXAMPLE"', "test.ts");
      expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(true);
    });
    it("does not match non-AWS prefix", () => {
      const findings = scanContent('KEY="XKIAIOSFODNN7EXAMPLE"', "test.ts");
      expect(findings.some((f) => f.ruleId === "aws-access-key")).toBe(false);
    });
  });

  // === GitHub ===
  describe("github-pat", () => {
    it("detects GitHub PAT", () => {
      const findings = scanContent(
        'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "github-pat")).toBe(true);
    });
    it("ignores short ghp_ prefix", () => {
      const findings = scanContent('x = "ghp_short"', "test.ts");
      expect(findings.some((f) => f.ruleId === "github-pat")).toBe(false);
    });
  });

  describe("github-fine-grained-pat", () => {
    it("detects fine-grained PAT", () => {
      const findings = scanContent(
        'token = "github_pat_ABCDEFGHIJKLMNOPQRSTUVa"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "github-fine-grained-pat")).toBe(true);
    });
  });

  // === Stripe ===
  describe("stripe-live-secret", () => {
    it("detects Stripe live secret key", () => {
      const findings = scanContent(
        'const key = "sk_live_FAKEFAKEFAKEFAKEFAKEFAKE"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "stripe-live-secret")).toBe(true);
    });
    it("does not match Stripe test key", () => {
      const findings = scanContent(
        'const key = "sk_test_FAKEFAKEFAKEFAKEFAKEFAKE"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "stripe-live-secret")).toBe(false);
    });
  });

  // === GCP ===
  describe("gcp-api-key", () => {
    it("detects GCP API key", () => {
      const findings = scanContent(
        'apiKey = "AIzaSyDFAKEKEYabcdefghijklmnopqrst12345"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "gcp-api-key")).toBe(true);
    });
  });

  // === Slack ===
  describe("slack-webhook", () => {
    it("detects Slack webhook URL", () => {
      const findings = scanContent(
        "https://hooks.slack.com/services/TFAKEFAKE/BFAKEFAKE/FAKEFAKEFAKEFAKEFAKEFAKE",
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "slack-webhook")).toBe(true);
    });
  });

  // === SendGrid ===
  describe("sendgrid-api-key", () => {
    it("detects SendGrid API key", () => {
      const findings = scanContent(
        'key = "SG.FAKEFAKEFAKEFAKEFAKEFA.FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEfak"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "sendgrid-api-key")).toBe(true);
    });
  });

  // === Private Key ===
  describe("private-key", () => {
    it("detects PEM private key header", () => {
      const findings = scanContent(
        "-----BEGIN RSA PRIVATE KEY-----",
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "private-key")).toBe(true);
    });
    it("detects EC private key", () => {
      const findings = scanContent(
        "-----BEGIN EC PRIVATE KEY-----",
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "private-key")).toBe(true);
    });
    it("does not match public key", () => {
      const findings = scanContent(
        "-----BEGIN PUBLIC KEY-----",
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "private-key")).toBe(false);
    });
  });

  // === JWT ===
  describe("jwt", () => {
    it("detects JWT token", () => {
      const findings = scanContent(
        'const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "jwt")).toBe(true);
    });
  });

  // === Connection Strings ===
  describe("connection-string", () => {
    it("detects PostgreSQL connection string", () => {
      const findings = scanContent(
        'const url = "postgresql://user:pass@host:5432/db"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "connection-string")).toBe(true);
    });
    it("detects MongoDB connection string", () => {
      const findings = scanContent(
        'const url = "mongodb+srv://admin:s3cret@cluster.mongodb.net/prod"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "connection-string")).toBe(true);
    });
    it("ignores URL without credentials", () => {
      const findings = scanContent(
        'const url = "https://api.example.com/v1"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "connection-string")).toBe(false);
    });
  });

  // === Anthropic ===
  describe("anthropic-api-key", () => {
    it("detects Anthropic API key", () => {
      const key = "sk-ant-" + "a".repeat(95);
      const findings = scanContent(`key = "${key}"`, "test.ts");
      expect(findings.some((f) => f.ruleId === "anthropic-api-key")).toBe(true);
    });
  });

  // === OpenAI ===
  describe("openai-api-key-v2", () => {
    it("detects project-scoped OpenAI key", () => {
      const findings = scanContent(
        'key = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcde"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "openai-api-key-v2")).toBe(true);
    });
  });

  // === npm ===
  describe("npm-token", () => {
    it("detects npm access token", () => {
      const findings = scanContent(
        'NPM_TOKEN="npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"',
        "test.ts",
      );
      expect(findings.some((f) => f.ruleId === "npm-token")).toBe(true);
    });
  });
});

describe("scanContent — no false positives", () => {
  it("safe code triggers no findings", () => {
    const safeCode = `
import { createServer } from "node:http";
const PORT = process.env.PORT ?? 3000;
const API_KEY = process.env.API_KEY;
const config = { key: "primary", token: "access", secret: "mode" };
const MAX_RETRIES = 3;
const BASE_URL = "https://api.example.com";
    `;
    const findings = scanContent(safeCode, "safe.ts");
    expect(findings).toHaveLength(0);
  });

  it("env var references are not secrets", () => {
    const code = `
process.env.DATABASE_URL
process.env.API_KEY
os.environ["SECRET_KEY"]
    `;
    const findings = scanContent(code, "app.py");
    expect(findings).toHaveLength(0);
  });
});
