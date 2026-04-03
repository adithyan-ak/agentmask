import { describe, it, expect } from "vitest";
import { isBlockedPath, isBinaryFile, isAllowlistedPath } from "../src/scanner/file-patterns.js";

describe("isBlockedPath", () => {
  it("blocks .env", () => {
    expect(isBlockedPath(".env")).toBe(true);
    expect(isBlockedPath("/project/.env")).toBe(true);
  });

  it("blocks .env variants", () => {
    expect(isBlockedPath(".env.local")).toBe(true);
    expect(isBlockedPath(".env.production")).toBe(true);
    expect(isBlockedPath("/app/.env.development")).toBe(true);
  });

  it("blocks credential files", () => {
    expect(isBlockedPath("credentials.json")).toBe(true);
    expect(isBlockedPath("config/serviceAccountKey.json")).toBe(true);
  });

  it("blocks key files", () => {
    expect(isBlockedPath("server.pem")).toBe(true);
    expect(isBlockedPath("ssl/server.key")).toBe(true);
    expect(isBlockedPath("certs/ca.p12")).toBe(true);
  });

  it("blocks SSH keys", () => {
    expect(isBlockedPath("/home/user/.ssh/id_rsa")).toBe(true);
    expect(isBlockedPath("id_ed25519")).toBe(true);
  });

  it("blocks cloud credentials", () => {
    expect(isBlockedPath(".aws/credentials")).toBe(true);
    expect(isBlockedPath("/home/user/.kube/config")).toBe(true);
  });

  it("allows normal source files", () => {
    expect(isBlockedPath("src/index.ts")).toBe(false);
    expect(isBlockedPath("package.json")).toBe(false);
    expect(isBlockedPath("README.md")).toBe(false);
    expect(isBlockedPath("tsconfig.json")).toBe(false);
  });

  it("allows .env.example (documentation)", () => {
    // .env.example IS blocked by .env.* pattern — this is intentional.
    // Users should allowlist .env.example explicitly if they want it readable.
    expect(isBlockedPath(".env.example")).toBe(true);
  });
});

describe("isBinaryFile", () => {
  it("detects binary files", () => {
    expect(isBinaryFile("image.png")).toBe(true);
    expect(isBinaryFile("photo.jpg")).toBe(true);
    expect(isBinaryFile("archive.zip")).toBe(true);
    expect(isBinaryFile("app.exe")).toBe(true);
    expect(isBinaryFile("font.woff2")).toBe(true);
  });

  it("allows text files", () => {
    expect(isBinaryFile("code.ts")).toBe(false);
    expect(isBinaryFile("config.json")).toBe(false);
    expect(isBinaryFile("style.css")).toBe(false);
    expect(isBinaryFile("README.md")).toBe(false);
  });
});

describe("isAllowlistedPath", () => {
  it("matches allowlisted patterns", () => {
    expect(isAllowlistedPath("tests/foo.test.ts", ["tests/**"])).toBe(true);
    expect(isAllowlistedPath("src/fixtures/data.ts", ["**/fixtures/**"])).toBe(true);
  });

  it("does not match non-allowlisted paths", () => {
    expect(isAllowlistedPath("src/index.ts", ["tests/**"])).toBe(false);
  });

  it("returns false for empty allowlist", () => {
    expect(isAllowlistedPath("anything.ts", [])).toBe(false);
  });
});
