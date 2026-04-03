import { describe, it, expect } from "vitest";
import { shannonEntropy, isLikelySecret } from "../src/scanner/entropy.js";

describe("shannonEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for single repeated char", () => {
    expect(shannonEntropy("aaaaaaa")).toBe(0);
  });

  it("returns low entropy for simple words", () => {
    expect(shannonEntropy("true")).toBeLessThanOrEqual(2.0);
    expect(shannonEntropy("false")).toBeLessThan(2.5);
  });

  it("returns moderate entropy for common words", () => {
    expect(shannonEntropy("development")).toBeGreaterThan(2.5);
    expect(shannonEntropy("development")).toBeLessThan(4.0);
  });

  it("returns high entropy for random-looking strings", () => {
    expect(shannonEntropy("a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5")).toBeGreaterThan(3.5);
    expect(shannonEntropy("xK9mP2nQ4rS6tU8vW0yA1bC3dE5fG7hI")).toBeGreaterThan(4.0);
  });
});

describe("isLikelySecret", () => {
  it("returns false for booleans", () => {
    expect(isLikelySecret("true")).toBe(false);
    expect(isLikelySecret("false")).toBe(false);
  });

  it("returns false for numbers", () => {
    expect(isLikelySecret("3000")).toBe(false);
    expect(isLikelySecret("8080")).toBe(false);
  });

  it("returns false for common config values", () => {
    expect(isLikelySecret("development")).toBe(false);
    expect(isLikelySecret("production")).toBe(false);
    expect(isLikelySecret("localhost")).toBe(false);
  });

  it("returns false for short strings", () => {
    expect(isLikelySecret("abc")).toBe(false);
    expect(isLikelySecret("test")).toBe(false);
  });

  it("returns true for high-entropy strings with secret key names", () => {
    expect(isLikelySecret("sk_live_FAKEFAKEFAKEFAKEFAKEFAKE", "API_KEY")).toBe(true);
    expect(isLikelySecret("a8f3b2c1d4e5f6a7b8c9", "SECRET_TOKEN")).toBe(true);
  });

  it("returns false for simple URLs", () => {
    expect(isLikelySecret("https://api.example.com")).toBe(false);
    expect(isLikelySecret("http://localhost:3000")).toBe(false);
  });
});
