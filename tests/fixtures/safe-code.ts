// This file should NOT trigger any secret detection
import { createServer } from "node:http";

const PORT = process.env.PORT ?? 3000;
const API_KEY = process.env.API_KEY; // env var reference, not a hardcoded secret

export function startServer() {
  const server = createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
  });
  server.listen(PORT);
  return server;
}

// Various code patterns that should NOT be flagged
const config = {
  key: "primary",
  token: "access",
  secret: "mode",
  password: "required",
  auth: "enabled",
};

const SKIP_DIRS = new Set(["node_modules", ".git", "dist"]);
const MAX_RETRIES = 3;
const BASE_URL = "https://api.example.com";
