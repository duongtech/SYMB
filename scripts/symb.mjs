#!/usr/bin/env node

import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);

// If called with arguments (e.g. 'setup' or 'solve'), run CLI
if (args.length > 0 && args[0] !== "--stdio") {
  const cliScript = path.join(__dirname, "..", "dist", "cli.js");
  const child = spawn("node", [cliScript, ...args], { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code || 0));
} else {
  // Default: start MCP server on stdio
  const serverScript = path.join(__dirname, "..", "dist", "index.js");
  const child = spawn("node", [serverScript], { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code || 0));
}
