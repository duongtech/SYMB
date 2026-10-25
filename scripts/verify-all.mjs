#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import chalk from "chalk";

console.log(chalk.magenta.bold("\n" + "═".repeat(60)));
console.log(chalk.magenta.bold("   🚀 SYMB COMPREHENSIVE VERIFICATION SUITE"));
console.log(chalk.magenta.bold("═".repeat(60) + "\n"));

const suites = [
  { name: "System Capabilities & Solver Audit", script: "scripts/audit-capabilities.mjs" },
  { name: "MCP Tool Contracts & Zod Schemas", script: "scripts/verify-mcp-contracts.mjs" },
  { name: "Native High-Speed EXE Decompiler & Layout Engine", script: "scripts/verify-decompiler.mjs" },
  { name: "Z3 SMT Mathematical Logic Engine", script: "scripts/verify-z3-solver.mjs" },
  { name: "OLLVM Control-Flow Unflattening (PE & ELF)", script: "scripts/verify-ollvm-unflatten.mjs" },
  { name: "SMT Branch Reachability Solver", script: "scripts/verify-smt-branch.mjs" },
  { name: "Large Media & Binary Buffer Optimizer Engine", script: "scripts/verify-media-optimizer.mjs" },
  { name: "Active Binary Intervention & Weaponized RE Engine", script: "scripts/verify-binary-intervention.mjs" }
];

let failedCount = 0;
const startTime = Date.now();

for (const s of suites) {
  console.log(chalk.yellow.bold(`\n▶ [SUITE] ${s.name}`));
  const res = spawnSync("node", [s.script], { stdio: "inherit" });
  if (res.status !== 0) {
    failedCount++;
  }
}

const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

console.log(chalk.magenta.bold("\n" + "═".repeat(60)));
if (failedCount === 0) {
  console.log(chalk.green.bold(`✨ ALL ${suites.length} VERIFICATION SUITES PASSED CLEANLY IN ${elapsed}s! ✨`));
  console.log(chalk.green.bold("   SYMB is production-ready for autonomous AI Agent deployment."));
} else {
  console.log(chalk.red.bold(`❌ ${failedCount} SUITE(S) FAILED OUT OF ${suites.length}`));
}
console.log(chalk.magenta.bold("═".repeat(60) + "\n"));

process.exit(failedCount === 0 ? 0 : 1);
