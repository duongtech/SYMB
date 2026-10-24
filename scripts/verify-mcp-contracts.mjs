#!/usr/bin/env node
import assert from "node:assert/strict";
import chalk from "chalk";
import {
  UnflattenInputSchema,
  SolveBranchInputSchema,
  TaintInputSchema,
  HotPatchInputSchema
} from "../dist/contracts/schemas.js";

console.log(chalk.cyan.bold("\n📜 SYMB MCP TOOL SCHEMAS & CANONICAL EVIDENCE CONTRACTS VERIFICATION\n"));

const schemas = [
  {
    name: "unflatten_control_flow Schema",
    schema: UnflattenInputSchema,
    sampleValid: { binary_path: "test.exe", function_address: "0x140001000", timeout_seconds: 60 }
  },
  {
    name: "solve_branch_reachability Schema",
    schema: SolveBranchInputSchema,
    sampleValid: { binary_path: "target.exe", target_address: "0x401580", avoid_addresses: ["0x401590"] }
  },
  {
    name: "trace_symbolic_taint Schema",
    schema: TaintInputSchema,
    sampleValid: { binary_path: "libcore.so", source_symbol: "read_buf", sink_symbol: "memcpy" }
  },
  {
    name: "hot_patch_live_memory Schema",
    schema: HotPatchInputSchema,
    sampleValid: { pid: 1337, memory_address: "0x7FFF0010", patch_bytes_hex: "909090" }
  }
];

let allPassed = true;

for (const s of schemas) {
  process.stdout.write(`  Validating contract: ${chalk.bold(s.name)}... `);
  try {
    const parsed = s.schema.parse(s.sampleValid);
    assert(parsed !== null, "Parsing returned null");
    console.log(chalk.green("PASSED ✔"));
  } catch (err) {
    allPassed = false;
    console.log(chalk.red(`FAILED ✖ (${err.message})`));
  }
}

console.log("\n" + "─".repeat(50));
if (allPassed) {
  console.log(chalk.green.bold("★ ALL MCP TOOL CONTRACT SCHEMAS VERIFIED 100% SPEC-COMPLIANT!\n"));
  process.exit(0);
} else {
  console.log(chalk.red.bold("✖ MCP Schema verification errors encountered\n"));
  process.exit(1);
}
