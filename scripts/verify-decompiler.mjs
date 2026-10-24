#!/usr/bin/env node
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import chalk from "chalk";
import { runDecompile } from "../dist/core/decompile.js";
import { runInspectLayout } from "../dist/core/layout.js";
import { runCryptoScan } from "../dist/core/crypto.js";

console.log(chalk.cyan.bold("\n⚡ SYMB HIGH-SPEED NATIVE DECOMPILER & EXECUTABLE ENGINE VERIFICATION\n"));

const targetPE = resolve("examples/01_ollvm_cff/CFF_win64.exe");

if (!existsSync(targetPE)) {
  console.log(chalk.red("Test target binary not found"));
  process.exit(1);
}

let allPassed = true;

// 1. Binary Layout & Section Entropy
process.stdout.write(`  [1/3] Inspecting PE Layout & Section Entropy... `);
try {
  const layoutRes = await runInspectLayout(targetPE);
  const layout = layoutRes.normalized_result;
  if (layout.sections_count && layout.sections_count > 0 && layout.architecture) {
    console.log(chalk.green(`PASSED ✔ (${layout.format}, ${layout.architecture}, ${layout.sections_count} sections, Max Entropy: ${layout.max_entropy})`));
  } else {
    console.log(chalk.red("FAILED ✖"));
    allPassed = false;
  }
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

// 2. High-speed Capstone Disassembly & Pseudocode Lifting
process.stdout.write(`  [2/3] Decompiling Native Function to C Pseudocode... `);
try {
  const decRes = await runDecompile(targetPE, "0x4014e0");
  const dec = decRes.normalized_result;
  if (dec.instruction_count > 0 && dec.decompiled_pseudocode.includes("sub_4014e0")) {
    console.log(chalk.green(`PASSED ✔ (${dec.instruction_count} instructions lifted in ${decRes.execution_time_ms}ms)`));
  } else {
    console.log(chalk.red("FAILED ✖ (No instructions lifted)"));
    allPassed = false;
  }
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

// 3. Cryptographic Primitive Scanner
process.stdout.write(`  [3/3] Scanning for Cryptographic Constants & Tables... `);
try {
  const cryptoRes = await runCryptoScan(targetPE);
  const cr = cryptoRes.normalized_result;
  console.log(chalk.green(`PASSED ✔ (Scan completed in ${cryptoRes.execution_time_ms}ms, Primitives: ${cr.total_primitives_found})`));
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

console.log("\n" + "─".repeat(50));
if (allPassed) {
  console.log(chalk.green.bold("★ HIGH-SPEED EXE DECOMPILER & BINARY SCANNER FULLY OPERATIONAL!\n"));
  process.exit(0);
} else {
  console.log(chalk.red.bold("✖ Decompiler verification errors encountered\n"));
  process.exit(1);
}
