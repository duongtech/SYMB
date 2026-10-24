#!/usr/bin/env node
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import chalk from "chalk";
import { runUnflatten } from "../dist/core/unflatten.js";

console.log(chalk.cyan.bold("\n🌪 SYMB OLLVM CONTROL-FLOW UNFLATTENING VERIFICATION\n"));

const targets = [
  {
    name: "Windows x64 PE - OLLVM Flattened (CFF_win64.exe)",
    path: resolve("examples/01_ollvm_cff/CFF_win64.exe"),
    address: "0x140001000"
  },
  {
    name: "Linux x64 ELF - OLLVM Switch Flattened (fauxware_fla)",
    path: resolve("examples/01_ollvm_cff/fauxware_fla"),
    address: "0x400720"
  }
];

let allPassed = true;

for (const t of targets) {
  process.stdout.write(`  Deobfuscating: ${chalk.bold(t.name)}... `);
  if (!existsSync(t.path)) {
    console.log(chalk.red("SKIPPED (File not found)"));
    allPassed = false;
    continue;
  }

  try {
    const res = await runUnflatten(t.path, t.address);
    const count = res?.normalized_result?.recovered_blocks_count ?? 0;
    if (res && count > 0) {
      console.log(chalk.green(`PASSED ✔ (${count} blocks recovered in ${res.execution_time_ms}ms)`));
    } else {
      console.log(chalk.red("FAILED ✖ (0 blocks recovered)"));
      allPassed = false;
    }
  } catch (err) {
    console.log(chalk.red(`FAILED ✖ (${err.message})`));
    allPassed = false;
  }
}

console.log("\n" + "─".repeat(50));
if (allPassed) {
  console.log(chalk.green.bold("★ OLLVM CFF DEOBFUSCATION ENGINE VERIFIED ACROSS PE & ELF!\n"));
  process.exit(0);
} else {
  console.log(chalk.red.bold("✖ Unflattening verification errors encountered\n"));
  process.exit(1);
}
