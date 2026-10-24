#!/usr/bin/env node
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import chalk from "chalk";
import { runBranchSolver } from "../dist/core/solver.js";

console.log(chalk.cyan.bold("\n🎯 SYMB SMT BRANCH REACHABILITY SOLVER VERIFICATION\n"));

const targets = [
  {
    name: "CTF Challenge - ais3_crackme",
    path: resolve("examples/02_smt_crackme/ais3_crackme"),
    target_addr: "0x400602",
    avoid_addrs: ["0x400609"]
  }
];

let allPassed = true;

for (const t of targets) {
  process.stdout.write(`  Solving path for: ${chalk.bold(t.name)}... `);
  if (!existsSync(t.path)) {
    console.log(chalk.red("SKIPPED (File not found)"));
    allPassed = false;
    continue;
  }

  try {
    const res = await runBranchSolver(t.path, t.target_addr, t.avoid_addrs);
    if (res && res.normalized_result?.satisfiable) {
      console.log(chalk.green(`PASSED ✔ (Status: ${res.normalized_result.status}, Converged in ${res.execution_time_ms}ms)`));
      if (res.normalized_result.concrete_input_ascii) {
        console.log(chalk.gray(`     Recovered solution: "${res.normalized_result.concrete_input_ascii.slice(0, 30)}..."`));
      }
    } else {
      console.log(chalk.red(`FAILED ✖ (${res?.normalized_result?.status})`));
      allPassed = false;
    }
  } catch (err) {
    console.log(chalk.red(`FAILED ✖ (${err.message})`));
    allPassed = false;
  }
}

console.log("\n" + "─".repeat(50));
if (allPassed) {
  console.log(chalk.green.bold("★ SMT BRANCH REACHABILITY ENGINE VERIFIED!\n"));
  process.exit(0);
} else {
  console.log(chalk.red.bold("✖ Branch solver verification errors encountered\n"));
  process.exit(1);
}
