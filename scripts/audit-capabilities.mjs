#!/usr/bin/env node
import { execSync } from "node:child_process";
import chalk from "chalk";

console.log(chalk.cyan.bold("\n🔍 SYMB SYSTEM CAPABILITIES & SOLVER AUDIT\n"));

const checks = [
  {
    name: "Node.js Runtime",
    check: () => {
      const v = process.version;
      const major = parseInt(v.replace("v", "").split(".")[0], 10);
      return { ok: major >= 18, msg: `${v} (Required >= 18.0.0)` };
    }
  },
  {
    name: "Python 3 Runtime",
    check: () => {
      try {
        const out = execSync("python --version", { encoding: "utf-8" }).trim();
        return { ok: true, msg: out };
      } catch {
        return { ok: false, msg: "Python not found in PATH" };
      }
    }
  },
  {
    name: "Z3 SMT Theorem Prover",
    check: () => {
      try {
        const out = execSync("python -c \"import z3; print(z3.get_version_string())\"", { encoding: "utf-8" }).trim();
        return { ok: true, msg: `Z3 Version ${out}` };
      } catch {
        return { ok: false, msg: "z3-solver package not installed" };
      }
    }
  },
  {
    name: "angr Symbolic Execution Engine",
    check: () => {
      try {
        const out = execSync("python -c \"import angr; print(angr.__version__)\"", { encoding: "utf-8" }).trim();
        return { ok: true, msg: `angr Version ${out}` };
      } catch {
        return { ok: false, msg: "angr package not installed" };
      }
    }
  },
  {
    name: "Unicorn CPU Emulator",
    check: () => {
      try {
        const out = execSync("python -c \"import unicorn; print(unicorn.__version__)\"", { encoding: "utf-8" }).trim();
        return { ok: true, msg: `unicorn Version ${out}` };
      } catch {
        return { ok: false, msg: "unicorn package not installed" };
      }
    }
  },
  {
    name: "Capstone Disassembly Framework",
    check: () => {
      try {
        const out = execSync("python -c \"import capstone; print(capstone.__version__)\"", { encoding: "utf-8" }).trim();
        return { ok: true, msg: `capstone Version ${out}` };
      } catch {
        return { ok: false, msg: "capstone package not installed" };
      }
    }
  }
];

let allPassed = true;

for (const c of checks) {
  try {
    const res = c.check();
    if (res.ok) {
      console.log(`  ${chalk.green("✔")} ${chalk.bold(c.name)}: ${chalk.green(res.msg)}`);
    } else {
      allPassed = false;
      console.log(`  ${chalk.red("✖")} ${chalk.bold(c.name)}: ${chalk.red(res.msg)}`);
    }
  } catch (err) {
    allPassed = false;
    console.log(`  ${chalk.red("✖")} ${chalk.bold(c.name)}: ${chalk.red(err.message)}`);
  }
}

console.log("\n" + "─".repeat(50));
if (allPassed) {
  console.log(chalk.green.bold("★ ALL SYMB SOLVER CAPABILITIES OPERATIONAL & VERIFIED!\n"));
  process.exit(0);
} else {
  console.log(chalk.yellow.bold("⚠ Some native solvers require installation: pip install angr z3-solver unicorn capstone\n"));
  process.exit(1);
}
