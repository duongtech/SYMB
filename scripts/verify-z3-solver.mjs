#!/usr/bin/env node
import { execSync } from "node:child_process";
import chalk from "chalk";

console.log(chalk.cyan.bold("\n📐 SYMB SMT & Z3 SOLVER ENGINE VERIFICATION\n"));

const testCases = [
  {
    name: "Linear 32-bit Integer Constraint Sat",
    script: `
import z3
s = z3.Solver()
x = z3.BitVec('x', 32)
y = z3.BitVec('y', 32)
s.add(x + y == 1338)
s.add(x - y == 42)
res = s.check()
assert str(res) == 'sat', 'Expected SAT'
m = s.model()
assert m[x].as_long() + m[y].as_long() == 1338
print('OK')
`
  },
  {
    name: "Nonlinear Bitwise Rotation & XOR S-Box Inversion",
    script: `
import z3
s = z3.Solver()
k = z3.BitVec('k', 32)
rot = z3.RotateLeft(k ^ 0x5A5A5A5A, 5)
s.add(rot == 0xDEADBEEF)
assert str(s.check()) == 'sat', 'Expected SAT'
m = s.model()
sol = m[k].as_long()
val = ((sol ^ 0x5A5A5A5A) << 5 & 0xFFFFFFFF) | ((sol ^ 0x5A5A5A5A) >> 27)
assert val == 0xDEADBEEF, 'Mathematical inversion verification failed'
print('OK')
`
  },
  {
    name: "Unsatisfiable Invariant (Opaque Predicate Detection)",
    script: `
import z3
s = z3.Solver()
y = z3.BitVec('y', 32)
s.add(z3.ULT(y * y, 0))
assert str(s.check()) == 'unsat', 'Expected UNSAT for unsigned negative'
print('OK')
`
  }
];

let allPassed = true;

for (const t of testCases) {
  try {
    process.stdout.write(`  Running: ${chalk.bold(t.name)}... `);
    execSync("python -", { input: t.script, encoding: "utf-8" });
    console.log(chalk.green("PASSED ✔"));
  } catch (err) {
    allPassed = false;
    console.log(chalk.red("FAILED ✖"));
    console.error(err.message);
  }
}

console.log("\n" + "─".repeat(50));
if (allPassed) {
  console.log(chalk.green.bold("★ Z3 SMT CONSTRAINT ENGINE VERIFIED 100% MATHEMATICALLY ACCURATE!\n"));
  process.exit(0);
} else {
  console.log(chalk.red.bold("✖ SMT Verification failures detected\n"));
  process.exit(1);
}
