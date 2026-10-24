# SMT Branch Constraint Solving Guide

Symbolic execution uses Satisfiability Modulo Theories (SMT) solvers to compute exact input values that drive program execution to specific targets while avoiding crash states or failure blocks.

---

## 🧮 How SYMB Solves Branch Reachability

Traditional fuzzing tests billions of random inputs hoping to hit branch conditions. For cryptographic hash checks, checksums, or multi-stage key validators, fuzzing takes weeks or fails entirely.

**SYMB uses Z3 and angr to mathematically prove and invert branch constraints in milliseconds**:

1. **Symbolic Variables Allocation**:
   Marks input buffers, file descriptors, network streams, or function arguments as symbolic bit-vectors (`BitVec('input', 8 * size)`).
2. **Intermediate Representation (VEX/LLVM IR)**:
   Translates machine instructions into architecture-independent IR.
3. **Path Constraint Accumulation**:
   At each conditional branch (`jz`, `jnz`, `cbnz`), SYMB forks the execution state and records the condition as an SMT formula:
   $$\Phi = \bigwedge_{i=1}^n C_i(\vec{x})$$
4. **Target Reachability & Model Extraction**:
   When execution reaches the `target_address`, SYMB queries Z3:
   $$\text{Check}(\Phi_{\text{target}} \land \neg \Phi_{\text{avoid}})$$
   If `SAT`, Z3 yields the concrete evaluation $\vec{x}$ (the exact key, password, or payload).

---

## 🛠️ MCP Tool: `solve_branch_reachability`

### Input Parameters
```json
{
  "binary_path": "crackme_v2.exe",
  "start_address": "0x140001000",
  "target_address": "0x140001250",
  "avoid_addresses": ["0x140001280", "0x140001990"],
  "symbolic_variables": ["license_key"],
  "timeout_seconds": 60
}
```

### Output (`BranchSolverResult`)
```json
{
  "status": "SAT",
  "solution_found": true,
  "execution_time_ms": 34.2,
  "concrete_inputs": {
    "license_key": "SYMB-7F89-A2C4-9981"
  },
  "raw_hex": "53594d422d374638392d413243342d39393831",
  "evidence": {
    "facts": [
      "Constraint set: 14 linear equations + 2 modular congruences",
      "Solver engine: Z3 SMT Theorem Prover 4.12+",
      "Target address 0x140001250 proved reachable under model"
    ]
  }
}
```
