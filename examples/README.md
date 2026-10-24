# SYMB Official Demonstrations & Benchmark Binaries

This folder contains authentic target binaries and demonstration scripts illustrating SYMB's unique symbolic deobfuscation and SMT solving capabilities.

---

## 📂 Target Inventory

### 1. `01_ollvm_cff/` — Control-Flow Flattening Deobfuscation
- **`CFF_win64.exe`**: Authentic Windows x64 PE executable protected by Obfuscator-LLVM (OLLVM) Control-Flow Flattening (`-mllvm -fla`).
- **`CFF_win.cc`**: Original C++ source code before obfuscation, demonstrating the original `target_function` control flow.
- **`fauxware_fla`**: Authentic Linux x86_64 ELF binary protected with OLLVM switch dispatcher flattening (from the official `angr` test suite).

**How to test with SYMB**:
```bash
# Analyze OLLVM flattened CFG and eliminate switch dispatcher
symb unflatten --binary examples/01_ollvm_cff/CFF_win64.exe --addr 0x140001000
```

---

### 2. `02_smt_crackme/` — Branch Reachability SMT Solver
- **`ais3_crackme`**: The legendary AI & CTF benchmark crackme requiring 100-byte symbolic bitvector constraint solving to reach the success address (`0x400602`).
- **`solve_ais3.py`**: Automated solver demonstrating Z3/angr convergence to find the exact flag:
  $$\text{Key} = \text{"ais3\{I\_tak3\_g00d\_n0t3s\}"}$$

**How to test with SYMB**:
```bash
python examples/02_smt_crackme/solve_ais3.py
```

---

### 3. `03_zero_disk_hook/` — Live Process In-Memory Surgery
- **`live_daemon.py`**: A background process daemon simulating an integrity-checking security agent.
- Illustrates how SYMB's `hot_patch_live_memory` tool performs atomic trampoline detours without modifying on-disk file checksums.
