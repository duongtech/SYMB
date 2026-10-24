# Symbolic Engineering & Deobfuscation Guide

## Understanding Control Flow Flattening (OLLVM)

Control Flow Flattening (CFF) transforms structured code (`if/else`, `while`, `for`) into a flat, single-level state machine. The basic blocks of the original function are broken apart and enclosed in a giant `switch-case` loop controlled by a synthetic state variable.

### Why Standard Decompilers Fail
Decompilers like Ghidra or IDA try to reconstruct high-level control structures from graph topology. In flattened code:
- Every block jumps back to the central dispatcher.
- The original dominance tree is completely destroyed.
- The decompiler outputs an unreadable loop with thousands of cases.

### How SYMB Solves CFF
SYMB applies **Symbolic Execution with Angr & Triton**:
1. **Dispatcher Identification**: Identifies the central switch block and the state variable.
2. **Symbolic Stepping**: For each case block, symbolises the state variable and steps execution until the next state update is calculated.
3. **Graph Reconstruction**: Replaces the jump back to the dispatcher with a direct edge to the true successor state.
4. **Dead Block Elimination**: Eliminates the synthetic dispatcher and opaque predicates, yielding clean, original CFG.

---

## SMT Constraint Solving with Z3

When a binary compares user input against cryptographic or mathematical checks:

```c
if (((input[0] ^ 0x5a) + 17) % 256 == 0x3f && input[1] == input[0] + 5) {
    grant_access();
}
```

Instead of brute-forcing $2^{128}$ possibilities, SYMB represents the input as a vector of symbolic variables. The operations are converted into First-Order Logic formulas in the **Z3 Theorem Prover**. Z3 solves the satisfiability problem (SAT) and emits concrete satisfying values in milliseconds.
