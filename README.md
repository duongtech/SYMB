<div align="center">

**English** · [Tiếng Việt](docs/readme/README_vi.md)

# SYMB: Symbolic Reverse Engineering & Deobfuscation

### One MCP server for symbolic execution, OLLVM unflattening, and constraint solving across binaries and runtimes.

[![npm version](https://img.shields.io/npm/v/symb-agents?style=flat-square&color=cb3837)](https://www.npmjs.com/package/symb-agents)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](docs/mcp-contracts.md)
[![Python requirements](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](#requirements)
[![Node.js requirements](https://img.shields.io/badge/Node.js-requirements-339933?style=flat-square&logo=nodedotjs&logoColor=white)](#requirements)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

<br />

```bash
npx symb-agents setup
```

<br />

</div>

---

## ⚡ What is SYMB?

**SYMB** is an autonomous Model Context Protocol (MCP) server that empowers AI Agents (Claude Code, Cursor, Antigravity, Copilot, Codex) with **Symbolic Execution, SMT Constraint Solving, and Control-Flow Deobfuscation**.

While standard decompilers only perform passive syntax inspection, **SYMB elevates AI agents into active mathematical solvers**:
- **Symbolic Control-Flow Unflattening:** Eliminates OLLVM / Obfuscator-LLVM flattening, unrolls opaque predicates, and reconstructs clean, human-readable control flow graphs.
- **Automated SMT Branch Solving:** Discovers exact byte-level inputs that drive execution to target success branches using **angr** and the **Z3 Theorem Prover**.
- **Dynamic Symbolic Taint Tracking:** Proves whether untrusted inputs propagate into dangerous memory sinks.
- **In-Memory Process Surgery:** Enables zero-disk live function hooking and memory patching directly from the agent chat interface.

---

## 🛠️ MCP Tool Catalog

SYMB provides high-performance MCP tools designed specifically for AI Agent autonomous workflows:

### 1. `unflatten_control_flow`
Symbolically analyzes OLLVM / Obfuscator-LLVM Control Flow Flattening (CFF). Identifies state variables, eliminates dispatcher blocks, unrolls opaque predicates, and reconstructs clean, human-readable structured pseudocode.

### 2. `solve_branch_reachability`
Uses `angr` and the `Z3 SMT Theorem Prover` to find the exact byte sequence that drives execution to a target address (e.g. `SUCCESS`, `VALID_LICENSE`, `UNLOCKED`) while avoiding failure paths.

### 3. `trace_symbolic_taint`
Performs dynamic taint analysis across native assembly and WebAssembly modules. Verifies whether user-controlled inputs can propagate into critical memory sinks (`memcpy`, `strcpy`, format strings, or indirect branch targets).

### 4. `devirtualize_bytecode_vm`
Detects custom virtual machine interpreter loops. Identifies the virtual program counter (VPC), handler tables, and lifts the virtual instructions back to standard LLVM IR / C.

### 5. `hot_patch_live_memory`
Performs zero-disk in-memory trampoline injection and function hooking on running processes. Allows agents to test logic modifications and bypasses in RAM without altering on-disk binary signatures.

---

## 🚀 Quickstart

### 1. One-Click Agent Setup

Run the interactive setup wizard in your terminal:

```bash
npx symb-agents setup
```

Select your target agents (**Claude Code**, **Cursor**, **Antigravity**, **Gemini CLI**, or **Codex**). SYMB automatically registers the MCP server into your agent configuration files.

### 2. Asking Your Agent

Once registered, your agent can solve complex binary puzzles directly in chat:

```text
User: "The license verification function at 0x00401500 in auth_core.exe is protected with OLLVM flattening. Unflatten it and solve for the valid 16-byte key that reaches 0x00401580."

Agent: 
⚡ [SYMB] Calling unflatten_control_flow(binary="auth_core.exe", func="0x401500")...
⚡ [SYMB] Eliminating dispatcher at 0x401520. Reconstructed original CFG with 4 basic blocks.
⚡ [SYMB] Calling solve_branch_reachability(target="0x401580", avoid=["0x401590"])...
⚡ [SYMB] Z3 SMT solver converged in 1.4s. 

Key solution found:
ASCII: "K3Y-9842-AXQ-771"
Hex: 4b 33 59 2d 39 38 34 32 2d 41 58 51 2d 37 37 31
```

---

## 🏗️ Architecture

```mermaid
flowchart TD
    User["👨‍💻 User Prompt in Agent UI"] --> Agent["🤖 AI Agent (Claude Code / Cursor / Antigravity)"]
    Agent -->|"Model Context Protocol (stdio/JSON-RPC)"| SymbServer["⚡ SYMB MCP Server (TypeScript / Node.js)"]
    
    subgraph SymbCore ["🧠 SYMB Core Engine"]
        SymbServer --> Bridge["Python Native IPC Bridge"]
        Bridge --> Angr["🔬 angr Symbolic Execution Engine"]
        Bridge --> Z3["📐 Z3 SMT Theorem Prover"]
        Bridge --> Triton["⚡ Triton Dynamic Binary Analysis"]
        Bridge --> Trampoline["💉 Live Process Memory Trampoline"]
    end
    
    SymbCore -->|"Canonical Evidence Record (Facts + Solved Inputs)"| Agent
    Agent -->|"Verified Solution / Unflattened Code"| User
```

---

## 📦 Requirements

- **Node.js**: `>= 18.0.0`
- **Python**: `>= 3.10`
- **Native Solvers**: `pip install angr z3-solver triton` (SYMB's setup script can install these automatically).

---

## 📖 Documentation

- [MCP Tool Contracts & Evidence Schema](docs/mcp-contracts.md)
- [Agent Integration Guide](docs/installation.md)
- [Symbolic Engineering & Deobfuscation Guide](docs/symbolic-engineering-guide.md)
- [Instructions for AI Agents](AGENTS.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

---

## 📄 License

MIT License © 2026 [duongtech](https://github.com/duongtech).
