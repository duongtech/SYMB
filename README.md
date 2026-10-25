<div align="center">

<p align="center">
  <img src="docs/assets/symb-banner.svg" alt="SYMB Banner" width="100%">
</p>

**English** · [Tiếng Việt](docs/readme/README_vi.md)

### One MCP server for symbolic execution, OLLVM unflattening, and active binary intervention across binaries and runtimes.

[![CI Audit](https://github.com/duongtech/SYMB/actions/workflows/ci.yml/badge.svg)](https://github.com/duongtech/SYMB/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/duongtech/SYMB?style=flat-square&color=2ea44f)](https://github.com/duongtech/SYMB/releases)
[![npm version](https://img.shields.io/npm/v/symb-agents?style=flat-square&color=cb3837)](https://www.npmjs.com/package/symb-agents)
[![MCP tool catalog](https://img.shields.io/badge/MCP-20%20Tools%20Active-5c4ee5?style=flat-square)](docs/mcp-contracts.md)
[![Python requirements](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](#-requirements--environment)
[![Node.js requirements](https://img.shields.io/badge/Node.js-requirements-339933?style=flat-square&logo=nodedotjs&logoColor=white)](#-requirements--environment)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

<br />

```bash
npx symb-agents setup
```

<br />

</div>

---

## 📑 Table of Contents (Mục Lục)

- [⚡ What is SYMB?](#-what-is-symb)
- [⚔️ Architectural Comparison: SYMB vs REA](#️-architectural-comparison-symb-vs-rea)
- [🛠️ MCP Tool Reference (20 Native Tools)](#️-mcp-tool-reference-20-native-tools)
  - [⚔️ Active Binary Intervention Arsenal (5 Tools)](#️-active-binary-intervention-arsenal-5-tools)
  - [🔬 Symbolic Execution & SMT Solver Engines (3 Tools)](#-symbolic-execution--smt-solver-engines-3-tools)
  - [⚡ Multi-Platform Native Decompilers & Unpackers (4 Tools)](#-multi-platform-native-decompilers--unpackers-4-tools)
  - [🔍 Deep Binary Auditing & Memory Engines (8 Tools)](#-deep-binary-auditing--memory-engines-8-tools)
- [📚 Documentation Hub & Architecture Guides (`docs/`)](#-documentation-hub--architecture-guides-docs)
- [💻 Standalone Command-Line Interface (CLI)](#-standalone-command-line-interface-cli)
- [🧪 Testing & Rigorous Verification (100% Pass)](#-testing--rigorous-verification-100-pass)
- [📦 Requirements & Environment](#-requirements--environment)
- [📄 License](#-license)

---

<p align="center">
  <img src="docs/assets/symb-hero-benchmark.svg" alt="SYMB vs REA Benchmark Matrix" width="100%">
</p>

---

## ⚡ What is SYMB?

**SYMB** is an autonomous reverse engineering, constraint solving, and **active binary intervention** engine purpose-built for AI agents. It wraps low-level symbolic execution engines (**Z3 SMT Solver**, **angr**, **Unicorn CPU Emulator**, **Capstone**, **pefile**) into clean Model Context Protocol (MCP) tool contracts.

---

## ⚔️ Architectural Comparison: SYMB vs REA

Mainstream reverse engineering assistants (such as `morluto/rea`) are designed strictly as **passive observers**: they decompile, format pseudocode, and catalog observations, but explicitly refuse to perform binary mutations, bypass checks, or intervene in execution.

| Feature / Capability | Passive Assistants (e.g. REA) | SYMB (Active RE & Symbolic Engine) |
| :--- | :---: | :---: |
| **Philosophy** | Passive Read-Only Analysis | **Active Dynamic Intervention & Weaponization** |
| **Binary opcodes mutation** | ❌ Refused / Out of scope | ✔ **Surgical disk binary patcher with RVA-to-Raw conversion** |
| **PE Optional CheckSum** | ❌ None | ✔ **Automated PE CheckSum recalculation on patched binaries** |
| **Anti-Debug / Anti-Analysis** | ⚠️ Report detections only | ✔ **Automated trap neutralization (NOP out RDTSC, INT 2D, PEB BeingDebugged)** |
| **License & DRM Logic** | ⚠️ Static report | ✔ **Automated branch conditional inversion (`JZ`<->`JNZ`, force success, keygen)** |
| **Dynamic Instrumentation** | ⚠️ Basic passive trace | ✔ **Frida script generator (SSL Unpinning, Root cloak, Anti-Debug API hook)** |
| **Live RAM Hot Patching** | ❌ None | ✔ **Zero-disk memory trampolines via Win32 VirtualProtectEx / /proc/pid/mem** |
| **OLLVM Deobfuscation** | ❌ Basic heuristic | ✔ **Symbolic state-variable dispatcher unflattening via Z3 & angr** |
| **Evidence & Provenance** | ✔ Standard schema | ✔ **Target Identity (SHA256/MD5), Engine Provenance, Fail-Closed verification** |
| **Test Verification** | ✔ Complex test suite | ✔ **Vitest Unit/Integration Tests + 8 Automated Verification Suites** |

---

## 🛠️ MCP Tool Reference (20 Native Tools)

SYMB implements 20 high-speed native reversing and intervention tools via standard MCP JSON-RPC:

### ⚔️ Active Binary Intervention Arsenal (5 Tools)
Tools specifically engineered for active exploitation, cracking, and binary neutralization:

| Tool Name | Key Arguments | Primary Capability | Deep-Dive Guide |
| :--- | :--- | :--- | :--- |
| `patch_binary_executable` | `binary_path`, `patches`, `output_path` | Surgical physical disk patcher. Converts RVA to physical file offset, modifies arbitrary hex bytes, generates byte-by-byte diffs, and updates PE checksums. | [Guide](docs/active-binary-intervention.md#1-patch_binary_executable) |
| `neutralize_anti_debugging` | `binary_path`, `auto_patch`, `output_path` | Scans and neutralizes inline RDTSC timing traps, INT 2D/3 traps, and PEB BeingDebugged checks. Automatically writes patched binaries with recalculated PE checksums. | [Guide](docs/active-binary-intervention.md#2-neutralize_anti_debugging) |
| `bypass_license_authorization` | `binary_path`, `force_success`, `apply_to_file` | Evaluates authorization branch conditionals, computes inversion patches (`JE`<->`JNE`, force `JMP`), and writes permanently cracked binaries. | [Guide](docs/active-binary-intervention.md#3-bypass_license_authorization) |
| `generate_frida_instrumentation` | `target`, `platform`, `script_type` | Generates battle-tested Frida dynamic instrumentation scripts for SSL unpinning, RootBeer cloaking, and Windows native API hooks. | [Guide](docs/active-binary-intervention.md#4-generate_frida_instrumentation) |
| `hot_patch_live_memory` | `pid`, `memory_address`, `patch_bytes_hex` | Injects atomic zero-disk trampolines into running process RAM without touching disk binaries. | [Guide](docs/zero-disk-trampolines.md) |

### 🔬 Symbolic Execution & SMT Solver Engines (3 Tools)
| Tool Name | Key Arguments | Primary Capability | Deep-Dive Guide |
| :--- | :--- | :--- | :--- |
| `unflatten_control_flow` | `binary_path`, `function_address` | Symbolically deobfuscates OLLVM switch dispatchers and restores original CFG. | [Guide](docs/ollvm-unflattening.md) |
| `solve_branch_reachability` | `binary_path`, `target_address` | Uses Z3 SMT Solver & angr to solve for exact inputs reaching target branches. | [Guide](docs/smt-branch-solving.md) |
| `trace_symbolic_taint` | `binary_path`, `source_symbol`, `sink_symbol` | Bit-level dataflow propagation analysis from input buffers to critical memory sinks. | [Contracts](docs/mcp-contracts.md) |

### ⚡ Multi-Platform Native Decompilers & Unpackers (4 Tools)
| Tool Name | Key Arguments | Primary Capability | Deep-Dive Guide |
| :--- | :--- | :--- | :--- |
| `dynamically_unpack_binary` | `binary_path`, `max_instructions` | Unicorn CPU emulation unpacker. Executes binary past packer stubs (UPX, Themida, crypters), detects OEP tail jumps, and dumps unpacked memory images. | [Guide](docs/decompiler-advanced.md) |
| `decompile_native_function` | `binary_path`, `function_address` | Decompiles machine code to clean C pseudocode in < 400ms with Capstone and struct layout inference. | [Guide](docs/decompiler-advanced.md) |
| `decompile_entire_program` | `binary_path`, `max_functions` | Automated whole-program decompiler. Recovers function entry points and generates unified C source files. | [Guide](docs/decompiler-advanced.md) |
| `decompile_apk_package` | `target_path`, `max_classes` | 5-Pass native Dalvik DEX decompiler. Audits permissions, keystore signature schemes (v1/v2/v3), CWEs, and lifts Dalvik to Java. | [Guide](docs/decompiler-advanced.md) |

### 🔍 Deep Binary Auditing & Memory Engines (8 Tools)
| Tool Name | Key Arguments | Primary Capability | Deep-Dive Guide |
| :--- | :--- | :--- | :--- |
| `decompile_ios_ipa_package` | `target_path` | Decompiles Apple iOS IPA packages & ARM64 Mach-O binaries. Audits FairPlay DRM (cryptid) and Anti-Jailbreak heuristics. | [Contracts](docs/mcp-contracts.md) |
| `decrypt_obfuscated_strings` | `binary_path`, `max_candidates` | Solves Single-byte XOR, Multi-byte cycling XOR, Rolling Key XOR, and Base64 across PE, ELF, APK, and .so binaries. | [Contracts](docs/mcp-contracts.md) |
| `detect_binary_protections` | `binary_path` | Detects packers (UPX, Themida, VMProtect, Enigma), Anti-Debug APIs, Anti-VM artifacts, and ASM timing traps. | [Contracts](docs/mcp-contracts.md) |
| `inspect_binary_layout` | `binary_path` | Scans PE/ELF headers, ASLR/DEP/SafeSEH mitigations, IAT/EAT exports, and measures section entropy. | [Contracts](docs/mcp-contracts.md) |
| `detect_crypto_primitives` | `binary_path` | Scans for AES S-Boxes, SHA/MD5 constants, CRC32 tables, RC4 loops, and ChaCha schedules for SMT inversion. | [Contracts](docs/mcp-contracts.md) |
| `scan_byte_entropy` | `binary_path`, `block_size` | 256-byte sliding window Shannon entropy heatmap generator for encrypted shellcode and compressed overlays. | [Contracts](docs/mcp-contracts.md) |
| `trace_binary_xrefs` | `binary_path` | Maps whole-program call graph edges, indirect calls, and string literal cross-references. | [Contracts](docs/mcp-contracts.md) |
| `optimize_large_media_buffer` | `file_path`, `target_max_mb` | Downsamples oversized videos, isolates audio tracks, and streams multi-GB dumps via zero-RAM mmap. | [Guide](docs/media-optimizer.md) |

---

## 📚 Documentation Hub & Architecture Guides (`docs/`)

SYMB maintains comprehensive, modular documentation covering theoretical foundations, implementation guides, and MCP specifications:

| Guide / Document | Focus Area | Description |
| :--- | :--- | :--- |
| ⚔️ **[Active Binary Intervention](docs/active-binary-intervention.md)** | **Binary Cracking & Patching** | Complete guide for RVA-to-Raw mapping, PE CheckSum recalculation, Anti-Debug neutralization, and Frida generator. |
| 📜 **[Canonical MCP Tool Contracts](docs/mcp-contracts.md)** | **Protocol Specification** | Formal JSON schemas, inputs, outputs, and Canonical Evidence records for all 20 native MCP tools. |
| 🌪️ **[OLLVM Control-Flow Unflattening](docs/ollvm-unflattening.md)** | **Deobfuscation** | Mathematical state-variable solving, dispatcher pruning, and CFG restoration using Z3 & angr. |
| 🎯 **[SMT Branch Solving Guide](docs/smt-branch-solving.md)** | **Symbolic Execution** | Automated path reachability, SAT solving, and crackme solving with Z3 SMT Theorem Prover. |
| ⚡ **[Advanced Decompiler Architectures](docs/decompiler-advanced.md)** | **Native & Dalvik Lifting** | Unicorn CPU emulation unpacker, high-speed C pseudocode generator, and 5-pass Android DEX decompiler. |
| 🔒 **[Zero-Disk Memory Trampolines](docs/zero-disk-trampolines.md)** | **Live Memory Hooking** | Win32 API (`VirtualProtectEx`) and Linux `/proc/pid/mem` live memory surgery without disk footprints. |
| 🎬 **[Large Media & Buffer Optimizer](docs/media-optimizer.md)** | **Context Management** | Hardware-accelerated audio extraction, video downsampling budgets, and zero-RAM `mmap` streaming. |
| 🧠 **[Symbolic Engineering Guide](docs/symbolic-engineering-guide.md)** | **Architecture** | Core system principles, mathematical invariants, and agent integration guidelines. |
| 🎯 **[Target & Architecture Matrix](docs/target-matrix.md)** | **Compatibility** | Platform support matrix across Windows (x86/x64), Linux (x86/x64/ARM), macOS, Android, and iOS. |
| 🚀 **[Installation & Setup Guide](docs/installation.md)** | **Getting Started** | Detailed step-by-step setup for Claude Desktop, Cursor, Antigravity, and global CLI usage. |

---

## 💻 Standalone Command-Line Interface (CLI)

```bash
# Neutralize Anti-Debugging traps and produce patched binary
symb antidebug ./target.exe --patch

# Bypass license authorization checks and invert branch logic
symb license-bypass ./target.exe --force-success

# Dynamically unpack UPX or encrypted binary via Unicorn CPU emulation
symb unpack ./examples/01_ollvm_cff/CFF_win64.exe

# Decompile native function with control-flow structuring & struct inference
symb decompile ./examples/02_smt_crackme/ais3_crackme 0x4005f6

# Translate an entire binary to a unified C project file
symb decompile-all ./examples/02_smt_crackme/ais3_crackme --limit 10

# Decompile Android APK with resources.arsc symbol resolution
symb apk ./examples/04_apk_sample/sample_protected.apk
```

---

## 🧪 Testing & Rigorous Verification (100% Pass)

SYMB enforces strict **fail-closed verification** and canonical evidence contracts:

```bash
# Run Vitest Unit & Integration Suites
npm run test:unit

# Run All 8 Comprehensive System Verification Suites
npm test
```

Suites include:
1. **System Capabilities & Solver Audit** (Node, Python, Z3, angr, Unicorn, Capstone)
2. **MCP Tool Contracts & Zod Schemas** (Validating all 20 tool schemas)
3. **Native High-Speed EXE Decompiler & Layout Engine**
4. **Z3 SMT Mathematical Logic Engine**
5. **OLLVM Control-Flow Unflattening** (PE & ELF)
6. **SMT Branch Reachability Solver**
7. **Large Media & Binary Buffer Optimizer Engine**
8. **Active Binary Intervention & Weaponized RE Engine**

---

## 📦 Requirements & Environment

- **Node.js**: `>= 18.0.0` (Verified on Node 20, 22, and 24)
- **Python**: `>= 3.10`
- **Native Solvers**: `pip install -r requirements.txt` (Z3 SMT Solver, angr, Unicorn, Capstone, pefile).
- Run `symb audit` or `npx symb-agents setup` to automatically audit your local runtime capabilities.

---

## 📄 License

MIT License. Open-source for developers, security researchers, and autonomous AI agents.
