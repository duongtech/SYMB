<div align="center">

<p align="center">
  <img src="docs/assets/symb-banner.svg" alt="SYMB Banner" width="100%">
</p>

**English** · [Tiếng Việt](docs/readme/README_vi.md)

### One MCP server for symbolic execution, OLLVM unflattening, and active reverse engineering intervention across binaries and runtimes.

[![CI Audit](https://github.com/duongtech/SYMB/actions/workflows/ci.yml/badge.svg)](https://github.com/duongtech/SYMB/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/duongtech/SYMB?style=flat-square&color=2ea44f)](https://github.com/duongtech/SYMB/releases)
[![npm version](https://img.shields.io/npm/v/symb-agents?style=flat-square&color=cb3837)](https://www.npmjs.com/package/symb-agents)
[![MCP tool catalog](https://img.shields.io/badge/MCP-20%20Tools%20Active-5c4ee5?style=flat-square)](docs/mcp-contracts.md)
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

<p align="center">
  <img src="docs/assets/symb-hero-benchmark.svg" alt="SYMB vs REA Benchmark Matrix" width="100%">
</p>

---

## ⚡ What is SYMB?

**SYMB** is an autonomous reverse engineering, constraint solving, and **active binary intervention** engine purpose-built for AI agents. It wraps low-level symbolic execution engines (**Z3 SMT Solver**, **angr**, **Unicorn CPU Emulator**, **Capstone**, **pefile**) into clean Model Context Protocol (MCP) tool contracts.

---

## ⚔️ Why SYMB Surpasses Passive Reversing Tools (like REA)

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

### ⚔️ Active Binary Intervention Arsenal (What REA Lacks)
| Tool Name | Key Arguments | Primary Capability |
| :--- | :--- | :--- |
| `neutralize_anti_debugging` | `binary_path`, `auto_patch`, `output_path` | Scans and neutralizes inline RDTSC timing traps, INT 2D/3 traps, and PEB BeingDebugged checks. Automatically writes patched binaries with recalculated PE checksums. |
| `bypass_license_authorization` | `binary_path`, `force_success`, `apply_to_file` | Evaluates authorization branch conditionals, computes inversion patches (`JE`<->`JNE`, force `JMP`), and writes permanently cracked binaries. |
| `patch_binary_executable` | `binary_path`, `patches`, `output_path` | Surgical physical disk patcher. Converts RVA to physical file offset, modifies arbitrary hex bytes, generates byte-by-byte diffs, and updates PE checksums. |
| `generate_frida_instrumentation` | `target`, `platform`, `script_type` | Generates battle-tested Frida dynamic instrumentation scripts for SSL unpinning, RootBeer cloaking, and Windows native API hooks. |
| `hot_patch_live_memory` | `pid`, `memory_address`, `patch_bytes_hex` | Injects atomic zero-disk trampolines into running process RAM without touching disk binaries. |

### 🔬 Symbolic Execution, Deobfuscation & Analysis Engines
| Tool Name | Key Arguments | Primary Capability |
| :--- | :--- | :--- |
| `dynamically_unpack_binary` | `binary_path`, `max_instructions` | Unicorn CPU emulation unpacker. Executes binary past packer stubs (UPX, Themida, crypters), detects OEP tail jumps, and dumps unpacked memory images. |
| `unflatten_control_flow` | `binary_path`, `function_address` | Symbolically deobfuscates OLLVM switch dispatchers and restores original CFG. |
| `solve_branch_reachability` | `binary_path`, `target_address` | Uses Z3 SMT Solver & angr to solve for exact inputs reaching target branches. |
| `trace_symbolic_taint` | `binary_path`, `source_symbol`, `sink_symbol` | Bit-level dataflow propagation analysis from input buffers to critical memory sinks. |
| `decompile_native_function` | `binary_path`, `function_address` | Decompiles machine code to clean C pseudocode in < 400ms with Capstone and struct layout inference. |
| `decompile_entire_program` | `binary_path`, `max_functions` | Automated whole-program decompiler. Recovers function entry points and generates unified C source files. |
| `decompile_apk_package` | `target_path`, `max_classes` | 5-Pass native Dalvik DEX decompiler. Audits permissions, keystore signature schemes (v1/v2/v3), CWEs, and lifts Dalvik to Java. |
| `decompile_ios_ipa_package` | `target_path` | Decompiles Apple iOS IPA packages & ARM64 Mach-O binaries. Audits FairPlay DRM (cryptid) and Anti-Jailbreak heuristics. |
| `decrypt_obfuscated_strings` | `binary_path`, `max_candidates` | Solves Single-byte XOR, Multi-byte cycling XOR, Rolling Key XOR, and Base64 across PE, ELF, APK, and .so binaries. |
| `detect_binary_protections` | `binary_path` | Detects packers (UPX, Themida, VMProtect, Enigma), Anti-Debug APIs, Anti-VM artifacts, and ASM timing traps. |
| `inspect_binary_layout` | `binary_path` | Scans PE/ELF headers, ASLR/DEP/SafeSEH mitigations, IAT/EAT exports, and measures section entropy. |
| `detect_crypto_primitives` | `binary_path` | Scans for AES S-Boxes, SHA/MD5 constants, CRC32 tables, RC4 loops, and ChaCha schedules for SMT inversion. |
| `scan_byte_entropy` | `binary_path`, `block_size` | 256-byte sliding window Shannon entropy heatmap generator for encrypted shellcode and compressed overlays. |
| `trace_binary_xrefs` | `binary_path` | Maps whole-program call graph edges, indirect calls, and string literal cross-references. |
| `optimize_large_media_buffer` | `file_path`, `target_max_mb` | Downsamples oversized videos, isolates audio tracks, and streams multi-GB dumps via zero-RAM mmap. |

---

## 💻 Standalone Command-Line Interface (CLI)

```bash
# Neutralize Anti-Debugging traps and produce patched binary
symb antidebug ./target.exe --patch

# Bypass license authorization checks
symb license-bypass ./target.exe --force-success

# Dynamically unpack UPX or encrypted binary via Unicorn CPU emulation
symb unpack ./examples/01_ollvm_cff/CFF_win64.exe

# Decompile native function with control-flow structuring & struct inference
symb decompile ./examples/02_smt_crackme/ais3_crackme 0x4005f6

# Translate an entire binary to a unified C project file
symb decompile-all ./examples/02_smt_crackme/ais3_crackme --limit 10

# Decompile Android APK with resources.arsc symbol resolution
symb apk ./examples/04_apk_sample/Termux.apk
```

---

## 🧪 Testing & Rigorous Verification

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

## 📄 License

MIT License. Open-source for developers, security researchers, and autonomous AI agents.
