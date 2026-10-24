# SYMB Target Analysis & Solving Matrix

SYMB supports symbolic execution, deobfuscation, constraint solving, and memory hooking across a broad matrix of operating systems, architectures, and protection schemes.

| Target Category | Protection / Architecture | What SYMB Solves & Returns | Requirements & Guide |
| :--- | :--- | :--- | :--- |
| **Control-Flow Flattening (CFF)** | OLLVM, Hikari, Goron, Tigress (x86_64, ARM64) | Identifies switch dispatchers, eliminates bogus jump edges, reconstructs clean linear CFG and decompilable C pseudocode | Built-in angr / symbolic AST solver; [OLLVM Guide](ollvm-unflattening.md) |
| **Complex Branch Reachability** | Multi-branch keygens, serial validators, anti-tamper | Exact concrete byte sequence (ASCII, Hex) that unlocks the target address while avoiding failure paths | Z3 SMT Solver & angr; [SMT Solver Guide](smt-branch-solving.md) |
| **Custom Bytecode VMs** | Themida, VMProtect, custom interpreter dispatchers | Extracts Virtual Program Counter (VPC), maps handler opcode tables, lifts bytecode instructions to standard IR | Built-in symbolic trace engine; `devirtualize_bytecode_vm` |
| **Live Process Memory** | Windows (PE/x64), Linux (ELF/x64), macOS (Mach-O) | Zero-disk in-memory function hooking, atomic trampoline detours, real-time memory patching without modifying disk files | Caller permissions (Admin/root); [Trampolines Guide](zero-disk-trampolines.md) |
| **Symbolic Taint Tracing** | Native binaries (x86, ARM), WebAssembly (WASM) | Bit-level taint propagation from untrusted input buffers to dangerous sinks (`memcpy`, format strings, indirect calls) | Built-in taint engine; `trace_symbolic_taint` |
| **Cryptographic Hash Pre-states** | Custom checksums, Adler32, CRC32, nonlinear bit-shifts | Mathematical inversion of state transformations to recover valid original payloads | Z3 bit-vector logic; `solve_branch_reachability` |
| **Bogus Control Flow (BCF)** | Opaque predicates ($7y^2 - 1 \neq x^2$), dead loops | Proves invariant truth values using Z3, eliminates dead blocks, simplifies instruction sequences | Built-in SMT simplifier; `unflatten_control_flow` |
| **Mobile Security SDKs** | Android Native Libraries (`.so`), iOS Mach-O Frameworks | Unflattens root-detection and integrity-checking routines in ARM64 `.so` modules | ARM64 backend with angr / Z3; [OLLVM Guide](ollvm-unflattening.md) |
| **WebAssembly Binaries** | WASM bytecodes with flattened dispatcher switches | Recovers original structured control flow (`block`, `loop`, `br_table` normalization) | Built-in WASM parser; `unflatten_control_flow` |
