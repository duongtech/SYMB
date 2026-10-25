# ⚡ Advanced Decompiler & Binary Analysis Architectures

To bridge the gap between classical static disassembly and industrial decompilers (IDA Pro, Ghidra, JADX), SYMB integrates four advanced analysis engines:

1. **Android Resource Table Decoupling (`resources.arsc` & AXML)**
2. **High-Level Control Flow Structuring (`while`, `for`, `switch/case`)**
3. **Struct Layout Inference & Type Propagation**
4. **Dynamic Unicorn CPU Emulation Memory Unpacker**

---

## 1. 📱 Android Resource Table Decoupling (`resources.arsc` & AXML)

In raw APK bytecode decompilation, UI references and system strings are typically rendered as opaque 32-bit hexadecimal integers (e.g., `findViewById(0x7f08001c)` or `getString(0x7f0b0004)`). 

SYMB parses the binary `resources.arsc` chunk hierarchy (`RES_TABLE_TYPE`, `RES_STRING_POOL_TYPE`, `RES_TABLE_PACKAGE_TYPE`, `RES_TABLE_TYPE_SPEC_TYPE`, `RES_TABLE_TYPE_TYPE`) to reconstruct symbolic mappings:

```
0x7f08001c ────► R.id.btn_submit
0x7f0b0004 ────► R.string.api_endpoint_url
0x7f040001 ────► R.layout.activity_main
```

### Decompiled Java Comparison:
| Raw Bytecode Lifting | SYMB Decoupled Reconstruction |
| :--- | :--- |
| `int v0 = 0x7f08001c;` | `int v0 = 0x7f08001c; // Resolved: R.id.btn_submit` |
| `v1.findViewById(v0);` | `v1.findViewById(R.id.btn_submit);` |

---

## 2. 🌪️ High-Level Control Flow Structuring (AST Loops & Switch Ladders)

Low-level disassemblers produce flat listings dominated by condition branches (`if (!cond) goto loc_401520; ... goto loc_401500;`). SYMB performs control-flow interval analysis to detect back-edges and dominator boundaries:

### Natural Loop Structuring:
- **Backward Branch Detection**: Jumps targeting predecessor basic blocks ($\text{Target} \le \text{Current}$) are identified as natural loop edges.
- **Induction Analysis**: Register increment operations (`i++` or `rcx += 1`) combined with loop boundary comparisons are structured into idiomatic C `for` loops:
  ```c
  // Structured For Loop
  for (int i = 0; i < max_count; i++) {
      process_item(i);
  }
  ```
- **While Loops**: General condition headers are structured into `while (cond) { ... }` blocks, eliminating spaghettified `goto` jump labels.

### Multi-Way Switch/Case Synthesis:
Sequential comparison cascades on a single register (`cmp eax, 1; je ...; cmp eax, 2; je ...`) or indirect jump tables are collapsed into structured C `switch (eax) { case 1: ...; case 2: ...; default: ...; }`.

---

## 3. 🧩 Struct Layout Inference & Type Propagation

When functions manipulate C structures or object instances passed via pointers (`rdi`, `rsi`, `rcx`, `rax`), assembly code accesses fields via relative byte offsets (`mov [rdi + 0x18], rax`).

SYMB collects all memory dereference patterns across a function, groups offsets by base pointer, estimates field boundaries, and automatically synthesizes C `typedef struct` definitions:

```c
// --- Inferred Structure Definitions ---
typedef struct {
    void* field_0x0;        // offset 0x0 (size: 8)
    uint64_t field_0x8;     // offset 0x8 (size: 8)
    uint32_t field_0x10;    // offset 0x10 (size: 4)
    uint8_t field_0x14;     // offset 0x14 (size: 1)
} struct_rdi_t;

__int64 sub_401120(struct_rdi_t* rdi) {
    rdi->field_0x8 = 0x1000;
    rdi->field_0x10 = 42;
    return 0;
}
```

---

## 4. 🔓 Dynamic Unicorn CPU Emulation Memory Unpacker

When binaries are protected by runtime packers (UPX, ASPack, Petite, custom XOR cryptors, Themida), static disassemblers only analyze the unpacking stub, unable to inspect the true application logic.

SYMB integrates **Unicorn CPU Emulator** (`unicorn`) to execute packed binaries in a virtual sandbox:

1. **Virtual Page Mapping**: Maps binary sections and allocates runtime stack memory (`0x70000000`).
2. **Instruction Tracing & Tail Jump Detection**: Emulates execution step-by-step with `UC_HOOK_CODE`. Detects when the instruction pointer jumps outside the unpacker stub into newly decrypted `.text` memory (the Original Entry Point or OEP).
3. **Memory Image Dumping**: Dumps the uncompressed, decrypted process memory, recalculates headers, and saves `<binary>.unpacked.bin`.

### CLI Command:
```bash
# Dynamically unpack a protected binary via Unicorn CPU emulation
symb unpack ./examples/01_ollvm_cff/CFF_win64.exe --max-instructions 50000
```

### JSON Response:
```json
{
  "status": "UNPACKED",
  "packer_detected": "UPX / High-Entropy Stub",
  "original_entropy": 7.8421,
  "unpacked_entropy": 5.1205,
  "original_entry_point": "0x401500",
  "recovered_oep": "0x401120",
  "emulated_instructions": 1420,
  "tail_jump_detected": true,
  "unpacked_output_file": "./examples/01_ollvm_cff/CFF_win64.exe.unpacked.bin"
}
```
The unpacked artifact can then be fed directly into `symb decompile` or `symb decompile-all` for clean, unhindered decompilation!
