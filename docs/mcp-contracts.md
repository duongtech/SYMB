# SYMB MCP Runtime Contracts & Specification

This document details the tool schemas, inputs, outputs, and Canonical Evidence records exposed by SYMB MCP server.

## Evidence Model

Every tool returns an Evidence record compliant with the Model Context Protocol structured content standard:

```typescript
interface SymbEvidence<T> {
  evidence_id: string;        // SHA-256 fingerprint of the analysis state
  timestamp: string;          // ISO-8601 execution time
  tool: string;               // Name of the executing tool
  normalized_result: T;       // Structured high-level result for Agent reasoning
  raw_solver_output: string;  // Raw solver diagnostics (Z3 / angr stdout)
  execution_time_ms: number;  // Solver execution duration
  limitations: string[];      // Any path pruning or timeout constraints encountered
}
```

---

## Tool 1: `unflatten_control_flow`

Dỡ bỏ mã làm rối luồng điều khiển OLLVM Control Flow Flattening (CFF).

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string", "description": "Absolute path to the target binary (PE, ELF, Mach-O)" },
    "function_address": { "type": "string", "description": "Hex address (e.g. '0x401500') or function symbol" },
    "timeout_seconds": { "type": "number", "default": 60, "description": "Maximum solver search budget" }
  },
  "required": ["binary_path", "function_address"]
}
```

### Output Schema
```json
{
  "type": "object",
  "properties": {
    "dispatcher_address": { "type": "string" },
    "state_variable": { "type": "string" },
    "recovered_blocks_count": { "type": "number" },
    "unflattened_pseudocode": { "type": "string" },
    "clean_cfg": { "type": "object" }
  }
}
```

---

## Tool 2: `solve_branch_reachability`

Sử dụng angr và Z3 SMT Solver để tìm chuỗi byte đầu vào thỏa mãn điều kiện nhảy tới target_address.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string", "description": "Absolute path to target binary" },
    "target_address": { "type": "string", "description": "Hex address of the desired branch (e.g. '0x401820')" },
    "avoid_addresses": { "type": "array", "items": { "type": "string" }, "description": "Hex addresses of failure paths to prune" },
    "input_length": { "type": "number", "default": 32, "description": "Expected symbolic input byte length" }
  },
  "required": ["binary_path", "target_address"]
}
```

### Output Schema
```json
{
  "type": "object",
  "properties": {
    "satisfiable": { "type": "boolean" },
    "status": { "type": "string", "enum": ["SAT", "UNSAT", "TIMEOUT"] },
    "concrete_input_ascii": { "type": "string" },
    "concrete_input_hex": { "type": "string" },
    "symbolic_path_depth": { "type": "number" }
  }
}
```

---

## Tool 3: `trace_symbolic_taint`

Thực hiện phân tích vết dữ liệu biểu trưng (Taint Analysis) để tìm kiếm các điểm nghẽn và lỗ hổng tràn bộ nhớ.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string" },
    "source_symbol": { "type": "string", "description": "Entry point or input buffer symbol (e.g. 'argv[1]', 'read')" },
    "sink_symbol": { "type": "string", "description": "Target sink function (e.g. 'strcpy', 'system', 'memcpy')" }
  },
  "required": ["binary_path", "source_symbol", "sink_symbol"]
}
```

---

## Tool 4: `hot_patch_live_memory`

Can thiệp trực tiếp vào RAM của tiến trình đang chạy mà không cần sửa file trên đĩa (Zero-Disk Patching).

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "pid": { "type": "number", "description": "Target Process ID" },
    "memory_address": { "type": "string", "description": "Target virtual address or relative module offset" },
    "patch_bytes_hex": { "type": "string", "description": "Hex bytes to write (e.g. '90 90' or 'B8 01 00 00 00 C3')" },
    "expected_original_bytes": { "type": "string", "description": "Verification check to prevent accidental corruption" }
  },
  "required": ["pid", "memory_address", "patch_bytes_hex"]
}
```


---

## Tool 5: `decompile_native_function`

Dịch ngược tức thời mã máy thành mã giả C (C Pseudocode), phân rã khối cơ bản (basic blocks) và liên kết chuỗi hằng số (.rdata XREFs) với tốc độ mili-giây.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string", "description": "Absolute path to binary (PE/EXE, ELF, Mach-O)" },
    "function_address": { "type": "string", "description": "Hex address (e.g. '0x1400014e0') or entry point" },
    "max_instructions": { "type": "number", "default": 250, "description": "Maximum instructions to lift" }
  },
  "required": ["binary_path"]
}
```

---

## Tool 6: `inspect_binary_layout`

Quét cấu trúc PE/ELF, các lớp bảo vệ (ASLR, DEP/NX, SafeSEH, CFG), bảng hàm Import/Export, và đo lường độ hỗn loạn entropy Shannon trên từng section để phát hiện packer (UPX, Themida, VMProtect).

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string", "description": "Absolute path to target binary" }
  },
  "required": ["binary_path"]
}
```

---

## Tool 7: `detect_crypto_primitives`

Tầm soát và định vị các cấu trúc mật mã trong binary: S-Box AES Rijndael, Hằng số SHA-256 / MD5, Bảng CRC32, ChaCha20 constant, và Base64 alphabet để phục vụ bài toán nghịch đảo key SMT.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string", "description": "Absolute path to target binary" }
  },
  "required": ["binary_path"]
}
```


---

## Tool 8: `detect_binary_protections`

Quét và phát hiện các lớp bảo vệ nhị phân (Anti-Debugging, Anti-VM, Timing Traps, Packers).

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string", "description": "Absolute path to target binary" }
  },
  "required": ["binary_path"]
}
```

---

## Tool 9: `decompile_apk_package`

Phân rã gói Android APK và Dalvik DEX bytecode. Giải mã bảng tài nguyên `resources.arsc`, trích xuất Manifest quyền hạn, kiểm tra chứng chỉ X.509 và dịch ngược bytecode sang Java class.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "target_path": { "type": "string", "description": "Absolute path to APK or DEX file" },
    "max_classes": { "type": "number", "default": 15, "description": "Maximum classes to decompile" }
  },
  "required": ["target_path"]
}
```

---

## Tool 10: `decrypt_obfuscated_strings`

Giải mã chuỗi ẩn giấu (Single-byte XOR, Cycling XOR, Rolling Key XOR, Base64) trên các file thực thi PE, ELF, APK, và .so.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string", "description": "Absolute path to binary" },
    "max_candidates": { "type": "number", "default": 20, "description": "Maximum candidate strings to return" }
  },
  "required": ["binary_path"]
}
```

---

## Tool 11: `decompile_ios_ipa_package`

Phân rã gói Apple iOS IPA và ARM64 Mach-O. Kiểm tra FairPlay DRM (`cryptid`), phát hiện Anti-Jailbreak và tái tạo cấu trúc Objective-C / Swift.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "target_path": { "type": "string", "description": "Absolute path to iOS IPA or Mach-O" }
  },
  "required": ["target_path"]
}
```

---

## Tool 12: `scan_byte_entropy`

Tính toán biểu đồ nhiệt độ hỗn loạn Shannon entropy trên các khối 256/512 byte để phát hiện shellcode mã hóa và payload ẩn giấu.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string", "description": "Absolute path to binary file" },
    "block_size": { "type": "number", "default": 512, "description": "Block size for entropy calculation" }
  },
  "required": ["binary_path"]
}
```

---

## Tool 13: `trace_binary_xrefs`

Xây dựng đồ thị gọi hàm (Call Graph) toàn chương trình và giải mã liên kết chéo (XREFs) giữa địa chỉ lệnh thực thi và hằng số chuỗi.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string", "description": "Absolute path to binary" },
    "limit": { "type": "number", "default": 100, "description": "Max call edges to return" }
  },
  "required": ["binary_path"]
}
```

---

## Tool 14: `optimize_large_media_buffer`

Tối ưu hóa bộ nhớ đệm đa phương tiện và file nhị phân dung lượng lớn cho AI Agents. Bóc tách luồng âm thanh `.m4a`, nén video về ngưỡng bộ nhớ và stream memory dump nhiều GB bằng `mmap` không tốn RAM.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "file_path": { "type": "string", "description": "Path to media file (.mp4, .mov) or memory dump (.bin, .dmp)" },
    "target_max_mb": { "type": "number", "default": 50, "description": "Target memory budget in MB" }
  },
  "required": ["file_path"]
}
```

---

## Tool 15: `dynamically_unpack_binary`

Giải mã động packer nhị phân (UPX, Themida, crypters) bằng CPU emulator Unicorn. Theo dõi vết thực thi, phát hiện cú nhảy đuôi (tail jump) thoát khỏi stub và dump bộ nhớ OEP đã giải mã.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "binary_path": { "type": "string", "description": "Absolute path to packed binary (PE, ELF)" },
    "max_instructions": { "type": "number", "default": 50000, "description": "Maximum CPU emulation steps" }
  },
  "required": ["binary_path"]
}
```

---

## Tool 16: `hot_patch_live_memory`

Tiêm trampoline bộ nhớ nguyên tử vào tiến trình đang chạy mà không cần sửa đổi tệp thực thi trên đĩa.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "pid": { "type": "number", "description": "Target process ID" },
    "memory_address": { "type": "string", "description": "Hex address to hook" },
    "patch_bytes_hex": { "type": "string", "description": "Hex patch bytes" }
  },
  "required": ["pid", "memory_address", "patch_bytes_hex"]
}
```
