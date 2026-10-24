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
