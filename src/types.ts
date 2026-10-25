export interface TargetIdentity {
  path: string;
  sha256?: string;
  md5?: string;
  size_bytes?: number;
  format?: "PE" | "ELF" | "MACH-O" | "DEX" | "RAW" | "ZIP" | "UNKNOWN";
  arch?: "x86" | "x64" | "arm" | "arm64" | "dalvik" | "unknown";
}

export interface EngineProvenance {
  engine: string;
  version?: string;
  mode: "real-native" | "symbolic-smt" | "emulated-cpu" | "ast-lifter";
}

export interface SymbEvidence<T = any> {
  evidence_id: string;
  timestamp: string;
  tool: string;
  target_identity?: TargetIdentity;
  provenance?: EngineProvenance;
  confidence?: "MATHEMATICALLY_PROVEN" | "STATICALLY_VERIFIED" | "DYNAMICALLY_OBSERVED" | "HEURISTIC";
  normalized_result: T;
  raw_solver_output: string;
  execution_time_ms: number;
  limitations: string[];
  unknowns?: string[];
  fail_closed?: boolean;
}

export interface PatchDiffEntry {
  offset_hex: string;
  rva_hex?: string;
  original_bytes: string;
  patched_bytes: string;
  description: string;
}

export interface BinaryPatchResult {
  binary_path: string;
  output_path: string;
  backup_path?: string;
  patches_applied: number;
  diff_entries: PatchDiffEntry[];
  pe_checksum_updated: boolean;
  old_pe_checksum?: string;
  new_pe_checksum?: string;
  success: boolean;
}

export interface UnflattenResult {
  dispatcher_address?: string;
  state_variable?: string;
  recovered_blocks_count: number;
  unflattened_pseudocode: string;
  clean_cfg: {
    nodes: Array<{ id: string; label: string; address?: string }>;
    edges: Array<{ from: string; to: string; condition?: string }>;
  };
}

export interface BranchSolverResult {
  satisfiable: boolean;
  status: "SAT" | "UNSAT" | "TIMEOUT" | "ERROR";
  concrete_input_ascii?: string;
  concrete_input_hex?: string;
  symbolic_path_depth: number;
  constraints_count: number;
}

export interface TaintResult {
  vulnerable: boolean;
  sink_reached: boolean;
  path_summary: string;
  tainted_registers: string[];
}

export interface HotPatchResult {
  success: boolean;
  pid: number;
  memory_address: string;
  bytes_written: number;
  previous_bytes?: string;
}

export interface AntiDebugDetection {
  technique: string;
  address: string;
  instruction: string;
  patch_suggestion: string;
  rva?: string;
  file_offset?: string;
}

export interface AntiDebugResult {
  binary_path: string;
  total_detections: number;
  detections: AntiDebugDetection[];
  auto_patched: boolean;
  patched_binary_path?: string;
  patch_diff_summary: string[];
}

export interface LicenseBranchDecision {
  function_address: string;
  conditional_jump_address: string;
  file_offset?: string;
  mnemonic: string;
  target_success_address: string;
  recommended_patch: "FORCE_JUMP" | "NOP_OUT" | "INVERT_CONDITION" | "RETURN_TRUE";
  patch_bytes_hex: string;
}

export interface LicenseBypassResult {
  binary_path: string;
  detected_license_checks: number;
  decisions: LicenseBranchDecision[];
  patched_binary_path?: string;
  runtime_ram_patch_ready: boolean;
  bypass_verification_status: "READY" | "APPLIED" | "SIMULATED";
}

export interface FridaHookResult {
  target: string;
  platform: "android" | "ios" | "windows" | "linux";
  script_type: "ssl_unpinning" | "root_jailbreak_bypass" | "anti_debug_runtime_cloak" | "crypto_tracer" | "api_logger" | "custom_interceptor";
  generated_script_javascript: string;
  spawn_command: string;
  features_included: string[];
}

export interface GhidraDecompileResult {
  binary_path: string;
  functions_decompiled: number;
  entry_point?: string;
  decompiled_c_code: string;
  source_provenance: "GHIDRA_HEADLESS_NATIVE" | "CAPSTONE_AST_FALLBACK";
  function_signatures: string[];
}

