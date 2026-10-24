export interface SymbEvidence<T = any> {
  evidence_id: string;
  timestamp: string;
  tool: string;
  normalized_result: T;
  raw_solver_output: string;
  execution_time_ms: number;
  limitations: string[];
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
