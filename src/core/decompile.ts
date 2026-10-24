import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { SymbEvidence } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface DecompileResult {
  function_address: string;
  symbol_name?: string;
  instruction_count: number;
  basic_blocks_count: number;
  disassembly: Array<{
    address: string;
    mnemonic: string;
    op_str: string;
    bytes: string;
    string_xref?: string;
    iat_xref?: string;
  }>;
  decompiled_pseudocode: string;
  string_references: string[];
  iat_imports_used?: string[];
}

export async function runDecompile(
  binaryPath: string,
  functionAddress?: string,
  maxInstructions: number = 300
): Promise<SymbEvidence<DecompileResult>> {
  const startTime = Date.now();
  const pyScript = path.join(__dirname, "python_engines", "decompiler_core.py");
  const args = [pyScript, binaryPath];
  if (functionAddress) {
    args.push(functionAddress);
  }

  return new Promise((resolve) => {
    const child = spawn("python", args);
    let output = "";
    let errorOutput = "";

    child.stdout.on("data", (data) => {
      output += data.toString();
    });

    child.stderr.on("data", (data) => {
      errorOutput += data.toString();
    });

    child.on("close", () => {
      const elapsed = Date.now() - startTime;
      let result: DecompileResult;

      try {
        result = JSON.parse(output.trim());
      } catch {
        result = {
          function_address: functionAddress || "0x0",
          instruction_count: 0,
          basic_blocks_count: 0,
          disassembly: [],
          decompiled_pseudocode: `// Error decompiling function at ${functionAddress}\n${errorOutput}`,
          string_references: [],
          iat_imports_used: []
        };
      }

      resolve({
        evidence_id: `ev_dec_${Date.now()}`,
        timestamp: new Date().toISOString(),
        tool: "decompile_native_function",
        normalized_result: result,
        raw_solver_output: output || errorOutput,
        execution_time_ms: elapsed,
        limitations: []
      });
    });
  });
}
