import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { UnflattenResult, SymbEvidence } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function runUnflatten(
  binaryPath: string,
  functionAddress: string,
  timeoutSeconds: number = 60
): Promise<SymbEvidence<UnflattenResult>> {
  const startTime = Date.now();
  const pyScript = path.join(__dirname, "python_engines", "unflatten_core.py");
  const payload = JSON.stringify({
    binary_path: binaryPath,
    function_address: functionAddress,
    timeout_seconds: timeoutSeconds
  });

  return new Promise((resolve) => {
    const child = spawn("python", [pyScript, payload]);
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
      let result: UnflattenResult;
      const limitations: string[] = [];

      try {
        result = JSON.parse(output.trim());
      } catch {
        result = {
          dispatcher_address: functionAddress,
          state_variable: "unknown",
          recovered_blocks_count: 0,
          unflattened_pseudocode: `// [SYMB ERROR] Failed to parse unflatten output for ${functionAddress}\n// Output: ${errorOutput.trim() || output.trim() || "Process failed"}`,
          clean_cfg: {
            nodes: [
              { id: "entry", label: "Entry", address: functionAddress }
            ],
            edges: []
          }
        };
        limitations.push(`Unflatten execution error: ${errorOutput.trim() || output.trim() || "Failed to produce valid JSON"}`);
      }

      resolve({
        evidence_id: `ev_unflat_${Date.now()}`,
        timestamp: new Date().toISOString(),
        tool: "unflatten_control_flow",
        normalized_result: result,
        raw_solver_output: output || errorOutput,
        execution_time_ms: elapsed,
        limitations
      });
    });
  });
}
