import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { BranchSolverResult, SymbEvidence } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function runBranchSolver(
  binaryPath: string,
  targetAddress: string,
  avoidAddresses: string[] = [],
  inputLength: number = 32
): Promise<SymbEvidence<BranchSolverResult>> {
  const startTime = Date.now();
  const pyScript = path.join(__dirname, "python_engines", "z3_solver_core.py");
  const payload = JSON.stringify({
    binary_path: path.resolve(binaryPath),
    target_address: targetAddress,
    avoid_addresses: avoidAddresses,
    input_length: inputLength
  });

  return new Promise((resolve) => {
    const child = spawn("python", [pyScript]);
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
      let result: BranchSolverResult;
      const limitations: string[] = [];

      try {
        result = JSON.parse(output.trim());
      } catch {
        result = {
          satisfiable: false,
          status: "ERROR",
          symbolic_path_depth: 0,
          constraints_count: 0
        };
      }

      if (result.status === "ERROR") {
        limitations.push(`Solver engine error: ${errorOutput.trim() || output.trim() || "Python solver process failed to produce valid JSON"}`);
      } else if (result.status === "UNSAT") {
        limitations.push("Target branch reachability constraints are unsatisfiable (no valid input exists)");
      }

      resolve({
        evidence_id: `ev_solve_${Date.now()}`,
        timestamp: new Date().toISOString(),
        tool: "solve_branch_reachability",
        normalized_result: result,
        raw_solver_output: output || errorOutput,
        execution_time_ms: elapsed,
        limitations
      });
    });

    // Write payload cleanly to stdin
    child.stdin.write(payload);
    child.stdin.end();
  });
}
