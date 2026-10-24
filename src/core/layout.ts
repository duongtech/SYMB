import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { SymbEvidence } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface BinaryLayoutResult {
  format: string;
  architecture?: string;
  file_size_bytes: number;
  entry_point?: string;
  image_base?: string;
  mitigations?: Record<string, boolean>;
  sections_count?: number;
  sections?: Array<{
    name: string;
    virtual_address: string;
    raw_size: number;
    entropy: number;
    packed_risk: string;
  }>;
  max_entropy?: number;
  likely_packed?: boolean;
  imports?: Record<string, string[]>;
  exports?: Array<{ name: string; address: string }>;
}

export async function runInspectLayout(
  binaryPath: string
): Promise<SymbEvidence<BinaryLayoutResult>> {
  const startTime = Date.now();
  const pyScript = path.join(__dirname, "python_engines", "binary_layout_core.py");

  return new Promise((resolve) => {
    const child = spawn("python", [pyScript, binaryPath]);
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
      let result: BinaryLayoutResult;

      try {
        result = JSON.parse(output.trim());
      } catch {
        result = {
          format: "Unknown",
          file_size_bytes: 0
        };
      }

      resolve({
        evidence_id: `ev_layout_${Date.now()}`,
        timestamp: new Date().toISOString(),
        tool: "inspect_binary_layout",
        normalized_result: result,
        raw_solver_output: output || errorOutput,
        execution_time_ms: elapsed,
        limitations: []
      });
    });
  });
}
