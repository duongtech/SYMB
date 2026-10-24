import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { SymbEvidence } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface CryptoScanResult {
  binary_path: string;
  total_primitives_found: number;
  primitives: Array<{
    primitive: string;
    algorithm: string;
    type: string;
    file_offset: string;
    matched_bytes_hex: string;
  }>;
}

export async function runCryptoScan(
  binaryPath: string
): Promise<SymbEvidence<CryptoScanResult>> {
  const startTime = Date.now();
  const pyScript = path.join(__dirname, "python_engines", "crypto_detector_core.py");

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
      let result: CryptoScanResult;

      try {
        result = JSON.parse(output.trim());
      } catch {
        result = {
          binary_path: binaryPath,
          total_primitives_found: 0,
          primitives: []
        };
      }

      resolve({
        evidence_id: `ev_crypto_${Date.now()}`,
        timestamp: new Date().toISOString(),
        tool: "detect_crypto_primitives",
        normalized_result: result,
        raw_solver_output: output || errorOutput,
        execution_time_ms: elapsed,
        limitations: []
      });
    });
  });
}
