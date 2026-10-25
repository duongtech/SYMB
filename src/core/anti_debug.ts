import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { AntiDebugResult, SymbEvidence } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function runAntiDebugAnnihilator(
  binaryPath: string,
  autoPatch: boolean = false,
  outputPath?: string
): Promise<SymbEvidence<AntiDebugResult>> {
  const startTime = Date.now();
  const pyScript = path.join(__dirname, "python_engines", "anti_debug_core.py");
  const payload = JSON.stringify({
    binary_path: path.resolve(binaryPath),
    auto_patch: autoPatch,
    output_path: outputPath ? path.resolve(outputPath) : undefined
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
      let result: AntiDebugResult;
      const limitations: string[] = [];
      let targetIdentity: any = undefined;

      try {
        const parsed = JSON.parse(output.trim());
        result = {
          binary_path: parsed.binary_path || binaryPath,
          total_detections: parsed.total_detections || 0,
          detections: parsed.detections || [],
          auto_patched: Boolean(parsed.auto_patched),
          patched_binary_path: parsed.patched_binary_path,
          patch_diff_summary: parsed.patch_diff_summary || []
        };
        if (parsed.limitations && Array.isArray(parsed.limitations)) {
          limitations.push(...parsed.limitations);
        }
        if (parsed.target_identity) {
          targetIdentity = parsed.target_identity;
        }
      } catch {
        result = {
          binary_path: binaryPath,
          total_detections: 0,
          detections: [],
          auto_patched: false,
          patch_diff_summary: []
        };
        limitations.push(`Anti-debug engine error: ${errorOutput.trim() || output.trim() || "Process error"}`);
      }

      const isVerified = result.total_detections > 0 || result.auto_patched;

      resolve({
        evidence_id: `ev_antidebug_${Date.now()}`,
        timestamp: new Date().toISOString(),
        tool: "neutralize_anti_debugging",
        target_identity: targetIdentity,
        provenance: {
          engine: "pefile_inline_opcode_scanner",
          version: "2.1.0",
          mode: "real-native"
        },
        confidence: isVerified ? "STATICALLY_VERIFIED" : "HEURISTIC",
        normalized_result: result,
        raw_solver_output: output || errorOutput,
        execution_time_ms: elapsed,
        limitations,
        fail_closed: result.total_detections === 0 && Boolean(errorOutput)
      });
    });

    child.stdin.write(payload);
    child.stdin.end();
  });
}
