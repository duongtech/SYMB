import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { HotPatchResult, SymbEvidence } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function runHotPatch(
  pid: number,
  memoryAddress: string,
  patchBytesHex: string,
  expectedOriginalBytes?: string
): Promise<SymbEvidence<HotPatchResult>> {
  const startTime = Date.now();
  const pyScript = path.join(__dirname, "python_engines", "trampoline_core.py");
  const payload = JSON.stringify({
    pid,
    memory_address: memoryAddress,
    patch_bytes_hex: patchBytesHex,
    expected_original_bytes: expectedOriginalBytes
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
      let result: HotPatchResult;
      const limitations: string[] = [];

      try {
        const parsed = JSON.parse(output.trim());
        result = {
          success: Boolean(parsed.success),
          pid: parsed.pid || pid,
          memory_address: parsed.memory_address || memoryAddress,
          bytes_written: Number(parsed.bytes_written) || 0,
          previous_bytes: parsed.previous_bytes || expectedOriginalBytes || "unavailable"
        };
        if (!result.success && parsed.error) {
          limitations.push(parsed.error);
        }
      } catch {
        result = {
          success: false,
          pid,
          memory_address: memoryAddress,
          bytes_written: 0,
          previous_bytes: expectedOriginalBytes || "unknown"
        };
        limitations.push(`Failed executing live memory patcher: ${errorOutput.trim() || output.trim() || "Process error"}`);
      }

      resolve({
        evidence_id: `ev_patch_${Date.now()}`,
        timestamp: new Date().toISOString(),
        tool: "hot_patch_live_memory",
        normalized_result: result,
        raw_solver_output: output || errorOutput || `[RAM TRAMPOLINE] Completed for PID ${pid}`,
        execution_time_ms: elapsed,
        limitations
      });
    });
  });
}
