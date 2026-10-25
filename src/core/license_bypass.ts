import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { LicenseBypassResult, SymbEvidence } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function runLicenseBypass(
  binaryPath: string,
  functionAddress?: string,
  forceSuccess: boolean = true,
  applyToFile: boolean = false,
  outputPath?: string
): Promise<SymbEvidence<LicenseBypassResult>> {
  const startTime = Date.now();
  const pyScript = path.join(__dirname, "python_engines", "license_bypass_core.py");
  const payload = JSON.stringify({
    binary_path: path.resolve(binaryPath),
    function_address: functionAddress,
    force_success: forceSuccess,
    apply_to_file: applyToFile,
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
      let result: LicenseBypassResult;
      const limitations: string[] = [];
      let targetIdentity: any = undefined;

      try {
        const parsed = JSON.parse(output.trim());
        result = {
          binary_path: parsed.binary_path || binaryPath,
          detected_license_checks: parsed.detected_license_checks || 0,
          decisions: parsed.decisions || [],
          patched_binary_path: parsed.patched_binary_path,
          runtime_ram_patch_ready: Boolean(parsed.runtime_ram_patch_ready),
          bypass_verification_status: parsed.bypass_verification_status || "SIMULATED"
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
          detected_license_checks: 0,
          decisions: [],
          runtime_ram_patch_ready: false,
          bypass_verification_status: "SIMULATED"
        };
        limitations.push(`License bypass engine error: ${errorOutput.trim() || output.trim() || "Process error"}`);
      }

      const isProven = result.bypass_verification_status === "APPLIED" || (result.decisions && result.decisions.length > 0);

      resolve({
        evidence_id: `ev_license_${Date.now()}`,
        timestamp: new Date().toISOString(),
        tool: "bypass_license_authorization",
        target_identity: targetIdentity,
        provenance: {
          engine: "capstone_smt_branch_inverter",
          version: "2.1.0",
          mode: "real-native"
        },
        confidence: isProven ? "STATICALLY_VERIFIED" : "HEURISTIC",
        normalized_result: result,
        raw_solver_output: output || errorOutput,
        execution_time_ms: elapsed,
        limitations,
        fail_closed: result.detected_license_checks === 0 && Boolean(errorOutput)
      });
    });

    child.stdin.write(payload);
    child.stdin.end();
  });
}
