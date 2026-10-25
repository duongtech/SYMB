import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";
import { BinaryPatchResult, SymbEvidence } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface PatchRequestItem {
  address?: string | number;
  offset?: string | number;
  bytes_hex: string;
  description?: string;
  is_rva?: boolean;
  is_va?: boolean;
}

export async function runBinaryPatcher(
  binaryPath: string,
  patches: PatchRequestItem[],
  outputPath?: string,
  createBackup: boolean = true,
  recalculatePeChecksum: boolean = true
): Promise<SymbEvidence<BinaryPatchResult>> {
  const startTime = Date.now();
  const pyScript = path.join(__dirname, "python_engines", "binary_patcher_core.py");
  const payload = JSON.stringify({
    binary_path: path.resolve(binaryPath),
    patches,
    output_path: outputPath ? path.resolve(outputPath) : undefined,
    create_backup: createBackup,
    recalculate_pe_checksum: recalculatePeChecksum
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
      let result: BinaryPatchResult;
      const limitations: string[] = [];
      let targetIdentity: any = undefined;

      try {
        const parsed = JSON.parse(output.trim());
        result = {
          binary_path: parsed.binary_path || binaryPath,
          output_path: parsed.output_path || outputPath || binaryPath,
          backup_path: parsed.backup_path,
          patches_applied: parsed.patches_applied || 0,
          diff_entries: parsed.diff_entries || [],
          pe_checksum_updated: Boolean(parsed.pe_checksum_updated),
          old_pe_checksum: parsed.old_pe_checksum,
          new_pe_checksum: parsed.new_pe_checksum,
          success: Boolean(parsed.success)
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
          output_path: outputPath || binaryPath,
          patches_applied: 0,
          diff_entries: [],
          pe_checksum_updated: false,
          success: false
        };
        limitations.push(`Binary patcher engine error: ${errorOutput.trim() || output.trim() || "Process error"}`);
      }

      resolve({
        evidence_id: `ev_patch_${Date.now()}`,
        timestamp: new Date().toISOString(),
        tool: "patch_binary_executable",
        target_identity: targetIdentity,
        provenance: {
          engine: "pefile_lief_capstone_patcher",
          version: "2.0.0",
          mode: "real-native"
        },
        confidence: result.success ? "STATICALLY_VERIFIED" : "HEURISTIC",
        normalized_result: result,
        raw_solver_output: output || errorOutput,
        execution_time_ms: elapsed,
        limitations,
        fail_closed: !result.success
      });
    });

    child.stdin.write(payload);
    child.stdin.end();
  });
}
