import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface ProtectionsResult {
  binary_path: string;
  format: string;
  protection_risk_score: number;
  protection_risk_level: string;
  detected_packers: string[];
  anti_debugging_apis: string[];
  anti_vm_signatures: string[];
  heuristics: {
    timing_trap_rdtsc: boolean;
    peb_direct_read: boolean;
  };
  analyzed_sections: string[];
  error?: string;
}

export async function runProtectionsScan(binary_path: string): Promise<ProtectionsResult> {
  const pythonScript = path.join(__dirname, "python_engines", "protections_detector_core.py");
  const absBinaryPath = path.resolve(binary_path);

  return new Promise((resolve, reject) => {
    const proc = spawn("python", [pythonScript, absBinaryPath]);

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      if (code !== 0 && !stdout) {
        return reject(new Error(`Protections detector failed (code ${code}): ${stderr}`));
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve(parsed);
      } catch (err) {
        reject(new Error(`Failed to parse protections output: ${err}\nRaw stdout: ${stdout}`));
      }
    });
  });
}
