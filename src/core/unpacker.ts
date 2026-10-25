import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface DynamicUnpackResult {
  status: "UNPACKED" | "COMPLETED" | "FAILED";
  packer_detected: string;
  is_packed: boolean;
  original_entropy: number;
  unpacked_entropy: number;
  original_entry_point: string;
  recovered_oep: string;
  emulated_instructions: number;
  tail_jump_detected: boolean;
  unpacked_output_file: string;
  unpacked_payload_size_bytes: number;
  agent_guidance: string;
  error?: string;
}

export async function runDynamicUnpacker(
  binaryPath: string,
  outputPath?: string,
  maxInstructions: number = 50000
): Promise<DynamicUnpackResult> {
  const pythonScript = path.join(__dirname, "python_engines", "dynamic_unpacker_core.py");
  const absPath = path.resolve(binaryPath);
  const args = [pythonScript, absPath];
  if (outputPath) {
    args.push(path.resolve(outputPath));
  }

  return new Promise((resolve, reject) => {
    const proc = spawn("python", args);

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
        return reject(new Error(`Dynamic unpacker failed (code ${code}): ${stderr}`));
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve(parsed);
      } catch (err) {
        reject(new Error(`Failed to parse unpacker output: ${err}\nRaw stdout: ${stdout}`));
      }
    });
  });
}
