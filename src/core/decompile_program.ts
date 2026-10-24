import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface DecompileProgramResult {
  binary_path: string;
  total_functions_discovered: number;
  total_functions_decompiled: number;
  functions: Array<{
    address: string;
    name: string;
    instruction_count: number;
    basic_blocks_count: number;
    pseudocode: string;
  }>;
  reconstructed_c_translation: string;
  error?: string;
}

export async function runDecompileProgram(binary_path: string, max_functions: number = 10): Promise<DecompileProgramResult> {
  const pythonScript = path.join(__dirname, "python_engines", "decompile_program_core.py");
  const absBinaryPath = path.resolve(binary_path);

  return new Promise((resolve, reject) => {
    const proc = spawn("python", [pythonScript, absBinaryPath, String(max_functions)]);

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
        return reject(new Error(`Program decompiler failed (code ${code}): ${stderr}`));
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve(parsed);
      } catch (err) {
        reject(new Error(`Failed to parse program decompiler output: ${err}\nRaw stdout: ${stdout}`));
      }
    });
  });
}
