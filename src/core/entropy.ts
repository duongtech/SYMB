import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface HighEntropyRegion {
  offset_hex: string;
  size_bytes: number;
  max_entropy: number;
  classification: string;
}

export interface EntropyScanResult {
  target: string;
  file_size_bytes: number;
  block_size_bytes: number;
  total_blocks_analyzed: number;
  min_entropy: number;
  max_entropy: number;
  mean_entropy: number;
  packed_blocks_count: number;
  packed_percentage: string;
  is_packed_or_encrypted: boolean;
  high_entropy_regions_count: number;
  high_entropy_regions: HighEntropyRegion[];
  ascii_entropy_histogram: string[];
  error?: string;
}

export async function runEntropyScan(
  targetPath: string,
  blockSize: number = 512
): Promise<EntropyScanResult> {
  const pythonScript = path.join(__dirname, "python_engines", "entropy_scanner_core.py");
  const absPath = path.resolve(targetPath);

  return new Promise((resolve, reject) => {
    const proc = spawn("python", [pythonScript, absPath, String(blockSize)]);

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
        return reject(new Error(`Entropy scanner failed (code ${code}): ${stderr}`));
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve(parsed);
      } catch (err) {
        reject(new Error(`Failed to parse entropy scanner output: ${err}\nRaw stdout: ${stdout}`));
      }
    });
  });
}
