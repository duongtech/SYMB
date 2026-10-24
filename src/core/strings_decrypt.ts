import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface StringDecryptResult {
  binary_path: string;
  total_encrypted_strings_recovered: number;
  total_base64_strings_decoded: number;
  recovered_strings: Array<{
    algorithm: string;
    key_hex: string;
    indicator_hit: string;
    decrypted_snippet: string;
    file_offset: string;
  }>;
  decoded_base64_strings: Array<{
    type: string;
    original_b64: string;
    decoded_plaintext: string;
  }>;
  error?: string;
}

export async function runStringDecrypt(
  binaryPath: string,
  maxCandidates: number = 20
): Promise<StringDecryptResult> {
  const pythonScript = path.join(__dirname, "python_engines", "string_decryptor_core.py");
  const absPath = path.resolve(binaryPath);

  return new Promise((resolve, reject) => {
    const proc = spawn("python", [pythonScript, absPath, String(maxCandidates)]);

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
        return reject(new Error(`String decryptor failed (code ${code}): ${stderr}`));
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve(parsed);
      } catch (err) {
        reject(new Error(`Failed to parse string decryptor output: ${err}\nRaw stdout: ${stdout}`));
      }
    });
  });
}
