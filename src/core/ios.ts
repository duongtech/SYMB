import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface IosDecompileResult {
  target: string;
  is_ipa: boolean;
  is_macho: boolean;
  bundle_id: string;
  permissions_count: number;
  permissions: string[];
  macho_analysis: {
    architecture: string;
    filetype: string;
    load_commands_count: number;
    segments: string[];
    fairplay_drm_encrypted: boolean;
    crypt_id: number;
    imported_frameworks: string[];
    jailbreak_detection_alerts: string[];
    discovered_classes: string[];
    discovered_selectors: string[];
    executable_path: string;
  };
  reconstructed_objc_header: string;
  error?: string;
}

export async function runIosDecompile(targetPath: string): Promise<IosDecompileResult> {
  const pythonScript = path.join(__dirname, "python_engines", "ios_ipa_decompiler_core.py");
  const absPath = path.resolve(targetPath);

  return new Promise((resolve, reject) => {
    const proc = spawn("python", [pythonScript, absPath]);

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
        return reject(new Error(`iOS decompiler failed (code ${code}): ${stderr}`));
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve(parsed);
      } catch (err) {
        reject(new Error(`Failed to parse iOS decompiler output: ${err}\nRaw stdout: ${stdout}`));
      }
    });
  });
}
