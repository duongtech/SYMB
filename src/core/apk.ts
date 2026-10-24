import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface ApkDecompileResult {
  target: string;
  is_apk: boolean;
  is_dex: boolean;
  package_name: string;
  permissions_count: number;
  permissions: string[];
  activities: string[];
  services: string[];
  native_libraries: Array<{
    path: string;
    size_bytes: number;
    arch: string;
  }>;
  total_dex_files: number;
  total_classes_found: number;
  security_audit_alerts: string[];
  sample_string_constants: string[];
  reconstructed_java: string;
  error?: string;
}

export async function runApkDecompile(
  targetPath: string,
  maxClasses: number = 15
): Promise<ApkDecompileResult> {
  const pythonScript = path.join(__dirname, "python_engines", "apk_decompiler_core.py");
  const absPath = path.resolve(targetPath);

  return new Promise((resolve, reject) => {
    const proc = spawn("python", [pythonScript, absPath, String(maxClasses)]);

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
        return reject(new Error(`APK decompiler failed (code ${code}): ${stderr}`));
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve(parsed);
      } catch (err) {
        reject(new Error(`Failed to parse APK decompiler output: ${err}\nRaw stdout: ${stdout}`));
      }
    });
  });
}
