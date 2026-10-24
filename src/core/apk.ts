import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface ApkSignatureSigner {
  cert_sha256: string;
  cert_sha1: string;
  subject_dn: string;
  issuer_dn: string;
  validity: string;
}

export interface ApkSignatureInfo {
  schemes: {
    v1: boolean;
    v2: boolean;
    v3: boolean;
  };
  is_signed: boolean;
  is_debug_keystore: boolean;
  signers: ApkSignatureSigner[];
}

export interface ApkVulnerability {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
}

export interface ApkSecretFinding {
  type: string;
  match: string;
  severity: string;
}

export interface ApkNativeLibrary {
  path: string;
  size_bytes: number;
  arch: string;
  jni_exports: string[];
  anti_debug_hooks: string[];
}

export interface ApkDecompileResult {
  target: string;
  is_apk: boolean;
  is_dex: boolean;
  package_name: string;
  permissions_count: number;
  permissions: string[];
  activities: string[];
  services: string[];
  receivers?: string[];
  providers?: string[];
  native_libraries: ApkNativeLibrary[];
  total_dex_files: number;
  total_classes_found: number;
  security_audit_alerts: string[];
  vulnerabilities?: ApkVulnerability[];
  signature_info?: ApkSignatureInfo;
  secret_hunting_results?: ApkSecretFinding[];
  sample_string_constants: string[];
  reconstructed_java: string;
  passes_summary?: {
    pass1_manifest: string;
    pass2_signature: string;
    pass3_dalvik_lifter: string;
    pass4_secret_hunt: string;
    pass5_native_jni: string;
  };
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
