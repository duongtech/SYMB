import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface CallEdge {
  caller_address: string;
  target: string;
  is_indirect: boolean;
  resolved_api?: string | null;
}

export interface StringXref {
  instruction_address: string;
  string_address: string;
  string_literal: string;
}

export interface TopTarget {
  target: string;
  caller_references: number;
}

export interface XrefAnalysisResult {
  format: string;
  entry_point?: string;
  total_call_instructions: number;
  total_string_xrefs: number;
  top_called_targets?: TopTarget[];
  sample_call_edges: CallEdge[];
  sample_string_xrefs?: StringXref[];
  error?: string;
}

export async function runXrefAnalysis(targetPath: string): Promise<XrefAnalysisResult> {
  const pythonScript = path.join(__dirname, "python_engines", "xref_graph_core.py");
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
        return reject(new Error(`XREF analysis failed (code ${code}): ${stderr}`));
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve(parsed);
      } catch (err) {
        reject(new Error(`Failed to parse XREF output: ${err}\nRaw stdout: ${stdout}`));
      }
    });
  });
}
