import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface StoryboardScene {
  scene_index: number;
  timestamp_seconds: number;
  timestamp_formatted: string;
  frame_preview_path: string;
  recommended_typography_zone: string;
  color_hierarchy_spec: {
    headline: string;
    key_benefit: string;
    accent_warning: string;
    proof_metric: string;
  };
}

export interface MediaOptimizerResult {
  status: string;
  file_type: "VIDEO_MEDIA" | "LARGE_BINARY_STREAM";
  original_file?: string;
  original_size_mb?: number;
  target_max_mb?: number;
  is_downsampled?: boolean;
  optimized_file?: string;
  optimized_size_mb?: number;
  isolated_audio_track?: {
    path: string;
    size_mb: number;
    note: string;
  };
  extracted_keyframes_count?: number;
  storyboard_plan?: StoryboardScene[];
  file_path?: string;
  file_size_mb?: number;
  chunk_size_mb?: number;
  total_chunks?: number;
  streamed_chunks_preview?: Array<{
    chunk_index: number;
    offset_hex: string;
    size_bytes: number;
    sample_header_hex: string;
  }>;
  agent_guidance: string;
  error?: string;
}

export async function runMediaOptimizer(
  filePath: string,
  targetMaxMb: number = 50
): Promise<MediaOptimizerResult> {
  const pythonScript = path.join(__dirname, "python_engines", "large_media_optimizer_core.py");
  const absPath = path.resolve(filePath);

  return new Promise((resolve, reject) => {
    const proc = spawn("python", [pythonScript, absPath, String(targetMaxMb)]);

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
        return reject(new Error(`Media optimizer failed (code ${code}): ${stderr}`));
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve(parsed);
      } catch (err) {
        reject(new Error(`Failed to parse media optimizer output: ${err}\nRaw stdout: ${stdout}`));
      }
    });
  });
}
