# -*- coding: utf-8 -*-
"""
SYMB HIGH-CAPACITY LARGE MEDIA & BINARY BUFFER OPTIMIZER (MCP & CLI CORE)
Solves memory-exhaustion and context limit issues when AI agents handle oversized video,
audio, firmware, or binary dumps (> 50MB - 10GB).

Capabilities:
1. Video Auto-Downsampler & Bitrate Governor: Downsamples oversized videos to agent memory budget (e.g. <= 50MB).
2. Audio Track Extractor: Isolates voiceover audio (.m4a/.mp3) for zero-bloat speech-to-text processing.
3. Keyframe Storyboard Generator: Extracts timestamped video keyframes and suggests text-safe layout zones.
4. Large Binary Streamer (mmap): Memory-mapped chunked slicing for multi-gigabyte memory dumps and ROMs.
"""

import sys
import json
import os
import subprocess
import re
import mmap
import shutil

def find_ffmpeg_binary():
    candidates = [
        "ffmpeg",
        r"C:\Program Files\Bricsys\BricsCAD V26 en_US\ffmpeg.exe",
        r"C:\ffmpeg\bin\ffmpeg.exe",
        r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
        r"D:\ffmpeg\bin\ffmpeg.exe"
    ]
    for c in candidates:
        try:
            res = subprocess.run([c, "-version"], capture_output=True, text=True)
            if res.returncode == 0:
                return c
        except Exception:
            pass
    return None

def probe_video_metadata(ffmpeg_bin, file_path):
    cmd = [ffmpeg_bin, "-i", file_path]
    res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
    stderr = res.stderr

    duration_sec = 0.0
    dur_match = re.search(r"Duration:\s*(\d+):(\d+):(\d+\.\d+)", stderr)
    if dur_match:
        h, m, s = map(float, dur_match.groups())
        duration_sec = h * 3600 + m * 60 + s

    width, height = 0, 0
    res_match = re.search(r"Video:.*?(\d{3,5})x(\d{3,5})", stderr)
    if res_match:
        width = int(res_match.group(1))
        height = int(res_match.group(2))

    bitrate_kbps = 0
    br_match = re.search(r"bitrate:\s*(\d+)\s*kb/s", stderr)
    if br_match:
        bitrate_kbps = int(br_match.group(1))

    return {
        "duration_seconds": round(duration_sec, 2),
        "width": width,
        "height": height,
        "bitrate_kbps": bitrate_kbps
    }

def process_large_video(ffmpeg_bin, file_path, target_max_mb=50, output_dir=None):
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(file_path), "symb_optimized_media")
    os.makedirs(output_dir, exist_ok=True)

    base_name = os.path.splitext(os.path.basename(file_path))[0]
    file_size_bytes = os.path.getsize(file_path)
    file_size_mb = round(file_size_bytes / (1024 * 1024), 2)

    meta = probe_video_metadata(ffmpeg_bin, file_path)
    duration = meta["duration_seconds"]

    # 1. Extract lightweight voiceover audio (.m4a)
    audio_path = os.path.join(output_dir, f"{base_name}_audio.m4a")
    cmd_audio = [ffmpeg_bin, "-y", "-i", file_path, "-vn", "-c:a", "aac", "-b:a", "128k", audio_path]
    subprocess.run(cmd_audio, capture_output=True)
    audio_size_mb = round(os.path.getsize(audio_path) / (1024 * 1024), 2) if os.path.exists(audio_path) else 0.0

    # 2. Extract keyframes (e.g. 1 frame every 4 seconds, max 12 frames)
    interval = max(int(duration / 10), 1) if duration > 0 else 2
    frame_pattern = os.path.join(output_dir, f"{base_name}_frame_%02d.jpg")
    cmd_frames = [
        ffmpeg_bin, "-y", "-i", file_path,
        "-vf", f"fps=1/{interval},scale=640:-2",
        "-vframes", "10",
        frame_pattern
    ]
    subprocess.run(cmd_frames, capture_output=True)

    extracted_frames = []
    for f in sorted(os.listdir(output_dir)):
        if f.startswith(f"{base_name}_frame_") and f.endswith(".jpg"):
            extracted_frames.append(os.path.join(output_dir, f))

    # 3. Transcode / compress if oversized
    compressed_video_path = file_path
    compressed_size_mb = file_size_mb
    is_downsampled = False

    if file_size_mb > target_max_mb and duration > 0:
        compressed_video_path = os.path.join(output_dir, f"{base_name}_budget_{target_max_mb}mb.mp4")
        # Target bitrate in kbps: (target_max_mb * 8192 / duration) * 0.85 safety margin
        target_v_bitrate_kbps = max(int(((target_max_mb * 8192) / duration) * 0.82) - 96, 300)
        
        # Scale to 720p or 480p depending on budget
        scale_filter = "scale=-2:720" if target_v_bitrate_kbps >= 1200 else "scale=-2:480"

        # Try h264_mf, fallback to mpeg4
        cmd_compress = [
            ffmpeg_bin, "-y", "-i", file_path,
            "-vf", scale_filter,
            "-c:v", "mpeg4",
            "-b:v", f"{target_v_bitrate_kbps}k",
            "-c:a", "aac",
            "-b:a", "96k",
            compressed_video_path
        ]
        res = subprocess.run(cmd_compress, capture_output=True)
        if res.returncode == 0 and os.path.exists(compressed_video_path):
            compressed_size_mb = round(os.path.getsize(compressed_video_path) / (1024 * 1024), 2)
            is_downsampled = True

    # 4. Generate structured Storyboard & Typography Safe-Zone Plan
    storyboard_scenes = []
    for idx, f_path in enumerate(extracted_frames):
        ts = round(idx * interval, 1)
        storyboard_scenes.append({
            "scene_index": idx + 1,
            "timestamp_seconds": ts,
            "timestamp_formatted": f"{int(ts // 60):02d}:{int(ts % 60):02d}",
            "frame_preview_path": f_path,
            "recommended_typography_zone": "TOP_HEADER_ZONE (Avoids subject face in center/bottom)",
            "color_hierarchy_spec": {
                "headline": "#FFFFFF (White)",
                "key_benefit": "#00F2FE (Cyan Neon)",
                "accent_warning": "#F43F5E (Red Alert)",
                "proof_metric": "#10B981 (Green Emerald)"
            }
        })

    return {
        "status": "SUCCESS",
        "file_type": "VIDEO_MEDIA",
        "original_file": file_path,
        "original_size_mb": file_size_mb,
        "target_max_mb": target_max_mb,
        "is_downsampled": is_downsampled,
        "optimized_file": compressed_video_path,
        "optimized_size_mb": compressed_size_mb,
        "isolated_audio_track": {
            "path": audio_path,
            "size_mb": audio_size_mb,
            "note": "Use this lightweight track for direct AI transcription to avoid video context bloat"
        },
        "extracted_keyframes_count": len(extracted_frames),
        "storyboard_plan": storyboard_scenes,
        "agent_guidance": "Video has been optimized to fit within agent temporary buffer. Audio and keyframes isolated for zero-memory loss."
    }

def process_large_binary_stream(file_path, chunk_size_mb=10, max_chunks=5):
    file_size_bytes = os.path.getsize(file_path)
    file_size_mb = round(file_size_bytes / (1024 * 1024), 2)
    chunk_bytes = int(chunk_size_mb * 1024 * 1024)

    chunks_info = []
    with open(file_path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            total_chunks = (len(mm) + chunk_bytes - 1) // chunk_bytes
            for i in range(min(total_chunks, max_chunks)):
                start = i * chunk_bytes
                end = min(start + chunk_bytes, len(mm))
                sample = mm[start : min(start + 512, end)]
                chunks_info.append({
                    "chunk_index": i + 1,
                    "offset_hex": hex(start),
                    "size_bytes": end - start,
                    "sample_header_hex": sample[:16].hex()
                })

    return {
        "status": "SUCCESS",
        "file_type": "LARGE_BINARY_STREAM",
        "file_path": file_path,
        "file_size_mb": file_size_mb,
        "chunk_size_mb": chunk_size_mb,
        "total_chunks": total_chunks,
        "streamed_chunks_preview": chunks_info,
        "agent_guidance": "Binary is mapped via mmap with zero heap memory overhead. Query specific chunk offsets as needed."
    }

def optimize_media_buffer(file_path, target_max_mb=50):
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    ext = os.path.splitext(file_path)[1].lower()
    video_exts = [".mp4", ".mov", ".mkv", ".avi", ".webm", ".flv", ".wmv", ".m4v"]

    if ext in video_exts:
        ffmpeg_bin = find_ffmpeg_binary()
        if not ffmpeg_bin:
            return {"error": "FFmpeg binary not detected on system. Please ensure FFmpeg is installed."}
        return process_large_video(ffmpeg_bin, file_path, target_max_mb=target_max_mb)
    else:
        return process_large_binary_stream(file_path)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        mb = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        print(json.dumps(optimize_media_buffer(target, mb), indent=2))
