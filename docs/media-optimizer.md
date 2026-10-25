# 🎬 High-Capacity Media & Raw Buffer Optimizer for AI Agents

When AI agents process large media files or gigabyte-scale memory dumps, standard execution environments frequently crash with **"temporary processing memory exhausted"** or trigger severe context window bloat. 

SYMB provides an autonomous, hardware-accelerated media pipeline and zero-RAM memory-mapped binary streamer designed specifically for autonomous agents.

---

## 🏗️ Architecture Pipeline

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                      SYMB LARGE MEDIA & BUFFER OPTIMIZATION PIPELINE                   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   Oversized Input File (100MB - 5GB)                                                   │
│   [ Video: .mp4 / .mov / .mkv ] ────► [ FFmpeg Hardware Extraction ]                   │
│                                           │                                            │
│                                           ├──► Isolated Audio Track (.m4a/.mp3)        │
│                                           │    (95% context reduction for STT/whisper) │
│                                           │                                            │
│                                           ├──► Smart Video Downsampler (<= 50MB)       │
│                                           │    (Fits standard agent memory budget)     │
│                                           │                                            │
│                                           └──► Keyframe Storyboard & Safe-Zone Spec    │
│                                                (Avoids top header text covering faces) │
│                                                                                        │
│   [ Raw Binary / Memory Dump (.bin/.dmp) ] ──► Zero-RAM mmap Chunked Streaming         │
│                                                (Streams gigabyte files with 0MB heap)  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Core Capabilities

### 1. Isolated Audio Stream Demuxing
Large video files (e.g. 300MB - 1GB `.mp4` recordings) consume massive context memory if ingested directly. SYMB isolates the primary audio track into a compact AAC `.m4a` file (typically 3–5MB), reducing memory consumption by over **95%** while preserving 100% transcript fidelity for speech-to-text models.

### 2. Smart Video Downscaling
If visual scene understanding is strictly required, SYMB dynamically downsamples resolution and throttles framerates to guarantee the resulting video strictly adheres to a user-defined memory budget (e.g. $\le 50\text{ MB}$).

### 3. Visual Storyboard & Safe-Zone Specification
Extracts keyframes at significant scene transitions and computes typography safe-zone coordinates (e.g. Top Header zone) to ensure AI agent text overlays do not obscure human subjects or critical UI elements.

### 4. Zero-RAM Memory-Mapped Binary Streaming (`mmap`)
Raw binary dumps, kernel crash dumps (`.dmp`), and firmware ROMs ranging from 500MB to 10GB cannot be loaded into Node.js V8 heap memory. SYMB leverages OS-level virtual memory mapping (`mmap`) to stream chunked slices on demand with **0MB heap overhead**.

---

## 💻 CLI Usage

```bash
# Optimize large video and extract isolated audio + storyboard
symb optimize-media ./path/to/large_video.mp4 --target-mb 50

# Map and stream multi-gigabyte memory dump without loading into RAM
symb optimize-media ./dumps/system_crash.dmp --target-mb 20
```

---

## 📜 MCP Tool Contract: `optimize_large_media_buffer`

```json
{
  "file_path": "/path/to/large_recording.mp4",
  "target_max_mb": 50
}
```

### Response Example:
```json
{
  "status": "SUCCESS",
  "file_type": "VIDEO_MEDIA",
  "original_size_mb": 184.2,
  "target_max_mb": 50,
  "is_downsampled": true,
  "optimized_size_mb": 42.1,
  "isolated_audio_track": {
    "path": "/path/to/extracted_audio.m4a",
    "size_mb": 3.8,
    "note": "Use this audio track for speech recognition to save 95% of agent context memory."
  },
  "extracted_keyframes_count": 5,
  "storyboard_plan": [
    {
      "scene_index": 1,
      "timestamp_formatted": "00:00:02",
      "frame_preview_path": ".../keyframe_0.jpg",
      "recommended_typography_zone": "Top Header (avoid subject face)"
    }
  ],
  "agent_guidance": "Video optimized successfully within target budget."
}
```
