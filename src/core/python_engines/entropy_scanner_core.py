# -*- coding: utf-8 -*-
"""
SYMB HIGH-SPEED ROLLING SHANNON ENTROPY & CRYPTOR SCANNER
Zero-dependency binary entropy analyzer, packed payload detector, and section distribution visualizer.
"""

import sys
import json
import os
import math

def compute_shannon_entropy(chunk):
    if not chunk:
        return 0.0
    length = len(chunk)
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    ent = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            ent -= p * math.log2(p)
    return ent

def scan_entropy(target_path, block_size=512):
    if not os.path.exists(target_path):
        return {"error": f"File not found: {target_path}"}

    file_size = os.path.getsize(target_path)
    if file_size == 0:
        return {"error": "File is empty"}

    with open(target_path, "rb") as f:
        data = f.read()

    total_blocks = (len(data) + block_size - 1) // block_size
    entropy_values = []
    high_entropy_regions = []

    current_region_start = None
    current_region_blocks = 0
    region_max_ent = 0.0

    for i in range(total_blocks):
        chunk = data[i * block_size : (i + 1) * block_size]
        h = compute_shannon_entropy(chunk)
        entropy_values.append(round(h, 4))

        if h >= 7.2:
            if current_region_start is None:
                current_region_start = i * block_size
                current_region_blocks = 1
                region_max_ent = h
            else:
                current_region_blocks += 1
                region_max_ent = max(region_max_ent, h)
        else:
            if current_region_start is not None:
                high_entropy_regions.append({
                    "offset_hex": hex(current_region_start),
                    "size_bytes": current_region_blocks * block_size,
                    "max_entropy": round(region_max_ent, 4),
                    "classification": "ENCRYPTED_OR_COMPRESSED_PAYLOAD"
                })
                current_region_start = None
                current_region_blocks = 0

    if current_region_start is not None:
        high_entropy_regions.append({
            "offset_hex": hex(current_region_start),
            "size_bytes": current_region_blocks * block_size,
            "max_entropy": round(region_max_ent, 4),
            "classification": "ENCRYPTED_OR_COMPRESSED_PAYLOAD"
        })

    min_h = min(entropy_values) if entropy_values else 0.0
    max_h = max(entropy_values) if entropy_values else 0.0
    mean_h = sum(entropy_values) / len(entropy_values) if entropy_values else 0.0

    packed_blocks_count = sum(1 for h in entropy_values if h >= 7.2)
    packed_ratio = packed_blocks_count / len(entropy_values) if entropy_values else 0.0
    is_packed = packed_ratio >= 0.20 or max_h >= 7.85

    # Generate 10-bucket ASCII histogram
    buckets = [0] * 10
    for h in entropy_values:
        idx = min(int(h / 0.8), 9)
        buckets[idx] += 1

    histogram_lines = []
    max_b = max(buckets) if max(buckets) > 0 else 1
    for b_idx in range(10):
        low = b_idx * 0.8
        high = (b_idx + 1) * 0.8
        bar_len = int((buckets[b_idx] / max_b) * 24)
        bar = "█" * bar_len + "░" * (24 - bar_len)
        histogram_lines.append(f"{low:3.1f} - {high:3.1f} | {bar} ({buckets[b_idx]} blocks)")

    return {
        "target": target_path,
        "file_size_bytes": file_size,
        "block_size_bytes": block_size,
        "total_blocks_analyzed": len(entropy_values),
        "min_entropy": round(min_h, 4),
        "max_entropy": round(max_h, 4),
        "mean_entropy": round(mean_h, 4),
        "packed_blocks_count": packed_blocks_count,
        "packed_percentage": f"{packed_ratio * 100:.2f}%",
        "is_packed_or_encrypted": is_packed,
        "high_entropy_regions_count": len(high_entropy_regions),
        "high_entropy_regions": high_entropy_regions[:10],
        "ascii_entropy_histogram": histogram_lines
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        bs = int(sys.argv[2]) if len(sys.argv) > 2 else 512
        print(json.dumps(scan_entropy(target, bs), indent=2))
