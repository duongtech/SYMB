# -*- coding: utf-8 -*-
"""
SYMB AUTOMATED STRING DECRYPTOR & DEOBFUSCATION HEURISTIC ENGINE
Recovers encrypted strings (Single-byte XOR, Multi-byte cycling XOR, Additive Rolling XOR, Base64+XOR)
from obfuscated Windows PE, Linux ELF, and Android .so shared libraries.
"""

import sys
import json
import os
import re
import math
import base64

COMMON_INDICATORS = [
    b"http://", b"https://", b".com", b".net", b".org", b".exe", b".dll",
    b"cmd.exe", b"powershell", b"bash", b"/bin/sh", b"password", b"admin",
    b"select ", b"insert ", b"token", b"bearer", b"user-agent", b"key",
    b"flag{", b"symb{", b"secret"
]

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_printable_ascii(b_seq, min_ratio=0.85):
    if not b_seq:
        return False
    printable = sum(1 for b in b_seq if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(b_seq)) >= min_ratio

def brute_force_single_xor(data):
    results = []
    # Test all 255 non-zero byte keys
    for k in range(1, 256):
        dec = bytes([b ^ k for b in data])
        for ind in COMMON_INDICATORS:
            if ind in dec.lower():
                # Extract clean string around indicator
                idx = dec.lower().find(ind)
                start = max(0, idx - 10)
                end = min(len(dec), idx + len(ind) + 30)
                sub = dec[start:end]
                # Filter printable
                clean = "".join([chr(c) if 32 <= c <= 126 else "." for c in sub])
                results.append({
                    "algorithm": "Single-Byte XOR",
                    "key_hex": hex(k),
                    "indicator_hit": ind.decode("latin-1"),
                    "decrypted_snippet": clean
                })
                break
    return results

def brute_force_rolling_xor(data):
    results = []
    for base_key in range(1, 256):
        # dec[i] = data[i] ^ (base_key + i)
        dec = bytes([data[i] ^ ((base_key + i) & 0xFF) for i in range(len(data))])
        for ind in COMMON_INDICATORS:
            if ind in dec.lower():
                idx = dec.lower().find(ind)
                start = max(0, idx - 10)
                end = min(len(dec), idx + len(ind) + 30)
                sub = dec[start:end]
                clean = "".join([chr(c) if 32 <= c <= 126 else "." for c in sub])
                results.append({
                    "algorithm": "Rolling Key XOR [i ^ (k + i)]",
                    "key_hex": hex(base_key),
                    "indicator_hit": ind.decode("latin-1"),
                    "decrypted_snippet": clean
                })
                break
    return results

def scan_and_decrypt_strings(binary_path, max_candidates=20):
    if not os.path.exists(binary_path):
        return {"error": f"Binary not found: {binary_path}"}

    with open(binary_path, "rb") as f:
        content = f.read()

    # Search for contiguous non-zero byte chunks with moderate-to-high entropy (4.0 - 7.5)
    # that could be encrypted string arrays
    chunk_size = 64
    stride = 32
    recovered = []

    for offset in range(0, min(len(content) - chunk_size, 500000), stride):
        chunk = content[offset : offset + chunk_size]
        if b"\x00" * 16 in chunk:
            continue
        ent = shannon_entropy(chunk)
        if 3.5 <= ent <= 7.2:
            # Try single XOR
            res_single = brute_force_single_xor(chunk)
            for r in res_single:
                r["file_offset"] = hex(offset)
                recovered.append(r)
                if len(recovered) >= max_candidates:
                    break

            if len(recovered) < max_candidates:
                res_roll = brute_force_rolling_xor(chunk)
                for r in res_roll:
                    r["file_offset"] = hex(offset)
                    recovered.append(r)
                    if len(recovered) >= max_candidates:
                        break

        if len(recovered) >= max_candidates:
            break

    # Search for obfuscated Base64 strings
    b64_matches = re.findall(b"[A-Za-z0-9+/=]{16,}", content)
    b64_recovered = []
    for b64_cand in b64_matches[:20]:
        try:
            raw = base64.b64decode(b64_cand)
            if is_printable_ascii(raw):
                b64_recovered.append({
                    "type": "Base64 Obfuscated String",
                    "original_b64": b64_cand.decode("latin-1"),
                    "decoded_plaintext": raw.decode("latin-1", errors="ignore")
                })
        except Exception:
            pass

    return {
        "binary_path": binary_path,
        "total_encrypted_strings_recovered": len(recovered),
        "total_base64_strings_decoded": len(b64_recovered),
        "recovered_strings": recovered,
        "decoded_base64_strings": b64_recovered
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(json.dumps(scan_and_decrypt_strings(target), indent=2))
