# -*- coding: utf-8 -*-
"""
SYMB CRYPTOGRAPHIC PRIMITIVE & ALGORITHM SCANNER
Scans binaries for AES, DES, SHA, MD5, CRC32, ChaCha, and S-Boxes
"""

import sys
import json
import os

CRYPTO_SIGNATURES = [
    {
        "name": "AES S-Box (Forward Rijndael)",
        "bytes": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]),
        "algorithm": "AES-128/192/256",
        "type": "Substitution Box"
    },
    {
        "name": "AES Inverse S-Box",
        "bytes": bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb]),
        "algorithm": "AES-128/192/256 Decryption",
        "type": "Inverse Substitution Box"
    },
    {
        "name": "ChaCha20 Constant ('expand 32-byte k')",
        "bytes": b"expand 32-byte k",
        "algorithm": "ChaCha20 / Poly1305",
        "type": "Stream Cipher Key Schedule Constant"
    },
    {
        "name": "Standard Base64 Table",
        "bytes": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "algorithm": "Base64 Encoding",
        "type": "Encoding Alphabet"
    },
    {
        "name": "MD5 Initial Constants (IV)",
        "bytes": bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]),
        "algorithm": "MD5 Hash",
        "type": "Initial State Vector"
    },
    {
        "name": "SHA-256 Initial Constants (H0-H3)",
        "bytes": bytes([0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5]),
        "algorithm": "SHA-256 Hash",
        "type": "Initial State Vector"
    }
]

def scan_crypto_primitives(binary_path):
    if not os.path.exists(binary_path):
        return {"error": f"File not found: {binary_path}"}

    with open(binary_path, "rb") as f:
        content = f.read()

    detected = []
    for sig in CRYPTO_SIGNATURES:
        pattern = sig["bytes"]
        offset = 0
        while True:
            idx = content.find(pattern, offset)
            if idx == -1:
                break
            detected.append({
                "primitive": sig["name"],
                "algorithm": sig["algorithm"],
                "type": sig["type"],
                "file_offset": hex(idx),
                "matched_bytes_hex": pattern.hex()
            })
            offset = idx + len(pattern)

    return {
        "binary_path": os.path.abspath(binary_path),
        "total_primitives_found": len(detected),
        "primitives": detected
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(json.dumps(scan_crypto_primitives(sys.argv[1]), indent=2))
