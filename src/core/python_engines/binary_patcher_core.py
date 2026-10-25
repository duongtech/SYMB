# -*- coding: utf-8 -*-
"""
SYMB SURGICAL BINARY PATCHER & ACTIVE INTERVENTION CORE ENGINE
Applies permanent byte patches to PE, ELF, Mach-O, and RAW binaries with RVA-to-Raw mapping
and automatic PE checksum recalculation.
"""

import sys
import json
import os
import shutil
import hashlib

def calculate_hashes(data):
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256

def rva_to_file_offset(pe, rva):
    """Translates a Relative Virtual Address (RVA) to physical file offset in PE."""
    for section in pe.sections:
        sec_rva = section.VirtualAddress
        sec_size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        if sec_rva <= rva < sec_rva + sec_size:
            offset = (rva - sec_rva) + section.PointerToRawData
            return offset
    return None

def apply_binary_patches(binary_path, patches, output_path=None, create_backup=True, recalculate_pe_checksum=True):
    if not os.path.exists(binary_path):
        return {
            "success": False,
            "error": f"Binary not found: {binary_path}",
            "patches_applied": 0,
            "diff_entries": []
        }

    with open(binary_path, "rb") as f:
        raw_data = bytearray(f.read())

    initial_md5, initial_sha256 = calculate_hashes(raw_data)
    file_size = len(raw_data)

    is_pe = raw_data[:2] == b"MZ"
    pe = None
    image_base = 0x400000
    if is_pe:
        try:
            import pefile
            pe = pefile.PE(data=bytes(raw_data), fast_load=True)
            if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "ImageBase"):
                image_base = pe.OPTIONAL_HEADER.ImageBase
        except Exception:
            pe = None

    diff_entries = []
    patches_applied = 0
    limitations = []

    for idx, p in enumerate(patches):
        raw_addr_val = p.get("offset") or p.get("address")
        if raw_addr_val is None:
            limitations.append(f"Patch #{idx} missing target address/offset")
            continue

        if isinstance(raw_addr_val, str):
            addr_int = int(raw_addr_val, 16) if raw_addr_val.startswith("0x") or any(c in "abcdefABCDEF" for c in raw_addr_val) else int(raw_addr_val)
        else:
            addr_int = int(raw_addr_val)

        is_rva = p.get("is_rva", False)
        is_va = p.get("is_va", False)

        target_file_offset = None
        target_rva = None

        if pe:
            if is_va or addr_int >= image_base:
                target_rva = addr_int - image_base
                target_file_offset = rva_to_file_offset(pe, target_rva)
            elif is_rva:
                target_rva = addr_int
                target_file_offset = rva_to_file_offset(pe, target_rva)
            else:
                target_file_offset = addr_int
                if target_file_offset >= file_size:
                    # Might be RVA given without is_rva flag
                    offset_try = rva_to_file_offset(pe, addr_int)
                    if offset_try and offset_try < file_size:
                        target_file_offset = offset_try
                        target_rva = addr_int
        else:
            target_file_offset = addr_int

        if target_file_offset is None or target_file_offset >= file_size or target_file_offset < 0:
            limitations.append(f"Offset 0x{addr_int:x} could not be resolved to valid file offset (file size: {file_size})")
            continue

        clean_hex = p.get("bytes_hex", "").replace(" ", "").replace("0x", "")
        try:
            patch_bytes = bytes.fromhex(clean_hex)
        except Exception as e:
            limitations.append(f"Invalid hex bytes '{clean_hex}': {e}")
            continue

        if target_file_offset + len(patch_bytes) > file_size:
            limitations.append(f"Patch at 0x{target_file_offset:x} exceeds file boundary")
            continue

        orig_slice = raw_data[target_file_offset:target_file_offset + len(patch_bytes)]
        orig_hex = " ".join(f"{b:02x}" for b in orig_slice)
        patch_hex_formatted = " ".join(f"{b:02x}" for b in patch_bytes)

        # Apply byte patch
        raw_data[target_file_offset:target_file_offset + len(patch_bytes)] = patch_bytes
        patches_applied += 1

        diff_entries.append({
            "offset_hex": f"0x{target_file_offset:x}",
            "rva_hex": f"0x{target_rva:x}" if target_rva is not None else None,
            "original_bytes": orig_hex,
            "patched_bytes": patch_hex_formatted,
            "description": p.get("description", f"Patch #{idx+1}")
        })

    # Optional PE CheckSum recalculation
    old_pe_checksum = None
    new_pe_checksum = None
    pe_checksum_updated = False

    if is_pe and recalculate_pe_checksum and patches_applied > 0:
        try:
            import pefile
            reloaded_pe = pefile.PE(data=bytes(raw_data), fast_load=True)
            if hasattr(reloaded_pe, "OPTIONAL_HEADER"):
                old_pe_checksum = hex(reloaded_pe.OPTIONAL_HEADER.CheckSum)
                calc_sum = reloaded_pe.generate_checksum()
                reloaded_pe.OPTIONAL_HEADER.CheckSum = calc_sum
                new_pe_checksum = hex(calc_sum)
                raw_data = bytearray(reloaded_pe.write())
                pe_checksum_updated = True
        except Exception as e:
            limitations.append(f"PE checksum recalculation warning: {e}")

    # Determine destination
    target_out = output_path or (binary_path + ".patched.bin")
    backup_path = None

    if target_out == binary_path and create_backup:
        backup_path = binary_path + ".bak"
        try:
            shutil.copy2(binary_path, backup_path)
        except Exception as e:
            limitations.append(f"Failed creating backup: {e}")

    try:
        with open(target_out, "wb") as f:
            f.write(raw_data)
        success = patches_applied > 0
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed writing patched binary: {e}",
            "patches_applied": patches_applied,
            "diff_entries": diff_entries,
            "limitations": limitations
        }

    final_md5, final_sha256 = calculate_hashes(raw_data)

    return {
        "success": success,
        "binary_path": binary_path,
        "output_path": target_out,
        "backup_path": backup_path,
        "patches_applied": patches_applied,
        "diff_entries": diff_entries,
        "pe_checksum_updated": pe_checksum_updated,
        "old_pe_checksum": old_pe_checksum,
        "new_pe_checksum": new_pe_checksum,
        "target_identity": {
            "path": target_out,
            "sha256": final_sha256,
            "md5": final_md5,
            "size_bytes": len(raw_data),
            "format": "PE" if is_pe else ("ELF" if raw_data[:4] == b"\x7fELF" else "RAW")
        },
        "limitations": limitations
    }

if __name__ == "__main__":
    raw_str = sys.argv[1] if len(sys.argv) > 1 else ""
    if not raw_str and not sys.stdin.isatty():
        raw_str = sys.stdin.read().strip()

    req = {}
    if raw_str:
        try:
            req = json.loads(raw_str)
        except Exception:
            req = {}

    res = apply_binary_patches(
        binary_path=req.get("binary_path", ""),
        patches=req.get("patches", []),
        output_path=req.get("output_path"),
        create_backup=req.get("create_backup", True),
        recalculate_pe_checksum=req.get("recalculate_pe_checksum", True)
    )
    print(json.dumps(res))
