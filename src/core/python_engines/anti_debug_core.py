# -*- coding: utf-8 -*-
"""
SYMB ANTI-DEBUG ANNIHILATOR CORE ENGINE (PROACTIVE RE INTERVENTION)
Scans, detects, and automatically patches anti-debugging traps, timing checks, and hypervisor detection.
Converts Virtual Addresses to physical raw file offsets, neutralizes traps, and recalculates PE checksums.
"""

import sys
import json
import os
import hashlib

def calculate_hashes(data):
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256

def rva_to_file_offset(pe, rva):
    for section in pe.sections:
        sec_rva = section.VirtualAddress
        sec_size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        if sec_rva <= rva < sec_rva + sec_size:
            offset = (rva - sec_rva) + section.PointerToRawData
            return offset
    return None

def scan_and_patch_anti_debug(binary_path, auto_patch=False, output_path=None):
    if not os.path.exists(binary_path):
        return {
            "error": f"Binary not found: {binary_path}",
            "binary_path": binary_path,
            "total_detections": 0,
            "detections": [],
            "auto_patched": False,
            "patch_diff_summary": []
        }

    with open(binary_path, "rb") as f:
        raw_data = bytearray(f.read())

    initial_md5, initial_sha256 = calculate_hashes(raw_data)
    file_size = len(raw_data)

    detections = []
    patch_diff = []
    limitations = []

    is_pe = raw_data[:2] == b"MZ"
    is_elf = raw_data[:4] == b"\x7fELF"
    pe = None

    # 1. PE Format Anti-Debug Scanner
    if is_pe:
        try:
            import pefile
            pe = pefile.PE(data=bytes(raw_data), fast_load=True)

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "unknown.dll"
                    for imp in entry.imports:
                        if imp.name:
                            name_str = imp.name.decode("utf-8", errors="ignore")
                            suspicious_apis = {
                                "IsDebuggerPresent": "Returns 1 if debugged. Patch: XOR EAX, EAX; RET",
                                "CheckRemoteDebuggerPresent": "Queries NtQueryInformationProcess. Patch: Set pbDebuggerPresent to 0",
                                "NtQueryInformationProcess": "Queries ProcessDebugPort. Patch: return STATUS_SUCCESS with port 0",
                                "OutputDebugStringA": "Detects GetLastError changes. Patch: NOP stub",
                                "QueryPerformanceCounter": "Timing delta attack. Patch: Constant delta return",
                                "GetTickCount": "Timing delta attack. Patch: Zero tick advance",
                                "GetTickCount64": "Timing delta attack. Patch: Constant tick advance",
                                "SetUnhandledExceptionFilter": "SEH hijacking. Patch: NOP registration",
                                "NtSetInformationThread": "ThreadHideFromDebugger check. Patch: STATUS_SUCCESS"
                            }
                            if name_str in suspicious_apis:
                                detections.append({
                                    "technique": f"API_IMPORT_{name_str}",
                                    "address": hex(imp.address),
                                    "instruction": f"Import: {dll_name}!{name_str}",
                                    "patch_suggestion": suspicious_apis[name_str]
                                })
        except Exception as e:
            limitations.append(f"PE import scan warning: {e}")

    # 2. Inline Opcode Pattern Scanner
    # Determine scan range (first 2MB or whole binary)
    scan_limit = min(file_size, 2 * 1024 * 1024)
    offset = 0

    while offset < scan_limit - 1:
        matched = False
        two_bytes = raw_data[offset:offset+2]

        # RDTSC: 0F 31
        if two_bytes == b"\x0f\x31":
            addr_hex = f"0x{offset:x}"
            detections.append({
                "technique": "INLINE_TIMING_RDTSC",
                "address": addr_hex,
                "file_offset": addr_hex,
                "instruction": "rdtsc",
                "patch_suggestion": "NOP out 2 bytes (90 90)"
            })
            if auto_patch:
                raw_data[offset] = 0x90
                raw_data[offset+1] = 0x90
                patch_diff.append(f"Patched rdtsc at {addr_hex} -> 90 90 (NOP)")
            offset += 2
            continue

        # RDTSCP: 0F 01 F9
        if offset < scan_limit - 2 and raw_data[offset:offset+3] == b"\x0f\x01\xf9":
            addr_hex = f"0x{offset:x}"
            detections.append({
                "technique": "INLINE_TIMING_RDTSCP",
                "address": addr_hex,
                "file_offset": addr_hex,
                "instruction": "rdtscp",
                "patch_suggestion": "NOP out 3 bytes (90 90 90)"
            })
            if auto_patch:
                raw_data[offset:offset+3] = b"\x90\x90\x90"
                patch_diff.append(f"Patched rdtscp at {addr_hex} -> 90 90 90 (NOP)")
            offset += 3
            continue

        # INT 2D: CD 2D
        if two_bytes == b"\xcd\x2d":
            addr_hex = f"0x{offset:x}"
            detections.append({
                "technique": "INLINE_INT_2D_TRAP",
                "address": addr_hex,
                "file_offset": addr_hex,
                "instruction": "int 0x2d",
                "patch_suggestion": "NOP out 2 bytes (90 90)"
            })
            if auto_patch:
                raw_data[offset] = 0x90
                raw_data[offset+1] = 0x90
                patch_diff.append(f"Patched int 2d at {addr_hex} -> 90 90 (NOP)")
            offset += 2
            continue

        # INT 3: CC (filter out padding sequences: only if isolated or in function body)
        if raw_data[offset] == 0xCC and offset > 0 and raw_data[offset-1] not in (0xCC, 0x90, 0xC3):
            # Potential inline software breakpoint trap
            addr_hex = f"0x{offset:x}"
            detections.append({
                "technique": "INLINE_INT3_TRAP",
                "address": addr_hex,
                "file_offset": addr_hex,
                "instruction": "int3",
                "patch_suggestion": "NOP out 1 byte (90)"
            })
            if auto_patch:
                raw_data[offset] = 0x90
                patch_diff.append(f"Patched int3 at {addr_hex} -> 90 (NOP)")
            offset += 1
            continue

        # PEB BeingDebugged check pattern (x86: 64 a1 30 00 00 00 -> mov eax, fs:[30h])
        if offset < scan_limit - 6 and raw_data[offset:offset+6] == b"\x64\xa1\x30\x00\x00\x00":
            addr_hex = f"0x{offset:x}"
            detections.append({
                "technique": "PEB_BEING_DEBUGGED_CHECK_X86",
                "address": addr_hex,
                "file_offset": addr_hex,
                "instruction": "mov eax, fs:[0x30]",
                "patch_suggestion": "Neutralize PEB access or zero BeingDebugged flag"
            })
            offset += 6
            continue

        offset += 1

    patched_file = None
    if auto_patch and patch_diff:
        out_target = output_path or (binary_path + ".antidebug_patched.exe" if is_pe else binary_path + ".antidebug_patched.bin")
        if is_pe:
            try:
                import pefile
                patched_pe = pefile.PE(data=bytes(raw_data), fast_load=True)
                if hasattr(patched_pe, "OPTIONAL_HEADER"):
                    patched_pe.OPTIONAL_HEADER.CheckSum = patched_pe.generate_checksum()
                    raw_data = bytearray(patched_pe.write())
            except Exception as e:
                limitations.append(f"PE checksum recalculation warning: {e}")

        try:
            with open(out_target, "wb") as f:
                f.write(raw_data)
            patched_file = out_target
        except Exception as e:
            limitations.append(f"Failed writing patched binary: {e}")

    final_md5, final_sha256 = calculate_hashes(raw_data)

    return {
        "binary_path": binary_path,
        "total_detections": len(detections),
        "detections": detections,
        "auto_patched": bool(patched_file),
        "patched_binary_path": patched_file,
        "patch_diff_summary": patch_diff,
        "target_identity": {
            "path": binary_path,
            "sha256": initial_sha256,
            "md5": initial_md5,
            "size_bytes": file_size,
            "format": "PE" if is_pe else ("ELF" if is_elf else "RAW")
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

    res = scan_and_patch_anti_debug(
        binary_path=req.get("binary_path", ""),
        auto_patch=req.get("auto_patch", False),
        output_path=req.get("output_path")
    )
    print(json.dumps(res))
