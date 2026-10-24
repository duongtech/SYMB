# -*- coding: utf-8 -*-
"""
SYMB DEEP BINARY LAYOUT & SECURITY MITIGATION ANALYZER
Inspects PE, ELF, Mach-O structure, section entropy, and protections
"""

import sys
import json
import os
import math

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    for count in occurrences:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def inspect_binary(binary_path):
    if not os.path.exists(binary_path):
        return {"error": f"File not found: {binary_path}"}

    file_size = os.path.getsize(binary_path)
    
    with open(binary_path, "rb") as f:
        magic = f.read(4)

    # 1. PE / Windows Binary Inspection
    if magic[:2] == b"MZ":
        try:
            import pefile
            pe = pefile.PE(binary_path)
            
            machine_map = {
                0x14c: "i386 (32-bit)",
                0x8664: "AMD64 (x86_64)",
                0xaa64: "ARM64",
                0x1c0: "ARM"
            }
            arch = machine_map.get(pe.FILE_HEADER.Machine, f"Unknown ({hex(pe.FILE_HEADER.Machine)})")
            entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)
            
            # Mitigations (DllCharacteristics)
            dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
            mitigations = {
                "aslr": bool(dll_char & 0x0040),
                "dep_nx": bool(dll_char & 0x0100),
                "no_seh": bool(dll_char & 0x0400),
                "cfg_control_flow_guard": bool(dll_char & 0x4000),
                "high_entropy_va": bool(dll_char & 0x0020)
            }
            
            sections = []
            max_entropy = 0.0
            for s in pe.sections:
                s_name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                s_data = s.get_data()
                s_ent = calculate_entropy(s_data)
                max_entropy = max(max_entropy, s_ent)
                sections.append({
                    "name": s_name,
                    "virtual_address": hex(s.VirtualAddress),
                    "virtual_size": s.Misc_VirtualSize,
                    "raw_size": s.SizeOfRawData,
                    "entropy": s_ent,
                    "packed_risk": "HIGH" if s_ent > 7.2 else ("MEDIUM" if s_ent > 6.8 else "NORMAL")
                })
                
            # Imports
            imports = {}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    funcs = []
                    for imp in entry.imports:
                        if imp.name:
                            funcs.append(imp.name.decode("utf-8", errors="ignore"))
                        elif imp.ordinal:
                            funcs.append(f"Ordinal_{imp.ordinal}")
                    imports[dll_name] = funcs[:15]

            # Exports
            exports = []
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append({"name": exp.name.decode("utf-8", errors="ignore"), "address": hex(exp.address)})

            return {
                "format": "PE / Windows Executable",
                "architecture": arch,
                "file_size_bytes": file_size,
                "entry_point": entry_point,
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "mitigations": mitigations,
                "sections_count": len(sections),
                "sections": sections,
                "max_entropy": max_entropy,
                "likely_packed": max_entropy > 7.2,
                "imports": imports,
                "exports": exports
            }
        except Exception as e:
            return {"format": "PE", "error": str(e)}

    # 2. ELF / Linux Binary Inspection
    elif magic[:4] == b"\x7fELF":
        try:
            from elftools.elf.elffile import ELFFile
            with open(binary_path, "rb") as f:
                elf = ELFFile(f)
                header = elf.header
                arch = header["e_machine"]
                entry_point = hex(header["e_entry"])
                
                sections = []
                max_entropy = 0.0
                for s in elf.iter_sections():
                    s_name = s.name
                    s_data = s.data()
                    s_ent = calculate_entropy(s_data)
                    max_entropy = max(max_entropy, s_ent)
                    sections.append({
                        "name": s_name,
                        "virtual_address": hex(s["sh_addr"]),
                        "raw_size": s["sh_size"],
                        "entropy": s_ent,
                        "packed_risk": "HIGH" if s_ent > 7.2 else "NORMAL"
                    })

                return {
                    "format": "ELF / Linux Executable",
                    "architecture": arch,
                    "file_size_bytes": file_size,
                    "entry_point": entry_point,
                    "sections_count": len(sections),
                    "sections": sections[:15],
                    "max_entropy": max_entropy,
                    "likely_packed": max_entropy > 7.2
                }
        except Exception as e:
            return {"format": "ELF", "error": str(e)}

    return {"format": "Unknown / Raw Binary", "file_size_bytes": file_size}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        path = sys.argv[1]
        print(json.dumps(inspect_binary(path), indent=2))
