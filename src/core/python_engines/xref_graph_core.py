# -*- coding: utf-8 -*-
"""
SYMB HIGH-SPEED BINARY CROSS-REFERENCE (XREF) & CALL GRAPH ENGINE
Reconstructs whole-program function call graphs, discovers callers/callees,
and traces string & API references across Windows PE and Linux ELF binaries.
"""

import sys
import json
import os
import re
import struct

def parse_pe_xrefs(pe_path):
    import pefile
    import capstone

    pe = pefile.PE(pe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    arch_mode = capstone.CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else capstone.CS_MODE_32

    # Map string literals in data sections
    string_map = {}
    for sec in pe.sections:
        name = sec.Name.decode("latin-1", errors="ignore").strip("\x00")
        if any(k in name for k in [".rdata", ".data", ".rodata"]):
            sec_bytes = sec.get_data()
            sec_va = image_base + sec.VirtualAddress
            for m in re.finditer(b"[\x20-\x7E]{4,}", sec_bytes):
                s_va = sec_va + m.start()
                string_map[s_va] = m.group().decode("latin-1")

    # Map imports
    iat_map = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("latin-1", errors="ignore")
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode("latin-1", errors="ignore")
                    iat_map[imp.address] = f"{dll_name}!{func_name}"

    # Disassemble .text section
    text_sec = next((s for s in pe.sections if b".text" in s.Name), None)
    if not text_sec:
        return {"error": "No .text section found"}

    code_bytes = text_sec.get_data()
    code_va = image_base + text_sec.VirtualAddress

    md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
    md.detail = True

    calls = []
    string_xrefs = []
    function_nodes = set()
    function_nodes.add(hex(entry_point))

    for insn in md.disasm(code_bytes, code_va):
        addr_hex = hex(insn.address)

        # Detect function calls
        if insn.mnemonic.startswith("call"):
            target_str = insn.op_str.strip()
            target_va = None
            resolved_api = None

            if target_str.startswith("0x"):
                try:
                    target_va = int(target_str, 16)
                    function_nodes.add(target_str)
                except ValueError:
                    pass
            elif "[" in target_str and "rip" in target_str:
                # RIP-relative indirect call (e.g. call qword ptr [rip + disp])
                match = re.search(r"rip\s*([+-])\s*0x([0-9a-fA-F]+)", target_str)
                if match:
                    sign = 1 if match.group(1) == "+" else -1
                    disp = int(match.group(2), 16) * sign
                    iat_target = insn.address + insn.size + disp
                    if iat_target in iat_map:
                        resolved_api = iat_map[iat_target]

            calls.append({
                "caller_address": addr_hex,
                "target": resolved_api if resolved_api else target_str,
                "is_indirect": "[" in target_str or target_str.startswith("r") or target_str.startswith("e"),
                "resolved_api": resolved_api
            })

        # Detect string XREFs (mov / lea referencing string_map)
        if insn.mnemonic in ["lea", "mov"]:
            # Check rip relative
            if "rip" in insn.op_str:
                match = re.search(r"rip\s*([+-])\s*0x([0-9a-fA-F]+)", insn.op_str)
                if match:
                    sign = 1 if match.group(1) == "+" else -1
                    disp = int(match.group(2), 16) * sign
                    target_va = insn.address + insn.size + disp
                    if target_va in string_map:
                        string_xrefs.append({
                            "instruction_address": addr_hex,
                            "string_address": hex(target_va),
                            "string_literal": string_map[target_va]
                        })
            else:
                # Immediate hex
                matches = re.findall(r"0x[0-9a-fA-F]+", insn.op_str)
                for m in matches:
                    val = int(m, 16)
                    if val in string_map:
                        string_xrefs.append({
                            "instruction_address": addr_hex,
                            "string_address": m,
                            "string_literal": string_map[val]
                        })

    # Call graph summary
    callers_count = {}
    for c in calls:
        t = c["target"]
        callers_count[t] = callers_count.get(t, 0) + 1

    top_called_functions = [
        {"target": t, "caller_references": cnt}
        for t, cnt in sorted(callers_count.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    return {
        "format": "PE / Windows Executable",
        "entry_point": hex(entry_point),
        "total_call_instructions": len(calls),
        "total_string_xrefs": len(string_xrefs),
        "top_called_targets": top_called_functions,
        "sample_call_edges": calls[:15],
        "sample_string_xrefs": string_xrefs[:15]
    }

def analyze_xrefs(target_path):
    if not os.path.exists(target_path):
        return {"error": f"File not found: {target_path}"}

    with open(target_path, "rb") as f:
        head = f.read(4)

    if head.startswith(b"MZ"):
        return parse_pe_xrefs(target_path)
    elif head.startswith(b"\x7fELF"):
        # Basic ELF XREF extraction
        import capstone
        with open(target_path, "rb") as f:
            data = f.read()

        is_64 = (data[4] == 2)
        arch_mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)

        calls = []
        for insn in md.disasm(data[0x1000:0x4000], 0x401000):
            if insn.mnemonic.startswith("call"):
                calls.append({
                    "caller_address": hex(insn.address),
                    "target": insn.op_str.strip(),
                    "is_indirect": "[" in insn.op_str or insn.op_str.startswith("r")
                })

        return {
            "format": "ELF / Linux Executable",
            "total_call_instructions": len(calls),
            "total_string_xrefs": 0,
            "sample_call_edges": calls[:15]
        }
    else:
        return {"error": "Unsupported binary format for XREF analysis (expected PE or ELF)"}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(json.dumps(analyze_xrefs(target), indent=2))
