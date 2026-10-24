# -*- coding: utf-8 -*-
"""
SYMB WHOLE-PROGRAM DECOMPILER & C TRANSLATOR
Discovers all functions, decompiles them to unified C pseudocode with forward declarations
"""

import sys
import json
import os
import re
from decompiler_core import disassemble_and_decompile

def discover_functions(binary_path, max_funcs=15):
    if not os.path.exists(binary_path):
        return []

    with open(binary_path, "rb") as f:
        magic = f.read(4)

    is_pe = magic[:2] == b"MZ"
    is_elf = magic[:4] == b"\x7fELF"

    functions = []

    if is_pe:
        import pefile
        pe = pefile.PE(binary_path)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint + image_base
        functions.append({"address": hex(entry_point), "name": "main_entry"})

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.address:
                    fn_va = image_base + exp.address
                    fn_name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"export_{hex(fn_va)}"
                    if fn_va != entry_point:
                        functions.append({"address": hex(fn_va), "name": fn_name})

        # Scan .text section for function prologues (sub rsp, ... or push rbp)
        for s in pe.sections:
            s_name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
            if s_name == ".text":
                data = s.get_data()
                sec_va = image_base + s.VirtualAddress
                # Look for 'push rbp; mov rbp, rsp' (55 48 89 e5) or 'sub rsp, ...' (48 83 ec)
                for m in re.finditer(b"\x55\x48\x89\xe5|\x48\x83\xec", data):
                    candidate_va = sec_va + m.start()
                    if candidate_va not in [int(f["address"], 16) for f in functions]:
                        functions.append({"address": hex(candidate_va), "name": f"sub_{hex(candidate_va)[2:]}"})
                    if len(functions) >= max_funcs:
                        break
                break

    elif is_elf:
        from elftools.elf.elffile import ELFFile
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            entry_point = elf.header["e_entry"]
            functions.append({"address": hex(entry_point), "name": "_start"})

            symtab = elf.get_section_by_name(".symtab")
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"] > 0:
                        fn_va = sym["st_value"]
                        if fn_va not in [int(f["address"], 16) for f in functions]:
                            functions.append({"address": hex(fn_va), "name": sym.name})
                    if len(functions) >= max_funcs:
                        break

    return functions[:max_funcs]

def decompile_entire_program(binary_path, max_funcs=10):
    discovered = discover_functions(binary_path, max_funcs=max_funcs)
    decompiled_funcs = []
    forward_decls = []
    c_source_blocks = [
        "// ===========================================================================",
        "// SYMB NATIVE DECOMPILER SUITE :: UNIFIED RECONSTRUCTED C TRANSLATION",
        f"// Source Binary: {os.path.basename(binary_path)}",
        "// ===========================================================================\n",
        "#include <stdint.h>",
        "#include <stdbool.h>",
        "#include <stdio.h>",
        "#include <stdlib.h>\n"
    ]

    for fn in discovered:
        addr = fn["address"]
        res = disassemble_and_decompile(binary_path, function_address=addr, max_instructions=150)
        if "error" not in res:
            sym_name = res.get("symbol_name", fn["name"])
            forward_decls.append(f"__int64 {sym_name}();")
            decompiled_funcs.append({
                "address": addr,
                "name": sym_name,
                "instruction_count": res["instruction_count"],
                "basic_blocks_count": res["basic_blocks_count"],
                "pseudocode": res["decompiled_pseudocode"]
            })

    c_source_blocks.append("// --- FORWARD DECLARATIONS ---")
    c_source_blocks.extend(forward_decls)
    c_source_blocks.append("\n// --- DECOMPILED FUNCTIONS ---")

    for df in decompiled_funcs:
        c_source_blocks.append(df["pseudocode"])
        c_source_blocks.append("")

    return {
        "binary_path": binary_path,
        "total_functions_discovered": len(discovered),
        "total_functions_decompiled": len(decompiled_funcs),
        "functions": decompiled_funcs,
        "reconstructed_c_translation": "\n".join(c_source_blocks)
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        bin_p = sys.argv[1]
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 8
        print(json.dumps(decompile_entire_program(bin_p, limit), indent=2))
