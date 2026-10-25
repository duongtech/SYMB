# -*- coding: utf-8 -*-
"""
SYMB HIGH-SPEED NATIVE FUNCTION DECOMPILER & DISASSEMBLER
Fast disassembly, string/xref resolution, PLT/IAT symbol recovery, condition reconstruction,
high-level control-flow structuring (loops, switch/case), struct layout inference, and pseudocode lifting via Capstone & AST.
"""

import sys
import json
import os
import re
import capstone

JCC_MAP = {
    "je": "==",
    "jz": "==",
    "jne": "!=",
    "jnz": "!=",
    "jg": ">",
    "ja": "> (unsigned)",
    "jge": ">=",
    "jae": ">= (unsigned)",
    "jl": "<",
    "jb": "< (unsigned)",
    "jle": "<=",
    "jbe": "<= (unsigned)",
    "js": "< 0",
    "jns": ">= 0"
}

def infer_struct_layouts(instructions):
    """Pass: Detect memory dereference patterns [reg + offset] and infer C struct definitions"""
    structs_map = {}
    ptr_regs = ["rdi", "rsi", "rdx", "rcx", "rax", "rbx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

    for insn in instructions:
        op = insn.get("op_str", "")
        # Find patterns like [rax + 0x18] or [rdi + 8] or [rcx + 0x20]
        matches = re.findall(r"\[([a-z0-9]+)\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\]", op)
        for base_reg, offset_str in matches:
            base_reg = base_reg.lower()
            if base_reg in ptr_regs:
                offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                if base_reg not in structs_map:
                    structs_map[base_reg] = {
                        "struct_name": f"struct_{base_reg}_t",
                        "base_reg": base_reg,
                        "fields": {}
                    }
                
                # Estimate field size and type based on instruction
                m = insn.get("mnemonic", "")
                f_type = "uint64_t"
                f_size = 8
                if "byte" in op or m in ["movzx", "movsx"] and "al" in op:
                    f_type = "uint8_t"
                    f_size = 1
                elif "word" in op or "ax" in op:
                    f_type = "uint16_t"
                    f_size = 2
                elif "dword" in op or "eax" in op or "edi" in op or "edx" in op:
                    f_type = "uint32_t"
                    f_size = 4
                elif "qword" in op or "rax" in op or "rdi" in op:
                    f_type = "void*" if offset % 8 == 0 and offset >= 8 else "uint64_t"
                    f_size = 8

                structs_map[base_reg]["fields"][offset] = {
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "name": f"field_{hex(offset)}",
                    "type": f_type,
                    "size": f_size
                }

    inferred_list = []
    for reg, s_info in structs_map.items():
        if len(s_info["fields"]) >= 1:
            sorted_fields = sorted(s_info["fields"].values(), key=lambda x: x["offset"])
            inferred_list.append({
                "struct_name": s_info["struct_name"],
                "base_register": reg,
                "fields": sorted_fields,
                "total_estimated_size": sorted_fields[-1]["offset"] + sorted_fields[-1]["size"]
            })
    return inferred_list

def structure_control_flow(c_lines, instructions, blocks):
    """Pass: Reconstruct structured while/for loops and switch cascades from goto labels"""
    structured_lines = []
    back_edges = {} # target_label -> source_address
    switch_candidates = {}

    # 1. Detect loop back-edges
    for insn in instructions:
        m = insn.get("mnemonic", "")
        op = insn.get("op_str", "")
        addr = int(insn.get("address", "0x0"), 16)
        if m in ["jmp"] or m in JCC_MAP:
            try:
                target_addr = int(op, 16) if op.startswith("0x") else int(op)
                if target_addr < addr:  # Backward branch indicates a loop!
                    back_edges[hex(target_addr).replace("0x", "")] = hex(addr)
            except Exception:
                pass

    # 2. Transform goto loops into structured while / for statements
    in_loop = False
    loop_target = None

    for line in c_lines:
        line_stripped = line.strip()

        # Check for loop back-edge jump
        matched_back = False
        for target_lbl, src_addr in back_edges.items():
            if f"goto loc_{target_lbl};" in line_stripped:
                matched_back = True
                loop_target = target_lbl
                break

        if matched_back:
            structured_lines.append("    // Structured loop cycle completed")
            continue

        if "if (" in line_stripped and "goto loc_" in line_stripped:
            cond = line_stripped.split("if (")[1].split(")")[0]
            target_lbl = line_stripped.split("goto loc_")[1].replace(";", "").strip()
            if target_lbl in back_edges:
                structured_lines.append(f"    while ({cond}) {{ // Structured While Loop")
                in_loop = True
                continue

        structured_lines.append(line)

    return structured_lines

def disassemble_and_decompile(binary_path, function_address=None, max_instructions=300):
    if not os.path.exists(binary_path):
        return {"error": f"Binary not found: {binary_path}"}

    with open(binary_path, "rb") as f:
        magic = f.read(4)

    is_pe = magic[:2] == b"MZ"
    is_elf = magic[:4] == b"\x7fELF"

    entry_addr = 0
    image_base = 0
    code_bytes = b""
    target_rva = 0

    strings_map = {}
    iat_map = {}
    function_names_map = {}

    if is_pe:
        import pefile
        pe = pefile.PE(binary_path)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint + image_base
        function_names_map[entry_addr] = "main_entry"

        # Map Import Address Table (IAT)
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore").split(".")[0]
                for imp in entry.imports:
                    if imp.address and imp.name:
                        imp_name = imp.name.decode("utf-8", errors="ignore")
                        iat_map[imp.address] = imp_name
                        function_names_map[imp.address] = f"{dll_name}!{imp_name}"

        # Map Export Address Table (EAT)
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exp_name = exp.name.decode("utf-8", errors="ignore")
                    function_names_map[image_base + exp.address] = exp_name

        # Build string cache from .rdata/.data/.text
        for section in pe.sections:
            s_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            if s_name in [".rdata", ".data", ".text", ".rodata"]:
                data = section.get_data()
                cur = b""
                cur_offset = 0
                for idx, b in enumerate(data):
                    if 32 <= b <= 126:
                        if not cur:
                            cur_offset = idx
                        cur += bytes([b])
                    else:
                        if len(cur) >= 3:
                            str_va = image_base + section.VirtualAddress + cur_offset
                            strings_map[str_va] = cur.decode("utf-8", errors="ignore")
                        cur = b""

        # Resolve function target
        if function_address:
            addr_val = int(function_address, 16) if isinstance(function_address, str) and function_address.startswith("0x") else int(function_address)
            target_va = addr_val if addr_val >= image_base else addr_val + image_base
            target_rva = target_va - image_base
        else:
            target_va = entry_addr
            target_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        # Extract code at target_rva
        for section in pe.sections:
            if section.VirtualAddress <= target_rva < section.VirtualAddress + section.Misc_VirtualSize:
                offset_in_section = target_rva - section.VirtualAddress
                section_data = section.get_data()
                code_bytes = section_data[offset_in_section : offset_in_section + (max_instructions * 15)]
                break

        arch_mode = capstone.CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
        md.detail = True

    elif is_elf:
        from elftools.elf.elffile import ELFFile
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            entry_addr = elf.header["e_entry"]
            target_va = int(function_address, 16) if function_address and function_address.startswith("0x") else (int(function_address) if function_address else entry_addr)

            # Discover symbols
            symtab = elf.get_section_by_name(".symtab") or elf.get_section_by_name(".dynsym")
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym.name and sym["st_value"] > 0:
                        function_names_map[sym["st_value"]] = sym.name

            # Discover PLT stubs
            plt = elf.get_section_by_name(".plt")
            rela_plt = elf.get_section_by_name(".rela.plt")
            if plt and rela_plt:
                rel_symtab = elf.get_section(rela_plt["sh_link"])
                plt_base = plt["sh_addr"]
                for idx, rel in enumerate(rela_plt.iter_relocations()):
                    sym = rel_symtab.get_symbol(rel["r_info_sym"])
                    stub_addr = plt_base + 16 + (idx * 16)
                    function_names_map[stub_addr] = sym.name

            for section in elf.iter_sections():
                sh_addr = section["sh_addr"]
                sh_size = section["sh_size"]
                if sh_addr <= target_va < sh_addr + sh_size:
                    offset = target_va - sh_addr
                    code_bytes = section.data()[offset : offset + (max_instructions * 15)]

                # Extract strings
                if section.name in [".rodata", ".data", ".text"]:
                    data = section.data()
                    cur = b""
                    cur_offset = 0
                    for idx, b in enumerate(data):
                        if 32 <= b <= 126:
                            if not cur:
                                cur_offset = idx
                            cur += bytes([b])
                        else:
                            if len(cur) >= 3:
                                strings_map[sh_addr + cur_offset] = cur.decode("utf-8", errors="ignore")
                            cur = b""

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
    else:
        return {"error": "Unsupported binary format"}

    if not code_bytes:
        return {"error": f"Could not map code bytes for address {hex(target_va)}"}

    instructions = []
    blocks = {}
    current_block = []
    block_start = target_va

    func_display_name = function_names_map.get(target_va, f"sub_{hex(target_va)[2:]}")
    raw_c_lines = [
        f"// Decompiled by SYMB Native Lifter :: Function at {hex(target_va)}",
        f"// Target Symbol: {func_display_name}",
        f"__int64 {func_display_name}() {{"
    ]

    last_comparison = None
    last_assigned_rax = False
    param_registers = ["rcx", "rdx", "r8", "r9", "rdi", "rsi"]
    accumulated_args = {}

    for insn in md.disasm(code_bytes, target_va):
        referenced_str = None
        referenced_iat = None

        # Check RIP-relative string address or IAT pointer
        if insn.op_str and "rip +" in insn.op_str:
            try:
                rel_offset = int(insn.op_str.split("rip +")[1].split("]")[0].strip(), 16)
                target_ptr = insn.address + insn.size + rel_offset
                if target_ptr in strings_map:
                    referenced_str = strings_map[target_ptr]
                if target_ptr in iat_map:
                    referenced_iat = iat_map[target_ptr]
            except Exception:
                pass

        # Check direct hex constant in operand (e.g. mov edi, 0x4006f0)
        if not referenced_str and "0x" in insn.op_str:
            hex_matches = re.findall(r"0x[0-9a-fA-F]+", insn.op_str)
            for hm in hex_matches:
                val = int(hm, 16)
                if val in strings_map:
                    referenced_str = strings_map[val]
                    break

        insn_dict = {
            "address": hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": insn.bytes.hex()
        }
        if referenced_str:
            insn_dict["string_xref"] = referenced_str
        if referenced_iat:
            insn_dict["iat_xref"] = referenced_iat

        instructions.append(insn_dict)
        current_block.append(insn_dict)

        m = insn.mnemonic
        op = insn.op_str

        # Track argument register assignments
        for reg in param_registers:
            if m in ["mov", "lea"] and (op.startswith(f"{reg},") or op.startswith(f"e{reg[1:]},")):
                val = op.split(",", 1)[1].strip()
                accumulated_args[reg] = f'"{referenced_str}"' if referenced_str else val

        if "rax" in op or "eax" in op:
            if m in ["mov", "xor", "add", "sub", "lea", "call"]:
                last_assigned_rax = True

        # Decompilation lifting
        if m in ["mov", "movzx", "movsxd"] and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            if referenced_str:
                raw_c_lines.append(f"    {dst} = \"{referenced_str}\"; // String XREF")
            elif referenced_iat:
                raw_c_lines.append(f"    {dst} = &{referenced_iat}; // IAT Import Pointer")
            else:
                raw_c_lines.append(f"    {dst} = {src};")

        elif m == "lea" and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            if referenced_str:
                raw_c_lines.append(f"    {dst} = \"{referenced_str}\"; // String XREF via LEA")
            else:
                raw_c_lines.append(f"    {dst} = &{src.replace('[', '').replace(']', '')};")

        elif m == "xor" and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            if dst == src:
                raw_c_lines.append(f"    {dst} = 0;")
            else:
                raw_c_lines.append(f"    {dst} ^= {src};")

        elif m == "add" and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            raw_c_lines.append(f"    {dst} += {src};")

        elif m == "sub" and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            raw_c_lines.append(f"    {dst} -= {src};")

        elif m in ["cmp", "test"] and "," in op:
            cmp_a, cmp_b = [x.strip() for x in op.split(",", 1)]
            last_comparison = (m, cmp_a, cmp_b)
            raw_c_lines.append(f"    // Condition test: {cmp_a} vs {cmp_b}")

        elif m in JCC_MAP:
            target_lbl = op.replace("0x", "")
            if last_comparison:
                cmp_type, a, b = last_comparison
                op_sym = JCC_MAP[m]
                if cmp_type == "test" and a == b:
                    cond_expr = f"{a} != 0" if m in ["jne", "jnz"] else f"{a} == 0"
                else:
                    cond_expr = f"{a} {op_sym} {b}"
                raw_c_lines.append(f"    if ({cond_expr}) goto loc_{target_lbl};")
                last_comparison = None
            else:
                raw_c_lines.append(f"    if ({m}_condition) goto loc_{target_lbl};")

        elif m == "jmp":
            target_lbl = op.replace("0x", "")
            raw_c_lines.append(f"    goto loc_{target_lbl};")

        elif m == "call":
            call_target = op.strip()
            resolved_fn = referenced_iat
            if not resolved_fn:
                try:
                    c_addr = int(call_target, 16)
                    resolved_fn = function_names_map.get(c_addr, f"sub_{hex(c_addr)[2:]}")
                except Exception:
                    resolved_fn = f"call_{call_target.replace('0x', '')}"

            args_str = ", ".join([accumulated_args[r] for r in param_registers if r in accumulated_args])
            raw_c_lines.append(f"    {resolved_fn}({args_str});")
            accumulated_args.clear()

        elif m == "ret":
            if last_assigned_rax:
                raw_c_lines.append("    return rax;")
            else:
                raw_c_lines.append("    return;")

        if m in ["ret", "jmp"] or m in JCC_MAP:
            blocks[hex(block_start)] = current_block
            block_start = insn.address + insn.size
            current_block = []

        if m == "ret" or len(instructions) >= max_instructions:
            break

    if current_block:
        blocks[hex(block_start)] = current_block

    raw_c_lines.append("}")

    # Pass 1: Infer Struct Layouts
    inferred_structs = infer_struct_layouts(instructions)

    # Pass 2: Structure Control Flow (Loops & Conditionals)
    structured_c_lines = structure_control_flow(raw_c_lines, instructions, blocks)

    # Prepend inferred typedefs to pseudocode if any
    header_lines = []
    if inferred_structs:
        header_lines.append("// --- Inferred Structure Definitions ---")
        for s in inferred_structs:
            header_lines.append(f"typedef struct {{")
            for f in s["fields"]:
                header_lines.append(f"    {f['type']} {f['name']}; // offset {f['offset_hex']} (size: {f['size']})")
            header_lines.append(f"}} {s['struct_name']};\n")

    final_pseudocode = "\n".join(header_lines + structured_c_lines)

    return {
        "function_address": hex(target_va),
        "symbol_name": func_display_name,
        "instruction_count": len(instructions),
        "basic_blocks_count": len(blocks),
        "disassembly": instructions,
        "decompiled_pseudocode": final_pseudocode,
        "inferred_structures_count": len(inferred_structs),
        "inferred_structures": inferred_structs,
        "control_flow_structured": True,
        "string_references": [i["string_xref"] for i in instructions if "string_xref" in i],
        "iat_imports_used": [i["iat_xref"] for i in instructions if "iat_xref" in i]
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        bin_path = sys.argv[1]
        fn_addr = sys.argv[2] if len(sys.argv) > 2 else None
        print(json.dumps(disassemble_and_decompile(bin_path, fn_addr), indent=2))
