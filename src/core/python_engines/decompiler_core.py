# -*- coding: utf-8 -*-
"""
SYMB HIGH-SPEED NATIVE FUNCTION DECOMPILER & DISASSEMBLER
Fast disassembly, string/xref resolution, PLT/IAT symbol recovery, condition reconstruction, and pseudocode lifting via Capstone & AST
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
    c_lines = [
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
                c_lines.append(f"    {dst} = \"{referenced_str}\"; // String XREF")
            elif referenced_iat:
                c_lines.append(f"    {dst} = &{referenced_iat}; // IAT Import Pointer")
            else:
                c_lines.append(f"    {dst} = {src};")

        elif m == "lea" and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            if referenced_str:
                c_lines.append(f"    {dst} = \"{referenced_str}\"; // String XREF via LEA")
            else:
                c_lines.append(f"    {dst} = &{src.replace('[', '').replace(']', '')};")

        elif m == "xor" and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            if dst == src:
                c_lines.append(f"    {dst} = 0;")
            else:
                c_lines.append(f"    {dst} ^= {src};")

        elif m == "add" and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            c_lines.append(f"    {dst} += {src};")

        elif m == "sub" and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            c_lines.append(f"    {dst} -= {src};")

        elif m in ["cmp", "test"] and "," in op:
            cmp_a, cmp_b = [x.strip() for x in op.split(",", 1)]
            last_comparison = (m, cmp_a, cmp_b)
            c_lines.append(f"    // Condition test: {cmp_a} vs {cmp_b}")

        elif m in JCC_MAP:
            target_lbl = op.replace("0x", "")
            if last_comparison:
                cmp_type, a, b = last_comparison
                op_sym = JCC_MAP[m]
                if cmp_type == "test" and a == b:
                    cond_expr = f"{a} != 0" if m in ["jne", "jnz"] else f"{a} == 0"
                else:
                    cond_expr = f"{a} {op_sym} {b}"
                c_lines.append(f"    if ({cond_expr}) goto loc_{target_lbl};")
                last_comparison = None
            else:
                c_lines.append(f"    if ({m}_condition) goto loc_{target_lbl};")

        elif m == "jmp":
            target_lbl = op.replace("0x", "")
            c_lines.append(f"    goto loc_{target_lbl};")

        elif m == "call":
            call_target = op.strip()
            # Resolve target function or IAT
            resolved_fn = referenced_iat
            if not resolved_fn:
                try:
                    c_addr = int(call_target, 16)
                    resolved_fn = function_names_map.get(c_addr, f"sub_{hex(c_addr)[2:]}")
                except Exception:
                    resolved_fn = f"call_{call_target.replace('0x', '')}"

            # Format call with known arguments
            args_str = ", ".join([accumulated_args[r] for r in param_registers if r in accumulated_args])
            c_lines.append(f"    {resolved_fn}({args_str});")
            accumulated_args.clear()

        elif m == "ret":
            if last_assigned_rax:
                c_lines.append("    return rax;")
            else:
                c_lines.append("    return;")

        # Basic block splitting
        if m in ["ret", "jmp"] or m in JCC_MAP:
            blocks[hex(block_start)] = current_block
            block_start = insn.address + insn.size
            current_block = []

        if m == "ret" or len(instructions) >= max_instructions:
            break

    if current_block:
        blocks[hex(block_start)] = current_block

    c_lines.append("}")

    return {
        "function_address": hex(target_va),
        "symbol_name": func_display_name,
        "instruction_count": len(instructions),
        "basic_blocks_count": len(blocks),
        "disassembly": instructions,
        "decompiled_pseudocode": "\n".join(c_lines),
        "string_references": [i["string_xref"] for i in instructions if "string_xref" in i],
        "iat_imports_used": [i["iat_xref"] for i in instructions if "iat_xref" in i]
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        bin_path = sys.argv[1]
        fn_addr = sys.argv[2] if len(sys.argv) > 2 else None
        print(json.dumps(disassemble_and_decompile(bin_path, fn_addr), indent=2))
