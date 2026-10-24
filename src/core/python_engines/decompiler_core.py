# -*- coding: utf-8 -*-
"""
SYMB HIGH-SPEED NATIVE FUNCTION DECOMPILER & DISASSEMBLER
Fast disassembly, string/xref resolution, and pseudocode lifting via Capstone & AST
"""

import sys
import json
import os
import capstone

def disassemble_and_decompile(binary_path, function_address=None, max_instructions=250):
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

    if is_pe:
        import pefile
        pe = pefile.PE(binary_path)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint + image_base
        
        # Build string cache from .rdata/.data
        for section in pe.sections:
            s_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            if s_name in [".rdata", ".data", ".text"]:
                data = section.get_data()
                # extract ascii strings > 4 chars
                cur = b""
                cur_offset = 0
                for idx, b in enumerate(data):
                    if 32 <= b <= 126:
                        if not cur:
                            cur_offset = idx
                        cur += bytes([b])
                    else:
                        if len(cur) >= 4:
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

            for section in elf.iter_sections():
                sh_addr = section["sh_addr"]
                sh_size = section["sh_size"]
                if sh_addr <= target_va < sh_addr + sh_size:
                    offset = target_va - sh_addr
                    code_bytes = section.data()[offset : offset + (max_instructions * 15)]
                    break

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
    
    # Lifted C statements
    c_lines = [f"// Decompiled by SYMB Native Lifter :: Function at {hex(target_va)}", f"void sub_{hex(target_va)[2:]}() {{"]
    local_vars = set()

    for insn in md.disasm(code_bytes, target_va):
        referenced_str = None
        # Check RIP-relative string address
        if insn.op_str and "rip +" in insn.op_str:
            try:
                rel_offset = int(insn.op_str.split("rip +")[1].split("]")[0].strip(), 16)
                target_str_addr = insn.address + insn.size + rel_offset
                if target_str_addr in strings_map:
                    referenced_str = strings_map[target_str_addr]
            except:
                pass

        insn_dict = {
            "address": hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": insn.bytes.hex()
        }
        if referenced_str:
            insn_dict["string_xref"] = referenced_str

        instructions.append(insn_dict)
        current_block.append(insn_dict)

        # Decompilation heuristic lifting
        m = insn.mnemonic
        op = insn.op_str
        
        if m in ["mov", "movzx", "movsxd"] and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            if referenced_str:
                c_lines.append(f"    {dst} = \"{referenced_str}\"; // String XREF")
            else:
                c_lines.append(f"    {dst} = {src};")
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
        elif m == "cmp" and "," in op:
            dst, src = [x.strip() for x in op.split(",", 1)]
            c_lines.append(f"    // Compare {dst} with {src}")
        elif m.startswith("j") and m not in ["jmp"]:
            c_lines.append(f"    if ({m}_condition) goto loc_{op.replace('0x', '')};")
        elif m == "jmp":
            c_lines.append(f"    goto loc_{op.replace('0x', '')};")
        elif m == "call":
            c_lines.append(f"    call_{op.replace('0x', '')}();")
        elif m == "ret":
            c_lines.append("    return;")

        # Basic block terminators
        if m in ["ret", "jmp", "je", "jne", "jg", "jl", "jge", "jle", "ja", "jb"]:
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
        "instruction_count": len(instructions),
        "basic_blocks_count": len(blocks),
        "disassembly": instructions,
        "decompiled_pseudocode": "\n".join(c_lines),
        "string_references": [i["string_xref"] for i in instructions if "string_xref" in i]
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        bin_path = sys.argv[1]
        fn_addr = sys.argv[2] if len(sys.argv) > 2 else None
        print(json.dumps(disassemble_and_decompile(bin_path, fn_addr), indent=2))
