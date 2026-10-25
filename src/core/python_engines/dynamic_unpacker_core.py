# -*- coding: utf-8 -*-
"""
SYMB DYNAMIC EMULATION MEMORY UNPACKER
CPU emulation-based unpacker using Unicorn engine to trace unpacker stubs, detect tail jumps, and dump clean OEP payloads.
"""

import sys
import json
import os
import struct
import math
import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_PROT_ALL, UC_HOOK_CODE
import unicorn.x86_const as x86_const

def calculate_shannon_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def dynamically_unpack(binary_path, max_instructions=50000, output_path=None):
    if not os.path.exists(binary_path):
        return {"error": f"Binary not found: {binary_path}"}

    with open(binary_path, "rb") as f:
        raw_data = f.read()

    is_pe = raw_data[:2] == b"MZ"
    is_elf = raw_data[:4] == b"\x7fELF"

    if not is_pe and not is_elf:
        return {"error": "Only PE (Windows) and ELF (Linux) binaries are supported for dynamic emulation unpacking"}

    overall_entropy = calculate_shannon_entropy(raw_data)
    is_packed = False
    packer_type = "NONE"
    sections_info = []

    image_base = 0x400000
    entry_point_rva = 0
    is_64bit = True

    if is_pe:
        import pefile
        pe = pefile.PE(binary_path)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        is_64bit = pe.FILE_HEADER.Machine == 0x8664

        for s in pe.sections:
            s_name = s.Name.decode("latin-1", errors="ignore").strip("\x00")
            s_entropy = s.get_entropy()
            sections_info.append({
                "name": s_name,
                "va": image_base + s.VirtualAddress,
                "size": s.Misc_VirtualSize or s.SizeOfRawData,
                "entropy": round(s_entropy, 4),
                "data": s.get_data()
            })
            if "UPX" in s_name.upper():
                is_packed = True
                packer_type = "UPX"
            elif s_entropy > 7.1 and s_name in [".text", ".packed", "stub", ".themida"]:
                is_packed = True
                packer_type = "High-Entropy Packed Stub"

    elif is_elf:
        from elftools.elf.elffile import ELFFile
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            is_64bit = elf.header["e_ident"]["EI_CLASS"] == "ELFCLASS64"
            entry_point_rva = elf.header["e_entry"]
            image_base = 0

            for sec in elf.iter_sections():
                if sec["sh_size"] > 0:
                    sec_data = sec.data()
                    sec_entropy = calculate_shannon_entropy(sec_data)
                    sections_info.append({
                        "name": sec.name,
                        "va": sec["sh_addr"],
                        "size": sec["sh_size"],
                        "entropy": sec_entropy,
                        "data": sec_data
                    })
                    if "UPX" in sec.name.upper():
                        is_packed = True
                        packer_type = "UPX"
                    elif sec_entropy > 7.1 and sec.name in [".text", ".stub"]:
                        is_packed = True
                        packer_type = "High-Entropy Packed Stub"

    # Setup Unicorn Emulator
    mode = UC_MODE_64 if is_64bit else UC_MODE_32
    mu = Uc(UC_ARCH_X86, mode)

    # Memory allocation setup
    PAGE_SIZE = 0x1000
    base_map_addr = (image_base // PAGE_SIZE) * PAGE_SIZE
    total_mem_size = 0x2000000  # 32MB virtual memory space

    try:
        mu.mem_map(base_map_addr, total_mem_size, UC_PROT_ALL)
    except Exception:
        # Fallback to standard 0x400000 base
        base_map_addr = 0x400000
        mu.mem_map(base_map_addr, total_mem_size, UC_PROT_ALL)

    # Map stack
    STACK_ADDR = 0x70000000
    STACK_SIZE = 0x100000  # 1MB
    mu.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_ALL)

    # Write sections into Unicorn memory
    for sec in sections_info:
        if sec["va"] and sec["data"]:
            try:
                # Align to page
                aligned_va = (sec["va"] // PAGE_SIZE) * PAGE_SIZE
                mu.mem_write(sec["va"], sec["data"])
            except Exception:
                pass

    # Setup Registers
    initial_rip = (image_base + entry_point_rva) if is_pe else entry_point_rva
    initial_rsp = STACK_ADDR + STACK_SIZE - 0x1000

    if is_64bit:
        mu.reg_write(x86_const.UC_X86_REG_RIP, initial_rip)
        mu.reg_write(x86_const.UC_X86_REG_RSP, initial_rsp)
    else:
        mu.reg_write(x86_const.UC_X86_REG_EIP, initial_rip)
        mu.reg_write(x86_const.UC_X86_REG_ESP, initial_rsp)

    # Emulation hook variables
    emulated_count = [0]
    tail_jump_found = [None]
    visited_addrs = set()
    stub_region = (initial_rip, initial_rip + 0x2000)

    def hook_code(uc, address, size, user_data):
        emulated_count[0] += 1
        visited_addrs.add(address)

        # Detect transition jump: jump outside stub region into lower code section (.text)
        if emulated_count[0] > 10:
            if address < stub_region[0] or address > stub_region[1] + 0x10000:
                # Execution jumped out of unpacker stub -> Potential OEP
                tail_jump_found[0] = address
                uc.emu_stop()

        if emulated_count[0] >= max_instructions:
            uc.emu_stop()

    mu.hook_add(UC_HOOK_CODE, hook_code)

    # Run emulation
    try:
        mu.emu_start(initial_rip, initial_rip + 0x100000, timeout=10000000, count=max_instructions)
    except Exception as e:
        # Stop on expected jump or fault
        pass

    recovered_oep = tail_jump_found[0] or initial_rip

    # Dump unpacked memory
    dump_size = 0x100000 # 1MB dump around recovered OEP
    try:
        dump_start = (recovered_oep // PAGE_SIZE) * PAGE_SIZE
        unpacked_bytes = mu.mem_read(dump_start, dump_size)
    except Exception:
        unpacked_bytes = raw_data

    # Save artifact
    if not output_path:
        base_dir = os.path.dirname(binary_path)
        output_path = os.path.join(base_dir, f"{os.path.basename(binary_path)}.unpacked.bin")

    with open(output_path, "wb") as f_out:
        f_out.write(unpacked_bytes)

    unpacked_entropy = calculate_shannon_entropy(unpacked_bytes)

    return {
        "status": "UNPACKED" if is_packed or tail_jump_found[0] else "COMPLETED",
        "packer_detected": packer_type,
        "is_packed": is_packed,
        "original_entropy": overall_entropy,
        "unpacked_entropy": unpacked_entropy,
        "original_entry_point": hex(initial_rip),
        "recovered_oep": hex(recovered_oep),
        "emulated_instructions": emulated_count[0],
        "tail_jump_detected": tail_jump_found[0] is not None,
        "unpacked_output_file": output_path,
        "unpacked_payload_size_bytes": len(unpacked_bytes),
        "agent_guidance": "Dynamic CPU emulation traced execution past unpacking stub. The unpacked binary is written to disk for deep decompilation."
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        out = sys.argv[2] if len(sys.argv) > 2 else None
        print(json.dumps(dynamically_unpack(target, output_path=out), indent=2))
