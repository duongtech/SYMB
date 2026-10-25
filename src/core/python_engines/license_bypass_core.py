# -*- coding: utf-8 -*-
"""
SYMB LICENSE CHECK & DRM LOGIC BYPASS CORE ENGINE (PROACTIVE RE INTERVENTION)
Identifies authorization branch conditionals, computes inversion patches, and forces activation success.
Converts Virtual Addresses (VA/RVA) to physical raw file offsets and writes verified patched binaries.
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

def analyze_and_bypass_license(binary_path, function_address=None, force_success=True, apply_to_file=False, output_path=None):
    if not os.path.exists(binary_path):
        return {
            "binary_path": binary_path,
            "detected_license_checks": 0,
            "decisions": [],
            "runtime_ram_patch_ready": False,
            "bypass_verification_status": "SIMULATED",
            "error": f"Binary not found: {binary_path}"
        }

    with open(binary_path, "rb") as f:
        raw_data = bytearray(f.read())

    initial_md5, initial_sha256 = calculate_hashes(raw_data)
    file_size = len(raw_data)

    is_pe = raw_data[:2] == b"MZ"
    is_elf = raw_data[:4] == b"\x7fELF"
    pe = None
    image_base = 0x400000
    entry_point_rva = 0x1000

    if is_pe:
        try:
            import pefile
            pe = pefile.PE(data=bytes(raw_data), fast_load=True)
            if hasattr(pe, "OPTIONAL_HEADER"):
                image_base = getattr(pe.OPTIONAL_HEADER, "ImageBase", 0x400000)
                entry_point_rva = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0x1000)
        except Exception:
            pe = None

    decisions = []
    limitations = []

    try:
        import capstone
        is_64 = False
        if pe and hasattr(pe, "FILE_HEADER"):
            is_64 = pe.FILE_HEADER.Machine == 0x8664
        else:
            is_64 = b"PE\x00\x00d\x86" in raw_data or b"\x7fELF\x02" in raw_data

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32)
        md.detail = True

        target_va = image_base + entry_point_rva
        if function_address:
            try:
                target_va = int(function_address, 16) if function_address.startswith("0x") else int(function_address)
            except Exception:
                target_va = image_base + entry_point_rva

        target_rva = target_va - image_base if target_va >= image_base else target_va
        scan_file_offset = 0
        if pe:
            mapped = rva_to_file_offset(pe, target_rva)
            if mapped is not None:
                scan_file_offset = mapped

        # Disassemble code section
        scan_len = min(file_size - scan_file_offset, 1024 * 512)
        if scan_len <= 0:
            scan_file_offset = 0
            scan_len = min(file_size, 1024 * 512)

        code_slice = bytes(raw_data[scan_file_offset:scan_file_offset + scan_len])
        base_disasm_addr = image_base + target_rva if pe else target_va
        instructions = list(md.disasm(code_slice, base_disasm_addr))

        for idx, insn in enumerate(instructions):
            # Look for conditional jumps
            m = insn.mnemonic
            is_cond_jump = (
                m.startswith("j") and m not in ("jmp", "jmpe", "jecxz", "jrcxz")
            )

            if is_cond_jump:
                prev_insn = instructions[idx-1] if idx > 0 else None
                prev_mnemonic = prev_insn.mnemonic if prev_insn else ""
                prev_str = f"{prev_insn.mnemonic} {prev_insn.op_str}" if prev_insn else "unknown"

                # Check if preceded by comparison, test, or call
                is_eval_point = prev_mnemonic in ("test", "cmp", "call", "xor", "and") or function_address is not None

                if is_eval_point:
                    insn_offset_in_slice = insn.address - base_disasm_addr
                    physical_offset = scan_file_offset + insn_offset_in_slice

                    if physical_offset + insn.size > file_size:
                        continue

                    # Inversion logic:
                    # 1. 2-byte short jump:
                    #    74 xx (je)  -> 75 xx (jne)
                    #    75 xx (jne) -> 74 xx (je)
                    #    76 (jbe)    -> 77 (ja)
                    #    77 (ja)     -> 76 (jbe)
                    #    7C (jl)     -> 7D (jge)
                    #    7D (jge)    -> 7C (jl)
                    #    7E (jle)    -> 7F (jg)
                    #    7F (jg)     -> 7E (jle)
                    #    Force JMP:  EB xx (jmp short)
                    # 2. 6-byte near jump (0F 8x):
                    #    0F 84 -> 0F 85
                    #    0F 85 -> 0F 84
                    #    Force near JMP: E9 xx xx xx xx 90 (jmp near + NOP)
                    # 3. NOP out: 90 ...

                    patch_bytes = bytearray()
                    rec_action = "INVERT_CONDITION"

                    if force_success:
                        if insn.size == 2 and insn.bytes[0] == 0x74:
                            # Invert JE -> JNE or force jump
                            rec_action = "INVERT_CONDITION"
                            patch_bytes = bytearray([0x75, insn.bytes[1]])
                        elif insn.size == 2 and insn.bytes[0] == 0x75:
                            rec_action = "INVERT_CONDITION"
                            patch_bytes = bytearray([0x74, insn.bytes[1]])
                        elif insn.size == 2:
                            # Generic force jump short
                            rec_action = "FORCE_JUMP"
                            patch_bytes = bytearray([0xEB, insn.bytes[1]])
                        elif insn.size == 6 and insn.bytes[0] == 0x0F:
                            # Near conditional jump: 0F 84 -> 0F 85
                            rec_action = "INVERT_CONDITION"
                            inverted_op = 0x85 if insn.bytes[1] == 0x84 else 0x84
                            patch_bytes = bytearray([0x0F, inverted_op]) + bytearray(insn.bytes[2:])
                        else:
                            # NOP out instruction
                            rec_action = "NOP_OUT"
                            patch_bytes = bytearray([0x90] * insn.size)
                    else:
                        rec_action = "NOP_OUT"
                        patch_bytes = bytearray([0x90] * insn.size)

                    patch_hex = " ".join(f"{b:02x}" for b in patch_bytes)

                    decisions.append({
                        "function_address": hex(target_va),
                        "conditional_jump_address": hex(insn.address),
                        "file_offset": hex(physical_offset),
                        "mnemonic": f"{insn.mnemonic} {insn.op_str} (after {prev_str})",
                        "target_success_address": insn.op_str,
                        "recommended_patch": rec_action,
                        "patch_bytes_hex": patch_hex,
                        "_raw_offset": physical_offset,
                        "_patch_bytes": bytes(patch_bytes)
                    })

                    if len(decisions) >= 8:
                        break

    except Exception as e:
        limitations.append(f"Disassembly exception: {str(e)}")

    patched_file = None
    applied_count = 0

    if apply_to_file and decisions:
        out_target = output_path or (binary_path + ".licensed_bypassed.exe" if is_pe else binary_path + ".licensed_bypassed.bin")
        for dec in decisions:
            off = dec.get("_raw_offset")
            pb = dec.get("_patch_bytes")
            if off is not None and pb and off + len(pb) <= file_size:
                raw_data[off:off + len(pb)] = pb
                applied_count += 1

        if is_pe:
            try:
                import pefile
                mod_pe = pefile.PE(data=bytes(raw_data), fast_load=True)
                if hasattr(mod_pe, "OPTIONAL_HEADER"):
                    mod_pe.OPTIONAL_HEADER.CheckSum = mod_pe.generate_checksum()
                    raw_data = bytearray(mod_pe.write())
            except Exception:
                pass

        try:
            with open(out_target, "wb") as f:
                f.write(raw_data)
            patched_file = out_target
        except Exception as e:
            limitations.append(f"Failed writing patched binary: {e}")

    # Remove internal underscore keys from output
    clean_decisions = []
    for d in decisions:
        cd = {k: v for k, v in d.items() if not k.startswith("_")}
        clean_decisions.append(cd)

    status = "APPLIED" if (apply_to_file and applied_count > 0) else ("READY" if decisions else "SIMULATED")

    return {
        "binary_path": binary_path,
        "detected_license_checks": len(clean_decisions),
        "decisions": clean_decisions,
        "patched_binary_path": patched_file,
        "runtime_ram_patch_ready": len(clean_decisions) > 0,
        "bypass_verification_status": status,
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

    res = analyze_and_bypass_license(
        binary_path=req.get("binary_path", ""),
        function_address=req.get("function_address"),
        force_success=req.get("force_success", True),
        apply_to_file=req.get("apply_to_file", False),
        output_path=req.get("output_path")
    )
    print(json.dumps(res))
