# -*- coding: utf-8 -*-
"""
SYMB ADVANCED BINARY PROTECTIONS & PACKER DETECTOR
Identifies Packers (UPX, Themida, VMProtect), Anti-Debugging APIs, Anti-VM artifacts, and Timing Traps
"""

import sys
import json
import os
import re

PACKER_SIGNATURES = {
    "UPX": [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
    "VMProtect": [b".vmp0", b".vmp1", b".vmp2", b"VMProtect"],
    "Themida/WinLicense": [b".themida", b".wl", b"Themida", b"WinLicense"],
    "Enigma": [b".enigma1", b".enigma2", b"Enigma"],
    "ASPack": [b".aspack", b"ASPack"],
    "PECompact": [b".pec", b"PECompact"],
    "MPRESS": [b".mpress1", b".mpress2"]
}

ANTI_DEBUG_APIS = [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "ZwQueryInformationProcess",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "FindWindowA",
    "FindWindowW",
    "GetTickCount",
    "QueryPerformanceCounter",
    "timeGetTime",
    "BlockInput",
    "NtSetInformationThread",
    "SetUnhandledExceptionFilter"
]

ANTI_VM_STRINGS = [
    b"VMware", b"vmware", b"VBox", b"vbox", b"VirtualBox",
    b"QEMU", b"qemu", b"Xen", b"Sandboxie", b"wireshark",
    b"x64dbg", b"ida.exe", b"ida64.exe", b"ollydbg"
]

def analyze_protections(binary_path):
    if not os.path.exists(binary_path):
        return {"error": f"Binary not found: {binary_path}"}

    with open(binary_path, "rb") as f:
        content = f.read()

    detected_packers = []
    section_names = []
    detected_anti_debug_apis = []
    detected_anti_vm = []
    timing_trap_detected = False
    peb_access_detected = False

    # Check PE / ELF
    is_pe = content[:2] == b"MZ"
    is_elf = content[:4] == b"\x7fELF"

    if is_pe:
        import pefile
        try:
            pe = pefile.PE(data=content)
            for s in pe.sections:
                s_name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                section_names.append(s_name)

            # Check imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            name_str = imp.name.decode("utf-8", errors="ignore")
                            for ad_api in ANTI_DEBUG_APIS:
                                if ad_api.lower() == name_str.lower():
                                    detected_anti_debug_apis.append(name_str)
        except Exception as e:
            pass
    elif is_elf:
        from elftools.elf.elffile import ELFFile
        import io
        try:
            elf = ELFFile(io.BytesIO(content))
            for s in elf.iter_sections():
                section_names.append(s.name)
        except Exception:
            pass

    # Scan for packer signatures
    for packer, sigs in PACKER_SIGNATURES.items():
        found = False
        for s in section_names:
            for sig in sigs:
                if sig.decode("latin-1", errors="ignore").lower() in s.lower():
                    detected_packers.append(f"{packer} (via section '{s}')")
                    found = True
                    break
            if found:
                break
        if not found:
            for sig in sigs:
                if sig in content:
                    detected_packers.append(f"{packer} (signature in payload)")
                    break

    # Scan for anti-vm strings
    for vm_sig in ANTI_VM_STRINGS:
        if vm_sig in content:
            detected_anti_vm.append(vm_sig.decode("latin-1", errors="ignore"))

    # ASM Heuristic Byte Patterns
    # RDTSC: 0F 31
    if b"\x0f\x31" in content:
        timing_trap_detected = True

    # PEB check in 32-bit (fs:[0x30]: 64 A1 30 00 00 00 or 64 8B ... 30) or 64-bit (gs:[0x60]: 65 48 8B ... 60)
    if b"\x64\xa1\x30\x00\x00\x00" in content or b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00" in content:
        peb_access_detected = True

    risk_score = 0
    if detected_packers:
        risk_score += 40
    risk_score += min(30, len(detected_anti_debug_apis) * 10)
    risk_score += min(20, len(detected_anti_vm) * 5)
    if timing_trap_detected:
        risk_score += 10
    if peb_access_detected:
        risk_score += 15

    risk_level = "LOW"
    if risk_score >= 60:
        risk_level = "CRITICAL / HEAVILY ARMORED"
    elif risk_score >= 30:
        risk_level = "MODERATE"

    return {
        "binary_path": binary_path,
        "format": "PE/COFF" if is_pe else ("ELF" if is_elf else "Raw/Unknown"),
        "protection_risk_score": min(100, risk_score),
        "protection_risk_level": risk_level,
        "detected_packers": list(set(detected_packers)),
        "anti_debugging_apis": list(set(detected_anti_debug_apis)),
        "anti_vm_signatures": list(set(detected_anti_vm)),
        "heuristics": {
            "timing_trap_rdtsc": timing_trap_detected,
            "peb_direct_read": peb_access_detected
        },
        "analyzed_sections": section_names[:10]
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(json.dumps(analyze_protections(target), indent=2))
