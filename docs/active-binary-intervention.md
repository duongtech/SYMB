# ⚔️ SYMB Active Binary Intervention & Weaponized RE Guide

## 1. Overview: The Shift from Passive RE to Active Intervention

Mainstream reverse engineering assistants (such as `morluto/rea`) operate strictly as **passive observers**:
- They read binaries, parse headers, lift basic blocks to pseudocode, and log static observations.
- By design and policy, they refuse to modify binary files, bypass licensing checks, neutralize anti-debug protections, or inject runtime trampolines.

**SYMB Titan v2.0.0** bridges this gap by introducing the **Active Binary Intervention Arsenal**. When autonomous AI agents identify security controls, anti-analysis traps, or license validation gates, SYMB provides the native surgical capabilities to **invert, neutralize, and permanently patch** targets on disk and in memory.

---

## 2. Core Technical Innovations

### I. Surgical RVA-to-Raw File Offset Translation
When decompilers or debuggers analyze an executable, instruction addresses are represented as **Virtual Addresses (VA)** or **Relative Virtual Addresses (RVA)** based on the image base (e.g. `0x400000` or `0x140000000`).

To patch an executable on disk, SYMB inspects PE/ELF section headers and computes:
$$\text{RawOffset} = (\text{RVA} - \text{Section.VirtualAddress}) + \text{Section.PointerToRawData}$$

This ensures byte patches land on the exact physical file offset without corrupting headers or adjacent sections.

### II. Automatic PE Checksum Recalculation
Windows PE loader and driver verification modules check `OptionalHeader.CheckSum`. Any raw byte modification invalidates this checksum. SYMB calculates the standard PE checksum algorithm:
$$\text{CheckSum} = \sum \text{Words} \pmod{2^{32}} + \text{FileSize}$$
and updates the optional header in-place before saving.

### III. Safe Backups & Visual Hex Diffs
Before any in-place patch is applied, SYMB automatically creates a timestamped `.bak` duplicate and emits canonical visual diffs:
```json
{
  "offset_hex": "0x400",
  "rva_hex": "0x1000",
  "original_bytes": "0f 31",
  "patched_bytes": "90 90",
  "description": "Neutralized RDTSC timing trap"
}
```

---

## 3. Tool Reference & Execution Workflows

### 🛠️ 1. `patch_binary_executable`
Surgical physical disk patcher for PE, ELF, Mach-O, and RAW binaries.

#### MCP Input:
```json
{
  "binary_path": "C:\\target\\app.exe",
  "patches": [
    {
      "address": "0x401520",
      "bytes_hex": "90 90 90",
      "description": "NOP out integrity check",
      "is_va": true
    },
    {
      "offset": "0x1240",
      "bytes_hex": "EB 15",
      "description": "Force unconditional jump"
    }
  ],
  "create_backup": true,
  "recalculate_pe_checksum": true
}
```

---

### 🛠️ 2. `neutralize_anti_debugging`
Automated detector and patcher for anti-debugging techniques:
- **Inline Opcode Traps**: `RDTSC` (`0F 31`), `RDTSCP` (`0F 01 F9`), `INT 2D` (`CD 2D`), `INT 3` (`CC`), `ICEBP` (`F1`).
- **PEB Inspection**: Direct segment register access to `BeingDebugged` (`FS:[0x30] + 2` in x86, `GS:[0x60] + 2` in x64) and `NtGlobalFlag` (`FS:[0x30] + 0x68`).
- **API Call Sites**: Imports and calls to `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugStringA`, `QueryPerformanceCounter`.

#### MCP Input:
```json
{
  "binary_path": "C:\\target\\protected.exe",
  "auto_patch": true,
  "output_path": "C:\\target\\protected.unhooked.exe"
}
```

---

### 🛠️ 3. `bypass_license_authorization`
Disassembles surrounding code at authorization check sites, detects comparison operations (`CMP`, `TEST`, `CALL check_license`), and computes inversion patches:
- **Short Conditional Jumps (2 bytes)**:
  - `JZ` / `JE` (`0x74`) $\leftrightarrow$ `JNZ` / `JNE` (`0x75`)
  - `JBE` (`0x76`) $\leftrightarrow$ `JA` (`0x77`)
  - Force Short `JMP` (`0xEB`)
- **Near Conditional Jumps (6 bytes)**:
  - `0F 84 xx xx xx xx` $\leftrightarrow$ `0F 85 xx xx xx xx`
  - Force Near `JMP` (`E9 xx xx xx xx 90`)
- **Return Value Forcing**:
  - `MOV EAX, 1; RET` (`B8 01 00 00 00 C3`)

#### MCP Input:
```json
{
  "binary_path": "C:\\target\\software.exe",
  "force_success": true,
  "apply_to_file": true,
  "output_path": "C:\\target\\software.cracked.exe"
}
```

---

### 🛠️ 4. `generate_frida_instrumentation`
Synthesizes dynamic instrumentation scripts for active runtime hijacking:
- **`ssl_unpinning`**: Universal TrustManagerImpl, OkHttp3 CertificatePinner, and BoringSSL hooks.
- **`root_jailbreak_bypass`**: Su binary existence cloaking (`/system/bin/su`, `/system/xbin/su`, `magisk`), RootBeer API hijacking.
- **`anti_debug_runtime_cloak`**: Windows `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` and Linux `ptrace(PTRACE_TRACEME)` hooks.
- **`crypto_tracer`**: Dynamic sniffer for `javax.crypto.Cipher`, AES keys, IVs, and plaintext streams.

#### MCP Input:
```json
{
  "target": "com.banking.app",
  "platform": "android",
  "script_type": "ssl_unpinning"
}
```

---

### 🛠️ 5. `hot_patch_live_memory`
Zero-disk live memory surgeon:
- Uses Win32 `OpenProcess`, `VirtualProtectEx` (`PAGE_EXECUTE_READWRITE`), `WriteProcessMemory`, and `FlushInstructionCache`.
- On Linux, writes directly to `/proc/{pid}/mem`.
- Completely avoids modifying disk binaries, bypassing file integrity and hash checks.
