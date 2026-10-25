# -*- coding: utf-8 -*-
"""
SYMB REAL ZERO-DISK LIVE PROCESS HOT-PATCHER CORE ENGINE
Real-time Virtual Memory Surgeon for Windows (Win32 API) and Linux (/proc/pid/mem)
"""

import sys
import json
import os
import binascii

def hot_patch_live_memory(pid, memory_address_str, patch_bytes_hex, expected_original_bytes=None):
    clean_hex = patch_bytes_hex.replace(" ", "").replace("0x", "")
    try:
        patch_bytes = bytes.fromhex(clean_hex)
    except Exception as e:
        return {
            "success": False,
            "pid": pid,
            "memory_address": memory_address_str,
            "bytes_written": 0,
            "previous_bytes": "",
            "error": f"Invalid patch hex string: {str(e)}"
        }

    patch_len = len(patch_bytes)
    target_addr = int(memory_address_str, 16) if memory_address_str.startswith("0x") else int(memory_address_str)

    # Windows Native Implementation
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32

        PROCESS_VM_READ = 0x0010
        PROCESS_VM_WRITE = 0x0020
        PROCESS_VM_OPERATION = 0x0008
        PROCESS_QUERY_INFORMATION = 0x0400
        PAGE_EXECUTE_READWRITE = 0x40

        hProcess = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            False,
            pid
        )
        if not hProcess:
            err = kernel32.GetLastError()
            return {
                "success": False,
                "pid": pid,
                "memory_address": hex(target_addr),
                "bytes_written": 0,
                "previous_bytes": "",
                "error": f"OpenProcess failed for PID {pid} (Win32 Error: {err})"
            }

        try:
            # 1. Read previous bytes
            read_buf = ctypes.create_string_buffer(patch_len)
            bytes_read = ctypes.c_size_t(0)
            prev_hex = ""
            if kernel32.ReadProcessMemory(hProcess, ctypes.c_void_p(target_addr), read_buf, patch_len, ctypes.byref(bytes_read)):
                prev_hex = " ".join(f"{b:02x}" for b in read_buf.raw[:bytes_read.value])

            # 2. VirtualProtectEx to PAGE_EXECUTE_READWRITE
            old_protect = wintypes.DWORD()
            if not kernel32.VirtualProtectEx(hProcess, ctypes.c_void_p(target_addr), patch_len, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)):
                err = kernel32.GetLastError()
                return {
                    "success": False,
                    "pid": pid,
                    "memory_address": hex(target_addr),
                    "bytes_written": 0,
                    "previous_bytes": prev_hex,
                    "error": f"VirtualProtectEx failed: {err}"
                }

            # 3. Write patch bytes
            write_buf = ctypes.create_string_buffer(patch_bytes, patch_len)
            bytes_written = ctypes.c_size_t(0)
            write_ok = kernel32.WriteProcessMemory(hProcess, ctypes.c_void_p(target_addr), write_buf, patch_len, ctypes.byref(bytes_written))

            # 4. Restore protection and flush CPU instruction cache
            kernel32.VirtualProtectEx(hProcess, ctypes.c_void_p(target_addr), patch_len, old_protect.value, ctypes.byref(old_protect))
            kernel32.FlushInstructionCache(hProcess, ctypes.c_void_p(target_addr), patch_len)

            if write_ok and bytes_written.value == patch_len:
                return {
                    "success": True,
                    "pid": pid,
                    "memory_address": hex(target_addr),
                    "bytes_written": bytes_written.value,
                    "previous_bytes": prev_hex or (expected_original_bytes or "unknown")
                }
            else:
                return {
                    "success": False,
                    "pid": pid,
                    "memory_address": hex(target_addr),
                    "bytes_written": bytes_written.value,
                    "previous_bytes": prev_hex,
                    "error": f"WriteProcessMemory incomplete: wrote {bytes_written.value}/{patch_len} bytes"
                }
        finally:
            kernel32.CloseHandle(hProcess)

    # Linux /proc/<pid>/mem Implementation
    elif sys.platform.startswith("linux"):
        mem_path = f"/proc/{pid}/mem"
        try:
            prev_hex = ""
            with open(mem_path, "rb+") as f:
                f.seek(target_addr)
                prev_bytes = f.read(patch_len)
                prev_hex = " ".join(f"{b:02x}" for b in prev_bytes)
                f.seek(target_addr)
                f.write(patch_bytes)
            return {
                "success": True,
                "pid": pid,
                "memory_address": hex(target_addr),
                "bytes_written": patch_len,
                "previous_bytes": prev_hex
            }
        except Exception as e:
            return {
                "success": False,
                "pid": pid,
                "memory_address": hex(target_addr),
                "bytes_written": 0,
                "previous_bytes": "",
                "error": f"Failed writing /proc/{pid}/mem: {str(e)}"
            }

    return {
        "success": False,
        "pid": pid,
        "memory_address": memory_address_str,
        "bytes_written": 0,
        "previous_bytes": "",
        "error": f"Unsupported platform: {sys.platform}"
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            req = json.loads(sys.argv[1])
            res = hot_patch_live_memory(
                req.get("pid", 0),
                req.get("memory_address", "0x0"),
                req.get("patch_bytes_hex", ""),
                req.get("expected_original_bytes")
            )
            print(json.dumps(res))
        except Exception as e:
            print(json.dumps({
                "success": False,
                "pid": 0,
                "memory_address": "0x0",
                "bytes_written": 0,
                "previous_bytes": "",
                "error": str(e)
            }))
