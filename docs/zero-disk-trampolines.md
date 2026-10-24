# Zero-Disk Dynamic Memory Trampolines & In-Memory Hooks

When analyzing anti-tamper systems, binary integrity verifiers, or live game and enterprise daemons, modifying the executable file on disk triggers checksum alarms (e.g. Authenticode signature mismatch, VAC, BattleEye, or self-hashing checks).

**SYMB provides Zero-Disk In-Memory Hot-Patching via Trampolines**:

---

## 💉 Mechanics of Zero-Disk Trampolines

```mermaid
flowchart TD
    subgraph Process_RAM ["Target Process Virtual Memory Space"]
        direction TB
        FuncEntry["Target Function Entry<br/><code>0x7FFF0010: push rbp; mov rbp, rsp</code>"]
        Overwritten["Overwritten with 5-byte/14-byte DETOUR<br/><code>JMP [Hook Address]</code>"]
        RemainingBytes["Remaining Function Body<br/><code>0x7FFF0015: sub rsp, 0x40 ...</code>"]
    end

    subgraph Injected_Hooks ["Zero-Disk Allocated Trampoline"]
        direction TB
        HookPayload["SYMB Custom Hook Payload<br/>(Logic bypass, token capture, logger)"]
        TrampolineBuffer["Trampoline Buffer<br/>(Original Stolen Bytes: push rbp; mov rbp, rsp)"]
        JmpBack["Jump Back Instruction<br/><code>JMP 0x7FFF0015</code>"]
    end

    FuncEntry -.-> Overwritten
    Overwritten ==>|"Detour Redirect"| HookPayload
    HookPayload --> TrampolineBuffer
    TrampolineBuffer --> JmpBack
    JmpBack ==>|"Resume Original Flow"| RemainingBytes
```

1. **Virtual Memory Permission Management**:
   - Windows: Calls `VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)`.
   - Linux: Calls `mprotect(aligned_addr, size, PROT_READ | PROT_WRITE | PROT_EXEC)`.
2. **Stolen Bytes Preservation**:
   Extracts leading instructions and relocates them into a dedicated executable trampoline buffer.
3. **Atomic Jump Detour**:
   Writes an absolute 64-bit indirect jump (`FF 25 00 00 00 00 [64-bit pointer]`) or 32-bit relative jump (`E9 [relative_offset]`).
4. **Zero-Disk Integrity**:
   The disk image remains 100% authentic. All operations take place strictly within the running process virtual address space.

---

## 🛠️ MCP Tool: `hot_patch_live_memory`

### Input Parameters
```json
{
  "target_pid": 4820,
  "hook_address": "0x7FFF0024A100",
  "patch_bytes_hex": "4831C048FFC0C3",
  "method": "trampoline_detour"
}
```

### Result:
- Injects trampoline safely.
- Returns previous bytes for instant clean rollback.
- Confirms execution diversion.
