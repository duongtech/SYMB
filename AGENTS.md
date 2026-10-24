# Instructions for AI Agents using SYMB

This file guides AI agents (Claude Code, Cursor, Antigravity, Copilot, Codex) when calling SYMB MCP tools.

## Core Rules for Agents

1. **Verify Binary Availability**:
   Before initiating symbolic execution, ensure the target binary path exists and is accessible.
2. **Prefer Small Targets First**:
   Symbolic execution can suffer from state explosion if applied to an entire binary. Always direct `unflatten_control_flow` and `solve_branch_reachability` to specific functions (`start_address` or symbol name).
3. **Use Concrete Constraints**:
   When calling `solve_branch_reachability`, provide both `target_address` (desired branch) and `avoid_addresses` (error handlers, exit calls) to bound the Z3 solver path search.
4. **Interpret Evidence**:
   Every SYMB tool returns a structured canonical Evidence record containing `evidence_id`, `normalized_result`, `concrete_inputs`, and `solver_diagnostics`. Present the concrete input in both ASCII and Hex representations to the user.

## Common Workflows

### Workflow 1: Defeating OLLVM Control Flow Flattening
1. Identify the flattened function address (e.g. from disassembly or user prompt).
2. Call `symb:unflatten_control_flow(binary_path, function_address)`.
3. If the tool identifies a dispatcher switch, read the reconstructed CFG and present the cleaned pseudo-code without dispatcher blocks.

### Workflow 2: Automated Keygen & Branch Solver
1. Call `symb:solve_branch_reachability(binary_path, target_address, avoid_addresses, input_length)`.
2. Check `normalized_result.status === "SAT"`.
3. Extract `concrete_inputs` and present the satisfying string/bytes directly to the user.

### Workflow 3: Live Process Intervention
1. Identify the running process name or PID.
2. Call `symb:hot_patch_live_memory(pid, target_offset, patch_opcode, verify_original)`.
3. Confirm memory patch success and report state changes to the user.
