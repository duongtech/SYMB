import { z } from "zod";

export const UnflattenInputSchema = z.object({
  binary_path: z.string().describe("Absolute path to the target binary (PE, ELF, Mach-O)"),
  function_address: z.string().describe("Hex address (e.g. '0x401500') or function symbol"),
  timeout_seconds: z.number().default(60).describe("Maximum solver search budget")
});

export const SolveBranchInputSchema = z.object({
  binary_path: z.string().describe("Absolute path to target binary"),
  target_address: z.string().describe("Hex address of the desired branch (e.g. '0x401820')"),
  avoid_addresses: z.array(z.string()).default([]).describe("Hex addresses of failure paths to prune"),
  input_length: z.number().default(32).describe("Expected symbolic input byte length")
});

export const TaintInputSchema = z.object({
  binary_path: z.string().describe("Absolute path to binary"),
  source_symbol: z.string().describe("Entry point or input buffer symbol (e.g. 'argv[1]', 'read')"),
  sink_symbol: z.string().describe("Target sink function (e.g. 'strcpy', 'system', 'memcpy')")
});

export const HotPatchInputSchema = z.object({
  pid: z.number().describe("Target Process ID"),
  memory_address: z.string().describe("Target virtual address or relative module offset"),
  patch_bytes_hex: z.string().describe("Hex bytes to write (e.g. '90 90' or 'B8 01 00 00 00 C3')"),
  expected_original_bytes: z.string().optional().describe("Verification check to prevent accidental corruption")
});
