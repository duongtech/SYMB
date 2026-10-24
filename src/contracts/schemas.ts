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

export const DecompileInputSchema = z.object({
  binary_path: z.string().describe("Absolute path to target binary (PE/EXE, ELF, Mach-O)"),
  function_address: z.string().optional().describe("Function hex address or symbol name. If omitted, decompiles entry point"),
  max_instructions: z.number().default(300).describe("Maximum instruction window to disassemble")
});

export const DecompileProgramInputSchema = z.object({
  binary_path: z.string().describe("Absolute path to target binary (PE/EXE, ELF, Mach-O)"),
  max_functions: z.number().default(10).describe("Maximum number of discovered functions to decompile")
});

export const InspectLayoutInputSchema = z.object({
  binary_path: z.string().describe("Absolute path to target binary")
});

export const CryptoScanInputSchema = z.object({
  binary_path: z.string().describe("Absolute path to target binary")
});

export const ProtectionsScanInputSchema = z.object({
  binary_path: z.string().describe("Absolute path to target binary")
});

export const DecompileApkInputSchema = z.object({
  target_path: z.string().describe("Absolute path to APK package (.apk) or Dalvik executable (.dex)"),
  max_classes: z.number().default(15).describe("Maximum number of classes to lift into Java pseudocode")
});

export const DecryptStringsInputSchema = z.object({
  binary_path: z.string().describe("Absolute path to target binary (PE, ELF, APK, .so)"),
  max_candidates: z.number().default(20).describe("Maximum number of decrypted candidate strings to return")
});
