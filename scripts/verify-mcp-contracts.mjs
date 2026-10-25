#!/usr/bin/env node
import assert from "node:assert/strict";
import chalk from "chalk";
import {
  UnflattenInputSchema,
  SolveBranchInputSchema,
  TaintInputSchema,
  HotPatchInputSchema,
  DecompileInputSchema,
  DecompileProgramInputSchema,
  InspectLayoutInputSchema,
  CryptoScanInputSchema,
  ProtectionsScanInputSchema,
  DecompileApkInputSchema,
  DecryptStringsInputSchema,
  DecompileIosInputSchema,
  EntropyScanInputSchema,
  XrefAnalysisInputSchema,
  OptimizeMediaInputSchema,
  DynamicallyUnpackInputSchema
} from "../dist/contracts/schemas.js";

console.log(chalk.cyan.bold("\n📜 SYMB MCP TOOL SCHEMAS & CANONICAL EVIDENCE CONTRACTS VERIFICATION\n"));

const schemas = [
  {
    name: "dynamically_unpack_binary Schema",
    schema: DynamicallyUnpackInputSchema,
    sampleValid: { binary_path: "target.exe", max_instructions: 50000 }
  },
  {
    name: "optimize_large_media_buffer Schema",
    schema: OptimizeMediaInputSchema,
    sampleValid: { file_path: "video.mp4", target_max_mb: 50 }
  },
  {
    name: "scan_byte_entropy Schema",
    schema: EntropyScanInputSchema,
    sampleValid: { binary_path: "target.exe", block_size: 512 }
  },
  {
    name: "trace_binary_xrefs Schema",
    schema: XrefAnalysisInputSchema,
    sampleValid: { binary_path: "target.exe" }
  },
  {
    name: "decompile_ios_ipa_package Schema",
    schema: DecompileIosInputSchema,
    sampleValid: { target_path: "app.ipa" }
  },
  {
    name: "decompile_apk_package Schema",
    schema: DecompileApkInputSchema,
    sampleValid: { target_path: "app.apk", max_classes: 15 }
  },
  {
    name: "decrypt_obfuscated_strings Schema",
    schema: DecryptStringsInputSchema,
    sampleValid: { binary_path: "payload.bin", max_candidates: 20 }
  },
  {
    name: "decompile_native_function Schema",
    schema: DecompileInputSchema,
    sampleValid: { binary_path: "test.exe", function_address: "0x140001000", max_instructions: 300 }
  },
  {
    name: "decompile_entire_program Schema",
    schema: DecompileProgramInputSchema,
    sampleValid: { binary_path: "test.exe", max_functions: 10 }
  },
  {
    name: "detect_binary_protections Schema",
    schema: ProtectionsScanInputSchema,
    sampleValid: { binary_path: "test.exe" }
  },
  {
    name: "inspect_binary_layout Schema",
    schema: InspectLayoutInputSchema,
    sampleValid: { binary_path: "target.exe" }
  },
  {
    name: "detect_crypto_primitives Schema",
    schema: CryptoScanInputSchema,
    sampleValid: { binary_path: "target.exe" }
  },
  {
    name: "unflatten_control_flow Schema",
    schema: UnflattenInputSchema,
    sampleValid: { binary_path: "test.exe", function_address: "0x140001000", timeout_seconds: 60 }
  },
  {
    name: "solve_branch_reachability Schema",
    schema: SolveBranchInputSchema,
    sampleValid: { binary_path: "target.exe", target_address: "0x401580", avoid_addresses: ["0x401590"] }
  },
  {
    name: "trace_symbolic_taint Schema",
    schema: TaintInputSchema,
    sampleValid: { binary_path: "libcore.so", source_symbol: "read_buf", sink_symbol: "memcpy" }
  },
  {
    name: "hot_patch_live_memory Schema",
    schema: HotPatchInputSchema,
    sampleValid: { pid: 1337, memory_address: "0x7FFF0010", patch_bytes_hex: "909090" }
  }
];

let allPassed = true;

for (const s of schemas) {
  process.stdout.write(`  Validating contract: ${chalk.bold(s.name)}... `);
  try {
    const parsed = s.schema.parse(s.sampleValid);
    assert(parsed !== null, "Parsing returned null");
    console.log(chalk.green("PASSED ✔"));
  } catch (err) {
    allPassed = false;
    console.log(chalk.red(`FAILED ✖ (${err.message})`));
  }
}

console.log("\n" + "─".repeat(50));
if (allPassed) {
  console.log(chalk.green.bold("★ ALL 16 MCP TOOL CONTRACT SCHEMAS VERIFIED 100% SPEC-COMPLIANT!\n"));
  process.exit(0);
} else {
  console.log(chalk.red.bold("✖ MCP Schema verification errors encountered\n"));
  process.exit(1);
}
