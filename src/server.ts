import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from "@modelcontextprotocol/sdk/types.js";
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
} from "./contracts/schemas.js";
import { runDynamicUnpacker } from "./core/unpacker.js";
import { runUnflatten } from "./core/unflatten.js";
import { runBranchSolver } from "./core/solver.js";
import { runTaintAnalysis } from "./core/taint.js";
import { runHotPatch } from "./core/trampoline.js";
import { runDecompile } from "./core/decompile.js";
import { runDecompileProgram } from "./core/decompile_program.js";
import { runInspectLayout } from "./core/layout.js";
import { runCryptoScan } from "./core/crypto.js";
import { runProtectionsScan } from "./core/protections.js";
import { runApkDecompile } from "./core/apk.js";
import { runStringDecrypt } from "./core/strings_decrypt.js";
import { runIosDecompile } from "./core/ios.js";
import { runEntropyScan } from "./core/entropy.js";
import { runXrefAnalysis } from "./core/xref.js";
import { runMediaOptimizer } from "./core/media_optimizer.js";

export function createSymbServer(): Server {
  const server = new Server(
    {
      name: "symb",
      version: "1.0.0"
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // List all available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "dynamically_unpack_binary",
          description:
            "Unicorn CPU emulation unpacker. Executes binary past packer stubs (UPX, Themida, crypters), detects OEP tail jumps, and dumps unpacked memory images.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to packed binary (PE, ELF)" },
              max_instructions: { type: "number", description: "Maximum CPU emulation steps (default: 50000)" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "optimize_large_media_buffer",
          description:
            "Solves agent memory/context exhaustion for oversized media (video/audio) and large binary dumps (> 50MB). Auto-downsamples videos to agent budget, isolates audio tracks for transcription, extracts keyframes, and provides mmap streaming.",
          inputSchema: {
            type: "object",
            properties: {
              file_path: { type: "string", description: "Absolute path to media or binary file" },
              target_max_mb: { type: "number", description: "Target max MB memory budget (default 50)" }
            },
            required: ["file_path"]
          }
        },
        {
          name: "scan_byte_entropy",
          description:
            "Calculates rolling Shannon entropy heatmap across any binary (PE, ELF, APK, Mach-O). Detects packed/encrypted payloads and outputs visual distribution histograms.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to target binary" },
              block_size: { type: "number", description: "Block size in bytes (default 512)" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "trace_binary_xrefs",
          description:
            "Traces whole-program call graph edges, indirect calls, resolved IAT/PLT stubs, and literal string cross-references (XREFs).",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to target binary (PE, ELF)" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "decompile_ios_ipa_package",
          description:
            "Decompiles Apple iOS IPA packages (.ipa) and ARM64 Mach-O executables. Audits FairPlay DRM (cryptid), Anti-Jailbreak heuristics, and reconstructs Objective-C / Swift interfaces.",
          inputSchema: {
            type: "object",
            properties: {
              target_path: { type: "string", description: "Absolute path to IPA or Mach-O" }
            },
            required: ["target_path"]
          }
        },
        {
          name: "decompile_apk_package",
          description:
            "5-Pass native Dalvik DEX decompiler. Audits permissions, keystore signature schemes (v1/v2/v3), CWE vulnerabilities, hardcoded secrets, and lifts Dalvik bytecode to Java classes.",
          inputSchema: {
            type: "object",
            properties: {
              target_path: { type: "string", description: "Absolute path to APK or DEX" },
              max_classes: { type: "number", description: "Max classes to decompile" }
            },
            required: ["target_path"]
          }
        },
        {
          name: "decrypt_obfuscated_strings",
          description:
            "Automated string decryptor across raw binary sections. Recovers Single-byte XOR, Multi-byte cycling XOR, and Additive Rolling-Key XOR encrypted strings.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to target binary" },
              max_candidates: { type: "number", description: "Max candidate decrypted strings" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "decompile_native_function",
          description:
            "High-speed machine code decompiler (< 400ms). Lifts x86/x64/ARM assembly into clean C pseudocode with branch conditions, string references, and IAT/PLT stub resolution.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to binary" },
              function_address: { type: "string", description: "Hex address or function symbol" },
              max_instructions: { type: "number", description: "Instruction window limit" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "decompile_entire_program",
          description:
            "Whole-program C decompiler. Discovers function entry points and generates unified, compilable C source files with forward declarations.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to binary" },
              max_functions: { type: "number", description: "Max functions to decompile" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "detect_binary_protections",
          description:
            "Detects commercial packers (UPX, Themida, VMProtect, Enigma), Anti-Debugging APIs, Anti-VM heuristics, and RDTSC timing traps.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to binary" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "inspect_binary_layout",
          description:
            "Scans PE/ELF headers, ASLR/DEP/SafeSEH mitigations, IAT/EAT exports, and measures Shannon entropy per section.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to binary" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "detect_crypto_primitives",
          description:
            "Scans for AES S-Boxes, SHA/MD5 constants, CRC32 tables, RC4 loops, and ChaCha schedules for SMT inversion.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to binary" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "unflatten_control_flow",
          description:
            "Symbolically deobfuscates OLLVM Control-Flow Flattening (CFF) state dispatchers and reconstructs clean linear basic blocks.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Path to binary" },
              function_address: { type: "string", description: "Hex address of flattened function" },
              timeout_seconds: { type: "number", description: "Solver timeout" }
            },
            required: ["binary_path", "function_address"]
          }
        },
        {
          name: "solve_branch_reachability",
          description:
            "Uses Z3 SMT Theorem Prover and angr to solve for exact concrete inputs reaching target branches while pruning failure paths.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Path to binary" },
              target_address: { type: "string", description: "Hex address of target block" },
              avoid_addresses: { type: "array", items: { type: "string" }, description: "Pruned addresses" },
              input_length: { type: "number", description: "Symbolic input length" }
            },
            required: ["binary_path", "target_address"]
          }
        },
        {
          name: "trace_symbolic_taint",
          description:
            "Symbolic dataflow taint analysis proving whether attacker-controlled inputs propagate to dangerous memory sinks.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Path to binary" },
              source_symbol: { type: "string", description: "Input source symbol" },
              sink_symbol: { type: "string", description: "Vulnerable sink function" }
            },
            required: ["binary_path", "source_symbol", "sink_symbol"]
          }
        },
        {
          name: "hot_patch_live_memory",
          description:
            "Injects atomic hot-patch memory trampolines into running processes without touching disk binaries.",
          inputSchema: {
            type: "object",
            properties: {
              pid: { type: "number", description: "Process ID" },
              memory_address: { type: "string", description: "Hex address to hook" },
              patch_bytes_hex: { type: "string", description: "Hex bytes payload" },
              expected_original_bytes: { type: "string", description: "Optional safety check bytes" }
            },
            required: ["pid", "memory_address", "patch_bytes_hex"]
          }
        }
      ]
    };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        case "dynamically_unpack_binary": {
          const parsed = DynamicallyUnpackInputSchema.parse(args);
          const result = await runDynamicUnpacker(parsed.binary_path, undefined, parsed.max_instructions);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "optimize_large_media_buffer": {
          const parsed = OptimizeMediaInputSchema.parse(args);
          const result = await runMediaOptimizer(parsed.file_path, parsed.target_max_mb);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "scan_byte_entropy": {
          const parsed = EntropyScanInputSchema.parse(args);
          const result = await runEntropyScan(parsed.binary_path, parsed.block_size);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "trace_binary_xrefs": {
          const parsed = XrefAnalysisInputSchema.parse(args);
          const result = await runXrefAnalysis(parsed.binary_path);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "decompile_ios_ipa_package": {
          const parsed = DecompileIosInputSchema.parse(args);
          const result = await runIosDecompile(parsed.target_path);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "decompile_apk_package": {
          const parsed = DecompileApkInputSchema.parse(args);
          const result = await runApkDecompile(parsed.target_path, parsed.max_classes);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "decrypt_obfuscated_strings": {
          const parsed = DecryptStringsInputSchema.parse(args);
          const result = await runStringDecrypt(parsed.binary_path, parsed.max_candidates);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "decompile_native_function": {
          const parsed = DecompileInputSchema.parse(args);
          const result = await runDecompile(
            parsed.binary_path,
            parsed.function_address,
            parsed.max_instructions
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "decompile_entire_program": {
          const parsed = DecompileProgramInputSchema.parse(args);
          const result = await runDecompileProgram(parsed.binary_path, parsed.max_functions);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "detect_binary_protections": {
          const parsed = ProtectionsScanInputSchema.parse(args);
          const result = await runProtectionsScan(parsed.binary_path);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "inspect_binary_layout": {
          const parsed = InspectLayoutInputSchema.parse(args);
          const result = await runInspectLayout(parsed.binary_path);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "detect_crypto_primitives": {
          const parsed = CryptoScanInputSchema.parse(args);
          const result = await runCryptoScan(parsed.binary_path);
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "unflatten_control_flow": {
          const parsed = UnflattenInputSchema.parse(args);
          const result = await runUnflatten(
            parsed.binary_path,
            parsed.function_address,
            parsed.timeout_seconds
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "solve_branch_reachability": {
          const parsed = SolveBranchInputSchema.parse(args);
          const result = await runBranchSolver(
            parsed.binary_path,
            parsed.target_address,
            parsed.avoid_addresses,
            parsed.input_length
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "trace_symbolic_taint": {
          const parsed = TaintInputSchema.parse(args);
          const result = await runTaintAnalysis(
            parsed.binary_path,
            parsed.source_symbol,
            parsed.sink_symbol
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "hot_patch_live_memory": {
          const parsed = HotPatchInputSchema.parse(args);
          const result = await runHotPatch(
            parsed.pid,
            parsed.memory_address,
            parsed.patch_bytes_hex,
            parsed.expected_original_bytes
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        default:
          throw new Error(`Unknown SYMB tool: ${name}`);
      }
    } catch (error: any) {
      return {
        isError: true,
        content: [{ type: "text", text: `Tool Error: ${error.message}` }]
      };
    }
  });

  return server;
}

export async function runServer(): Promise<void> {
  const server = createSymbServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("SYMB (Symbolic Reversing & Decompiler) MCP Server running on stdio");
}

export const runStdioServer = runServer;
