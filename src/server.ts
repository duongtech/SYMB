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
  DynamicallyUnpackInputSchema,
  AntiDebugInputSchema,
  LicenseBypassInputSchema,
  FridaHookInputSchema,
  BinaryPatchInputSchema
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
import { runAntiDebugAnnihilator } from "./core/anti_debug.js";
import { runLicenseBypass } from "./core/license_bypass.js";
import { runFridaGenerator } from "./core/frida_generator.js";
import { runBinaryPatcher } from "./core/patcher.js";

export function createSymbServer(): Server {
  const server = new Server(
    {
      name: "symb",
      version: "2.0.0"
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
        },
        {
          name: "neutralize_anti_debugging",
          description:
            "Active reverse engineering intervention. Scans and neutralizes anti-debugging traps, PEB BeingDebugged checks, INT 2D/3 traps, and RDTSC timing checks. Automatically NOPs out traps on disk binary with PE checksum recalculation.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to binary (PE, ELF)" },
              auto_patch: { type: "boolean", description: "Automatically NOP out traps and write patched binary" },
              output_path: { type: "string", description: "Optional output destination path" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "bypass_license_authorization",
          description:
            "Active reverse engineering intervention. Detects authorization/license validation branches, computes conditional jump inversions, and applies permanent binary bypass patches on disk.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to target binary" },
              function_address: { type: "string", description: "Target validation function address or symbol" },
              force_success: { type: "boolean", description: "Invert conditionals to force valid license" },
              apply_to_file: { type: "boolean", description: "Write patched binary to disk" },
              output_path: { type: "string", description: "Optional output path" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "generate_frida_instrumentation",
          description:
            "Active reverse engineering intervention. Generates production-grade Frida dynamic instrumentation scripts for SSL unpinning, root/jailbreak cloaking, anti-debug runtime hooks, and dynamic crypto sniffing.",
          inputSchema: {
            type: "object",
            properties: {
              target: { type: "string", description: "Target process name or package ID" },
              platform: { type: "string", enum: ["android", "ios", "windows", "linux"], description: "Target platform" },
              script_type: {
                type: "string",
                enum: ["ssl_unpinning", "root_jailbreak_bypass", "anti_debug_runtime_cloak", "crypto_tracer", "api_logger", "custom_interceptor"],
                description: "Type of dynamic instrumentation"
              },
              custom_filter: { type: "string", description: "Optional function or class name filter" }
            },
            required: ["target"]
          }
        },
        {
          name: "patch_binary_executable",
          description:
            "Active reverse engineering intervention. Surgical disk binary patcher with RVA-to-Raw conversion, PE/ELF section mapping, arbitrary hex byte modification, automatic backup creation, and PE checksum recalculation.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to target binary (PE, ELF, RAW)" },
              patches: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    address: { description: "Virtual address, RVA, or physical offset" },
                    offset: { description: "Physical file offset" },
                    bytes_hex: { type: "string", description: "Hex bytes to write (e.g. '90 90' or 'EB 15')" },
                    description: { type: "string", description: "Description of patch" },
                    is_rva: { type: "boolean", description: "Whether address is an RVA" },
                    is_va: { type: "boolean", description: "Whether address is a full Virtual Address" }
                  },
                  required: ["bytes_hex"]
                },
                description: "List of byte patches"
              },
              output_path: { type: "string", description: "Optional destination output path" },
              create_backup: { type: "boolean", description: "Create .bak backup when modifying in-place" },
              recalculate_pe_checksum: { type: "boolean", description: "Recalculate PE optional header checksum" }
            },
            required: ["binary_path", "patches"]
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

        case "neutralize_anti_debugging": {
          const parsed = AntiDebugInputSchema.parse(args);
          const result = await runAntiDebugAnnihilator(
            parsed.binary_path,
            parsed.auto_patch,
            parsed.output_path
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "bypass_license_authorization": {
          const parsed = LicenseBypassInputSchema.parse(args);
          const result = await runLicenseBypass(
            parsed.binary_path,
            parsed.function_address,
            parsed.force_success,
            parsed.apply_to_file,
            parsed.output_path
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "generate_frida_instrumentation": {
          const parsed = FridaHookInputSchema.parse(args);
          const result = await runFridaGenerator(
            parsed.target,
            parsed.platform,
            parsed.script_type,
            parsed.custom_filter
          );
          return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
          };
        }

        case "patch_binary_executable": {
          const parsed = BinaryPatchInputSchema.parse(args);
          const result = await runBinaryPatcher(
            parsed.binary_path,
            parsed.patches as any,
            parsed.output_path,
            parsed.create_backup,
            parsed.recalculate_pe_checksum
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
  console.error("SYMB (Symbolic Reversing & Dynamic Binary Intervention) MCP Server running on stdio");
}

export const runStdioServer = runServer;
