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
  ProtectionsScanInputSchema
} from "./contracts/schemas.js";
import { runUnflatten } from "./core/unflatten.js";
import { runBranchSolver } from "./core/solver.js";
import { runTaintAnalysis } from "./core/taint.js";
import { runHotPatch } from "./core/trampoline.js";
import { runDecompile } from "./core/decompile.js";
import { runDecompileProgram } from "./core/decompile_program.js";
import { runInspectLayout } from "./core/layout.js";
import { runCryptoScan } from "./core/crypto.js";
import { runProtectionsScan } from "./core/protections.js";

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
          name: "decompile_native_function",
          description:
            "Decompiles native machine code into clean C pseudocode in milliseconds (< 400ms). Disassembles basic blocks, extracts string references (.rdata/.rodata XREFs), resolves IAT/PLT symbols, and reconstructs branch conditions across Windows PE and Linux ELF.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to binary (PE/EXE, ELF, Mach-O)" },
              function_address: { type: "string", description: "Function hex address (e.g. '0x4015f6') or entry point" },
              max_instructions: { type: "number", default: 300, description: "Maximum instruction count to lift" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "decompile_entire_program",
          description:
            "Automated whole-binary decompiler. Scans entry point, export tables (EAT), and function prologues across the binary to generate a unified, compilable C source code file with forward declarations and cross-referenced calls.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to target binary" },
              max_functions: { type: "number", default: 10, description: "Maximum number of discovered functions to decompile" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "detect_binary_protections",
          description:
            "Scans binary for protectors/packers (UPX, Themida, VMProtect, Enigma), Anti-Debugging APIs (IsDebuggerPresent, NtQueryInformationProcess, etc.), Anti-VM artifacts, and ASM timing traps (RDTSC, PEB direct read) with an automated security risk score.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to target binary" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "inspect_binary_layout",
          description:
            "Scans binary headers (PE/ELF), mitigations (ASLR, DEP/NX, SafeSEH, CFG), imported/exported DLL functions, and measures Shannon entropy per section to detect packing and encrypted payloads.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to target binary" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "detect_crypto_primitives",
          description:
            "Scans binary bytes to detect cryptographic primitives, including AES S-Boxes, SHA-256 / MD5 constants, CRC32 tables, RC4 KSA loops, and ChaCha20 schedules for automated SMT inversion.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to target binary" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "unflatten_control_flow",
          description:
            "Symbolically unflatten OLLVM Control Flow Flattening (CFF). Eliminates dispatchers, resolves state variables, and reconstructs clean original CFG.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to target binary" },
              function_address: { type: "string", description: "Hex address (e.g. '0x401500') or symbol" },
              timeout_seconds: { type: "number", default: 60 }
            },
            required: ["binary_path", "function_address"]
          }
        },
        {
          name: "solve_branch_reachability",
          description:
            "Uses angr and Z3 SMT Solver to find the exact byte sequence that drives execution to a target address (bypass check/keygen/exploit path).",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to binary" },
              target_address: { type: "string", description: "Target reachability hex address" },
              avoid_addresses: {
                type: "array",
                items: { type: "string" },
                description: "Array of failure hex addresses to prune"
              },
              input_length: { type: "number", default: 32 }
            },
            required: ["binary_path", "target_address"]
          }
        },
        {
          name: "trace_symbolic_taint",
          description:
            "Traces memory and register data-flow dependencies from user input sources directly to critical execution sinks.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Path to binary" },
              source_symbol: { type: "string", description: "Input source symbol or entry point" },
              sink_symbol: { type: "string", description: "Vulnerable sink function" }
            },
            required: ["binary_path", "source_symbol", "sink_symbol"]
          }
        },
        {
          name: "hot_patch_live_memory",
          description:
            "Injects atomic hot-patch memory trampolines into running processes without touching disk binaries or triggering file-integrity checks.",
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
          const result = await runDecompileProgram(
            parsed.binary_path,
            parsed.max_functions
          );
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
