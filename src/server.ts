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
  InspectLayoutInputSchema,
  CryptoScanInputSchema
} from "./contracts/schemas.js";
import { runUnflatten } from "./core/unflatten.js";
import { runBranchSolver } from "./core/solver.js";
import { runTaintAnalysis } from "./core/taint.js";
import { runHotPatch } from "./core/trampoline.js";
import { runDecompile } from "./core/decompile.js";
import { runInspectLayout } from "./core/layout.js";
import { runCryptoScan } from "./core/crypto.js";

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
            "Decompiles native machine code into clean C pseudocode in milliseconds. Disassembles basic blocks, extracts string references (.rdata XREFs), and reconstructs branch conditions across Windows PE and Linux ELF.",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string", description: "Absolute path to binary (PE/EXE, ELF, Mach-O)" },
              function_address: { type: "string", description: "Function hex address (e.g. '0x1400014e0') or entry point" },
              max_instructions: { type: "number", default: 250, description: "Maximum instruction count to lift" }
            },
            required: ["binary_path"]
          }
        },
        {
          name: "inspect_binary_layout",
          description:
            "Scans binary headers (PE/ELF), mitigations (ASLR, DEP/NX, SafeSEH, CFG), imported/exported DLL functions, and measures Shannon entropy per section to detect UPX, Themida, and VMProtect packing.",
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
              target_address: { type: "string", description: "Target hex address (e.g. '0x401820')" },
              avoid_addresses: { type: "array", items: { type: "string" }, description: "Error paths to avoid" },
              input_length: { type: "number", default: 32 }
            },
            required: ["binary_path", "target_address"]
          }
        },
        {
          name: "trace_symbolic_taint",
          description:
            "Performs dynamic taint analysis to verify if user-controlled input propagates into memory sinks (memcpy, strcpy, system).",
          inputSchema: {
            type: "object",
            properties: {
              binary_path: { type: "string" },
              source_symbol: { type: "string", description: "Input source symbol" },
              sink_symbol: { type: "string", description: "Target sink function" }
            },
            required: ["binary_path", "source_symbol", "sink_symbol"]
          }
        },
        {
          name: "hot_patch_live_memory",
          description:
            "Performs zero-disk in-memory trampoline injection and function hooking on a running process.",
          inputSchema: {
            type: "object",
            properties: {
              pid: { type: "number", description: "Target Process ID" },
              memory_address: { type: "string", description: "Virtual address or relative offset" },
              patch_bytes_hex: { type: "string", description: "Hex bytes to write" },
              expected_original_bytes: { type: "string", description: "Verification bytes" }
            },
            required: ["pid", "memory_address", "patch_bytes_hex"]
          }
        }
      ]
    };
  });

  // Handle Tool Executions
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      if (name === "decompile_native_function") {
        const parsed = DecompileInputSchema.parse(args);
        const evidence = await runDecompile(parsed.binary_path, parsed.function_address, parsed.max_instructions);
        return {
          content: [{ type: "text", text: JSON.stringify(evidence, null, 2) }]
        };
      }

      if (name === "inspect_binary_layout") {
        const parsed = InspectLayoutInputSchema.parse(args);
        const evidence = await runInspectLayout(parsed.binary_path);
        return {
          content: [{ type: "text", text: JSON.stringify(evidence, null, 2) }]
        };
      }

      if (name === "detect_crypto_primitives") {
        const parsed = CryptoScanInputSchema.parse(args);
        const evidence = await runCryptoScan(parsed.binary_path);
        return {
          content: [{ type: "text", text: JSON.stringify(evidence, null, 2) }]
        };
      }

      if (name === "unflatten_control_flow") {
        const parsed = UnflattenInputSchema.parse(args);
        const evidence = await runUnflatten(parsed.binary_path, parsed.function_address, parsed.timeout_seconds);
        return {
          content: [{ type: "text", text: JSON.stringify(evidence, null, 2) }]
        };
      }

      if (name === "solve_branch_reachability") {
        const parsed = SolveBranchInputSchema.parse(args);
        const evidence = await runBranchSolver(
          parsed.binary_path,
          parsed.target_address,
          parsed.avoid_addresses,
          parsed.input_length
        );
        return {
          content: [{ type: "text", text: JSON.stringify(evidence, null, 2) }]
        };
      }

      if (name === "trace_symbolic_taint") {
        const parsed = TaintInputSchema.parse(args);
        const evidence = await runTaintAnalysis(parsed.binary_path, parsed.source_symbol, parsed.sink_symbol);
        return {
          content: [{ type: "text", text: JSON.stringify(evidence, null, 2) }]
        };
      }

      if (name === "hot_patch_live_memory") {
        const parsed = HotPatchInputSchema.parse(args);
        const evidence = await runHotPatch(
          parsed.pid,
          parsed.memory_address,
          parsed.patch_bytes_hex,
          parsed.expected_original_bytes
        );
        return {
          content: [{ type: "text", text: JSON.stringify(evidence, null, 2) }]
        };
      }

      throw new Error(`Unknown tool: ${name}`);
    } catch (err: any) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error executing ${name}: ${err.message}`
          }
        ]
      };
    }
  });

  return server;
}

export async function runStdioServer() {
  const server = createSymbServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("⚡ SYMB MCP Server running on stdio");
}
