import { Command } from "commander";
import chalk from "chalk";
import fs from "fs";
import path from "path";
import os from "os";
import { runDecompile } from "./core/decompile.js";
import { runDecompileProgram } from "./core/decompile_program.js";
import { runInspectLayout } from "./core/layout.js";
import { runCryptoScan } from "./core/crypto.js";
import { runProtectionsScan } from "./core/protections.js";
import { runUnflatten } from "./core/unflatten.js";
import { runApkDecompile } from "./core/apk.js";
import { runStringDecrypt } from "./core/strings_decrypt.js";
import { runIosDecompile } from "./core/ios.js";

const program = new Command();

program
  .name("symb")
  .description("SYMB: Symbolic Reverse Engineering & Deobfuscation for AI Agents")
  .version("1.0.0");

program
  .command("setup")
  .description("Register SYMB MCP server with your AI coding agents (Claude, Cursor, Antigravity)")
  .action(async () => {
    console.log(chalk.bold.cyan("\n⚡ SYMB AGENT REGISTRATION WIZARD\n"));

    const claudeConfigPath = path.join(
      os.homedir(),
      "AppData",
      "Roaming",
      "Claude",
      "claude_desktop_config.json"
    );

    let registeredCount = 0;

    try {
      if (fs.existsSync(claudeConfigPath)) {
        const raw = fs.readFileSync(claudeConfigPath, "utf-8");
        const cfg = JSON.parse(raw);
        cfg.mcpServers = cfg.mcpServers || {};
        cfg.mcpServers.symb = {
          command: "npx",
          args: ["-y", "symb-agents"]
        };
        fs.writeFileSync(claudeConfigPath, JSON.stringify(cfg, null, 2), "utf-8");
        console.log(chalk.green("✔ Registered SYMB with Claude Desktop"));
        registeredCount++;
      }
    } catch {}

    const cursorConfigPath = path.join(
      os.homedir(),
      ".cursor",
      "mcp.json"
    );

    try {
      if (!fs.existsSync(path.dirname(cursorConfigPath))) {
        fs.mkdirSync(path.dirname(cursorConfigPath), { recursive: true });
      }
      let cfg: any = { mcpServers: {} };
      if (fs.existsSync(cursorConfigPath)) {
        cfg = JSON.parse(fs.readFileSync(cursorConfigPath, "utf-8"));
      }
      cfg.mcpServers = cfg.mcpServers || {};
      cfg.mcpServers.symb = {
        command: "npx",
        args: ["-y", "symb-agents"]
      };
      fs.writeFileSync(cursorConfigPath, JSON.stringify(cfg, null, 2), "utf-8");
      console.log(chalk.green("✔ Registered SYMB with Cursor IDE"));
      registeredCount++;
    } catch {}

    console.log(chalk.bold.green(`\n🎉 SYMB successfully registered with ${registeredCount} agent environment(s)!`));
    console.log(chalk.dim("Restart your AI agent or reload window to start using SYMB tools.\n"));
  });

program
  .command("decompile <binary> [address]")
  .description("Decompile a native function into clean C pseudocode in < 400ms")
  .option("-m, --max-instructions <num>", "Instruction limit", "300")
  .action(async (binary, address, options) => {
    const t0 = Date.now();
    console.log(chalk.cyan(`\n⚡ Decompiling ${binary} at ${address || "entry_point"}...`));
    try {
      const res = await runDecompile(binary, address, parseInt(options.maxInstructions, 10));
      const elapsed = Date.now() - t0;
      const data = res.normalized_result;
      console.log(chalk.green(`✔ Decompiled ${data.instruction_count} instructions across ${data.basic_blocks_count} blocks in ${elapsed}ms\n`));
      console.log(chalk.bold.white(data.decompiled_pseudocode));
      if (data.string_references?.length) {
        console.log(chalk.yellow(`\nString References:`), data.string_references);
      }
      if (data.iat_imports_used?.length) {
        console.log(chalk.cyan(`Import References:`), data.iat_imports_used);
      }
    } catch (e: any) {
      console.error(chalk.red(`Error: ${e.message}`));
    }
  });

program
  .command("decompile-all <binary>")
  .description("Decompile entire binary into unified C translation source file")
  .option("-l, --limit <num>", "Maximum functions to decompile", "10")
  .action(async (binary, options) => {
    const t0 = Date.now();
    console.log(chalk.cyan(`\n⚡ Translating entire binary ${binary} to C...`));
    try {
      const res = await runDecompileProgram(binary, parseInt(options.limit, 10));
      const elapsed = Date.now() - t0;
      console.log(chalk.green(`✔ Discovered ${res.total_functions_discovered} functions, decompiled ${res.total_functions_decompiled} in ${elapsed}ms\n`));
      console.log(chalk.bold.white(res.reconstructed_c_translation));
    } catch (e: any) {
      console.error(chalk.red(`Error: ${e.message}`));
    }
  });

program
  .command("inspect <binary>")
  .description("Inspect PE/ELF headers, security mitigations, and section entropy")
  .action(async (binary) => {
    console.log(chalk.cyan(`\n🔍 Inspecting binary layout: ${binary}...`));
    try {
      const res = await runInspectLayout(binary);
      console.log(JSON.stringify(res, null, 2));
    } catch (e: any) {
      console.error(chalk.red(`Error: ${e.message}`));
    }
  });

program
  .command("protections <binary>")
  .description("Detect packers (UPX, VMProtect, Themida), Anti-Debug APIs, and Anti-VM heuristics")
  .action(async (binary) => {
    console.log(chalk.cyan(`\n🛡️ Scanning binary protections: ${binary}...`));
    try {
      const res = await runProtectionsScan(binary);
      console.log(JSON.stringify(res, null, 2));
    } catch (e: any) {
      console.error(chalk.red(`Error: ${e.message}`));
    }
  });

program
  .command("crypto <binary>")
  .description("Scan binary for AES S-Boxes, SHA-256, MD5, CRC32, and RC4 constants")
  .action(async (binary) => {
    console.log(chalk.cyan(`\n🔑 Scanning crypto constants: ${binary}...`));
    try {
      const res = await runCryptoScan(binary);
      console.log(JSON.stringify(res, null, 2));
    } catch (e: any) {
      console.error(chalk.red(`Error: ${e.message}`));
    }
  });

program
  .command("unflatten <binary> <address>")
  .description("Symbolically deobfuscate OLLVM Control-Flow Flattening (CFF)")
  .option("-t, --timeout <seconds>", "Solver timeout", "60")
  .action(async (binary, address, options) => {
    console.log(chalk.cyan(`\n🔄 Unflattening OLLVM state dispatcher at ${address} in ${binary}...`));
    try {
      const res = await runUnflatten(binary, address, parseInt(options.timeout, 10));
      console.log(JSON.stringify(res, null, 2));
    } catch (e: any) {
      console.error(chalk.red(`Error: ${e.message}`));
    }
  });

program
  .command("apk <target>")
  .description("Decompile Android APK / DEX packages, audit permissions, and reconstruct Java")
  .option("-c, --max-classes <num>", "Maximum classes to decompile", "15")
  .action(async (target, options) => {
    console.log(chalk.cyan(`\n📱 Decompiling APK / DEX: ${target}...`));
    try {
      const res = await runApkDecompile(target, parseInt(options.maxClasses, 10));
      console.log(chalk.green(`✔ Package: ${res.package_name}`));
      console.log(chalk.green(`✔ Permissions (${res.permissions_count}):`), res.permissions);
      if (res.security_audit_alerts?.length) {
        console.log(chalk.red.bold(`⚠ Security Alerts:`), res.security_audit_alerts);
      }
      if (res.native_libraries?.length) {
        console.log(chalk.yellow(`Native Shared Libraries:`), res.native_libraries);
      }
      console.log(chalk.bold.white("\nReconstructed Java Classes:\n" + res.reconstructed_java));
    } catch (e: any) {
      console.error(chalk.red(`Error: ${e.message}`));
    }
  });

program
  .command("decrypt-strings <binary>")
  .description("Automated recovery of XOR, Rolling-Key, and Base64 encrypted strings")
  .option("-m, --max-candidates <num>", "Max candidates", "20")
  .action(async (binary, options) => {
    console.log(chalk.cyan(`\n🔓 Decrypting obfuscated strings in ${binary}...`));
    try {
      const res = await runStringDecrypt(binary, parseInt(options.maxCandidates, 10));
      console.log(chalk.green(`✔ Recovered ${res.total_encrypted_strings_recovered} encrypted strings, ${res.total_base64_strings_decoded} Base64 strings\n`));
      console.log(JSON.stringify(res, null, 2));
    } catch (e: any) {
      console.error(chalk.red(`Error: ${e.message}`));
    }
  });

program
  .command("ipa <target>")
  .description("Decompile Apple iOS IPA packages / ARM64 Mach-O, check FairPlay DRM and Anti-Jailbreak")
  .action(async (target) => {
    console.log(chalk.cyan(`\n🍏 Decompiling Apple iOS IPA / Mach-O: ${target}...`));
    try {
      const res = await runIosDecompile(target);
      console.log(chalk.green(`✔ Bundle ID: ${res.bundle_id}`));
      console.log(chalk.green(`✔ Permissions (${res.permissions_count}):`), res.permissions);
      console.log(chalk.green(`✔ Architecture: ${res.macho_analysis?.architecture}`));
      console.log(chalk.yellow(`DRM Encrypted (cryptid): ${res.macho_analysis?.crypt_id} (${res.macho_analysis?.fairplay_drm_encrypted ? "FairPlay Active" : "Decrypted/Cracked"})`));
      if (res.macho_analysis?.jailbreak_detection_alerts?.length) {
        console.log(chalk.red.bold(`⚠ Jailbreak Detection Alerts:`), res.macho_analysis.jailbreak_detection_alerts);
      }
      if (res.macho_analysis?.imported_frameworks?.length) {
        console.log(chalk.cyan(`Imported Frameworks:`), res.macho_analysis.imported_frameworks);
      }
      console.log(chalk.bold.white("\nReconstructed Objective-C / Swift Interface:\n" + res.reconstructed_objc_header));
    } catch (e: any) {
      console.error(chalk.red(`Error: ${e.message}`));
    }
  });

program.parse(process.argv);
