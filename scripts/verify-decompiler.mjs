#!/usr/bin/env node
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import chalk from "chalk";
import { runDecompile } from "../dist/core/decompile.js";
import { runDecompileProgram } from "../dist/core/decompile_program.js";
import { runInspectLayout } from "../dist/core/layout.js";
import { runCryptoScan } from "../dist/core/crypto.js";
import { runProtectionsScan } from "../dist/core/protections.js";
import { runApkDecompile } from "../dist/core/apk.js";
import { runStringDecrypt } from "../dist/core/strings_decrypt.js";
import { runIosDecompile } from "../dist/core/ios.js";

console.log(chalk.cyan.bold("\n⚡ SYMB HIGH-SPEED NATIVE DECOMPILER & EXECUTABLE ENGINE VERIFICATION\n"));

const targetPE = resolve("examples/01_ollvm_cff/CFF_win64.exe");
const targetELF = resolve("examples/02_smt_crackme/ais3_crackme");
const targetAPK = resolve("examples/04_apk_sample/sample_protected.apk");
const targetIPA = resolve("examples/05_ios_sample/sample_protected.ipa");

if (!existsSync(targetPE) || !existsSync(targetELF) || !existsSync(targetAPK) || !existsSync(targetIPA)) {
  console.log(chalk.red("Test target binaries not found"));
  process.exit(1);
}

let allPassed = true;

// 1. Binary Layout & Section Entropy
process.stdout.write(`  [1/8] Inspecting PE Layout & Section Entropy... `);
try {
  const layoutRes = await runInspectLayout(targetPE);
  const layout = layoutRes.normalized_result;
  if (layout.sections_count && layout.sections_count > 0 && layout.architecture) {
    console.log(chalk.green(`PASSED ✔ (${layout.format}, ${layout.architecture}, ${layout.sections_count} sections, Max Entropy: ${layout.max_entropy})`));
  } else {
    console.log(chalk.red("FAILED ✖"));
    allPassed = false;
  }
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

// 2. High-speed Capstone Disassembly & Pseudocode Lifting (with Strings & IAT/PLT)
process.stdout.write(`  [2/8] Decompiling Native Function to C Pseudocode... `);
try {
  const decRes = await runDecompile(targetELF, "0x4005f6");
  const dec = decRes.normalized_result;
  if (dec.instruction_count > 0 && dec.decompiled_pseudocode.includes("puts")) {
    console.log(chalk.green(`PASSED ✔ (${dec.instruction_count} instructions lifted in ${decRes.execution_time_ms}ms, PLT stubs resolved)`));
  } else {
    console.log(chalk.red("FAILED ✖ (No instructions or PLT stubs resolved)"));
    allPassed = false;
  }
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

// 3. Whole Program C Translation
process.stdout.write(`  [3/8] Reconstructing Whole-Program C Source Project... `);
try {
  const progRes = await runDecompileProgram(targetELF, 5);
  if (progRes.total_functions_decompiled >= 3 && progRes.reconstructed_c_translation.includes("FORWARD DECLARATIONS")) {
    console.log(chalk.green(`PASSED ✔ (${progRes.total_functions_decompiled} functions unified with headers & forward decls)`));
  } else {
    console.log(chalk.red("FAILED ✖ (Whole program reconstruction incomplete)"));
    allPassed = false;
  }
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

// 4. Binary Protections, Packers & Anti-Debug Scanner
process.stdout.write(`  [4/8] Scanning Protections, Anti-Debugging & Timing Traps... `);
try {
  const protRes = await runProtectionsScan(targetPE);
  if (protRes.protection_risk_score !== undefined && protRes.anti_debugging_apis.length > 0) {
    console.log(chalk.green(`PASSED ✔ (Risk Score: ${protRes.protection_risk_score}/100, Anti-Debug: ${protRes.anti_debugging_apis.join(", ")})`));
  } else {
    console.log(chalk.red("FAILED ✖"));
    allPassed = false;
  }
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

// 5. Native APK & Dalvik DEX Decompiler Suite
process.stdout.write(`  [5/8] Decompiling Android APK & Reconstructing Java Classes... `);
try {
  const apkRes = await runApkDecompile(targetAPK, 10);
  if (apkRes.is_apk && apkRes.permissions.length > 0 && apkRes.reconstructed_java.includes("VaultManager")) {
    console.log(chalk.green(`PASSED ✔ (Package: ${apkRes.package_name}, ${apkRes.permissions_count} permissions, Java Classes lifted)`));
  } else {
    console.log(chalk.red("FAILED ✖ (APK decompilation incomplete)"));
    allPassed = false;
  }
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

// 6. Apple iOS IPA & Mach-O ARM64 Decompiler Suite
process.stdout.write(`  [6/8] Decompiling iOS IPA, FairPlay DRM & Anti-Jailbreak... `);
try {
  const iosRes = await runIosDecompile(targetIPA);
  if (iosRes.is_ipa && iosRes.macho_analysis?.fairplay_drm_encrypted && iosRes.macho_analysis?.jailbreak_detection_alerts.length > 0) {
    console.log(chalk.green(`PASSED ✔ (Bundle ID: ${iosRes.bundle_id}, DRM: FairPlay cryptid=${iosRes.macho_analysis.crypt_id}, Anti-Jailbreak Detected)`));
  } else {
    console.log(chalk.red("FAILED ✖ (iOS IPA decompilation incomplete)"));
    allPassed = false;
  }
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

// 7. Automated String Decryptor & Deobfuscator
process.stdout.write(`  [7/8] Decrypting Obfuscated Strings (Rolling XOR & Base64)... `);
try {
  const decStrRes = await runStringDecrypt(targetPE, 10);
  if (decStrRes.total_encrypted_strings_recovered > 0) {
    console.log(chalk.green(`PASSED ✔ (${decStrRes.total_encrypted_strings_recovered} encrypted strings solved via rolling-key XOR)`));
  } else {
    console.log(chalk.red("FAILED ✖ (No encrypted strings recovered)"));
    allPassed = false;
  }
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

// 8. Cryptographic Primitive Scanner
process.stdout.write(`  [8/8] Scanning for Cryptographic Constants & Tables... `);
try {
  const cryptoRes = await runCryptoScan(targetPE);
  const cr = cryptoRes.normalized_result;
  console.log(chalk.green(`PASSED ✔ (Scan completed in ${cryptoRes.execution_time_ms}ms, Primitives: ${cr.total_primitives_found})`));
} catch (e) {
  console.log(chalk.red(`FAILED ✖ (${e.message})`));
  allPassed = false;
}

console.log("\n" + "─".repeat(50));
if (allPassed) {
  console.log(chalk.green.bold("★ HIGH-SPEED EXE, APK & IOS IPA DECOMPILER SUITE FULLY OPERATIONAL!\n"));
  process.exit(0);
} else {
  console.log(chalk.red.bold("✖ Decompiler verification errors encountered\n"));
  process.exit(1);
}
