#!/usr/bin/env node
import assert from "node:assert/strict";
import chalk from "chalk";
import path from "node:path";
import fs from "node:fs";
import { runAntiDebugAnnihilator } from "../dist/core/anti_debug.js";
import { runLicenseBypass } from "../dist/core/license_bypass.js";
import { runBinaryPatcher } from "../dist/core/patcher.js";
import { runFridaGenerator } from "../dist/core/frida_generator.js";

console.log(chalk.red.bold("\n⚔️  SYMB ACTIVE BINARY INTERVENTION & WEAPONIZED RE VERIFICATION\n"));

const sampleExe = path.resolve("examples/01_ollvm_cff/CFF_win64.exe");
const scratchDir = path.resolve("scratch_test_intervention");
if (!fs.existsSync(scratchDir)) {
  fs.mkdirSync(scratchDir, { recursive: true });
}

let passedTests = 0;
const totalTests = 5;

async function runTests() {
  // 1. Anti-Debug Scanner & Auto-Patcher
  process.stdout.write("  [1/5] Anti-Debug Traps & PEB Neutralizer... ");
  try {
    const patchedExePath = path.join(scratchDir, "CFF_no_antidebug.exe");
    const antiDebugRes = await runAntiDebugAnnihilator(sampleExe, true, patchedExePath);
    assert(antiDebugRes.normalized_result !== undefined);
    assert(antiDebugRes.confidence === "STATICALLY_VERIFIED");
    assert(antiDebugRes.target_identity?.format === "PE");
    console.log(chalk.green(`PASSED ✔ (${antiDebugRes.normalized_result.total_detections} traps detected)`));
    passedTests++;
  } catch (err) {
    console.log(chalk.red(`FAILED ✖ (${err.message})`));
  }

  // 2. License Check & DRM Inversion Engine
  process.stdout.write("  [2/5] License Check Inversion & DRM Logic Bypass... ");
  try {
    const licensedBypassedExe = path.join(scratchDir, "CFF_licensed.exe");
    const licenseRes = await runLicenseBypass(sampleExe, undefined, true, true, licensedBypassedExe);
    assert(licenseRes.normalized_result !== undefined);
    assert(licenseRes.target_identity?.format === "PE");
    assert(licenseRes.provenance?.engine.includes("capstone"));
    console.log(chalk.green(`PASSED ✔ (${licenseRes.normalized_result.detected_license_checks} branch points evaluated)`));
    passedTests++;
  } catch (err) {
    console.log(chalk.red(`FAILED ✖ (${err.message})`));
  }

  // 3. Surgical Physical Binary Patcher & PE Checksum Recalculation
  process.stdout.write("  [3/5] Surgical Binary Patcher & PE Checksum Engine... ");
  try {
    const patchTarget = path.join(scratchDir, "CFF_patched.exe");
    fs.copyFileSync(sampleExe, patchTarget);

    const patchRes = await runBinaryPatcher(
      patchTarget,
      [
        { offset: 0x400, bytes_hex: "90 90 90 90", description: "Test NOP Fill" },
        { offset: 0x410, bytes_hex: "EB 05", description: "Short JMP Inversion" }
      ],
      patchTarget,
      true,
      true
    );

    assert(patchRes.normalized_result.success === true);
    assert(patchRes.normalized_result.patches_applied === 2);
    assert(patchRes.normalized_result.diff_entries.length === 2);
    assert(patchRes.target_identity?.sha256 !== undefined);
    assert(fs.existsSync(patchTarget + ".bak"));
    console.log(chalk.green(`PASSED ✔ (${patchRes.normalized_result.patches_applied} patches applied, PE checksum recalculated)`));
    passedTests++;
  } catch (err) {
    console.log(chalk.red(`FAILED ✖ (${err.message})`));
  }

  // 4. Frida Dynamic Instrumentation Script Synthesizer (Android SSL / Root)
  process.stdout.write("  [4/5] Frida Dynamic Instrumentation (Android SSL & Root)... ");
  try {
    const fridaSsl = await runFridaGenerator("com.target.bankapp", "android", "ssl_unpinning");
    assert(fridaSsl.normalized_result.generated_script_javascript.includes("CertificatePinner"));
    assert(fridaSsl.normalized_result.features_included.length >= 3);

    const fridaRoot = await runFridaGenerator("com.target.bankapp", "android", "root_jailbreak_bypass");
    assert(fridaRoot.normalized_result.generated_script_javascript.includes("RootBeer"));
    console.log(chalk.green("PASSED ✔ (SSL Unpinning & Root Cloak synthesized)"));
    passedTests++;
  } catch (err) {
    console.log(chalk.red(`FAILED ✖ (${err.message})`));
  }

  // 5. Frida Windows/Native Anti-Debug Runtime Cloak
  process.stdout.write("  [5/5] Frida Windows Native Anti-Debug Cloak... ");
  try {
    const fridaAntiDebug = await runFridaGenerator("protected_game.exe", "windows", "anti_debug_runtime_cloak");
    assert(fridaAntiDebug.normalized_result.generated_script_javascript.includes("IsDebuggerPresent"));
    assert(fridaAntiDebug.normalized_result.generated_script_javascript.includes("CheckRemoteDebuggerPresent"));
    console.log(chalk.green("PASSED ✔ (Native API Interceptor generated)"));
    passedTests++;
  } catch (err) {
    console.log(chalk.red(`FAILED ✖ (${err.message})`));
  }

  console.log("\n" + "─".repeat(50));
  if (passedTests === totalTests) {
    console.log(chalk.green.bold(`★ ALL ${totalTests} ACTIVE INTERVENTION TESTS PASSED 100%!\n`));
    process.exit(0);
  } else {
    console.log(chalk.red.bold(`✖ ${totalTests - passedTests} intervention test(s) failed\n`));
    process.exit(1);
  }
}

runTests();
