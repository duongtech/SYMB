import { describe, it, expect } from "vitest";
import path from "path";
import fs from "fs";
import { runBinaryPatcher } from "../src/core/patcher";
import { runAntiDebugAnnihilator } from "../src/core/anti_debug";
import { runLicenseBypass } from "../src/core/license_bypass";

describe("SYMB Active Binary Intervention Test Suite", () => {
  const sampleExe = path.resolve(__dirname, "../examples/01_ollvm_cff/CFF_win64.exe");
  const scratchDir = path.resolve(__dirname, "../scratch_test_intervention");

  if (!fs.existsSync(scratchDir)) {
    fs.mkdirSync(scratchDir, { recursive: true });
  }

  it("applies surgical physical byte patches and recalculates PE checksum", async () => {
    const testTarget = path.join(scratchDir, "vitest_patch_target.exe");
    fs.copyFileSync(sampleExe, testTarget);

    const res = await runBinaryPatcher(
      testTarget,
      [
        { offset: 0x500, bytes_hex: "90 90 90 90", description: "Vitest NOP sled" },
        { offset: 0x510, bytes_hex: "EB 10", description: "Vitest short jump" }
      ],
      testTarget,
      true,
      true
    );

    expect(res.normalized_result.success).toBe(true);
    expect(res.normalized_result.patches_applied).toBe(2);
    expect(res.normalized_result.diff_entries.length).toBe(2);
    expect(res.normalized_result.diff_entries[0].patched_bytes).toBe("90 90 90 90");
    expect(res.normalized_result.diff_entries[1].patched_bytes).toBe("eb 10");
    expect(res.target_identity?.sha256).toBeDefined();
    expect(res.target_identity?.format).toBe("PE");
    expect(res.confidence).toBe("STATICALLY_VERIFIED");
  });

  it("scans and neutralizes anti-debugging traps", async () => {
    const patchedOutput = path.join(scratchDir, "vitest_antidebug_out.exe");
    const res = await runAntiDebugAnnihilator(sampleExe, true, patchedOutput);

    expect(res.normalized_result.total_detections).toBeGreaterThan(0);
    expect(res.normalized_result.detections.length).toBeGreaterThan(0);
    expect(res.target_identity?.format).toBe("PE");
    expect(res.confidence).toBe("STATICALLY_VERIFIED");
    expect(res.provenance?.engine).toBe("pefile_inline_opcode_scanner");
  });

  it("analyzes authorization logic and inverts license branches", async () => {
    const patchedOutput = path.join(scratchDir, "vitest_license_out.exe");
    const res = await runLicenseBypass(sampleExe, undefined, true, true, patchedOutput);

    expect(res.normalized_result.detected_license_checks).toBeGreaterThan(0);
    expect(res.normalized_result.decisions.length).toBeGreaterThan(0);
    expect(res.normalized_result.runtime_ram_patch_ready).toBe(true);

    const firstDecision = res.normalized_result.decisions[0];
    expect(firstDecision.conditional_jump_address).toBeDefined();
    expect(firstDecision.recommended_patch).toBeDefined();
    expect(firstDecision.patch_bytes_hex).toBeDefined();
  });
});
