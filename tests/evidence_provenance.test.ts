import { describe, it, expect } from "vitest";
import path from "path";
import { runBinaryPatcher } from "../src/core/patcher";
import { runAntiDebugAnnihilator } from "../src/core/anti_debug";

describe("SYMB Canonical Evidence & Provenance Contract Suite", () => {
  const sampleExe = path.resolve(__dirname, "../examples/01_ollvm_cff/CFF_win64.exe");

  it("produces compliant evidence structure with target identity and provenance", async () => {
    const res = await runAntiDebugAnnihilator(sampleExe, false);

    // Evidence Envelope
    expect(res.evidence_id).toMatch(/^ev_/);
    expect(res.timestamp).toBeDefined();
    expect(res.tool).toBe("neutralize_anti_debugging");
    expect(res.execution_time_ms).toBeGreaterThan(0);
    expect(Array.isArray(res.limitations)).toBe(true);

    // Target Identity
    expect(res.target_identity).toBeDefined();
    expect(res.target_identity?.path).toBe(sampleExe);
    expect(res.target_identity?.sha256).toMatch(/^[0-9a-f]{64}$/i);
    expect(res.target_identity?.md5).toMatch(/^[0-9a-f]{32}$/i);
    expect(res.target_identity?.format).toBe("PE");
    expect(res.target_identity?.size_bytes).toBeGreaterThan(1000);

    // Provenance & Confidence
    expect(res.provenance).toBeDefined();
    expect(res.provenance?.mode).toBe("real-native");
    expect(res.confidence).toBe("STATICALLY_VERIFIED");
  });
});
