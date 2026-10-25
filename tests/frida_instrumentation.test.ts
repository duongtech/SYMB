import { describe, it, expect } from "vitest";
import { runFridaGenerator } from "../src/core/frida_generator";

describe("SYMB Frida Dynamic Instrumentation Suite", () => {
  it("synthesizes Universal Android SSL Unpinning script", async () => {
    const res = await runFridaGenerator("com.banking.mobile", "android", "ssl_unpinning");

    expect(res.normalized_result.target).toBe("com.banking.mobile");
    expect(res.normalized_result.platform).toBe("android");
    expect(res.normalized_result.script_type).toBe("ssl_unpinning");
    expect(res.normalized_result.generated_script_javascript).toContain("CertificatePinner");
    expect(res.normalized_result.generated_script_javascript).toContain("TrustManagerImpl");
    expect(res.normalized_result.spawn_command).toContain("frida -U -f com.banking.mobile");
    expect(res.confidence).toBe("STATICALLY_VERIFIED");
  });

  it("synthesizes Android Root / Magisk Cloaking script", async () => {
    const res = await runFridaGenerator("com.protected.game", "android", "root_jailbreak_bypass");

    expect(res.normalized_result.generated_script_javascript).toContain("RootBeer");
    expect(res.normalized_result.generated_script_javascript).toContain("/system/bin/su");
    expect(res.normalized_result.features_included).toContain("RootBeer API Hijacking");
  });

  it("synthesizes Windows Native Anti-Debug API hook", async () => {
    const res = await runFridaGenerator("target.exe", "windows", "anti_debug_runtime_cloak");

    expect(res.normalized_result.platform).toBe("windows");
    expect(res.normalized_result.generated_script_javascript).toContain("IsDebuggerPresent");
    expect(res.normalized_result.generated_script_javascript).toContain("CheckRemoteDebuggerPresent");
  });
});
