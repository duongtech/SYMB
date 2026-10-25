import { describe, it, expect } from "vitest";
import path from "path";
import fs from "fs";
import { runApkDecompile } from "../src/core/apk";

describe("SYMB Native APK 5-Pass Decompiler Suite", () => {
  const sampleProtectedApk = path.resolve(__dirname, "../examples/04_apk_sample/sample_protected.apk");
  const termuxApk = path.resolve(__dirname, "../examples/04_apk_sample/Termux.apk");

  it("executes all 5 passes on committed sample APK fixture", async () => {
    const res = await runApkDecompile(sampleProtectedApk, 5);

    expect(res.is_apk).toBe(true);
    expect(res.total_dex_files).toBeGreaterThan(0);
    expect(res.total_classes_found).toBeGreaterThan(0);

    // Pass 1: Manifest
    expect(res.permissions_count).toBeGreaterThan(0);
    expect(res.permissions).toContain("android.permission.INTERNET");

    // Pass 2: Signature
    expect(res.signature_info).toBeDefined();

    // Pass 3: Dalvik to Java
    expect(res.reconstructed_java).toContain("class");

    // Pass 4: Secret hunting & passes summary
    expect(res.passes_summary).toBeDefined();
    expect(res.passes_summary?.pass1_manifest).toBeDefined();
    expect(res.passes_summary?.pass2_signature).toBeDefined();
    expect(res.passes_summary?.pass3_dalvik_lifter).toBeDefined();
    expect(res.passes_summary?.pass4_secret_hunt).toBeDefined();
    expect(res.passes_summary?.pass5_native_jni).toBeDefined();

    // Pass 5: Native JNI
    expect(res.native_libraries.length).toBeGreaterThan(0);
  });

  it("executes deep verification on Termux APK when present", async () => {
    if (!fs.existsSync(termuxApk)) {
      // In CI environments where large 33MB binaries are excluded from Git clone
      return;
    }

    const res = await runApkDecompile(termuxApk, 5);
    expect(res.is_apk).toBe(true);
    expect(res.total_dex_files).toBeGreaterThan(0);
    expect(res.total_classes_found).toBeGreaterThan(500);
    expect(res.permissions_count).toBeGreaterThan(5);
    expect(res.permissions).toContain("android.permission.INTERNET");
    expect(res.signature_info?.is_signed).toBe(true);
    expect(res.signature_info?.schemes.v2).toBe(true);
    expect(res.signature_info?.signers.length).toBeGreaterThan(0);
    expect(res.reconstructed_java).toContain("public class");
  }, 45000);
});
