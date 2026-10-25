<div align="center">

<p align="center">
  <img src="../assets/symb-banner.svg" alt="SYMB Banner" width="100%">
</p>

[English](../../README.md) · **Tiếng Việt**

### Một MCP Server duy nhất cho Thực thi Biểu trưng (Symbolic Execution), Gỡ rối OLLVM (Unflattening) và Can thiệp Dịch ngược Chủ động (Active Binary Intervention) cho mọi AI Agent.

[![npm version](https://img.shields.io/npm/v/symb-agents?style=flat-square&color=cb3837)](https://www.npmjs.com/package/symb-agents)
[![MCP tool catalog](https://img.shields.io/badge/MCP-20%20Tools%20Active-5c4ee5?style=flat-square)](../mcp-contracts.md)
[![Python requirements](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](#yêu-cầu-hệ-thống)
[![Node.js requirements](https://img.shields.io/badge/Node.js-requirements-339933?style=flat-square&logo=nodedotjs&logoColor=white)](#yêu-cầu-hệ-thống)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

<br />

```bash
npx symb-agents setup
```

<br />

</div>

---

<p align="center">
  <img src="../assets/symb-terminal-demo.svg" alt="SYMB Interactive Session" width="100%">
</p>

---

## ⚡ SYMB Là Gì?

**SYMB** là một Model Context Protocol (MCP) Server tự động hóa, trao quyền cho các AI Agent hàng đầu hiện nay (**Claude Code**, **Cursor**, **Antigravity**, **Gemini CLI**, **Copilot**, **Codex**) năng lực **Thực thi Biểu trưng (Symbolic Execution), Giải bài toán Ràng buộc SMT và Tự động Can thiệp Dịch ngược (Active Binary Intervention)**.

Trong khi các công cụ dịch ngược truyền thống (như `morluto/rea`) chỉ quan sát tĩnh và từ chối can thiệp nhị phân, **SYMB biến AI Agent thành một cỗ máy bẻ khóa và can thiệp tự trị thực thụ**:

- **Tự động Gỡ phẳng Luồng điều khiển (OLLVM Unflattening):** Quét biến trạng thái (state variable), triệt tiêu các vòng lặp điều phối (switch dispatcher) của OLLVM/Hikari/Goron, khử vị từ mờ (opaque predicates) và khôi phục đồ thị luồng điều khiển (CFG) nguyên bản.
- **Tự động Giải nhánh SMT (Automated Branch Solving):** Sử dụng **angr** và **Z3 Theorem Prover** để tính toán chính xác chuỗi byte đầu vào thỏa mãn các nhánh thành công (`VALID_LICENSE`, `UNLOCKED`) mà không cần fuzzing ngẫu nhiên.
- **Can thiệp Nhị phân & Phẫu thuật File Thực thi trên Đĩa:** Chuyển đổi chính xác RVA sang Raw File Offset, đảo nhánh nhảy có điều kiện (`JZ` $\leftrightarrow$ `JNZ`), ghi trực tiếp opcode đã vá và tự động cập nhật lại `PE OptionalHeader.CheckSum`.
- **Triệt hạ Bẫy Chống Debug & Kiểm tra PEB:** Tự động phát hiện và NOP out (`0x90`) các bẫy `RDTSC`, `RDTSCP`, `INT 2D`, `INT 3`, và truy cập cờ `BeingDebugged` trong PEB.
- **Tổng hợp Frida Dynamic Instrumentation:** Tự động sinh mã kịch bản Frida vượt kiểm tra chứng chỉ số (Universal SSL Unpinning), ẩn danh Root/Magisk và hook API Windows native (`IsDebuggerPresent`).
- **Phẫu thuật Bộ nhớ Tiến trình Zero-Disk:** Tiêm hook và trampoline trực tiếp vào RAM của tiến trình đang chạy mà không làm thay đổi tệp nhị phân trên đĩa cứng.

---

## ⚔️ So Sánh SYMB vs REA (Passive vs Active)

| Tính năng | Trợ lý thụ động (như `morluto/rea`) | SYMB (Active Intervention Engine) |
| :--- | :---: | :---: |
| **Triết lý** | Chỉ đọc, mô tả và quan sát thụ động | **Can thiệp thực chiến & Tự động bẻ khóa** |
| **Sửa đổi nhị phân trên đĩa** | ❌ Từ chối tích hợp | ✔ **Phẫu thuật file trực tiếp với RVA-to-Raw mapping** |
| **Tự động tính lại PE CheckSum** | ❌ Không hỗ trợ | ✔ **Tự động cập nhật `OptionalHeader.CheckSum`** |
| **Xử lý Anti-Debug / Timing** | ⚠️ Chỉ liệt kê cảnh báo | ✔ **Tự động NOP out RDTSC, INT 2D, PEB BeingDebugged** |
| **Bypass Bản quyền / License** | ⚠️ Chỉ nhận diện logic | ✔ **Tự động đảo nhánh điều kiện & xuất file đã crack** |
| **Sinh Frida Hook Scripts** | ⚠️ Giới hạn | ✔ **Tự động sinh kịch bản SSL Unpinning, Root Cloak** |
| **Live RAM Hot Patch** | ❌ Không hỗ trợ | ✔ **Zero-Disk memory trampolines qua Win32 API / Linux mem** |
| **Hệ thống Kiểm thử** | ✔ Đa dạng | ✔ **4 Vitest Suites + 8 Comprehensive Suites (Pass 100%)** |

---

## 🛠️ Danh Mục 20 Công Cụ MCP Native

### ⚔️ Vũ Khí Can Thiệp Nhị Phân Chủ Động (Active Intervention)
| Tên công cụ | Tham số chính | Chức năng cốt lõi |
| :--- | :--- | :--- |
| `neutralize_anti_debugging` | `binary_path`, `auto_patch`, `output_path` | Quét và triệt tiêu bẫy debug inline (RDTSC, INT 2D/3, PEB), tự động NOP out và ghi ra file đã vá với PE checksum chuẩn. |
| `bypass_license_authorization` | `binary_path`, `force_success`, `apply_to_file` | Đánh giá các nhánh kiểm tra bản quyền, tính toán đảo ngược mã nhảy (`JE` $\leftrightarrow$ `JNE`), và xuất file đã bẻ khóa. |
| `patch_binary_executable` | `binary_path`, `patches`, `output_path` | Phẫu thuật byte nhị phân trên đĩa cứng. Chuyển đổi RVA sang raw offset, tính toán bảng chênh lệch và cập nhật PE CheckSum. |
| `generate_frida_instrumentation` | `target`, `platform`, `script_type` | Tự động sinh script Frida chuyên dụng cho SSL unpinning, ẩn giấu RootBeer/Magisk và hook API Anti-Debug. |
| `hot_patch_live_memory` | `pid`, `memory_address`, `patch_bytes_hex` | Tiêm trampoline và hook động trực tiếp vào RAM tiến trình mà không ghi đĩa. |

### 🔬 Lõi Thực Thi Biểu Trưng & Dịch Ngược Chuyên Sâu
| Tên công cụ | Tham số chính | Chức năng cốt lõi |
| :--- | :--- | :--- |
| `dynamically_unpack_binary` | `binary_path`, `max_instructions` | Giải nén mã độc và packer bằng giả lập CPU Unicorn, bắt OEP tail jump và dump bộ nhớ sạch. |
| `unflatten_control_flow` | `binary_path`, `function_address` | Gỡ rối OLLVM switch dispatcher, khôi phục đồ thị CFG tuyến tính nguyên bản. |
| `solve_branch_reachability` | `binary_path`, `target_address` | Dùng Z3 SMT Solver & angr giải chính xác payload kích hoạt nhánh thành công. |
| `trace_symbolic_taint` | `binary_path`, `source_symbol`, `sink_symbol` | Kiểm tra luồng dữ liệu biểu trưng từ input tới các hàm sink nguy hiểm (`memcpy`, format string). |
| `decompile_native_function` | `binary_path`, `function_address` | Dịch ngược mã máy sang C pseudocode trong < 400ms bằng Capstone với tái cấu trúc vòng lặp. |
| `decompile_entire_program` | `binary_path`, `max_functions` | Dịch ngược toàn bộ chương trình và tái tạo project mã nguồn C hoàn chỉnh. |
| `decompile_apk_package` | `target_path`, `max_classes` | Bộ dịch ngược Android APK 5-pass: kiểm tra chữ ký v1/v2/v3, quét CWE, trích xuất JNI và dịch Dalvik sang Java. |
| `decompile_ios_ipa_package` | `target_path` | Dịch ngược gói Apple iOS IPA & Mach-O ARM64, kiểm tra FairPlay DRM (cryptid) và Anti-Jailbreak. |
| `decrypt_obfuscated_strings` | `binary_path`, `max_candidates` | Tự động hóa giải mã chuỗi mã hóa XOR (Single-byte, Rolling-key) và Base64. |
| `detect_binary_protections` | `binary_path` | Nhận diện packer (UPX, Themida, VMProtect), API Anti-Debug, Anti-VM và bẫy chu kỳ xung nhịp RDTSC. |
| `inspect_binary_layout` | `binary_path` | Quét cấu trúc PE/ELF, các cơ chế ASLR/DEP/SafeSEH, bảng import IAT và entropy từng section. |
| `detect_crypto_primitives` | `binary_path` | Tầm soát S-Box AES, hằng số SHA/MD5, bảng CRC32, ChaCha cho bài toán nghịch đảo SMT. |
| `scan_byte_entropy` | `binary_path`, `block_size` | Bản đồ nhiệt Shannon entropy 256-byte nhận diện shellcode mã hóa và dữ liệu nén. |
| `trace_binary_xrefs` | `binary_path` | Lập đồ thị gọi hàm toàn cục và dò vết chuỗi tham chiếu chéo (XREFs). |
| `optimize_large_media_buffer` | `file_path`, `target_max_mb` | Nén video, tách âm thanh và stream dump nhị phân hàng GB qua zero-RAM mmap. |

---

## 🚀 Cài Đặt & Khởi Động Nhanh

```bash
# Cấu hình tự động cho AI Coding Agents
npx symb-agents setup

# Kiểm tra năng lực toàn hệ thống
npm test
```

---

## 📄 Bản Quyền

Giấy phép MIT © 2026 [duongtech](https://github.com/duongtech).
