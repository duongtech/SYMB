<div align="center">

<p align="center">
  <img src="../assets/symb-banner.svg" alt="SYMB Banner" width="100%">
</p>

[English](../../README.md) · **Tiếng Việt**

### Một MCP Server duy nhất cho Thực thi Biểu trưng (Symbolic Execution), Gỡ rối OLLVM (Unflattening) và Can thiệp Dịch ngược Chủ động (Active Binary Intervention) cho mọi AI Agent.

[![npm version](https://img.shields.io/npm/v/symb-agents?style=flat-square&color=cb3837)](https://www.npmjs.com/package/symb-agents)
[![MCP tool catalog](https://img.shields.io/badge/MCP-20%20Tools%20Active-5c4ee5?style=flat-square)](../mcp-contracts.md)
[![Python requirements](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](#-yêu-cầu-hệ-thống)
[![Node.js requirements](https://img.shields.io/badge/Node.js-requirements-339933?style=flat-square&logo=nodedotjs&logoColor=white)](#-yêu-cầu-hệ-thống)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

<br />

```bash
npx symb-agents setup
```

<br />

</div>

---

## 📑 Mục Lục (Table of Contents)

- [⚡ SYMB Là Gì?](#-symb-là-gì)
- [⚔️ So Sánh Kiến Trúc: SYMB vs REA](#️-so-sánh-kiến-trúc-symb-vs-rea)
- [🛠️ Danh Mục 20 Công Cụ MCP Native](#️-danh-mục-20-công-cụ-mcp-native)
  - [⚔️ Vũ Khí Can Thiệp Nhị Phân Chủ Động (5 Công cụ)](#️-vũ-khí-can-thiệp-nhị-phân-chủ-động-5-công-cụ)
  - [🔬 Lõi Thực Thi Biểu Trưng & Giải Ràng Buộc SMT (3 Công cụ)](#-lõi-thực-thi-biểu-trưng--giải-ràng-buộc-smt-3-công-cụ)
  - [⚡ Trình Dịch Ngược Đa Nền Tảng & Unpacker (4 Công cụ)](#-trình-dịch-ngược-đa-nền-tảng--unpacker-4-công-cụ)
  - [🔍 Tầm Soát Nhị Phân & Quản Lý Bộ Nhớ (8 Công cụ)](#-tầm-soát-nhị-phân--quản-lý-bộ-nhớ-8-công-cụ)
- [📚 Trung Tâm Tài Liệu Chuyên Sâu (`docs/`)](#-trung-tâm-tài-liệu-chuyên-sâu-docs)
- [🚀 Cài Đặt & Khởi Động Nhanh](#-cài-đặt--khởi-động-nhanh)
- [💻 Giao Diện Dòng Lệnh Độc Lập (CLI)](#-giao-diện-dòng-lệnh-độc-lập-cli)
- [🧪 Kiểm Thử & Xác Minh Đa Tầng (100% Pass)](#-kiểm-thử--xác-minh-đa-tầng-100-pass)
- [📦 Yêu Cầu Hệ Thống](#-yêu-cầu-hệ-thống)
- [📄 Bản Quyền](#-bản-quyền)

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

## ⚔️ So Sánh Kiến Trúc: SYMB vs REA

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

### ⚔️ Vũ Khí Can Thiệp Nhị Phân Chủ Động (5 Công cụ)
| Tên công cụ | Tham số chính | Chức năng cốt lõi | Tài liệu chi tiết |
| :--- | :--- | :--- | :--- |
| `patch_binary_executable` | `binary_path`, `patches`, `output_path` | Phẫu thuật byte nhị phân trên đĩa cứng. Chuyển đổi RVA sang raw offset, tính toán bảng chênh lệch và cập nhật PE CheckSum. | [Xem tài liệu](../active-binary-intervention.md#1-patch_binary_executable) |
| `neutralize_anti_debugging` | `binary_path`, `auto_patch`, `output_path` | Quét và triệt tiêu bẫy debug inline (RDTSC, INT 2D/3, PEB), tự động NOP out và ghi ra file đã vá với PE checksum chuẩn. | [Xem tài liệu](../active-binary-intervention.md#2-neutralize_anti_debugging) |
| `bypass_license_authorization` | `binary_path`, `force_success`, `apply_to_file` | Đánh giá các nhánh kiểm tra bản quyền, tính toán đảo ngược mã nhảy (`JE` $\leftrightarrow$ `JNE`), và xuất file đã bẻ khóa. | [Xem tài liệu](../active-binary-intervention.md#3-bypass_license_authorization) |
| `generate_frida_instrumentation` | `target`, `platform`, `script_type` | Tự động sinh script Frida chuyên dụng cho SSL unpinning, ẩn giấu RootBeer/Magisk và hook API Anti-Debug. | [Xem tài liệu](../active-binary-intervention.md#4-generate_frida_instrumentation) |
| `hot_patch_live_memory` | `pid`, `memory_address`, `patch_bytes_hex` | Tiêm trampoline và hook động trực tiếp vào RAM tiến trình mà không ghi đĩa. | [Xem tài liệu](../zero-disk-trampolines.md) |

### 🔬 Lõi Thực Thi Biểu Trưng & Giải Ràng Buộc SMT (3 Công cụ)
| Tên công cụ | Tham số chính | Chức năng cốt lõi | Tài liệu chi tiết |
| :--- | :--- | :--- | :--- |
| `unflatten_control_flow` | `binary_path`, `function_address` | Gỡ rối OLLVM switch dispatcher, khôi phục đồ thị CFG tuyến tính nguyên bản. | [Xem tài liệu](../ollvm-unflattening.md) |
| `solve_branch_reachability` | `binary_path`, `target_address` | Dùng Z3 SMT Solver & angr giải chính xác payload kích hoạt nhánh thành công. | [Xem tài liệu](../smt-branch-solving.md) |
| `trace_symbolic_taint` | `binary_path`, `source_symbol`, `sink_symbol` | Kiểm tra luồng dữ liệu biểu trưng từ input tới các hàm sink nguy hiểm (`memcpy`, format string). | [Xem tài liệu](../mcp-contracts.md) |

### ⚡ Trình Dịch Ngược Đa Nền Tảng & Unpacker (4 Công cụ)
| Tên công cụ | Tham số chính | Chức năng cốt lõi | Tài liệu chi tiết |
| :--- | :--- | :--- | :--- |
| `dynamically_unpack_binary` | `binary_path`, `max_instructions` | Giải nén mã độc và packer bằng giả lập CPU Unicorn, bắt OEP tail jump và dump bộ nhớ sạch. | [Xem tài liệu](../decompiler-advanced.md) |
| `decompile_native_function` | `binary_path`, `function_address` | Dịch ngược mã máy sang C pseudocode trong < 400ms bằng Capstone với tái cấu trúc vòng lặp. | [Xem tài liệu](../decompiler-advanced.md) |
| `decompile_entire_program` | `binary_path`, `max_functions` | Dịch ngược toàn bộ chương trình và tái tạo project mã nguồn C hoàn chỉnh. | [Xem tài liệu](../decompiler-advanced.md) |
| `decompile_apk_package` | `target_path`, `max_classes` | Bộ dịch ngược Android APK 5-pass: kiểm tra chữ ký v1/v2/v3, quét CWE, trích xuất JNI và dịch Dalvik sang Java. | [Xem tài liệu](../decompiler-advanced.md) |

### 🔍 Tầm Soát Nhị Phân & Quản Lý Bộ Nhớ (8 Công cụ)
| Tên công cụ | Tham số chính | Chức năng cốt lõi | Tài liệu chi tiết |
| :--- | :--- | :--- | :--- |
| `decompile_ios_ipa_package` | `target_path` | Dịch ngược gói Apple iOS IPA & Mach-O ARM64, kiểm tra FairPlay DRM (cryptid) và Anti-Jailbreak. | [Xem tài liệu](../mcp-contracts.md) |
| `decrypt_obfuscated_strings` | `binary_path`, `max_candidates` | Tự động hóa giải mã chuỗi mã hóa XOR (Single-byte, Rolling-key) và Base64. | [Xem tài liệu](../mcp-contracts.md) |
| `detect_binary_protections` | `binary_path` | Nhận diện packer (UPX, Themida, VMProtect), API Anti-Debug, Anti-VM và bẫy chu kỳ xung nhịp RDTSC. | [Xem tài liệu](../mcp-contracts.md) |
| `inspect_binary_layout` | `binary_path` | Quét cấu trúc PE/ELF, các cơ chế ASLR/DEP/SafeSEH, bảng import IAT và entropy từng section. | [Xem tài liệu](../mcp-contracts.md) |
| `detect_crypto_primitives` | `binary_path` | Tầm soát S-Box AES, hằng số SHA/MD5, bảng CRC32, ChaCha cho bài toán nghịch đảo SMT. | [Xem tài liệu](../mcp-contracts.md) |
| `scan_byte_entropy` | `binary_path`, `block_size` | Bản đồ nhiệt Shannon entropy 256-byte nhận diện shellcode mã hóa và dữ liệu nén. | [Xem tài liệu](../mcp-contracts.md) |
| `trace_binary_xrefs` | `binary_path` | Lập đồ thị gọi hàm toàn cục và dò vết chuỗi tham chiếu chéo (XREFs). | [Xem tài liệu](../mcp-contracts.md) |
| `optimize_large_media_buffer` | `file_path`, `target_max_mb` | Nén video, tách âm thanh và stream dump nhị phân hàng GB qua zero-RAM mmap. | [Xem tài liệu](../media-optimizer.md) |

---

## 📚 Trung Tâm Tài Liệu Chuyên Sâu (`docs/`)

SYMB tổ chức hệ thống tài liệu chuyên sâu theo từng chủ đề trong thư mục `docs/`:

| Tài liệu / Cẩm nang | Chủ đề chính | Nội dung chi tiết |
| :--- | :--- | :--- |
| ⚔️ **[Active Binary Intervention](../active-binary-intervention.md)** | **Bẻ khóa & Can thiệp mã máy** | Hướng dẫn RVA-to-Raw mapping, tính lại PE CheckSum, triệt hạ bẫy Anti-Debug, và sinh Frida hook. |
| 📜 **[Đặc tả Hợp đồng MCP Tool](../mcp-contracts.md)** | **Chuẩn giao thức MCP** | Chi tiết JSON Schema đầu vào/đầu ra và cấu trúc bằng chứng Canonical Evidence cho 20 công cụ. |
| 🌪️ **[Hướng dẫn Gỡ rối OLLVM](../ollvm-unflattening.md)** | **Khử làm rối luồng điều khiển** | Cơ chế giải biến trạng thái, xóa switch dispatcher và phục hồi CFG nguyên bản bằng Z3 & angr. |
| 🎯 **[Giải Ràng buộc Nhánh SMT](../smt-branch-solving.md)** | **Thực thi biểu trưng** | Tìm kiếm dữ liệu đầu vào kích hoạt nhánh đích, giải crackme CTF bằng Z3 SMT Theorem Prover. |
| ⚡ **[Kiến trúc Decompiler Nâng cao](../decompiler-advanced.md)** | **Dịch ngược Native & Dalvik** | Bộ giải nén Unicorn CPU, tái cấu trúc mã C pseudocode siêu tốc và bộ dịch ngược APK 5-pass. |
| 🔒 **[Tiêm Trampoline Zero-Disk](../zero-disk-trampolines.md)** | **Can thiệp RAM tiến trình** | Kỹ thuật sử dụng Win32 API (`VirtualProtectEx`) và `/proc/pid/mem` không để lại dấu vết trên đĩa. |
| 🎬 **[Tối ưu Buffer & Media Lớn](../media-optimizer.md)** | **Quản lý Context AI Agent** | Trích xuất audio tăng tốc phần cứng, nén video xuống <= 50MB, và streaming mmap bộ nhớ lớn. |
| 🧠 **[Cẩm nang Kỹ thuật Biểu trưng](../symbolic-engineering-guide.md)** | **Nguyên lý kiến trúc** | Định lý toán học bất biến, phương pháp tích hợp cho các tác nhân AI tự trị. |
| 🎯 **[Ma trận Mục tiêu & Nền tảng](../target-matrix.md)** | **Khả năng tương thích** | Hỗ trợ Windows (x86/x64), Linux (x86/x64/ARM), macOS (Mach-O), Android (DEX/.so) và iOS (IPA). |
| 🚀 **[Hướng dẫn Cài đặt Toàn diện](../installation.md)** | **Khởi đầu nhanh** | Hướng dẫn cấu hình chi tiết cho Claude Desktop, Cursor, Antigravity và cài đặt global CLI. |

---

## 🚀 Cài Đặt & Khởi Động Nhanh

```bash
# Cấu hình tự động cho AI Coding Agents
npx symb-agents setup

# Kiểm tra năng lực toàn hệ thống
npm test
```

---

## 💻 Giao Diện Dòng Lệnh Độc Lập (CLI)

```bash
# Triệt hạ bẫy Anti-Debugging và xuất file đã vá
symb antidebug ./target.exe --patch

# Bẻ khóa bản quyền và đảo ngược nhánh điều kiện
symb license-bypass ./target.exe --force-success

# Tự động giải nén file bị đóng gói (UPX / packer) bằng giả lập CPU Unicorn
symb unpack ./examples/01_ollvm_cff/CFF_win64.exe

# Dịch ngược hàm mã máy sang C pseudocode
symb decompile ./examples/02_smt_crackme/ais3_crackme 0x4005f6

# Dịch ngược Android APK và trích xuất chữ ký, manifest, lớp Java
symb apk ./examples/04_apk_sample/sample_protected.apk
```

---

## 🧪 Kiểm Thử & Xác Minh Đa Tầng (100% Pass)

```bash
# Chạy Vitest Unit & Integration Suites
npm run test:unit

# Chạy toàn bộ 8 hệ thống kiểm định tự trị
npm test
```

Bao gồm:
1. **System Capabilities & Solver Audit** (Node, Python, Z3, angr, Unicorn, Capstone)
2. **MCP Tool Contracts & Zod Schemas** (20 công cụ)
3. **Native High-Speed EXE Decompiler & Layout Engine**
4. **Z3 SMT Mathematical Logic Engine**
5. **OLLVM Control-Flow Unflattening** (PE & ELF)
6. **SMT Branch Reachability Solver**
7. **Large Media & Binary Buffer Optimizer Engine**
8. **Active Binary Intervention & Weaponized RE Engine**

---

## 📦 Yêu Cầu Hệ Thống

- **Node.js**: `>= 18.0.0` (Tương thích Node 20, 22, 24)
- **Python**: `>= 3.10`
- **Bộ Giải Toán Native**: `pip install -r requirements.txt` (Z3, angr, Unicorn, Capstone, pefile).

---

## 📄 Bản Quyền

Giấy phép MIT © 2026 [duongtech](https://github.com/duongtech).
