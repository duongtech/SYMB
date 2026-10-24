<div align="center">

[English](../../README.md) · **Tiếng Việt**

# SYMB: Kỹ thuật Dịch ngược Biểu trưng & Dỡ Mã Rối cho AI Agent

### Một MCP Server duy nhất cho thực thi biểu trưng, dỡ mã làm rối OLLVM và giải phương trình ràng buộc nhị phân.

**REA quan sát mã nguồn. SYMB giải quyết nó.**

[![npm version](https://img.shields.io/npm/v/symb-agents?style=flat-square&color=cb3837)](https://www.npmjs.com/package/symb-agents)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-5c4ee5?style=flat-square)](../mcp-contracts.md)
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

## ⚡ SYMB Là Gì?

**SYMB** là một máy chủ Model Context Protocol (MCP) mã nguồn mở, trang bị cho các AI Agent (Claude Code, Cursor, Antigravity, Copilot, Codex) siêu năng lực về **Thực thi biểu trưng (Symbolic Execution), Giải ràng buộc SMT, và Dỡ bỏ mã làm rối luồng điều khiển (Deobfuscation)**.

Trong khi các công cụ như [REA](https://github.com/morluto/rea) rất xuất sắc ở khâu *quan sát tĩnh* (dịch ngược file nhị phân, đọc AST, giải nén ASAR), **SYMB lấp đầy khoảng trống then chốt: giải toán toán học và dỡ rối chủ động**.

Khi các trình decompiler thông thường đầu hàng vì mã nguồn bị làm phẳng bằng OLLVM, ảo hóa (VM-based), hoặc được bảo vệ bởi các biểu thức kiểm tra mã hóa phức tạp, SYMB kích hoạt sức mạnh của **angr**, **Z3 SMT Solver**, và **Triton** để tự động giải ra input hợp lệ, dỡ phẳng đồ thị luồng điều khiển (CFG), và chứng minh các đường đi thực thi trong vòng vài giây.

---

## ⚔️ Tại Sao Lại Chọn SYMB? (So Sánh Trực Diện Với REA)

| Tiêu Chí | REA (`morluto/rea`) | SYMB (`duongtech/symb`) |
| :--- | :--- | :--- |
| **Bản Chất Cốt Lõi** | Quan sát cú pháp tĩnh thụ động | **Thực thi biểu trưng & Can thiệp giải toán chủ động** |
| **Mã Bị Làm Phẳng OLLVM** | ❌ Đầu hàng (Ra vòng lặp switch 50.000 dòng vô nghĩa) | ✅ **Dỡ phẳng biểu trưng & Phục hồi CFG gốc sạch sẽ** |
| **Tìm Input Thỏa Mãn Nhánh** | ❌ Thủ công (Bắt lập trình viên tự tính tay) | ✅ **Bộ giải Z3 giải nghiệm byte chính xác trong < 3s** |
| **Phân Tích Đường Đi (Reachability)** | ❌ Ước lượng sơ đồ hàm | ✅ **Chứng minh toán học đường đi khả thi / bất khả thi** |
| **Truy Vết Lỗ Hổng (Taint Analysis)** | ⚠️ Nhận xét bề mặt văn bản | ✅ **Theo dấu vết biến độc hại tới tận memory sinks** |
| **Can Thiệp Bộ Nhớ Tiến Trình** | ⚠️ Thụ động | ✅ **Hot-patching trực tiếp trong RAM (Zero-Disk)** |
| **Kết Quả Trả Về Cho Agent** | Đoạn text AST / C giả chung chung | **Chứng cứ chuẩn hóa + Dữ liệu nghiệm Input cụ thể** |

---

## 🛠️ Danh Mục Công Cụ MCP

SYMB cung cấp các công cụ MCP hiệu năng cao được thiết kế chuyên biệt cho AI Agent:

### 1. `unflatten_control_flow`
Phân tích biểu trưng kỹ thuật Control Flow Flattening (CFF) của OLLVM / Obfuscator-LLVM. Tự động nhận diện biến trạng thái (state variable), loại bỏ khối điều hướng rác (dispatcher block), mở rộng các bẫy điều kiện giả (opaque predicates), và tái cấu trúc lại mã nguồn C giả có cấu trúc rõ ràng.

### 2. `solve_branch_reachability`
Sử dụng `angr` và bộ chứng minh định lý `Z3 SMT Theorem Prover` để tìm chính xác chuỗi byte đầu vào đưa luồng thực thi đi thẳng tới địa chỉ mong muốn (như `SUCCESS`, `VALID_LICENSE`, `UNLOCKED`) và né tránh các nhánh báo lỗi.

### 3. `trace_symbolic_taint`
Thực hiện phân tích vết dữ liệu biểu trưng trên assembly gốc và WebAssembly. Kiểm tra xem dữ liệu do người dùng kiểm soát có thể tràn vào các điểm nhạy cảm (`memcpy`, `strcpy`, format strings, địa chỉ nhảy gián tiếp) hay không.

### 4. `devirtualize_bytecode_vm`
Nhận diện vòng lặp phân phối lệnh (Dispatcher) của các máy ảo tùy biến (Themida / custom bytecode). Phục hồi con trỏ lệnh ảo (VPC), bảng xử lý opcode, và nâng cấp tập lệnh ảo ngược về LLVM IR / C chuẩn.

### 5. `hot_patch_live_memory`
Thực hiện kỹ thuật tiêm trampoline và hook hàm trực tiếp trong bộ nhớ RAM của tiến trình đang chạy (Zero-Disk). Cho phép Agent thử nghiệm các thay đổi logic và mở khóa mà không cần ghi đè file trên ổ cứng.

---

## 🚀 Hướng Dẫn Bắt Đầu Nhanh

### 1. Cài Đặt Vào Agent Trong 1 Bước

Chạy lệnh hướng dẫn tương tác trong terminal của bạn:

```bash
npx symb-agents setup
```

Chọn các Agent bạn muốn tích hợp (**Claude Code**, **Cursor**, **Antigravity**, **Gemini CLI**, hoặc **Codex**). SYMB sẽ tự động đăng ký cấu hình MCP.

### 2. Hỏi Agent Của Bạn

Sau khi cài đặt, bạn chỉ cần ra lệnh trong khung chat:

```text
User: "Hàm kiểm tra bản quyền tại 0x00401500 trong file auth_core.exe bị OLLVM làm phẳng luồng điều khiển. Dỡ rối cho tôi và tìm chuỗi key 16 byte để nhảy vào 0x00401580."

Agent: 
⚡ [SYMB] Đang gọi unflatten_control_flow(binary="auth_core.exe", func="0x401500")...
⚡ [SYMB] Đã loại bỏ khối dispatcher tại 0x401520. Phục hồi đồ thị CFG nguyên bản với 4 basic blocks.
⚡ [SYMB] Đang gọi solve_branch_reachability(target="0x401580", avoid=["0x401590"])...
⚡ [SYMB] Z3 SMT solver hội tụ nghiệm sau 1.4s.

Đã tìm thấy chuỗi nghiệm hợp lệ:
ASCII: "K3Y-9842-AXQ-771"
Hex: 4b 33 59 2d 39 38 34 32 2d 41 58 51 2d 37 37 31
```

---

## 📦 Yêu Cầu Hệ Thống

- **Node.js**: `>= 18.0.0`
- **Python**: `>= 3.10`
- **Bộ giải toán**: `pip install angr z3-solver triton` (Script setup của SYMB có thể tự động cài đặt).

---

## 📄 Bản Quyền

Bản quyền mã nguồn MIT License © 2026 [duongtech](https://github.com/duongtech).
