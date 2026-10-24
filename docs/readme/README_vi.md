<div align="center">

<p align="center">
  <img src="../assets/symb-banner.svg" alt="SYMB Banner" width="100%">
</p>

[English](../../README.md) · **Tiếng Việt**

### Một MCP Server duy nhất cho Thực thi Biểu trưng (Symbolic Execution), Gỡ rối OLLVM (Unflattening) và Giải ràng buộc SMT cho mọi tác vụ Dịch ngược và Tác nhân AI.

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

<p align="center">
  <img src="../assets/symb-terminal-demo.svg" alt="SYMB Interactive Session" width="100%">
</p>

---

## ⚡ SYMB Là Gì?

**SYMB** là một Model Context Protocol (MCP) Server tự động hóa, trao quyền cho các AI Agent hàng đầu hiện nay (**Claude Code**, **Cursor**, **Antigravity**, **Gemini CLI**, **Copilot**, **Codex**) năng lực **Thực thi Biểu trưng (Symbolic Execution), Giải bài toán Ràng buộc SMT và Tự động Giải mã Làm rối Luồng điều khiển (CFG Deobfuscation)**.

Trong khi các công cụ dịch ngược thụ động truyền thống chỉ trích xuất cú pháp hoặc mã giả tĩnh, **SYMB biến AI Agent thành một cỗ máy giải toán tự trị thực thụ**:

- **Tự động Gỡ phẳng Luồng điều khiển (OLLVM Unflattening):** Quét biến trạng thái (state variable), triệt tiêu các vòng lặp điều phối (switch dispatcher) của OLLVM/Hikari/Goron, khử vị từ mờ (opaque predicates) và khôi phục đồ thị luồng điều khiển (CFG) nguyên bản.
- **Tự động Giải nhánh SMT (Automated Branch Solving):** Sử dụng **angr** và **Z3 Theorem Prover** để tính toán chính xác chuỗi byte đầu vào thỏa mãn các nhánh thành công (như `SUCCESS`, `VALID_LICENSE`, `UNLOCKED`) mà không cần fuzzing ngẫu nhiên.
- **Theo vết Biểu trưng Nhiễm bẩn (Symbolic Taint Tracing):** Chứng minh toán học luồng dữ liệu không tin cậy có thể xâm nhập vào các điểm nguy hiểm (`memcpy`, format string, indirect call).
- **Phẫu thuật Bộ nhớ Tiến trình Zero-Disk:** Tiêm hook và trampoline trực tiếp vào RAM của tiến trình đang chạy mà không làm thay đổi tệp nhị phân trên đĩa cứng, vượt qua các lớp bảo vệ kiểm tra mã băm (hash check/integrity).

---

## 🌊 Cách Thức Hoạt Động Của SYMB

<p align="center">
  <img src="../assets/symb-solver-flow.svg" alt="SYMB Investigation Flow" width="100%">
</p>

1. **Khởi tạo từ AI Agent**: Agent của bạn tiếp nhận yêu cầu phân tích binary hoặc giải bài toán và gọi SYMB qua giao thức chuẩn MCP JSON-RPC (stdio).
2. **Xây dựng Cây Cú pháp Biểu trưng (AST)**: SYMB dịch các tập lệnh máy hoặc khối basic block bị làm rối sang biểu diễn trung gian (VEX/LLVM IR) và xây dựng biểu thức logic.
3. **Giải Ràng buộc SMT**: Lõi Z3 và angr duyệt biểu trưng các đường dẫn thực thi, tích lũy điều kiện rẽ nhánh $\Phi$ và giải phương trình tìm nghiệm SAT.
4. **Trả lời Dưới dạng Bằng chứng Chuẩn hóa (Canonical SymbEvidence)**: Phản hồi về Agent dưới dạng JSON chi tiết chứa bằng chứng toán học, đồ thị liên kết basic block và chuỗi payload thực tế.

---

## 🎯 Ma Trận Mục Tiêu & Năng Lực Giải Quyết

SYMB yêu cầu Node.js 18+ và Python 3.10+ cùng các thư viện giải toán `z3-solver` và `angr`:

| Mục tiêu & Thách thức | Những gì SYMB Phân tích & Trả về | Yêu cầu & Tài liệu hướng dẫn |
| :--- | :--- | :--- |
| **Làm rối Luồng điều khiển (OLLVM / CFF)** | Triệt tiêu vòng lặp switch dispatcher, loại bỏ các bước nhảy rác, khôi phục CFG tuyến tính và mã giả C sạch | Tích hợp sẵn angr / Z3 AST solver; [Hướng dẫn OLLVM](../ollvm-unflattening.md) |
| **Giải Rẽ nhánh Phức tạp (SMT Branch Reachability)** | Chuỗi byte chính xác (ASCII, Hex) kích hoạt nhánh thành công và né tránh các nhánh báo lỗi | Z3 SMT Solver & angr; [Hướng dẫn SMT](../smt-branch-solving.md) |
| **Máy ảo Tùy biến (Custom Bytecode VMs)** | Trích xuất con trỏ lệnh ảo (VPC), bảng phân phối opcode và dịch ngược mã byte ảo về LLVM IR / C | Tích hợp bộ giải biểu trưng; [Ma trận mục tiêu](../target-matrix.md) |
| **Bộ nhớ Tiến trình Thời gian thực** | Tiêm hook và trampoline động trong RAM mà không chỉnh sửa file nhị phân trên đĩa (Zero-disk) | Quyền thực thi phù hợp (Admin/root); [Hướng dẫn Trampoline](../zero-disk-trampolines.md) |
| **Phân tích Taint Biểu trưng** | Dò vết truyền dữ liệu từ bộ đệm đầu vào tới các hàm đích nguy hiểm (`memcpy`, format string) | Tích hợp công cụ Taint; [Đặc tả Hợp đồng MCP](../mcp-contracts.md) |
| **Nghịch đảo Trạng thái Băm Mật mã** | Nghịch đảo các phép toán dịch bit phi tuyến, vòng lặp tính checksum tùy chỉnh để tìm seed ban đầu | Z3 bit-vector solver; [Hướng dẫn SMT](../smt-branch-solving.md) |
| **Luồng Điều khiển Rác (Bogus Control Flow)** | Chứng minh tính bất biến của vị từ mờ ($y^2 \ge 0$), xóa bỏ các khối lệnh chết và vòng lặp vô nghĩa | Tích hợp SMT simplifier; [Hướng dẫn OLLVM](../ollvm-unflattening.md) |
| **SDK Bảo mật Mobile** | Khôi phục luồng kiểm tra root và kiểm tra tính toàn vẹn bị làm rối trong file `.so` Android ARM64 | ARM64 backend với angr / Z3; [Hướng dẫn OLLVM](../ollvm-unflattening.md) |
| **Mã nhị phân WebAssembly (WASM)** | Gỡ phẳng các bảng switch WASM phức tạp và chuẩn hóa cấu trúc `block`/`loop` | Trình phân tích WASM tích hợp; [Ma trận mục tiêu](../target-matrix.md) |

---

## 🌟 Tình Huống Thực Tế Điển Hình (Showcases)

### Tình huống 1: Gỡ rối SDK Bảo mật Mobile bảo vệ bằng OLLVM
Một thư viện native Android `libsecurity.so` giấu hàm kiểm tra thiết bị root sau một máy trạng thái 48 nhánh rẽ:
- **Công cụ SYMB**: `unflatten_control_flow`
- **Kết quả**: Phát hiện biến trạng thái nằm trong thanh ghi `w19`, loại bỏ 38 cạnh dispatch rác và khôi phục 4 khối lệnh xác thực ban đầu chỉ trong 1.2 giây.

### Tình huống 2: Giải Ràng buộc SMT 128-bit cho Thuật toán Bản quyền
Một hàm DRM thực hiện 16 vòng xoay bit và số học modulo trước khi so sánh với mã băm mục tiêu:
- **Công cụ SYMB**: `solve_branch_reachability`
- **Kết quả**: Thiết lập biểu thức bit-vector 128-bit trên Z3; tìm ra mã bản quyền hợp lệ (`SYMB-7F89-A2C4-9981`) trong 38.4 mili-giây mà không cần brute-force.

### Tình huống 3: Tiêm Trampoline Bộ nhớ Không Ghi Đĩa (Zero-Disk) trong Live Daemon
Một dịch vụ nền Linux tự kiểm tra mã băm SHA256 của file nhị phân trên đĩa trước khi xử lý token bảo mật:
- **Công cụ SYMB**: `hot_patch_live_memory`
- **Kết quả**: Cấp phát bộ đệm trampoline thực thi trong RAM, chuyển hướng luồng kiểm tra và trích xuất token giải mã mà không thay đổi bất kỳ byte nào trên file nhị phân gốc.

---

## 🚀 Cài Đặt & Khởi Động Nhanh

### 1. Trình Thuật Sĩ Tự Động Thiết Lập
Chạy lệnh sau trên terminal để tự động cấu hình các AI Agent của bạn:

```bash
npx symb-agents setup
```

### 2. Cấu Hình Thủ Công Theo Từng Agent

#### Claude Code (`~/.claude/config.json`)
```json
{
  "mcpServers": {
    "symb": {
      "command": "npx",
      "args": ["-y", "symb-agents", "serve"]
    }
  }
}
```

#### Cursor (`~/.cursor/mcp.json` hoặc `.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "symb": {
      "command": "node",
      "args": ["/đường/dẫn/đến/symb/dist/index.js"]
    }
  }
}
```

#### Antigravity / Gemini CLI (`antigravity.json`)
```json
{
  "mcpServers": {
    "symb": {
      "command": "symb",
      "args": ["serve"]
    }
  }
}
```

---

## 🛠️ Danh Mục Công Cụ MCP

SYMB cung cấp bộ 7 công cụ dịch ngược và giải bài toán biểu trưng cốt lõi qua giao thức chuẩn MCP:

| Tên công cụ | Tham số chính | Chức năng cốt lõi |
| :--- | :--- | :--- |
| `decompile_native_function` | `binary_path`, `function_address`, `max_instructions` | Dịch ngược mã máy sang C Pseudocode siêu tốc bằng Capstone (.rdata XREFs) |
| `inspect_binary_layout` | `binary_path` | Quét cấu trúc PE/ELF, các cơ chế ASLR/DEP, bảng import IAT, và entropy section |
| `detect_crypto_primitives` | `binary_path` | Tầm soát S-Box AES, hằng số SHA/MD5, bảng CRC32, ChaCha cho bài toán nghịch đảo |
| `unflatten_control_flow` | `binary_path`, `function_address`, `arch` | Gỡ rối OLLVM switch dispatcher, khôi phục CFG sạch |
| `solve_branch_reachability` | `target_address`, `avoid_addresses`, `symbolic_vars` | Dùng Z3 giải chính xác dữ liệu đầu vào kích hoạt nhánh đích |
| `trace_symbolic_taint` | `source_address`, `sink_address`, `taint_var` | Kiểm tra luồng dữ liệu từ input không tin cậy tới memory sink |
| `hot_patch_live_memory` | `target_pid`, `hook_address`, `patch_bytes_hex` | Tiêm trampoline và hook động trực tiếp vào RAM tiến trình |

---

## 📦 Yêu Cầu Hệ Thống

- **Node.js**: `>= 18.0.0` (Tương thích Node 20, 22, 24)
- **Python**: `>= 3.10`
- **Bộ Giải Toán Native**: `pip install angr z3-solver triton` (Thuật sĩ `npx symb-agents setup` có thể tự động cài đặt).

---

## 📖 Tài Liệu Tham Khảo

- [Ma Trận Phân Tích & Giải Quyết Mục Tiêu](../target-matrix.md)
- [Hướng Dẫn Gỡ Rối OLLVM](../ollvm-unflattening.md)
- [Hướng Dẫn Giải Ràng Buộc Nhánh SMT](../smt-branch-solving.md)
- [Hướng Dẫn Tiêm Trampoline Bộ Nhớ Zero-Disk](../zero-disk-trampolines.md)
- [Đặc Tả Hợp Đồng Công Cụ MCP](../mcp-contracts.md)
- [Hướng Dẫn Tích Hợp Cho Agent](../installation.md)
- [Chỉ Dẫn Cho AI Agent](../../AGENTS.md)
- [Chính Sách Đóng Góp](../../CONTRIBUTING.md)
- [Chính Sách Bảo Mật](../../SECURITY.md)

---

## 📄 Bản Quyền

Giấy phép MIT © 2026 [duongtech](https://github.com/duongtech).
