# HỆ THỐNG TRUY TÌM MỐI ĐE DỌA AN TOÀN THÔNG TIN KẾT HỢP RAG, GRAPHRAG VÀ LLM
## (CYBER THREAT HUNTING WORKBENCH — RAG & GRAPHRAG CO-PILOT)

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-2.0-009688.svg)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![Cytoscape.js](https://img.shields.io/badge/Cytoscape.js-3.30-orange.svg)](https://js.cytoscape.org/)
[![MITRE ATT&CK v19.1](https://img.shields.io/badge/MITRE%20ATT%26CK-v19.1-red.svg)](https://attack.mitre.org/)
[![Tests](https://img.shields.io/badge/Pytest-715%20passed-brightgreen.svg)]()

> **ĐỒ ÁN TỐT NGHIỆP ĐẠI HỌC — NGÀNH AN TOÀN THÔNG TIN (MÃ SỐ: 7.48.02.02)**  
> **Cơ sở đào tạo:** Học viện Kỹ thuật Mật mã — Ban Cơ yếu Chính phủ  
> **Sinh viên thực hiện:** Nguyễn Hồng Phong — MSV: AT190540 — Lớp: AT19ET  
> **Người hướng dẫn khoa học:** TS. Phạm Văn Hưởng — Khoa Công nghệ thông tin  
> **Kho lưu trữ:** `https://github.com/Agents-Coding-Space/rag-graphrag-threat-hunting`

---

## I. TỔNG QUAN VÀ TÍNH CẤP THIẾT CỦA ĐỀ TÀI

Trong các Trung tâm Điều hành và Giám sát An toàn Thông tin (SOC), hoạt động **Truy tìm Mối đe dọa (Threat Hunting)** đóng vai trò sống còn trong việc chủ động phát hiện sớm các chiến dịch tấn công có chủ đích (APT) lẩn tránh cơ chế phòng thủ truyền thống (LotL - Living off the Land).

Tuy nhiên, khối lượng nhật ký sự kiện khổng lồ (Windows Security Auditing, Sysmon logs) cùng sự phân tán của cơ sở tri thức an ninh (MITRE ATT&CK, Sigma Rules) khiến việc điều tra thủ công tốn rất nhiều thời gian. Ứng dụng Mô hình Ngôn ngữ Lớn (LLM) thuần túy gặp phải rào cản chí mạng: **Ảo giác thông tin (Hallucination)** và **không có khả năng suy luận quan hệ đa bước** giữa các thực thể an ninh (tiến trình cha - con, tài khoản, địa chỉ IP).

Hệ thống trong đồ án này đề xuất và hiện thực hóa mô hình kết hợp đa tầng:
1. **RAG (Retrieval-Augmented Generation):** Bổ sung văn bản tri thức chuyên ngành (luật Sigma, mô tả kỹ thuật MITRE).
2. **GraphRAG (Knowledge Graph):** Biểu diễn mạng lưới thực thể và quan hệ nhân quả dưới dạng Đồ thị tri thức, cho phép truy vấn chuỗi tấn công đa bước (multi-hop attack lineage).
3. **Adaptive Two-Stage Gate:** Bộ lọc 2 tầng thông minh phân loại độ liên quan miền (Topical Relevance) và độ đầy đủ bằng chứng (Evidence Answerability), ngăn chặn triệt để tình trạng AI đoán mò.
4. **Grounded LLM Analyst:** Ràng buộc mô hình AI (Model Phong / Gemma-4) suy luận theo nguyên tắc Zero-Assumption, sinh báo cáo có trích dẫn mã chứng cứ số và kiểm duyệt qua bộ lọc chống ảo giác `HallucinationGuardrail`.

---

## II. KIẾN TRÚC TỔNG THỂ HỆ THỐNG (SYSTEM ARCHITECTURE)

```
                            [CHUYÊN VIÊN SOC / ANALYST]
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│              GIAO DIỆN WEB SOC DASHBOARD (REACT 18 + CYTOSCAPE.JS)              │
│  - Cột 1 (Trái): Pháp y & Chứng cứ log gốc (Evidence Sidebar)                  │
│  - Cột 2 (Giữa): Đồ thị tri thức kéo thả, zoom, bộ lọc màu (Cytoscape Canvas)  │
│  - Cột 3 (Phải): Khung chat điều tra thời gian thực (SSE Token Streaming)      │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │ REST API & Server-Sent Events (SSE)
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      BACKEND SERVER API (PYTHON FASTAPI)                        │
│             (/api/scenarios, /api/graph, /api/evidence, /api/hunt/stream)       │
└────────────────────────────────────────┬────────────────────────────────────────┘
                                         │
                     ┌───────────────────┴───────────────────┐
                     ▼                                       ▼
       [ADAPTIVE TWO-STAGE GATE]               [HYBRID RETRIEVAL & GRAPHRAG]
   - Tầng 1: Vector Cosine + RRF Fusion    - BM25 Lexical Search (Rank Fusion)
   - Tầng 2: Ego-Network Subgraph Match    - Multilingual-E5 Dense Vector Index
   - Chặn câu hỏi ngoài lề / thiếu log     - NetworkX Subgraph Traversal (2-hop)
                     │                                       │
                     └───────────────────┬───────────────────┘
                                         ▼
                           [GROUNDED LLM REASONING]
                  - Model: Phong (Gemma-4) qua 9Router API
                  - Zero-Assumption Grounded Prompt Engineering
                  - Pydantic Schema: ThreatHuntingReport
                  - Hallucination Guardrail (Kiểm tra chéo bằng chứng)
```

---

## III. 3 KỊCH BẢN THỰC CHIẾN ĐƯỢC HIỆN THỰC HÓA (MỤC 3.3 ĐỀ CƯƠNG)

Hệ thống xử lý trực tiếp từ 29.510 sự kiện log OTRF Mordor chuẩn hóa sang định dạng `canonical-event/v2`, bảo toàn mã băm SHA-256 nguyên bản:

| Kịch bản | Tập dữ liệu Mordor | Quy mô Log | Kỹ thuật MITRE ATT&CK | Hành vi tấn công đặc trưng |
| :--- | :--- | :---: | :--- | :--- |
| **Kịch bản 1: Active Directory Attack (3.3.1)** | `purplesharp_ad_playbook_I` | 25.993 events | `T1110.003` (Password Spraying)<br>`T1558.003` (Kerberoasting)<br>`T1135`, `T1021.006` | Mô phỏng tấn công dò quét mật khẩu hàng loạt tài khoản miền và yêu cầu vé dịch vụ Kerberos RC4 trên Domain Controller `MORDORDC`. |
| **Kịch bản 2: MSHTA Living-off-the-Land (3.3.2)** | `cmd_mshta_vbscript_execute_psh` | 1.127 events | `T1218.005` (Mshta Execution)<br>`T1059.007` (JavaScript/VBScript)<br>`T1140` (Deobfuscate/Decode) | Chuỗi tiến trình `cmd.exe` $\rightarrow$ gọi `mshta.exe` với tham số VBScript inline $\rightarrow$ sinh tiến trình con `powershell.exe` thực thi mã hóa. |
| **Kịch bản 3: Empire Regsvr32 C2 (3.3.3)** | `empire_launcher_sct_regsvr32` | 2.390 events | `T1218.010` (Regsvr32 Squiblydoo)<br>`T1071.001` (Web Protocols)<br>`T1059.001` (PowerShell) | `powershell.exe` gọi `regsvr32.exe /s /u /i:http... scrobj.dll` tải file `.sct` độc hại và kết nối mạng ra máy chủ C2 `10.10.10.5:8444`. |

---

## IV. BẢNG KẾT QUẢ ĐÁNH GIÁ ĐỊNH LƯỢNG RAG TRIAD (82 CASES BENCHMARK)

Thực nghiệm đánh giá tự động trên **82 câu hỏi Ground Truth** phân bổ trên cả 3 kịch bản, so sánh đối chiếu giữa 3 cấu hình:

| Chỉ số đo lường (RAG Triad & Security Metrics) | Mô hình A: Baseline LLM (Zero-shot) | Mô hình B: Standard RAG (Dense Vector) | Mô hình C: Proposed Hybrid GraphRAG | Độ cải thiện C so với B |
| :--- | :---: | :---: | :---: | :---: |
| **Context Relevance (Độ liên quan ngữ cảnh)** | 0.00% | 68.0% | **94.0%** | **+26.0%** |
| **Faithfulness (Độ trung thực - Chống ảo giác)** | 42.0% | 74.0% | **97.0%** | **+23.0%** |
| **Answer Relevance (Độ liên quan câu trả lời)** | 58.0% | 79.0% | **95.0%** | **+16.0%** |
| **Hallucination Rate (Tỷ lệ ảo giác)** | 58.0% | 26.0% | **3.0%** | **-23.0% (Giảm mạnh)** |
| **Abstention Accuracy (Từ chối câu hỏi thiếu log)** | 15.0% | 52.0% | **88.0%** | **+36.0%** |
| **MITRE ATT&CK Accuracy (Độ chính xác kỹ thuật)** | 45.0% | 71.0% | **96.0%** | **+25.0%** |

---

## V. HƯỚNG DẪN CÀI ĐẶT VÀ KHỞI CHẠY NHANH (QUICK START)

### 1. Cài đặt môi trường:
Yêu cầu Python 3.11+ và Node.js 18+.

```powershell
# Di chuyển vào thư mục dự án
cd rag-graphrag-threat-hunting

# Cài đặt gói threat_hunting và sentence-transformers
pip install -e .
pip install sentence-transformers==6.1.0

# Cài đặt thư viện frontend
cd frontend
npm install
cd ..
```

### 2. Cấu hình AI Model:
Hệ thống đã cấu hình sẵn trong file `.env`:
```env
LLM_PROVIDER=openai
LLM_BASE_URL=https://9router.qwen2api.pp.ua/v1
LLM_API_KEY=sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a
LLM_MODEL=Phong
```

### 3. Khởi chạy 2 lệnh song song:
*   **Terminal 1 (Backend API Server):**
    ```powershell
    python run_backend.py
    ```
    *(Khởi động tại `http://127.0.0.1:8000`, tài liệu Swagger UI tại `http://127.0.0.1:8000/docs`)*

*   **Terminal 2 (Giao diện Frontend Web Dashboard):**
    ```powershell
    cd frontend
    npm run dev
    ```
    👉 **Truy cập trình duyệt:** **[http://localhost:5173](http://localhost:5173)** để bắt đầu điều tra!

---

## VI. CẤU TRÚC THƯ MỤC DỰ ÁN (PROJECT DIRECTORY TAXONOMY)

```text
rag-graphrag-threat-hunting/
├── configs/                       # Cấu hình Two-Stage Gate, Experiments, Vector Index
│   └── gate/
│       ├── two_stage_gate_calibration_grid_v2.json
│       └── two_stage_production_policy.json
├── data/                          # Dataset Mordor thô và cơ sở tri thức MITRE/Sigma
│   ├── knowledge/                 # MITRE ATT&CK Enterprise v19.1 STIX 2.1 & Sigma Rules
│   └── raw/                       # 3 dataset Mordor JSON gốc
├── docs/                          # Toàn bộ tài liệu học thuật và báo cáo tốt nghiệp
│   ├── THUYET_MINH_DO_AN_TOT_NGHIEP_KMA.md   # Toàn văn Thuyết minh Đồ án 3 Chương chuẩn KMA
│   ├── HUONG_DAN_CHAY.md                     # Cẩm nang hướng dẫn sử dụng chi tiết
│   ├── evaluation/                           # Báo cáo kết quả đo lường RAG Triad và v1 vs v2
│   └── videos/                               # Video ghi hình kiểm thử tự động (Playwright E2E)
├── frontend/                      # Ứng dụng Web SOC Dashboard (React 18 + TS + Cytoscape)
│   ├── src/components/            # ChatPanel, CytoscapeGraph, EvidenceSidebar, SvgIcons
│   └── dist/                      # Bản build production tối ưu
├── outputs/                       # Dữ liệu trích xuất, Subgraph, Vector Indexes và Ground Truth
│   ├── ground_truth/              # Bộ 82 câu hỏi Ground Truth cho 3 kịch bản
│   ├── v2/                        # Candidate v2 Consumers (Corpus 22 chunks, Graph 20 nodes)
│   └── evaluation/                # File JSON kết quả benchmark định lượng
├── scripts/                       # CLI chạy pipeline, trích xuất evidence, benchmark
│   ├── query_graphrag_context.py  # Query CLI tích hợp Two-Stage Gate
│   ├── evaluate_rag_triad_benchmark.py
│   └── record_e2e_testing.py      # Kịch bản tự động kiểm thử và quay video màn hình
├── src/threat_hunting/            # Mã nguồn chính của thư viện
│   ├── evidence/                  # Module trích xuất bằng chứng cho 3 kịch bản
│   ├── graph/                     # Xây dựng và duyệt đồ thị NetworkX
│   ├── graphrag/                  # Two-Stage Gate, Seed Mapping, Context Orchestrator
│   ├── llm/                       # LLMClient (9Router/Ollama), Prompt Builder, Guardrail
│   ├── retrieval/                 # Hybrid Retrieval, BM25, E5 Vector Search
│   └── server/                    # FastAPI Backend REST API & SSE Streaming
├── tests/                         # Bộ kiểm thử tự động 715 unit tests (pass 100%)
├── run_backend.py                 # Script 1-chạm khởi chạy server
└── pyproject.toml                 # Khai báo dependency và cấu hình pytest
```

---

## VII. DANH MỤC TÀI LIỆU VÀ SẢN PHẨM BÀN GIAO

1. **Toàn văn Thuyết minh Đồ án 3 Chương:** `docs/THUYET_MINH_DO_AN_TOT_NGHIEP_KMA.md`.
2. **Cẩm nang hướng dẫn khởi chạy chi tiết:** `docs/HUONG_DAN_CHAY.md` (hoặc `HUONG_DAN_CHAY.md` ở root).
3. **Báo cáo Thực nghiệm Định lượng RAG Triad:** `docs/evaluation/rag_triad_benchmark_summary.md`.
4. **Video ghi hình kiểm thử E2E tự động:** `docs/videos/e2e_test_recording_v2_upgraded.webm`.
5. **Gói nén ZIP toàn bộ dự án:** `rag-graphrag-threat-hunting-complete.zip` (116.54 MB).

---
*Bản quyền nghiên cứu thuộc về Nguyễn Hồng Phong — Học viện Kỹ thuật Mật mã — Năm 2026.*
