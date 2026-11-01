# THESIS FACTS — số liệu đã kiểm chứng để viết luận văn

**Ngày:** 01/11/2026 · **Profile:** `integrated-final-direct-v18`

Mọi con số dưới đây đọc trực tiếp từ artifact và có đường dẫn nguồn. **Không** dùng số liệu
trong tài liệu lịch sử (HANDOVER v7, `docs/EXPERIMENTAL_RESULTS.md` cũ) vì chúng thuộc bản đã
thất bại.

> **Quy tắc bắt buộc khi viết:** tách bốn tầng. Không viết "GraphRAG đúng 92%" hay "GraphRAG
> thắng 6–0". 11/12 là **số câu vượt cổng bằng chứng**, chưa chấm nội dung.

---

## 1. Kiến trúc thực tế

### Luồng xử lý

```
raw Mordor JSONL
      │  canonical normalization (dropped = 0)
      ▼
canonical events  ──┬──► knowledge graph (JSON nodes/edges)
                    └──► retrieval corpus + E5 vector index (384 chiều)
                              │
                              ▼
                    truy xuất lai: BM25 + cosine, hợp nhất RRF
                              │
                    ┌─────────┴──────────┐
                    ▼                    ▼
                   RAG              GraphRAG
              (chỉ chunk trả về)  (thêm seed mapping + duyệt đồ thị
                                   both, depth 2, ≤100 nút, ≤200 cạnh)
                    └─────────┬──────────┘
                              ▼
                  cổng bằng chứng hai tầng
                  1. topical relevance
                  2. evidence answerability   ──► abstain (dừng, 0 request)
                              │ proceed
                              ▼
                    LLM sinh báo cáo JSON
                              │
                              ▼
                  guardrail + validator (v3.1)
                              │
                              ▼
              accepted_draft / validation_failed
                              │
                              ▼
                    dashboard ba cột / artifact
```

### Stack

| Thành phần | Giá trị thực tế |
|---|---|
| Python | 3.14.0 (hỗ trợ ≥3.11) |
| Embedding | `intfloat/multilingual-e5-small`, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, 384 chiều, cosine, prefix `query: ` / `passage: ` |
| Frontend | React 18 + TypeScript + Vite 7.3.7 + Cytoscape |
| Backend | FastAPI 0.141.1 + uvicorn 0.49.0 |
| LLM | `cmc/reflection/beam:free` qua gateway OpenAI-compatible, temperature 0, max_tokens 16384 |
| Vector DB | **Không dùng** — index là file JSON |

---

## 2. Ba kịch bản (phạm vi đề tài)

| Mã | Kịch bản | Nguồn Mordor | Raw records | Corpus chunks | Graph nút/cạnh |
|---|---|---|---:|---:|---:|
| 3.3.1 | Brute force và đăng nhập bất thường (PurpleSharp AD) | `purplesharp_ad_playbook_I_2020-10-22042947` | 25.993 | 43 | 37 / 52 |
| 3.3.2 | Thực thi PowerShell nghi vấn (MSHTA) | `cmd_mshta_vbscript_execute_psh_2020-10-2202580804` | 1.127 | 25 | 24 / 24 |
| 3.3.3 | Kết nối mạng bất thường / nghi vấn C2 (Regsvr32) | `empire_launcher_sct_regsvr32_2020_07_21232741` | 2.390 | 33 | 29 / 39 |
| | **Tổng** | | **29.510** | 101 | 90 / 115 |

Nguồn: `outputs/canonical/mordor-selected-v2/manifest.json`,
`outputs/integrated/20261030_v5/consumers/<scenario>/`.

Canonical: **29.510 records, dropped = 0** (kiểm bằng `verify_package.py`).

### Tri thức bảo mật

| Nguồn | Chi tiết |
|---|---|
| MITRE ATT&CK | Enterprise v19.1, STIX 2.1, commit và bundle hash đã khóa |
| Sigma | 6 rule SigmaHQ ngoài + 1 rule tương quan nội bộ `win_security_password_spray_correlation.yml` |
| CTI | 3 nguồn (Microsoft CovertNetwork-1658, Red Canary, Uptycs) có HTML snapshot, text, offset trích dẫn |
| Provenance | 21 entry, 12 consumer lịch sử + 12 portable, 3 CTI snapshot — `verify_package.py` xác nhận |

---

## 3. Kết quả đo được

### 3.1 Tầng 1 — Coverage của cổng bằng chứng

Profile `integrated-final-direct-v8` (live, 16 request):

| Nhánh | Vượt cổng | Abstain | Tổng |
|---|---:|---:|---:|
| RAG (BM25 + vector + RRF) | **5** | 7 | 12 |
| GraphRAG (+ đồ thị) | **11** | 1 | 12 |

Map đối chiếu 12 cặp:

| Câu | RAG | GraphRAG |
|---|---|---|
| AUTH-DIRECT | proceed | proceed |
| AUTH-CORRELATE | abstain | proceed |
| AUTH-CTI | proceed | proceed |
| AUTH-LIMIT | abstain | abstain |
| PS-DIRECT | abstain | proceed |
| PS-CORRELATE | proceed | proceed |
| PS-CTI | abstain | proceed |
| PS-LIMIT | abstain | proceed |
| NET-DIRECT | proceed | proceed |
| NET-CORRELATE | abstain | proceed |
| NET-CTI | abstain | proceed |
| NET-LIMIT | proceed | proceed |

**Sáu câu chỉ GraphRAG vượt cổng:** AUTH-CORRELATE, **PS-DIRECT**, PS-CTI, PS-LIMIT,
NET-CORRELATE, NET-CTI. Đây là **hỗn hợp**, không phải toàn câu tương quan đa bước — phải nói
đúng như vậy.

**Một câu cả hai cùng abstain:** AUTH-LIMIT — đây là **từ chối đúng** (bằng chứng thật sự không
có trong ngữ cảnh). Dùng làm bằng chứng cổng hoạt động đúng ở cả hai nhánh.

**Không câu nào RAG vượt mà GraphRAG không** — nhưng đây là quan sát trên 12 câu, không phải
định luật.

### Quy mô đồ thị GraphRAG (đọc từ artifact, ghi rõ mẫu số)

| Cách tính | Nút TB | Cạnh TB |
|---|---:|---:|
| 11 nhánh không abstain | **20,73** | **30,73** |
| Cả 12 nhánh (abstain tính 0) | 21,08 | — |

Nguồn: `result.json` từng nhánh trong `outputs/experiments/integrated-final-v8-live-01/`.
**Phải ghi mẫu số** khi trích con số này; 20,73 không áp dụng cho cả 12 nhánh.

Nguồn: `outputs/experiments/integrated-final-v8-live-01/results.json`

### 3.2 Lý do cổng từ chối

| Nhánh | Mã lý do | Số lần |
|---|---|---:|
| RAG | `authentication_correlation_summary_missing` | 1 |
| RAG | `two_process_relationships_missing` | 1 |
| RAG | `process_network_observations_missing` | 1 |
| RAG | `network_identity_lifetime_summary_missing` | 1 |
| RAG | `local_telemetry_anchor_missing` | 1 |
| RAG | `relevant_observed_anchor_not_returned` | 1 |
| RAG | `actor_bound_command_fields_not_returned` | 1 |
| GraphRAG | `logon_temporal_context_missing` | 1 |
| GraphRAG | `authentication_account_outcome_fields_missing` | 1 |

Nhóm lý do của RAG đều thuộc **thiếu liên kết giữa thực thể**. Đây là **giả thuyết hợp lý**, cần
kiểm từng ca; chưa phải kết luận nhân quả đã chứng minh.

### 3.3 Tầng 2 — Draft acceptance

| Bộ | Model | Request | accepted_draft | validation_failed | abstain | provider_error |
|---|---|---:|---:|---:|---:|---:|
| v7 (31/10) | gemma-4-31b-it | 1 | **0** | 0 | 8 | 1 (HTTP 402) |
| v8 | cmc/reflection/beam:free | 16 | 13 | 3 | 8 | **0** |
| v9 (chấm lại 3 ca v8 bằng validator sửa) | — | 0 | +2 | **1 còn bị chặn** | — | — |
| Smoke v13 (6 nhánh) | cmc/reflection/beam:free | 5 | 5 | 0 | 1 | 0 |

Nguồn: `outputs/experiments/integrated-final-v8-live-01/results.json`,
`outputs/final/20261101_direct_v10/v8_revalidation_under_v31.json`,
`outputs/final/20261101_direct_v13/review_smoke_scores.json`

> **Cảnh báo cho người viết:** con số 13 accepted ở v8 là **trước khi sửa validator**. Ba ca
> `validation_failed` được chấm lại: 2 ca pass, **1 ca vẫn phải bị chặn** vì ghi sai Status
> 4625. Vì vậy con số "13 accepted" **không** phải 13 câu đúng.

### 3.4 Tầng 3 — Nội dung và trích dẫn

**Chấm được (smoke 6 nhánh):**

| Tiêu chí | Kết quả |
|---|---|
| Factual correctness | 5/5 |
| Citation support | 5/5 |
| Trả lời đúng câu hỏi | 5/5 |
| Giữ giới hạn bằng chứng | 6/6 |

**Chưa chấm:** 16 câu trả lời của bộ v8. Đây là lý do **không được** viết kết luận về chất lượng
hay về ưu thế RAG/GraphRAG.

### 3.5 Tầng 4 — Thời gian và lỗi

| Chỉ số | Giá trị |
|---|---|
| Truy xuất + dựng ngữ cảnh (24 nhánh) | trung bình **0,41s**, max 0,89s |
| Request LLM đã dùng (v8) | 16 |
| Lỗi HTTP | **0** |
| Pacing thực tế | 57–60 giây/request |
| Ngữ cảnh mỗi nhánh | 17–256 KB |
| Message mỗi nhánh | 28–281 KB |

Nguồn: `result.json` từng nhánh, `request_budget.json`.

---

## 4. Phân biệt ba khái niệm (bắt buộc khi viết)

| Khái niệm | Định nghĩa | Số liệu |
|---|---|---|
| **Coverage** | Ngữ cảnh truy xuất có đủ bằng chứng để cổng cho qua | RAG 5/12, GraphRAG 11/12 |
| **Acceptance** | Câu trả lời qua schema + guardrail + validator | 16/16 eligible sinh draft; 13 accepted ở v8 (trước sửa validator) |
| **Semantic correctness** | Câu trả lời đúng sự thật, trích dẫn hỗ trợ đúng claim | **Chưa chấm** — chỉ smoke 6 nhánh |

---

## 5. Phát hiện có giá trị học thuật (nên đưa vào luận văn)

1. **`max_tokens` là nút thắt ẩn.** Cùng một prompt, `max_tokens=2048` cho `finish_reason=length`
   và **nội dung rỗng**; `16384` cho kết quả đầy đủ. Model cần ~8.187 completion token cho một
   câu hỏi threat hunting có ngữ cảnh lớn.

2. **Vượt validator ≠ đúng nội dung.** Report `AUTH-CTI/GraphRAG` được validator đánh `passed`
   nhưng ghi sai Status 4625 (`0xc000006a` thay vì `0xc000006d`). Đây là phản ví dụ mạnh nhất và
   **phải** được nêu như giới hạn của hệ thống, không được giấu.

3. **Phủ định cần ranh giới mệnh đề, không phải cửa sổ ký tự.** Câu
   `"Không có IP nguồn, nhưng host dùng C2"` bị phân loại sai là caveat khi dùng cửa sổ 120 ký
   tự. Sửa bằng clause-local + affirmative-use.

4. **Đánh giá hai tầng: coverage rồi mới tới chất lượng.** Nếu chỉ báo "11/12 vs 5/12" mà không
   chấm nội dung thì đó là kết luận vượt bằng chứng — chính lỗi mà review đã chỉ ra.

---

## 6. Điều **không được** viết

| Không viết | Vì sao |
|---|---|
| "GraphRAG đúng 92%" | 11/12 là vượt cổng, tầng 3 chưa chấm |
| "GraphRAG thắng 6–0" | Chỉ là chênh lệch coverage, không phải chất lượng |
| "Đồ thị tri thức là cần thiết" | Không có ablation chứng minh |
| "RAG là vector-only baseline" | RAG dùng `retrieve_hybrid` = BM25 + vector + RRF |
| "Đã validation độc lập" | 12 câu cùng dự án, chưa có holdout ngoài |
| "Hệ thống đã nghiệm thu hoàn chỉnh" | Ground truth vẫn `pending_human_review`, chưa chấm ngữ nghĩa |
| "Độ chính xác 100%" | Không có cơ sở |

---

## 7. Đường dẫn artifact để trích dẫn

| Nội dung | File |
|---|---|
| Coverage 12 cặp | `outputs/experiments/integrated-final-v8-live-01/results.json` |
| Bảng lý do từ chối | `outputs/experiments/integrated-final-v8-live-01/<case>_<branch>/gate.json` |
| Chấm lại 3 ca v8 | `outputs/final/20261101_direct_v10/v8_revalidation_under_v31.json` |
| Smoke 6 nhánh — khai báo trước | `outputs/final/20261101_direct_v12/review_smoke_declaration.json` |
| Smoke 6 nhánh — điểm | `outputs/final/20261101_direct_v13/review_smoke_scores.json` |
| Preflight 24 nhánh | `outputs/final/20261101_direct_v18/preflight/results.json` |
| Pin (107 file + policy) | `outputs/final/20261101_direct_v18/runtime_pin.json` |
| Môi trường | `outputs/final/integrated-final-direct-v13/execution_environment.json` |
| Dashboard QA | `outputs/final/20261101_direct_v18/dashboard_qa.json` |
| Kiểm gói | chạy `verify_package.py` |
