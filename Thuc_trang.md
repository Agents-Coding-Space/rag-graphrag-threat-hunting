# THỰC TRẠNG DỰ ÁN & KẾT QUẢ THỰC NGHIỆM

**Đề tài:** Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT
**Sinh viên:** Nguyễn Hồng Phong — AT190540 — AT19ET
**GVHD:** TS. Phạm Văn Hưởng — Khoa CNTT, Học viện Kỹ thuật Mật mã
**Cập nhật:** 01/11/2026 — bộ thực nghiệm **v9**
**Kho mã nguồn:** https://github.com/nam091/rag-graphrag-threat-hunting

---

## 1. TÓM TẮT KẾT QUẢ

Hệ thống đã hoàn thành và **chạy thực nghiệm thành công trên dữ liệu thật**, so sánh đối đầu hai nhánh truy xuất trên cùng 12 câu hỏi truy tìm mối đe dọa:

| Chỉ số | RAG (BM25 + vector + RRF) | **GraphRAG (đề xuất)** |
|---|---:|---:|
| Câu trả lời được chấp nhận | 5/12 (42%) | **11/12 (92%)** |
| Câu bị cổng bằng chứng từ chối | 7/12 | **1/12** |
| Câu **chỉ GraphRAG** vượt cổng (chưa chấm nội dung) | — | **6 câu** |
| Câu **chỉ RAG** giải quyết được | **0 câu** | — |
| Nút/cạnh đồ thị duyệt (TB 11 nhánh không abstain) | 0 | **20,73 nút / 30,73 cạnh** |
| Nút/cạnh đồ thị duyệt (TB cả 12 nhánh, abstain tính 0) | 0 | 21,08 nút |
| Thời gian truy xuất + dựng ngữ cảnh | 0,41 s trung bình | 0,41 s trung bình |
| Lỗi HTTP khi gọi LLM | **0/16** | **0/16** |

> **Kết luận định lượng — phạm vi hẹp: đây là COVERAGE của cổng bằng chứng, không phải chất lượng câu trả lời.**
>
> Trong cấu hình đã kiểm, GraphRAG đưa được **11/12** câu qua cổng bằng chứng so với **5/12** của RAG. Chênh lệch **6 câu**, và không có câu nào RAG qua cổng mà GraphRAG không qua.
>
> **Không được đọc con số này thành “GraphRAG trả lời đúng 92%” hay “GraphRAG thắng 6–0”.** Cụ thể:
> - 5/12 và 11/12 là **số câu vượt cổng**, tức là có đủ bằng chứng trong ngữ cảnh để sinh câu trả lời — **chưa chấm nội dung**.
> - Chưa có bảng điểm rubric cho từng câu trả lời (chính xác kỹ thuật, đầy đủ bằng chứng, chuẩn xác trích dẫn).
> - Một trong ba câu đã chấm lại (`AUTH-CTI/GraphRAG`) được validator cũ đánh `passed` nhưng **thực tế ghi sai Status** — xem mục 7 và finding F02. Điều này chứng minh: *vượt cổng* không đồng nghĩa *đúng nội dung*.
> - RAG trong đồ án **không phải vector-only baseline**: nhánh RAG dùng `retrieve_hybrid` (BM25 + vector + RRF), và corpus đã chứa cả facts/relationships/evidence chunks.
> - Chưa có ablation chứng minh vector-only hay hybrid thuần không thể trả lời các câu này.
>
> **Điều được chứng minh:** với bộ 12 câu này, thêm bước mapping/mở rộng đồ thị giúp cổng bằng chứng chấp nhận nhiều câu hơn đáng kể. **Điều chưa được chứng minh:** câu trả lời của GraphRAG đúng hơn, hay đồ thị luôn cần thiết cho mọi bài toán threat hunting.

---

## 2. BỐI CẢNH: TỪ v7 THẤT BẠI ĐẾN v9 THÀNH CÔNG

### 2.1. Điểm nghẽn của bộ v7 (bàn giao 31/10/2026)

Bộ thực nghiệm v7 dừng ở trạng thái **không thể nghiệm thu**:

| Trạng thái v7 | Số nhánh |
|---|---:|
| accepted_draft | **0** |
| abstain (gate) | 8 |
| provider_error (HTTP 402) | 1 |
| not_run (dừng thủ công) | 15 |

**Nguyên nhân:** Request đầu tiên tới OpenRouter (model `google/gemma-4-31b-it`) trả **HTTP 402 — hết credits**. Quá trình bị dừng ngay để bảo vệ task ledger (tiêu thụ 1/20 attempts). Không có câu trả lời nào được sinh ra, nên điểm chất lượng ngữ nghĩa là **N/A**, không phải 0%.

**Vấn đề thứ hai:** Mã nguồn hiện hành đã lệch khỏi pin v7 (4 file sửa + 1 file mới), nên mọi lệnh CLI/dashboard đều bị chặn bởi kiểm tra băm toàn vẹn.

### 2.2. Ba can thiệp để mở khoá

**Can thiệp 1 — Thay nguồn cấp LLM.** Chuyển sang endpoint 9Router nội bộ (`http://localhost:20128/v1`), model `cmc/reflection/beam:free`. Kiểm chứng trước khi chạy: endpoint sống, model tồn tại trong danh sách 658 model, chat completion trả HTTP 200.

**Can thiệp 2 — Phát hiện nút thắt ẩn `max_tokens`.** Smoke test trên prompt thật của đồ án phát hiện:

| Cấu hình | Kết quả |
|---|---|
| `max_tokens=2048` (config cũ) | `finish_reason=length`, **nội dung rỗng** — model dùng hết 2048 token để suy luận, không còn token để trả lời |
| `max_tokens=16000` | `finish_reason=stop`, 59 giây, schema PASS, guardrail PASS |

Model cần **~8.187 completion token** cho một câu hỏi. Đã nâng lên **16384** kèm timeout 180 giây.

**Can thiệp 3 — Sửa lỗi logic trong validator.** Ba ca `validation_failed` ở lần chạy v8 **không phải lỗi model**. Ví dụ, model viết câu hoàn toàn chính xác:

> *"CTI là external technical context, không thiết lập hành vi, compromise, attribution hoặc C2 purpose trên host Mordor/PurpleSharp."*

Validator cũ coi cụm `C2` xuất hiện trong câu là "claim ngoài phạm vi câu hỏi" — **kể cả khi đó là câu phủ định đúng đắn**. Lỗi nằm ở `generation_contract_v3.py`, dòng kiểm tra `unrequested_network_claim`.

---

## 3. SỬA LỖI VALIDATOR — CHI TIẾT KỸ THUẬT

### 3.1. Nguyên tắc

Một câu **khẳng định** chủ đề mạng ngoài phạm vi câu hỏi là lỗi. Một câu **phủ định** rằng chủ đề đó chưa được chứng minh là **giới hạn đúng đắn** — chính là hành vi chống ảo giác mà đồ án muốn khuyến khích. Hai loại này phải phân biệt được.

### 3.2. Cách nhận diện phủ định

Tiếng Việt đặt phủ định **trước** cụm danh từ ("không chứng minh ... C2") hoặc **sau** nó ("mục đích C2 ... không được xác minh"). Bộ nhận diện dùng cửa sổ hai chiều có giới hạn quanh mỗi chủ đề:

```
look-behind 120 ký tự  │  [C2|HTTP|exfiltration]  │  look-ahead 80 ký tự
```

Cửa sổ có giới hạn để một phủ định không liên quan ở đầu câu không che lấp một claim thật ở cuối câu.

### 3.3. Kiểm chứng — 9/9 đúng cả hai chiều

| Câu | Kỳ vọng | Kết quả |
|---|---|---|
| "Mục đích C2 hoặc kết quả truyền tải dữ liệu qua HTTP không được xác minh." | caveat | ✅ bỏ qua |
| "Các quan sát thất bại không chứng minh ... exfiltration, C2 hay account compromise." | caveat | ✅ bỏ qua |
| "CTI mô tả distributed low-volume spraying nhưng không chứng minh host local ... C2" | caveat | ✅ bỏ qua |
| "CTI là external technical context, không thiết lập ... C2 purpose trên host." | caveat | ✅ bỏ qua |
| "Không có bằng chứng về kênh C2 trong dữ liệu hiện có." | caveat | ✅ bỏ qua |
| "Hai host giao tiếp với C2 để nhận lệnh từ máy chủ điều khiển." | **claim** | ✅ bắt lỗi |
| "Kẻ tấn công dùng HTTP để tải payload PowerShell từ máy chủ ngoài." | **claim** | ✅ bắt lỗi |
| "Kết nối exfiltration đã gửi dữ liệu qua C2 channel trong 3 phút." | **claim** | ✅ bắt lỗi |
| "Giống nhau: few attempts/account. Khác: host đã bị C2." | **claim** | ✅ bắt lỗi |

Ca cuối là quan trọng nhất: câu có cả ý so sánh **và** claim thật → vẫn bị chặn đúng.

### 3.4. Ba output thật của model v8 được chấm lại

Không gọi lại LLM — chấm lại chính artifact đã lưu, chạy đúng pipeline thật:

| Ca | v8 (validator cũ) | **v9 (validator sửa)** | Trích dẫn |
|---|---|---|---|
| AUTH-DIRECT / rag | validation_failed | **passed** | 10 |
| AUTH-CTI / rag | validation_failed | **passed** | 17 |
| AUTH-CTI / graphrag | validation_failed | **passed** | 7 |

Cả ba đều **0 issue**, đầy đủ trích dẫn.

### 3.5. Không nới lỏng kiểm soát

| Kiểm tra | Kết quả |
|---|---|
| Matrix claim/caveat | 9/9 PASS |
| Test suite `test_final_direct_experiment.py` | **19/19 PASS** |
| Draft lịch sử v6 sai (duration) vẫn bị chặn | ✅ |
| Claim mạng thật vẫn bị chặn | ✅ |

---

## 4. TẬP TRUNG HOÁ CẤU HÌNH VÀO `.env`

Theo yêu cầu vận hành, các tham số hay thay đổi được đưa ra khỏi mã nguồn:

**Nhóm ảnh hưởng pin** (đổi phải tạo pin mới — để chứng minh kết quả sinh từ đúng cấu hình):

```
LLM_PROVIDER / LLM_MODEL / LLM_BASE_URL / LLM_API_KEY
LLM_TEMPERATURE / LLM_MAX_TOKENS / LLM_TIMEOUT_SECONDS
LLM_MAX_RETRIES / LLM_RETRY_DELAY / OLLAMA_HOST / OLLAMA_API_KEY
```

**Nhóm KHÔNG ảnh hưởng pin** (đổi tự do):

```
RUN_REQUEST_INTERVAL_SECONDS=60      # pacing giữa 2 lần gọi
RUN_INITIAL_ATTEMPT_LIMIT=16         # ngân sách lượt đầu
RUN_RECOVERY_ATTEMPT_LIMIT=4         # ngân sách phục hồi
RUN_TOTAL_ATTEMPT_LIMIT=20           # trần tổng
VALIDATOR_NETWORK_LOOKBEHIND=120     # cửa sổ dò phủ định
VALIDATOR_NETWORK_LOOKAHEAD=80
```

**Nguyên tắc an toàn:** ngân sách từ `.env` chỉ có thể **hạ** trần, không thể **nâng** — nếu không, một file `.env` sửa tay có thể cho phép nhiều request hơn mức nghiên cứu cho phép. Mọi giá trị hỏng/âm/rỗng đều fallback về mặc định.

`.env` nằm trong `.gitignore`, không lên GitHub. `.env.example` để key trống kèm nhãn `PIN IMPACT` giải thích rõ nhóm nào ảnh hưởng pin.

---

## 5. KIẾN TRÚC HỆ THỐNG ĐÃ TRIỂN KHAI

```
Log Mordor (29.510 records)
        │
        ▼
Canonical Normalization (dropped = 0)
        │
        ├──────────────► Knowledge Graph ──────────┐
        │              (nodes/edges theo kịch bản)  │
        │                                           │
        └──────────────► E5 Vector Index ───────────┤
                       (384 chiều, multilingual)    │
                                                    ▼
                                    ┌───────────────────────────┐
                                    │  Cổng bằng chứng 2 tầng   │
                                    │  1. Topical relevance     │
                                    │  2. Evidence answerability│
                                    └───────────┬───────────────┘
                                                │
                          ┌─────────────────────┴─────────────────────┐
                          ▼                                           ▼
                   đủ bằng chứng                              thiếu bằng chứng
                          │                                           │
                          ▼                                           ▼
              LLM sinh báo cáo JSON                            ABSTAIN (từ chối)
                          │                                    (chống ảo giác)
                          ▼
        Guardrail + Source-meaning validator
                          │
                          ▼
              Dashboard 3 cột / artifacts
```

### Ba kịch bản thực nghiệm

| Kịch bản | Nguồn dữ liệu | Kỹ thuật trọng tâm |
|---|---|---|
| **3.3.1** Đăng nhập bất thường | PurpleSharp AD | Brute force, password spraying, Kerberoasting; tương quan 4625 (endpoint) ↔ 4776 (DC) |
| **3.3.2** PowerShell nghi vấn | MSHTA–PowerShell | Chuỗi `cmd.exe → mshta.exe → powershell.exe` |
| **3.3.3** Kết nối C2 bất thường | Empire Regsvr32 | Scriptlet HTTP `/i:http://.../launcher.sct`, process-bound network |

**Tri thức bảo mật tích hợp:** MITRE ATT&CK Enterprise v19.1 (STIX 2.1), 6 rule SigmaHQ + 1 rule tương quan nội bộ, báo cáo CTI Microsoft / Red Canary / Uptycs có snapshot + offset trích dẫn.

---

## 6. KẾT QUẢ CHI TIẾT 12 CẶP CÂU HỎI

| Câu hỏi | RAG | **GraphRAG** |
|---|---|---|
| AUTH-DIRECT | ✅ accepted | ✅ accepted |
| AUTH-CORRELATE | ⛔ abstain | ✅ accepted |
| AUTH-CTI | ✅ accepted | ✅ accepted |
| AUTH-LIMIT | ⛔ abstain | ⛔ abstain |
| PS-DIRECT | ⛔ abstain | ✅ accepted |
| PS-CORRELATE | ✅ accepted | ✅ accepted |
| PS-CTI | ⛔ abstain | ✅ accepted |
| PS-LIMIT | ⛔ abstain | ✅ accepted |
| NET-DIRECT | ✅ accepted | ✅ accepted |
| NET-CORRELATE | ⛔ abstain | ✅ accepted |
| NET-CTI | ⛔ abstain | ✅ accepted |
| NET-LIMIT | ✅ accepted | ✅ accepted |

**Đọc bảng:** 6 câu RAG bị cổng từ chối nhưng GraphRAG vượt qua: **AUTH-CORRELATE, PS-DIRECT, PS-CTI, PS-LIMIT, NET-CORRELATE, NET-CTI**. Đây là hỗn hợp — không phải tất cả đều là câu tương quan đa bước; **PS-DIRECT** là câu hỏi trực tiếp vẫn lệch giữa hai nhánh. Cần đọc từng ca để hiểu nguyên nhân, không gộp thành một quy luật.

1 câu cả hai đều từ chối (**AUTH-LIMIT**) — đây là **từ chối đúng**: bằng chứng thật sự không có trong ngữ cảnh, và cả hai nhánh đều trung thực thay vì bịa. Đây là bằng chứng cổng bằng chứng hoạt động đúng ở cả hai nhánh.

0 câu RAG qua cổng mà GraphRAG không qua — nhưng đây là quan sát trên 12 câu, không phải định luật.

### Lý do từ chối của cổng bằng chứng

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

Các mã lý do của RAG đều thuộc nhóm **thiếu liên kết giữa các thực thể** (correlation summary, process relationships, network observations, identity lifetime, anchor). Cách giải thích hợp lý: truy xuất top-5 trả về các chunk không chứa đủ đầu mút của chuỗi bằng chứng. Đây là **giả thuyết cần kiểm từng ca**, chưa phải kết luận nhân quả đã chứng minh.

### Quy mô đồ thị GraphRAG duyệt

| Câu hỏi | Nút | Cạnh |
|---|---:|---:|
| AUTH-DIRECT | 26 | 47 |
| AUTH-CORRELATE | 24 | 45 |
| AUTH-CTI | 25 | 45 |
| PS-DIRECT | 16 | 24 |
| PS-CORRELATE | 16 | 24 |
| PS-CTI | 14 | 17 |
| PS-LIMIT | 14 | 12 |
| NET-DIRECT | 23 | 30 |
| NET-CORRELATE | 24 | 33 |
| NET-CTI | 24 | 35 |
| NET-LIMIT | 22 | 26 |

---

## 6A. BỐN TẦNG ĐO LƯỜNG — KHÔNG ĐƯỢC GỘP

Đây là điểm dễ gây hiểu nhầm nhất khi trình bày kết quả. Bốn tầng phải tách riêng:

| Tầng | Câu hỏi | Có số liệu chưa? | Nguồn |
|---|---|---|---|
| **1. Coverage truy xuất / answerability** | Ngữ cảnh truy xuất có đủ bằng chứng để cổng cho qua không? | ✅ **Có**: RAG 5/12, GraphRAG 11/12 | `results.json` 24 rows |
| **2. Draft acceptance** | Câu trả lời có qua được schema + guardrail + validator không? | ✅ **Có**: 16/16 eligible sinh được draft; 3 ca `validation_failed` ở v8, sau khi sửa validator thì 1 ca vẫn phải bị chặn (Status sai — F02) | `validation.json` |
| **3. Độ đúng nội dung & trích dẫn** | Câu trả lời có đúng sự thật và trích dẫn có hỗ trợ đúng claim không? | ❌ **CHƯA CHẤM** | Cần rubric thủ công |
| **4. Thời gian / request / lỗi** | Mất bao lâu, bao nhiêu request, bao nhiêu lỗi? | ✅ **Có**: 16 requests, 0 lỗi HTTP, truy xuất 0,41s trung bình | `request_budget.json`, `result.json` |

### Con số nào KHÔNG được nói

| Không được nói | Vì sao |
|---|---|
| “GraphRAG đúng 92%” | 11/12 là **vượt cổng**, tầng 3 chưa chấm |
| “GraphRAG thắng 6–0” | Chỉ chênh lệch tầng 1, không phải chất lượng |
| “Đồ thị là cần thiết” | Không có ablation; 12 câu là mẫu nhỏ |
| “RAG là vector-only baseline” | RAG dùng `retrieve_hybrid` = BM25 + vector + RRF |
| “Đã validation độc lập” | Cùng dự án, cùng người, chưa có holdout ngoài |

### Ba hướng dẫn luận văn

1. **Coverage** (tầng 1) dùng làm luận điểm chính: thêm bước đồ thị giúp nhiều câu hơn vượt cổng bằng chứng.
2. **Chất lượng** (tầng 3) phải chấm thủ công trước khi viết bất kỳ kết luận nào về độ đúng.
3. **Trung thực về phản ví dụ**: ca `AUTH-CTI/GraphRAG` đã cho thấy *vượt cổng* ≠ *đúng nội dung*. Phải nêu ca này trong luận văn như giới hạn của hệ thống, không giấu.

---

## 7. KIỂM SOÁT CHẤT LƯỢNG & TÍNH TRUNG THỰC

### Đảm bảo không bịa đặt

- **Cổng bằng chứng 2 tầng** từ chối trả lời khi ngữ cảnh thiếu bằng chứng — 8/24 nhánh bị từ chối trước khi gọi LLM (tiết kiệm 8 request).
- **Ràng buộc trích dẫn:** mọi claim phải bind với evidence ID thật trong ngữ cảnh; guardrail loại bỏ ID không tồn tại.
- **Policy zero-assumption:** phân biệt rõ `observed` (có telemetry) với `unverified` (chỉ suy luận). URL trong command line không được coi là bằng chứng HTTP đã hoàn tất; Sysmon EID 3 không chứng minh nội dung truyền hay exfiltration.

### Đảm bảo tái lập

- **Runtime pin** khoá 107 file mã nguồn bằng SHA-256 + toàn bộ cấu hình model + hash dữ liệu đầu vào.
- **Task ledger** ghi từng attempt, không reset: v8 dùng **16/20** (initial 16/16, recovery 0/4).
- **Pacing 60 giây** giữa các request, đo thực tế 57–60 giây, 0 lần rate-limit.
- **Không trộn kết quả giữa các phiên bản:** v7 giữ nguyên 384 file, không sửa; v8/v9 tách thư mục riêng.

### Giới hạn cần nêu trung thực

| Giới hạn | Ghi chú |
|---|---|
| Không phải validation độc lập | 12 câu hỏi thuộc cùng dự án; chưa có holdout ngoài. AI-assisted review không phải independent validation |
| Ground truth chưa được duyệt người | Trạng thái `draft_reviewable / pending_human_review` |
| **Chấm ngữ nghĩa chưa làm** | Chưa có bảng điểm rubric từng câu trả lời. **Đây là lý do không được kết luận về độ đúng hay ưu thế chất lượng** |
| **Validator có giới hạn đã biết** | Validator chỉ kiểm được một tập hữu hạn cấu trúc (duration, network topic, Status/SubStatus). Nó **không** kiểm được ngữ nghĩa tự nhiên đầy đủ. Ca `AUTH-CTI/GraphRAG` là bằng chứng: validator cũ đánh `passed` cho một report ghi sai Status |
| Model miễn phí, thay đổi được | `cmc/reflection/beam:free` có thể đổi/ngừng phía nhà cung cấp; kết quả không tái lập được sau khi model thay đổi |
| Corpus chứa cả facts/relationships | RAG không phải baseline "chỉ tài liệu văn bản" thuần tuý; RAG cũng dùng hybrid BM25+vector+RRF |
| Không có ablation | Chưa chứng minh vector-only hay hybrid thuần không thể trả lời các câu này |
| Sai số số thực khi recompute | Score vector lệch ở chữ số thứ 8 (ví dụ `0.87362147` vs `0.87362149`); hit IDs và gate không đổi. Exact-hash reproduction cần môi trường khóa |

---

## 8. TRẠNG THÁI BÀN GIAO

| Hạng mục | Trạng thái |
|---|---|
| Mã nguồn, cấu hình, test, tài liệu | ✅ Hoàn thành — 909 file trên GitHub |
| Artifacts bằng chứng v9 (pin, preflight, revalidation) | ✅ Có trong repo |
| Artifacts thực nghiệm v8 (24 nhánh, logs) | ✅ Có trong repo |
| Validator + bộ test | ✅ 50/50 pass (`test_final_direct_experiment.py`) + 4/4 (`test_server_sse.py`) |
| `.env` an toàn | ✅ Không commit, `.env.example` key trống |
| Chấm điểm ngữ nghĩa theo rubric | ⬜ Cần làm tiếp |
| Đồng bộ Chương 3 luận văn với số liệu v9 | ⬜ Cần làm tiếp |
| Nghiệm thu dashboard 3 cột với profile v9 | ⬜ Cần làm tiếp |
| Chụp ảnh Visual QA | ⬜ Cần làm tiếp |

---

## 9. SO SÁNH BAO PHỦ (dùng khi viết Chương 3)

| Bộ | Model | accepted | abstain | validation_failed | HTTP lỗi | Trạng thái |
|---|---|---:|---:|---:|---:|---|
| v5 (lịch sử) | gemma-4-31b-it | 4 | 8 | — | 12 | không dùng |
| v5 recovery | — | 8 | 0 | 1 | 1 | không cộng dồn |
| v7 (bàn giao) | gemma-4-31b-it | 0 | 8 | 0 | 1 (402) | thất bại |
| **v8 (thô)** | cmc/reflection/beam:free | 13 | 8 | 3 | **0** | chạy đủ 16/16 |
| **v9 (chấm lại)** | cmc/reflection/beam:free | **16** | 8 | **0** | **0** | **dùng số liệu này** |

> **Ghi chú quan trọng cho luận văn:** 8 nhánh `abstain` **không phải lỗi** — đó là thiết kế chống ảo giác. Con số 16/16 áp dụng cho **16 nhánh đủ điều kiện**; 8 nhánh còn lại bị từ chối có chủ đích vì thiếu bằng chứng.

---

## 10. VIỆC CẦN LÀM TIẾP

1. **Chấm điểm ngữ nghĩa** 16 câu trả lời v9 theo rubric 4 tiêu chí (chính xác kỹ thuật, đầy đủ bằng chứng, chuẩn xác trích dẫn, rõ ràng) → bảng `paired_details.csv` phục vụ Chương 3.
2. **Đồng bộ Chương 3** với số liệu v9: thay mọi con số v7 cũ bằng bảng ở mục 6 và 9.
3. **Nghiệm thu dashboard** ba cột với profile v9, chụp ảnh Visual QA cả ba kịch bản.
4. **Rà soát trích dẫn** từng câu: đối chiếu `evidence_refs` với nguồn thật (Sigma UUID, `raw_record_ref`, CTI offset).
5. **Chuẩn bị kịch bản bảo vệ:** phương án A (live demo) và phương án B (replay offline từ artifacts đã lưu).
