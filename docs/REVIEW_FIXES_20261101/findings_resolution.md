# FINDINGS RESOLUTION — F01 đến F11

**Ngày:** 01/11/2026 · **Baseline:** `2b48d8d~1` · **Profile cuối:** `integrated-final-direct-v18`

Mỗi finding ghi: trạng thái, file sửa, bằng chứng trước/sau, test liên quan. Không dùng
`not_applicable` mà không có giải thích.

---

## Tổng hợp

| ID | Mức | Nội dung ngắn | Trạng thái |
|---|---|---|---|
| F01 | P1 | Phủ định ở mệnh đề khác che claim C2 dương tính | **fixed** |
| F02 | P1 | AUTH-CTI/GraphRAG ghi sai Status 4625 nhưng validator passed | **fixed** |
| F03 | P1 | Tham số validator đổi được kết quả nhưng không nằm trong pin | **fixed** |
| F04 | P1 | Kết luận "GraphRAG thắng 6–0" vượt bằng chứng chất lượng | **fixed** |
| F05 | P2 | Fresh query không tái lập exact context/message hash | **partially_fixed** |
| F06 | P2 | Script regression exit 1 | **fixed** |
| F07 | P2 | Tooling live không biểu diễn được kiểm giới hạn 3 cặp/6 attempts | **fixed** |
| F08 | P2 | Lockfile frontend có 3 dependency advisories | **fixed** |
| F09 | P3 | Tài liệu/manifest chưa theo checkout hiện tại | **fixed** |
| F10 | P1 | SSE legacy dùng câu trả lời dựng sẵn và verdict MALICIOUS | **fixed** |
| F11 | P2 | Test suite có contract/fixture lịch sử không tương thích | **fixed** |

`partially_fixed` cho F05 được giải thích ở mục F05: dung sai số thực đã được định nghĩa, ghi
version và có test, nhưng **chưa chứng minh được** rằng hai máy khác nhau cho cùng chữ số cuối;
điều đó phụ thuộc BLAS và không thể hứa.

---

## F10 — SSE legacy trả verdict dựng sẵn (P1)

**Trạng thái: fixed**

**Trước:** `GET /api/hunt/stream` trả `sample_analysis` và `"verdict": "MALICIOUS"` là hằng số
trong `server/app.py`; route không gọi `assess_query_scope`. Câu thời tiết nhận verdict tấn công,
trong khi `POST /api/hunt` cùng câu đó abstain.

**Sau:**
- Bỏ hoàn toàn `sample_analysis`, `MALICIOUS` và sự kiện `token`.
- Route chạy `assess_query_scope` trước, phát sự kiện `scope`, abstain ngay nếu ngoài phạm vi.
- Chạy cùng cổng hai tầng như POST.
- Sự kiện cuối: `status="proceeded_without_generation"`, `verdict=null`,
  `executive_summary=null`, `analysis_generated=false`, kèm `execution.llm_called=false`.

**File:** `src/threat_hunting/server/app.py`, `tests/test_server_sse.py`

**Bằng chứng:** `grep -rn "MALICIOUS\|sample_analysis" src/threat_hunting/server/app.py` → không
còn kết quả.

**Test:** 4 test trong `tests/test_server_sse.py`, gồm
`test_sse_never_fabricates_attack_verdict_for_out_of_scope_query` (chặn chuỗi `MALICIOUS`,
`xác nhận`, `token`) và `test_sse_and_post_agree_on_out_of_scope_query`.

---

## F01 — Phủ định che claim ở mệnh đề khác (P1)

**Trạng thái: fixed**

**Trước:** `is_negated_network_statement` dùng cửa sổ 120/80 ký tự, nên
`"Không có IP nguồn, nhưng host dùng C2 để nhận lệnh."` được phân loại **caveat** (bỏ qua), dù
mệnh đề thứ hai là claim khẳng định.

**Sau:**
- Phủ định phải nằm **trong cùng mệnh đề** với chủ đề. Mệnh đề tách theo dấu chấm, `;`, `but`,
  `however`, `nhung`, `tuy nhien`, `whereas`, và dấu phẩy **chỉ khi** phía sau là một mệnh đề độc
  lập có chủ ngữ.
- Liệt kê (`hoặc`, `hay`, `or`, `and`) **không** tách mệnh đề — để
  `"không chứng minh exfiltration, C2 hay compromise"` vẫn là caveat.
- Thêm kiểm `affirmative-use`: cụm `uses/used/sent/gửi/truyền/beacon/bị` + chủ đề là claim,
  trừ khi phía sau có boundary marker (`but`, `không`, `chưa`, `not`).
- Cửa sổ ký tự chỉ giới hạn phạm vi **trong** mệnh đề, không vượt ranh giới.

**File:** `src/threat_hunting/llm/generation_contract_v3.py`

**Bằng chứng trước/sau:**

| Câu | Trước | Sau |
|---|---|---|
| `Không có IP nguồn, nhưng host dùng C2 để nhận lệnh.` | caveat ❌ | **claim** ✅ |
| `C2 đã gửi dữ liệu ra ngoài nhưng chưa xác định tài khoản.` | caveat ❌ | **claim** ✅ |
| `The actor used HTTP but C2 was not established.` | claim ❌ | **caveat** ✅ |
| `Các quan sát không chứng minh exfiltration, C2 hay compromise.` | caveat | **caveat** ✅ |
| `Host dùng C2 để nhận lệnh.` | — | **claim** ✅ |

**Test:** `tests/test_final_direct_experiment.py`
`test_negation_in_another_clause_does_not_mask_a_positive_network_claim` (8 câu) và
`test_true_boundary_caveats_are_still_accepted` (5 câu) — tổng 18/18 probe đúng, gồm đủ 4
counterexample của review.

---

## F02 — Status/SubStatus không bind với event (P1)

**Trạng thái: fixed**

**Trước:** Report `AUTH-CTI/GraphRAG` (output thật của v8, đã lưu) viết
`"Status 0xc000006a, SubStatus 0xc000006a"`. Validator đánh `passed`, `issues` rỗng, vì chỉ kiểm
citation ID tồn tại.

**Sự thật từ dữ liệu (không phải từ kỳ vọng):**

| Event | Status | SubStatus |
|---|---|---|
| 4625 (endpoint) | `0xc000006d` | `0xc000006a` |
| 4776 (domain controller) | `0xc000006a` | **không ghi** |

**Sau:** thêm `check_auth_field_binding()`. Với mỗi câu có token `0xc…`, xác định event được
nhắc (4625 / 4776 / không nêu) rồi kiểm:
- `auth_status_event_mismatch` khi giá trị không thuộc event được nêu;
- `auth_status_views_merged` khi Status và SubStatus trùng nhau trong câu không nêu event mà
  ngữ cảnh có cả hai view (đây chính là lỗi của report v8).

Chỉ chạy khi ngữ cảnh thật sự chứa `event_id` 4625/4776, nên scenario khác không bị ảnh hưởng.

**File:** `src/threat_hunting/llm/generation_contract_v3.py`

**Bằng chứng:** report cũ **không bị ghi đè**; chấm lại nó và lưu kết quả vào
`outputs/final/20261101_direct_v10/v8_revalidation_under_v31.json`: AUTH-DIRECT/rag `passed`,
AUTH-CTI/rag `passed`, **AUTH-CTI/graphrag `failed` với `auth_status_views_merged`** — đúng như
bản chất lỗi.

**Test:** `test_saved_v8_auth_cti_graphrag_status_merge_is_rejected` (dùng chính artifact cũ làm
regression fixture), `test_correct_auth_status_report_is_not_flagged`, 3 test parametrized cho
vi phạm, 2 test cho giá trị đúng, và 1 test khẳng định không chạy khi ngữ cảnh không có
authentication event.

---

## F03 — Tham số validator không nằm trong pin (P1)

**Trạng thái: fixed**

**Trước:** đổi `VALIDATOR_NETWORK_LOOKBEHIND` từ 120 xuống 1 làm cùng một câu đổi từ caveat
sang claim, trong khi `code_sha256` và `_safe_config()` không đổi. Docstring ghi "bounded" nhưng
không có upper bound.

**Sau:**
- `effective_validator_policy()` trả policy đang có hiệu lực: `policy_id`, lookbehind/lookahead
  **sau khi clamp**, bounds, `negation_scope=clause-local`, danh sách kiểm.
- `_safe_config()` gắn `validator_policy` vào model config đã pin → hai validator behaviour khác
  nhau **không thể** dùng chung một pin.
- `_env_int` có `maximum` thật (400) và fallback khi giá trị ≤ 0 hoặc không phải số.

**File:** `src/threat_hunting/llm/generation_contract_v3.py`,
`src/threat_hunting/evaluation/experimental_comparison.py`

**Bằng chứng:**

```
lookbehind=120  -> safe_config A
lookbehind=200  -> safe_config B   (A != B  -> pin phát hiện được)
lookbehind=99999-> 400 (clamp)
lookbehind='abc'|'0'|'-5'|''  -> 120 (fallback)
```

**Test:** `test_safe_config_carries_validator_policy`,
`test_validator_parameter_change_alters_pin_safe_config`,
`test_validator_window_bounds_and_fallback` (6 case),
`test_validator_window_can_change_outcome_but_is_visible`.

---

## F04 — Kết luận vượt bằng chứng (P1)

**Trạng thái: fixed**

**Trước:** `Thuc_trang.md` viết *"GraphRAG thắng áp đảo 6–0"*, *"truy xuất quan hệ nhiều bước
trên đồ thị là cần thiết"*, mô tả RAG là *"vector baseline"*, và nói 6 câu chênh lệch *"đều là
CORRELATE, CTI, LIMIT"*.

**Sau:**
- Bỏ hoàn toàn cụm "thắng 6–0" và mọi tuyên bố ưu thế chất lượng.
- Thêm **mục 6A — Bốn tầng đo lường**: coverage / draft acceptance / nội dung-citation /
  timing, kèm bảng "con số nào KHÔNG được nói".
- Ghi đúng: 5/12 và 11/12 là **số câu vượt cổng**, chưa chấm nội dung.
- Sửa mô tả RAG: dùng `retrieve_hybrid` = BM25 + vector + RRF, corpus có cả facts/relationships.
- Sửa danh sách 6 câu chênh lệch: AUTH-CORRELATE, **PS-DIRECT**, PS-CTI, PS-LIMIT, NET-CORRELATE,
  NET-CTI — và nói rõ đây là hỗn hợp, không phải toàn câu tương quan đa bước.
- Nêu ca `AUTH-CTI/GraphRAG` như **phản ví dụ**: vượt validator ≠ đúng nội dung.
- Thêm mục giới hạn với 8 dòng, gồm "chưa có ablation" và "không phải validation độc lập".

**File:** `Thuc_trang.md`, `docs/CURRENT_STATUS.md`

**Test:** kiểm chứng bằng script đối chiếu 24 assertion với artifact thật; phát hiện và sửa một
sai số. Ghi chú trung thực: bản đầu tôi ghi "20,4 nút / 30,7 cạnh" rồi "sửa" thành 20,7, nhưng **cả hai đều không khớp artifact**. Giá trị đúng đọc từ 12 `result.json` của `integrated-final-v8-live-01` là **20,73 nút / 30,73 cạnh trên 11 nhánh không abstain** (hoặc 19,0 / 28,2 nếu tính cả 12 nhánh với abstain = 0). Đã sửa `Thuc_trang.md` và `thesis_facts.md` theo mẫu số nêu rõ.

---

## F05 — Sai số số thực và môi trường (P2) — **partially_fixed**

**Trạng thái: partially_fixed**

**Đã làm:**
- `pyproject.toml` khai báo đủ dependency trực tiếp từng thiếu: `fastapi==0.141.1`,
  `uvicorn==0.49.0`, `pydantic==2.12.5`, `httpx==0.28.1`, `python-dotenv==1.2.1`; thêm extra
  `numeric` cho `numpy`, `torch`, `transformers`, `huggingface-hub`, `scikit-learn`, `scipy`.
- `docs/REPRODUCIBILITY.md`: bảng phiên bản môi trường, embedding revision, và **policy
  `reproducibility-tolerance/v1`** (1e-6 tuyệt đối/tương đối, **chỉ** áp cho score).
- `src/threat_hunting/retrieval/reproducibility.py`: so sánh tách **exact** (hit order, chunk id,
  evidence id, gate decision, reason codes, key set, length, mọi giá trị không phải số) khỏi
  **tolerated** (chỉ score), và báo cáo từng sai lệch được dung sai thay vì âm thầm chấp nhận.
- `scripts/record_execution_environment.py` ghi `execution_environment.json`.

**Chưa làm (vì sao):** chưa chứng minh hai máy khác nhau cho cùng chữ số cuối của score. Điều
này phụ thuộc BLAS/CPU và không thể cam kết. Đã kiểm chứng policy đúng trên dữ liệu thật
(self-compare equivalent, đảo 2 hit → bị chặn).

**File:** `pyproject.toml`, `docs/REPRODUCIBILITY.md`,
`src/threat_hunting/retrieval/reproducibility.py`,
`scripts/record_execution_environment.py`

**Test:** `tests/test_reproducibility_policy.py`, 11 test, gồm
`test_the_observed_float_drift_is_tolerated_and_reported` (đúng cặp `0.87362147` vs `0.87362149`
của review) và `test_reordered_hits_are_never_tolerated`.

---

## F06 — Script regression exit 1 (P2)

**Trạng thái: fixed**

**Trước:** `scripts/verify_env_config.py` exit 1 vì v6 regression tìm thiếu
`unrequested_network_claim`. Câu bị đòi chặn là `"Mục đích C2 … không được xác minh."` — một
caveat đúng, bị validator cũ bắt oan.

**Sau:** script có 6 nhóm kiểm và exit 0 chỉ khi tất cả pass:
`(a)` matrix 9/9, `(a2)` cross-clause 6/6, `(b)` live v8 3/3, `(c)` v6 historical (duration vẫn
bị chặn, network là caveat), `(d)` auth binding 5/5, `(e)` validator policy trong pin.

Không sửa kỳ vọng cho có lợi: nhóm `(c)` **vẫn** đòi `unsupported_physical_duration_inference`
bị chặn; việc bỏ `unrequested_network_claim` được giải thích bằng nghĩa câu và bằng nhóm `(a2)`
chặt hơn (phủ định cross-clause).

**File:** `scripts/verify_env_config.py`

**Bằng chứng:** `OVERALL: PASS`, exit 0.

---

## F07 — Chế độ kiểm live có giới hạn (P2)

**Trạng thái: fixed**

**Trước:** không có đường CLI nào chạy được 3 cặp/6 attempts. `run_comparison` chặn live khi có
`final_run_policy`; `run_final` đòi cố định 16 eligible, không có selector.

**Sau:** thêm `--review-selection "CASE:branch,..."` cho runner chính, dùng chung pipeline:
- trần cứng **6 nhánh / 6 attempt**, không vượt quá số cặp khai báo;
- `recovery_attempt_limit = 0` cho subset;
- **ledger riêng** `review_request_budget.json` — không tiêu và không reset ledger của study;
- không resume, không `--continue-task`, không mượn `--execution-pin`;
- cặp phải tồn tại trong preflight đã đóng băng;
- pacing chỉ được **nâng**, không được hạ dưới giá trị đã pin;
- manifest ghi `execution_scope=review_subset` + `review_declaration` kèm `claim_scope`.

**Smoke đã chạy** (`outputs/final/20261101_direct_v12/review_smoke_declaration.json`, khai báo
**trước** khi sinh bất kỳ output): 1 câu DIRECT mỗi scenario × 2 nhánh.

| Chỉ số | Kết quả |
|---|---|
| Request dùng | **5 / 6** |
| accepted_draft | 5 |
| abstain | 1 (PS-DIRECT/rag, 0 request) |
| provider_error | 0 |
| Pacing | ~59 giây |

Chấm nội dung tách khỏi structural acceptance
(`review_smoke_scores.json`): factual correctness 5/5, citation support 5/5, trả lời đúng câu hỏi
5/5, giữ giới hạn bằng chứng 6/6.

**File:** `src/threat_hunting/evaluation/final_experiment.py`,
`scripts/run_final_experiment.py`, `tests/test_review_subset.py`

**Lỗi tìm thấy khi chạy thật (đã sửa):** `TaskBudget.remaining()` ném `KeyError: 'review'` vì
phase `review` không có bucket riêng — subset giờ tiêu từ pool `initial`, đúng ý nghĩa "một
ngân sách, hai phạm vi".

**Sửa provenance (kiểm toán viên phát hiện):** declaration được ghi vào thư mục profile **v12**
trong khi lần chạy và điểm chấm nằm ở **v13** — hai profile khác nhau, nên cặp "khai báo trước,
chấm sau" không nằm trong một hồ sơ. Đã tạo
`outputs/final/20261101_direct_v18/review_smoke_evidence.json` gộp cả ba (declaration gốc, lần
chạy, điểm chấm) kèm hash từng phần và 6 kiểm nhất quán đều PASS, gồm
`declaration_before_first_attempt` (so `declared_utc` với `started_utc` đầu tiên trong ledger).
Declaration gốc **không bị sửa hay tạo lại**.

---

## F08 — npm advisories (P2)

**Trạng thái: fixed**

**Trước:** `npm audit` → **1 high + 2 moderate**: vite (path traversal + 5 advisory
launch-editor trên Windows), esbuild (dev server cho phép origin bất kỳ đọc response),
postcss-selector-parser (quadratic complexity).

**Sau:** **0 vulnerabilities**.

| Package | Trước | Sau |
|---|---|---|
| vite | 5.4.21 | **7.3.7** |
| esbuild | 0.21.5 | **0.28.2** |
| postcss-selector-parser | 6.1.4 | **6.1.5** |

Không chạy `audit fix --force` mù quáng; nâng vite có chủ đích rồi `audit fix` cho phần còn lại.

**Ghi chú phạm vi:** cả 3 advisory liên quan **dev server và build toolchain**, không phải asset
tĩnh mà backend phục vụ. Vẫn sửa vì người review và người đóng góp chạy các tool này cục bộ.

**Kiểm lại:** `tsc && vite build` pass (40 modules, 22s); API + SSE suite pass (10 test).

---

## F09 — Tài liệu/manifest chưa theo checkout (P3)

**Trạng thái: fixed**

**Trước:** `START_HERE`, `HANDOVER`, `PROJECT_CONTEXT`, `AGENTS` chỉ dẫn v7; `Thuc_trang.md` nói
v9; config thật là v10; `verify_package.py` fail vì inventory lịch sử lệch 1.605 file.

**Sau:**
- `docs/CURRENT_STATUS.md` là **entry point duy nhất** cho trạng thái thật.
- `START_HERE.md` và `HUONG_DAN_CHAY.md` viết lại quanh profile hiện hành, có bảng xử lý sự cố
  giải thích từng thông báo guard thay vì giấu.
- `HANDOVER.md`, `PROJECT_CONTEXT.md`, `AGENTS.md` **giữ nguyên lịch sử**, thêm banner chỉ sang
  `CURRENT_STATUS` để chỉ dẫn cũ không bị đọc như hiện hành.
- `PROJECT_PROGRESS.md` **append** mục 24; byte cũ không đổi.
- `packaging/release_manifest_20261101.json` là manifest **mới** (410 file);
  `packaging/package_manifest.json` **giữ nguyên** và checksum của nó được ghi trong manifest mới.
  `verify_package.py` ưu tiên manifest mới, và **vẫn fail nếu manifest lịch sử bị sửa**.

**Bằng chứng:** `verify_package.py` → `status: passed`, `release_files_verified: 410`,
`raw_records: 29510`, `canonical_records: 29510`.

---

## F11 — Test suite có contract/fixture lịch sử (P2)

**Trạng thái: fixed**

**Trước:** `6715 passed, 8 failed, 26 errors`.

**Sau:** **`6726 passed, 29 skipped, 0 failed, 0 errors`** (3 lần chạy liên tiếp).

Ba nhóm xử lý tách bạch:

**1. Ba contract drift thật — sửa đúng, không che:**
`scenario-ground-truth/v3` là phiên bản *unresolved approval* mà integrated consumers **đang
dùng thật** (`SUPPORTED_GROUND_TRUTH_SCHEMA_VERSIONS` đã có v3), nhưng 3 test vẫn liệt kê v3 là
"unsupported". Đã bỏ v3 khỏi danh sách từ chối và **thêm test khẳng định v3 được chấp nhận** ở
cả builder lẫn schema.

**2. Hai mươi sáu setup error + 2 profile failure — fixture lịch sử:**
Pilot source contract 02, integrated v6, v7 là các run **đã đóng băng** với pin riêng; pin đó
ghi code image của ngày tạo. Thêm `tests/historical_fixtures.py` skip với lý do **nêu tên module
lệch**. Không xóa test, không nới pin. Bù lại bằng test mới cho profile hiện hành: validate v18
offline rồi boot dashboard với `client_factory` ném lỗi nếu bị gọi.

**3. Manifest v2 thiếu — skip trung thực:**

> Cảnh báo cho người đọc: `outputs/v2/manifest.json` là đường dẫn **lịch sử và không tồn tại**. Nó chỉ xuất hiện trong test như lý do skip, không phải file để mở.

`outputs/v2/manifest.json` (đường dẫn lịch sử, **không tồn tại trong repo**) và chưa từng được commit — đây là lý do test skip, không phải đường dẫn để người đọc mở. Tạo file giả sẽ là **dựng bằng chứng**, nên test skip và tự nêu đường dẫn còn thiếu trong thông báo skip. Kiểm tra corpus/index vẫn chạy trên artifact thật.

**Lỗi thật tìm thấy khi chạy lặp — và một lần sửa chưa trọn:**

Bản đầu tôi chỉ thêm retry vào **2 chỗ** (`final_experiment.snapshot`,
`experimental_recovery._snapshot`) rồi tuyên bố "0 failed". Kiểm toán viên chạy lại full suite
vẫn thấy **1 failed** ở `test_cli_overwrite_is_atomic...` với `[WinError 5] Access is denied`,
vì `scripts/build_vector_index.py` (và 13 file khác) vẫn gọi `os.replace` trần. Tôi đã sửa
**triệu chứng chứ không sửa lớp lỗi**.

Đã sửa gốc: thêm `src/threat_hunting/atomic_fs.py` với `replace_with_retry()`, thay **toàn bộ
25 call site `os.replace` trên 16 file** trong `src/` và `scripts/`. Retry chỉ áp cho mã lỗi
khoá tạm thời (WinError 5/32/33, EACCES); lỗi quyền thật nổi lên ngay sau số lần thử có giới hạn.

Thêm `tests/test_atomic_fs.py` (6 test), trong đó có
`test_no_source_file_bypasses_the_helper` quét `src/` và `scripts/` và **fail nếu có ai thêm
`os.replace` mới** — chặn tái phát đúng lớp lỗi này, không chỉ chặn một file.

**Báo cáo trung thực:** skip **không** được cộng vào passed; 29 skip đều có lý do cụ thể trong
`-rs` output.

---

## Điều chưa xác minh (nêu rõ, không giấu)

| Hạng mục | Trạng thái |
|---|---|
| Chấm ngữ nghĩa đủ 16 câu trả lời theo rubric | **Chưa làm** |
| Visual QA dashboard trên browser thật | **Chưa làm** — không có browser; đã có checklist tay |
| Live đủ 16 nhánh eligible trên profile v18 | **Chưa chạy** — mới có preflight + smoke 6 nhánh |
| Human approval ground truth | Vẫn `draft_reviewable / pending_human_review` |
| Chứng minh float score trùng khít giữa hai máy | Không cam kết được; có tolerance policy |
