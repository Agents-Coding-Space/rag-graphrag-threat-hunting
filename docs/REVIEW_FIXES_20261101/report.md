# REPORT — Sửa lỗi theo review độc lập

**Ngày:** 01/11/2026, Asia/Bangkok
**Phạm vi:** sửa 11 finding F01–F11 trong `review/`, kiểm thử, bàn giao.
**Profile cuối:** `integrated-final-direct-v17`
**Commit:** xem `changed_files.json` → `commits`

---

## 1. Kết quả chính

| Hạng mục | Trước | Sau |
|---|---|---|
| Full test suite | 6715 passed / 8 failed / 26 errors | **6720 passed / 29 skipped / 0 failed / 0 errors** |
| npm advisories | 1 high + 2 moderate | **0** |
| `verify_env_config.py` | exit 1 | **exit 0** (6 nhóm PASS) |
| `verify_package.py` | fail (inventory lịch sử lệch 1.605 file) | **passed** (release manifest 410 file, 29.510 canonical) |
| SSE câu ngoài phạm vi | verdict `MALICIOUS` dựng sẵn | **abstain, 0 LLM, verdict null** |
| Phủ định cross-clause | bị che (18 probe: 12/18) | **18/18 đúng** |
| Status 4625 sai | validator `passed` | **bị chặn** (`auth_status_views_merged`) |
| Tham số validator | ngoài pin | **trong pin**, clamp 400, fallback |
| Kết luận "thắng 6–0" | có | **đã bỏ**, thay bằng 4 tầng đo lường |

11/11 finding đã xử lý. Chi tiết từng finding: [findings_resolution.md](findings_resolution.md).

---

## 2. Những lỗi **thật** mà review tìm đúng

Bốn lỗi P1 đều là lỗi thật, không phải hiểu nhầm:

1. **SSE dựng sẵn kết quả.** Endpoint được `run_backend.py` quảng bá trả một narrative và
   verdict `MALICIOUS` hardcode cho **mọi** câu hỏi. Đây là hành vi bịa mà cả đồ án chống lại,
   và nó nằm ngay trong đường chạy chính.
2. **Validator bị lừa bởi phủ định ở mệnh đề khác.** Tôi đã tự tin với "9/9 PASS" nhưng bộ test
   của tôi thiếu đúng loại câu `"Không có IP nguồn, nhưng host dùng C2"`.
3. **Citation ID tồn tại ≠ claim đúng.** Report thật của model ghi sai Status 4625 mà validator
   vẫn `passed`. Đây là bằng chứng mạnh nhất rằng "vượt validator" không đồng nghĩa "đúng".
4. **Kết luận vượt bằng chứng.** Tôi đã viết "thắng áp đảo 6–0" trong khi chưa chấm nội dung
   câu nào, và mô tả RAG là "vector baseline" trong khi nó dùng hybrid BM25+vector+RRF.

---

## 3. Những gì đã thực hiện

### 3.1 Sửa code

| File | Thay đổi |
|---|---|
| `server/app.py` | Bỏ narrative/verdict dựng sẵn khỏi SSE; dùng chung scope + cổng hai tầng |
| `llm/generation_contract_v3.py` | Phủ định clause-local + affirmative-use; bind Status/SubStatus theo event; `effective_validator_policy()`; `_env_int` có bound thật |
| `evaluation/experimental_comparison.py` | `_safe_config()` mang `validator_policy` |
| `evaluation/final_experiment.py` | Chế độ subset (trần 6/6, ledger riêng, không resume); `snapshot()` retry khoá file Windows |
| `evaluation/experimental_recovery.py` | `_snapshot()` retry khoá file Windows |
| `retrieval/reproducibility.py` | **Mới** — so sánh exact vs tolerated, policy v1 |
| `scripts/run_final_experiment.py` | `--review-selection`, `--review-interval-seconds`, `--review-max-attempts` |
| `scripts/verify_env_config.py` | 6 nhóm kiểm, exit code = số nhóm fail |
| `scripts/record_execution_environment.py` | **Mới** — ghi môi trường thực thi |
| `verify_package.py` | Ưu tiên release manifest, kiểm checksum manifest lịch sử |
| `pyproject.toml` | Đủ dependency trực tiếp + extra `numeric` |
| `frontend/package*.json` | vite 7.3.7, esbuild 0.28.2, postcss-selector-parser 6.1.5 |

### 3.2 Test

| File | Nội dung |
|---|---|
| `tests/test_server_sse.py` | 4 test: SSE không bịa verdict, SSE khớp POST ở câu ngoài phạm vi |
| `tests/test_final_direct_experiment.py` | +31 test: F01 (13 probe), F02 (7), F03 (9) |
| `tests/test_review_subset.py` | **Mới** — 11 test cho chế độ subset (guard, trần, ledger riêng, label) |
| `tests/test_reproducibility_policy.py` | **Mới** — 11 test cho tolerance policy |
| `tests/historical_fixtures.py` | **Mới** — skip fixture lịch sử kèm tên module lệch |
| `tests/test_final_direct_profile.py` | +1 test cho profile hiện hành end-to-end |
| `tests/test_graph_ground_truth_v2.py`, `tests/test_retrieval_ground_truth_v2.py` | Sửa contract v3 lạc hậu + thêm test khẳng định v3 được chấp nhận |
| `tests/test_v2_candidate_artifacts.py` | Skip trung thực khi manifest lịch sử thiếu |

### 3.3 Tài liệu

| File | Nội dung |
|---|---|
| `docs/CURRENT_STATUS.md` | **Mới** — entry point duy nhất cho trạng thái thật |
| `docs/REPRODUCIBILITY.md` | **Mới** — môi trường, embedding revision, tolerance policy |
| `docs/DASHBOARD_QA_CHECKLIST.md` | **Mới** — checklist kiểm dashboard bằng tay |
| `START_HERE.md`, `HUONG_DAN_CHAY.md` | Viết lại quanh profile hiện hành + xử lý sự cố |
| `HANDOVER.md`, `PROJECT_CONTEXT.md`, `AGENTS.md` | Giữ lịch sử, thêm banner chỉ sang CURRENT_STATUS |
| `PROJECT_PROGRESS.md` | Append mục 24, byte cũ nguyên vẹn |
| `Thuc_trang.md` | Bỏ kết luận vượt bằng chứng, thêm mục 6A |
| `packaging/release_manifest_20261101.json` | **Mới** — 410 file; manifest cũ giữ nguyên |

---

## 4. Live và dashboard: đã làm gì, chưa làm gì

### Đã làm

**Smoke 6 nhánh** trên profile v13, khai báo **trước** khi sinh output
(`outputs/final/20261101_direct_v13/review_smoke_declaration.json`):
- 1 câu DIRECT mỗi scenario × 2 nhánh
- Dùng **5/6** request trần, 5 accepted, 1 abstain (0 request), 0 provider error
- Chấm nội dung tách riêng khỏi structural acceptance: factual 5/5, citation 5/5, trả lời đúng
  câu hỏi 5/5, giữ giới hạn bằng chứng 6/6

**Dashboard HTTP-level** trên profile v17 (offline, `max_requests=0`):
- `/` và `/experimental.html` → 200; 4 asset → 200
- branch sai và scenario sai → 422
- câu ngoài phạm vi → abstain, 0 LLM
- `--live` bị từ chối với profile cuối
- saved replay → 200
- đủ 6 tổ hợp scenario × branch

### Chưa làm — và không tuyên bố là đã làm

| Hạng mục | Lý do |
|---|---|
| **Visual QA dashboard** | không có browser điều khiển được trong môi trường này; không có ảnh chụp |
| **Live đủ 16 nhánh trên v17** | mới có preflight; smoke 6 nhánh không thay benchmark |
| **Chấm ngữ nghĩa 16 câu** | chưa có bảng rubric; đây là lý do không kết luận về chất lượng |

### Hai sự cố ghi nhận

1. **`response.json` bị khoá giữa lượt QA** — `OSError 22` rồi `Permission denied` khi file tồn
   tại 232.929 byte. Cùng hiện tượng review gặp ở `regr32_sigma_recheck.json`. Đã query lại
   endpoint lấy payload trong bộ nhớ, không retry file, và ghi sự cố vào QA report.
2. **`os.replace` ném `WinError 5` ngẫu nhiên khi chạy full suite** — mỗi lần một test khác nhau
   fail. Đây là tranh chấp khoá file trên Windows. Đã thêm retry có giới hạn ở hai chỗ
   `snapshot`; sau đó suite chạy sạch ổn định.

---

## 5. Phần đạt / phần chưa xác minh

### Đạt (có bằng chứng)

- ✅ 11/11 finding xử lý, mỗi cái có test hoặc artifact chứng minh
- ✅ Full suite 6720 passed, 0 failed, 0 errors
- ✅ `verify_package.py` passed: 410 file, 29.510 canonical, 21 provenance, 3 CTI snapshot
- ✅ npm 0 vulnerabilities, build pass
- ✅ Smoke 6 nhánh: pipeline chạy end-to-end, 5 accepted, 1 abstain đúng
- ✅ Dashboard HTTP-level 6/6 tổ hợp, guard 422 đúng, live bị chặn
- ✅ Không có API key trong bất kỳ file nào được commit

### Chưa xác minh

- ❌ Chất lượng nội dung đầy đủ 16 câu trả lời
- ❌ Visual QA dashboard trên browser
- ❌ Reproduce float score khít giữa hai máy (có tolerance, không hứa)
- ❌ Human approval ground truth
- ❌ Kết luận RAG vs GraphRAG về chất lượng

---

## 6. Bảo toàn dữ liệu và kết quả lịch sử

| Hạng mục | Trạng thái |
|---|---|
| `packaging/package_manifest.json` (bàn giao 31/10) | **Giữ nguyên byte**, checksum ghi trong manifest mới |
| `outputs/final/20261031_direct_v7/` | Nguyên vẹn |
| `outputs/experiments/integrated-final-v8-live-01/` | Nguyên vẹn — dùng làm regression fixture cho F02 |
| Report v8 `AUTH-CTI/GraphRAG` sai | **Không ghi đè**; chấm lại và lưu kết quả riêng |
| `PROJECT_PROGRESS.md` | Chỉ append; phần cũ không sửa |
| Raw data, canonical, consumers | Không đổi; `verify_package.py` xác nhận 29.510 records |
| Pin lịch sử | v7/v8/v9/v10 giữ nguyên; profile mới là v11…v17 |

---

## 7. Không tuyên bố gì

Không báo "hoàn thiện 100%".

Điều đã chứng minh: pipeline chạy đúng, các lỗi cụ thể đã được sửa và có test chặn tái phát,
dữ liệu và lịch sử được bảo toàn.
Điều **chưa** chứng minh: câu trả lời của hệ thống đúng về nội dung, hay GraphRAG tốt hơn RAG.
Muốn kết luận hai điều đó thì phải chấm ngữ nghĩa đủ 16 câu trước.
