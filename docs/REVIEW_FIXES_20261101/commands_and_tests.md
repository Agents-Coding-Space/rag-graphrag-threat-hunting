# COMMANDS AND TESTS

Mọi lệnh dưới đây chạy được từ thư mục gốc dự án. Môi trường: **Windows 11**, Python **3.14.0**,
npm **11.13.0**, Node **25.0.0**. Xem [../REPRODUCIBILITY.md](../REPRODUCIBILITY.md).

`PYTHONDONTWRITEBYTECODE=1` được dùng để không sinh `.pyc` làm lệch kiểm tra file.

**Profile cuối:** `integrated-final-direct-v18` — pin `outputs/final/20261101_direct_v18/runtime_pin.json`.
Mọi lệnh dưới đây trỏ tới v18. Các profile cũ (v10 đến v17) đã bị thay thế và chỉ còn giá trị lịch sử.

---

## 1. Cài đặt

```cmd
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[test,numeric]"
Set-Location frontend
npm.cmd ci
npm.cmd run build
Set-Location ..
copy .env.example .env
```

Điền `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` trong `.env`. Không commit `.env`.

---

## 2. Kiểm tra nhanh

```cmd
REM Gói + dữ liệu + provenance (không mạng, không LLM)
.venv\Scripts\python.exe -B verify_package.py

REM Validator policy, cross-clause, auth binding, pin inclusion
.venv\Scripts\python.exe -B scripts\verify_env_config.py
```

Kết quả mong đợi:

```
verify_package.py   -> status: passed, release_files_verified: 410, raw_records: 29510
verify_env_config.py-> OVERALL: PASS, exit 0
```

---

## 3. Full test suite

```cmd
.venv\Scripts\python.exe -m pytest tests\ -q -p no:cacheprovider
```

Kết quả mong đợi (đo thật):

```
6726 passed, 29 skipped, 6 subtests passed in ~14 min
```

Xem chi tiết skip có lý do:

```cmd
.venv\Scripts\python.exe -m pytest tests\ -q -p no:cacheprovider -rs
```

### Nhóm test trọng tâm (chạy nhanh)

```cmd
.venv\Scripts\python.exe -m pytest tests\test_final_direct_experiment.py tests\test_review_subset.py tests\test_reproducibility_policy.py tests\test_server_sse.py -q -p no:cacheprovider
```

Kết quả mong đợi: **95 passed, 1 skipped** (~68s).

| File | Số test | Kiểm gì |
|---|---|---|
| `test_final_direct_experiment.py` | 50 | F01 (negation locality), F02 (auth binding), F03 (pinned policy), runner |
| `test_review_subset.py` | 11 | F07 — guard, trần 6/6, ledger riêng, label |
| `test_reproducibility_policy.py` | 11 | F05 — tolerance policy |
| `test_server_sse.py` | 4 | F10 — SSE không bịa verdict |
| `test_final_direct_profile.py` | 3 | Profile hiện hành end-to-end |

---

## 4. Chạy thực nghiệm

### 4.1 Offline (0 request LLM)

```cmd
.venv\Scripts\python.exe -B scripts\run_final_experiment.py ^
  --config configs\evaluation\integrated_final_direct_v18.json ^
  --pin outputs\final\20261101_direct_v18\runtime_pin.json ^
  --preflight outputs\final\20261101_direct_v18\preflight ^
  --output outputs\experiments\my-dryrun-01
```

### 4.2 Kiểm live có giới hạn — 6 nhánh, trần 6 request

```cmd
.venv\Scripts\python.exe -B scripts\run_final_experiment.py ^
  --config configs\evaluation\integrated_final_direct_v18.json ^
  --pin outputs\final\20261101_direct_v18\runtime_pin.json ^
  --preflight outputs\final\20261101_direct_v18\preflight ^
  --output outputs\experiments\my-review-01 ^
  --review-selection "AUTH-DIRECT:rag,AUTH-DIRECT:graphrag,PS-DIRECT:rag,PS-DIRECT:graphrag,NET-DIRECT:rag,NET-DIRECT:graphrag" ^
  --live --review-max-attempts 6
```

Đo thật: **5 request**, 5 accepted, 1 abstain, 0 provider error, pacing ~59s.

### 4.3 Live đủ 16 nhánh eligible

```cmd
.venv\Scripts\python.exe -B scripts\run_final_experiment.py ^
  --config configs\evaluation\integrated_final_direct_v18.json ^
  --pin outputs\final\20261101_direct_v18\runtime_pin.json ^
  --preflight outputs\final\20261101_direct_v18\preflight ^
  --output outputs\experiments\my-live-full-01 ^
  --live
```

Trần 16 request initial + 4 recovery, pacing 60s, ledger persistent, không retry/fallback.

---

## 5. Dashboard

```cmd
.venv\Scripts\python.exe -B scripts\serve_experimental_ui.py ^
  --config configs\evaluation\integrated_final_direct_v18.json ^
  --pin outputs\final\20261101_direct_v18\runtime_pin.json ^
  --port 8031 --output outputs\demo\qa-manual-v18
```

Mở <http://127.0.0.1:8031/>. Kiểm theo [../DASHBOARD_QA_CHECKLIST.md](../DASHBOARD_QA_CHECKLIST.md).

Kiểm tự động mức HTTP:

```cmd
curl -sS http://127.0.0.1:8031/experimental-api/config
curl -sS -X POST http://127.0.0.1:8031/experimental-api/hunt ^
  -H "Content-Type: application/json" ^
  -d "{\"query\":\"Thoi tiet hom nay the nao?\",\"scenario_id\":\"purplesharp-ad\",\"branch\":\"rag\"}"
```

Kết quả mong đợi cho câu ngoài phạm vi: `outcome=abstain`, `llm_http_attempts=0`.

---

## 6. Tạo profile và pin mới

Khi sửa code hoặc đổi cấu hình model, **phải** tạo profile mới (pin cũ sẽ chặn đúng):

```cmd
REM 1. Tạo config mới (copy v18, đổi profile_id + task_ledger + saved_results_manifest)

REM 2. Sinh preflight — không gọi LLM
.venv\Scripts\python.exe -B scripts\evaluate_rag_graphrag.py ^
  --config configs\evaluation\integrated_final_direct_v18.json ^
  --output outputs\final\20261101_direct_v18\preflight

REM 3. Khóa pin
.venv\Scripts\python.exe -B scripts\pin_integrated_runtime.py ^
  --config configs\evaluation\integrated_final_direct_v18.json ^
  --preflight outputs\final\20261101_direct_v18\preflight ^
  --output outputs\final\20261101_direct_v18\runtime_pin.json

REM 4. Cập nhật release manifest (nếu muốn verify_package.py phản ánh checkout mới)
.venv\Scripts\python.exe -B scripts\record_execution_environment.py --profile integrated-final-direct-v18
```

Kỳ vọng mỗi bước: `planned=24, eligible=16, llm_http_attempts=0`.

---

## 7. Frontend

```cmd
Set-Location frontend
npm.cmd ci
npm.cmd audit
npm.cmd run build
Set-Location ..
```

Kết quả mong đợi: `found 0 vulnerabilities`; `tsc && vite build` pass (40 modules, ~22s).

---

## 8. Xử lý sự cố

| Thông báo | Nghĩa | Cách xử lý |
|---|---|---|
| `Frozen runtime changed; an explicit execution delta pin is required` | Code đã khác pin | **Đúng thiết kế.** Tạo profile + pin mới (mục 6) |
| `Task ledger profile or budget changed` | Ledger đã có attempt với giới hạn khác | Không reset. Khai báo subset mới hoặc dùng profile mới |
| `Evaluated runtime module changed: ...` | Fixture dashboard lịch sử chạy trên code mới | Dùng profile hiện hành; fixture lịch sử đã skip tự động |
| `Release manifest content hash mismatch` | Có file sửa sau khi sinh manifest | Chạy lại bước 4 mục 6 |
| `historical v2 candidate manifest absent` | Artifact lịch sử chưa từng commit | Skip có chủ đích, không tạo file giả |
| `PermissionError [WinError 5]` trên `*.tmp` | Scanner/AV đang giữ file | Đã có retry; chạy lại nếu vẫn gặp |
| Thiếu cache E5 | Chưa có `multilingual-e5-small` rev `614241f6...` | Xem [../../E5_MODEL.md](../../E5_MODEL.md) |

---

## 9. Artifact quan trọng

| Đường dẫn | Nội dung |
|---|---|
| `outputs/final/20261101_direct_v18/runtime_pin.json` | Pin hiện hành (107 file code + validator policy) |
| `outputs/final/20261101_direct_v18/preflight/results.json` | 24 nhánh, 16 eligible, 0 HTTP |
| `outputs/final/20261101_direct_v18/dashboard_qa.json` | Dashboard HTTP-level QA |
| `outputs/final/20261101_direct_v12/review_smoke_declaration.json` | Khai báo smoke **trước** khi chạy |
| `outputs/final/20261101_direct_v13/review_smoke_scores.json` | Chấm 4 tiêu chí từng câu |
| `outputs/final/20261101_direct_v10/v8_revalidation_under_v31.json` | Chấm lại 3 ca v8 |
| `packaging/release_manifest_20261101.json` | Manifest phát hành (410 file) |
| `docs/REVIEW_FIXES_20261101/changed_files.json` | Danh sách file thay đổi theo commit |
