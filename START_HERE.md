# BẮT ĐẦU TỪ ĐÂY

**Profile hiện hành:** `integrated-final-direct-v18` — xem [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md) để biết trạng thái đầy đủ và giới hạn.

> Tài liệu này đã được viết lại ngày 01/11/2026. Các phiên bản trước chỉ dẫn profile v7 (đã thất bại vì HTTP 402) và bị lệch pin. Nếu anh đọc một tài liệu nào còn nói v7 là bản cuối, tài liệu đó là lịch sử.

## 1. Cài đặt (một lần)

```cmd
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[test,numeric]"
Set-Location frontend
npm.cmd ci
npm.cmd run build
Set-Location ..
```

Python 3.11+ được hỗ trợ. Môi trường đã dùng để sinh ra các số liệu báo cáo: Python **3.14.0**, numpy 2.3.4, torch 2.12.0+cpu. Chi tiết đầy đủ ở [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md).

## 2. Cấu hình LLM

```cmd
copy .env.example .env
notepad .env
```

Điền `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`. `.env` nằm trong `.gitignore` và không bao giờ được commit.

Nhóm biến trong `.env.example` có ghi rõ biến nào **ảnh hưởng pin** (đổi phải tạo pin mới) và biến nào không.

## 3. Ba lệnh chạy chính

### Kiểm gói offline (không cần mạng, không gọi LLM)

```cmd
.venv\Scripts\python.exe -B verify_package.py
```

### Chạy dashboard ba cột (offline, không gọi LLM)

```cmd
.venv\Scripts\python.exe -B scripts\serve_experimental_ui.py ^
  --config configs\evaluation\integrated_final_direct_v18.json ^
  --pin outputs\final\20261101_direct_v18\runtime_pin.json ^
  --port 8031 --output outputs\demo\demo-v18
```

Mở <http://127.0.0.1:8031/>.

### Chạy thực nghiệm offline (0 request LLM)

```cmd
.venv\Scripts\python.exe -B scripts\run_final_experiment.py ^
  --config configs\evaluation\integrated_final_direct_v18.json ^
  --pin outputs\final\20261101_direct_v18\runtime_pin.json ^
  --preflight outputs\final\20261101_direct_v18\preflight ^
  --output outputs\experiments\my-dryrun-01
```

## 4. Chạy live (tùy chọn, có kiểm soát)

Live run tiêu tốn request thật. Có hai chế độ:

**Kiểm nhanh 6 nhánh** (khuyến nghị lần đầu — trần cứng 6 request):

```cmd
.venv\Scripts\python.exe -B scripts\run_final_experiment.py ^
  --config configs\evaluation\integrated_final_direct_v18.json ^
  --pin outputs\final\20261101_direct_v18\runtime_pin.json ^
  --preflight outputs\final\20261101_direct_v18\preflight ^
  --output outputs\experiments\my-review-01 ^
  --review-selection "AUTH-DIRECT:rag,AUTH-DIRECT:graphrag,PS-DIRECT:rag,PS-DIRECT:graphrag,NET-DIRECT:rag,NET-DIRECT:graphrag" ^
  --live --review-max-attempts 6
```

**Toàn bộ 16 nhánh eligible** — thêm `--live` vào lệnh dry-run ở mục 3, bỏ `--review-selection`.

Cả hai đều dùng chung task ledger, pacing 60 giây, stop policy và không retry ngầm.

## 5. Chạy kiểm thử

```cmd
.venv\Scripts\python.exe -m pytest tests\ -q
.venv\Scripts\python.exe -B scripts\verify_env_config.py
```

Số liệu hiện hành: **6726 passed, 29 skipped, 0 failed, 0 errors**. 29 skip đều là fixture lịch sử có lý do ghi rõ — không phải test bị xóa.

## 6. Nếu có gì không chạy

| Triệu chứng | Nguyên nhân thường gặp |
|---|---|
| `Frozen runtime changed; an explicit execution delta pin is required` | Mã nguồn đã bị sửa so với pin. Đây là **hành vi đúng**. Tạo pin mới bằng `scripts/pin_integrated_runtime.py` sau khi sinh preflight mới |
| `Task ledger profile or budget changed` | Ledger đã có attempt với giới hạn khác. Không reset; khai báo subset mới hoặc dùng ledger mới |
| `Evaluated runtime module changed: ...` | Fixture dashboard lịch sử đang chạy trên code hiện tại. Dùng profile hiện hành |
| Thiếu model E5 | Cache `intfloat/multilingual-e5-small` revision `614241f6...` chưa có. Xem [E5_MODEL.md](E5_MODEL.md) |

## 7. Đọc tiếp theo thứ tự

1. [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md) — trạng thái thật, đã làm gì, chưa làm gì
2. [Thuc_trang.md](Thuc_trang.md) — kết quả thực nghiệm và giới hạn diễn giải
3. [docs/REVIEW_FIXES_20261101/report.md](docs/REVIEW_FIXES_20261101/report.md) — bản sửa lỗi theo review
4. [HANDOVER.md](HANDOVER.md) — hồ sơ bàn giao kỹ thuật
5. [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) — bối cảnh đồ án và phạm vi
