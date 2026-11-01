# HƯỚNG DẪN CHẠY NHANH

Bắt đầu tại [START_HERE.md](START_HERE.md) — có đủ lệnh cài đặt, chạy dashboard, chạy thực nghiệm và xử lý sự cố.

**Ba lệnh cần nhớ:**

```cmd
REM 1. Kiểm gói offline (không mạng, không gọi LLM)
.venv\Scripts\python.exe -B verify_package.py

REM 2. Dashboard ba cột (offline)
.venv\Scripts\python.exe -B scripts\serve_experimental_ui.py --config configs\evaluation\integrated_final_direct_v19.json --pin outputs\final\20261101_direct_v19\runtime_pin.json --port 8031 --output outputs\demo\demo-v19

REM 3. Kiểm thử
.venv\Scripts\python.exe -m pytest tests\ -q
```

**Profile hiện hành:** `integrated-final-direct-v19`
**Trạng thái test:** 6726 passed, 29 skipped, 0 failed, 0 errors
**Chấm nội dung (live v19):** 16/16 factual, 15/16 citation
**Dashboard:** <http://127.0.0.1:8031/> (chỉ offline/replay với profile cuối)

Cần API key: copy `.env.example` thành `.env` rồi điền. Không commit `.env`.

Đọc thêm:
- [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md) — trạng thái thật và giới hạn
- [Thuc_trang.md](Thuc_trang.md) — kết quả thực nghiệm
- [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) — môi trường và dung sai số thực
- [docs/DASHBOARD_QA_CHECKLIST.md](docs/DASHBOARD_QA_CHECKLIST.md) — checklist kiểm dashboard bằng tay
