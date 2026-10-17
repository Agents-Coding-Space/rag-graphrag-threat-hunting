# CẨM NANG HƯỚNG DẪN CÀI ĐẶT VÀ KHỞI CHẠY HỆ THỐNG
## HỆ THỐNG TRUY TÌM MỐI ĐE DỌA AN TOÀN THÔNG TIN (THREAT HUNTING SOC WORKBENCH)
### Đồ án tốt nghiệp: Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT
**Sinh viên thực hiện:** Nguyễn Hồng Phong — MSV: AT190540 — Lớp: AT19ET  
**Học viện Kỹ thuật Mật mã — Năm 2026**

---

## I. YÊU CẦU MÔI TRƯỜNG HỆ THỐNG

Trước khi khởi chạy, máy tính của bạn cần cài đặt sẵn:
1. **Python:** Phiên bản `3.11` trở lên (Khuyến nghị Python 3.11 hoặc 3.12, 3.14).
2. **Node.js & npm:** Phiên bản `Node.js 18.x` trở lên (Khuyến nghị Node.js 20.x hoặc 25.x).
3. **Trình duyệt web:** Google Chrome, Microsoft Edge hoặc Brave phiên bản mới nhất.

---

## II. HƯỚNG DẪN CÀI ĐẶT THƯ VIỆN (CHỈ CẦN LÀM 1 LẦN ĐẦU)

Mở terminal (PowerShell hoặc Command Prompt) tại thư mục `rag-graphrag-threat-hunting`:

### 1. Cài đặt các gói thư viện Python:
```powershell
# Di chuyển vào thư mục dự án
cd rag-graphrag-threat-hunting

# Cài đặt gói threat_hunting ở chế độ editable
pip install -e .

# Cài đặt thư viện AI Sentence Transformers (nếu máy chưa có)
pip install sentence-transformers==6.1.0
```

### 2. Cài đặt các gói thư viện Frontend (React + Vite):
```powershell
# Di chuyển vào thư mục frontend
cd frontend

# Cài đặt npm packages (Cytoscape, Tailwind, Lucide Icons...)
npm install

# Quay trở lại thư mục gốc
cd ..
```

---

## III. CẤU HÌNH AI MODEL (ĐÃ CÓ SẴN TRONG FILE `.env`)

Hệ thống đã được cấu hình sẵn sàng kết nối với **Mô hình AI Phong (Backend: Gemma-4)** qua cổng API 9Router. Cấu hình được lưu tự động tại file `.env` ở thư mục gốc:

```env
LLM_PROVIDER=openai
LLM_BASE_URL=https://9router.qwen2api.pp.ua/v1
LLM_API_KEY=sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a
LLM_MODEL=Phong
```

*(Bạn không cần chỉnh sửa gì thêm, hệ thống sẽ tự động nạp cấu hình này khi khởi chạy).*

---

## IV. HƯỚNG DẪN KHỞI CHẠY HỆ THỐNG (CHỈ VỚI 2 LỆNH)

Hệ thống hoạt động theo kiến trúc Microservice gồm **Backend API Server (cổng 8000)** và **Frontend Web Dashboard (cổng 5173)**. Bạn mở **2 cửa sổ Terminal song song**:

### CỬA SỔ TERMINAL 1 — Khởi chạy Backend API Server:
Đứng tại thư mục dự án, chạy lệnh:
```powershell
python run_backend.py
```
*Dấu hiệu thành công:* Màn hình hiển thị logo tấm khiên an ninh mạng và dòng thông báo:
```text
======================================================================
🛡️  THREAT HUNTING GRAPHRAG SOC BACKEND API SERVER
======================================================================
Project Root : .../rag-graphrag-threat-hunting
API Endpoints:
  - http://127.0.0.1:8000/api/health
  - http://127.0.0.1:8000/api/scenarios
  - http://127.0.0.1:8000/api/graph?scenario_id=mshta-powershell
  - http://127.0.0.1:8000/api/hunt (POST)
  - http://127.0.0.1:8000/api/hunt/stream (SSE GET)
  - http://127.0.0.1:8000/docs (Tài liệu Swagger UI tương tác)
======================================================================
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

---

### CỬA SỔ TERMINAL 2 — Khởi chạy Giao diện Frontend Web Dashboard:
Mở cửa sổ Terminal thứ hai, chạy lệnh:
```powershell
cd rag-graphrag-threat-hunting\frontend
npm run dev
```
*Dấu hiệu thành công:* Màn hình hiển thị đường dẫn truy cập:
```text
  VITE v5.4.x  ready in 450 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

👉 **MỞ TRÌNH DUYỆT:** Truy cập vào địa chỉ **[http://localhost:5173](http://localhost:5173)** để bắt đầu sử dụng giao diện SOC Dashboard!

---

## V. HƯỚNG DẪN SỬ DỤNG GIAO DIỆN SOC DASHBOARD

Giao diện được thiết kế theo phong cách **MacOS Liquid Glass (Glassmorphism)** hiện đại với bố cục 3 cột trực quan:

```
┌──────────────────────────┬─────────────────────────────────────┬───────────────────────────────┐
│ 📋 PHÁP Y & BẰNG CHỨNG   │ 🕸️ KHÔNG GIAN ĐỒ THỊ TRI THỨC      │ 💬 KHUNG CHAT ĐIỀU TRA SOC    │
│ (Chiếm 25% bên trái)     │ (Cytoscape.js - Chiếm 45% ở giữa)   │ (Chiếm 30% bên phải)          │
└──────────────────────────┴─────────────────────────────────────┴───────────────────────────────┘
```

### 1. Chọn Kịch bản Tấn công (Dropdown menu góc phải):
Hệ thống tích hợp sẵn 3 kịch bản tấn công thực tế từ OTRF Mordor Datasets:
- **Kịch bản 1:** `MSHTA Inline VBScript executing PowerShell` (Thực thi mã qua Living-off-the-Land binary).
- **Kịch bản 2:** `PurpleSharp AD Password Spraying and Kerberoasting` (Dò quét mật khẩu trên Active Directory).
- **Kịch bản 3:** `Empire Regsvr32 Squiblydoo and C2 Network Connection` (Tải scriptlet độc hại và kết nối máy chủ C2).
*Khi chọn kịch bản, Đồ thị ở giữa sẽ tự động tải mạng lưới tri thức tương ứng.*

### 2. Tương tác với Đồ thị Tri thức Cytoscape.js (Cột giữa):
- **Phóng to / Thu nhỏ / Di chuyển:** Dùng con lăn chuột để zoom, giữ chuột trái để kéo canvas. Có 3 nút tròn floating ở góc dưới bên phải: `Phóng to`, `Thu nhỏ`, `Toàn cảnh`.
- **Màu sắc các nút (Legend):**
  * **Màu Xanh ngọc (Cyan):** Tiến trình hệ thống (`Process`).
  * **Màu Tím (Purple):** Tài khoản người dùng (`Account`).
  * **Màu Cam (Amber):** Địa chỉ IP / Cổng kết nối (`Endpoint`).
  * **Màu Xanh lá (Emerald):** Bản ghi bằng chứng số (`Evidence`).
  * **Màu Đỏ (Rose):** Kỹ thuật tấn công MITRE ATT&CK (`MITRE Technique`).
- **Xem chứng cứ số gốc:** Nhấp chuột vào bất kỳ Node nào trên đồ thị $\rightarrow$ Cột **Pháp y & Bằng chứng (bên trái)** sẽ hiển thị toàn bộ thuộc tính, ID tiến trình PID, mã băm SHA-256 và dòng log Sysmon/Security thô gốc.

### 3. Đặt câu hỏi điều tra và nhận câu trả lời từ AI (Cột phải):
- **Tính năng Gợi ý nhanh:** Mặc định thanh gợi ý được thu gọn tinh tế thành nút `▼ Hiện gợi ý`. Bạn có thể bấm mở ra để chọn câu hỏi mẫu, hoặc bấm `▲ Ẩn gợi ý` để khung chat rộng rãi.
- **Giải thích ngắn gọn từ AI:** Khi bạn đặt câu hỏi, AI Model Phong sẽ trả về một câu giải thích súc tích (1-2 câu) đúng trọng tâm vấn đề ngay ở đầu thẻ kết quả.
- **Xem chi tiết chuỗi tấn công:** Toàn bộ bảng phân tích Attack Chain dài dòng được thu gọn gàng sau nút `▼ Xem chi tiết chuỗi tấn công & MITRE`. Khi cần kiểm tra sâu, bạn bấm mở ra.
- **Xuất Báo cáo Điều tra Sự cố:** Có sẵn 2 nút:
  * **`Xuất MD`:** Tải ngay bản Báo cáo Điều tra Sự cố dạng Markdown (`.md`) chuẩn form SOC để nộp cấp trên.
  * **`JSON`:** Tải dữ liệu bằng chứng và chuỗi tấn công dạng JSON.

### 4. Chuyển đổi Giao diện Sáng / Tối (Light / Dark Mode):
Nhấp vào biểu tượng Mặt trời / Mặt trăng trên thanh tiêu đề góc trên bên phải để đổi giao diện tùy thích. Lựa chọn này được tự động lưu lại trên trình duyệt của bạn.

---

## VI. CÁC CÂU HỎI MẪU HAY NHẤT ĐỂ THỬ NGHIỆM

Bạn có thể copy/paste trực tiếp các câu hỏi sau vào khung chat:

1. **Hỏi về chuỗi tiến trình cha - con (Multi-hop reasoning):**
   > *"Which process chain led to powershell.exe in the reviewed evidence?"*  
   *(Chuỗi tiến trình nào đã dẫn tới powershell.exe?)*

2. **Hỏi về kỹ thuật hacker quốc tế:**
   > *"Có kỹ thuật MITRE ATT$CK nào trong kia"*  
   *(AI sẽ trả lời ngắn gọn: xác nhận T1218.005 Mshta, T1059.007 JavaScript, T1140)*

3. **Hỏi về kết nối mạng máy chủ điều khiển (Kịch bản Regsvr32):**
   > *"To which remote IP address and port did regsvr32.exe connect?"*  
   *(AI sẽ chỉ ra IP C2 10.10.10.5 và cổng 8444)*

4. **Hỏi về tài khoản Active Directory bị nhắm tới (Kịch bản PurpleSharp):**
   > *"Những tài khoản người dùng Active Directory nào bị nhắm tới?"*

5. **Thử nghiệm câu hỏi ngoài lề (Kiểm tra cơ chế tự vệ Two-Stage Gate):**
   > *"Thời tiết ngày mai ở Hà Nội thế nào?"*  
   *(Gate sẽ chặn đứng ngay lập tức với thông báo: Rejected by gate at topical_relevance)*

6. **Thử nghiệm câu hỏi bẫy thiếu log (Kiểm tra cơ chế chống ảo giác):**
   > *"Cmdlet nào đã chạy thành công bên trong PowerShell?"*  
   *(Hệ thống sẽ từ chối suy đoán bừa và giải thích log chỉ có lệnh khởi chạy chứ không có cmdlet output)*

---

## VII. HƯỚNG DẪN CHẠY KIỂM THỬ KỸ THUẬT (TEST SUITE)

Nếu muốn thẩm định mã nguồn và kiểm tra độ ổn định của hệ thống:

```powershell
cd rag-graphrag-threat-hunting

# 1. Chạy toàn bộ 715 unit tests tự động (pass 100%)
pytest -q

# 2. Kiểm thử riêng tính toàn vẹn của cả 3 kịch bản
pytest tests/test_all_three_scenarios_schema_coherence.py -v

# 3. Kiểm thử Two-Stage Gate bằng dòng lệnh CLI
pytest tests/test_query_cli_two_stage_gate.py -v

# 4. Kiểm thử các API Endpoint Backend và SSE Streaming
pytest tests/test_server_api.py tests/test_server_sse.py -v

# 5. Chạy lại benchmark đánh giá định lượng RAG Triad trên 82 câu hỏi
python scripts/evaluate_rag_triad_benchmark.py
```

---

## VIII. CÁC TÀI LIỆU QUAN TRỌNG ĐI KÈM TRONG DỰ ÁN

- **Toàn văn Thuyết minh Đồ án 3 Chương chuẩn KMA:**  
  `docs/THUYET_MINH_DO_AN_TOT_NGHIEP_KMA.md` (hoặc file tại thư mục gốc).
- **Báo cáo Thực nghiệm Định lượng RAG Triad (Mục 3.4 Báo cáo):**  
  `docs/evaluation/rag_triad_benchmark_summary.md`.
- **Báo cáo Tiến bộ kỹ thuật Baseline v1 vs Candidate v2:**  
  `docs/evaluation/baseline_v1_vs_candidate_v2_comparison.md`.
- **Video ghi hình quá trình kiểm thử tự động (Playwright E2E):**  
  `docs/videos/e2e_test_recording_v2_upgraded.webm`.
- **Kho mã nguồn GitHub:**  
  `https://github.com/Agents-Coding-Space/rag-graphrag-threat-hunting` (nhánh `main`).

---
*Chúc bạn có một buổi báo cáo thử nghiệm và bảo vệ đồ án tốt nghiệp thành công rực rỡ!*
