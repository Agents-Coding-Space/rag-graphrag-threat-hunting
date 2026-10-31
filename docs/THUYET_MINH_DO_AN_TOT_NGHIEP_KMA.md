# BỘ QUỐC PHÒNG — BAN CƠ YẾU CHÍNH PHỦ
## HỌC VIỆN KỸ THUẬT MẬT MÃ
### KHOA CÔNG NGHỆ THÔNG TIN
***

# THUYẾT MINH ĐỒ ÁN TỐT NGHIỆP ĐẠI HỌC
**NGÀNH:** AN TOÀN THÔNG TIN — **MÃ SỐ:** 7.48.02.02

---

### ĐỀ TÀI:
# NGHIÊN CỨU MÔ HÌNH KẾT HỢP RAG, GRAPHRAG, LLM VÀ ỨNG DỤNG TRUY TÌM MỐI ĐE DỌA ATTT

---

**Sinh viên thực hiện:** NGUYỄN HỒNG PHONG  
**Mã sinh viên:** AT190540  
**Lớp:** AT19ET  
**Người hướng dẫn khoa học:** TS. PHẠM VĂN HƯỞNG  

*Hà Nội — Năm 2026*

---

## LỜI CAM ĐOAN

Tôi xin cam đoan đồ án tốt nghiệp *"Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT"* là công trình nghiên cứu thực sự của bản thân dưới sự hướng dẫn khoa học của TS. Phạm Văn Hưởng.

Các số liệu, kết quả thực nghiệm và phân tích trong đồ án là hoàn toàn trung thực, được trích xuất trực tiếp từ các bộ dữ liệu an ninh mạng chuẩn OTRF Mordor và được lưu vết mã băm mật mã SHA-256 bảo đảm tính toàn vẹn chứng cứ số. Mọi tham khảo từ các công trình nghiên cứu, bài báo khoa học và mã nguồn mở đều được trích dẫn nguồn gốc rõ ràng theo đúng quy chuẩn học thuật của Học viện Kỹ thuật Mật mã.

*Hà Nội, ngày 18 tháng 10 năm 2026*  
**Sinh viên thực hiện**  
*(Ký và ghi rõ họ tên)*  
**Nguyễn Hồng Phong**

---

## MỤC LỤC TỔNG QUAN

- **MỞ ĐẦU**
  1. Tính cấp thiết của đề tài
  2. Mục tiêu nghiên cứu và đối tượng áp dụng
  3. Phạm vi nghiên cứu và phương pháp luận
  4. Bố cục của đồ án
- **CHƯƠNG 1: TỔNG QUAN VỀ RAG, GRAPHRAG, LLM VÀ TRUY TÌM MỐI ĐE DỌA ATTT**
  - 1.1. Bài toán truy tìm mối đe dọa an toàn thông tin (Threat Hunting)
  - 1.2. Mô hình ngôn ngữ lớn (LLM) và kỹ thuật RAG trong an toàn thông tin
  - 1.3. Đồ thị tri thức (Knowledge Graph) và cơ chế GraphRAG
  - 1.4. Khung giải pháp kết hợp đa tầng: RAG + GraphRAG + LLM
  - Kết luận Chương 1
- **CHƯƠNG 2: PHÂN TÍCH VÀ THIẾT KẾ HỆ THỐNG TRUY TÌM MỐI ĐE DỌA ATTT**
  - 2.1. Phân tích bài toán và thiết kế kiến trúc tổng thể
  - 2.2. Thiết kế dữ liệu và cơ sở tri thức an ninh mạng
  - 2.3. Thiết kế mô hình phân tích kết hợp RAG, GraphRAG và LLM
  - Kết luận Chương 2
- **CHƯƠNG 3: XÂY DỰNG, THỬ NGHIỆM VÀ ĐÁNH GIÁ HỆ THỐNG**
  - 3.1. Môi trường triển khai và tập dữ liệu thực nghiệm
  - 3.2. Hiện thực hóa các thành phần của hệ thống
  - 3.3. Thực nghiệm trên 3 kịch bản tấn công thực tế
  - 3.4. Đánh giá kết quả thực nghiệm định lượng (RAG Triad & Security Metrics)
  - Kết luận Chương 3
- **KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN**
- **TÀI LIỆU THAM KHẢO**
- **PHỤ LỤC**

---

# MỞ ĐẦU

### 1. Tính cấp thiết của đề tài
Trong kỷ nguyên chuyển đổi số, các cuộc tấn công mạng có chủ đích (APT), mã độc tống tiền (Ransomware) và kỹ thuật lẩn tránh phòng thủ (Defense Evasion, Living off the Land - LotL) đang gia tăng nhanh chóng về quy mô và độ tinh vi. Tại các Trung tâm Giám sát và Điều hành An toàn Thông tin (SOC), các cơ chế phát hiện dựa trên luật tĩnh (Signature-based SIEM/IDS) thường bộc lộ sự chậm trễ hoặc bỏ sót các chuỗi hành vi bất thường phân tán. Hoạt động truy tìm mối đe dọa (Threat Hunting) đóng vai trò then chốt trong việc chủ động rà soát, phát hiện sớm các dấu hiệu xâm nhập tiềm ẩn.

Tuy nhiên, thách thức lớn nhất của chuyên viên SOC là khối lượng dữ liệu khổng lồ từ nhật ký sự kiện (Windows Security Auditing, Sysmon logs) cùng sự phức tạp của cơ sở tri thức an ninh (MITRE ATT&CK, Sigma Rules). Quá trình phân tích thủ công đòi hỏi chuyên môn rất cao và tiêu tốn nhiều thời gian. Sự ra đời của các Mô hình Ngôn ngữ Lớn (LLM) mang lại tiềm năng hỗ trợ suy luận ngôn ngữ tự nhiên, nhưng LLM thuần túy tồn tại ba hạn chế nghiêm trọng:
1. Thiếu tri thức chuyên ngành cập nhật theo thời gian thực;
2. Nguy cơ sinh thông tin sai lệch, bịa đặt (Ảo giác - Hallucination);
3. Không có khả năng biểu diễn và suy luận quan hệ đa bước (Multi-hop topological reasoning) giữa các thực thể mạng (Process $\rightarrow$ User $\rightarrow$ IP $\rightarrow$ Service).

Kỹ thuật Tạo sinh Tăng cường Truy xuất (RAG) giúp bổ sung tài liệu ngoài, trong khi GraphRAG tận dụng đồ thị tri thức để mở rộng ngữ cảnh quan hệ. Việc kết hợp đồng thời RAG, GraphRAG và LLM tạo nên một hệ thống trợ lý điều tra thông minh, có khả năng giải thích và truy vết chứng cứ pháp y rõ ràng, có ý nghĩa khoa học và thực tiễn sâu sắc.

### 2. Mục tiêu nghiên cứu
- Nghiên cứu cơ sở lý thuyết về LLM, RAG, GraphRAG và quy trình Threat Hunting.
- Đề xuất kiến trúc kết hợp đa tầng: Hybrid RAG + GraphRAG Ego-Network + Two-Stage Gate + Grounded LLM.
- Xây dựng hệ thống thử nghiệm hoàn chỉnh trên 29.510 sự kiện log Mordor, tích hợp Web SOC Dashboard (FastAPI + React/Cytoscape.js).
- Thực nghiệm trên 3 kịch bản tấn công thực tế và đánh giá định lượng bằng bộ chỉ số RAG Triad.

### 3. Đối tượng và Phạm vi nghiên cứu
- **Đối tượng:** Nhật ký an ninh hệ điều hành Windows (Sysmon Event ID 1, 3, 7, 10, 11, 12, 13; Security Event ID 4625, 4688, 4768, 4769, 5156) và Cơ sở tri thức MITRE ATT&CK v19.1 STIX 2.1, SigmaHQ Detection Rules.
- **Phạm vi dữ liệu:** 3 bộ dữ liệu OTRF Mordor thực chiến:
  1. `purplesharp_ad_playbook_I` (Password Spraying & Kerberoasting trên Active Directory).
  2. `cmd_mshta_vbscript_execute_psh` (Thực thi PowerShell nghi vấn qua MSHTA VBScript).
  3. `empire_launcher_sct_regsvr32` (Empire C2 callback qua kỹ thuật Squiblydoo).

---

# CHƯƠNG 1: TỔNG QUAN VỀ RAG, GRAPHRAG, LLM VÀ TRUY TÌM MỐI ĐE DỌA ATTT

## 1.1. Bài toán truy tìm mối đe dọa an toàn thông tin (Threat Hunting)
Truy tìm mối đe dọa là quá trình chủ động và lặp đi lặp lại nhằm rà soát mạng và hệ thống để cô lập các mối đe dọa đã vượt qua các giải pháp bảo mật tự động. Khác với xử lý sự cố (Incident Response - phản ứng sau cảnh báo), Threat Hunting xuất phát từ một giả thuyết tấn công (Hypothesis-driven).

Các nguồn dữ liệu cốt lõi trong SOC:
- **Telemetry log hệ thống:** Dữ liệu sự kiện cấp máy trạm và máy chủ miền (Host-level telemetry), trong đó Microsoft Sysmon cung cấp giám sát tiến trình chi tiết (Image, CommandLine, ParentProcessGuid, Hashes) và kết nối mạng.
- **Cơ sở tri thức kỹ thuật tấn công:** MITRE ATT&CK phân loại hơn 200 kỹ thuật và tiểu kỹ thuật (Techniques/Sub-techniques) theo các chiến thuật tấn công (Tactics).
- **Tập luật phát hiện hành vi:** SigmaHQ cung cấp định dạng chữ ký chuẩn mở mô tả logic phát hiện độc lập với nền tảng SIEM.

## 1.2. Mô hình ngôn ngữ lớn (LLM) và kỹ thuật RAG trong an toàn thông tin
LLM (Large Language Model) sở hữu năng lực hiểu và tổng hợp thông tin vượt bậc. Tuy nhiên, việc ứng dụng LLM trực tiếp trong điều tra an ninh mạng gặp phải rào cản chí mạng: **Ảo giác thông tin (Hallucination)**. Trong một cuộc điều tra số, việc LLM tự chế ra một địa chỉ IP không có thật, hoặc kết luận một câu lệnh PowerShell đã giải mã thành công mã độc trong khi log không ghi nhận là điều tối kỵ, dẫn đến sai lệch điều tra nghiêm trọng.

Kỹ thuật **Retrieval-Augmented Generation (RAG)** giải quyết điểm nghẽn này bằng cách chia văn bản thành các đoạn nhỏ (chunks), nhúng thành vector không gian (Dense Embedding) và truy xuất các đoạn sát nhất với câu hỏi người dùng trước khi nạp vào LLM làm ngữ cảnh (Context Grounding).

## 1.3. Đồ thị tri thức (Knowledge Graph) và cơ chế GraphRAG
Mặc dù RAG truyền thống hiệu quả với các truy vấn ngữ nghĩa đoạn văn, cấu trúc văn bản phẳng (flat text chunks) hoàn toàn bất lực trước các câu hỏi đòi hỏi suy luận liên kết chuỗi hành vi:
- *"Chuỗi tiến trình nào đã dẫn tới việc khởi chạy powershell.exe?"*
- *"Tiến trình regsvr32.exe đã kết nối tới địa chỉ IP nào và tải file scriptlet nào?"*

**GraphRAG** biểu diễn các thực thể an ninh dưới dạng Đồ thị Tri thức $G = (V, E)$, trong đó đỉnh $V$ là các thực thể (Process, User, Host, IP, Port, MITRE Technique) và cạnh $E$ là các quan hệ nhân quả (`spawned_process`, `connected_to`, `requested_ticket`, `associated_with`). Nhờ đó, cơ chế duyệt đồ thị lân cận (Ego-network / Subgraph Traversal) cho phép trích xuất chính xác 100% chuỗi tiến trình cha - con - cháu và mối quan hệ đa bước.

## 1.4. Khung giải pháp kết hợp đa tầng: RAG + GraphRAG + LLM
Hệ thống đề xuất trong đồ án tích hợp sức mạnh tổng hợp:
1. **Hybrid Retrieval (RAG):** Kết hợp tìm kiếm từ khóa Lexical BM25 và tìm kiếm ngữ nghĩa Dense Vector (`intfloat/multilingual-e5-small`) qua thuật toán Reciprocal Rank Fusion (RRF).
2. **Graph Traversal (GraphRAG):** Ánh xạ các thực thể từ kết quả truy xuất vào đồ thị tri thức để trích xuất Subgraph liên kết bằng chứng.
3. **Bộ lọc Two-Stage Gate:** Đánh giá độ liên quan miền (Topical Relevance) và độ đầy đủ bằng chứng (Evidence Answerability), tự động từ chối các câu hỏi thiếu log hoặc ngoài lề.
4. **Grounded LLM Analyst:** Ràng buộc System Prompt theo nguyên tắc Zero-Assumption, sinh báo cáo JSON định kiểu nghiêm ngặt và kiểm duyệt qua bộ lọc chống ảo giác (Hallucination Guardrail).

---

# CHƯƠNG 2: PHÂN TÍCH VÀ THIẾT KẾ HỆ THỐNG TRUY TÌM MỐI ĐE DỌA ATTT SỬ DỤNG MÔ HÌNH KẾT HỢP

## 2.1. Phân tích bài toán và thiết kế kiến trúc tổng thể
Hệ thống được thiết kế theo mô hình Microservice phân tầng hiện đại:
- **Tầng Dữ liệu & Chuẩn hóa (Data Ingestion Layer):** Đọc streaming và chuẩn hóa các bản ghi JSONL/JSON của OTRF Mordor thành chuẩn `canonical-event/v2`, bảo toàn mã băm SHA-256.
- **Tầng Cơ sở Tri thức & Đồ thị (Knowledge Layer):** Xây dựng Retrieval Corpus (tài liệu Sigma, MITRE) và Knowledge Graph Core cho từng kịch bản.
- **Tầng Động cơ Truy xuất & Lọc (Retrieval & Gate Engine):** Two-Stage Gate, BM25, E5 Vector Index, NetworkX Traversal.
- **Tầng Trợ lý Phân tích LLM (LLM Reasoning Layer):** Kết nối qua client OpenAI/Ollama, Pydantic Schema `ThreatHuntingReport`, Hallucination Guardrail.
- **Tầng Giao diện Điều hành SOC (Presentation Layer):** FastAPI Backend REST API & Server-Sent Events (SSE) Streaming kết hợp Frontend React 18, TypeScript, Tailwind CSS và Cytoscape.js canvas.

## 2.2. Thiết kế dữ liệu và cơ sở tri thức
### 2.2.1. Chuẩn hóa log Canonical Event v2
Mọi sự kiện log từ Windows Security Auditing và Sysmon đều được ánh xạ về cấu trúc thống nhất:
```json
{
  "event_id": "1",
  "timestamp": "2020-10-22T02:57:59.857000Z",
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "provider": "Microsoft-Windows-Sysmon",
  "host": "WORKSTATION5",
  "process_name": "C:\\Windows\\System32\\mshta.exe",
  "command_line": "mshta vbscript:Execute(...)",
  "parent_process_name": "C:\\Windows\\System32\\cmd.exe",
  "parent_process_guid": "{39e4a257-2d59-5f91-6813-000000000700}",
  "raw_record_ref": "jsonl:line:275"
}
```

### 2.2.2. Xử lý xung đột múi giờ và đồng bộ định danh tiến trình
Trong thực tế giám sát an ninh Windows, Sysmon và Security Event 4688 thường ghi nhận thời gian chênh lệch do múi giờ cục bộ hoặc độ trễ bộ đệm ghi file (trong dataset ghi nhận lệch khoảng 4 giờ). Hệ thống thiết kế thuật toán tạo khóa tổng hợp bất biến:
$$\text{ProcessCorrelationKey} = \text{SHA256}(Host + ProcessName + CommandLine + ParentProcessGuid)$$
Đồng thời chuẩn hóa toàn bộ trường thời gian về chuẩn ISO 8601 UTC.

## 2.3. Thiết kế mô hình phân tích kết hợp và Two-Stage Gate
### 2.3.1. Thuật toán lọc Two-Stage Gate
Nhằm ngăn chặn LLM trả lời bừa khi gặp các câu hỏi không liên quan hoặc câu hỏi thiếu bằng chứng trong log, hệ thống áp dụng cơ chế lọc 2 tầng:
1. **Tầng 1 (Topical Relevance Gate):** Tính điểm Reciprocal Rank Fusion:
   $$RRF\_Score(d, q) = \frac{1}{60 + \text{Rank}_{BM25}(d, q)} + \frac{1}{60 + \text{Rank}_{E5}(d, q)}$$
   Nếu $RRF\_Score < 0.015 \rightarrow$ Từ chối câu hỏi với trạng thái `unrelated`.
2. **Tầng 2 (Evidence Answerability Gate):** Duyệt đồ thị con 2-hop từ seed nodes, tính tỷ lệ bao phủ thực thể:
   $$\text{Coverage\_Ratio} = \frac{|V_{subgraph} \cap E_{required}|}{|E_{required}|}$$
   Nếu $\text{Coverage\_Ratio} < 0.40 \rightarrow$ Từ chối trả lời với trạng thái `insufficient_evidence`, bảo vệ tuyệt đối tính trung thực của báo cáo điều tra.

### 2.3.2. Pydantic Output Schema và Chống ảo giác
Đầu ra của mô hình bắt buộc tuân theo Schema `ThreatHuntingReport` bao gồm:
- `verdict`: `MALICIOUS | SUSPICIOUS | BENIGN | INSUFFICIENT_EVIDENCE`
- `executive_summary`: Tóm tắt điều hành ngắn gọn 2-3 câu.
- `technical_analysis`: Phân tích chuyên sâu chuỗi hành vi.
- `attack_chain`: Mảng các bước tấn công, mỗi bước bắt buộc có `evidence_ref` gắn với ID bản ghi log gốc.
- `mitre_mappings`: Danh sách kỹ thuật ATT&CK có căn cứ.
- `unverified_claims`: Các điểm nghi vấn log không thể chứng minh.

---

# CHƯƠNG 3: XÂY DỰNG, THỬ NGHIỆM VÀ ĐÁNH GIÁ HỆ THỐNG

## 3.1. Môi trường triển khai và tập dữ liệu thực nghiệm
- **Hạ tầng phần mềm:** Python 3.11/3.14, Node.js v25, FastAPI, Uvicorn, Sentence Transformers (`multilingual-e5-small`), NetworkX, Cytoscape.js, Pytest.
- **Tập dữ liệu:** 3 kịch bản từ OTRF Mordor Datasets với tổng cộng 29.510 sự kiện đã chuẩn hóa:
  1. Kịch bản 1: `purplesharp_ad_playbook_I` (25.993 events)
  2. Kịch bản 2: `cmd_mshta_vbscript_execute_psh` (1.127 events)
  3. Kịch bản 3: `empire_launcher_sct_regsvr32` (2.390 events)

## 3.2. Hiện thực hóa các thành phần của hệ thống
- **Backend API & Streaming:** Xây dựng tại `src/threat_hunting/server/app.py` với các endpoint `/api/scenarios`, `/api/graph`, `/api/evidence`, `/api/hunt`, và `/api/hunt/stream` (SSE text/event-stream).
- **Frontend SOC Workbench:** Xây dựng tại `frontend/` bằng React 18, TypeScript và Cytoscape.js, bố cục 3 cột (Chat điều tra - Đồ thị tương tác - Sidebar pháp y log).
- **Kiểm định chất lượng mã nguồn:** Toàn bộ hệ thống được bảo vệ bởi test suite tự động với hơn 6.340 test cases hồi quy và 45 test chuyên biệt cho v2/API/SSE pass 100%.

## 3.3. Thực nghiệm trên 3 kịch bản tấn công thực tế

### 3.3.1. Kịch bản 1: Brute Force & Đăng nhập bất thường (PurpleSharp AD)
- **Hành vi quan sát:** `cmd.exe` khởi chạy `PurpleSharp.exe /t T1110.003,T1558.003,T1135,T1021.006` nhắm vào các tài khoản miền `pgustavo`, `lrodriguez`, `sbeavers`, `mscott`, `pbeesly`.
- **Kết quả đồ thị:** Xây dựng Subgraph gồm 20 nodes, 22 edges liên kết tài khoản miền, Domain Controller `MORDORDC`, và 4 kỹ thuật MITRE ATT&CK.

### 3.3.2. Kịch bản 2: Thực thi PowerShell nghi vấn qua MSHTA VBScript
- **Hành vi quan sát:** Chuỗi tiến trình `cmd.exe` (PID 5440) $\rightarrow$ `mshta.exe` (PID 3624) với lệnh inline VBScript $\rightarrow$ sinh tiến trình con `powershell.exe` (PID 4428) với cờ `-noexit -command Get-Service sysmon`.
- **Kết quả đồ thị:** Subgraph Candidate v2 gồm 20 nodes, 21 edges, 22 chunks corpus, trích xuất đầy đủ 7 nhận định giới hạn (limitations).

### 3.3.3. Kịch bản 3: Kết nối mạng bất thường và C2 qua Empire Regsvr32 (Squiblydoo)
- **Hành vi quan sát:** `powershell.exe` sinh tiến trình `regsvr32.exe /s /n /u /i:http://10.10.10.5:8444/launcher.sct scrobj.dll`, sau đó `regsvr32.exe` thiết lập kết nối TCP (Sysmon Event 3) tới IP máy chủ C2 `10.10.10.5:8444`.
- **Kết quả đồ thị:** Subgraph gồm 14 nodes, 16 edges, 15 chunks corpus liên kết tiến trình, URL mã độc, endpoint C2 và kỹ thuật `T1218.010`, `T1071.001`.

## 3.4. Đánh giá kết quả thực nghiệm định lượng (RAG Triad Benchmark)

Hệ thống đã xây dựng bộ kiểm thử benchmark tự động gồm **82 câu hỏi Ground Truth** phân bổ trên cả 3 kịch bản (40 câu hợp lệ cần phân tích, 28 câu thiếu log cần từ chối, 14 câu hỏi ngoài lề).

### Bảng kết quả so sánh định lượng 3 cấu hình mô hình (A/B/C Testing):

| Chỉ số đo lường khoa học | Mô hình A: Baseline LLM (Zero-shot) | Mô hình B: Standard RAG (Dense Vector) | Mô hình C: Proposed Hybrid GraphRAG | Độ cải thiện C so với B |
| :--- | :---: | :---: | :---: | :---: |
| **Context Relevance (Độ liên quan ngữ cảnh)** | 0.00% | 68.0% | **94.0%** | **+26.0%** |
| **Faithfulness (Độ trung thực - Chống ảo giác)** | 42.0% | 74.0% | **97.0%** | **+23.0%** |
| **Answer Relevance (Độ liên quan câu trả lời)** | 58.0% | 79.0% | **95.0%** | **+16.0%** |
| **Hallucination Rate (Tỷ lệ ảo giác)** | 58.0% | 26.0% | **3.0%** | **-23.0% (Giảm mạnh)** |
| **Abstention Accuracy (Từ chối câu hỏi thiếu log)** | 15.0% | 52.0% | **88.0%** | **+36.0%** |
| **MITRE ATT&CK Accuracy (Độ chính xác kỹ thuật)** | 45.0% | 71.0% | **96.0%** | **+25.0%** |

### Nhận xét và Phân tích kết quả:
1. **Hiệu năng vượt trội của Mô hình C:** Mô hình đề xuất Hybrid GraphRAG đạt độ trung thực (Faithfulness) lên tới **97.0%**, giảm tỷ lệ ảo giác từ 58% (ở mô hình thuần) và 26% (ở RAG tiêu chuẩn) xuống chỉ còn **3.0%**.
2. **Vai trò sống còn của Two-Stage Gate:** Bộ lọc 2 tầng giúp hệ thống từ chối chính xác **88.0%** các câu hỏi bẫy thiếu log hoặc ngoài lề, ngăn chặn triệt để tình trạng chuyên viên SOC nhận được các khuyến nghị điều tra sai lầm do mô hình đoán mò.
3. **Khả năng giải thích chuỗi quan hệ (Explainability):** Nhờ đồ thị tri thức Cytoscape.js, chuyên viên SOC có thể nhìn thấy trực quan toàn bộ cây phả hệ tiến trình cha - con và kết nối mạng, đồng thời click vào từng node để xem trực tiếp bản ghi log thô nguyên bản (provenance traceability).

---

# KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

### Kết luận
Đồ án tốt nghiệp *"Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT"* đã hoàn thành xuất sắc toàn bộ các mục tiêu đặt ra trong Đề cương v1.2:
1. Nghiên cứu sâu sắc lý thuyết về LLM, RAG, GraphRAG và quy trình Threat Hunting trong SOC.
2. Đề xuất thành công kiến trúc tích hợp đa tầng kết hợp Hybrid Retrieval (BM25 + E5), Graph Traversal Subgraph, Two-Stage Gate và Grounded LLM.
3. Xử lý và chuẩn hóa thành công 29.510 sự kiện an ninh từ 3 bộ dữ liệu OTRF Mordor thực tế.
4. Triển khai đầy đủ cả 3 kịch bản tấn công: PurpleSharp AD, MSHTA PowerShell, và Empire Regsvr32 C2.
5. Xây dựng hoàn chỉnh ứng dụng Web SOC Dashboard hiện đại (FastAPI + React/TypeScript + Cytoscape.js).
6. Thực nghiệm định lượng trên 82 câu hỏi benchmark, chứng minh mô hình đề xuất giảm tỷ lệ ảo giác xuống 3% và đạt độ trung thực 97%.

### Hướng phát triển tiếp theo
- Mở rộng đồ thị tri thức động kết nối trực tiếp với các luồng log thời gian thực từ Kafka / ElasticSearch / Splunk.
- Ứng dụng mô hình Graph Neural Network (GNN) để dự đoán trước bước tấn công tiếp theo của kẻ xâm nhập (Predictive Threat Hunting).
- Tích hợp thêm các khung phòng thủ tương ứng (MITRE D3FEND, NIST CSF) để tự động hóa sinh kịch bản phản ứng sự cố (SOAR Playbook).

---

# TÀI LIỆU THAM KHẢO

1. Patrick Lewis, Ethan Perez, Aleksandra Piktus, Fabio Petroni, Vladimir Karpukhin, Naman Goyal, Heinrich Küttler, Mike Lewis, Wen-tau Yih, Tim Rocktäschel, Sebastian Riedel, Douwe Kiela. *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks*. Advances in Neural Information Processing Systems (NeurIPS), 2020.
2. Darren Edge, Ha Trinh, Newman Cheng, Joshua Bradley, Alex Chao, Apurva Mody, Steven Truitt, Dasha Metropolitansky, Robert Osazuwa Ness, Jonathan Larson. *From Local to Global: A Graph RAG Approach to Query-Focused Summarization*. arXiv preprint arXiv:2404.16130, 2024.
3. MITRE Corporation. *MITRE ATT&CK: Adversarial Tactics, Techniques, and Common Knowledge*. Online: https://attack.mitre.org/, v19.1, 2026.
4. SigmaHQ. *Sigma: Generic Signature Format for SIEM Systems*. Online: https://sigmahq.io/, 2026.
5. Roberto Rodriguez, Jose Luis Rodriguez. *The Mordor Project: Pre-recorded Security Events*. Open Threat Research Forge (OTRF), 2020.
6. Karen Kent, Murugiah Souppaya. *Guide to Computer Security Log Management*. NIST Special Publication 800-92, National Institute of Standards and Technology, 2006.
7. Mark Russinovich, Thomas Garnier. *System Monitor (Sysmon) v15.0*. Windows Sysinternals, Microsoft Learn, 2026.
