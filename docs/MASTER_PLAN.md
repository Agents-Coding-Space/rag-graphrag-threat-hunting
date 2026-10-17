# KẾ HOẠCH TỔNG THỂ HOÀN THIỆN ĐỒ ÁN TỐT NGHIỆP (MASTER IMPLEMENTATION PLAN)

**Đề tài:** Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT  
**Sinh viên thực hiện:** Nguyễn Hồng Phong — MSV: AT190540 — Lớp: AT19ET  
**Người hướng dẫn:** TS. Phạm Văn Hưởng — Khoa Công nghệ thông tin, Học viện Kỹ thuật Mật mã  
**Hệ thống thực thi:** PI-Agent phối hợp cùng Advisor Argon  
**Mã nguồn lưu trữ:** `https://github.com/Agents-Coding-Space/rag-graphrag-threat-hunting`  
**Ngày lập kế hoạch:** 18/10/2026  
**Trạng thái:** Chờ phê duyệt (Pending Human Approval)

---

## I. TỔNG QUAN VÀ ĐỐI CHIẾU ĐỀ CƯƠNG HỌC VIỆN KỸ THUẬT MẬT MÃ

Kế hoạch này được xây dựng trên cơ sở bám sát 100% **Đề cương Đồ án Tốt nghiệp v1.2** (file `Nguyễn Hồng Phong-AT190540_v1.2.docx`) và hiện trạng mã nguồn thực tế tại repository.

### 1. Mục tiêu đồ án (Theo Đề cương)
1. Nghiên cứu cơ sở lý thuyết về LLM, RAG, GraphRAG và bài toán truy tìm mối đe dọa an toàn thông tin (Threat Hunting trong SOC).
2. Đề xuất mô hình kiến trúc kết hợp RAG, GraphRAG và LLM cho bài toán truy tìm mối đe dọa ATTT.
3. Xây dựng quy trình xử lý dữ liệu log, nguồn tri thức bảo mật (MITRE ATT&CK, Sigma Rule) và đồ thị tri thức (Knowledge Graph).
4. Xây dựng hệ thống thử nghiệm triển khai mô hình kết hợp RAG, GraphRAG và LLM kèm giao diện cho chuyên viên SOC.
5. Thực nghiệm trên 3 kịch bản truy tìm mối đe dọa và đánh giá hiệu quả của mô hình theo các tiêu chí khoa học.

### 2. Cấu trúc 3 Chương đề cương và Ánh xạ Kỹ thuật
*   **Chương 1: Tổng quan về RAG, GraphRAG, LLM và truy tìm mối đe dọa ATTT**
    *   *Nội dung:* Bài toán Threat Hunting trong SOC; Nguồn dữ liệu & tri thức; Năng lực & hạn chế của LLM trong ATTT (hallucination, thiếu tri thức quan hệ); Kiến trúc RAG và GraphRAG; Khung giải pháp kết hợp.
*   **Chương 2: Phân tích và thiết kế hệ thống truy tìm mối đe dọa ATTT sử dụng mô hình kết hợp RAG, GraphRAG, LLM**
    *   *Nội dung:* Yêu cầu hệ thống; Kiến trúc tổng thể; Luồng xử lý; Chuẩn hóa log (Canonical Event); Thiết kế cơ sở tri thức (MITRE ATT&CK STIX, Sigma Rules, CTI); Thiết kế đồ thị tri thức (Knowledge Graph Schema & Traversal); Thiết kế RAG pipeline, GraphRAG pipeline, Cơ chế phối hợp truy xuất & Gate hai tầng (Topical Relevance -> Evidence Answerability); Thiết kế prompt và định dạng đầu ra phân tích LLM có bằng chứng (provenance).
*   **Chương 3: Xây dựng, thử nghiệm và đánh giá hệ thống**
    *   *Môi trường & Dữ liệu:* Công nghệ (Python 3.11+, Sentence Transformers, NetworkX, Streamlit, Ollama/OpenAI API); Dữ liệu OTRF Mordor Datasets.
    *   *3 Kịch bản thực nghiệm bắt buộc (Mục 3.3 Đề cương):*
        1. **Kịch bản 1 (3.3.1):** Brute force và đăng nhập bất thường (Password Spraying & Kerberoasting từ PurpleSharp AD playbook).
        2. **Kịch bản 2 (3.3.2):** Thực thi PowerShell nghi vấn (MSHTA gọi PowerShell qua VBScript).
        3. **Kịch bản 3 (3.3.3):** Kết nối mạng bất thường hoặc nghi vấn C2 (Empire Launcher qua Regsvr32 Squiblydoo).
    *   *Đánh giá kết quả (Mục 3.4 Đề cương):* Đánh giá độ chính xác truy xuất (Precision/Recall), tính đầy đủ, khả năng giải thích, tỷ lệ giảm thiểu ảo giác (Faithfulness/Hallucination), thời gian đáp ứng và khả năng hỗ trợ chuyên viên phân tích SOC.

---

## II. ĐÁNH GIÁ HIỆN TRẠNG MÃ NGUỒN VÀ KHOẢNG TRỐNG KỸ THUẬT

### 1. Những phần đã hoàn thành và đạt chuẩn kiểm định
- **Inspection & Chuẩn hóa Log (Canonical Normalization):**
  - Xử lý thành công 29.510 raw records từ 3 dataset Mordor (`purplesharp_ad_playbook_I`, `empire_launcher_sct_regsvr32`, `cmd_mshta_vbscript_execute_psh`) thành 29.510 canonical events chuẩn `canonical-event/v2` với tỷ lệ mất mát `dropped=0`.
  - Lưu vết SHA-256 nguyên vẹn, đảm bảo tính toàn vẹn chứng cứ số (digital forensics).
- **Lát cắt Kịch bản 2 (MSHTA–PowerShell) - Hoàn thiện mức Core:**
  - Trích xuất bằng chứng (Evidence Extraction): 3 process entities, 2 process_spawn relationships, 2 evidence items, 4 raw references.
  - Sigma Evaluator: 4 observation matches -> 2 behavior matches trên tập log.
  - MITRE Resolver: STIX 2.1 ATT&CK v19.1 exact match `T1218.005` (Mshta), `T1059.007` (JavaScript/VBScript), `T1140` (Deobfuscate/Decode).
  - Knowledge Graph Core: 17 nodes, 21 edges định dạng JSON.
  - Retrieval Corpus: 19 chunks tài liệu bảo mật.
  - Vector Index: Hỗ trợ song song MiniLM và Multilingual E5 (`intfloat/multilingual-e5-small`).
  - Truy xuất Hybrid: BM25 + Cosine Vector + RRF (Reciprocal Rank Fusion).
  - Seed Mapping & Graph Traversal: Ánh xạ câu hỏi vào seed nodes và duyệt lân cận.
  - Bộ 32 Ground Truth Questions & Reference Answers: Đã được review kỹ thuật bởi Codex, phân loại 16 proceed, 8 insufficient_evidence, 8 unrelated.
  - Unit tests: 592 tests passed.

### 2. Các khoảng trống kỹ thuật trọng yếu cần hoàn thiện (Gaps)
1. **Phê duyệt Ground Truth MSHTA:** Bản sửa sau review và 32 đáp án tham chiếu đang ở trạng thái `pending_human_review`, cần người dùng chính thức phê duyệt để làm mốc khóa SHA-256.
2. **Hiệu chuẩn Two-Stage Gate:** Module lọc 2 tầng (Query Topical Relevance -> Evidence Answerability) chưa chọn được Production Policy tối ưu (các lần thử trước trả `no_eligible_policy` do ngưỡng quá ngặt), cần hiệu chuẩn lại để tích hợp vào CLI/Runtime.
3. **Module LLM Generator / Threat Analyst:** Chưa có code kết nối LLM (Local Ollama hoặc API), chưa có bộ Prompt chuẩn hóa có grounding, chưa có schema JSON đầu ra có trích dẫn provenance (`evidence_id`, `technique_id`, `confidence`).
4. **Mở rộng 2 Kịch bản còn lại (PurpleSharp & Regsvr32):** Mới chỉ dừng ở mức normalize log, chưa xây dựng pipeline trích xuất evidence, Sigma match, MITRE mapping, Knowledge Graph, Retrieval Corpus và Ground Truth cho 2 kịch bản này để đạt đủ 3 kịch bản của Mục 3.3 Đề cương.
5. **Giao diện Người dùng (UI Dashboard cho SOC):** Chưa có giao diện đồ họa. Cần một Dashboard trực quan giúp chuyên viên SOC nhập câu hỏi, xem đồ thị tri thức truy vết (Graph visualization) và báo cáo phân tích từ LLM.
6. **Khung đánh giá thực nghiệm (Evaluation Suite):** Chưa có công cụ đo lường tự động so sánh định lượng 3 mô hình (LLM thuần vs Standard RAG vs Hybrid RAG+GraphRAG) để phục vụ số liệu và biểu đồ cho Chương 3 đồ án.

---

## III. CÁC CÔNG NGHỆ, MÃ NGUỒN MỞ VÀ DATASET UY TÍN ĐƯỢC LỰA CHỌN

Theo chỉ đạo của người dùng và tư vấn từ Advisor Argon, dự án sẽ tận dụng tối đa các mã nguồn mở uy tín hàng đầu thế giới:

| Phân hệ | Công nghệ / Nguồn mở đề xuất | Lý do và Giá trị mang lại |
| --- | --- | --- |
| **Log Dataset** | **OTRF Mordor Security Datasets** | Dataset uy tín số 1 thế giới của Open Threat Research Forge, mô phỏng các kỹ thuật tấn công thực tế ghi nhận qua Windows Sysmon và Security Event Logs. |
| **Tri thức ATTT** | **MITRE ATT&CK v19.1 STIX 2.1** & **SigmaHQ Rules** | Cơ sở tri thức chuẩn công nghiệp toàn cầu về chiến thuật/kỹ thuật tấn công và tập luật phát hiện hành vi. |
| **Embeddings** | **`intfloat/multilingual-e5-small`** (chính) & **`all-MiniLM-L6-v2`** (đối chứng) | E5 hỗ trợ xuất sắc cả tiếng Anh và tiếng Việt, ngữ nghĩa sâu, tốc độ suy luận nhanh trên CPU/GPU phổ thông. |
| **Đồ thị tri thức** | **NetworkX** & **Pyvis** | NetworkX tối ưu cho cấu trúc đồ thị, tính toán đường đi, centrality; Pyvis cho phép render đồ thị tương tác HTML (kéo thả, zoom, click xem chi tiết node/edge) cực kỳ trực quan cho SOC. |
| **LLM Backend** | **Ollama** (Llama-3.1-8B-Instruct / Qwen-2.5-7B) & **OpenAI-Compatible API** (LiteLLM / Gemini / GPT) | Cho phép chạy hoàn toàn Offline bảo mật trong mạng nội bộ (On-premise SOC) qua Ollama, đồng thời có thể cắm API cloud mạnh mẽ khi cần. |
| **Giao diện SOC** | **Streamlit** | Framework web nhanh, chuyên nghiệp, hỗ trợ nhúng đồ thị Pyvis, chatbox đa lượt, timeline phân tích và trích xuất báo cáo Markdown/PDF. |
| **Đánh giá RAG** | **RAG Triad Metrics** (Context Relevance, Faithfulness, Answer Relevance) | Bộ tiêu chuẩn đánh giá định lượng khách quan, kiểm chứng khả năng giảm thiểu ảo giác (Hallucination reduction) từ GraphRAG. |

---

## IV. LỘ TRÌNH TRIỂN KHAI CHI TIẾT (6 PHA TUẦN TỰ)

```
[Pha 1: Phê duyệt GT MSHTA & Rebuild]
                 ↓
[Pha 2: Calibrate Two-Stage Gate & Query CLI]
                 ↓
[Pha 3: Tích hợp LLM Connector & Grounded Prompting]
                 ↓
[Pha 4: Mở rộng 2 Kịch bản: PurpleSharp & Regsvr32]
                 ↓
[Pha 5: Xây dựng Web UI Dashboard SOC (Streamlit + Pyvis)]
                 ↓
[Pha 6: Thực nghiệm Đánh giá Định lượng & Soạn Báo cáo]
```

---

### PHA 1: PHÊ DUYỆT GROUND TRUTH MSHTA & REBUILD CONSUMERS
*Thời gian ước tính: 2 - 3 ngày*  
*Mục tiêu:* Đóng gói mốc xuất phát vững chắc cho Kịch bản MSHTA; giải quyết triệt để trạng thái `pending_human_review`.

*   **Nhiệm vụ 1.1: Phê duyệt chính thức Ground Truth MSHTA**
    *   Trình người dùng xác nhận bản sửa `outputs/review/mshta-ground-truth/scenario_ground_truth.json` và 32 đáp án tham chiếu.
    *   Chạy script `sync_ground_truth_v2_consumers.py` để cập nhật trạng thái `approved` kèm chữ ký số và metadata người duyệt.
*   **Nhiệm vụ 1.2: Rebuild Artifacts của Kịch bản MSHTA**
    *   Rebuild Retrieval Corpus (19 chunks) gắn provenance chuẩn xác từ Ground Truth đã duyệt.
    *   Rebuild Knowledge Graph Core (17 nodes, 21 edges).
    *   Rebuild Vector Indexes (ưu tiên `multilingual-e5-small` và `all-MiniLM-L6-v2`).
    *   Kiểm tra tính bất biến của SHA-256 và chạy lại 100% test suite liên quan.
*   **DoD (Tiêu chí hoàn thành):** 
    *   Tất cả consumer artifacts khớp SHA-256 của Ground Truth approved.
    *   Zero test failures trên module MSHTA.

---

### PHA 2: HIỆU CHUẨN TWO-STAGE GATE & TÍCH HỢP QUERY CLI
*Thời gian ước tính: 3 - 4 ngày*  
*Mục tiêu:* Xử lý điểm nghẽn `no_eligible_policy`, chọn ra Policy lọc 2 tầng sản xuất để hệ thống biết từ chối câu hỏi không đủ bằng chứng.

*   **Nhiệm vụ 2.1: Tinh chỉnh không gian tham số hiệu chuẩn (Calibration Search Space)**
    *   Phân tích nguyên nhân `no_eligible_policy`: Tiêu chí acceptance trước đây quá chặt (yêu cầu accuracy 100% trên cả 32 cases).
    *   Mở rộng dải threshold cho Tầng 1 (Topical Relevance - hybrid score cutoff: 0.25 -> 0.65) và Tầng 2 (Evidence Answerability - seed coverage: 1 -> 3 nodes, graph path distance: $\le 2$).
    *   Chạy `calibrate_two_stage_gate.py` với ma trận cấu hình thực tế.
*   **Nhiệm vụ 2.2: Lựa chọn Production Policy**
    *   Chọn policy có cân bằng F1-score tối ưu (tối đa hóa True Proceed trên 16 câu hỏi hợp lệ, chặn 100% câu unrelated và cảnh báo chính xác `insufficient_evidence` trên 8 câu thiếu log).
    *   Ghi nhận policy được chọn vào cấu hình `configs/gate/two_stage_production_policy.json`.
*   **Nhiệm vụ 2.3: Tích hợp Two-Stage Gate vào Query CLI**
    *   Cập nhật `scripts/query_graphrag_context.py` để tự động kích hoạt Two-Stage Gate trước khi trả context.
    *   Đầu ra CLI trả về cấu trúc rõ ràng: `{decision: "proceed" | "abstain", reason: "...", context: {...}, provenance: [...]}`.
*   **DoD:** 
    *   Có ít nhất 1 policy đạt chuẩn production.
    *   Query CLI từ chối trả lời câu hỏi bẫy hoặc câu hỏi ngoài log với thông báo `insufficient_evidence`.

---

### PHA 3: TÍCH HỢP LLM CONNECTOR, GROUNDED PROMPT & CHỐNG ẢO GIÁC
*Thời gian ước tính: 4 - 5 ngày*  
*Mục tiêu:* Hoàn thiện thành phần thứ ba của mô hình: LLM đóng vai trò Chuyên viên phân tích mối đe dọa (SOC Threat Analyst).

*   **Nhiệm vụ 3.1: Xây dựng Module LLM Client Đa năng (`threat_hunting/llm/`)**
    *   Hỗ trợ kiến trúc Adapter linh hoạt:
        *   Local LLM: Kết nối Ollama API (`localhost:11434`) chạy các mô hình mã nguồn mở tiên tiến (`llama3.1:8b`, `qwen2.5:7b-instruct`).
        *   Cloud API: Kết nối qua chuẩn OpenAI API (hỗ trợ OpenAI GPT-4o, Claude 3.5, Gemini 1.5/2.0 Flash) qua biến môi trường.
    *   Tự động quản lý retry, timeout và kiểm soát token budget.
*   **Nhiệm vụ 3.2: Thiết kế Grounded Prompt Engineering chuyên sâu ATTT**
    *   Thiết kế System Prompt đóng vai Chuyên viên SOC Cấp cao: Bắt buộc chỉ suy luận dựa trên Context được cung cấp từ RAG (tài liệu Sigma/MITRE) và GraphRAG (chuỗi sự kiện log).
    *   Quy tắc Grounding nghiêm ngặt: Tuyệt đối không suy đoán hành vi không có trong log. Nếu câu lệnh chỉ là khởi tạo process, không được kết luận tiến trình con đã chạy thành công trừ khi có log tương ứng.
*   **Nhiệm vụ 3.3: Thiết kế Output Schema Chuẩn JSON cho Threat Hunting**
    *   Định dạng đầu ra có cấu trúc máy đọc được:
        ```json
        {
          "threat_verdict": "SUSPICIOUS | MALICIOUS | BENIGN | INSUFFICIENT_DATA",
          "summary": "Tóm tắt ngắn gọn hành vi phát hiện",
          "observed_entities": ["process_id", "command_line", "user", "ip"],
          "attack_chain": [
            {"step": 1, "action": "cmd.exe gọi mshta.exe", "evidence_ref": "EV-001"}
          ],
          "mitre_mapping": [
            {"technique_id": "T1218.005", "technique_name": "Mshta", "confidence": "high", "rationale": "..."}
          ],
          "sigma_matches": ["rule_id_1"],
          "recommended_actions": ["Cô lập tiến trình PID ...", "Rà soát network egress ..."],
          "unverified_hypotheses": ["Chưa có log xác nhận kết quả tải payload qua mạng"]
        }
        ```
*   **Nhiệm vụ 3.4: Bộ linter kiểm tra chống ảo giác (Hallucination Guard)**
    *   Soát chiếu tự động: Mọi `technique_id` và `evidence_ref` trong câu trả lời của LLM phải tồn tại trong tập Context đầu vào. Nếu phát hiện bịa đặt -> gắn cờ cảnh báo.
*   **DoD:** 
    *   Chạy thử nghiệm thành công 32 câu hỏi MSHTA qua LLM.
    *   Tỷ lệ câu trả lời trích dẫn đúng ID bằng chứng đạt $\ge 95\%$.

---

### PHA 4: MỞ RỘNG TOÀN DIỆN PIPELINE CHO 2 KỊCH BẢN CÒN LẠI
*Thời gian ước tính: 7 - 10 ngày*  
*Mục tiêu:* Đạt đầy đủ 3 kịch bản thực nghiệm theo đúng Mục 3.3 của Đề cương KMA.

#### 4.1. Kịch bản 1: Brute Force & Đăng nhập bất thường (PurpleSharp AD Playbook)
*   **Dữ liệu:** `purplesharp_ad_playbook_I_2020-10-22042947.json` (25.993 events).
*   **Hành vi mục tiêu:** Password Spraying (T1110.003) và Kerberoasting (T1558.003) trên Active Directory (Event ID 4625, 4768, 4769).
*   **Công việc cụ thể:**
    *   Xây dựng `threat_hunting/evidence/purplesharp_ad.py`: Trích xuất các thực thể User Account, Source IP, Target Service/SPN, Failure Reason (Status Code 0xC000006A, 0xC0000064).
    *   Tích hợp Sigma Rules cho Password Spraying & Kerberoasting.
    *   Resolve MITRE ATT&CK: `T1110.003` (Brute Force: Password Spraying), `T1558.003` (Steal or Forge Kerberos Tickets: Kerberoasting).
    *   Xây dựng Subgraph PurpleSharp (các node Account, Host, Service, Domain, TicketRequest).
    *   Xây dựng Retrieval Corpus & Vector Index riêng cho kịch bản 1.
    *   Xây dựng tập Ground Truth gồm 20 - 25 câu hỏi thực nghiệm.

#### 4.2. Kịch bản 3: Kết nối mạng bất thường & C2 qua Regsvr32 (Empire Framework)
*   **Dữ liệu:** `empire_launcher_sct_regsvr32_2020-07-21232741.json` (2.390 events).
*   **Hành vi mục tiêu:** Squiblydoo (T1218.010 - Regsvr32 tải file `.sct` độc hại qua mạng) và kết nối C2 (T1071.001 - Web Protocols).
*   **Công việc cụ thể:**
    *   Xây dựng `threat_hunting/evidence/regsvr32_c2.py`: Trích xuất tiến trình `regsvr32.exe`, tham số `/s /u /i:http://... scrobj.dll`, kết nối mạng ra IP C2 ngoài Internet (Sysmon Event ID 1 & 3).
    *   Tích hợp Sigma Rules cho Regsvr32 network connection & scriptlet execution.
    *   Resolve MITRE ATT&CK: `T1218.010` (System Binary Proxy Execution: Regsvr32), `T1071.001` (Application Layer Protocol: Web Protocols).
    *   Xây dựng Subgraph Regsvr32 (các node Process, DLL, RemoteIP, Port, URL).
    *   Xây dựng Retrieval Corpus & Vector Index riêng cho kịch bản 3.
    *   Xây dựng tập Ground Truth gồm 20 - 25 câu hỏi thực nghiệm.

*   **DoD:** 
    *   Hoàn thiện đủ cả 3 kịch bản: Pipeline trích xuất evidence -> Sigma -> MITRE -> Graph -> Vector Index -> Ground Truth.

---

### PHA 5: XÂY DỰNG GIAO DIỆN NGƯỜI DÙNG (UI/DASHBOARD) CHO SOC
*Thời gian ước tính: 4 - 5 ngày*  
*Mục tiêu:* Cung cấp một giao diện web trực quan, hiện đại phục vụ demo báo cáo tốt nghiệp và hỗ trợ chuyên viên SOC điều tra thực tế.

*   **Nhiệm vụ 5.1: Thiết kế Kiến trúc Giao diện Streamlit (`ui/app.py`)**
    *   Khung giao diện chuyên nghiệp cho SOC với 3 tab chức năng:
        1. **Tab 1: Interactive Threat Hunting Chat:** Cho phép chuyên viên nhập câu hỏi điều tra bằng tiếng Việt hoặc tiếng Anh (ví dụ: *"Kiểm tra xem máy trạm có hành vi gọi mshta thực thi script bất thường không?"*, *"Có dấu hiệu password spraying trên domain không?"*).
        2. **Tab 2: Interactive Knowledge Graph Explorer (Pyvis):** Trực quan hóa toàn bộ đồ thị tri thức hoặc đồ thị con (subgraph) liên quan đến câu hỏi. Các node (Process, User, IP, MITRE Technique) có màu sắc và icon phân biệt; cho phép click để xem chi tiết log evidence.
        3. **Tab 3: Evidence & Provenance Inspector:** Bảng đối soát chi tiết từng bản ghi log gốc (raw Sysmon/Security), quy tắc Sigma tương ứng và mã băm SHA-256 xác thực.
*   **Nhiệm vụ 5.2: Tích hợp Realtime Pipeline vào UI**
    *   Khi người dùng gửi câu hỏi -> Kích hoạt Pipeline:
        1. Phân loại câu hỏi qua Two-Stage Gate.
        2. Nếu `proceed` -> Chạy Hybrid Retrieval (RAG) + Graph Traversal (GraphRAG).
        3. Tổng hợp Context và gọi LLM sinh báo cáo phân tích.
        4. Render đồ thị NetworkX sang Pyvis HTML động ngay trên màn hình.
        5. Hiển thị báo cáo phân tích có trích dẫn rõ ràng, nút tải báo cáo Markdown/PDF.
*   **DoD:** 
    *   Ứng dụng Streamlit chạy mượt mà, phản hồi câu hỏi trực quan, hiển thị đồ thị động không lỗi.

---

### PHA 6: THỰC NGHIỆM ĐÁNH GIÁ ĐỊNH LƯỢNG & HOÀN THIỆN THUYẾT MINH ĐỒ ÁN
*Thời gian ước tính: 5 - 7 ngày*  
*Mục tiêu:* Tạo lập toàn bộ số liệu thực nghiệm khoa học cho Mục 3.4 Đề cương và hoàn thiện bản báo cáo Đồ án tốt nghiệp 3 Chương.

*   **Nhiệm vụ 6.1: Thiết kế Kịch bản Đánh giá Định lượng So sánh 3 Mô hình (A/B/C Testing)**
    *   Đánh giá trên toàn bộ tập câu hỏi của cả 3 kịch bản (khoảng 75 - 80 câu hỏi):
        *   **Cấu hình A (Baseline):** LLM thuần (Zero-shot / Direct Prompting không có RAG).
        *   **Cấu hình B (Standard RAG):** LLM kết hợp Vector Search / BM25 thuần túy.
        *   **Cấu hình C (Mô hình Đề xuất):** LLM kết hợp Hybrid RAG + GraphRAG + Two-Stage Gate.
*   **Nhiệm vụ 6.2: Thu thập và Đo lường Bộ Chỉ số Đánh giá (Evaluation Metrics)**
    *   **Độ chính xác truy xuất (Retrieval Accuracy):** Precision@K, Recall@K, Mean Reciprocal Rank (MRR).
    *   **Chất lượng tạo sinh (Generation Quality - RAG Triad):**
        *   *Context Relevance:* Ngữ cảnh truy xuất có sát với câu hỏi không?
        *   *Faithfulness / Groundedness:* Tỷ lệ nội dung trả lời bám sát bằng chứng log (chỉ số chống ảo giác).
        *   *Answer Relevance:* Câu trả lời có giải quyết đúng trọng tâm yêu cầu điều tra của SOC không?
    *   **Khả năng suy luận đa bước (Multi-hop Reasoning):** Tỷ lệ phát hiện đúng chuỗi tấn công liên kết nhiều thực thể (ví dụ: `cmd -> mshta -> powershell -> network connection`).
    *   **Tỷ lệ từ chối đúng (Abstention Accuracy):** Khả năng Two-Stage Gate từ chối câu hỏi thiếu bằng chứng thay vì để LLM bịa chuyện.
    *   **Hiệu năng thời gian:** Latency trung bình trên từng câu hỏi (Retrieval time + LLM Generation time).
*   **Nhiệm vụ 6.3: Xuất Báo cáo Thống kê và Biểu đồ Trực quan**
    *   Tự động sinh các bảng số liệu so sánh và biểu đồ (Matplotlib/Seaborn) lưu vào `outputs/evaluation/`.
*   **Nhiệm vụ 6.4: Hỗ trợ Soạn thảo Thuyết minh Đồ án Tốt nghiệp 3 Chương chuẩn KMA**
    *   Tổng hợp toàn bộ kiến trúc, sơ đồ khối, bảng đặc tả dữ liệu, kết quả thực nghiệm và nhận xét ưu/nhược điểm theo chuẩn văn phong học thuật KMA (sử dụng skill `kma-bao-cao` và template báo cáo).
*   **DoD:** 
    *   Có đầy đủ bảng số liệu và biểu đồ định lượng chứng minh tính ưu việt của mô hình kết hợp RAG + GraphRAG + LLM.
    *   Bản thảo báo cáo Đồ án tốt nghiệp 3 Chương hoàn chỉnh.

---

## V. BẢNG TIẾN ĐỘ THỰC HIỆN VÀ PHÂN CÔNG (GANTT CHART TỔNG HỢP)

| Pha | Nội dung trọng tâm | Đầu ra (Deliverables) | Thời gian dự kiến | Phụ trách chính |
| :---: | :--- | :--- | :---: | :---: |
| **Pha 1** | Phê duyệt GT MSHTA & Rebuild Consumers | Artifacts MSHTA đồng bộ SHA-256, 592+ tests pass | 2 - 3 ngày | PI-Agent (Worker) |
| **Pha 2** | Calibrate Two-Stage Gate & Query CLI | Policy production, CLI lọc câu hỏi thiếu log | 3 - 4 ngày | PI-Agent & Advisor Argon |
| **Pha 3** | Tích hợp LLM Connector & Grounded Prompt | LLM client (Ollama/API), JSON schema có provenance | 4 - 5 ngày | PI-Agent (Worker) |
| **Pha 4** | Mở rộng Kịch bản PurpleSharp & Regsvr32 | Pipeline trích xuất, Graph, Vector, GT cho 2 kịch bản | 7 - 10 ngày | PI-Agent & Advisor Argon |
| **Pha 5** | Xây dựng Web UI Dashboard SOC | Ứng dụng Streamlit + Pyvis tương tác đồ thị & chat | 4 - 5 ngày | PI-Agent (Worker) |
| **Pha 6** | Thực nghiệm Đánh giá & Viết Thuyết minh | Bộ số liệu định lượng, biểu đồ so sánh, báo cáo KMA | 5 - 7 ngày | PI-Agent & Reviewer Luna |

---

## VI. BẢO ĐẢM AN TOÀN, KIỂM SOÁT RỦI RO VÀ NGUYÊN TẮC THỰC THI

1. **Nguyên tắc Provenance Bất biến:** Mọi khẳng định về mối đe dọa trong đồ án đều phải truy vết được về ID bản ghi log gốc trong dataset Mordor. Tuyệt đối không để LLM "tưởng tượng" ra cuộc tấn công.
2. **Quản lý Mã nguồn & Phiên bản:** Sau mỗi pha hoàn thiện, toàn bộ code, test và artifacts sẽ được commit và push lên repository `https://github.com/Agents-Coding-Space/rag-graphrag-threat-hunting` để lưu vết lịch sử minh bạch.
3. **Quy trình Kiểm soát Chất lượng 3 Phân tầng:** 
   - Advisor (Argon) chịu trách nhiệm phản biện và định hướng kiến trúc.
   - PI-Agent thực thi code tuần tự, kiểm thử chặt chẽ qua Pytest.
   - Reviewer kiểm tra độc lập chất lượng và độ an toàn trước khi đóng gói từng mốc.

---

*Kính trình Người dùng (Anh) xem xét và phê duyệt Kế hoạch Tổng thể trên để Đội ngũ Agent bắt đầu triển khai chính thức Pha 1.*
