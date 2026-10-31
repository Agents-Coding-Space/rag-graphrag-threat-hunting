# KẾ HOẠCH KỸ THUẬT VÀ ĐẶC TẢ THỰC THI CHI TIẾT (DEEP-DIVE TECHNICAL MASTER SPECIFICATION)

**Đề tài:** Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT  
**Sinh viên thực hiện:** Nguyễn Hồng Phong — MSV: AT190540 — Lớp: AT19ET  
**Người hướng dẫn:** TS. Phạm Văn Hưởng — Khoa Công nghệ thông tin, Học viện Kỹ thuật Mật mã  
**Hệ thống thiết kế:** PI-Agent phối hợp cùng Advisor Argon (Technical Review & Architecture)  
**Mã nguồn lưu trữ:** `https://github.com/Agents-Coding-Space/rag-graphrag-threat-hunting`  
**Phiên bản:** v2.0 (Deep-Dive Technical Specification)  
**Ngày cập nhật:** 18/10/2026  
**Trạng thái:** Đã qua thẩm định kỹ thuật của Advisor Argon — Trình duyệt triển khai

---

## I. TỔNG QUAN HỆ THỐNG VÀ ÁNH XẠ ĐỀ CƯƠNG HỌC VIỆN KỸ THUẬT MẬT MÃ

Đồ án giải quyết bài toán cốt lõi trong Trung tâm Điều hành An toàn Thông tin (SOC): **Hỗ trợ chuyên viên Threat Hunting tự động liên kết các bằng chứng rải rác từ log hệ thống với tri thức tấn công chuyên ngành (MITRE ATT&CK, Sigma Rules) thông qua mô hình kết hợp RAG + GraphRAG + LLM.**

```
                                  [HỆ THỐNG ĐIỀU TRA THREAT HUNTING]
                                                  │
                 ┌────────────────────────────────┴────────────────────────────────┐
                 ▼                                                                 ▼
      [NGUỒN DỮ LIỆU LOG MORDOR]                                      [CƠ SỞ TRI THỨC BẢO MẬT]
   - Kịch bản 1: PurpleSharp AD (25.993 events)                   - MITRE ATT&CK Enterprise v19.1 STIX 2.1
   - Kịch bản 2: MSHTA-PowerShell (1.127 events)                  - SigmaHQ Detection Rules
   - Kịch bản 3: Empire Regsvr32 C2 (2.390 events)                - CTI Threat Intelligence Reports
                 │                                                                 │
                 ▼                                                                 ▼
      [CANONICAL NORMALIZATION]                                      [KNOWLEDGE GRAPH & RETRIEVAL CORPUS]
   - Schema: canonical-event/v2 (29.510 events)                   - Text Chunks (Sigma + MITRE descriptions)
   - Lưu vết mã băm SHA-256 bất biến                             - Graph Nodes: Process, IP, User, SPN, Technique
                 │                                                                 │
                 └────────────────────────────────┬────────────────────────────────┘
                                                  ▼
                                      [HYBRID RETRIEVAL & GRAPHRAG]
                                  - Tầng 1: BM25 + Multilingual-E5 (RRF Fusion)
                                  - Tầng 2: Seed Mapping + Ego-Network Subgraph
                                  - Two-Stage Gate: Topical Relevance -> Answerability
                                                  │
                                                  ▼
                                      [GROUNDED LLM ANALYST]
                                  - System Prompt Chống Ảo giác (Grounded)
                                  - Pydantic Output Schema (bắt buộc trích dẫn evidence_refs)
                                                  │
                                                  ▼
                                      [GIAO DIỆN SOC DASHBOARD]
                                  - Streamlit Web UI + Pyvis Interactive Graph Explorer
```

### Ánh xạ chi tiết 3 Chương Đề cương v1.2:
*   **Chương 1: Tổng quan về RAG, GraphRAG, LLM và truy tìm mối đe dọa ATTT**
    *   1.1. Bài toán Threat Hunting trong SOC; Nguồn dữ liệu log và tri thức CTI.
    *   1.2. Mô hình ngôn ngữ lớn (LLM): Điểm mạnh (diễn giải tự nhiên) và điểm yếu (hallucination, thiếu tri thức quan hệ đa bước).
    *   1.3. Đồ thị tri thức (Knowledge Graph) và cơ chế GraphRAG; So sánh RAG truyền thống vs GraphRAG.
    *   1.4. Khung giải pháp kết hợp 3 tầng: Vector RAG + GraphRAG + LLM.
*   **Chương 2: Phân tích và thiết kế hệ thống truy tìm mối đe dọa ATTT sử dụng mô hình kết hợp RAG, GraphRAG, LLM**
    *   2.1. Yêu cầu hệ thống, phân tích luồng dữ liệu (Data Pipeline).
    *   2.2. Thiết kế Canonical Event Schema và Knowledge Graph Core Schema cho 3 kịch bản.
    *   2.3. Thiết kế Two-Stage Gate (Lọc câu hỏi lạc đề và câu hỏi thiếu bằng chứng) và cơ chế Grounded Prompting.
*   **Chương 3: Xây dựng, thử nghiệm và đánh giá hệ thống**
    *   3.1. Môi trường triển khai: Python 3.11+, Sentence Transformers, NetworkX, Pyvis, Streamlit, Ollama.
    *   3.2. Hiện thực hóa các module (Extractors, Builders, Two-Stage Gate, LLM Connector).
    *   3.3. Thực nghiệm chuyên sâu trên 3 kịch bản bắt buộc:
        *   3.3.1. Kịch bản Password Spraying & Kerberoasting (PurpleSharp AD).
        *   3.3.2. Kịch bản Thực thi PowerShell nghi vấn qua MSHTA VBScript.
        *   3.3.3. Kịch bản Kết nối mạng bất thường và C2 qua Empire Regsvr32.
    *   3.4. Đánh giá định lượng kết quả: So sánh 3 mô hình (Baseline vs Standard RAG vs Hybrid GraphRAG) theo bộ chỉ số RAG Triad và Security Metrics.

---

## II. ĐẶC TẢ KỸ THUẬT DỮ LIỆU & PIPELINE CHO 3 KỊCH BẢN THỰC NGHIỆM

Hệ thống xử lý trực tiếp từ các file dataset OTRF Mordor đã được chuẩn hóa sang định dạng `canonical-event/v2` (tổng cộng 29.510 records, `dropped=0`), giữ nguyên SHA-256 để bảo đảm tính toàn vẹn chứng cứ số.

### 1. Kịch bản 1: Brute Force & Đăng nhập bất thường (PurpleSharp Active Directory)
*   **Dữ liệu đầu vào:** `purplesharp_ad_playbook_I_2020-10-22042947.json` (25.993 canonical events).
*   **Event ID mục tiêu và ý nghĩa pháp y:**
    *   `Security ID 4625`: An account failed to log on. Trích xuất: `TargetUserName`, `WorkstationName`, `IpAddress`, `SubStatus` (0xC000006A: Sai mật khẩu; 0xC0000064: Tài khoản không tồn tại).
    *   `Security ID 4768`: A Kerberos authentication ticket (TGT) was requested. Trích xuất: `TargetUserName`, `ResultCode` (0x18: Pre-authentication failed).
    *   `Security ID 4769`: A Kerberos service ticket was requested. Trích xuất: `ServiceName` (SPN), `TicketEncryptionType` (0x17: RC4-HMAC — dấu hiệu đặc trưng của kỹ thuật Kerberoasting).
*   **Thuật toán Correlator / Time-Window Clustering:**
    *   *Password Spraying:* Quét trượt cửa sổ thời gian $W = 300\text{s}$. Gom nhóm theo `IpAddress`/`WorkstationName`. Nếu số lượng `TargetUserName` khác nhau bị lỗi xác thực $\ge 5$ tài khoản $\rightarrow$ Khẳng định hành vi Password Spraying (`T1110.003`).
    *   *Kerberoasting:* Quét trượt $W = 120\text{s}$. Lọc các yêu cầu Event 4769 có `TicketEncryptionType == 0x17` với danh sách SPN dịch vụ có đặc quyền $\rightarrow$ Khẳng định hành vi Kerberoasting (`T1558.003`).
*   **Đặc tả Schema Node & Edge cho Subgraph PurpleSharp:**
    *   *Nodes:*
        *   `Account`: `{id: "user:phong.nh", name: "phong.nh", domain: "CORP"}`
        *   `Host`: `{id: "host:WS01", hostname: "WS01", ip: "192.168.1.50"}`
        *   `SPN`: `{id: "spn:MSSQLSvc/db01.corp", service: "MSSQLSvc"}`
        *   `Technique`: `{id: "technique:T1110.003", name: "Password Spraying"}`
    *   *Edges:*
        *   `ATTEMPTS_LOGIN`: `(Host) -> (Account)` kèm `{fail_count: 8, window_sec: 300, sub_status: "0xC000006A"}`
        *   `REQUESTS_TICKET`: `(Account) -> (SPN)` kèm `{encryption: "RC4-HMAC", ticket_options: "0x40810000"}`
        *   `ASSOCIATED_WITH`: `(ATTEMPTS_LOGIN) -> (Technique)`

### 2. Kịch bản 2: Thực thi PowerShell nghi vấn qua MSHTA VBScript
*   **Dữ liệu đầu vào:** `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json` (1.127 canonical events).
*   **Chuỗi tiến trình mục tiêu (Process Lineage):**
    `cmd.exe` (PID 5440) $\rightarrow$ gọi `mshta.exe` (PID 3624) với tham số VBScript inline $\rightarrow$ sinh tiến trình con `powershell.exe` (PID 4428).
*   **Thuật toán Xử lý Lệch Thời gian (Timestamp Conflict Resolution):**
    *   Sysmon Event 1 và Security Event 4688 trên máy Windows thường có độ trễ hoặc lệch múi giờ cục bộ (trong dataset ghi nhận lệch khoảng 4 giờ).
    *   *Giải pháp:* Không dùng quan hệ timestamp tuyệt đối làm khóa chính. Sử dụng thuật toán `ProcessCorrelationKey`:
        $$\text{Key} = \text{Hash}(ProcessName + CommandLine + ParentProcessGuid + ParentProcessId)$$
        Sau đó chuẩn hóa toàn bộ `UtcTime` sang chuẩn ISO 8601 UTC trước khi tính delta time.
*   **MITRE ATT&CK Mapping:**
    *   `T1218.005`: Mshta (Trạng thái: `supported_by_observed_behavior`).
    *   `T1059.007`: JavaScript/VBScript (Lệnh inline chứa VBScript syntax).
    *   `T1140`: Deobfuscate/Decode Files or Information (Lệnh PowerShell giải mã payload).

### 3. Kịch bản 3: Kết nối mạng bất thường & C2 qua Empire Regsvr32 (Squiblydoo)
*   **Dữ liệu đầu vào:** `empire_launcher_sct_regsvr32_2020-07-21232741.json` (2.390 canonical events).
*   **Event ID mục tiêu và Regex Parser:**
    *   `Sysmon Event 1` (Process Creation): Bắt lệnh `regsvr32.exe`.
        Regex phân tích command line:
        `r"(?i)regsvr32(\.exe)?\s+.*(/s|/u|/n|/i:(?P<url>https?://[^\s]+))\s+(?P<dll>scrobj\.dll)?"`
        Trích xuất URL tải scriptlet `.sct` độc hại và DLL liên kết.
    *   `Sysmon Event 3` (Network Connect): Bắt kết nối mạng do `regsvr32.exe` khởi tạo.
        Trích xuất: `Image`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort` (thường là 80/443 hoặc port C2 8080/8443).
*   **Đặc tả Schema Node & Edge cho Subgraph Regsvr32:**
    *   *Nodes:*
        *   `Process`: `{id: "proc:regsvr32_pid3820", image: "regsvr32.exe", pid: 3820}`
        *   `RemoteEndpoint`: `{id: "net:192.168.100.5:8080", ip: "192.168.100.5", port: 8080}`
        *   `ScriptletPayload`: `{id: "url:http://192.168.100.5/launcher.sct", url: "..."}`
        *   `Technique`: `{id: "technique:T1218.010", name: "Regsvr32"}`
    *   *Edges:*
        *   `INITIATED_CONNECTION`: `(Process) -> (RemoteEndpoint)`
        *   `DOWNLOADED_PAYLOAD`: `(Process) -> (ScriptletPayload)`
        *   `EXHIBITS_TECHNIQUE`: `(Process) -> (Technique)`

---

## III. THUẬT TOÁN TWO-STAGE GATE (CƠ CHẾ LỌC CÂU HỎI 2 TẦNG)

Hiện tượng `no_eligible_policy` trong 2 đợt chạy thử nghiệm trước đó là do: **Không gian tìm kiếm 672 cấu hình áp dụng tiêu chí chấp nhận đơn mục tiêu quá cứng nhắc (yêu cầu 0 false proceed VÀ 0 false abstain trên toàn bộ 32 cases).** Khi người dùng đặt câu hỏi hơi rộng, hybrid score của câu hỏi bị rớt nhẹ dưới ngưỡng cắt mặc dù đồ thị có bằng chứng.

```
                  [CÂU HỎI TỪ CHUYÊN VIÊN SOC]
                               │
                               ▼
            ┌──────────────────────────────────────┐
            │   TẦNG 1: TOPICAL RELEVANCE GATE     │
            │  (Đánh giá độ liên quan miền ATTT)   │
            └──────────────────┬───────────────────┘
                               │
                RRF_Score < 0.015? ──► [TỪ CHỐI: "unrelated"]
                               │
                               ▼
            ┌──────────────────────────────────────┐
            │  TẦNG 2: EVIDENCE ANSWERABILITY GATE │
            │ (Kiểm tra đồ thị có đủ log chứng minh)│
            └──────────────────┬───────────────────┘
                               │
            Coverage_Ratio < 0.40? ──► [CẢNH BÁO: "insufficient_evidence"]
                               │
                               ▼
                   [CHO PHÉP: "proceed"]
                 (Chuyển sang RAG + LLM)
```

### 1. Thuật toán Tầng 1: Topical Relevance Gate
*   **Đầu vào:** Câu hỏi $q$, tập corpus $D$ gồm 19 chunks tài liệu Sigma + MITRE.
*   **Phương pháp:** Tính điểm kết hợp Reciprocal Rank Fusion (RRF) giữa Lexical BM25 và Vector Cosine (`multilingual-e5-small`):
    $$RRF\_Score(d, q) = \frac{1}{60 + \text{Rank}_{BM25}(d, q)} + \frac{1}{60 + \text{Rank}_{E5}(d, q)}$$
*   **Ngưỡng hiệu chuẩn mới (Relaxed Threshold):**
    *   Nếu $\max_{d \in D} RRF\_Score(d, q) < \theta_{topical} = 0.015$:
        $\rightarrow$ **Quyết định:** `unrelated` (Câu hỏi không liên quan đến an toàn thông tin hoặc log hệ thống, ví dụ: *"Thời tiết hôm nay thế nào?"*). Hệ thống dừng ngay, không gọi LLM để tiết kiệm chi phí.

### 2. Thuật toán Tầng 2: Evidence Answerability Gate
*   **Đầu vào:** Câu hỏi $q$, tập seed nodes $S_q$ thu được từ Tầng 1, Đồ thị tri thức $G = (V, E)$.
*   **Phương pháp:**
    *   Trích xuất $k$-hop Ego-Network từ $S_q$ (với $k = 2$).
    *   Xác định tập thực thể bắt buộc cần để trả lời (Required Entities in Query $E_{req}$, ví dụ: process name, user, IP, technique ID).
    *   Tính tỷ lệ bao phủ bằng chứng thực nghiệm (Evidence Coverage Ratio):
        $$\text{Coverage\_Ratio} = \frac{|V_{subgraph} \cap E_{req}|}{|E_{req}|}$$
*   **Ngưỡng hiệu chuẩn mới:**
    *   Nếu $\text{Coverage\_Ratio} < \theta_{evidence} = 0.40$ hoặc không tìm thấy quan hệ log kết nối giữa các thực thể:
        $\rightarrow$ **Quyết định:** `insufficient_evidence` (Log có thể có nhắc đến tên tiến trình nhưng không có bằng chứng chứng minh hành vi con, ví dụ: *"Cmdlet nào đã chạy thành công bên trong PowerShell?"*).
    *   Nếu $\text{Coverage\_Ratio} \ge 0.40$ và có ít nhất 1 chuỗi quan hệ:
        $\rightarrow$ **Quyết định:** `proceed` (Đủ bằng chứng để LLM phân tích).

---

## IV. THIẾT KẾ MODULE LLM, GROUNDED PROMPTING & CHỐNG ẢO GIÁC

Module được tổ chức tại `src/threat_hunting/llm/`.

### 1. Pydantic Output Schema (`src/threat_hunting/llm/schema.py`)
Mọi đầu ra của LLM bắt buộc phải tuân theo cấu trúc JSON định kiểu chặt chẽ:

```python
from pydantic import BaseModel, Field
from typing import List, Literal, Optional

class AttackStep(BaseModel):
    step_number: int = Field(..., description="Thứ tự bước trong chuỗi tấn công")
    source_entity: str = Field(..., description="Thực thể nguồn (ví dụ: cmd.exe PID 5440)")
    action: str = Field(..., description="Hành vi thực hiện (ví dụ: spawn process, network connect)")
    target_entity: str = Field(..., description="Thực thể đích (ví dụ: mshta.exe PID 3624)")
    evidence_ref: str = Field(..., description="Mã tham chiếu bằng chứng log (ví dụ: EV-MSHTA-001)")

class MitreTechniqueMatch(BaseModel):
    technique_id: str = Field(..., description="Mã kỹ thuật MITRE (ví dụ: T1218.005)")
    technique_name: str = Field(..., description="Tên kỹ thuật")
    confidence: Literal["confirmed", "supported_by_observed_behavior", "candidate"]
    rationale: str = Field(..., description="Lý giải căn cứ vào bằng chứng log nào")

class ThreatHuntingReport(BaseModel):
    verdict: Literal["MALICIOUS", "SUSPICIOUS", "BENIGN", "INSUFFICIENT_EVIDENCE"]
    executive_summary: str = Field(..., description="Tóm tắt ngắn gọn 2-3 câu cho chỉ huy SOC")
    technical_analysis: str = Field(..., description="Phân tích chi tiết chuỗi hành vi")
    attack_chain: List[AttackStep] = Field(default_factory=list, description="Chuỗi bước tấn công có log")
    mitre_mappings: List[MitreTechniqueMatch] = Field(default_factory=list)
    sigma_matches: List[str] = Field(default_factory=list, description="ID các rule Sigma khớp")
    containment_recommendations: List[str] = Field(..., description="Khuyến nghị cô lập và xử lý")
    unverified_claims: List[str] = Field(
        default_factory=list, 
        description="Các điểm nghi vấn chưa thể khẳng định do thiếu log bổ trợ"
    )
```

### 2. Grounded System Prompt Chuyên sâu ATTT
```text
[VAI TRÒ VÀ NGUYÊN TẮC TỐI THƯỢNG]
Bạn là Senior SOC Threat Hunting Analyst hoạt động trong môi trường giám sát an ninh mạng thực tế.
Nhiệm vụ của bạn là phân tích và kết luận về các mối đe dọa an toàn thông tin.

[NGUYÊN TẮC BẰNG CHỨNG - BẮT BUỘC TUÂN THỦ 100%]
1. CHỈ KẾT LUẬN KHI CÓ BẰNG CHỨNG (ZERO-ASSUMPTION POLICY):
   - Mọi thực thể (Process, IP, User, File) và hành vi tấn công được nêu trong báo cáo BẮT BUỘC phải trích xuất trực tiếp từ [CONTEXT PHÁP Y] được cung cấp.
   - TUYỆT ĐỐI CẤM suy đoán những gì log không ghi nhận. Ví dụ: Nếu log chỉ có lệnh gọi `powershell.exe`, CẤM TUYỆT ĐỐI kết luận rằng payload bên trong PowerShell đã chạy thành công hoặc đã tải mã độc thành công, trừ khi có log ghi nhận network traffic hoặc script block logging tương ứng.
2. TRÍCH DẪN MÃ BẰNG CHỨNG (EVIDENCE CITATION):
   - Mỗi bước trong `attack_chain` bắt buộc phải kèm theo trường `evidence_ref` chính xác.
3. KHI THIẾU BẰNG CHỨNG:
   - Nếu câu hỏi yêu cầu phân tích một khía cạnh mà Context không đủ dữ liệu, bạn BẮT BUỘC phải ghi nhận điểm đó vào trường `unverified_claims` và đặt trạng thái là `INSUFFICIENT_EVIDENCE`, không được cố gắng trả lời bịa đặt.
4. ĐỊNH DẠNG ĐẦU RA:
   - Chỉ xuất ra định dạng JSON thuần khớp 100% với Pydantic Schema đã quy định. Không thêm lời chào, không văn phong giải thích ngoài khối JSON.
```

### 3. Thuật toán Kiểm tra Chống Ảo giác Tự động (Hallucination Validator)
Trước khi trả kết quả cho người dùng hoặc giao diện, hệ thống chạy hàm kiểm định:
*   Bóc tách toàn bộ danh sách `[IP, Process, Port, Username, Technique_ID]` có trong câu trả lời JSON của LLM.
*   Đối soát với tập Node $V$ của Subgraph và tập Event log gốc.
*   Nếu phát hiện bất kỳ thực thể nào có trong JSON nhưng **hoàn toàn không tồn tại** trong Context $\rightarrow$ Hủy bỏ câu trả lời, ghi nhận vi phạm ảo giác và tự động sinh cảnh báo: `[HALLUCINATION_DETECTED: Entity X was fabricated]`.

---

## IV. GIAO DIỆN NGƯỜI DÙNG WEB DASHBOARD CHO SOC (STREAMLIT + PYVIS)

Module được xây dựng tại: `src/threat_hunting/ui/app.py`.

```
┌───────────────────────────────────────────────────────────────────────────────┐
│ SOC THREAT HUNTING WORKBENCH — RAG + GRAPHRAG + LLM ASSISTANT                 │
├───────────────────────────────────────────────────────────────────────────────┤
│ [TAB 1: THREAT HUNTING CHAT]  [TAB 2: GRAPH EXPLORER]  [TAB 3: LOG PROVENANCE]│
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│ 🧑‍💻 Analyst: "Kiểm tra máy trạm có hành vi gọi mshta thực thi script không?" │
│                                                                               │
│ 🤖 Assistant (Two-Stage Gate: PROCEED | Confidence: 94.5%):                  │
│    ┌───────────────────────────────────────────────────────────────────────┐  │
│    │ 🔴 VERDICT: MALICIOUS EXECUTION DETECTED                              │  │
│    │ Tóm tắt: Phát hiện chuỗi tiến trình cmd.exe gọi mshta.exe thực thi    │  │
│    │ lệnh VBScript inline và sinh tiến trình powershell.exe mã hóa.        │  │
│    │                                                                       │  │
│    │ 📌 Attack Chain:                                                      │  │
│    │ 1. cmd.exe (PID 5440) -> mshta.exe (PID 3624) [Evidence: EV-001]      │  │
│    │ 2. mshta.exe -> powershell.exe (PID 4428) [Evidence: EV-002]          │  │
│    │                                                                       │  │
│    │ 🛡️ MITRE ATT&CK: T1218.005 (Mshta), T1059.007 (VBScript)              │  │
│    │ ⚡ Sigma Matches: proc_creation_win_mshta_powershell                   │  │
│    │ ⚠️ Unverified: Chưa có log xác nhận cmdlet hoàn thành hay egress C2.  │  │
│    └───────────────────────────────────────────────────────────────────────┘  │
│                                                                               │
│ [Interactive Graph Visualization Canvas (Pyvis HTML rendered below)]          │
│ (cmd.exe) ──spawn──> (mshta.exe) ──spawn──> (powershell.exe)                 │
│      │                     │                                                 │
│      └──[T1059.003]        └──[T1218.005]                                    │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Kiến trúc chi tiết các Tab trong UI:
1.  **Tab 1: Interactive Threat Hunting Chat:**
    *   Cho phép nhập truy vấn tiếng Việt/tiếng Anh.
    *   Hiển thị huy hiệu trạng thái của Two-Stage Gate (`Proceed`, `Insufficient Evidence`, `Unrelated`).
    *   Trình bày báo cáo phân tích mối đe dọa với màu sắc phân cấp nguy cơ (Đỏ: Malicious, Vàng: Suspicious, Xanh: Benign).
2.  **Tab 2: Interactive Knowledge Graph Explorer (Pyvis):**
    *   Chuyển đổi NetworkX subgraph thành mạng đồ thị HTML tương tác bằng Pyvis.
    *   Tự động gán màu và icon: Node Process (Xanh lam), Node IP (Cam), Node Account (Tím), Node MITRE Technique (Đỏ).
    *   Cho phép zoom, kéo thả, click vào từng node/edge để hiển thị popup chứa nội dung raw log tương ứng.
3.  **Tab 3: Evidence & Provenance Inspector:**
    *   Bảng tra cứu đối soát bản ghi log: Event ID, UtcTime, ComputerName, Raw SHA-256.
    *   Nút trích xuất báo cáo vụ việc ra file Markdown và PDF chuẩn báo cáo điều tra sự cố.

---

## V. KHUNG ĐÁNH GIÁ THỰC NGHIỆM ĐỊNH LƯỢNG (EVALUATION SUITE)

Để phục vụ toàn bộ số liệu khoa học cho **Mục 3.4 của Đề cương**, hệ thống xây dựng bộ kiểm thử định lượng tự động so sánh **3 cấu hình mô hình**:
*   **Mô hình A (Baseline):** LLM thuần (Llama-3.1-8B Zero-shot không có RAG).
*   **Mô hình B (Standard RAG):** LLM kết hợp Vector Search (BM25 + Cosine) thuần túy.
*   **Mô hình C (Mô hình Đề xuất):** LLM kết hợp Hybrid RAG + GraphRAG Subgraph + Two-Stage Gate.

### 1. Bộ 75 Câu hỏi Đánh giá Ground Truth (Benchmark Dataset)
Bộ câu hỏi được chia đều cho 3 kịch bản thực nghiệm (mỗi kịch bản 25 câu hỏi):
*   **12 câu hỏi Hợp lệ (Proceed):** Yêu cầu phân tích hành vi có đầy đủ log minh chứng.
*   **7 câu hỏi Thiếu bằng chứng (Insufficient Evidence):** Các câu hỏi bẫy hỏi về kết quả cmdlet, file bị xóa, hoặc lưu lượng mạng mà log không ghi nhận.
*   **6 câu hỏi Không liên quan (Unrelated):** Các câu hỏi ngoài phạm vi an ninh mạng hoặc hỏi về phần mềm không có trong hệ thống.

### 2. Các chỉ số đo lường định lượng khoa học:
1.  **Context Relevance (Độ liên quan ngữ cảnh):**
    $$\text{Context Relevance} = \frac{|\text{Các câu log/tri thức chứa thông tin cần thiết}|}{|\text{Tổng số câu trong Context đưa vào LLM}|}$$
2.  **Faithfulness / Groundedness (Độ trung thực - Chỉ số chống ảo giác):**
    $$\text{Faithfulness} = \frac{|\text{Số lượng nhận định của LLM được chứng minh bởi log}|}{|\text{Tổng số nhận định do LLM sinh ra}|}$$
    *(Mô hình đề xuất kỳ vọng đạt $\ge 95\%$, trong khi Baseline LLM thường dưới $60\%$ do bị ảo giác).*
3.  **Mitre Technique Exact Match (Độ chính xác ánh xạ MITRE):**
    Tỷ lệ F1-Score trong việc gán đúng các mã kỹ thuật ATT&CK so với Ground Truth.
4.  **Multi-hop Reasoning Accuracy (Độ chính xác suy luận đa bước):**
    Khả năng liên kết đúng toàn bộ chuỗi tiến trình cha - con - cháu và tương quan IP mạng.
5.  **Abstention Accuracy (Độ chính xác từ chối câu hỏi thiếu bằng chứng):**
    Tỷ lệ phần trăm hệ thống trả lời chính xác `insufficient_evidence` trên các câu hỏi bẫy thay vì đoán mò.

---

## VI. CẤU TRÚC THUYẾT MINH ĐỒ ÁN TỐT NGHIỆP 3 CHƯƠNG CHUẨN KMA

Toàn văn báo cáo đồ án tốt nghiệp sẽ được hoàn thiện theo đúng cấu trúc đề cương v1.2 và quy chuẩn định dạng của Học viện Kỹ thuật Mật mã:

```text
LỜI CẢM ƠN
MỤC LỤC
DANH MỤC CÁC KÝ HIỆU VÀ CHỮ VIẾT TẮT
DANH MỤC CÁC HÌNH VẼ
DANH MỤC CÁC BẢNG BIỂU

MỞ ĐẦU
1. Tính cấp thiết của đề tài
2. Mục tiêu nghiên cứu và đối tượng áp dụng
3. Phạm vi nghiên cứu và phương pháp luận
4. Bố cục của đồ án

CHƯƠNG 1: TỔNG QUAN VỀ RAG, GRAPHRAG, LLM VÀ TRUY TÌM MỐI ĐE DỌA ATTT
1.1. Bài toán truy tìm mối đe dọa an toàn thông tin
  1.1.1. Khái niệm và vai trò của truy tìm mối đe dọa trong SOC
  1.1.2. Nguồn tri thức và dữ liệu phục vụ phân tích mối đe dọa (Log, Sigma, MITRE ATT&CK)
1.2. Mô hình ngôn ngữ lớn và kỹ thuật RAG
  1.2.1. Khả năng và hạn chế của LLM trong miền an toàn thông tin
  1.2.2. Kiến trúc và quy trình hoạt động của Retrieval-Augmented Generation (RAG)
  1.2.3. Vai trò của RAG trong việc bổ sung tri thức bảo mật chuyên ngành
1.3. Đồ thị tri thức và GraphRAG
  1.3.1. Biểu diễn tri thức an toàn thông tin dưới dạng đồ thị (Knowledge Graph)
  1.3.2. Cơ chế truy xuất quan hệ đa bước trong GraphRAG
  1.3.3. So sánh đối chiếu RAG truyền thống và GraphRAG trong bối cảnh phân tích an ninh
1.4. Giải pháp kết hợp LLM, RAG, GraphRAG để truy tìm mối đe dọa ATTT
  1.4.1. Sự cần thiết của việc kết hợp mô hình đa tầng
  1.4.2. Khung ý tưởng ứng dụng mô hình kết hợp trong hỗ trợ chuyên viên SOC

CHƯƠNG 2: PHÂN TÍCH VÀ THIẾT KẾ HỆ THỐNG TRUY TÌM MỐI ĐE DỌA ATTT SỬ DỤNG MÔ HÌNH KẾT HỢP
2.1. Phân tích bài toán và thiết kế kiến trúc
  2.1.1. Phạm vi, đối tượng và yêu cầu chức năng/phi chức năng của hệ thống
  2.1.2. Kiến trúc tổng thể của hệ thống (Pipeline RAG + GraphRAG + LLM)
  2.1.3. Luồng xử lý dữ liệu và quy trình điều tra mối đe dọa
2.2. Thiết kế dữ liệu và cơ sở tri thức
  2.2.1. Thu thập và chuẩn hóa dữ liệu log theo chuẩn Canonical Event v2
  2.2.2. Xây dựng nguồn tri thức từ MITRE ATT&CK v19.1 STIX 2.1, SigmaHQ và CTI Reports
  2.2.3. Thiết kế Schema đồ thị tri thức đa thực thể phục vụ truy tìm mối đe dọa
2.3. Thiết kế mô hình phân tích kết hợp RAG, GraphRAG và LLM
  2.3.1. Thiết kế RAG pipeline (Lexical BM25 kết hợp Dense Embedding E5)
  2.3.2. Thiết kế GraphRAG pipeline (Seed mapping và Ego-network traversal)
  2.3.3. Cơ chế phối hợp truy xuất và bộ lọc Two-Stage Gate (Topical Relevance & Answerability)
  2.3.4. Thiết kế Grounded Prompt Engineering và JSON Output Schema có trích dẫn bằng chứng

CHƯƠNG 3: XÂY DỰNG, THỬ NGHIỆM VÀ ĐÁNH GIÁ HỆ THỐNG
3.1. Môi trường triển khai và dữ liệu thực nghiệm
  3.1.1. Công nghệ và công cụ sử dụng (Python, Sentence Transformers, NetworkX, Streamlit, Ollama)
  3.1.2. Bộ dữ liệu log Mordor và nguồn tri thức thực nghiệm
3.2. Xây dựng các thành phần của hệ thống
  3.2.1. Module xử lý log và trích xuất thực thể theo kịch bản
  3.2.2. Module RAG, GraphRAG và Two-Stage Gate
  3.2.3. Module phân tích kết quả bằng LLM và Giao diện Web SOC Dashboard
3.3. Thực nghiệm trên các kịch bản truy tìm mối đe dọa
  3.3.1. Kịch bản brute force và đăng nhập bất thường (PurpleSharp Active Directory)
  3.3.2. Kịch bản thực thi PowerShell nghi vấn qua MSHTA VBScript
  3.3.3. Kịch bản kết nối mạng bất thường và C2 qua Empire Regsvr32
3.4. Đánh giá kết quả thực nghiệm
  3.4.1. Đánh giá kết quả truy tìm mối đe dọa của hệ thống trên 3 kịch bản
  3.4.2. Đánh giá độ chính xác, tính đầy đủ và khả năng giải thích (RAG Triad Metrics)
  3.4.3. Đánh giá khả năng hỗ trợ chuyên viên phân tích an toàn thông tin
  3.4.4. Nhận xét ưu điểm, hạn chế và hướng phát triển tiếp theo

KẾT LUẬN VÀ KIẾN NGHỊ
TÀI LIỆU THAM KHẢO
PHỤ LỤC (Code chính, Bộ quy tắc Sigma, Bảng Ground Truth 75 câu hỏi)
```

---

## VII. LỘ TRÌNH THỰC HIỆN VÀ PHÂN BỔ CÔNG VIỆC THEO 6 PHA

```
[Pha 1: Phê duyệt GT MSHTA & Rebuild Artifacts] ──► [Pha 2: Calibrate Gate & Query CLI]
                                                                  │
                                                                  ▼
[Pha 4: Mở rộng PurpleSharp & Regsvr32] ◄── [Pha 3: Tích hợp LLM Connector & Prompt]
                 │
                 ▼
[Pha 5: Xây dựng SOC Dashboard (Streamlit)] ──► [Pha 6: Thực nghiệm Định lượng & Soạn Báo cáo]
```

*   **Pha 1: Phê duyệt Ground Truth MSHTA & Rebuild Consumers (2 - 3 ngày)**
    *   Chốt duyệt bản `scenario_ground_truth.json` và 32 câu hỏi MSHTA.
    *   Rebuild đồng bộ Corpus, Graph và Vector Index (`multilingual-e5-small`), bảo đảm 100% tests pass.
*   **Pha 2: Hiệu chuẩn Two-Stage Gate & Tích hợp Query CLI (3 - 4 ngày)**
    *   Áp dụng ngưỡng relaxed Pareto ($\theta_{topical} = 0.015, \theta_{evidence} = 0.40$), giải quyết lỗi `no_eligible_policy`.
    *   Tích hợp trực tiếp Gate vào `scripts/query_graphrag_context.py`.
*   **Pha 3: Tích hợp LLM Connector, Grounded Prompting & Chống Ảo giác (4 - 5 ngày)**
    *   Hiện thực hóa Client kết nối Ollama/OpenAI API.
    *   Áp dụng Pydantic Schema `ThreatHuntingReport` và bộ lọc chống ảo giác.
*   **Pha 4: Mở rộng Toàn diện Pipeline cho 2 Kịch bản còn lại (7 - 10 ngày)**
    *   *PurpleSharp:* Xây dựng extractor cho Event 4625/4769, Sigma match, MITRE T1110.003/T1558.003, Subgraph và 25 câu hỏi GT.
    *   *Regsvr32:* Xây dựng extractor cho Event 1/3, Regex URL, Sigma match, MITRE T1218.010/T1071.001, Subgraph và 25 câu hỏi GT.
*   **Pha 5: Xây dựng Giao diện Người dùng Web Dashboard cho SOC (4 - 5 ngày)**
    *   Hoàn thiện ứng dụng Streamlit với 3 Tab (Chat, Interactive Graph Explorer Pyvis, Log Provenance).
*   **Pha 6: Thực nghiệm Đánh giá Định lượng & Soạn Thuyết minh Đồ án (5 - 7 ngày)**
    *   Đo lường tự động A/B/C testing trên 75 câu hỏi benchmark.
    *   Xuất bảng số liệu, biểu đồ so sánh và hoàn thiện bản thảo thuyết minh 3 Chương chuẩn KMA.

---

*Toàn bộ đặc tả kỹ thuật trên đã được Advisor Argon thẩm định, phản biện và phê duyệt tính khả thi. Kính trình Anh (Người dùng) xem xét và phê duyệt để Đội ngũ Agent bắt đầu triển khai Pha 1.*
