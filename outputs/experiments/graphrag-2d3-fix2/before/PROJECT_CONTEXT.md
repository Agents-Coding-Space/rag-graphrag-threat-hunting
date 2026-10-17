# HỒ SƠ TRẠNG THÁI ĐỒ ÁN TỐT NGHIỆP

**Cập nhật gần nhất:** 14/10/2026

**Sinh viên:** Nguyễn Hồng Phong  
**Mã sinh viên:** AT190540  
**Lớp theo đề cương chính thức:** AT19ET  
**Ngành:** An toàn thông tin - Mã ngành 7.48.02.02  
**Cơ sở đào tạo:** Học viện Kỹ thuật Mật mã  
**Giảng viên hướng dẫn:** TS. Phạm Văn Hưởng, Khoa Công nghệ thông tin  
**Tên đề tài hiện tại:** **Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT**

> Tài liệu này là hồ sơ làm việc thống nhất để tiếp tục đồ án. Khi có xung đột, ưu tiên theo thứ tự: văn bản chính thức mới nhất → tài liệu mô hình/triển khai → quyết định rõ ràng của sinh viên trong trao đổi → đề xuất tham khảo. Các lựa chọn chưa được chốt được ghi riêng, không coi là phần đã hoàn thành.

## 1. Phạm vi được xác nhận

Đồ án hiện tại tập trung xây dựng và đánh giá một **hệ thống/trợ lý hỗ trợ truy tìm mối đe dọa an toàn thông tin** bằng cách kết hợp:

- **RAG:** truy xuất tài liệu và tri thức bảo mật có liên quan.
- **GraphRAG:** truy xuất các quan hệ nhiều bước giữa thực thể trong log và tri thức bảo mật.
- **LLM:** tổng hợp ngữ cảnh, phân tích, diễn giải, ánh xạ MITRE ATT&CK và gợi ý điều tra.

Đồ án **không nhằm huấn luyện lại LLM**. LLM được dùng như thành phần phân tích và sinh câu trả lời dựa trên ngữ cảnh đã được truy xuất.

**Hiện trạng ngày 14/10/2026:** đã có pipeline chuẩn hóa cả ba dataset và prototype retrieval RAG/GraphRAG cho lát cắt MSHTA–PowerShell. Ground truth và 32 đáp án tham chiếu đã được review kỹ thuật, vẫn chờ người dùng duyệt. Gate hai tầng mới có module và tests; chưa tích hợp CLI hoặc có policy production được kiểm chứng. Chưa có LLM sinh câu trả lời, giao diện hay database service.

Các dự án NIDS/CIC-IDS-2017, SOC lab, Solana, Hyperledger Fabric/OpenSSL và IAM/Keycloak **không thuộc phạm vi đồ án hiện tại**, trừ khi sau này sinh viên đưa ra quyết định tích hợp rõ ràng. Trong đó, dự án học sâu chống truy cập mạng trái phép hiện được xem là một dự án riêng, không gộp vào đề tài RAG/GraphRAG/LLM.

## 2. Bài toán và lý do chọn đề tài

- Threat Hunting cần chủ động tìm hành vi tấn công có thể chưa bị cơ chế cảnh báo truyền thống phát hiện.
- Dữ liệu log, cảnh báo và tài liệu tình báo mối đe dọa có khối lượng lớn, làm phân tích thủ công tốn thời gian và phụ thuộc mạnh vào kinh nghiệm chuyên gia.
- LLM có khả năng phân tích và diễn giải bằng ngôn ngữ tự nhiên nhưng có ba hạn chế chính: tri thức có thể không cập nhật, nguy cơ hallucination và khó khai thác quan hệ phức tạp giữa nhiều thực thể bảo mật.
- RAG bổ sung tri thức ngoài mô hình; GraphRAG bổ sung khả năng truy vấn quan hệ và suy luận nhiều bước; LLM tổng hợp hai nguồn ngữ cảnh để tạo kết quả dễ hiểu.
- Trọng tâm nghiên cứu không chỉ là tạo chatbot, mà là kiểm chứng xem mô hình kết hợp có hỗ trợ phân tích mối đe dọa tốt hơn hay không.

## 3. Mục tiêu

### 3.1. Mục tiêu tổng quát

Nghiên cứu, đề xuất và xây dựng hệ thống thử nghiệm kết hợp RAG, GraphRAG và LLM cho bài toán truy tìm mối đe dọa ATTT; sau đó thực nghiệm và đánh giá mô hình trên các kịch bản cụ thể.

### 3.2. Mục tiêu cụ thể

1. Nghiên cứu nền tảng LLM, RAG, GraphRAG và Threat Hunting.
2. Đề xuất kiến trúc kết hợp RAG + GraphRAG + LLM.
3. Xây dựng quy trình xử lý log, kho tri thức bảo mật và đồ thị tri thức.
4. Xây dựng hệ thống thử nghiệm triển khai mô hình.
5. Thử nghiệm trên các kịch bản truy tìm mối đe dọa.
6. Đánh giá độ chính xác, tính đầy đủ, khả năng giải thích và mức độ hỗ trợ chuyên viên phân tích.

## 4. Đề cương ba chương hiện tại

### Chương 1. Tổng quan về RAG, GraphRAG, LLM và truy tìm mối đe dọa ATTT

**1.1. Bài toán truy tìm mối đe dọa an toàn thông tin**

- 1.1.1. Khái niệm và vai trò của truy tìm mối đe dọa trong SOC
- 1.1.2. Nguồn tri thức và dữ liệu phục vụ phân tích mối đe dọa

**1.2. Mô hình ngôn ngữ lớn và kỹ thuật RAG**

- 1.2.1. Khả năng và hạn chế của LLM trong miền ATTT
- 1.2.2. Kiến trúc và quy trình hoạt động của RAG
- 1.2.3. Vai trò của RAG trong bổ sung tri thức chuyên ngành

**1.3. Đồ thị tri thức và GraphRAG**

- 1.3.1. Biểu diễn tri thức ATTT dưới dạng đồ thị
- 1.3.2. Cơ chế truy xuất quan hệ trong GraphRAG
- 1.3.3. So sánh RAG truyền thống và GraphRAG trong phân tích bảo mật

**1.4. Giải pháp kết hợp LLM, RAG, GraphRAG để truy tìm mối đe dọa ATTT**

- 1.4.1. Sự cần thiết của việc kết hợp
- 1.4.2. Khung ý tưởng ứng dụng mô hình kết hợp

**Kết luận Chương 1**

### Chương 2. Phân tích và thiết kế hệ thống truy tìm mối đe dọa ATTT sử dụng mô hình kết hợp RAG, GraphRAG, LLM

**2.1. Phân tích bài toán và thiết kế kiến trúc**

- 2.1.1. Phạm vi, đối tượng và yêu cầu hệ thống
- 2.1.2. Kiến trúc tổng thể của hệ thống
- 2.1.3. Luồng xử lý dữ liệu và phân tích mối đe dọa

**2.2. Thiết kế dữ liệu và cơ sở tri thức**

- 2.2.1. Thu thập và chuẩn hóa dữ liệu log
- 2.2.2. Xây dựng nguồn tri thức từ MITRE ATT&CK, Sigma Rule và CTI report
- 2.2.3. Thiết kế đồ thị tri thức phục vụ truy tìm mối đe dọa

**2.3. Thiết kế mô hình phân tích kết hợp RAG, GraphRAG và LLM**

- 2.3.1. Thiết kế RAG pipeline
- 2.3.2. Thiết kế GraphRAG pipeline
- 2.3.3. Cơ chế phối hợp truy xuất giữa RAG và GraphRAG
- 2.3.4. Thiết kế prompt và định dạng đầu ra phân tích

**Kết luận Chương 2**

### Chương 3. Xây dựng, thử nghiệm và đánh giá hệ thống

**3.1. Môi trường triển khai và dữ liệu thực nghiệm**

- 3.1.1. Công nghệ và công cụ sử dụng
- 3.1.2. Bộ dữ liệu log và nguồn tri thức sử dụng

**3.2. Xây dựng các thành phần của hệ thống**

- 3.2.1. Module xử lý log và trích xuất thực thể
- 3.2.2. Module RAG và GraphRAG
- 3.2.3. Module phân tích kết quả bằng LLM

**3.3. Thực nghiệm trên các kịch bản truy tìm mối đe dọa**

- 3.3.1. Password spraying và Kerberoasting
- 3.3.2. Thực thi PowerShell nghi vấn thông qua MSHTA
- 3.3.3. Kết nối C2 thông qua Regsvr32

**3.4. Đánh giá kết quả thực nghiệm**

- 3.4.1. Đánh giá kết quả truy tìm mối đe dọa
- 3.4.2. Đánh giá độ chính xác, tính đầy đủ và khả năng giải thích
- 3.4.3. Đánh giá khả năng hỗ trợ chuyên viên phân tích ATTT
- 3.4.4. Ưu điểm, hạn chế và hướng cải tiến

**Kết luận Chương 3**

## 5. Dữ liệu và nguồn tri thức

### 5.1. Dữ liệu log thực nghiệm đã chọn

**OTRF Security Datasets, còn gọi là Mordor**, là nguồn dữ liệu thực nghiệm chính.

Đặc điểm được sử dụng làm lý do lựa chọn:

- Chứa các sự kiện bảo mật được ghi nhận sau khi mô phỏng kỹ thuật tấn công.
- Dữ liệu được tổ chức theo nền tảng, nhóm tấn công, tactic và technique của MITRE ATT&CK.
- Phù hợp với Threat Hunting và ánh xạ hành vi sang MITRE ATT&CK.
- Có thể dùng dữ liệu có sẵn thay vì tự sinh toàn bộ log, giúp thực nghiệm có cơ sở rõ ràng và dễ tái lập.
- Tập log sử dụng ở dạng JSON.

**Quyết định cập nhật ngày 16/07/2026:** chốt ba file JSON Lines dưới đây. Chỉ cố định filename; đường dẫn thư mục có thể khác nhau giữa các máy và phải được tìm chính xác trước khi chạy.

| Kịch bản | File đã chốt | Records | SHA-256 |
| --- | --- | ---: | --- |
| Password spraying và Kerberoasting | `purplesharp_ad_playbook_I_2020-10-22042947.json` | 25.993 | `d86d22f0c02ab851564bb5e0c90c220e9df0319f5948bfc90dfa605b4511d4f0` |
| C2 thông qua Regsvr32 | `empire_launcher_sct_regsvr32_2020-07-21232741.json` | 2.390 | `8b619d07ad79713ae96234344c4ba9618eae7119c360ee008b5e0c2cfe4954d7` |
| PowerShell nghi vấn thông qua MSHTA | `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json` | 1.127 | `25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32` |

File `psh_powershell_httplistener_2020-11-0204130683.json` đã bị loại khỏi experiment chính vì không có `CommandLine` hoặc `ScriptBlockText` cần thiết để đánh giá năm Sigma PowerShell đã chọn trước đó. File này vẫn được giữ nguyên làm dữ liệu tham khảo, không bị xóa hay sửa.

Đã có ground truth MSHTA dạng `draft_reviewable` và 32 câu hỏi/đáp án tham chiếu. Bản review kỹ thuật ngày 14/10/2026 nằm riêng trong `outputs/review/mshta-ground-truth/`, vẫn `pending_human_review`. Ground truth cho hai kịch bản còn lại, cách chia calibration/holdout và tiêu chuẩn đánh giá cuối cùng chưa chốt.

### 5.2. Canonical event schema và thực thể cần trích xuất

Canonical schema `canonical-event/v2` đang được normalization sử dụng gồm:

```text
event_id, timestamp, channel, provider, host,
user, subject_user, target_user,
source_ip, source_port, destination_ip, destination_port,
process_name, process_id, process_guid,
parent_process_name, parent_process_id, parent_process_guid,
command_line, parent_command_line,
file_path, registry_key, dns_query,
raw_record_ref, source_file
```

Các trường mở rộng được đề xuất cho ba kịch bản, chưa có trong canonical schema đang chạy, gồm:

```text
target_domain, workstation,
status, sub_status, logon_type,
service_name, ticket_options, ticket_encryption_type,
original_file_name
```

`canonical-event/v2` đã được triển khai với mapping registry theo `provider + Event ID`, tạo 29.510 canonical events từ 29.510 raw records, không bỏ record. `user` giữ giá trị người dùng chung khi source không thể hiện vai trò; `subject_user` biểu diễn actor/subject; `target_user` biểu diễn tài khoản hoặc người dùng bị tác động. Security Event ID `4688` dùng `NewProcessId` cho `process_id` và `ProcessId` cho `parent_process_id`. Sysmon Event ID `10` có source/target process roles chưa được schema v2 biểu diễn, nên `SourceImage`/`TargetImage` không bị ép vào parent-child fields; context này được ghi nhận để review.

Không ép giá trị không tồn tại vào schema; trường scalar không có dữ liệu dùng `null`. `event_id` và process ID dùng string để giữ biểu diễn số hoặc hexadecimal. Normalization chuyển port hợp lệ sang integer và ghi review issue khi transformation không hợp lệ; structural inspection vẫn chỉ quan sát dữ liệu. Khi có Sysmon, ưu tiên `ProcessGuid`/`ParentProcessGuid` để liên kết và khử trùng process; PID chỉ có ý nghĩa trong phạm vi host và thời gian. `raw_record_ref` của ba file JSONL có dạng `jsonl:line:<line>` và kết hợp với `source_file` cùng SHA-256 để truy ngược record gốc.

Normalization giữ `TimeCreated` cho các evidence anchors MSHTA và ghi `timestamp_conflict` khi khác với các timestamp candidates. Sysmon `UtcTime` lệch khoảng 4 giờ so với `TimeCreated`/`@timestamp` và không có timezone trong chuỗi; review chưa xác minh được nguồn lệch, nên không tự sửa timestamp hoặc khẳng định timezone thực.

Schema miền dự kiến gồm User, Host, IP, Process, Service, Event, Technique và Rule. Prototype hiện tại xây graph từ Ground Truth Core MSHTA, giữ entity/fact/evidence/Sigma finding/MITRE assessment và provenance, thay vì tự tạo toàn bộ đồ thị miền từ log. File và Command Line được giữ dưới dạng thuộc tính khi có dữ liệu; chỉ chuyển thành node nếu thực nghiệm chứng minh cần truy vấn quan hệ riêng.

### 5.3. Nguồn tri thức bảo mật

1. **MITRE ATT&CK:** tactic, technique, mô tả hành vi và cơ sở ánh xạ.
2. **Sigma Rules:** luật phát hiện tổng quát, liên hệ hành vi và technique.
3. **CTI reports:** bối cảnh chiến dịch, IOC, TTP và mô tả mối đe dọa.

**Quyết định cập nhật ngày 16/07/2026:** chốt 6 Sigma rule chính thức sau khi đọc toàn bộ ba file log và kiểm tra điều kiện detection thực tế.

#### Sigma cho password spraying và Kerberoasting

- `win_security_susp_rc4_kerberos.yml`

Password spraying cần một Sigma correlation do đồ án định nghĩa, dự kiến đặt tên `win_security_password_spray_correlation.yml`. Đây là derived artifact, không tính vào 6 external Sigma inputs. Logic dự kiến: ít nhất 5 `TargetUserName` khác nhau từ cùng source context trong 1 phút, dựa trên Event ID `4625` và/hoặc `4776`; phải tránh đếm đôi telemetry endpoint và domain controller của cùng lần xác thực.

#### Sigma cho C2 thông qua Regsvr32

- `proc_creation_win_regsvr32_http_ip_pattern.yml`
- `proc_creation_win_regsvr32_susp_child_process.yml`
- `proc_creation_win_regsvr32_susp_parent.yml`

#### Sigma cho PowerShell nghi vấn thông qua MSHTA

- `proc_creation_win_mshta_susp_child_processes.yml`
- `proc_creation_win_mshta_susp_execution.yml`

#### Các Sigma bị loại khỏi active experiment

- `win_security_susp_failed_logon_reasons.yml`
- `win_security_susp_failed_logon_source.yml`
- `win_security_susp_kerberos_manipulation.yml`
- `proc_creation_win_regsvr32_flags_anomaly.yml`
- `proc_creation_win_regsvr32_remote_share.yml`
- `posh_ps_susp_download.yml`
- `posh_ps_susp_invocation_specific.yml`
- `proc_creation_win_powershell_base64_encoded_cmd.yml`
- `proc_creation_win_powershell_download_patterns.yml`
- `proc_creation_win_powershell_susp_download_patterns.yml`

Các file bị loại vẫn được giữ read-only làm tài liệu tham khảo. Không dùng chúng làm positive rule cho ground truth vì chúng tạo 0 match hoặc yêu cầu telemetry không tồn tại trong dữ liệu tương ứng.

Nguồn `enterprise-attack.json` production đã được pin tại release `v19.1`, commit `6c3719993d0401de199203ecc3f369544d9e091c`, collection version `19.1`; SHA-256 bundle là `bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3`. Loader/resolver STIX 2.1 dùng exact-match và fail-closed. Danh sách CTI report và pipeline ingestion CTI chưa chốt.

Sigma safe loader/evaluator đã chạy hai rules MSHTA trên 1.127 canonical events: 4 observation matches được gộp thành 2 behavior matches. Evaluator chỉ hỗ trợ subset `windows/process_creation`, ánh xạ Sysmon `1` và Security `4688`; logsource không được hỗ trợ bị từ chối. `OriginalFileName` có trong raw Sysmon nhưng chưa nằm trong canonical v2, được giữ thành caveat. Match vẫn là detection hypothesis cần review.

Tổng active external inputs hiện là 10 file: 3 JSONL, 6 SigmaHQ YAML và 1 `enterprise-attack.json`. Derived correlation không được tính là external input.

### 5.4. Kết quả kiểm tra dữ liệu đã xác minh

#### PurpleSharp

- 7 Event ID `4625` nhắm vào 7 tài khoản khác nhau trong 12 mili-giây tại `jsonl:line:788`, `790`, `792`, `794`, `796`, `798`, `803`.
- 7 Event ID `4776` trên domain controller là góc nhìn telemetry thứ hai của cùng 7 lần thử, không phải 7 lần tấn công bổ sung.
- `win_security_susp_rc4_kerberos.yml` match 5 Event ID `4769` tại `jsonl:line:1125`, `1136`, `1140`, `1144`, `1148`.

#### Empire Regsvr32

- `jsonl:line:97`: PowerShell sinh `regsvr32.exe` với `/i:http://10.10.10.5:8444/launcher.sct`; match rule HTTP-IP và suspicious-parent.
- `jsonl:line:224`: `regsvr32.exe` sinh PowerShell encoded; match suspicious-child.
- `jsonl:line:1001`: `regsvr32.exe` kết nối từ `172.18.39.5` tới `10.10.10.5:8444`; PowerShell con tiếp tục kết nối lặp lại tới `10.10.10.5:80`.

#### MSHTA thực thi PowerShell

- `jsonl:line:275`: `cmd.exe` sinh `mshta.exe` với `vbscript:Execute`; match `proc_creation_win_mshta_susp_execution.yml`.
- `jsonl:line:398`: `mshta.exe` sinh `powershell.exe`; match `proc_creation_win_mshta_susp_child_processes.yml`.
- Security `4688` tại dòng `4`, `30`, `36` tương ứng với Sysmon `1` tại dòng `275`, `398`, `422`; correlation giữ trạng thái `inferred`, không đếm thành process bổ sung. Ground Truth Core hiện chỉ bao gồm hai nhóm `cmd → mshta` và `mshta → powershell`; `powershell → conhost` nằm ngoài lát cắt này.
- Dòng `30` và `398` chứng minh PowerShell được khởi chạy với `-noexit -command Get-Service sysmon`. Không có scriptblock, command output hoặc kết quả dịch vụ để chứng minh cmdlet hoàn tất hay trạng thái Sysmon.
- Raw file không có Sysmon `3`/`22` hay PowerShell scriptblock telemetry. Security `5156` ở dòng `3` thuộc WindowsAzureGuestAgent, không phải chuỗi MSHTA. Raw còn có log-clearing records và temporary file deletion; không coi chúng là destructive payload hoặc tự ánh xạ technique. Không suy ra download/C2/credential theft/phá hoại từ command đang review, cũng không khẳng định toàn file không có network hoặc deletion.

Candidate cho phạm vi ba kịch bản gồm `T1110.003`, `T1558.003`, `T1218.010`, `T1218.005`; chưa có mapping nào được người dùng xác nhận. Production resolver MSHTA đã resolve các Sigma tags `T1059.007`, `T1140`, `T1218.005` từ ATT&CK objects. Review nhận định `T1218.005` có hỗ trợ hành vi, `T1059.007` không được command VBScript hỗ trợ, `T1140` còn `not_assessed`; cả ba giữ `candidate`. Resolve được object không đồng nghĩa đã xác nhận technique trên log.

## 6. Kiến trúc mục tiêu và phần đã triển khai

### 6.1. Luồng tổng quát

```text
Log Mordor + nguồn tri thức bảo mật
→ tiền xử lý và chuẩn hóa
→ trích xuất thực thể
→ xây kho vector cho RAG và đồ thị tri thức cho GraphRAG
→ RAG truy xuất tài liệu liên quan
→ GraphRAG truy xuất chuỗi quan hệ/bằng chứng
→ LLM tổng hợp, phân tích và diễn giải
→ kết quả hỗ trợ truy tìm mối đe dọa
```

### 6.2. Các khối chính

1. **Dữ liệu đầu vào:** log Mordor và kho tri thức MITRE/Sigma/CTI.
2. **Tiền xử lý và trích xuất:** chuẩn hóa log, chọn trường, tạo thực thể và liên kết ban đầu.
3. **Retrieval RAG hiện có:** corpus 19 chunks từ Ground Truth Core, local embeddings, BM25/cosine/hybrid RRF; vector index là JSON artifact và xử lý in-memory.
4. **GraphRAG hiện có:** graph MSHTA 17 nodes/21 edges, exact seed mapping và bounded traversal; gate hai tầng chưa tích hợp runtime CLI.
5. **LLM dự kiến:** nhận câu hỏi, tài liệu RAG, bằng chứng GraphRAG và log tiêu biểu; phần sinh câu trả lời chưa triển khai.
6. **Giao diện dự kiến:** chọn log, đặt câu hỏi và xem kết quả; chưa có UI chạy được.
7. **Đánh giá hiện có:** so sánh embedding và calibration relevance trên 32 cases; chưa có policy đạt tiêu chí production hoặc đánh giá hệ thống đầy đủ.

### 6.3. Vai trò của từng thành phần

- RAG trả lời câu hỏi **“Tài liệu/tri thức bảo mật nào liên quan?”**
- GraphRAG trả lời câu hỏi **“Các thực thể và sự kiện liên kết với nhau như thế nào?”**
- LLM trả lời câu hỏi **“Từ tri thức và bằng chứng đó, hành vi nào đáng ngờ, vì sao và nên điều tra tiếp thế nào?”**

## 7. Schema đồ thị tri thức hiện tại

### 7.1. Schema miền dự kiến

- User
- Host
- IP
- Process
- Service
- Event
- Technique
- Rule

Đây là schema miền ở mức thiết kế để mở rộng ba kịch bản. File và Command Line chưa được xác nhận là node chính trong schema cuối.

### 7.2. Quan hệ miền dự kiến

- `Host/Process -[attempted_authentication]-> User`
- `User -[requested_ticket_for]-> Service`
- `Process -[spawned]-> Process`
- `Process -[ran_on]-> Host`
- `Process -[connected_to]-> IP`
- `Rule -[matched]-> Event`
- `Event -[maps_to]-> Technique`
- `Rule -[detects]-> Technique`

Mục đích là truy vết chuỗi hành vi qua nhiều sự kiện, thay vì chỉ đánh giá từng dòng log riêng lẻ. Với password spraying, Event ID `4625` có `IpAddress: "-"`, vì vậy không được bịa quan hệ IP → User; nguồn quan sát được phải lấy từ Host, Workstation và Process. Với process chain, phải khử trùng Sysmon Event ID `1` và Security Event ID `4688` khi chúng mô tả cùng process.

### 7.3. Knowledge Graph Core đã triển khai

- Schema `knowledge-graph/v1`, builder, validation và query CLI đã có. Graph baseline MSHTA gồm 17 nodes: 3 entity, 2 fact, 2 evidence, 2 sigma_finding, 3 mitre_assessment, 4 limitation và 1 scenario.
- 21 edges gồm `process_spawn`, `fact_subject`, `fact_object`, `supports`, `supports_assessment`; chỉ tạo cạnh từ relationship và support links tường minh trong Ground Truth Core.
- Node/edge IDs deterministic; giữ source IDs, JSON pointers, raw references và SHA-256 ground truth. Trạng thái observed/inferred/candidate không được tự nâng thành confirmed.
- Traversal đã hỗ trợ direction, max_depth, allowed_edge_types và giới hạn nodes/edges; graph là JSON artifact được xử lý in-memory, chưa có graph database service.
- Graph hiện pin Ground Truth Core baseline cũ. Bản ground truth đã review kỹ thuật ngày 14/10/2026 là artifact riêng và chưa được áp dụng vào graph.

### 7.4. Phần đồ thị còn cần hoàn thiện

- Ground truth và provenance mới sau khi người dùng duyệt bản sửa.
- Query-specific answerability: có node/evidence trong neighborhood chưa chứng minh đủ bằng chứng trả lời câu hỏi cụ thể.
- Policy gate hai tầng được kiểm chứng trên calibration/holdout và tích hợp query CLI.
- Evidence/graph extraction cho PurpleSharp và Regsvr32, cùng database service nếu thực nghiệm cần.

## 8. RAG pipeline hiện tại

1. Builder tạo `retrieval-corpus/v1` từ Ground Truth Core MSHTA, gồm 19 chunks có object IDs, JSON pointers, evidence references và trạng thái review.
2. Lexical retrieval dùng BM25; vector retrieval dùng cosine similarity. Hybrid retrieval gộp thứ hạng bằng RRF, không cộng trực tiếp BM25 và cosine scores.
3. Local Sentence Transformers backend dùng model revision được pin. Đã có vector indexes cho `sentence-transformers/all-MiniLM-L6-v2` và `intfloat/multilingual-e5-small`.
4. Corpus/vector index được serialize thành JSON và query in-memory qua CLI, có top-k, candidate-k và filters. Chưa có vector database service.
5. Đã so sánh hai models trên 32 queries Anh/Việt; `multilingual-e5-small` là `provisional_recommendation`, chưa phải lựa chọn model cuối cùng.
6. Chưa nối retrieval context với LLM sinh câu trả lời; ingestion/chunking tài liệu CTI và kho tri thức rộng hơn chưa triển khai.

Đáp án tham chiếu, expected decisions và benchmark labels nằm trong evaluation artifacts, không đưa vào retrieval corpus hoặc runtime gate input. Corpus/indexes baseline vẫn pin ground truth cũ; cần rebuild với provenance mới sau khi bản sửa được duyệt. Các scores là điểm xếp hạng, không phải xác suất kết luận đúng hoặc mức độ nguy hiểm.

## 9. GraphRAG pipeline hiện tại

1. Evidence/Sigma/MITRE artifacts được hợp nhất thành Ground Truth Core reviewable cho MSHTA; builder tạo Knowledge Graph Core từ các claims và support links tường minh.
2. Query CLI thực hiện hybrid retrieval, ánh xạ hits sang graph seeds bằng IDs/JSON pointers và traversal có giới hạn.
3. Orchestrator tạo `graphrag-context/v1`, giữ kết quả retrieval/seed mapping/traversal, warnings và provenance. Khi không có hits/seeds phù hợp thì không thực hiện traversal.
4. Relevance gate cũ đã có calibration và diagnostics. Hai lần chạy baseline/E5 đều đánh giá 672 candidate policies trên 32 cases và trả `no_eligible_policy`; chưa chọn được policy đạt các constraints đã cấu hình.
5. Gate mới dùng `graphrag-two-stage-gate-policy/v1` và `graphrag-two-stage-gate-decision/v1`, tách `topical_relevance` và `evidence_answerability`; module/synthetic tests đã có, nhưng chưa tích hợp vào query CLI và chưa có production policy được calibrate/kiểm chứng.
6. `proceed` chỉ biểu thị context eligibility, không xác nhận đáp án hoặc technique. Chưa có LLM tổng hợp context, đánh giá GraphRAG trên holdout độc lập hoặc pipeline hoàn chỉnh cho hai kịch bản còn lại.

Prototype đã chứng minh được luồng retrieval → seeds → graph traversal cho MSHTA. Chưa thể coi GraphRAG hoàn chỉnh vì gate/answerability và đánh giá cuối còn chưa đạt; mở rộng schema phải bám ba kịch bản đã chọn.

## 10. Đầu vào, prompt và đầu ra LLM

Phần này mô tả yêu cầu thiết kế. Chưa có LLM client, prompt pipeline hoặc module sinh câu trả lời chạy được. Retrieval/GraphRAG hiện trả context JSON để kiểm tra riêng từng thành phần.

### 10.1. Đầu vào LLM

- Câu hỏi/yêu cầu phân tích của người dùng.
- Các đoạn tài liệu do RAG truy xuất.
- Chuỗi quan hệ và bằng chứng do GraphRAG truy xuất.
- Một số bản ghi log tiêu biểu liên quan.

### 10.2. Đầu ra đã thống nhất ở mức lõi

- Mô tả/tóm tắt hành vi nghi vấn.
- Bằng chứng log liên quan.
- Kỹ thuật MITRE ATT&CK tương ứng.
- Giải thích lý do hành vi bị coi là nghi vấn.
- Gợi ý truy vấn hoặc hướng điều tra tiếp theo.

### 10.3. Khác biệt cần chuẩn hóa giữa các bản thảo

Tệp hướng dẫn đề xuất định dạng cố định gồm **tóm tắt, bằng chứng, MITRE technique, mức độ nghiêm trọng, truy vấn và biện pháp khắc phục**. Bản mô hình/triển khai hiện nêu **mô tả, bằng chứng, MITRE technique, giải thích và gợi ý điều tra**. Cần quyết định schema cuối có thêm `severity` và `remediation` hay không.

Prompt cần ràng buộc LLM chỉ kết luận dựa trên bằng chứng được cung cấp, phân biệt dữ kiện với suy luận và không bịa IOC/Technique khi không đủ căn cứ. Cơ chế này là yêu cầu thiết kế cần triển khai, chưa có bằng chứng đã hoàn thành.

## 11. Giao diện và cách sử dụng dự kiến

Giao diện thử nghiệm được gợi ý bằng **Streamlit hoặc FastAPI** để:

- Chọn bộ log/kịch bản.
- Đặt câu hỏi bằng ngôn ngữ tự nhiên.
- Xem tài liệu RAG truy xuất.
- Xem bằng chứng/quan hệ GraphRAG.
- Xem phân tích cuối của LLM.

Streamlit và FastAPI hiện là hai phương án, chưa phải quyết định cuối. Chưa chốt việc có cần frontend riêng hay không.

Hiện có Python CLI cho inspection, normalization, evidence, ground truth, retrieval, graph và evaluation; chưa triển khai web UI/API cho người dùng.

## 12. Kịch bản thực nghiệm

### 12.1. Kịch bản 1 - Password spraying và Kerberoasting

Mục tiêu: phát hiện nhiều lần xác thực thất bại tập trung vào nhiều tài khoản trong thời gian ngắn, tránh đếm trùng Event ID `4625`/`4776`, đồng thời nhận diện yêu cầu Kerberos service ticket sử dụng RC4 phù hợp với Kerberoasting.

Dữ liệu và tri thức đã chốt:

- Log: `purplesharp_ad_playbook_I_2020-10-22042947.json`.
- SigmaHQ: `win_security_susp_rc4_kerberos.yml`.
- Derived rule cần xây: `win_security_password_spray_correlation.yml`.

Hiện đã inspection/normalization toàn bộ 25.993 records và xác định anchors tham chiếu. Evidence extractor, correlation rule, ground truth và đánh giá retrieval riêng cho kịch bản này chưa hoàn thành; kịch bản tạm hoãn để hoàn thiện MSHTA, vẫn thuộc phạm vi đồ án.

### 12.2. Kịch bản 2 - PowerShell nghi vấn thông qua MSHTA

Mục tiêu: phân tích chuỗi `cmd.exe → mshta.exe → powershell.exe`, chứng minh MSHTA proxy execution bằng command line và quan hệ parent-child, rồi truy xuất Sigma/MITRE phù hợp.

Dữ liệu và tri thức đã chốt:

- Log: `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`.
- Sigma: `proc_creation_win_mshta_susp_execution.yml` và `proc_creation_win_mshta_susp_child_processes.yml`.

Hiện đã có normalization 1.127 events, 2 evidence groups, Sigma evaluation, MITRE resolution, Ground Truth Core và prototype retrieval/GraphRAG. Bản ground truth và 32 đáp án tham chiếu được review kỹ thuật ngày 14/10/2026, vẫn chờ người dùng duyệt. Các consumers baseline chưa dùng bản sửa trong `outputs/review/mshta-ground-truth/`.

Giới hạn: chứng minh PowerShell được khởi chạy với `-noexit -command Get-Service sysmon`, chưa chứng minh cmdlet hoàn tất hay trạng thái Sysmon. Không gán nhãn download, C2, credential theft hoặc destructive payload cho hai nhóm hành vi đang review. Temporary file deletion, log clearing và background network records trong raw file không tự trở thành bằng chứng cho các nhãn đó.

### 12.3. Kịch bản 3 - C2 thông qua Regsvr32

Mục tiêu: liên kết chuỗi PowerShell parent → `regsvr32.exe` tải remote `.sct` → PowerShell encoded child → kết nối C2, đồng thời cung cấp bằng chứng process, command line và network.

Dữ liệu và tri thức đã chốt:

- Log: `empire_launcher_sct_regsvr32_2020-07-21232741.json`.
- Sigma: `proc_creation_win_regsvr32_http_ip_pattern.yml`, `proc_creation_win_regsvr32_susp_parent.yml`, `proc_creation_win_regsvr32_susp_child_process.yml`.

Hiện đã inspection/normalization toàn bộ 2.390 records và xác định anchors tham chiếu. Evidence extractor, ground truth và đánh giá retrieval riêng chưa hoàn thành; kịch bản tạm hoãn, không bị loại khỏi phạm vi đồ án.

Ba file JSONL và 6 SigmaHQ external inputs đã chốt; derived password-spraying correlation mới chốt ý tưởng, chưa triển khai. Ground truth được người dùng duyệt, holdout độc lập, số lần chạy và tiêu chuẩn đánh giá hệ thống cuối cùng vẫn chưa có. Bộ 32 queries/đáp án hiện có chỉ phục vụ lát cắt MSHTA.

## 13. Khung đánh giá

Các tiêu chí đã được nêu trong đề cương/tài liệu hướng dẫn:

1. **Độ chính xác truy xuất:** RAG lấy đúng tài liệu/đoạn tri thức cần thiết.
2. **Độ chính xác ánh xạ:** technique MITRE ATT&CK được gán đúng.
3. **Tính đầy đủ:** kết quả có đủ bằng chứng và thông tin quan trọng.
4. **Khả năng giải thích:** kết luận có lý do và truy vết được về log/tri thức.
5. **Độ hữu ích cho Threat Hunting:** kết quả có hỗ trợ chuyên viên tiếp tục điều tra hay không.
6. **So sánh phương pháp:** RAG truyền thống với GraphRAG; khi triển khai nên làm rõ có thêm cấu hình kết hợp RAG + GraphRAG hay không.
7. **Ưu điểm, hạn chế và khả năng cải tiến.**

Đã triển khai đánh giá retrieval với hit rate/recall/MRR/nDCG tại các cutoffs, so sánh MiniLM với multilingual E5 trên 32 cases (16 tiếng Anh, 16 tiếng Việt). Model selection đưa ra khuyến nghị E5 tạm thời; không so sánh trực tiếp raw cosine scores giữa hai models.

Reference set có 16 `proceed`, 8 `insufficient_evidence` và 8 `unrelated`. Review ngày 14/10/2026 đã làm rõ hai câu hỏi về launch command và bằng chứng payload cố ý phá hoại, giữ nguyên phân bố. Bộ câu hỏi/đáp án được kiểm tra kỹ thuật nhưng chưa được người dùng duyệt; expected decisions chỉ dùng để đánh giá.

Legacy relevance calibration và lần chạy E5 đều đánh giá 672 candidate policies trên 32 cases, trả `no_eligible_policy` với constraints hiện tại. Đây là kết quả chưa đạt của policy selection, không phải bằng chứng một gate production đã hoạt động tốt. Gate hai tầng mới có tests theo fixture synthetic; cần dữ liệu calibration/holdout phân biệt đúng chủ đề với đủ bằng chứng trả lời.

Chưa có đánh giá cuối về LLM/độ hữu ích cho chuyên viên, thang điểm human review, holdout độc lập, thống kê lặp lại hoặc so sánh đủ cả ba kịch bản. Không suy ra tỷ lệ hoàn thành toàn đồ án từ số lượng modules hoặc tests.

## 14. Công nghệ: đã xác định và chưa xác định

### Đã triển khai hoặc có artifact kiểm chứng

- Python 3.11+, package/CLI, `pytest`, PyYAML safe loader và Sentence Transformers; direct dependencies được pin trong `pyproject.toml`.
- Discovery/parser/inspection/normalization cho OTRF Security Datasets/Mordor, stable raw references và SHA-256 provenance.
- Sigma evaluator subset `windows/process_creation`, MITRE ATT&CK STIX 2.1 loader/resolver với nguồn production v19.1.
- Ground Truth Core, Retrieval Corpus, Knowledge Graph Core và vector indexes dạng JSON; query xử lý in-memory.
- BM25, cosine, hybrid RRF, graph seed mapping/traversal, legacy relevance calibration/diagnostics và gate hai tầng ở mức module/tests.
- MiniLM và multilingual E5 local embedding models có revision pin; E5 được khuyến nghị tạm thời.

### Chưa hoàn thành hoặc chưa chốt cuối cùng

- Người dùng duyệt ground truth/đáp án và chọn embedding model cuối cùng.
- Gate hai tầng: production policy, calibration/holdout và CLI integration.
- LLM cụ thể, cách truy cập local/API, prompt và output schema; không fine-tune theo thiết kế hiện tại.
- Vector/graph database service nếu cần; prototype hiện không dùng dịch vụ database.
- CTI sources/ingestion và evidence/ground-truth pipeline cho PurpleSharp, Regsvr32.
- Streamlit/FastAPI hay frontend khác, môi trường triển khai cuối, cơ chế vận hành và vai trò của Splunk.

## 15. Tiến độ hiện tại theo code, outputs và review

### Đã có bằng chứng hoàn thành

- Đề cương v1.2 ngày 01/07/2026, phạm vi nghiên cứu và cấu trúc ba chương; kiến trúc mục tiêu RAG + GraphRAG + LLM.
- Chọn đúng 10 external inputs, kiểm tra ba JSONL với counts 25.993/2.390/1.127 và giữ nguyên raw SHA-256; 6 SigmaHQ phù hợp với experiment, các reference bị loại vẫn read-only.
- CLI discovery/streaming parser/structural inspection v2, context-aware canonical mapping và normalization: 29.510 input records → 29.510 canonical events, dropped=0.
- MSHTA extractor đọc đủ 1.127 canonical events, tạo 3 process entities, 2 process_spawn relationships, 2 evidence items và 4 unique raw references; tương quan Security/Sysmon là `inferred`.
- Safe Sigma loader/evaluator: 4 observation matches/2 behavior matches trên MSHTA; metadata/caveats được giữ, không xác nhận attack từ rule match.
- MITRE ATT&CK v19.1 STIX resolver: resolve exact-match `T1059.007`, `T1140`, `T1218.005`, giữ candidate mappings và source version.
- Ground Truth Core builder/validation và bản draft MSHTA; review kỹ thuật ngày 14/10/2026 kiểm tra raw/canonical/provenance, sửa launch-command wording và bổ sung original fields trong review copy.
- 32 reference answers được review kỹ thuật với hai query corrections; vẫn 16 proceed/8 insufficient_evidence/8 unrelated, chờ người dùng duyệt.
- Baseline corpus 19 chunks, graph 17 nodes/21 edges, MiniLM/E5 vector indexes, BM25/cosine/hybrid retrieval và GraphRAG orchestration/query CLI.
- Embedding comparison/model selection, relevance calibration/diagnostics; E5 là khuyến nghị tạm thời. Hai calibration runs baseline/E5 trả `no_eligible_policy` sau 672 policies × 32 cases mỗi run.
- Gate signals và two-stage gate evaluator có strict validation, deterministic output và synthetic tests; chưa tích hợp CLI hoặc validate production policy.
- Checkpoint review gần nhất đã chạy 592 relevant tests passed cùng validation/readback/provenance/raw-immutability checks. Đây là tập tests liên quan ở checkpoint, không phải khẳng định full suite mới nhất đã chạy.

### Phần chưa hoàn thành

- Người dùng duyệt Ground Truth Core và 32 reference answers; không có human approval hoặc confirmed labels tự động.
- Rebuild corpus/graph/indexes/evaluation với provenance của ground truth đã sửa. Các consumers hiện có vẫn pin baseline cũ, review copy được giữ riêng để không phá chuỗi hashes.
- Calibrate/kiểm chứng gate hai tầng trên dữ liệu phù hợp, tích hợp query CLI và đánh giá holdout độc lập; chưa có production policy đạt tiêu chí.
- Hoàn thiện MSHTA answerability và giới hạn timestamp/telemetry; command-line launch không chứng minh cmdlet completion hoặc service state.
- Chọn embedding model cuối, CTI ingestion và database service nếu thực nghiệm yêu cầu.
- Triển khai LLM, prompt/output schema, tích hợp sinh câu trả lời và UI.
- Evidence extractor/ground truth riêng cho PurpleSharp, Regsvr32 và project-defined password-spraying correlation.
- Đánh giá hệ thống đầy đủ, human scoring, ba kịch bản, phân tích kết quả/hạn chế và kết luận đồ án.

**Hiện đã có nền dữ liệu và prototype retrieval/GraphRAG cho MSHTA; ground truth/đáp án chờ người dùng duyệt, gate production chưa đạt, LLM/UI và hai lát cắt scenario còn lại chưa hoàn thành.**

## 16. Các quyết định cần chốt tiếp theo

Ưu tiên theo thứ tự để tránh triển khai lan man:

1. Người dùng duyệt bản ground truth và 32 đáp án đã review trong `outputs/review/mshta-ground-truth/`, gồm hai câu được sửa, phạm vi payload và timestamp caveats. Review của Codex không thay thế human approval.
2. Sau khi duyệt, rebuild corpus/graph/MiniLM-E5 indexes và evaluation artifacts từ phiên bản ground truth mới, lưu provenance; giữ baseline cũ để so sánh có kiểm soát.
3. Chốt bộ nhãn cho topical relevance và evidence answerability, calibration/holdout độc lập; calibrate gate hai tầng, kiểm tra false proceed/abstain và tích hợp policy đạt tiêu chí vào query CLI.
4. Quyết định embedding model cuối dựa trên evaluation; E5 hiện chỉ là provisional recommendation. Xác định tiêu chí đủ bằng chứng cho từng câu hỏi trước khi nối LLM.
5. Chọn LLM, prompt/output schema và giao diện; thực hiện tích hợp/đánh giá khi nền evidence và gate ổn định. Prototype retrieval hiện có chưa đồng nghĩa hệ thống đầy đủ đã hoàn thành.
6. Tiếp tục hai kịch bản PurpleSharp/Regsvr32, password-spraying correlation và CTI ingestion theo phạm vi đã chốt; không thêm scenario thứ tư.

## 17. Rủi ro và điểm cần kiểm soát

- **Hallucination:** LLM có thể kết luận vượt quá bằng chứng; cần prompt ràng buộc và trích dẫn nguồn.
- **GraphRAG quá rộng:** schema lớn sẽ làm tăng thời gian xây dựng; nên giới hạn quanh ba kịch bản.
- **Đánh giá thiếu ground truth:** khó chứng minh hiệu quả nếu chỉ trình diễn đầu ra đẹp.
- **Ground truth chưa được người dùng duyệt:** technical review và candidate mappings chưa phải nhãn confirmed; review copy phải được version/rebuild rõ ràng trước khi dùng cho consumers.
- **Benchmark leakage và policy overfit:** reference answers không nằm trong runtime retrieval/gate input; 32 cases cùng lát cắt chưa thay thế holdout độc lập.
- **Topical relevance khác answerability:** có hits, seeds hoặc evidence nodes chưa đủ để trả lời trạng thái dịch vụ, cmdlet completion hoặc hành vi ngoài phạm vi log.
- **Timestamp/telemetry:** giữ conflict và missing fields; không biến thiếu script/network telemetry thành khẳng định hành vi không thể xảy ra.
- **So sánh không công bằng:** các cấu hình phải dùng cùng câu hỏi, dữ liệu và LLM.
- **Mapping MITRE chủ quan:** cần đáp án tham chiếu và quy tắc chấm.
- **CTI không đồng nhất:** cần kiểm soát nguồn, phiên bản và metadata.
- **Thuật ngữ:** phải phân biệt RAG tài liệu, truy vấn đồ thị và vai trò tổng hợp của LLM.
- **Phạm vi:** không gộp các dự án ATTT khác vào đồ án nếu không có quyết định chính thức.

## 18. Tài liệu tham khảo nền tảng đã có trong đề cương

1. Patrick Lewis và cộng sự, *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks*, NeurIPS 2020.
2. Darren Edge và cộng sự, *From Local to Global: A Graph RAG Approach to Query-Focused Summarization*, arXiv:2404.16130, 2024.
3. MITRE Corporation, MITRE ATT&CK.
4. SigmaHQ, Sigma: Generic Signature Format for SIEM Systems.
5. Karen Kent, Murugiah Souppaya, NIST SP 800-92, *Guide to Computer Security Log Management*, 2006.
6. Microsoft, Sysmon - Sysinternals.

## 19. Nguồn dùng để lập hồ sơ này

- `Nguyễn Hồng Phong-AT190540_v1.2.pdf`: đề cương chính thức sáu trang, phiên bản v1.2.
- `Nguyễn Hồng Phong-AT190540_Mô hình và triển khai.docx`: mô hình tổng quan và quy trình triển khai.
- `Hướng làm đồ án ATTT.pdf`: lịch sử trao đổi/hướng làm; bản đính kèm hiện bị hỏng phần cấu trúc cuối của PDF, nên nội dung được đối chiếu bằng phần văn bản đã được hệ thống lập chỉ mục và các nội dung trùng khớp trong bản Word.
- Lịch sử trao đổi liên quan trực tiếp đến đề tài RAG/GraphRAG/LLM.
- Sáu ảnh chụp ngày 12/07/2026 ghi nhận lựa chọn ban đầu gồm ba JSON và 13 Sigma rule.
- Kết quả đọc streaming toàn bộ ba file JSONL và kiểm tra trực tiếp các Sigma YAML ngày 15-16/07/2026, dùng để thay thế lựa chọn ban đầu bằng bộ 3 JSON + 6 SigmaHQ + 1 derived correlation.
- Mã nguồn hiện tại trong `src/threat_hunting/`, Python CLI trong `scripts/` và experiment/evaluation configs; thiết kế được đối chiếu với implementation, không suy ra hoàn thành từ đề cương.
- Các production artifacts tại `outputs/canonical/`, `outputs/evidence/`, `outputs/ground_truth/`, `outputs/retrieval/`, `outputs/graph/`, `outputs/evaluation/` và technical review ngày 14/10/2026 tại `outputs/review/mshta-ground-truth/`. Dữ liệu/output cục bộ không commit; các consumers baseline và review copies có chuỗi provenance riêng.

## 20. Nhật ký quyết định

Các mục có ngày dưới đây giữ trạng thái tại thời điểm quyết định, không thay thế tiến độ hiện tại ở mục 15. Ví dụ nhận định “normalization chưa triển khai” ngày 16/07/2026 là checkpoint lịch sử.

### 12/07/2026 - Chốt dữ liệu cho ba kịch bản

- Chốt 3 file Mordor JSON: PurpleSharp AD Playbook cho brute force, Empire Launcher SCT/Regsvr32 cho C2 và PowerShell HTTP Listener cho PowerShell nghi vấn.
- Chốt 13 Sigma rule: 3 brute force, 5 C2/Regsvr32 và 5 PowerShell.
- Quyết định này đã được thay thế một phần bởi cập nhật ngày 16/07/2026 sau khi kiểm tra telemetry và Sigma match thực tế.

### 16/07/2026 - Cập nhật bộ dữ liệu và Sigma sau kiểm tra thực tế

- Giữ `purplesharp_ad_playbook_I_2020-10-22042947.json` và `empire_launcher_sct_regsvr32_2020-07-21232741.json`.
- Thay `psh_powershell_httplistener_2020-11-0204130683.json` bằng `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`.
- Chốt 6 SigmaHQ: 1 cho Kerberoasting, 3 cho Regsvr32 và 2 cho MSHTA.
- Quyết định xây thêm `win_security_password_spray_correlation.yml` làm derived artifact của đồ án.
- Ghi nhận 7 failed-logon targets, 5 Kerberos RC4 matches, 3 Regsvr32 rule matches và 2 MSHTA rule matches với raw record references cụ thể.
- Loại các rule tạo 0 match hoặc cần telemetry không tồn tại khỏi active experiment; không xóa raw/reference files.
- Trạng thái tiếp theo: cập nhật experiment config, chạy lại inspection trên bộ ba mới, xây evidence extraction và tạo ground truth để người dùng duyệt.

### 16/07/2026 - Hoàn thành structural inspection v2

- Chạy `mordor-selected-v2` trên đúng ba raw JSONL đã chọn; toàn bộ baseline khớp và raw SHA-256 không thay đổi.
- Nâng report lên `mordor-inspection/v2` và canonical schema lên `canonical-event/v2` proposed/reviewable.
- Thay mapping theo alias/coverage toàn file bằng proposal phụ thuộc `provider + Event ID`; sửa semantic của Security `4688`, authentication user roles, registry, DNS và network fields.
- Ghi nhận Sysmon Event ID `10` source/target process roles là `context_specific_unmapped`, không ép thành quan hệ parent-child.
- Bổ sung thống kê timestamp conflict, cảnh báo timezone-naive và transformation port string-to-integer cần validation.
- Trạng thái tiếp theo: review schema/mapping; normalization, evidence extraction và ground truth chưa triển khai.

## 21. Quy tắc cập nhật hồ sơ

Mỗi quyết định mới nên ghi kèm:

- Ngày quyết định.
- Nội dung đã chốt.
- Lý do chọn.
- Tệp/code/kết quả liên quan.
- Phần nào của đề cương hoặc kiến trúc bị ảnh hưởng.

Không chuyển mục “chưa chốt” sang “đã hoàn thành” nếu chưa có bằng chứng như mã nguồn chạy được, ảnh kết quả, log thực nghiệm hoặc bảng đánh giá.

## 22. Checkpoint review kỹ thuật ngày 14/10/2026

Theo yêu cầu thực hiện bước review ground truth MSHTA và đáp án tham chiếu, Codex đã đối chiếu toàn bộ 1.127 raw records với canonical events, kiểm tra hai Sigma rules và STIX objects từ ATT&CK v19.1. Các source hashes giữ nguyên; 3 entities, 2 facts, 2 relationships và 4 evidence references của core có căn cứ.

Bản sửa và báo cáo nằm tại `outputs/review/mshta-ground-truth/`. `scenario_ground_truth.json` bổ sung original fields trong fact attributes và sửa khẳng định “PowerShell ran Get-Service sysmon” thành “PowerShell was launched with -noexit -command Get-Service sysmon”. Log process creation không chứng minh cmdlet hoàn tất hoặc trạng thái dịch vụ. Timestamp `TimeCreated`/`UtcTime` còn lệch khoảng 4 giờ; không tự xác nhận timezone.

32 đáp án tham chiếu giữ 16 proceed, 8 insufficient_evidence và 8 unrelated. Hai câu được làm rõ: câu về launch command và câu về bằng chứng payload cố ý phá hoại. Raw file có record xóa tệp tạm và event-log clearing ngoài hai nhóm process-creation core, nên không được khẳng định toàn dataset không có thao tác xóa hoặc tự coi thao tác đó là destructive payload. Không thêm scenario hoặc positive attack label.

Review kỹ thuật hoàn thành với 592 relevant tests passed, validation/readback/provenance và raw immutability checks. Reviewer là Codex, không phải người dùng; ground truth vẫn `draft_reviewable`/`pending_human_review`. T1218.005 có hỗ trợ hành vi, T1059.007 không được command VBScript hỗ trợ và T1140 còn not_assessed; tất cả giữ candidate.

Mã nguồn và output hiện có đã có prototype retrieval và GraphRAG cho MSHTA như tiến độ ở mục 15. Các consumer hiện có pin ground truth cũ; bản sửa là version riêng, chưa tự động áp dụng vào corpus/graph/indexes/evaluation. Bước tiếp theo sau khi người dùng duyệt bản sửa là rebuild consumer với provenance mới và kiểm chứng gate hai tầng. Đáp án tham chiếu chỉ dùng để đánh giá, không đưa vào retrieval corpus hoặc runtime gate input. LLM/UI và pipeline evidence đầy đủ cho PurpleSharp/Regsvr32 vẫn chưa hoàn thành.
