# HỒ SƠ TRẠNG THÁI ĐỒ ÁN TỐT NGHIỆP

**Cập nhật gần nhất:** 16/07/2026  
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

Vẫn chưa chốt: ground truth cuối cùng, tập câu hỏi đánh giá, cách chia tập thực nghiệm và tiêu chuẩn pass/fail.

### 5.2. Canonical event schema và thực thể cần trích xuất

Canonical schema tối thiểu hiện được đề xuất gồm:

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

Các trường mở rộng cần thiết cho đúng ba kịch bản đã quan sát gồm:

```text
target_domain, workstation,
status, sub_status, logon_type,
service_name, ticket_options, ticket_encryption_type,
original_file_name
```

`canonical-event/v2` hiện là schema **proposed/reviewable**, chưa phải schema normalization đã chốt. `user` giữ giá trị người dùng chung khi source không thể hiện vai trò; `subject_user` biểu diễn actor/subject; `target_user` biểu diễn tài khoản hoặc người dùng bị tác động. Mapping phải dựa trên `provider + Event ID`: ví dụ Security Event ID `4688` dùng `NewProcessId` cho `process_id` và `ProcessId` cho `parent_process_id`. Sysmon Event ID `10` dùng source/target process roles, nên `SourceImage`/`TargetImage` không bị ép vào parent-child fields khi schema v2 chưa biểu diễn các role đó.

Không ép giá trị không tồn tại vào schema; trường scalar không có dữ liệu dùng `null`. `event_id` và process ID dùng string khi chuẩn hóa để không làm mất biểu diễn số hoặc hexadecimal. Port nguồn có thể là string và chỉ được đề xuất chuyển sang integer sau validation; structural inspection chưa áp dụng transformation. Khi có Sysmon, ưu tiên `ProcessGuid`/`ParentProcessGuid` để liên kết và khử trùng process; PID chỉ có ý nghĩa trong phạm vi host và thời gian. `raw_record_ref` của ba file JSONL có dạng `jsonl:line:<line>` và phải kết hợp với `source_file` cùng SHA-256 để truy ngược record gốc.

Các thực thể dùng cho đồ thị gồm User, Host, IP, Process, Service, Event, Technique và Rule. File và Command Line trước mắt được giữ dưới dạng thuộc tính; chỉ chuyển thành node nếu thực nghiệm chứng minh cần truy vấn quan hệ riêng.

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

Vẫn chưa chốt: phiên bản/snapshot của `enterprise-attack.json`, danh sách CTI report, tiêu chí làm sạch tài liệu và phạm vi ngôn ngữ.

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
- Các Event ID `4688` tại dòng `4`, `30`, `36` là telemetry Security trùng với process Sysmon, không được đếm thành process bổ sung.
- Payload chỉ chạy `Get-Service sysmon`; không quan sát thấy PowerShell download, C2, credential theft hoặc hành vi phá hoại trong file này.

Các MITRE technique hiện là candidate: `T1110.003`, `T1558.003`, `T1218.010`, `T1218.005`. Chỉ đánh dấu confirmed sau khi giải quyết object tương ứng từ `enterprise-attack.json`.

## 6. Kiến trúc và pipeline được đề xuất

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
3. **RAG:** chia nhỏ tài liệu, tạo embedding, lưu vector database, truy xuất đoạn liên quan.
4. **GraphRAG:** xây knowledge graph, truy vấn quan hệ nhiều bước giữa thực thể.
5. **LLM:** nhận câu hỏi, tài liệu RAG, bằng chứng GraphRAG và log tiêu biểu; tạo câu trả lời có cấu trúc.
6. **Giao diện thử nghiệm:** cho phép chọn log, đặt câu hỏi tự nhiên và xem kết quả từng khối.
7. **Thực nghiệm/đánh giá:** chạy kịch bản và so sánh kết quả theo tiêu chí định trước.

### 6.3. Vai trò của từng thành phần

- RAG trả lời câu hỏi **“Tài liệu/tri thức bảo mật nào liên quan?”**
- GraphRAG trả lời câu hỏi **“Các thực thể và sự kiện liên kết với nhau như thế nào?”**
- LLM trả lời câu hỏi **“Từ tri thức và bằng chứng đó, hành vi nào đáng ngờ, vì sao và nên điều tra tiếp thế nào?”**

## 7. Schema đồ thị tri thức hiện tại

### 7.1. Node chính

- User
- Host
- IP
- Process
- Service
- Event
- Technique
- Rule

File và Command Line đã được nhắc ở bước trích xuất nhưng chưa được xác nhận là node chính trong schema cuối.

### 7.2. Quan hệ chính

- `Host/Process -[attempted_authentication]-> User`
- `User -[requested_ticket_for]-> Service`
- `Process -[spawned]-> Process`
- `Process -[ran_on]-> Host`
- `Process -[connected_to]-> IP`
- `Rule -[matched]-> Event`
- `Event -[maps_to]-> Technique`
- `Rule -[detects]-> Technique`

Mục đích là truy vết chuỗi hành vi qua nhiều sự kiện, thay vì chỉ đánh giá từng dòng log riêng lẻ. Với password spraying, Event ID `4625` có `IpAddress: "-"`, vì vậy không được bịa quan hệ IP → User; nguồn quan sát được phải lấy từ Host, Workstation và Process. Với process chain, phải khử trùng Sysmon Event ID `1` và Security Event ID `4688` khi chúng mô tả cùng process.

### 7.3. Điểm chưa chốt của đồ thị

- Thuộc tính bắt buộc và khóa định danh của từng node.
- Cách biểu diễn thời gian và thứ tự sự kiện.
- Cách gộp node trùng lặp và xử lý thực thể thiếu dữ liệu.
- Quy tắc tạo cạnh từ log thô.
- Loại cơ sở dữ liệu đồ thị và ngôn ngữ truy vấn.
- Độ sâu truy vấn nhiều bước, giới hạn neighborhood và cách xếp hạng bằng chứng.

## 8. RAG pipeline hiện tại

1. Thu thập MITRE ATT&CK, Sigma và CTI report.
2. Làm sạch và chia tài liệu thành chunk.
3. Sinh embedding.
4. Lưu vector vào vector database.
5. Từ câu hỏi/hành vi nghi vấn, truy xuất các chunk liên quan nhất.
6. Đưa các chunk này vào ngữ cảnh cho LLM để giảm thiếu tri thức và hallucination.

Chưa chốt: embedding model, chiến lược chunking, vector database, top-k, reranker, metadata filter, ngưỡng tương đồng và cách trích dẫn nguồn.

## 9. GraphRAG pipeline hiện tại

1. Trích xuất thực thể từ log đã chuẩn hóa.
2. Tạo node/cạnh theo schema bảo mật.
3. Liên kết sự kiện với MITRE Technique và Sigma Rule khi có căn cứ.
4. Xác định thực thể gốc từ câu hỏi hoặc sự kiện nghi vấn.
5. Truy vấn neighborhood/đường đi nhiều bước.
6. Chọn chuỗi quan hệ và bằng chứng liên quan để cung cấp cho LLM.

GraphRAG có chi phí thiết kế và xây dựng cao hơn RAG truyền thống; cần giới hạn schema và kịch bản để phù hợp phạm vi đồ án.

## 10. Đầu vào, prompt và đầu ra LLM

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

## 12. Kịch bản thực nghiệm

### 12.1. Kịch bản 1 - Password spraying và Kerberoasting

Mục tiêu: phát hiện nhiều lần xác thực thất bại tập trung vào nhiều tài khoản trong thời gian ngắn, tránh đếm trùng Event ID `4625`/`4776`, đồng thời nhận diện yêu cầu Kerberos service ticket sử dụng RC4 phù hợp với Kerberoasting.

Dữ liệu và tri thức đã chốt:

- Log: `purplesharp_ad_playbook_I_2020-10-22042947.json`.
- SigmaHQ: `win_security_susp_rc4_kerberos.yml`.
- Derived rule cần xây: `win_security_password_spray_correlation.yml`.

### 12.2. Kịch bản 2 - PowerShell nghi vấn thông qua MSHTA

Mục tiêu: phân tích chuỗi `cmd.exe → mshta.exe → powershell.exe`, chứng minh MSHTA proxy execution bằng command line và quan hệ parent-child, rồi truy xuất Sigma/MITRE phù hợp.

Dữ liệu và tri thức đã chốt:

- Log: `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`.
- Sigma: `proc_creation_win_mshta_susp_execution.yml` và `proc_creation_win_mshta_susp_child_processes.yml`.

Giới hạn: payload PowerShell chỉ chạy `Get-Service sysmon`; không gán nhãn download, C2 hoặc phá hoại cho kịch bản này.

### 12.3. Kịch bản 3 - C2 thông qua Regsvr32

Mục tiêu: liên kết chuỗi PowerShell parent → `regsvr32.exe` tải remote `.sct` → PowerShell encoded child → kết nối C2, đồng thời cung cấp bằng chứng process, command line và network.

Dữ liệu và tri thức đã chốt:

- Log: `empire_launcher_sct_regsvr32_2020-07-21232741.json`.
- Sigma: `proc_creation_win_regsvr32_http_ip_pattern.yml`, `proc_creation_win_regsvr32_susp_parent.yml`, `proc_creation_win_regsvr32_susp_child_process.yml`.

Ba file JSONL, 6 SigmaHQ và 1 derived correlation đã được chốt. Chưa chốt cho cả ba kịch bản: bộ câu hỏi thực nghiệm, ground truth được người dùng duyệt, số lần chạy, cấu hình hệ thống và tiêu chuẩn pass/fail.

## 13. Khung đánh giá

Các tiêu chí đã được nêu trong đề cương/tài liệu hướng dẫn:

1. **Độ chính xác truy xuất:** RAG lấy đúng tài liệu/đoạn tri thức cần thiết.
2. **Độ chính xác ánh xạ:** technique MITRE ATT&CK được gán đúng.
3. **Tính đầy đủ:** kết quả có đủ bằng chứng và thông tin quan trọng.
4. **Khả năng giải thích:** kết luận có lý do và truy vết được về log/tri thức.
5. **Độ hữu ích cho Threat Hunting:** kết quả có hỗ trợ chuyên viên tiếp tục điều tra hay không.
6. **So sánh phương pháp:** RAG truyền thống với GraphRAG; khi triển khai nên làm rõ có thêm cấu hình kết hợp RAG + GraphRAG hay không.
7. **Ưu điểm, hạn chế và khả năng cải tiến.**

Các tiêu chí hiện mới ở mức định tính/khung. Chưa có công thức metric, bộ câu hỏi đánh giá, thang điểm, người chấm, baseline, số mẫu và kiểm định lặp lại.

## 14. Công nghệ: đã xác định và chưa xác định

### Đã xác định ở mức kiến trúc

- OTRF Security Datasets/Mordor.
- MITRE ATT&CK.
- Sigma Rules.
- CTI reports.
- Vector database cho RAG (chưa chọn sản phẩm).
- Knowledge graph/graph database cho GraphRAG (chưa chọn sản phẩm).
- LLM có sẵn, không fine-tune/huấn luyện lại theo thiết kế hiện tại.
- Streamlit hoặc FastAPI là phương án giao diện/API.

### Chưa chốt

- LLM cụ thể và cách truy cập (local/API).
- Embedding model.
- Vector database.
- Graph database.
- Framework điều phối RAG/GraphRAG.
- Công cụ trích xuất thực thể và mapping log → MITRE.
- Môi trường triển khai, cấu hình phần cứng và hệ điều hành.
- Cơ chế cache, logging, theo dõi nguồn và bảo vệ dữ liệu.
- Streamlit hay FastAPI.
- Vai trò của Splunk trong bản triển khai cuối.

## 15. Tiến độ được suy ra từ tài liệu hiện có

### Đã có bằng chứng hoàn thành

- Đề cương chính thức phiên bản **v1.2**, đề ngày **01/07/2026**.
- Tên đề tài, lý do chọn đề tài, mục tiêu và cấu trúc ba chương.
- Lựa chọn Mordor/OTRF làm bộ dữ liệu log chính.
- Lựa chọn MITRE ATT&CK, Sigma và CTI làm nguồn tri thức.
- Lựa chọn và kiểm tra toàn bộ ba file Security Datasets/Mordor JSONL cho password spraying/Kerberoasting, PowerShell qua MSHTA và C2 qua Regsvr32.
- Xác nhận record count lần lượt là 25.993, 2.390 và 1.127; lưu SHA-256 để kiểm soát raw data.
- Chốt 6 SigmaHQ có telemetry phù hợp và match thực tế; xác định 10 Sigma cũ không phù hợp hoặc tạo 0 match và loại khỏi active experiment.
- Xác định cần xây 1 Sigma correlation của đồ án cho password spraying.
- Xác định các evidence anchor có thể truy ngược bằng `jsonl:line:<line>` cho cả ba kịch bản.
- Đã xây CLI inspection theo báo cáo triển khai: hỗ trợ discovery theo filename, JSONL/JSON array/object, streaming, schema statistics, canonical mapping proposal và reporting tách từng file.
- Đã chạy inspection trên bộ ba cũ và đạt 10/10 unit tests; raw data không thay đổi.
- Đã hoàn thành structural inspection v2 trên đúng `mordor-selected-v2`: 25.993, 2.390 và 1.127 records đều khớp baseline; manifest `completed`, 3/3 input thành công và không chứa PowerShell HTTP Listener cũ.
- Đã nâng output lên `mordor-inspection/v2` và canonical schema lên `canonical-event/v2` ở trạng thái proposed/reviewable; mapping proposal dùng context `provider + Event ID`, phân biệt process/parent và subject/target roles, đồng thời ghi nhận timestamp conflict và string-to-integer port transformation cần review.
- Đã đạt 14/14 tests cho parser/reference ổn định, context-aware mapping, JSON readback, summary và raw-input immutability; SHA-256 của cả ba raw dataset không thay đổi sau inspection.
- Kiến trúc tổng quan và sơ đồ pipeline RAG + GraphRAG + LLM.
- Mô tả tám bước triển khai ở mức thiết kế.
- Schema đồ thị ban đầu.
- Ba nhóm kịch bản thực nghiệm.
- Khung đầu vào/đầu ra LLM và tiêu chí đánh giá sơ bộ.

### Đang ở mức thiết kế hoặc chưa có bằng chứng hoàn thành

- Viết, kiểm thử và đánh dấu rõ `win_security_password_spray_correlation.yml` là project-defined rule.
- Trích xuất evidence có cấu trúc và tạo báo cáo trung gian dễ đọc cho người dùng duyệt.
- Tạo ground truth và tập câu hỏi thực nghiệm từ ba file đã chọn.
- Viết module chuẩn hóa log/trích xuất thực thể.
- Xây kho vector và kiểm thử truy xuất RAG.
- Xây graph database và truy vấn GraphRAG.
- Chọn/cấu hình LLM, prompt và output schema cuối.
- Tích hợp toàn bộ pipeline.
- Xây giao diện chạy được.
- Chạy ba kịch bản và lưu kết quả.
- Xây ground truth, baseline và thang đo định lượng.
- Viết kết quả thực nghiệm, phân tích hạn chế và kết luận.

Nói ngắn gọn: **structural inspection v2 trên bộ ba mới đã hoàn thành và canonical schema v2 đã sẵn sàng để review; normalization, evidence extraction, ground truth, RAG, GraphRAG, LLM và đánh giá thực nghiệm vẫn chưa hoàn thành.**

## 16. Các quyết định cần chốt tiếp theo

Ưu tiên theo thứ tự để tránh triển khai lan man:

1. Duyệt `canonical-event/v2`, timestamp recommendation và các mapping còn `ambiguous`/`context_specific_unmapped` trước khi viết normalization.
2. Xây password-spraying correlation và evidence extractor cho từng kịch bản.
3. Tạo bản nháp `scenario_ground_truth.json`, chưa tự động đánh dấu confirmed khi chưa được người dùng duyệt.
4. Xác minh MITRE objects từ `enterprise-attack.json` và chốt phiên bản ATT&CK.
5. Chốt bộ câu hỏi, output schema, baseline và metric đánh giá.
6. Sau khi ground truth được duyệt mới xây RAG, GraphRAG, LLM và giao diện.

## 17. Rủi ro và điểm cần kiểm soát

- **Hallucination:** LLM có thể kết luận vượt quá bằng chứng; cần prompt ràng buộc và trích dẫn nguồn.
- **GraphRAG quá rộng:** schema lớn sẽ làm tăng thời gian xây dựng; nên giới hạn quanh ba kịch bản.
- **Đánh giá thiếu ground truth:** khó chứng minh hiệu quả nếu chỉ trình diễn đầu ra đẹp.
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

## 20. Nhật ký quyết định

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
