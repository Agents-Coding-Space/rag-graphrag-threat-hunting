# TIẾN ĐỘ ĐỒ ÁN TỐT NGHIỆP

**Cập nhật gần nhất:** 15/09/2026
**Đề tài:** Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT
**Repository:** https://github.com/phong8924/rag-graphrag-threat-hunting
**Trạng thái hiện tại:** Hoàn thành structural inspection, production canonical normalization và MSHTA production evidence extraction. Evidence extraction cho toàn bộ ba scenario đang thực hiện; PurpleSharp, Regsvr32, Sigma, MITRE ATT&CK và ground truth chưa hoàn thành. Tiến độ tổng thể giữ ở mức khoảng 40%.

> File này dùng để theo dõi tiến độ thực tế. Chỉ đánh dấu một việc là hoàn thành khi có bằng chứng như mã nguồn, output hợp lệ, test result hoặc kết quả kiểm tra dữ liệu. Nội dung thiết kế hoặc kế hoạch không được coi là đã triển khai.

## 1. Mục tiêu gần nhất

Xây dựng pipeline nhỏ, có thể tái lập và truy vết để:

1. Kiểm tra cấu trúc ba log đã chọn mà không sửa raw data.
2. Chuẩn hóa các event cần thiết sang canonical schema đã được duyệt.
3. Trích xuất evidence cho ba threat-hunting scenario.
4. So sánh evidence với Sigma rules phù hợp.
5. Xác minh MITRE ATT&CK techniques từ `enterprise-attack.json`.
6. Tạo bản nháp `scenario_ground_truth.json` để người dùng duyệt.

Chưa triển khai RAG, GraphRAG, LLM, vector database, graph database hoặc giao diện trước khi hoàn thành và duyệt ground truth.

## 2. Dữ liệu và kịch bản đã chốt

### 2.1. Dataset

| Scenario | Dataset | Records | SHA-256 |
| --- | --- | ---: | --- |
| Password spraying và Kerberoasting | `purplesharp_ad_playbook_I_2020-10-22042947.json` | 25.993 | `d86d22f0c02ab851564bb5e0c90c220e9df0319f5948bfc90dfa605b4511d4f0` |
| C2 thông qua Regsvr32 | `empire_launcher_sct_regsvr32_2020-07-21232741.json` | 2.390 | `8b619d07ad79713ae96234344c4ba9618eae7119c360ee008b5e0c2cfe4954d7` |
| PowerShell thông qua MSHTA | `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json` | 1.127 | `25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32` |

Dataset `psh_powershell_httplistener_2020-11-0204130683.json` đã bị loại khỏi active experiment vì telemetry không phù hợp với các PowerShell Sigma rules ban đầu. File có thể được giữ làm reference read-only nhưng không được dùng trong experiment hiện tại.

### 2.2. Sigma rules

Password spraying và Kerberoasting:

- `win_security_susp_rc4_kerberos.yml`
- `win_security_password_spray_correlation.yml` — derived rule của đồ án, chưa hoàn thành triển khai và kiểm thử.

C2 thông qua Regsvr32:

- `proc_creation_win_regsvr32_http_ip_pattern.yml`
- `proc_creation_win_regsvr32_susp_child_process.yml`
- `proc_creation_win_regsvr32_susp_parent.yml`

PowerShell thông qua MSHTA:

- `proc_creation_win_mshta_susp_child_processes.yml`
- `proc_creation_win_mshta_susp_execution.yml`

### 2.3. MITRE ATT&CK

- Nguồn dữ liệu: `enterprise-attack.json`.
- Candidate techniques hiện tại: `T1110.003`, `T1558.003`, `T1218.010`, `T1218.005`.
- Chưa đánh dấu technique nào là `confirmed` cho đến khi resolve object tương ứng từ STIX 2.1 và gắn với evidence có thể truy vết.

## 3. Những việc đã hoàn thành

### 3.1. Khởi tạo và quản lý repository

- [x] Tạo `.gitignore` loại trừ raw data, knowledge data, processed data, outputs, virtual environment và secrets.
- [x] Tạo cấu trúc Python package, CLI và unit tests ban đầu.
- [x] Tạo `README.md`, `AGENTS.md`, `PROJECT_CONTEXT.md` và `pyproject.toml`.
- [x] Khởi tạo Git và tạo commit đầu tiên trên nhánh `main`.
- [x] Push repository lên GitHub.
- [x] Xác nhận raw data, generated outputs và `.env` không nằm trong commit đầu tiên.

### 3.2. Lựa chọn và kiểm tra dữ liệu

- [x] Giữ PurpleSharp và Empire Regsvr32.
- [x] Thay PowerShell HTTP Listener bằng MSHTA/PowerShell dataset.
- [x] Cập nhật experiment thành `mordor-selected-v2`.
- [x] Cập nhật baseline thành 25.993, 2.390 và 1.127 records.
- [x] Đối chiếu SHA-256 của ba raw datasets.
- [x] Chốt 6 SigmaHQ phù hợp với telemetry quan sát được.
- [x] Xác định cần xây một password-spraying correlation rule riêng của đồ án.

### 3.3. Structural inspection

- [x] Discovery input theo filename chính xác, không khóa cứng đường dẫn máy.
- [x] Hỗ trợ JSON Lines, JSON array và JSON object.
- [x] Đọc streaming cho JSONL và JSON array.
- [x] Sinh `raw_record_ref` ổn định theo format.
- [x] Thống kê toàn file thay vì suy ra schema từ record đầu.
- [x] Thống kê record count, field paths, missing/null, types, Event ID, provider và time range.
- [x] Tách report riêng cho từng input.
- [x] Sinh `manifest.json`, `canonical_schema.json`, các `inspection.json` và `summary.md`.
- [x] Chạy inspection thành công trên đúng ba dataset của `mordor-selected-v2`.
- [x] Manifest ghi nhận 3 input thành công, không có input thất bại và cả ba baseline đều khớp.
- [x] Summary phân biệt structural context với kết luận tấn công.
- [x] Summary hiển thị các Event ID liên quan đến schema nhưng không coi Event ID là ground truth.

### 3.4. Cải tiến canonical mapping proposal

- [x] Phân biệt `subject_user`, `target_user` và `user` chung.
- [x] Bổ sung đề xuất cho `process_guid`, `parent_process_guid` và `parent_command_line`.
- [x] Mapping proposal đã xét `provider + EventID`, không chỉ dựa trên tên field và coverage toàn file.
- [x] Xử lý đúng khác biệt semantic của `ProcessId`:
  - Sysmon Event ID 1: `ProcessId` là process hiện tại.
  - Security Event ID 4688: `ProcessId` là creator/parent process; `NewProcessId` là process mới.
- [x] Không ép `SourceImage`/`TargetImage` của Sysmon Event ID 10 thành quan hệ parent-child.
- [x] Đánh dấu port dạng string cần validated string-to-integer transformation.
- [x] Phát hiện timestamp candidates có khác biệt và không tự gán UTC cho timestamp naive.
- [x] Giữ mapping ở trạng thái reviewable; chưa dùng trạng thái `confirmed` trong inspection.

### 3.5. Evidence anchors đã xác định sơ bộ

Các anchor dưới đây đã được kiểm tra trực tiếp trước khi xây evidence-extraction pipeline. Chúng là kết quả tham chiếu sơ bộ, chưa phải ground truth cuối cùng.

- PurpleSharp:
  - 7 Event ID 4625 tại `jsonl:line:788`, `790`, `792`, `794`, `796`, `798`, `803`.
  - Các Event ID 4776 tương ứng là telemetry view trùng của cùng các authentication attempts, không được đếm thành attempt mới.
  - 5 RC4 Kerberos matches tại `jsonl:line:1125`, `1136`, `1140`, `1144`, `1148`.
- Empire Regsvr32:
  - `jsonl:line:97`: PowerShell tạo `regsvr32.exe` với remote `.sct` qua HTTP/IP.
  - `jsonl:line:224`: `regsvr32.exe` tạo encoded PowerShell child.
  - `jsonl:line:1001`: kết nối từ `regsvr32.exe` tới `10.10.10.5:8444`.
- MSHTA/PowerShell:
  - `jsonl:line:275`: `cmd.exe` tạo `mshta.exe` với `vbscript:Execute`.
  - `jsonl:line:398`: `mshta.exe` tạo `powershell.exe`.
  - Security Event ID 4688 tại các dòng `4`, `30`, `36` là telemetry view tương ứng với Sysmon process creation; không được coi là process bổ sung.
  - Payload quan sát được chỉ chạy `Get-Service sysmon`; không có bằng chứng download, C2, credential theft hoặc destructive behavior.

## 4. Checkpoint inspection và normalization

- [x] Structural inspection hoàn thành trên đúng ba dataset của `mordor-selected-v2`.
- [x] Canonical schema `canonical-event/v2` hoàn thành ở trạng thái reviewable.
- [x] Context-aware mapping registry theo `provider + EventID` hoàn thành.
- [x] Streaming normalization giữ contract một raw record tạo một canonical event.
- [x] Atomic writer và normalization CLI hoàn thành.
- [x] Production normalization hoàn thành: 29.510 input → 29.510 canonical events, dropped=0.
- [x] 104 tests đạt tại checkpoint normalization.

### 4.1. Checkpoint evidence schema và MSHTA production extractor

- [x] Evidence schema `scenario-evidence/v1` hoàn thành và được kiểm thử.
- [x] MSHTA in-memory evidence extractor hoàn thành cho fixture của `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`.
- [x] Correlation giữa Security Event ID 4688 và Sysmon Event ID 1 dùng telemetry grouping `inferred`; process-spawn evidence giữ trạng thái `observed`.
- [x] Custom correlation tolerance được validate, lưu trong intermediate group và dùng lại khi build evidence/document.
- [x] `time_window` validation đã xử lý exact keys, null pairing, ISO 8601, aware/naive consistency và chronological ordering mà không sửa chuỗi timestamp gốc.
- [x] Legacy correlation API có semantics cạnh tranh đã được loại bỏ; public pipeline còn lại là classify → `same_process_creation()` → `group_process_creations()`.
- [x] `normalize_process_name()` đã xử lý basename, Windows path, case, quote và các process-path edge cases đã kiểm thử.
- [x] Fixture hiện tạo 3 process entities, 2 evidence items, 2 `process_spawn` relationships và giữ đủ 4 raw references.
- [x] Fixture có `analysis_status=draft_reviewable`; không có status `confirmed`.
- [x] Production extraction đã chạy trên toàn bộ 1.127 canonical events: examined=1.127, matched=4, unmatched=1.123, rejected=0 và unprocessed=0.
- [x] Production output dùng `scenario-evidence/v1`, giữ `analysis_status=draft_reviewable`, tạo 3 process entities, 2 `process_spawn` relationships, 2 evidence items và 4 unique source references.
- [x] Hai cặp Security Event ID 4688/Sysmon Event ID 1 được tương quan, với độ lệch timestamp khoảng 0,001 giây và 0,027 giây; cả hai đều nằm trong tolerance 1 giây.
- [x] Hai Sysmon observations liên quan có upstream normalization issue `timestamp_conflict`; các conflict được giữ lại để review và không làm correlation vượt tolerance.
- [x] CLI/extractor warnings=0. Upstream normalization giữ 1.379 review issues, gồm 892 `timestamp_conflict` và 487 `unsupported_context`.
- [x] `raw_fields` trong production evidence hiện rỗng; provenance vẫn truy ngược được raw record bằng `source_file` và `raw_record_ref`.
- [x] Production output deterministic, SHA-256 `ea56d0bb07547da85a98339491af55d5b984d96ab8558eef3f8ec530955a4905`.
- [x] Raw SHA-256 trước và sau giữ nguyên `25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32`; canonical SHA-256 là `9bcac98d41746eb4365cb96efbc7411c595760c9f5c54678453219e71d4411d8`.
- [x] Full test suite hiện tại: 250 tests đạt, 0 failed và 0 skipped.

Production evidence output chưa có Sigma hoặc MITRE mapping.

### 4.2. Phạm vi chưa hoàn thành

- [ ] Chưa thực thi Sigma cho MSHTA.
- [ ] Chưa resolve MITRE ATT&CK.
- [ ] Chưa tạo ground truth được người dùng duyệt.
- [ ] Chưa xây evidence extractor cho Regsvr32 và PurpleSharp.
- [ ] Chưa triển khai RAG, GraphRAG, LLM hoặc UI.

## 5. Những việc cần làm tiếp theo

Thực hiện theo thứ tự; không bỏ qua ground truth để chuyển sớm sang RAG/GraphRAG.

### Chiến lược triển khai chuyên sâu

Báo cáo chuyên sâu sẽ xây dựng lát cắt hoàn chỉnh RAG và GraphRAG trên kịch bản MSHTA–PowerShell. Kiến trúc phải độc lập với kịch bản và có khả năng mở rộng sang PurpleSharp và Regsvr32; hai kịch bản này được tạm hoãn, không bị loại khỏi phạm vi đồ án tốt nghiệp.

### Milestone 3 — Sigma và evidence extraction

- [ ] Viết và kiểm thử `win_security_password_spray_correlation.yml` dưới dạng project-defined rule.
- [ ] Viết Sigma YAML loader an toàn, không thực thi arbitrary YAML tags.
- [ ] Giữ Sigma metadata: title, ID, status, logsource, condition, tags, level và references.
- [ ] Ghi rõ unsupported Sigma fields hoặc backend assumptions.
- [x] Xây MSHTA in-memory evidence extractor và khử trùng Sysmon Event ID 1 với Security Event ID 4688 khi chúng mô tả cùng process creation.
- [x] Chạy extractor trên 1.127 production canonical MSHTA events, ghi deterministic `scenario-evidence/v1` output và hoàn thành review.
- [ ] Xây evidence extractor cho Regsvr32 và PurpleSharp, gồm khử trùng Event ID 4625 với 4776 khi chúng mô tả cùng authentication attempt.
- [ ] Sinh báo cáo evidence trung gian dễ đọc để người dùng duyệt.
- [ ] Không coi Sigma match là ground truth tự động.

### Milestone 4 — MITRE ATT&CK và ground truth

- [ ] Parse `enterprise-attack.json` dưới dạng STIX 2.1.
- [ ] Lưu ATT&CK version hoặc collection metadata dùng trong experiment.
- [ ] Resolve candidate technique IDs từ ATT&CK objects.
- [ ] Liên kết mỗi mapping với log evidence, Sigma rule hoặc ATT&CK object.
- [ ] Tạo bản nháp `scenario_ground_truth.json` có trạng thái reviewable.
- [ ] Validate JSON và deterministic ordering.
- [ ] Người dùng duyệt evidence trước khi chuyển label sang `confirmed`.
- [ ] Xây bộ câu hỏi thực nghiệm, expected answers và investigation questions.

### Milestone 5 — RAG

- [ ] Chọn nguồn CTI bổ sung và metadata bắt buộc.
- [ ] Chốt chunking strategy.
- [ ] Chọn embedding model.
- [ ] Chọn vector database.
- [ ] Xây indexing và retrieval pipeline.
- [ ] Đánh giá retrieval bằng cùng bộ câu hỏi và ground truth đã duyệt.

### Milestone 6 — GraphRAG

- [ ] Chốt graph schema, node keys và edge rules.
- [ ] Chốt cách biểu diễn event time và provenance.
- [ ] Chọn graph database.
- [ ] Trích xuất entity và relationship từ canonical events.
- [ ] Khử trùng node/process/event.
- [ ] Xây neighborhood/path retrieval cho ba scenario.
- [ ] Đánh giá GraphRAG trên cùng dữ liệu và câu hỏi với RAG.

### Milestone 7 — LLM, giao diện và đánh giá

- [ ] Chọn LLM và cách truy cập local/API.
- [ ] Thiết kế prompt bắt buộc trích dẫn evidence và phân biệt fact/inference.
- [ ] Chốt output schema, bao gồm quyết định về severity và remediation.
- [ ] Tích hợp RAG + GraphRAG + LLM.
- [ ] Chọn Streamlit hoặc FastAPI.
- [ ] Xây giao diện thử nghiệm.
- [ ] Chạy thực nghiệm có cấu hình và log tái lập.
- [ ] Đánh giá độ chính xác, tính đầy đủ, khả năng giải thích và tính hữu ích.
- [ ] So sánh RAG, GraphRAG và cấu hình kết hợp một cách công bằng.

## 6. Trạng thái theo milestone

| Milestone | Trạng thái | Bằng chứng chính |
| --- | --- | --- |
| Repository và project setup | Hoàn thành | GitHub repository, README, pyproject, tests |
| Lựa chọn dataset/Sigma | Hoàn thành | 3 JSON, 6 SigmaHQ, 1 derived rule được lên kế hoạch |
| Structural inspection v2 | Hoàn thành | Manifest 3/3, summary, inspection reports, baseline và SHA-256 |
| Canonical schema/mapping review | Hoàn thành | `canonical-event/v2` và context-aware mapping registry đã được kiểm thử |
| Canonical normalization | Hoàn thành | Streaming iterator, atomic writer, CLI, production run 29.510 input → 29.510 canonical events, dropped=0 |
| Evidence schema | Hoàn thành | `scenario-evidence/v1`, deterministic IDs và validation được kiểm thử |
| Evidence extraction | Đang thực hiện | MSHTA production extraction hoàn thành trên 1.127 canonical events; chưa có extractor Regsvr32/PurpleSharp |
| Sigma execution/correlation | Chưa bắt đầu | Chưa có pipeline và derived correlation hoàn chỉnh |
| MITRE STIX resolution | Chưa bắt đầu | Mới có candidate technique IDs |
| Ground truth | Chưa bắt đầu | Chưa có bản nháp được người dùng duyệt |
| RAG | Chưa bắt đầu | Chưa chọn embedding/vector database |
| GraphRAG | Chưa bắt đầu | Mới có graph schema ở mức thiết kế |
| LLM và giao diện | Chưa bắt đầu | Chưa chọn LLM hoặc framework giao diện |
| Đánh giá thực nghiệm | Chưa bắt đầu | Chưa có bộ câu hỏi, metric và ground truth cuối |

## 7. Quy tắc kiểm soát tiến độ

- Không sửa, đổi tên, di chuyển hoặc ghi đè raw input.
- Không commit raw data, generated outputs, secrets hoặc đường dẫn máy cá nhân.
- Không bịa IOC, user, host, process, timestamp, Sigma match hoặc MITRE technique.
- Phân biệt `observed`, `inferred`, `candidate` và `confirmed`.
- Mọi canonical event phải truy ngược được bằng `raw_record_ref` và `source_file`.
- Mọi record bị bỏ qua hoặc lọc phải có count và lý do.
- Sigma là detection hypothesis, không phải ground truth tự động.
- MITRE mapping phải được resolve từ ATT&CK object và gắn với evidence.
- Không đánh dấu task hoàn thành nếu chưa chạy test hoặc chưa kiểm tra output tương ứng.
- Mỗi milestone chỉ thực hiện một phạm vi nhỏ, có output dễ đọc và có thể kiểm thử.

## 8. Bước tiếp theo duy nhất

**Hoàn thiện ground truth cho kịch bản MSHTA–PowerShell, gồm đối chiếu evidence với Sigma Rule, resolve MITRE ATT&CK từ STIX 2.1 và xây dựng bộ câu hỏi cùng đáp án mong đợi phục vụ đánh giá RAG và GraphRAG.**

## 9. Cách cập nhật file này

Sau mỗi milestone:

1. Cập nhật ngày.
2. Chuyển checkbox chỉ khi có bằng chứng.
3. Ghi file/code/output liên quan.
4. Ghi test command và kết quả thực tế.
5. Ghi raw hash trước/sau nếu có xử lý dữ liệu.
6. Ghi giới hạn và việc còn thiếu.
7. Chỉ giữ một “bước tiếp theo duy nhất” để tránh triển khai lan man.
