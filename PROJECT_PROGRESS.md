# TIẾN ĐỘ ĐỒ ÁN TỐT NGHIỆP

**Cập nhật gần nhất:** 14/10/2026

**Đề tài:** Nghiên cứu mô hình kết hợp RAG, GraphRAG, LLM và ứng dụng truy tìm mối đe dọa ATTT

**Repository:** https://github.com/phong8924/rag-graphrag-threat-hunting

**Trạng thái hiện tại:** Hoàn thành inspection, normalization, evidence/Sigma/MITRE cho MSHTA và review kỹ thuật ground truth cùng 32 đáp án tham chiếu. Có prototype retrieval và GraphRAG cho MSHTA; gate hai tầng chưa được kiểm chứng và tích hợp production. Ground truth sửa còn `pending_human_review`; chưa có LLM hoặc UI. PurpleSharp và Regsvr32 chưa có pipeline evidence đầy đủ. Không quy đổi tiến độ thành tỷ lệ phần trăm khi chưa có thang đo.

> File này dùng để theo dõi tiến độ thực tế. Chỉ đánh dấu một việc là hoàn thành khi có bằng chứng như mã nguồn, output hợp lệ, test result hoặc kết quả kiểm tra dữ liệu. Nội dung thiết kế hoặc kế hoạch không được coi là đã triển khai.

## 1. Checkpoint hiện tại — 14/10/2026

- Đọc streaming và đối chiếu đủ 1.127 raw records với 1.127 canonical events; 3 entities, 2 facts, 2 relationships và 4 evidence references của core khớp nguồn.
- Kiểm tra độc lập hai Sigma rules tạo 4 observation matches / 2 behavior matches; xác minh ATT&CK v19.1 và ba STIX technique objects.
- Tạo bản sửa riêng tại `outputs/review/mshta-ground-truth/scenario_ground_truth.json`; giữ nguyên hashes của raw và các artifact baseline.
- Sửa “PowerShell ran” thành launch command quan sát được; bổ sung original fields vào fact attributes, giữ cảnh báo timestamp lệch khoảng 4 giờ.
- Tạo 32 đáp án tham chiếu; giữ 16 proceed, 8 insufficient_evidence và 8 unrelated. Sửa 2 câu hỏi để phân biệt launch command với kết quả cmdlet và temporary-file deletion với destructive payload.
- Review identity là Codex; human approval còn pending, không nâng MITRE labels thành confirmed.
- Relevant checks: 592 tests passed, JSON readback/provenance/raw immutability đã kiểm tra. Đây là số tests của lượt review này, không phải tuyên bố đã chạy full suite hiện tại.
- Báo cáo: [review_report.md](outputs/review/mshta-ground-truth/review_report.md); đáp án: [reference_answers.md](outputs/review/mshta-ground-truth/reference_answers.md); hashes/counts: [review_manifest.json](outputs/review/mshta-ground-truth/review_manifest.json).
- Các corpus, graph, indexes và evaluation reports đang pin bản ground truth cũ. Trước milestone gate, cần dùng bản được người dùng duyệt để rebuild consumer và provenance; đáp án tham chiếu không được đưa vào retrieval corpus hoặc runtime gate input.

### 1.1. Mục tiêu gần nhất

Pipeline hiện có đã inspection và normalization cả ba dataset; MSHTA có evidence/Sigma/MITRE, ground truth bản nháp và prototype retrieval/GraphRAG. Lát cắt đang triển khai chuyên sâu là MSHTA–PowerShell. PurpleSharp và Regsvr32 vẫn thuộc phạm vi đồ án, nhưng chưa có pipeline evidence có cấu trúc hoặc ground truth đầy đủ.

Mục tiêu gần nhất là người dùng duyệt ground truth MSHTA sửa và 32 đáp án tham chiếu. Sau đó rebuild consumers với provenance mới, hiệu chỉnh/kiểm chứng gate hai tầng trên dữ liệu thực tế và holdout, rồi tích hợp policy đạt tiêu chí vào CLI. Chưa hoàn thành database service, LLM, giao diện hoặc đánh giá end-to-end cuối cùng.

## 2. Dữ liệu và kịch bản đã chốt

### 2.1. Dataset

| Scenario | Dataset | Raw records → canonical events | Dropped | SHA-256 raw |
| --- | --- | ---: | ---: | --- |
| Password spraying và Kerberoasting | `purplesharp_ad_playbook_I_2020-10-22042947.json` | 25.993 → 25.993 | 0 | `d86d22f0c02ab851564bb5e0c90c220e9df0319f5948bfc90dfa605b4511d4f0` |
| C2 thông qua Regsvr32 | `empire_launcher_sct_regsvr32_2020-07-21232741.json` | 2.390 → 2.390 | 0 | `8b619d07ad79713ae96234344c4ba9618eae7119c360ee008b5e0c2cfe4954d7` |
| PowerShell thông qua MSHTA | `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json` | 1.127 → 1.127 | 0 | `25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32` |

Tổng normalization: **29.510 input → 29.510 canonical events, dropped=0**. Active experiment có 10 external inputs: 3 JSONL, 6 SigmaHQ YAML và 1 MITRE bundle. Derived password-spraying correlation không được tính là external input.

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

- Nguồn dữ liệu production: `enterprise-attack.json`, được pin tại release `v19.1`, commit `6c3719993d0401de199203ecc3f369544d9e091c` và collection version `19.1`.
- Bundle SHA-256: `bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3`.
- Bundle chứa 25.843 STIX objects, 697 active attack-patterns và 477 quan hệ `subtechnique-of`.
- Resolver dùng exact-match và fail-closed.
- Production đã phân giải `T1059.007` — JavaScript, `T1140` — Deobfuscate/Decode Files or Information và `T1218.005` — Mshta.
- Output `mitre-resolution/v1` có 4 rule-technique candidate links, cùng hai quan hệ cha `T1059.007 → T1059` và `T1218.005 → T1218`.
- Techniques và links vẫn giữ trạng thái candidate; việc phân giải object không tự xác nhận hành vi. Ground truth MSHTA đánh giá `T1218.005` là `supported_by_observed_behavior`, `T1059.007` là `not_supported_by_observed_command` vì command dùng VBScript, còn `T1140` là `not_assessed`. Human review còn pending, không có label promotion sang `confirmed`.
- `attack.execution` và `attack.stealth` được giữ dưới dạng non-technique ATT&CK tags. Các tag `car.*` và `cve.*` được giữ riêng, không ánh xạ thành ATT&CK technique.

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
  - Core dùng hai cặp Security 4688/Sysmon 1: `4 ↔ 275` và `30 ↔ 398`. Cặp `36 ↔ 422` là PowerShell tạo `conhost.exe`, nằm ngoài hai nhóm evidence của core; không coi 3 entities core là toàn bộ process inventory.
  - PowerShell được khởi chạy với `-noexit -command Get-Service sysmon`; process creation không chứng minh cmdlet hoàn tất, đầu ra hoặc trạng thái dịch vụ.
  - Core không cung cấp bằng chứng download, C2, credential theft hay destructive payload. Full-file review có temporary-file deletion/event-log clearing ngoài core; không khẳng định toàn dataset không có thao tác xóa, và không tự coi các records này là payload cố ý phá hoại.

### 3.6. Prototype retrieval cho MSHTA

- [x] Builder tạo corpus **19 chunks** từ ground truth baseline, giữ IDs, status, pointers và source refs.
- [x] Có BM25 lexical retrieval, vector cosine retrieval, vector-index builder/query CLI và hybrid retrieval.
- [x] So sánh `all-MiniLM-L6-v2` và `multilingual-e5-small` trên bộ 32 câu Việt/Anh; có relevance judgments và model-selection artifact.
- [x] `multilingual-e5-small` được **đề xuất tạm thời** tại [embedding_model_selection.json](outputs/evaluation/mshta-powershell/embedding_model_selection.json); chưa phải lựa chọn cuối đã được human review và holdout xác nhận.
- [ ] Rebuild corpus/vector indexes/judgments từ version ground truth được duyệt và provenance mới.
- [ ] CTI bổ sung, model/parameters cuối cùng và vector database service nếu experiment yêu cầu.

Corpus/index là artifact cục bộ. Đáp án tham chiếu, category và expected decision chỉ dùng cho đánh giá, không đưa vào retrieval corpus hoặc runtime gate input.

### 3.7. Prototype GraphRAG và gate

- [x] Baseline graph builder tạo **17 nodes / 21 edges**, có validation/provenance.
- [x] Có neighborhood/path traversal và CLI; orchestration hybrid retrieval → seed mapping → multi-hop traversal → context có evidence.
- [x] Có relevance gate baseline, calibration/diagnostics và artifacts cho MiniLM/E5.
- [x] Có `gate_signals.py`, `two_stage_gate.py`, fixtures và unit tests cho gate hai tầng “đúng chủ đề → đủ bằng chứng”.
- [ ] Kiểm chứng gate hai tầng trên dữ liệu thực tế và holdout; chưa tích hợp vào CLI production.
- [ ] Policy gate đạt tiêu chí và graph database service; graph hiện lưu JSON và xử lý trong Python.

Cả [legacy calibration](outputs/evaluation/mshta-powershell/graphrag_relevance_calibration.json) và [E5 calibration](outputs/evaluation/mshta-powershell/graphrag_relevance_calibration_e5.json) thử **672 cấu hình × 32 câu**; đều có `no_eligible_policy`, `selected_policy=null`. Module/fixture pass không thay thế kiểm chứng gate trên dataset thực tế. GraphRAG chưa hoàn thành toàn bộ.

## 4. Checkpoint inspection và normalization

- [x] Structural inspection hoàn thành trên đúng ba dataset của `mordor-selected-v2`.
- [x] Canonical schema `canonical-event/v2` hoàn thành ở trạng thái reviewable.
- [x] Context-aware mapping registry theo `provider + EventID` hoàn thành.
- [x] Streaming normalization giữ contract một raw record tạo một canonical event.
- [x] Atomic writer và normalization CLI hoàn thành.
- [x] Production normalization hoàn thành: 29.510 input → 29.510 canonical events, dropped=0.
- [x] 104 tests passed tại checkpoint **20/07/2026** (commit `853b295`); đây là historical full-suite count, không phải số hiện tại.

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
- [x] Checkpoint production extraction **15/09/2026** (commit `d6a36c1`) ghi nhận 250 full-suite tests passed, 0 failed/skipped; đây là kết quả lịch sử.

`scenario-evidence/v1` không tự nhúng Sigma hay MITRE mapping; kết quả Sigma review được lưu thành artifact riêng để giữ ranh giới giữa evidence quan sát được và detection hypothesis.

### 4.2. Checkpoint Sigma MSHTA

- [x] Sigma YAML loader an toàn đã được triển khai bằng PyYAML safe loader, từ chối duplicate keys, arbitrary YAML tags và cấu trúc ngoài subset được hỗ trợ.
- [x] Sigma evaluator giới hạn đã được triển khai theo nguyên tắc fail-closed; logsource không được hỗ trợ làm evaluation dừng bằng exception thay vì âm thầm tạo zero matches.
- [x] Logsource hiện chỉ hỗ trợ đúng `product: windows` và `category: process_creation`, không phụ thuộc thứ tự hai key.
- [x] Mapping logsource tới canonical events chỉ chấp nhận Sysmon Event ID `1` hoặc Windows Security Event ID `4688`; provider được so sánh không phân biệt hoa thường và Event ID được chuẩn hóa an toàn giữa chuỗi với số nguyên.
- [x] Hai Sigma rules MSHTA đã chạy trên toàn bộ 1.127 canonical events: 4 observation matches, 2 behavior matches, 1.123 unmatched events và 0 `confirmed`.
- [x] Output dùng schema `sigma-match-review/v1`, giữ `analysis_status=needs_review` và deterministic SHA-256 `cafb455ce6ad59cc5cf5f62805a0d7354f6b88d69fc1414c6f860222fd147fe4`.
- [x] `OriginalFileName` được ghi nhận là known unmapped field vì chưa có trong `canonical-event/v2`; không bị trình bày như unsupported rule bị bỏ qua.
- [x] Sigma tags được giữ làm metadata/candidate mapping, chưa phải MITRE ATT&CK technique đã xác nhận.
- [x] Generated evidence, Sigma output và review package nằm trong `outputs/`, không commit.
- [x] Review package và milestone Sigma MSHTA đã được kiểm tra kỹ thuật PASS; điều này không thay thế human approval của ground truth.
- [x] Checkpoint Sigma **16/09/2026** (commit `e325c3e`) ghi nhận 40 Sigma tests và 290 full-suite tests passed, 0 failed/skipped; không gắn lại thành full suite hiện tại.
- [ ] Các câu hỏi âm tính/toàn dataset vẫn cần đánh giá riêng theo phạm vi đã chốt. Đọc toàn bộ raw file trong review 14/10 không tương đương detector âm tính toàn diện cho mọi hành vi.

### 4.3. Checkpoint MITRE ATT&CK STIX 2.1 resolver

- [x] Loader parse `enterprise-attack.json` dưới dạng STIX 2.1 và kiểm tra bundle theo nguyên tắc fail-closed.
- [x] Nguồn production được pin tại release `v19.1`, commit `6c3719993d0401de199203ecc3f369544d9e091c` và collection version `19.1`.
- [x] Bundle SHA-256 là `bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3`; bundle có 25.843 STIX objects, 697 active attack-patterns và 477 quan hệ `subtechnique-of`.
- [x] Resolver exact-match đã phân giải production techniques `T1059.007`, `T1140` và `T1218.005` từ ATT&CK objects.
- [x] Production output dùng schema `mitre-resolution/v1`, tạo 4 rule-technique candidate links và giữ quan hệ cha `T1059.007 → T1059`, `T1218.005 → T1218`.
- [x] Techniques và links giữ trạng thái `candidate`/`not_assessed`; không có technique nào được đánh dấu `confirmed`.
- [x] `attack.execution` và `attack.stealth` được giữ làm non-technique ATT&CK tags; `car.*` và `cve.*` được giữ riêng và không bị ánh xạ thành ATT&CK technique.
- [x] Production output deterministic, SHA-256 `f5eec09eaff36806e8567f215d9eed7edc7bc62dc3c3c9864dcbae3c6dcd608d`.
- [x] Enterprise ATT&CK production bundle và generated outputs không nằm trong Git.
- [x] Checkpoint MITRE **16/09/2026** (commit `fbafde9`) ghi nhận 29 MITRE tests và 319 full-suite tests passed, 0 failed/skipped; đây là kết quả lịch sử.
- [x] Review ZIP và milestone MITRE ATT&CK resolver đã được kiểm tra kỹ thuật PASS; mappings vẫn candidate và human approval còn pending.

### 4.4. Review checks ngày 14/10/2026 và phạm vi đánh giá

Lượt review ground truth/đáp án ghi nhận **592 relevant tests passed** thuộc sáu test files; JSON readback, source provenance và raw immutability được kiểm tra. Lệnh, kết quả và giới hạn Windows ACL được ghi tại [review_report.md](outputs/review/mshta-ground-truth/review_report.md). Đây không phải tuyên bố đã chạy full suite hiện tại.

Bộ 32 câu hiện là **calibration set**, chưa phải benchmark độc lập cho kết quả cuối cùng. Có 8 relevant_direct, 8 relevant_paraphrase, 8 insufficient_evidence và 8 unrelated; 16 câu tiếng Việt, 16 câu tiếng Anh. Insufficient evidence vẫn cùng chủ đề MSHTA, khác với unrelated dù cả hai đều có expected decision `abstain`.

Update Markdown này chỉ đồng bộ tài liệu; không thay code/JSON/raw và không chạy lại tests. Các historical test counts không được trình bày như kết quả hiện tại.

### 4.5. Phạm vi chưa hoàn thành

- [ ] Chưa tạo ground truth được người dùng duyệt.
- [ ] Chưa xây evidence extractor cho Regsvr32 và PurpleSharp.
- [ ] Chưa hoàn thành GraphRAG production policy, LLM hoặc UI; đã có prototype retrieval/GraphRAG cho MSHTA.

## 5. Những việc cần làm tiếp theo

Lát cắt chuyên sâu tiếp tục với MSHTA–PowerShell. Kiến trúc cần mở rộng được sang PurpleSharp và Regsvr32; hai kịch bản này chưa hoàn thành pipeline evidence và không bị loại khỏi phạm vi đồ án.

### 5.1. Thứ tự thực hiện cho MSHTA

1. **Người dùng duyệt ground truth sửa và 32 đáp án tham chiếu.** Giữ `pending_human_review` cho tới khi có quyết định thực sự; xử lý các caveat timestamp và phạm vi khi duyệt.
2. **Rebuild consumers và provenance** theo version được duyệt: corpus, graph, vector indexes, judgments và evaluation inputs. Không trộn hash baseline với bản review.
3. **Hiệu chỉnh/kiểm chứng gate hai tầng** trên dữ liệu thực tế; dành tập holdout riêng và báo cáo lỗi insufficient_evidence/unrelated riêng. Không dùng đáp án/category/expected decision làm runtime signal.
4. **Tích hợp policy đạt tiêu chí vào CLI GraphRAG**, lưu output tái lập và so sánh với RAG trên cùng dữ liệu/câu hỏi.
5. **Chọn và tích hợp LLM, prompt, output schema**, sau đó UI; bắt buộc trích dẫn và phân biệt observation/inference/candidate.
6. **Mở rộng evidence/ground truth sang PurpleSharp và Regsvr32** khi tiếp tục phạm vi ba kịch bản; viết/kiểm thử derived password-spraying correlation và tránh đếm đôi 4625/4776.

### 5.2. Checklist còn lại

- [ ] Human approval và ground truth cuối cùng cho MSHTA; 32 câu/đáp án hiện đã có bản review kỹ thuật.
- [ ] Consumer rebuild dùng đúng hash/version được duyệt.
- [ ] Holdout benchmark, tiêu chí pass/fail cuối cùng và policy gate hai tầng đạt yêu cầu.
- [ ] Gate hai tầng trong CLI/production workflow; module/fixture đã có.
- [ ] Model/parameters cuối cùng; E5 hiện chỉ được đề xuất tạm thời.
- [ ] Evidence extractor, Sigma/correlation và ground truth đầy đủ cho PurpleSharp/Regsvr32.
- [ ] `win_security_password_spray_correlation.yml` dưới dạng project-defined rule được kiểm thử.
- [ ] CTI bổ sung và quyết định vector/graph database service nếu experiment yêu cầu.
- [ ] LLM, prompt, output schema và quyết định severity/remediation.
- [ ] UI, end-to-end integration và thực nghiệm tái lập.
- [ ] Đánh giá độ chính xác, tính đầy đủ, khả năng giải thích, tính hữu ích và so sánh phương pháp cuối cùng.

## 6. Trạng thái theo milestone

| Milestone | Trạng thái | Bằng chứng chính |
| --- | --- | --- |
| Repository và project setup | Hoàn thành | GitHub repository, README, pyproject, tests |
| Lựa chọn dataset/Sigma | Hoàn thành | 3 JSON, 6 SigmaHQ, 1 derived rule được lên kế hoạch |
| Structural inspection v2 | Hoàn thành | Manifest 3/3, summary, inspection reports, baseline và SHA-256 |
| Canonical schema/mapping | Đã triển khai, còn review issues | `canonical-event/v2`, context-aware mapping registry và timestamp/context caveats được giữ |
| Canonical normalization | Hoàn thành | Streaming iterator, atomic writer, CLI, production run 29.510 input → 29.510 canonical events, dropped=0 |
| Evidence schema | Hoàn thành | `scenario-evidence/v1`, deterministic IDs và validation được kiểm thử |
| Evidence extraction | Đang thực hiện | MSHTA production extraction hoàn thành trên 1.127 canonical events; chưa có extractor Regsvr32/PurpleSharp |
| Sigma execution/correlation | Đang thực hiện | MSHTA loader/evaluator fail-closed và production review đã hoàn thành; password-spraying correlation cùng Regsvr32/PurpleSharp còn tạm hoãn |
| MITRE STIX resolution MSHTA | Hoàn thành resolver | Exact-match/fail-closed, ATT&CK v19.1, `mitre-resolution/v1`; mappings còn candidate/human pending |
| Ground truth | Review kỹ thuật hoàn thành; human approval pending | Bản sửa MSHTA và 32 đáp án tại `outputs/review/mshta-ground-truth/`, không có label promotion |
| RAG | Prototype retrieval cho MSHTA | 19 chunks, BM25/vector/hybrid; E5 đề xuất tạm thời; chưa rebuild từ ground truth sửa |
| GraphRAG | Prototype core cho MSHTA | 17 nodes/21 edges, traversal/orchestration; two-stage gate mới ở module/fixture level, chưa production |
| Relevance calibration | Đã chạy baseline/E5, chưa đạt | Mỗi lượt 672 × 32; `no_eligible_policy`, `selected_policy=null` |
| PurpleSharp/Regsvr32 evidence và ground truth | Chưa hoàn thành | Inspection/normalization/anchors có; chưa có pipeline evidence đầy đủ |
| LLM, giao diện và database services | Chưa triển khai | Chưa có tích hợp sinh câu trả lời, UI hoặc vector/graph database service |
| Đánh giá cuối cùng | Chưa hoàn thành | Calibration chưa thay thế holdout, human scoring hoặc end-to-end experiment |

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
- Không dùng reference answers, category hoặc expected decision làm corpus/runtime gate input.
- Không đổi thiếu evidence trong core thành kết luận vắng mặt toàn dataset.
- Không commit, push, publish data hoặc chỉnh tài liệu luận văn khi chưa được yêu cầu.

## 8. Bước tiếp theo duy nhất

**Người dùng duyệt bản sửa MSHTA và 32 đáp án tại `outputs/review/mshta-ground-truth/`.** Sau khi được duyệt: rebuild consumers/provenance → hiệu chỉnh và kiểm chứng gate hai tầng với holdout → tích hợp policy đạt tiêu chí vào CLI → LLM/UI. Review kỹ thuật đã hoàn thành; không tự ghi nhận human approval hay dùng reference answers làm runtime input.

## 9. Cách cập nhật file này

Sau mỗi milestone:

1. Cập nhật ngày.
2. Chuyển checkbox chỉ khi có bằng chứng.
3. Ghi file/code/output liên quan.
4. Ghi test command và kết quả thực tế.
5. Ghi raw hash trước/sau nếu có xử lý dữ liệu.
6. Ghi giới hạn và việc còn thiếu.
7. Chỉ giữ một “bước tiếp theo duy nhất” để tránh triển khai lan man.


## 10. Checkpoint GRAPHRAG-2D3 ? 16/10/2026

M?c n?y c?p nh?t tr?ng th?i hi?n h?nh; n?i dung checkpoint 14/10/2026 v? c?c thay ??i c? s?n ph?a tr?n ???c gi? nguy?n ?? truy v?t. Human approval MSHTA v? 32 reference answers ?? ???c ghi nh?t qu?n b?ng schema v2, reviewer `Nguyen Hong Phong`, th?i ?i?m ghi nh?n x?c nh?n `2026-10-15T23:36:13+07:00`. C?c nh?n evidence/MITRE v?n observed/inferred/candidate; approval t?i li?u kh?ng x?c nh?n attack.

Theo ch? ??nh hi?n t?i, GRAPHRAG-2D3 gi? nguy?n corpus/graph/indexes v? kh?ng t?ch h?p CLI. C? 32 cases ?? ???c d?ng ?? ch?n model v? calibration tr??c, n?n to?n b? v?n l? development/calibration data. Kh?ng chia l?i th?nh held-out ??c l?p. Audit kh?ng th?y benchmark labels, case IDs hay nguy?n reference answers trong corpus/graph, nh?ng ph?t hi?n wording c? ?PowerShell ran/runs Get-Service sysmon? v? thi?u ba caveats/original observations c?a Ground Truth ?? s?a. V? v?y ch? di?n gi?i calibration l? diagnostic; kh?ng x?c nh?n policy ??t y?u c?u.

?? d?ng E5 local c? s?n, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, thu context/signals cho 32 queries v?i retrieval top_k=5, candidate_k=20, RRF k=60, traversal both/depth=2/nodes=100/edges=200. Kh?ng t?i model m?i ho?c g?i LLM. Ch? text c?a truy v?n hi?n t?i ?i qua query embedding; labels/answers/expected evidence ???c gi? b?n ngo?i runtime. Kh?ng rebuild ho?c s?a consumer artifacts.

??nh gi? 17 candidate policies ch? hi?u ch?nh ba ?i?u ki?n ?? c?ng b?, ?? 8 topical v? 12 answerability settings. ?ng vi?n kh?ng abstain to?n b? t?t nh?t l? `two-stage-dev-5a4b308b106699e0`: TP=5, TN=15, FP=1, FN=11 theo nh?n dataset; false proceed unrelated=0/8, insufficient_evidence=1/8; coverage=6/32; sai trong proceed=1/6. Trong 13 c?u c? context ?? theo rubric ??nh gi? b?n ngo?i, false abstain=8/13; ba c?u kh?c c? ??p ?n trong Ground Truth nh?ng context thi?u th?ng tin. Answerability not_evaluated=26/32, kh?ng g?p th?nh failed. Rubric context l? di?n gi?i k? thu?t c? c?n c? t? approved sources, kh?ng ph?i t?p nh?n m?i ?? ???c con ng??i duy?t.

?? kh?a policy/configuration/split/evaluation code/criteria/signals b?ng SHA-256; replay saved signals kh?p ho?n to?n v? kh?ng ???c t?nh l? th? nghi?m ??c l?p. Held-out ch?a ch?y: kh?ng c? t?p c? ch?a d?ng; 11 probes m?i do AI ?? xu?t c?n pending_human_review (5 full-raw sufficient, 3 insufficient, 3 unrelated). C? 5 positives m?i c?n chi ti?t ngo?i core ch?a c? trong frozen consumers, n?n ch?a ?? ?i?u ki?n positive-context held-out c?a policy hi?n t?i. Kh?ng d?ng 11 probes ?? ch?n thresholds, kh?ng ch?y query embedding/gate tr?n ch?ng.

Tests: focused 124 passed; related regression 1.289 passed; full suite 5.815 passed + 6 subtests passed, 0 failed/skipped. L?nh ch?nh x?c, per-case results, hashes v? gi?i h?n n?m trong `outputs/review/graphrag-two-stage-gate-calibration/`; review package t?i `outputs/review/graphrag_two_stage_gate_calibration_review.zip`.

B??c ti?p theo duy nh?t: review k?t qu? diagnostic v? ph?m vi/nh?n c?c probes m?i; quy?t ??nh c?ch x? l? consumer evidence c? tr??c khi cho ph?p m?t l?n ki?m ch?ng ??c l?p c? ? ngh?a. Kh?ng t? chuy?n sang CLI, LLM ho?c UI; kh?ng stage/commit/amend/push.

## 11. Checkpoint GRAPHRAG-2D3-FIX1 — 16/10/2026

Theo yêu cầu FIX1, đã đồng bộ evidence consumers thử nghiệm với Ground Truth v2 được duyệt. Giữ nguyên toàn bộ bytes của checkpoint cũ phía trên. Branch vẫn `feature/mshta-evidence-extractor`, HEAD `af2243a3ee89c5e5721ec341eea0a8cb06814f41`, staging rỗng. Không sửa approved bundle, raw data hoặc consumer/review artifacts cũ.

Sáu compatibility source files được sửa: `retrieval/builder.py`, `retrieval/schema.py`, `graph/builder.py`, `graph/schema.py`, `graphrag/relevance.py`, `evaluation/calibration_schema.py`. Hỗ trợ đúng GT v1/v2, provenance ghi phiên bản thực tế, v1 golden outputs giữ nguyên; downstream schema v1 không đổi. Không đưa human approval hoặc benchmark questions/answers/labels/case IDs/rubric vào evidence embeddings hay runtime gate inputs.

Builders thực tế tạo `outputs/experiments/graphrag-2d3-fix1/`: 22 chunks, graph 20 nodes/21 edges, 22 vectors mới dimension 384. Nguồn là approved GT SHA-256 `8676d7a1df41058e7f4b1460a0d4bf909fca5d8f20992753e63be7d024268461`. Corpus mới `b57ffad3d1e3b797e1b5fae7360b605a67acbecede8fb98ce8faf6f993cc695c`; graph `04d6efd2ca47388689ad376766f96f9136a9a8f4ef22403b4bc1ed4ff30ae443`; index `2182baefb9598609c5e1e9a92ac370b366e0fcab79e8d672ac64adcb7717ae78`. Giữ E5 local revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, prefixes, L2/cosine và preprocessing cũ; 0 old-cache hits, 22 document và 32 query misses. Determinism replay chỉ dùng đúng inputs/vectors của cùng lần build.

Source observations giữ nguyên CommandLine, parent/child fields, IDs và raw references trong content/attributes được context trả về. Summary chỉ xác nhận PowerShell được khởi chạy với command line chứa Get-Service sysmon, không xác nhận cmdlet completion/output/service state. Đủ 7 limitations có trong consumers và mỗi limitation xuất hiện trong ít nhất một actual context của 32 queries; số contexts tương ứng là 2/3/3/2/3/1/13. Không thêm causal edges hoặc mở core sang probes ngoài phạm vi. Ba queries trọng tâm vẫn chưa nhận đủ context: scope-limitations và service-action có semantic support unassessed/null, final-review-limits thiếu structured analysis_status và các limits cần thiết. Không coi null là đã sửa xong.

Chạy lại đúng 32 development cases với policy `two-stage-dev-5a4b308b106699e0` và retrieval top-k=5, candidate-k=20, RRF k=60, traversal both/depth=2/nodes=100/edges=200 giữ nguyên. Không tune thresholds hoặc đổi rubric. TP/TN/FP/FN đổi 5/15/1/11 → 5/14/2/11; topical 7 passed/25 failed, answerability 7 passed/0 failed/25 not_evaluated; coverage 7/32, selective error 2/7. False proceed insufficient_evidence vẫn 1/8 (payload-download URL); unrelated tăng 0/8 → 1/8 (Linux cron). Chỉ có một transition abstain→proceed, không có true positive mới. False abstain với context đủ vẫn 8/13 theo conservative AI rubric ngoài runtime; hai positives chuyển false→null không được tính là đủ context.

Tests cuối: focused 85 passed; regression liên quan 2541 passed; full suite 5900 passed + 6 subtests passed, 0 failed/0 skipped. Exact commands, durations và các failed attempts trước khi sửa synthetic tests nằm trong `outputs/review/graphrag-ground-truth-v2-consumer-sync/tests.json`. Kiểm tra JSON/validators/bindings, replay context→signals→decisions và git diff --check đều pass. Inventory ghi hashes trước/sau của toàn bộ 5055 baseline files: chỉ sáu compatibility source files và phần append file tiến độ này thay đổi; raw inputs, approved bundle, consumer/review artifacts cùng ZIP cũ giữ nguyên hash.

Kết quả và per-case analysis tại `outputs/review/graphrag-ground-truth-v2-consumer-sync/`; gói review `outputs/review/graphrag_ground_truth_v2_consumer_sync_review.zip`. Source/build sync đạt; runtime context coverage và gate quality chưa đạt. Answerability hiện chỉ kiểm tra cấu trúc nên vẫn cho phép câu hỏi URL thiếu evidence và câu ngoài phạm vi. Bước tiếp theo duy nhất là review regression/context gaps này trước khi quyết định cơ chế answerability theo yêu cầu và retrieval hỗ trợ limitations. Không chạy 11 proposed probes hoặc held-out; không tích hợp production CLI/LLM/UI; không stage/commit/amend/push. Dừng chờ review kết quả.

## 12. Checkpoint GRAPHRAG-2D3-FIX2 — 17/10/2026

Đã triển khai luồng thử nghiệm query requirements → bounded context enrichment → evidence support → query-aware eligibility, với design note viết trước code. Thêm bốn modules `query_requirements.py`, `query_context.py`, `query_support.py`, `query_gate.py`, research runner `scripts/evaluate_query_aware_gate.py` và năm test files mới. Mọi source/tests/fixtures có sẵn giữ nguyên bytes; không đổi legacy APIs/schema/policy hoặc production defaults. Phần tiến độ cũ được giữ nguyên toàn bộ làm prefix.

Parser deterministic EN/VI có vocabulary công khai và biểu diễn supported/ambiguous/unsupported, scope/platform, process roles và mandatory requirements. Verifier chỉ kiểm tra items thực sự trả về, giữ supported/missing/unknown, trace tới field/ID/provenance, không dùng labels/answers/rubric. Process launch không chứng minh completion/output/service state; URL cần actor/action binding; candidate không thành confirmed. Với command invocation/service identity chưa bind được, verifier giữ unknown. Chỉ tách scope mismatch rõ ràng; phủ định/so sánh chưa phân giải là ambiguous.

Giữ nguyên FIX1 corpus/graph/index/model/revision cùng policy `two-stage-dev-5a4b308b106699e0`; không gọi embedding/LLM. Reuse ranked contexts đã đóng băng cho cùng 32 development queries; bổ sung evidence không có scores/paths giả. B/D tính lại legacy ranked signals và diagnostics final context riêng. Budget mặc định 12 supplements, 64 final items, 131072 canonical UTF-8 serialized bytes (không gọi là token count). Đã thêm tổng cộng 16 items cho 7 queries, max 6/query; không cut budget. External AI rubric giữ tiêu chí: context sufficient tăng 13→14, không đánh giá bằng checker mới rồi coi là ground truth.

A/B: TP/TN/FP/FN = 5/14/2/11, coverage 7/32, selective error 2/7. C/D: 2/16/0/14, coverage 2/32, selective error 0/2. D false abstain/context đủ = 12/14; parser 10 supported/10 ambiguous/12 unsupported; support 9 supported/1 missing/22 unknown. Linux cron bị scope mismatch; URL case bị chặn vì actor parsing ambiguous/support unknown, chưa phải xác minh trực tiếp missing download evidence. EN D2/8/0/6, VI D0/8/0/8; không có proceed tiếng Việt. Scope-limitations context đã đủ cả7 units theo rubric; final-review-limits vẫn thiếu context; service-action vẫn thiếu completion limitation theo rubric. False abstain và unsupported-query rate chưa chấp nhận được cho production.

Có hai vòng development; vòng đầu lưu riêng trong `iterations/initial/`. Review đã sửa invariant generic về named constraints/unanchored chain/ignored assertions/unresolved negated scope, dùng synthetic tests, không tune thresholds hoặc chạy proposed probes. Không coi các vòng này là held-out. Runtime/runner hashes vòng cuối được khóa và kiểm tra; source hashes vòng đầu chưa chụp tại thời điểm chạy được nêu rõ.

Tests cuối: focused 221 passed; regression 2541 passed; full suite 6121 passed + 6 subtests passed, 0 failed/skipped. Exact commands/logs tại `outputs/review/graphrag-query-aware-answerability/tests.json` và experiment logs. Inventory ghi hashes trước/sau của 5279 baseline files; raw data, approved bundle, FIX1 artifacts và các ZIP cũ không đổi. Git diff --check sạch, staging rỗng; branch/HEAD không đổi.

Kết quả tại `outputs/experiments/graphrag-2d3-fix2/` và `outputs/review/graphrag-query-aware-answerability/`; gói review `outputs/review/graphrag_query_aware_answerability_review.zip`. Bước tiếp theo duy nhất: review FIX2 và quyết định mở rộng clause/role binding, support completeness và cấu hình chất lượng EN/VI trước calibration/kiểm chứng độc lập. Chưa thực hiện các đề xuất đó. Không chạy 11 proposed probes hoặc held-out; không stage/commit/amend/push; không tích hợp production CLI/LLM/UI. Dừng chờ review kết quả.

## 13. Checkpoint GRAPHRAG-2D3-FIX3 — 17/10/2026

Đã thêm parser/context/support v2, policy composition riêng, research runner E0–E4 và 5 test files; giữ nguyên mọi source/tests/fixtures cũ và replay exact FIX2 D. Policy/design cùng hashes source được khóa trước benchmark, một design duy nhất, không sweep hoặc sửa runtime theo kết quả. E1 có checker compatibility cho requirement contract mới; E2 giữ old checker assessment và independent guards riêng. Labels/reference answers/rubric ngoài runtime. Không rebuild corpus/graph/index, đổi model hay gọi embedding/LLM.

E0 TP/TN/FP/FN=2/16/0/14; E1=5/16/0/11; E2=6/16/0/10; E3=8/16/0/8; E4=9/16/0/7. E4 cứu thêm 7 dataset positives so E0, gồm 4 VI, không mất baseline TP hoặc thêm dataset FP; EN=5/8/0/3, VI=4/8/0/4. Coverage9/32, selective error0/9, recall9/16; false abstain/context đủ6/14. Parser13supported/8ambiguous/11unsupported; support9supported/2missing/21unknown. URL-download đã bind PowerShell/download/url và kiểm tra trực tiếp missing, không còn parserunknown. Limits/chain completeness so exact source identities, host/GUID/sourceentity instances; không nối basename/PID khác lifetime, giữ unknown cho cycle/depth/unresolved source boundaries.

E4 tổng18supplements, max6/query; context26582–60995 canonical UTF-8 bytes, mean51389.1875; không cut budget. External AI rubric giữ nguyên: rp-vi-service-action proceed theo approved label nhưng context_sufficient=null vì thiếu exact completion limitation_4; chỉ launch command được chứng minh. E2→E3 mất tạm proxy-technique query do review_status requirement mới, E4 phục hồi bằng scenario metadata; object binding review-status còn cần review, không đồng nhất scenario analysis_status với technique/human approval. 7 false abstains còn lại và 21 supportunknown ngăn tuyên bố khóa production/independent-validation config.

Tests cuối: focused 221 passed; regression 2883 passed; full suite 6342 passed + 6 subtests, 0 failed/skipped. Exact commands/logs ở outputs/review/graphrag-parser-policy-fix3/tests.json. Audit5.528 baseline hashes giữ nguyên ngoại trừ append này; toàn bộ tiến độ cũ giữ nguyên bytes làm prefix. Raw inputs, approved bundle, FIX1/FIX2 artifacts và ZIP cũ không đổi; staging rỗng, branch/HEAD không đổi, git diff --check sạch.

Artifacts: outputs/experiments/graphrag-2d3-fix3/; báo cáo/changed cases/inventory tại outputs/review/graphrag-parser-policy-fix3/; ZIP outputs/review/graphrag_parser_policy_fix3_review.zip. Không chạy11proposedprobes/held-out, không production CLI/LLM/UI, không stage/commit/amend/push. Dừng chờ review FIX3; chưa thực hiện đề xuất sửa semantic coverage hoặc kiểm chứng tiếp theo.
