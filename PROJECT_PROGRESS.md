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


## 14. Checkpoint experimental và UI QA — 27/10/2026

Theo yêu cầu mới, đã chốt triển khai hiện có bằng inventory SHA-256, source/artifact package, QA UI bằng saved responses/fixtures và harness RAG–GraphRAG. Phạm vi này ưu tiên so với mô tả LLM/UI chưa triển khai ngày 14/10; không nâng approval hoặc techniques. Checkout hiện thiếu .git nên branch/HEAD/status không xác minh được; không suy từ lịch sử. Không commit/push.

Safe replay service phục vụ frontend build tại http://127.0.0.1:8001/qa.html?case=RG04, không có LLM routes. Đã sửa guard/export UI cho rejected/fallback, thêm nhãn draft/human review, citations và replay provenance. Browser control bị URL policy Cốc Cốc chặn; chưa dynamic browser QA hoặc ảnh thật. Hướng dẫn chụp thủ công 8 trạng thái trong review package.

Harness giữ nguyên 15 câu và rubric lịch sử (9 answerable/3 overreach/3 out_of_scope), cùng hybrid retrieval, prompt/schema/model/generation/validation/budgets. RAG không nhận graph context qua validator. Dry-run cuối đủ 30 nhánh, 0 LLM attempts, 0 runtime errors; 12 cặp retrieved có ranked hits giống nhau, 3 cặp scope abstain. RAG proceed0/15, GraphRAG12/15; policy yêu cầu graph traversal nên RAG bị chặn theo cấu trúc. Đây là blocker cho kết luận hơn-kém chất lượng đáp án, không phải bằng chứng GraphRAG vượt trội. Không nới policy; answer/citation semantic metrics còn pending.

Relevant verification: 123 backend/LLM tests và 21 harness/replay tests passed; 22 React SSR assertions passed; frontend TypeScript/Vite build passed (giữ bundle-size warning). Tests/build có lượt lỗi sandbox temp/esbuild, đã chạy lại cục bộ bằng quyền escalated; không phải retry API. Chưa full suite hoặc independent validation.

Giữ hashes của mọi old outputs/canonical/approved artifacts có trong inventory; append tiến độ giữ nguyên toàn bộ bytes cũ. Cả 10 original inputs không có trong checkout nên chưa fresh raw/Sigma/STIX audit. PurpleSharp hiện là launch slice; PS02 verdict SUSPICIOUS cần human review; MS01 chưa có pre-sanitize values lịch sử để phân định lỗi. Candidate/approval metadata giữ nguyên. Loại metric hardcode và SSE dựng sẵn khỏi phép đo.

Báo cáo, before/after/integrity manifests, final contexts và package tại outputs/review/experimental_checkpoint_20261026/. Thiết kế/lệnh CMD: docs/EXPERIMENTAL_EVALUATION.md. Lệnh offline0 requests; lệnh live chuẩn bị cap12 attempts tuần tự, gate chặn thì không gọi LLM, dừng401/403/429, không retry/fallback. Chưa gọi API LLM thật; không đổi model/provider/environment file. Không mở thêm vòng tinh chỉnh.


## 15. RAG source-evidence gate contract — 27/10/2026

Đã audit từng rejection từ experimental_checkpoint_20261026. Ba out_of_scope bị chặn đúng trước retrieval;12 RAG khác đều pass topical nhưng fail mapped-hit/seed/traversal requirements của graph-only contract. Adapter RAG cũ không thiếu graph objects do bug; dựng topology giả sẽ sai. Đã thêm experimental source-evidence contract chung, giữ legacy decision riêng, source raw fields/provenance từ returned context và finite query requirements. Không đổi production policy hoặc thresholds/prompt/schema/guardrail; không dùng benchmark labels/answers trong runtime.

Before→after: RAG0/15→8/7 proceed/abstain, GraphRAG12/3→9/6. MS03 cả hai thiếu explicit core boundary; RG02 RAG có URL summary nhưng thiếu source command_line fields; PS04/RG04 bị contract thận trọng chặn cả hai dù có thể trả lời giới hạn theo rubric cũ. Per-case expected criteria/actual chunks/witnesses/reasons và rubric review độc lập có tại outputs/review/rag_gate_contract_20261027/. Không gọi mọi rejection là lỗi hoặc thiếu evidence hoàn toàn.

Đã chạy lại30 branches và pilot dry-run4 branches,0 API LLM thật;24 returned contexts/messages và12 paired retrievals không đổi. Pilot PS02/RG03 chọn trước theo factual fields/provenance chung, cap4 requests chỉ vận hành, chưa live. Full set17 branches eligible nên cap12 cũ không đủ; source-contract harness yêu cầu cap bao hết planned branches của subset case pairs xác định trước, không cắt theo thứ tự, không auto-resume.

284 relevant tests passed (283 contract/harness/original gates +1 audit-join fixture). Sandbox temp error được rerun escalated; không full suite, không frontend changes/build. Checkpoint cũ, approved/runtime artifacts và benchmark giữ hashes; docs/progress append giữ prefix. Không ZIP mới, không .env/model/provider/approval changes, không commit/push hoặc claim independent validation/GraphRAG generation superiority. Báo cáo/lệnh CMD chính xác: outputs/review/rag_gate_contract_20261027/report.md; pilot_plan.json.


## 16. Offline review live pilot source-contract-02 — 27/10/2026

Đã review bốn saved live branches PS02/RG03 của outputs/experiments/rag-graphrag-pilot-source-contract-02, không gọi API mới hoặc chạy lại pilot. Core command/host/endpoint/Event ID/raw refs và citations khớp supplied context qua AI-assisted review; structured validation passed4/4 không xác nhận prose/verdict. Cả bốn SUSPICIOUS verdicts vẫn needs_human_review; reviewer là Codex/AI, không user approval. Review/field bindings riêng tại outputs/review/pilot_source_contract_02_offline_review_20261027/.

Đã sửa reporting-only: maximum_llm_requests ghi effective per-run cap (pilot4, offline0), tách harness_request_ceiling30; warning theo live/offline mode. Constant30 cũ không phải execution guard: manifest configured_request_budget4, một attempt/branch và tổng4. Không sửa artifacts gốc; source snapshot và AST check xác minh không đổi retrieval/gate/prompt/generation/validation hoặc budget application.16 focused mock tests passed sau rerun lỗi sandbox temp, không full suite/build frontend.

Budget vẫn262144 canonical UTF-8 bytes/context và294912 bytes/messages chung hai nhánh, không phải tokens/wire bytes; actual GraphRAG context dài hơn theo retrieval. Bốn saved messages dựng lại khớp exact, không provider probe. Khác biệt input-token usage/upstream model/retries chưa quan sát được; không tune từ pilot outputs.

Đã offline verify13 remaining cases (loại PS02/RG03),26 branches,13 eligible (RAG6/GraphRAG7),13 abstain,0 LLM attempts/runtime errors. Lệnh live chuẩn bị cap26 vì preflight yêu cầu bao toàn planned pairs; expected attempts theo frozen gate13, không gọi lại pilot. Config/model/rubric/artifact hashes tương thích; chỉ code reporting thay đổi. Chưa gộp live results vì remaining live chưa chạy; phải recheck actual manifests, disjoint complete keys và giữ batch/order trước gộp. Không .env/model/provider/gate/prompt/approval changes, không commit/push/ZIP.


## 17. Tổng hợp offline hai lượt RAG–GraphRAG — 27/10/2026

Đã đối chiếu actual manifests của pilot-source-contract-02 và remaining-source-contract-01. Config/model/generation/rubric/12 runtime artifacts khớp; code khác duy nhất là reporting-only cap/warning, đã bind snapshot và so AST không thay hành vi. Gộp riêng đủ15 case×2 branches, không trùng/thiếu, giữ batch/order và291 source files nguyên hash. Không API, không rerun generation/retrieval/embedding, không tune runtime.

Kết quả: RAG5 accepted/3 validation_failed/7 abstain; GraphRAG8/1/6; tổng17 recorded attempts,13 accepted drafts,4 rejected,13 abstain,0 provider/rate-limit/fallback/runtime errors. Review17 raw outputs theo locked criteria: primary factual anchors và citations phù hợp8/8 RAG,9/9 GraphRAG (diagnostic, gồm rejected); không đồng nghĩa toàn report đúng. Chỉ2 MS04 reports được AI review sạch trong scope;15/17 còn needs_human_review, gồm11 SUSPICIOUS,3 MALICIOUS chưa có evidence judgment riêng và1 INSUFFICIENT_EVIDENCE scope không rõ dù direct answer đúng. Không human approval.

Cả4 failures có pre-sanitize đầy đủ:3 RAG failures liên quan thiếu raw fields/structured assessment.external_id; MS02 GraphRAG actual confidence candidate khác giá trị supported_by_observed_behavior mà validator đòi, evidence_support khớp source. Reason assessment_promotion không chứng minh model nâng confirmed; giữ rejection và không sửa guardrail.13 abstains phân biệt6 đúng out_of_scope,2 MS03 context-incomplete theo positive label,4 overreach abstains được rubric cho phép nhưng limited-answer opportunity còn có,1 RG02 RAG summary-level false-abstain candidate.

Timing generation+validation tách khỏi abstain; pure provider-call timer không được lưu. Context byte means trên generated samples RAG16086.5/GraphRAG68582.4, cùng byte caps không cùng token count. Không dùng accepted coverage hoặc hai batch nhỏ làm bằng chứng GraphRAG generation tốt hơn. Regression đã dùng khi sửa hệ thống, single generation/branch/case, slice data và AI-assisted review là giới hạn bắt buộc.

Báo cáo/bảng30 rows và15 pairs/source traces/review riêng tại outputs/review/rag_graphrag_combined_semantic_20261027/. Có6 Markdown replay cards và screenshot_plan có nhãnOFFLINE, không ảnh giả/production UI QA claim hoặc API mới.4 fixture tests tổng hợp passed; không full suite/build vì không đổi runtime/frontend. PROJECT_PROGRESS append giữ lịch sử. Không model/prompt/gate/guardrail/env/approval changes, không ZIP lớn/commit/push.


## 18. Chốt tài liệu mốc thực nghiệm — 27/10/2026

Đã soạn docs/EXPERIMENTAL_RESULTS.md làm bản nháp chương thực nghiệm tiếng Việt từ review tổng hợp rag_graphrag_combined_semantic_20261027. Tài liệu mô tả implementation hybrid RAG/graph expansion thực tế, cấu hình model/E5/evidence contract/gate/guardrail, batch pilot và remaining, bảng outcomes/semantic/citation/timing có nguồn CSV/JSON, bốn cặp MS01/MS02/RG01/RG02 và giới hạn slice/regression/single-generation/AI review. Không gọi accepted coverage là accuracy hoặc kết luận GraphRAG sinh câu trả lời tốt hơn từ validation pass.

Làm rõ 15/17 whole reports còn điểm AI cần human review không phải tỷ lệ sai; tách contract failures đã tái dựng, verdict/role chưa được bằng chứng hỗ trợ và factual content chưa phát hiện lỗi. Cả17 vẫn chưa được người dùng phê duyệt ở cấp semantic review mới; không thay trạng thái approval hoặc các quyết định nguồn đã có.

Đã tạo docs/EXPERIMENTAL_DEMO.md: lệnh CMD cho replay server8001, sáu document replay cards theo screenshot_plan, hướng dẫn ảnh chụp thủ công. Nêu rõ allowlist UI hiện có dùng fixtures lịch sử khác, không gắn nhãn là hai lượt source-contract. Không khởi động dịch vụ/browser hoặc tạo ảnh trong task tài liệu. docs/EXPERIMENTAL_SUBMISSION_CHECKLIST.md tách nội dung bắt buộc theo đề cương, hướng phát triển và kết luận cần người dùng duyệt; PurpleSharp launch chưa hoàn thành kiểm chứng spraying/Kerberoasting, cần chốt phạm vi với người hướng dẫn thay vì tự nâng mức hoàn thành. Không đặt production/DB/holdout mới thành điều kiện chặn nộp.

Đã đối chiếu counts/status/annotations, kiểm tra liên kết nội bộ và UTF-8; kiểm tra hashes giữ nguyên artifacts hai lượt gốc, toàn review tổng hợp, runtime/frontend/config. Manifest kiểm tra tài liệu tại outputs/review/experimental_documentation_20261027/. PROJECT_PROGRESS chỉ append, giữ nguyên prefix lịch sử. Không API/retrieval/embedding/generation rerun, không tune runtime/model/prompt/gate/guardrail/env, không human approval tự động, không full suite/frontend build vì chỉ đổi tài liệu, không ZIP/commit/push. Mốc kết quả đã đóng để viết đồ án; còn tích hợp bản nộp, chụp minh họa thật và các quyết định human review/phạm vi.


## 19. Recheck gate từ experimental checkpoint — 27/10/2026

Theo yêu cầu nhắc lại mốc experimental_checkpoint_20261026, đã đối chiếu legacy graph-topology rejection và chạy lại30 branches bằng source-evidence contract hiện có, chỉ offline. Không sửa runtime vì migration đã được triển khai/review ở mục15. Legacy RAG0 proceed/15 abstain, GraphRAG12/3; recheck RAG8/7, GraphRAG9/6,17 eligible tổng,0 LLM attempts/runtime errors.24 contexts giống cả legacy checkpoint và lượt source-contract trước,24 messages giống source-contract trước;12 paired hybrid retrievals giống nhau. Gate/projection/budget decisions tái lập nguyên trạng. Reporting-only code difference lịch sử được bind snapshot/hash và kiểm tra AST lại.

Đã tái xuất audit15 cases/30 rows, nguyên query/expected criteria, retrieved chunks/content/provenance, original failed settings và source checks/witnesses tại outputs/review/rag_gate_contract_recheck_20261027/audit/. Rubric AI review tái dùng vì context exact equal, không runtime input/human approval.12 RAG ca qua scope cũ fail min_mapped_hit_count1/min_seed_node_count1/require_traversal=true với actual0/0/false;3 out_of_scope chặn đúng trước retrieval. Current abstains phân biệt MS03 boundary partial, RG02 RAG summary-level support thiếu raw field, PS04/RG04 limited-answer opportunity và out_of_scope; không gọi mọi rejection là lỗi hoặc thiếu toàn bộ evidence.

Pilot command cap4 dùng lại PS02/RG03 đã khóa trước outputs trong design cũ; đã verify selection hash và4 current branches eligible. Không chọn lại theo outputs, không chạy pilot live, không gọi selection này fresh/independent vì lịch sử đã có saved pilot+remaining live và review. Cap12 không đủ17 eligible của full15 pairs; preflight full planned set cần cap30, hoặc subset complete pairs xác định trước. Không có auto-resume; không thay ca khi gate chặn, không retry/fallback, dừng401/403/429.

18 focused source-contract tests passed, chỉ warning không ghi được pytest cache; không full suite/frontend build. Report/CSV/JSON/contexts/messages/config manifests mới trong outputs/review/rag_gate_contract_recheck_20261027/. Giữ nguyên936 files đã inventory trước append tiến độ; checkpoint/design/old runs/combined review/runtime/config không đổi. PROJECT_PROGRESS append giữ nguyên prefix, không .env/model/provider/approval changes, không ZIP/commit/push. Không có bằng chứng generation mới hoặc kết luận GraphRAG tốt hơn; mốc tài liệu và kết quả đã chốt trước đó vẫn giữ nguyên.


## 20. Đóng recheck và chuẩn bị demo saved outputs — 28/10/2026 (mốc thực nghiệm 27/10)

Theo quyết định người dùng, recheck là kiểm tra tái lập đã đóng, không mở pilot/full live mới. Hai lượt live đã tổng hợp và ba tài liệu EXPERIMENTAL_RESULTS/DEMO/SUBMISSION_CHECKLIST tiếp tục là mốc hiện hành. Đã thêm trạng thái chốt vào tài liệu và banner ngay đầu EXPERIMENTAL_EVALUATION: các lệnh live/cap/pilot ở kế hoạch cũ là lịch sử, không phải bước cần chạy hoặc điều kiện nộp. Giữ nguyên bản báo cáo/design/artifacts lịch sử, không sửa dữ liệu hoặc đánh giá đã chốt.

Đã chuẩn bị6 ảnh theo DEMO:4 document replay (overview, RG03 answer/citation, MS02 rejected, MS03/RG02 abstain) và2 historical UI replay (MS04 draft, MS01 rejection). Có filename/caption, thao tác VSCode Preview/split JSON/Win+Shift+S, thư mục screenshots riêng; chỉ4 document images nếu browser không khả dụng. Không tạo ảnh giả hoặc ảnh screenshot trong lượt này. Caption phân biệt UI fixtures corrective regression cũ với outputs source-contract mới; không gán ảnh UI cũ là số liệu hai lượt đã tổng hợp.

Đã khởi động riêng scripts/serve_ui_replay.py --port8001, không production backend/router LLM. GET local health/page/saved responses xác minh replay_only, llm_routes=false, HTTP200, source hashes khớp, MS04 proceed+validation passed, MS01 validation_failed, RG05 abstained. Không gọi provider hoặc generation. Chưa browser visual QA/click/export; người dùng thực hiện chụp ảnh thật. Bằng chứng HTTP và capture plan tại outputs/review/experimental_demo_ready_20261027/.

Phát hiện replay server lịch sử còn chạy và ghi các GET demo vào stderr log checkpoint. Đã xác minh/dừng đúng hai PID cũ, giữ server demo mới, lưu toàn bộ log phát sinh riêng trong thư mục demo và khôi phục exact prefix log checkpoint theo SHA-256 trước task. GET kiểm tra sau đó không thay log cũ; replay_log_preservation.json ghi chi tiết. Không mất dòng log hoặc sửa kết quả thực nghiệm.

Checklist mới có ánh xạ việc tích hợp vào chương2/3, kết luận, hình/bảng/phụ lục/tham khảo và các kết luận cần duyệt. Không lặp calibration, benchmark, aggregation, semantic scoring hoặc generation đã hoàn thành; không tune runtime. Chỉ cập nhật tài liệu và append tiến độ; không human approval tự động, không ZIP/full tests/frontend build/commit/push. Các artifacts live/combined/recheck được giữ hash, ba tài liệu cập nhật workflow/trạng thái không đổi số liệu thực nghiệm.


## 21. Source meaning v6, checkpoint recovery và integrated dashboard — 30/10/2026

Đã xác minh artifacts v5 thật: gốc4 accepted/12 provider_error/8 abstain; recovery8 accepted/1 validation_failed/1 provider_error/2 not_run. Trace trạng thái theo khóa là12 accepted/1 validation_failed/8 abstain/1 provider_error/2 not_run, không gộp generation khác phiên bản thành benchmark hoặc chọn câu trả lời tốt hơn.

Đã tích hợp source-meaning/v2 vào shared CLI/dashboard, giữ consumers/indexes/MITRE/Sigma/CTI và retrieval/gate/byte caps. Namespace Sigma phân biệt exact rule_id với finding/node ID; output sigma-prefixed sai cũ vẫn rejected, bản copy chẩn đoán dùng đúng UUID passed trong scope structured + bounded narrative. Clock semantics phân biệt canonical span với actual attack duration/cross-source sync, giữ14 observations/7 inferred attempts/raw clocks và caveats. Citation bindings phân biệt cmd tạo mshta (4/275), mshta tạo PowerShell (30/398 khi returned), command text và completion/output/service state. Kiểm prose chỉ một tập mệnh đề process creation có inline refs, không xác nhận toàn văn/verdict. Chưa generation live để xác minh model tuân thủ.

Recovery từ checkpoint có --include-not-run tường minh, kiểm chuỗi hashes/old code compatibility/input về nguồn thật, không dựng source giả. Dry-run đúng3 pending branches: NET-CTI/graphrag, NET-LIMIT/graphrag, NET-LIMIT/rag, cap3; không chọn NET-CORRELATE validation_failed. Context/messages v5 giữ nguyên,24 saved messages dựng lại exact; base validator AST và LLM prompt/schema/guardrail/client/config gốc không đổi. Pacing60, stop401/403/429/503, Ctrl+C/checkpoint và không retry/fallback/auto-resume được mock/fake-clock tests kiểm tra.

Active version: configs/evaluation/integrated_scenarios_v6.json, outputs/integrated/20261030_v6/runtime_pin_v6.json, version_manifest.json; pin lịch sử và recovery_harness_v1 không đổi, delta v2 riêng. Full offline24/16eligible/0attempts,24 retrieval/gate/eligibility bằng v5. Targeted corrective study5/5eligible/0attempts gồm AUTH-CORRELATE/graphrag, AUTH-CTI/rag+graphrag, PS-LIMIT/graphrag, NET-CORRELATE/graphrag; đây là study input mới, không recovery v5 hoặc independent validation. Những eligible khác không tự chạy lại.

Focused/regression55 rồi34 rồi44 pass (có chồng lặp, không cộng unique); integrated dashboard pin cuối2 tests pass với24 saved branches và3 actual shared offline queries, context/messages khớp harness, có CTI context. Old pilot UI fixture pin prompt mismatch được phân biệt với đường integrated hiện tại; không sửa fixtures/pin để xanh. Không sửa frontend/build mới, không claim visual QA; dashboard ba cột và các nhãn trạng thái giữ nguyên. Báo cáo/lệnh CMD dry+live cap3/cap5 và dashboard port8004 ở outputs/integrated/20261030_v6/report.md, commands.md. Không gọi LLM thật; live commands chỉ kiểm argparse offline. Giữ raw/canonical/GT/labels/approval/CTI/consumers/indexes/historical outputs/model/provider/.env; không stage/commit/push.


## 22. Direct OpenRouter final profile và service-blocked closeout — 31/10/2026

Theo quyền mới đã tìm một credential OpenRouter trong local provider store bằng read-only access, không in secret/dump env/database/headers. Cập nhật local .env sang https://openrouter.ai/api/v1, requested model google/gemma-4-31b-it, connector generic_openai và single attempt; không sửa upstream9Router. Không khẳng định mapping cũ sai hoặc key hết hạn/quota. Pin v5/v6 và outputs cũ giữ nguyên.

Đã thêm source-meaning/v3: trả lời đủ-vế so sánh telemetry/CTI và giữ source types riêng; canonical observation/anchor span không thành physical activity duration; bounded numeric-duration và unrequested HTTP/C2/exfiltration checks. Giữ exact Sigma rule_id namespace, process citation binding, command/creation/completion distinctions và approval statuses. Hai dashboard exports v6 sai vẫn bị kiểm tra mới từ chối. Không hardcode case/account/timestamp/expected answer trong runtime hoặc dùng rubric làm evidence.

Final profile configs/evaluation/integrated_final_direct_v7.json, pin outputs/final/20261031_direct_v7/runtime_pin.json đã khóa trước live. Full preflight24 planned/16eligible/0attempts;24 retrieval/gate/eligibility bằng v6, data/GT/labels/approval/CTI/consumers/indexes/embedding không đổi. Durable task ledger giới hạn initial16/recovery4/total20 qua process mới, pacingmonotonic>=60s, Retry-After numeric/HTTP-date, stop401/403/429/503, explicit service-only recovery, không regenerate accepted/rejected hoặc fallback. Profile dashboard chặn live để không bypass ledger, chỉ offline/replay.

Actual direct request đầu AUTH-DIRECT/RAG trảHTTP402, không có model text. Đã dừng thủ công trong pacing trước request2; kiểm tra không còn process của đúng run và task ledger giữ1 attempt. HTTP402 không được coi là temporary retry; không Reply OK/credits probe/đổi credential/model/token policy giữa bộ. Error body không lưu theo safe-client policy nên không đủ chứng cứ xác định root cause chi tiết hoặc kết luận key/account hết credits. Đây là blocker chưa giải quyết, không phải đã hoàn tất bộ so sánh generation.

Closeout trung thực đủ24 status rows/12 pairs:0 accepted,0 validation_failed,8 frozen-gate abstain,1 provider_error,15not_run; actual1/20requests, recovery0/4, generated answers0. Không trộn outputs v5/v6 hoặc giả semantic accuracy; review model/citation theo rubric là N/A vì không có generated answer. Original live checkpoint1row không bị sửa; not_run statuses là derived closeout có source/preflight/operator-stop refs, không fake generation/source dùng recovery.

Focused tests:74 pass/1failure ban đầu, fix token boundary CovertNetwork và rerun đúng2tests pass; actual direct-profile/dashboard2tests pass trước và2tests pass sau source-hashed replay index. Không cộng overlap thành unique count hoặc chạy full suite. Dashboard HTTP kiểm đủ24saved states,0LLM calls, đang chạy offline ở http://127.0.0.1:8010/. Minimal render-only labels cho not_run/interrupted để tránh nhầm runtime error; không đổi layout, frontend build và3status checks passed. Browser tool báo The browser access host is unavailable, không screenshot/visual QA claim hoặc ảnh giả. Core Python vẫn khớp pin, không đổi policy sau attempt1.

Thư mục bàn giao outputs/final/20261031_direct_v7 có report.md, results.csv24rows, paired_details.csv12pairs, semantic_review.md/JSON, thesis_facts.md, version/source/budget/hash manifests và một CMD dashboard. Đã kiểm lại29.510 raw records,21input-provenance hashes,3CTI snapshots/citation offsets. Không DOCX/ZIP/stage/commit/push. Phần live còn thiếu15eligible chưa gửi và1request không answer; không claim independent validation, accuracy hoặc GraphRAG tốt hơn RAG. Mọi phần độc lập hoàn thành, còn direct service rejectionHTTP402 trước khi tiếp tục generation.


## 23. Tổng kết bàn giao tài liệu — 31/10/2026 (Asia/Bangkok)

Phạm vi: chỉ đọc/đối chiếu và sửa tài liệu. Không sửa source/config/pin/runtime outputs, không gọi LLM/API, generation hoặc thực nghiệm mới; không sửa Word, ZIP/commit/push. Toàn bộ bytes lịch sử phía trước được giữ nguyên. Các chỉ dẫn dừng/bước tiếp theo trong checkpoint cũ là lịch sử; hướng dẫn hiện hành nằm trong HANDOVER.md.



**Bộ cuối chưa hoàn tất nghiệm thu.** Cấu hình so sánh mới nhất là [integrated_final_direct_v7.json](configs/evaluation/integrated_final_direct_v7.json), generation pin là [runtime_pin.json](outputs/final/20261031_direct_v7/runtime_pin.json). Bộ này dùng consumers **v5**, gate `source-evidence-contract/v2` và generation `source-meaning/v3`; số v7 không có nghĩa là có consumers v7.

**Working source đã khác pin:** đọc hash hiện tại thấy bốn tệp thay đổi: [run_final_experiment.py](scripts/run_final_experiment.py), [experimental_comparison.py](src/threat_hunting/evaluation/experimental_comparison.py), [final_experiment.py](src/threat_hunting/evaluation/final_experiment.py), [client.py](src/threat_hunting/llm/client.py); thêm [error_diagnostics.py](src/threat_hunting/llm/error_diagnostics.py) chưa có trong pin. Code mới có chẩn đoán lỗi đã lọc, stop HTTP402, continuation và xác nhận vận hành sau HTTP402. [http402_recovery_20261031_v1](outputs/offline/http402_recovery_20261031_v1/) hiện chỉ có `before_hashes.json`, chưa thấy execution delta pin/báo cáo/test results hoàn tất. Không gọi phần sửa này là đã kiểm chứng hoặc tự quay lui các thay đổi của người dùng.

Do kiểm tra full code manifest, **lệnh CLI/dashboard ghép working source hiện tại với pin v7 cũ sẽ bị chặn**. Báo cáo v7 mô tả code tại thời điểm khóa pin, không chứng minh source hiện tại khớp pin. Cần hoàn thiện migration pin ở công việc 1 bên dưới; không bỏ kiểm tra hash để chạy.

| Lớp kiểm chứng | Kết quả và giới hạn |
| --- | --- |
| Đã triển khai | Parser/normalization; evidence/correlation ba kịch bản; safe Sigma/STIX; CTI ingestion; corpus/JSON graph/E5 index; hybrid retrieval, graph traversal, evidence gate; LLM client/prompt/validation; harness/ledger; dashboard ba cột. |
| Đã kiểm chứng offline tại checkpoint | V7 preflight 24 nhánh, 16 eligible, 8 abstain, 0 HTTP attempts; RAG 5 eligible, GraphRAG 11. Đây là eligibility, không phải semantic accuracy. |
| Live v7 thực tế | Một request AUTH-DIRECT/RAG trả HTTP402, không có model text; dừng thủ công trước request 2. Checkpoint gốc chỉ có **1 row**. |
| Closeout dẫn xuất v7 | 24 rows/12 pairs: **0 accepted_draft, 0 validation_failed, 8 abstain, 1 provider_error, 15 not_run**. Generation quality/citation score: **N/A**. |
| Dashboard | V5 có ảnh/QA thật trong artifacts lịch sử; v7 có HTTP/replay QA 24 trạng thái, chưa visual QA/screenshot của profile cuối. Không khẳng định localhost còn chạy ở thời điểm nhận bàn giao. |
| Chưa nghiệm thu | Working source/pin migration mới, generation end-to-end nhất quán, review nội dung/citation, holdout độc lập, dashboard cuối và báo cáo luận văn đồng bộ. |

Nguồn: [report.md](outputs/final/20261031_direct_v7/report.md), [results.json](outputs/final/20261031_direct_v7/results.json), [results.csv](outputs/final/20261031_direct_v7/results.csv), [live checkpoint](outputs/experiments/integrated-final-direct-v7-live-01/results.json), [operational_stop.json](outputs/final/20261031_direct_v7/operational_stop.json), [request_budget.json](outputs/final/20261031_direct_v7/request_budget.json). Ledger giữ **1/20** attempts (initial 1/16, recovery 0/4), không reset. Error body của request cũ không được lưu; chưa có bằng chứng kết luận nguyên nhân chi tiết của HTTP402.


Đối chiếu live riêng theo version: pilot02 có4accepted; remaining01 riêng9accepted/4validation_failed/13abstain,13requests. Integrated v5 initial16requests:4accepted/8abstain/12provider_error; recovery01 riêng10requests:8accepted/1validation_failed/1provider_error/2not_run; pending-three-live02 riêng2requests:1validation_failed/1provider_error/1not_run. Không cộng recovery thành số câu độc lập hoặc trộn với v7. V6 targeted5eligible/0requests chỉ dry-run. Số tests lịch sử có overlap; không cộng thành unique total hoặc gọi full suite hiện tại. Lượt này không chạy runtime tests mới.

Approval: historical MSHTA bundle có reviewer Nguyen Hong Phong/time2026-10-15T23:36:13+07:00; integrated GT cả ba vẫn draft_reviewable/pending_human_review. Không chuyển approval hoặc nâng technique labels. Reference answers/rubric là evaluation-only.

Xác minh mới: streaming read đủ25.993/1.127/2.390 raw records, SHA-256 và canonical29.510/dropped0 khớp;21GT provenance entries/12consumer hashes/3CTI snapshot-text hashes và citation offsets khớp. Ba CLI --help trong HANDOVER exit0. Không cài dependencies/build/start server/dry-run/live. Checkout không có .git; không tuyên bố git status sạch.

Đóng gói: mười inputs ngoài friend tại thư mục data anh em, E5 cache ngoài repo; CTI snapshot v1 là dependency thật của consumers v5. Có absolute paths cần migration version mới; không sửa lịch sử. README và HUONG_DAN_CHAY chứa credential-like strings cần làm sạch bản phân phối; không chép giá trị, không gửi .env/provider stores/browser profiles. Hai file gốc đó được giữ nguyên ở lượt này.

Hồ sơ: cập nhật PROJECT_CONTEXT.md (hiện trạng/kiến trúc, giữ lịch sử20–22), AGENTS.md (chỉ dẫn lỗi thời), chỉ append PROJECT_PROGRESS.md; tạo HANDOVER.md, PACKAGING_CHECKLIST.md và .env.example key rỗng. Giữ đề tài/mục lục ba chương, ba scenario và dashboard ba cột. Người nhận được chọn local/API LLM; đổi model/params phải version config/pin/results, dùng cùng LLM/params trong hai nhánh so sánh.

Ưu tiên: hoàn thiện generation/source-pin và end-to-end; review rule_id/clocks/citations/source semantics; rà retrieval/gate/abstain; khóa evaluation; review nội dung/quality/time; nghiệm thu dashboard/exports/ảnh thật; đồng bộ chương3; cài đặt/tái lập/bảo vệ. HANDOVER ghi modules, hành động, điều kiện hoàn thành và sản phẩm từng việc. Không yêu cầu chủ dự án chạy lại thực nghiệm trong lượt tài liệu.

Snapshot bảo toàn trước sửa gồm7.428files; loại caches/node_modules/browser profiles/pytest scratch. Bốn test-temp directories access denied không đọc/đổi quyền: outputs/offline/harness-recovery-v1-final-checks, harness-recovery-v1-pytest, harness-recovery-v1-pytest-verified và outputs/review/experimental_checkpoint_20261026/harness_test_tmp_v2. Không tuyên bố đã rà nội dung các thư mục này. Kiểm links/hash cuối được ghi tiếp sau xác minh.

Kiểm cuối hoàn tất: 148 liên kết cục bộ trong phần tài liệu hiện hành đều tồn tại. Snapshot7.428files ngoài sáu tài liệu/mẫu được phép thay đổi giữ cùng aggregate SHA-256 trước/sau: 953af2392661e2174bb46fcd6b23000f0c77ba3088b1dc4bf128ebeee4e3f870. Prefix69.881bytes của PROJECT_PROGRESS giữ SHA-256 f86d2d2bb9e4151577ae3707cbc1769b1fdceabe98c759105d7b8432c98296ee. Tài liệu mới không có chuỗi credential theo mẫu đã rà; .env.example key rỗng. Không khẳng định nội dung cache/test-temp bị access denied. Không phát sinh output runtime hoặc thay đổi inputs.
