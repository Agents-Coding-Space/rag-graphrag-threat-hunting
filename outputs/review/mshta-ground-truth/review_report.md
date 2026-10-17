# Review kỹ thuật ground truth MSHTA–PowerShell

Ngày review: **14/10/2026**. Reviewer: **Codex (AI assistant)**.

**Kết quả: đã hoàn thành review kỹ thuật và tạo bản sửa có căn cứ.** Bản ground truth vẫn là `draft_reviewable`, `pending_human_review`; các MITRE assessments vẫn là `candidate`. Đây không phải chữ ký hay phê duyệt của người dùng.

## Phạm vi và kết quả kiểm tra

- Đọc streaming đủ **1.127 raw records** và đối chiếu **1.127 canonical events**, không bỏ record trong lượt audit.
- Kiểm tra **3 process entities, 2 facts, 2 process_spawn relationships, 2 evidence groups và 4 raw references** của core.
- Đối chiếu hai Sigma YAML bằng safe loading và detection trên raw process-creation fields; phân giải MITRE bằng STIX objects trong local ATT&CK bundle.
- Kiểm tra cả **32 câu hỏi**, **89 relevance pointers** của benchmark gốc và SHA-256 của các nguồn. Không phát hiện mâu thuẫn category/decision theo phạm vi core.
- Raw Mordor, Sigma, MITRE, canonical inputs và các artifact baseline không bị sửa. Các bản mới nằm riêng trong thư mục review này.

Raw filename: `cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`.

Raw SHA-256 trước và sau audit: `25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32`.

## Những dữ kiện được chấp nhận ở mức observed

| Dữ kiện | Log gốc | Quyết định kỹ thuật |
| --- | --- | --- |
| `cmd.exe` tạo `mshta.exe` với `vbscript:Execute` | Security 4688: `jsonl:line:4`; Sysmon 1: `jsonl:line:275` | Có căn cứ; cùng host, process/parent PID, image và command line |
| `mshta.exe` tạo `powershell.exe` | Security 4688: `jsonl:line:30`; Sysmon 1: `jsonl:line:398` | Có căn cứ; Sysmon ParentProcessGuid nối đúng process MSHTA |
| PowerShell được khởi chạy với `-noexit -command Get-Service sysmon` | `jsonl:line:30`, `jsonl:line:398` | Chỉ xác nhận launch command; không xác nhận cmdlet hoàn tất, đầu ra hoặc trạng thái dịch vụ |

Hai cặp telemetry `4 ↔ 275` và `30 ↔ 398` lệch `TimeCreated` lần lượt 1 ms và 27 ms. Việc tương quan hai nguồn telemetry là bước suy luận dựa trên các trường khớp nhau, không phải hai process bổ sung. `jsonl:line:36 ↔ jsonl:line:422` mô tả PowerShell tạo `conhost.exe`, nằm ngoài hai nhóm evidence của core; do đó 3 entities của core không phải toàn bộ process inventory.

Command lines và các trường gốc đã được bổ sung vào `facts[*].attributes.source_observations` của bản sửa. Các trường source giữ nguyên kiểu và giá trị, kể cả PID hexadecimal và timestamp strings; không tạo ScriptBlockText giả lập.

## Các sửa đổi trong bản review

1. Thay “PowerShell ran Get-Service sysmon” bằng “PowerShell was launched with -noexit -command Get-Service sysmon”. Dataset không có PowerShell script-block/action/output telemetry chứng minh cmdlet hoàn tất.
2. Sửa câu `rp-vi-service-action` để hỏi lệnh được ghi trên command line. Giữ `relevant_paraphrase` và `proceed`.
3. Sửa câu `ie-vi-destructive-files` để hỏi rõ bằng chứng **payload cố ý phá hoại** trong **hai nhóm process-creation evidence**. Log toàn file có Sysmon 23 xóa tệp tạm, nên câu “đã xóa hoặc phá hoại những tệp nào” trộn hành vi xóa quan sát được với kết luận phá hoại chưa được chứng minh. Giữ `insufficient_evidence` và `abstain` cho câu đã làm rõ phạm vi.
4. Bổ sung original fields để việc truy vết VBScript và launch command không chỉ dựa vào summary.
5. Bổ sung giới hạn về kết quả cmdlet, timestamp và telemetry ngoài core. Không đổi thứ tự entities/facts/evidence/MITRE assessments hoặc các IDs hiện có.

Như vậy, bản dataset mới sửa **2 câu hỏi**, không đổi bất kỳ category hay expected decision nào. Bản audit độc lập `reference_answers_audit.json` ghi nhận đề xuất ban đầu; `reference_answers.json` và `mshta_relevance_calibration_reviewed.json` là bản đã tổng hợp cả hai sửa đổi.

## Timestamp và giới hạn của kết luận âm tính

Canonical timestamp hiện theo `TimeCreated`. Hai Sysmon anchors có `UtcTime` lệch khoảng **4 giờ** và không kèm timezone offset. `time_window` được giữ theo contract canonical, chưa coi đây là thời gian UTC thực tế đã được xác nhận. Xem các giá trị nguyên gốc trong `raw_audit.json` và `source_observations`.

Lượt này đã đọc toàn bộ file để kiểm tra các trường và anchors; điều đó không tương đương một detector âm tính toàn diện cho download, C2, credential theft hoặc giải mã. Chỉ có network telemetry nền của Azure Guest Agent trong các record network đã tìm được; nó không phải bằng chứng C2 của MSHTA/PowerShell. Không gán IP này cho chuỗi MSHTA.

File còn có event-log clearing và temporary-file deletion ngoài hai nhóm process-creation core. Các record này không được coi là globally absent, và cũng không tự chứng minh destructive payload. Không mở thêm scenario hoặc thêm positive attack label trong review này.

## Sigma và MITRE ATT&CK

Hai Sigma rules tạo **4 observation matches**, được tương quan thành **2 behavior matches**:

- `proc_creation_win_mshta_susp_execution.yml`: lines **4, 275**; match vì command line chứa `vbscript`. Tên rule, CVE tags hoặc references không chứng minh download, polyglot file hay khai thác CVE.
- `proc_creation_win_mshta_susp_child_processes.yml`: lines **30, 398**; match quan hệ MSHTA sinh PowerShell.

`OriginalFileName` có trong raw Sysmon nhưng chưa được canonical mapping. Kiểm tra trực tiếp raw fields vẫn cho đúng 4 matches; caveat này được giữ trong ground truth.

ATT&CK snapshot **v19.1**, collection version **19.1**, commit `6c3719993d0401de199203ecc3f369544d9e091c`; SHA-256 bundle `bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3`.

| Technique | Kết quả review bằng chứng | Trạng thái giữ lại |
| --- | --- | --- |
| `T1218.005` — Mshta | `supported_by_observed_behavior`; VBScript qua MSHTA và quan hệ sinh PowerShell có log hỗ trợ | `candidate`, `needs_review` |
| `T1059.007` — JavaScript | `not_supported_by_observed_command`; command được review dùng VBScript. Giữ tag để bảo toàn provenance | `candidate`, `needs_review` |
| `T1140` — Deobfuscate/Decode Files or Information | `not_assessed`; chưa có evidence cho hành vi giải mã | `candidate`, `needs_review` |

Không tự thêm technique hoặc nâng mapping thành `confirmed`.

## Đáp án tham chiếu và cách dùng

- **16 proceed**: câu hỏi về dữ kiện quan sát hoặc trạng thái assessment hiện có.
- **8 insufficient_evidence / abstain**: cùng chủ đề MSHTA, nhưng yêu cầu IOC, attribution, decoded content, destructive intent hoặc mức chắc chắn không được core hỗ trợ.
- **8 unrelated / abstain**: nằm ngoài phạm vi MSHTA.

`abstain` vẫn cho phép một câu giải thích ngắn, có căn cứ về giới hạn. `abstention_support` là context để giải thích thiếu bằng chứng, không phải positive evidence cho hành vi mà câu hỏi giả định.

Đáp án có ở [reference_answers.json](reference_answers.json) và bản đọc dễ hơn ở [reference_answers.md](reference_answers.md). Chúng chỉ dùng cho đánh giá; **không đưa đáp án, category hoặc expected decision vào retrieval corpus hay runtime gate input**. Bộ 32 câu hiện là calibration set; chưa phải benchmark độc lập để tuyên bố hiệu quả cuối cùng.

## Artifact và khả năng tái lập

- [scenario_ground_truth.json](scenario_ground_truth.json): bản ground truth sửa, hợp lệ theo `scenario-ground-truth/v1`.
- [review_build_config.json](review_build_config.json): quyết định và original fields dùng để build bản sửa.
- [mshta_relevance_calibration_reviewed.json](mshta_relevance_calibration_reviewed.json): 32 câu hỏi, sửa 2 câu, giữ nhãn.
- [review_manifest.json](review_manifest.json): source hashes, artifact hashes, counts và review identity.
- [raw_audit.json](raw_audit.json), [sigma_mitre_audit.json](sigma_mitre_audit.json), [reference_answers_audit.json](reference_answers_audit.json): kết quả audit từng phần.

Chạy từ repository root:

```powershell
.\.venv\Scripts\python.exe -X utf8 outputs/review/mshta-ground-truth/audit_raw.py
.\.venv\Scripts\python.exe -X utf8 outputs/review/mshta-ground-truth/audit_sigma_mitre.py
.\.venv\Scripts\python.exe -X utf8 outputs/review/mshta-ground-truth/assemble_review.py
```

`assemble_review.py` kiểm tra pinned source hashes, đọc streaming toàn bộ raw file, xác thực 89 baseline pointers, build ground truth bằng builder hiện có, validate JSON/readback và kiểm tra input hashes trước/sau. Chạy lại không thay đổi các bản baseline.

Relevant tests đã chạy bằng Python của `.venv`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --tb=line tests/test_ground_truth_schema.py tests/test_ground_truth_builder.py tests/test_mshta_ground_truth_config.py tests/test_build_mshta_ground_truth_cli.py tests/test_retrieval_judgments.py tests/test_relevance_calibration_dataset.py
```

**Kết quả: 592 passed.** Các lượt đầu bị Windows ACL từ chối thư mục tạm; lượt dùng temp trong repository còn gây 4 kỳ vọng đường dẫn fixture sai. Lượt chạy ngoài sandbox với thư mục tạm chuẩn đã pass toàn bộ 592 checks. Không sửa tests hay implementation để xử lý các lỗi môi trường này.

## Trạng thái sau review

Review kỹ thuật và đáp án tham chiếu đã hoàn thành. Phê duyệt của con người, xác nhận timezone thực tế và kết luận attack cuối cùng vẫn chưa có. Ground-truth schema v1 chỉ cho phép `pending_human_review`, nên review identity được ghi đúng trong manifest/answer artifact thay vì giả lập reviewer của con người.

Các corpus, graph, vector indexes và evaluation reports hiện có pin hash của ground truth cũ. Bản sửa này là một version riêng. Bước tiếp theo phải build lại các consumer với provenance của bản đã được duyệt trước khi hiệu chỉnh gate hai tầng; không trộn hash hoặc dùng đáp án tham chiếu làm tín hiệu cho gate.
