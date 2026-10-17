# Prerequisite: Human approval MSHTA

Hoàn thành schema/validators và approval metadata; dừng để review. Chưa bắt đầu calibration, held-out evaluation hoặc GRAPHRAG-2D3.

## Sự kiện approval

Reviewer `Nguyen Hong Phong`, theo chỉ định hiện tại; không tìm thấy reviewer ID chính thức khác. Cả ba JSON dùng `2026-10-15T23:36:13+07:00`. Đây là thời điểm ghi nhận xác nhận approval trong yêu cầu hiện tại, từ clock đầu preflight `2026-10-15 16:36:13 UTC`. Không có timestamp của lần duyệt trước trong ngữ cảnh; không suy đoán thời gian trước đó.

GT dùng `scenario-ground-truth/v2`, `review.review_status=confirmed`. Answers dùng `mshta-reference-answers/v2`, `review.review_status=human_approved`. Manifest dùng `mshta-technical-review/v2`, `human_review_status=confirmed`. Technical reviewer Codex/ngày 2026-10-14/status giữ nguyên. `confirmed` chỉ là approval tài liệu; mọi evidence/Sigma/MITRE label giữ nguyên và `analysis_status` vẫn `draft_reviewable`.

V1 giữ pending-only với human reviewer/time null; producer constant vẫn v1. V2 pending bắt buộc null/null; approved bắt buộc reviewer không trắng và ISO datetime hợp lệ có timezone. Chi tiết vocabulary/transitions tại `docs/human_approval.md`.

## Repo và files thay đổi

Branch `feature/mshta-evidence-extractor`; HEAD `af2243a3ee89c5e5721ec341eea0a8cb06814f41` giữ nguyên. `git merge-base --is-ancestor aa9fd31 HEAD` exit 0. Staging rỗng trước/sau; không stage/commit/amend/push/PR.

Bốn Markdown dirty từ trước đã được xem diff và giữ nguyên bytes: AGENTS.md, PROJECT_CONTEXT.md, PROJECT_PROGRESS.md, README.md. Chúng giữ checkpoint pending cũ; yêu cầu mới của người dùng được ưu tiên mà không ghi đè những thay đổi đó.

Files code/documentation của lượt này:

- Sửa `src/threat_hunting/ground_truth/schema.py`: v1/v2 dispatch, ngoại lệ confirmed chỉ tại `$.review.review_status`, approval metadata rules.
- Sửa `src/threat_hunting/ground_truth/__init__.py`: export constants mới, giữ default v1.
- Thêm `src/threat_hunting/ground_truth/approval.py`: shared reviewer/timestamp/status validation.
- Thêm `src/threat_hunting/ground_truth/review_artifacts.py`: explicit contracts cho answers/manifest và bundle consistency/provenance validation.
- Thêm `src/threat_hunting/ground_truth/approval_update.py`: pure metadata transition, hash cascade và previous-artifact provenance; từ chối reapproval.
- Thêm `tests/test_ground_truth_approval.py`: synthetic fixtures, compatibility, malformed/contradictory metadata, bundle mismatch, preservation và gate isolation.
- Thêm `docs/human_approval.md`: vocabulary, transitions, timestamp basis, historical prose và consumer limitations.

Ba local derived artifacts cập nhật trong `outputs/review/mshta-ground-truth/`: `scenario_ground_truth.json`, `reference_answers.json`, `review_manifest.json`. Chỉ đổi schema/version, human approval fields, direct GT/answers hashes và approval provenance. Toàn bộ 32 cases, nhãn 16 proceed/16 abstain, câu hỏi, đáp án, constraints, observed/inferred/candidate labels, raw references và source provenance giữ nguyên. Notes/answers lịch sử nhắc pending được bảo toàn; metadata v2 thể hiện trạng thái hiện tại.

Audit riêng: `preflight.json`, ba `before_*.json`, `record_approval.py`, `verify_approval.py`, `postflight.json`, `test_results.json`, `write_report.py` và báo cáo này. Outputs local/ignored theo .gitignore; không stage. Các thư mục tạm tests ở đây chứa synthetic artifacts.

## Tests

| Nhóm thành công | Passed | Failed | Errors | Skipped | Thời gian |
| --- | ---: | ---: | ---: | ---: | ---: |
| Focused schema/approval | 158 | 0 | 0 | 0 | 0.73 s |
| Ground Truth và related contracts | 1533 | 0 | 0 | 0 | 13.52 s |
| Full suite | 5691 (+6 subtests passed) | 0 | 0 | 0 | 148.77 s |

Lệnh chính xác đã passed (PowerShell; ngoài sandbox vì quyền thư mục tạm Windows):

```powershell
.\.venv\Scripts\python.exe -m pytest -q --tb=short -p no:cacheprovider --basetemp=outputs/review/mshta-human-approval/test-tmp-focused tests/test_ground_truth_schema.py tests/test_ground_truth_approval.py
.\.venv\Scripts\python.exe -m pytest -q --tb=short -p no:cacheprovider --basetemp="$env:TEMP/rag-approval-related-20261015" tests/test_ground_truth_schema.py tests/test_ground_truth_approval.py tests/test_ground_truth_builder.py tests/test_mshta_ground_truth_config.py tests/test_build_mshta_ground_truth_cli.py tests/test_retrieval_schema.py tests/test_retrieval_builder.py tests/test_retrieval_judgments.py tests/test_relevance_calibration_dataset.py tests/test_knowledge_graph_schema.py tests/test_knowledge_graph_builder.py tests/test_graphrag_gate_signals.py tests/test_graphrag_two_stage_gate.py
.\.venv\Scripts\python.exe -m pytest -q --tb=short -p no:cacheprovider --basetemp="$env:TEMP/rag-approval-full-20261015"
```

Các lần chạy trước kết quả cuối:

- `.\.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_ground_truth_schema.py tests/test_ground_truth_approval.py`: 103 passed, 2 failed, 16 errors, 2 warnings. Chạy khi fixture mới còn hoàn thiện: thiếu original-source entry; đồng thời tmp/cache bị WinError 5. Fixture đã sửa trước successful focused run.
- Related run trong sandbox với `--basetemp=outputs/review/mshta-human-approval/test-tmp-related` kết thúc exit 1 vì WinError 5 khi tạo/cleanup temp; không có terminal summary hợp lệ nên không gán counts.
- Related run ngoài sandbox với `--basetemp=outputs/review/mshta-human-approval/test-tmp-related-elevated`: 1529 passed, 4 failed, 0 errors/skipped. Bốn CLI tests giả định fixtures ngoài repo; temp trong repo làm khác relative provenance paths. Đổi vị trí temp, không sửa CLI; related run cuối 1533 passed.
- Hai related attempts dùng cùng test list với lệnh thành công. Mọi lần tắt cacheprovider ngoại trừ focused attempt đầu.

## Verification và hashes

```powershell
.\.venv\Scripts\python.exe -X utf8 outputs/review/mshta-human-approval/record_approval.py
.\.venv\Scripts\python.exe -X utf8 outputs/review/mshta-human-approval/verify_approval.py
git merge-base --is-ancestor aa9fd31 HEAD
git diff --check
git diff --cached --name-only
git status --short
```

record_approval.py chạy một lần sau focused tests, có guard kiểm tra original bytes/serialization trước ghi. verify_approval.py chạy lại sau full suite: JSON readback/validators passed; khôi phục riêng metadata theo allowlist rồi so sánh toàn document bằng bản trước. Tất cả manifest artifact/source/baseline hashes khớp bytes. previous_artifacts giữ đủ hashes cũ của cả ba JSON.

Kiểm tra 4.826 files: 4.823 giữ nguyên hash; chỉ ba JSON dự kiến đổi. Inventory data/outputs/benchmarks/configs không thêm/mất file ngoài thư mục audit mới. Không unexpected hash changes. Branch/HEAD/staging khớp preflight; git diff --check sạch.

### Ba artifacts: SHA-256 trước/sau

| Artifact | Trước | Sau |
| --- | --- | --- |
| `scenario_ground_truth.json` | `b6c156358e17da6bfc092d5a97dce8a9f97c7e6ddd25522c43ed6fd506598186` | `8676d7a1df41058e7f4b1460a0d4bf909fca5d8f20992753e63be7d024268461` |
| `reference_answers.json` | `deadab1b0ad457a2501feca4ac75ff084df440f4e6b3ffc688db8cad5d823402` | `400026d106b863c4127c57c74d3b7722e672652474638bb9554089d322fba96b` |
| `review_manifest.json` | `65cab2ecbbf651743c356fd4d2e8c7cedb0b6cdc85643a3f37828bdd810d65ba` | `29507fe4f68a1222d93d5626da8d03f29b497d5798be3f2f6786f8911d0eedb4` |

### Bốn Markdown protected: trước = sau

| File | SHA-256 trước = sau |
| --- | --- |
| `AGENTS.md` | `3a4e70b15c784890daa3a63a47cba78a23475355087c21d7621f42fd57d7c575` |
| `PROJECT_CONTEXT.md` | `6f951295cdde54a938ca4c003ede3fe82032babba95dc002f4a9dcce415a3480` |
| `PROJECT_PROGRESS.md` | `cf87f1b1aeccb981a0ee2846e153e85274e67ffd878e8a5e94b61b00cdca709e` |
| `README.md` | `a25dbb784058004a73aa9e2bac44cca9cd81917b4f936d43e9dda6c45209dda1` |

### Selected external inputs: trước = sau

Đủ 10 selected filenames. Đếm read-only toàn bộ JSONL: PurpleSharp 25.993, Regsvr32 2.390, MSHTA 1.127; tổng 29.510. Sáu Sigma có bản upstream trùng tên/hash; chọn đúng `sigma/selected/`.

| Path trong repo | SHA-256 trước = sau |
| --- | --- |
| `data/knowledge/Mitre/enterprise-attack.json` | `bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3` |
| `data/knowledge/sigma/selected/brute_force/win_security_susp_rc4_kerberos.yml` | `6b95365726dfb2744695f0402f9784dc015f027f53543b4db4d0f60527b9b2b8` |
| `data/knowledge/sigma/selected/c2_regsvr32/proc_creation_win_regsvr32_http_ip_pattern.yml` | `5ed0c24908eb092479cb93eecc3dc212e5c1b5a573d74b18a8322d86e8eae771` |
| `data/knowledge/sigma/selected/c2_regsvr32/proc_creation_win_regsvr32_susp_child_process.yml` | `53bc06be29973d961a958f66b6640a8c8bfe04c4eb8e2bf385b14ee8a3b14380` |
| `data/knowledge/sigma/selected/c2_regsvr32/proc_creation_win_regsvr32_susp_parent.yml` | `14ca4424714aceb1836053f17196e1bb347f9593f8f615e841d7971cc570a8bc` |
| `data/knowledge/sigma/selected/powershell/proc_creation_win_mshta_susp_child_processes.yml` | `8a32fc6f6030da48f4e22446d7446ffb85b7801158ec204e4659a657ecc44380` |
| `data/knowledge/sigma/selected/powershell/proc_creation_win_mshta_susp_execution.yml` | `67d76c24526db9dadbacb2086115a62b5f6364a39a0d8197de96d6fb738b9774` |
| `data/raw/mordor/burte_force/purplesharp_ad_playbook_II/purplesharp_ad_playbook_I_2020-10-22042947.json` | `d86d22f0c02ab851564bb5e0c90c220e9df0319f5948bfc90dfa605b4511d4f0` |
| `data/raw/mordor/c2_network/empire_launcher_sct_regsvr32/empire_launcher_sct_regsvr32_2020-07-21232741.json` | `8b619d07ad79713ae96234344c4ba9618eae7119c360ee008b5e0c2cfe4954d7` |
| `data/raw/mordor/powershell/cmd_mshta_vbscript_execute_psh/cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json` | `25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32` |

Mọi hash khác, gồm corpus/graph/indexes/retrieval/evaluation outputs, nằm trong preflight.json/postflight.json.

## Giới hạn và điểm dừng

- Approval là metadata tài liệu. Gate signals/decision output không nhận confirmed; synthetic regression kiểm tra injection bị từ chối, decision vẫn context_eligibility_only / security_conclusion_made=false.
- Consumer contracts còn pin provenance v1. Một số builder sao chép source_review_status; approved v2 cần contract/rebuild milestone có kiểm soát sau review prerequisite. Chưa sửa production CLI hoặc consumers.
- Chưa chạy production calibration, chưa mở held-out, chưa gọi embedding model/LLM hoặc làm UI. Full suite chạy unit/fixture tests; embedding backend dùng fake/mocked models.
- Không chạy lại historical assembler lên bộ approved vì script có thể tái tạo pending artifacts. Technical review reports cũ và bốn dirty Markdown giữ nguyên.
- Chưa hỗ trợ revoke/reject/reapproval cycle; không thêm transitions ngoài prerequisite.
- **Dừng tại đây để review; chưa tiếp tục GRAPHRAG-2D3.**
