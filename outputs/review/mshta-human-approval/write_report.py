"""Write the local human-readable prerequisite audit from verified snapshots."""

from pathlib import Path
import json


audit = Path(__file__).resolve().parent
pre = json.loads((audit / "preflight.json").read_text(encoding="utf-8"))
post = json.loads((audit / "postflight.json").read_text(encoding="utf-8"))
base = r".\.venv\Scripts\python.exe -m pytest -q --tb=short -p no:cacheprovider "
focused = base + "--basetemp=outputs/review/mshta-human-approval/test-tmp-focused tests/test_ground_truth_schema.py tests/test_ground_truth_approval.py"
related_files = "tests/test_ground_truth_schema.py tests/test_ground_truth_approval.py tests/test_ground_truth_builder.py tests/test_mshta_ground_truth_config.py tests/test_build_mshta_ground_truth_cli.py tests/test_retrieval_schema.py tests/test_retrieval_builder.py tests/test_retrieval_judgments.py tests/test_relevance_calibration_dataset.py tests/test_knowledge_graph_schema.py tests/test_knowledge_graph_builder.py tests/test_graphrag_gate_signals.py tests/test_graphrag_two_stage_gate.py"
related = base + '--basetemp="$env:TEMP/rag-approval-related-20261015" ' + related_files
full = base + '--basetemp="$env:TEMP/rag-approval-full-20261015"'
results = {
    "focused": {"command": focused, "passed": 158, "failed": 0, "errors": 0, "skipped": 0, "seconds": 0.73},
    "related": {"command": related, "passed": 1533, "failed": 0, "errors": 0, "skipped": 0, "seconds": 13.52},
    "full_suite": {"command": full, "passed": 5691, "subtests_passed": 6, "failed": 0, "errors": 0, "skipped": 0, "seconds": 148.77},
}
(audit / "test_results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

lines = [
    "# Prerequisite: Human approval MSHTA", "",
    "Hoàn thành schema/validators và approval metadata; dừng để review. Chưa bắt đầu calibration, held-out evaluation hoặc GRAPHRAG-2D3.", "",
    "## Sự kiện approval", "",
    "Reviewer `Nguyen Hong Phong`, theo chỉ định hiện tại; không tìm thấy reviewer ID chính thức khác. Cả ba JSON dùng `2026-10-15T23:36:13+07:00`. Đây là thời điểm ghi nhận xác nhận approval trong yêu cầu hiện tại, từ clock đầu preflight `2026-10-15 16:36:13 UTC`. Không có timestamp của lần duyệt trước trong ngữ cảnh; không suy đoán thời gian trước đó.", "",
    "GT dùng `scenario-ground-truth/v2`, `review.review_status=confirmed`. Answers dùng `mshta-reference-answers/v2`, `review.review_status=human_approved`. Manifest dùng `mshta-technical-review/v2`, `human_review_status=confirmed`. Technical reviewer Codex/ngày 2026-10-14/status giữ nguyên. `confirmed` chỉ là approval tài liệu; mọi evidence/Sigma/MITRE label giữ nguyên và `analysis_status` vẫn `draft_reviewable`.", "",
    "V1 giữ pending-only với human reviewer/time null; producer constant vẫn v1. V2 pending bắt buộc null/null; approved bắt buộc reviewer không trắng và ISO datetime hợp lệ có timezone. Chi tiết vocabulary/transitions tại `docs/human_approval.md`.", "",
    "## Repo và files thay đổi", "",
    f"Branch `{pre['branch']}`; HEAD `{pre['head']}` giữ nguyên. `git merge-base --is-ancestor aa9fd31 HEAD` exit 0. Staging rỗng trước/sau; không stage/commit/amend/push/PR.", "",
    "Bốn Markdown dirty từ trước đã được xem diff và giữ nguyên bytes: AGENTS.md, PROJECT_CONTEXT.md, PROJECT_PROGRESS.md, README.md. Chúng giữ checkpoint pending cũ; yêu cầu mới của người dùng được ưu tiên mà không ghi đè những thay đổi đó.", "",
    "Files code/documentation của lượt này:", "",
    "- Sửa `src/threat_hunting/ground_truth/schema.py`: v1/v2 dispatch, ngoại lệ confirmed chỉ tại `$.review.review_status`, approval metadata rules.",
    "- Sửa `src/threat_hunting/ground_truth/__init__.py`: export constants mới, giữ default v1.",
    "- Thêm `src/threat_hunting/ground_truth/approval.py`: shared reviewer/timestamp/status validation.",
    "- Thêm `src/threat_hunting/ground_truth/review_artifacts.py`: explicit contracts cho answers/manifest và bundle consistency/provenance validation.",
    "- Thêm `src/threat_hunting/ground_truth/approval_update.py`: pure metadata transition, hash cascade và previous-artifact provenance; từ chối reapproval.",
    "- Thêm `tests/test_ground_truth_approval.py`: synthetic fixtures, compatibility, malformed/contradictory metadata, bundle mismatch, preservation và gate isolation.",
    "- Thêm `docs/human_approval.md`: vocabulary, transitions, timestamp basis, historical prose và consumer limitations.", "",
    "Ba local derived artifacts cập nhật trong `outputs/review/mshta-ground-truth/`: `scenario_ground_truth.json`, `reference_answers.json`, `review_manifest.json`. Chỉ đổi schema/version, human approval fields, direct GT/answers hashes và approval provenance. Toàn bộ 32 cases, nhãn 16 proceed/16 abstain, câu hỏi, đáp án, constraints, observed/inferred/candidate labels, raw references và source provenance giữ nguyên. Notes/answers lịch sử nhắc pending được bảo toàn; metadata v2 thể hiện trạng thái hiện tại.", "",
    "Audit riêng: `preflight.json`, ba `before_*.json`, `record_approval.py`, `verify_approval.py`, `postflight.json`, `test_results.json`, `write_report.py` và báo cáo này. Outputs local/ignored theo .gitignore; không stage. Các thư mục tạm tests ở đây chứa synthetic artifacts.", "",
    "## Tests", "",
    "| Nhóm thành công | Passed | Failed | Errors | Skipped | Thời gian |",
    "| --- | ---: | ---: | ---: | ---: | ---: |",
    "| Focused schema/approval | 158 | 0 | 0 | 0 | 0.73 s |",
    "| Ground Truth và related contracts | 1533 | 0 | 0 | 0 | 13.52 s |",
    "| Full suite | 5691 (+6 subtests passed) | 0 | 0 | 0 | 148.77 s |", "",
    "Lệnh chính xác đã passed (PowerShell; ngoài sandbox vì quyền thư mục tạm Windows):", "",
    "```powershell", focused, related, full, "```", "",
    "Các lần chạy trước kết quả cuối:", "",
    r"- `.\.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_ground_truth_schema.py tests/test_ground_truth_approval.py`: 103 passed, 2 failed, 16 errors, 2 warnings. Chạy khi fixture mới còn hoàn thiện: thiếu original-source entry; đồng thời tmp/cache bị WinError 5. Fixture đã sửa trước successful focused run.",
    "- Related run trong sandbox với `--basetemp=outputs/review/mshta-human-approval/test-tmp-related` kết thúc exit 1 vì WinError 5 khi tạo/cleanup temp; không có terminal summary hợp lệ nên không gán counts.",
    "- Related run ngoài sandbox với `--basetemp=outputs/review/mshta-human-approval/test-tmp-related-elevated`: 1529 passed, 4 failed, 0 errors/skipped. Bốn CLI tests giả định fixtures ngoài repo; temp trong repo làm khác relative provenance paths. Đổi vị trí temp, không sửa CLI; related run cuối 1533 passed.",
    "- Hai related attempts dùng cùng test list với lệnh thành công. Mọi lần tắt cacheprovider ngoại trừ focused attempt đầu.", "",
    "## Verification và hashes", "",
    "```powershell",
    r".\.venv\Scripts\python.exe -X utf8 outputs/review/mshta-human-approval/record_approval.py",
    r".\.venv\Scripts\python.exe -X utf8 outputs/review/mshta-human-approval/verify_approval.py",
    "git merge-base --is-ancestor aa9fd31 HEAD", "git diff --check",
    "git diff --cached --name-only", "git status --short", "```", "",
    "record_approval.py chạy một lần sau focused tests, có guard kiểm tra original bytes/serialization trước ghi. verify_approval.py chạy lại sau full suite: JSON readback/validators passed; khôi phục riêng metadata theo allowlist rồi so sánh toàn document bằng bản trước. Tất cả manifest artifact/source/baseline hashes khớp bytes. previous_artifacts giữ đủ hashes cũ của cả ba JSON.", "",
    "Kiểm tra 4.826 files: 4.823 giữ nguyên hash; chỉ ba JSON dự kiến đổi. Inventory data/outputs/benchmarks/configs không thêm/mất file ngoài thư mục audit mới. Không unexpected hash changes. Branch/HEAD/staging khớp preflight; git diff --check sạch.", "",
    "### Ba artifacts: SHA-256 trước/sau", "",
    "| Artifact | Trước | Sau |", "| --- | --- | --- |",
]
for name, hashes in post["artifact_hashes"].items():
    lines.append(f"| `{name}` | `{hashes['before']}` | `{hashes['after']}` |")
lines += ["", "### Bốn Markdown protected: trước = sau", "", "| File | SHA-256 trước = sau |", "| --- | --- |"]
for name in ("AGENTS.md", "PROJECT_CONTEXT.md", "PROJECT_PROGRESS.md", "README.md"):
    assert pre["hashes"][name] == post["hashes_after"][name]
    lines.append(f"| `{name}` | `{pre['hashes'][name]}` |")
lines += ["", "### Selected external inputs: trước = sau", "",
          "Đủ 10 selected filenames. Đếm read-only toàn bộ JSONL: PurpleSharp 25.993, Regsvr32 2.390, MSHTA 1.127; tổng 29.510. Sáu Sigma có bản upstream trùng tên/hash; chọn đúng `sigma/selected/`.", "",
          "| Path trong repo | SHA-256 trước = sau |", "| --- | --- |"]
selected_names = {
    "purplesharp_ad_playbook_I_2020-10-22042947.json", "empire_launcher_sct_regsvr32_2020-07-21232741.json",
    "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json", "enterprise-attack.json",
    "win_security_susp_rc4_kerberos.yml", "proc_creation_win_regsvr32_http_ip_pattern.yml",
    "proc_creation_win_regsvr32_susp_child_process.yml", "proc_creation_win_regsvr32_susp_parent.yml",
    "proc_creation_win_mshta_susp_child_processes.yml", "proc_creation_win_mshta_susp_execution.yml",
}
selected = []
for path, digest in pre["hashes"].items():
    if Path(path).name in selected_names and path.startswith(("data/raw/", "data/knowledge/Mitre/", "data/knowledge/sigma/selected/")):
        assert digest == post["hashes_after"][path]
        selected.append(path)
        lines.append(f"| `{path}` | `{digest}` |")
assert len(selected) == 10
lines += ["", "Mọi hash khác, gồm corpus/graph/indexes/retrieval/evaluation outputs, nằm trong preflight.json/postflight.json.", "",
    "## Giới hạn và điểm dừng", "",
    "- Approval là metadata tài liệu. Gate signals/decision output không nhận confirmed; synthetic regression kiểm tra injection bị từ chối, decision vẫn context_eligibility_only / security_conclusion_made=false.",
    "- Consumer contracts còn pin provenance v1. Một số builder sao chép source_review_status; approved v2 cần contract/rebuild milestone có kiểm soát sau review prerequisite. Chưa sửa production CLI hoặc consumers.",
    "- Chưa chạy production calibration, chưa mở held-out, chưa gọi embedding model/LLM hoặc làm UI. Full suite chạy unit/fixture tests; embedding backend dùng fake/mocked models.",
    "- Không chạy lại historical assembler lên bộ approved vì script có thể tái tạo pending artifacts. Technical review reports cũ và bốn dirty Markdown giữ nguyên.",
    "- Chưa hỗ trợ revoke/reject/reapproval cycle; không thêm transitions ngoài prerequisite.",
    "- **Dừng tại đây để review; chưa tiếp tục GRAPHRAG-2D3.**", ""]
(audit / "approval_report.md").write_text("\n".join(lines), encoding="utf-8")
print("Wrote approval_report.md and test_results.json")
