"""Render Vietnamese review reports from saved artifacts; never run retrieval or gate.

Run only after test_results.json has been written. The only outputs are report.md
and per_case_report.md beside this script. No timestamp is synthesized.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[2]


def read_json(name: str) -> Any:
    return json.loads((BASE / name).read_text(encoding="utf-8-sig"))


def pretty(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def fenced(value: Any, language: str = "json") -> str:
    text = value if isinstance(value, str) else pretty(value)
    return f"```{language}\n{text}\n```\n"


def cell(value: Any) -> str:
    if isinstance(value, (dict, list, bool)) or value is None:
        value = json.dumps(value, ensure_ascii=False)
    return str(value).replace("|", "\\|").replace("\n", " ")


def table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(cell(item) for item in row) + " |" for row in rows)
    return "\n".join(lines) + "\n"


def fraction(value: dict[str, Any]) -> str:
    numerator = value["numerator"]
    denominator = value["denominator"]
    result = value["value"]
    if result is None or denominator == 0:
        return f"{numerator}/{denominator} = N/A"
    return f"{numerator}/{denominator} = {result:.6f} ({result * 100:.2f}%)"


def repo_link(path: str) -> str:
    return f"[{path}](../../../{path})"


def file_hash(name: str) -> str:
    return hashlib.sha256((BASE / name).read_bytes()).hexdigest()


def metric_rows(metrics: dict[str, dict[str, Any]]) -> list[list[str]]:
    return [[name, fraction(value)] for name, value in metrics.items()]


def render_per_case(
    result: dict[str, Any],
    references: dict[str, dict[str, Any]],
    adjudications: dict[str, dict[str, Any]],
    signals: dict[str, dict[str, Any]],
    assignments: dict[str, str],
) -> str:
    cases = result["cases"]
    lines = [
        "# Kết quả từng case — calibration",
        "",
        f"Policy `{result['policy']['policy_id']}`; toàn bộ {len(cases)} cases là development/calibration. Không có held-out results.",
        "",
        "`expected_decision` là nhãn dataset đã duyệt. `context_sufficient` là đánh giá ngoài gate bằng conservative AI rubric trên context thực sự đã trả về; không phải nhãn human approval mới. `null` nghĩa chưa áp dụng/chưa đủ nhãn, không phải `false`. Các IDs/refs mong đợi chỉ dùng đối chiếu bên ngoài, không bổ sung context hoặc signals.",
        "",
        "Signals đầy đủ nằm ở [signals.json](signals.json), actual contexts ở [contexts.json](contexts.json), diagnostics ở [external_context_adjudication.json](external_context_adjudication.json). Dưới đây giữ nguyên toàn bộ signals của từng case và không dereference raw refs.",
        "",
    ]
    lines.append(table(
        ["Case", "Category", "Expected", "Actual", "Abstention stage", "Context sufficient"],
        [[c["case_id"], c["category"], c["expected_decision"], c["actual_decision"], c["gate_decision"]["abstention_stage"], c["context_sufficient"]] for c in cases],
    ))
    for case in cases:
        case_id = case["case_id"]
        reference = references[case_id]
        adjudication = adjudications[case_id]
        decision = case["gate_decision"]
        assert case["signals"] == signals[case_id], case_id
        assert case["expected_decision"] == reference["expected_decision"], case_id
        lines.extend([
            f"## {case_id}",
            "",
            f"Câu hỏi ({reference['language']}): {reference['query']}",
            "",
            table(
                ["Thuộc tính", "Giá trị"],
                [
                    ["Partition", assignments[case_id]],
                    ["Category", case["category"]],
                    ["Expected decision (dataset)", case["expected_decision"]],
                    ["Actual decision", case["actual_decision"]],
                    ["Abstention stage", decision["abstention_stage"]],
                    ["Reason codes", decision["reason_codes"]],
                    ["Topical expected label", case["topical_relevant"]],
                    ["Dataset answerable", case["dataset_answerable"]],
                    ["Actual context sufficient", case["context_sufficient"]],
                    ["External context basis", case["context_sufficiency_basis"]],
                    ["Topical actual stage status", decision["stage_results"]["topical_relevance"]["status"]],
                    ["Answerability actual stage status", decision["stage_results"]["evidence_answerability"]["status"]],
                ],
            ),
            "Đáp án tham chiếu đã duyệt (evaluation only; giữ nguyên nội dung lịch sử):",
            "",
            reference["reference_answer"],
            "",
            "Đối chiếu expected evidence và context thực tế; đây là diagnostic ngoài gate:",
            "",
            fenced({
                "ground_truth_pointers": reference["ground_truth_pointers"],
                "raw_record_references": reference["raw_record_references"],
                "expected_evidence_ids": adjudication.get("expected_evidence_ids", []),
                "returned_evidence_ids": adjudication.get("returned_evidence_ids", []),
                "missing_expected_evidence_ids": case["missing_expected_evidence_ids"],
                "missing_evidence_diagnostics": case["missing_evidence_diagnostics"],
                "external_context_sufficiency_basis": adjudication["context_sufficiency_basis"],
            }),
            "Signals đầy đủ đã cung cấp cho gate:",
            "",
            fenced(signals[case_id]),
        ])
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    # test_results.json is intentionally required: missing results must not be
    # replaced by guessed test counts or a premature report.
    tests = read_json("test_results.json")
    calibration = read_json("calibration_results.json")
    external = read_json("external_context_adjudication.json")
    plan = read_json("selection_plan.json")
    policies = read_json("candidate_policies.json")
    signals = read_json("signals.json")
    split = read_json("split_manifest.json")
    audit = read_json("consumer_audit.json")
    proposed = read_json("proposed_test_set.json")
    retrieval = read_json("frozen_retrieval_configuration.json")
    freeze = read_json("policy_freeze.json")
    replay = read_json("replay_result.json")
    heldout = read_json("heldout_status.json")
    preflight = read_json("preflight.json")
    answer_path = ROOT / retrieval["sources"]["answers"]["path"]
    answers = json.loads(answer_path.read_text(encoding="utf-8-sig"))
    references = {case["case_id"]: case for case in answers["cases"]}
    adjudications = {case["case_id"]: case for case in external["cases"]}
    selected = calibration["selected_result"]
    policy = selected["policy"]
    summary = selected["summary"]
    cases = selected["cases"]
    assert policy == calibration["selected_policy"]
    assert policy in policies
    assert len(policy["topical_relevance"]) == 8
    assert len(policy["evidence_answerability"]) == 12
    assert {case["case_id"] for case in cases} == set(signals) == set(references) == set(adjudications)
    assert all(split["assignments"][case["case_id"]] == "calibration" for case in cases)

    confusion = summary["dataset_label_confusion_matrix"]
    context_confusion = summary["context_eligibility_confusion_matrix"]
    fp = summary["false_proceed_by_category"]
    context_failures = [case["case_id"] for case in cases if case["dataset_answerable"] is True and case["context_sufficient"] is False]
    false_proceed_cases = [case["case_id"] for case in cases if case["expected_decision"] == "abstain" and case["actual_decision"] == "proceed"]
    languages = sorted({reference["language"] for reference in references.values()})
    language_rows = []
    for language in languages:
        subset = [case for case in cases if references[case["case_id"]]["language"] == language]
        proceeded = [case for case in subset if case["actual_decision"] == "proceed"]
        sufficient = [case for case in subset if case["context_sufficient"] is True]
        false_abstains = [case for case in sufficient if case["actual_decision"] == "abstain"]
        language_rows.append([
            language,
            len(subset),
            len(proceeded),
            f"{len(proceeded)}/{len(subset)}",
            sum(case["expected_decision"] == "abstain" for case in proceeded),
            f"{len(false_abstains)}/{len(sufficient)}" if sufficient else "0/0 = N/A",
        ])
    non_controls = [item for item in calibration["candidate_results"] if not item["summary"]["all_abstain"]]
    controls = [item for item in calibration["candidate_results"] if item["summary"]["all_abstain"]]
    grids = {
        condition: sorted({p["topical_relevance" if condition.startswith("min_returned") or condition == "min_query_token_coverage" else "evidence_answerability"][condition] for p in policies if p["policy_id"] != "negative-control-all-abstain"}, key=lambda value: (value is not None, value if value is not None else -1))
        for condition in plan["tunable_conditions"]
    }

    lines = [
        "# GRAPHRAG-2D3 — calibration gate hai tầng",
        "",
        f"Đã hoàn thành calibration chẩn đoán trên {len(cases)} cases development với {len(policies)} candidate policies. Policy không abstain toàn bộ được chọn để review là `{policy['policy_id']}`; **chưa đạt tiêu chí calibration và không đủ điều kiện production/held-out validation**. Dataset confusion matrix là TP={confusion['tp']}, TN={confusion['tn']}, FP={confusion['fp']}, FN={confusion['fn']}. False proceed ngoài phạm vi {fraction(fp['unrelated'])}; thiếu bằng chứng {fraction(fp['insufficient_evidence'])}. Coverage {fraction(summary['coverage'])}; tỷ lệ sai trong các case được proceed {fraction(summary['selective_error'])}.",
        "",
        "Hai giới hạn quyết định: frozen corpus/graph còn diễn đạt cũ rằng PowerShell đã chạy Get-Service thay vì chỉ được khởi chạy với command đó, và chưa có bộ held-out độc lập hợp lệ. Giữ nguyên các consumer theo phạm vi được giao; kết quả dưới đây chỉ là development diagnostics, không được dùng để công bố policy đạt yêu cầu.",
        "",
        "## Nhãn, approval và ranh giới dữ liệu",
        "",
        f"Ground Truth v2, reference answers v2 và manifest v2 ghi nhận approval của `{audit['human_approval']['reviewer']}`; thời điểm ghi nhận xác nhận từ clock preflight là `{audit['human_approval']['reviewed_at']}`. Đây không phải suy đoán timestamp của lần duyệt trước đó. `confirmed` chỉ xác nhận human review của tài liệu. Các MITRE mappings vẫn `candidate`/`needs_review`; không chuyển trạng thái approval thành gate signal, decision label hoặc kết luận an ninh. Nội dung đáp án có các câu pending-review lịch sử được bảo toàn; metadata v2 xác định approval hiện tại.",
        "",
        "Positive class là `proceed`, negative class là `abstain`. Dataset answerability hỏi dữ liệu có đủ căn cứ cho yêu cầu hay không; context answerability hỏi **những nội dung retrieval/traversal thực sự trả về** có đủ căn cứ hay không. Với câu thiếu bằng chứng, abstain áp dụng cho chi tiết/khẳng định được yêu cầu; giải thích ngắn về giới hạn vẫn có thể trả lời được.",
        "",
        "Chỉ query hiện tại được tính query embedding và truy xuất bằng local model đã pin. Không đưa bộ câu hỏi, reference answers, expected labels/decisions hoặc expected evidence vào query embedding, corpus, graph hay runtime signals. Expected evidence chỉ dùng đối chiếu ngoài gate; không dereference raw refs để bù context. Audit cấu trúc và full-string trên toàn corpus/graph không thấy evaluation fields, case IDs, toàn câu hỏi hay toàn đáp án. Đây không phải khẳng định đã phát hiện mọi semantic leakage; dữ kiện log trùng với câu trả lời là evidence được phép.",
        "",
        "## Lịch sử và chia tập",
        "",
        "Cả 32 IDs đã dùng trong embedding comparison/model selection, hai legacy calibration runs (672 policies mỗi run) và phân tích lỗi/review. Hai sửa wording không xóa lịch sử sử dụng. Tất cả được giữ ở calibration theo [split_manifest.json](split_manifest.json), không chia lại để gọi một phần là held-out độc lập. Semantic groups giữ các câu cùng ý nghĩa/bằng chứng trong cùng partition.",
        "",
        "Lịch sử có provenance:",
        "",
        fenced(audit["dataset_history"]),
        "## Policy và cách chọn",
        "",
        "Quy tắc được lưu trước search trong [selection_plan.json](selection_plan.json): ưu tiên ít false proceed ở unrelated và insufficient_evidence; nếu bằng nhau giữ nhiều context-sufficient positives hơn; tiếp đó ít enabled conditions hơn; cuối cùng `policy_id`. Candidate abstain toàn bộ bị loại khỏi selection. Chỉ hiệu chỉnh ba điều kiện từ signals thực tế, không vét cạn 20 fields hoặc hardcode query/case/keyword/answer vào evaluator.",
        "",
        "Các grid số thực tế (không dùng nhãn để dựng ngưỡng; cosine: tắt hoặc empirical Q25/Q50/Q75; coverage: 0 hoặc median; source-reference hits: 0 hoặc 1):",
        "",
        fenced(grids),
        f"Có {len(non_controls)} candidates không abstain toàn bộ và {len(controls)} negative control. Control có ngưỡng cosine cao hơn max observed nên coverage=0; selective error có mẫu số 0 là N/A, không được coi là thành công. Selection rank của policy chọn là `{selected['selection_rank']}` = `[false_proceed_count, -retained_context_sufficient_positives, enabled_condition_count, policy_id]`; enabled conditions={selected['complexity']}.",
        "",
        "Policy chọn giữ đủ **8 topical conditions + 12 answerability conditions**, không có hidden defaults; giá trị 0/null biểu diễn điều kiện không ràng buộc theo contract:",
        "",
        fenced(policy),
        "Lý do tắt các điều kiện còn lại:",
        "",
        table(["Nhóm điều kiện", "Lý do"], [[key, value] for key, value in plan["disabled_condition_rationales"].items()]),
        "Count hits/seeds/traversal chỉ chứng minh có cấu trúc truy xuất, không chứng minh đủ nội dung để trả lời query. Vì vậy không đặt thêm các ngưỡng mật độ graph tùy tiện. Limitation nodes có thể là context cần thiết; không phạt sự hiện diện của chúng.",
        "",
        "Kết quả của toàn candidate set:",
        "",
    ]
    candidate_rows = []
    for item in calibration["candidate_results"]:
        metrics = item["summary"]
        p = item["policy"]
        cm = metrics["dataset_label_confusion_matrix"]
        candidate_rows.append([
            p["policy_id"], p["topical_relevance"]["min_returned_top_cosine_score"],
            p["topical_relevance"]["min_query_token_coverage"], p["evidence_answerability"]["min_hits_with_source_references"],
            f"{cm['tp']}/{cm['tn']}/{cm['fp']}/{cm['fn']}",
            fraction(metrics["false_proceed_by_category"]["unrelated"]),
            fraction(metrics["false_proceed_by_category"]["insufficient_evidence"]),
            metrics["retained_context_sufficient_positives"], fraction(metrics["coverage"]),
            item["complexity"], "excluded all-abstain" if metrics["all_abstain"] else item["selection_rank"],
        ])
    lines.extend([
        table(["Policy", "Cosine min", "Coverage min", "Refs hits min", "TP/TN/FP/FN", "FP unrelated", "FP insufficient", "Context-good retained", "Coverage", "Complexity", "Selection rank"], candidate_rows),
        "Tiêu chí chấp nhận và trạng thái thực tế:",
        "",
        fenced({"acceptance_criteria": plan["acceptance_criteria"], "selection_status": calibration["selection_status"], "meets_calibration_error_constraints": calibration["meets_calibration_error_constraints"], "calibration_acceptance_failures": calibration["calibration_acceptance_failures"], "policy_qualified": calibration["policy_qualified"]}),
        "## Metrics của policy chọn",
        "",
        table(["Dataset expected \\ Actual", "proceed", "abstain", "Tổng"], [["proceed", confusion["tp"], confusion["fn"], confusion["tp"] + confusion["fn"]], ["abstain", confusion["fp"], confusion["tn"], confusion["fp"] + confusion["tn"]]]),
        table(["Dataset metric", "Tử số/mẫu số và giá trị"], metric_rows(summary["dataset_label_metrics"])),
        table(["Diagnostic", "Tử số/mẫu số và giá trị"], [
            ["False proceed ngoài phạm vi", fraction(fp["unrelated"])],
            ["False proceed thiếu bằng chứng", fraction(fp["insufficient_evidence"])],
            ["Coverage = proceed / tất cả cases", fraction(summary["coverage"])],
            ["Sai trong proceed (theo dataset label)", fraction(summary["selective_error"])],
            ["False abstain khi actual context đủ", fraction(summary["false_abstain_context_sufficient"])],
            ["Sai trong proceed (theo context eligibility)", fraction(summary["context_selective_error"])],
        ]),
        f"False proceed còn lại: `{', '.join(false_proceed_cases)}`. Với policy chọn, nhóm được proceed gồm 5 positive có actual context đủ và 1 câu thiếu bằng chứng. Gate hiện tại chưa phân biệt được yêu cầu URL tải payload với context process creation cùng chủ đề chỉ qua các aggregate signals.",
        "",
        "Phân bố ngôn ngữ được join từ approved reference cases **ngoài gate**, không sửa threshold hoặc runtime signals:",
        "",
        table(["Language", "Cases", "Proceed", "Coverage", "False proceed count", "False abstain / context-good"], language_rows),
        "Cả 6 cases được proceed đều tiếng Anh; tiếng Việt có coverage 0/16. Đây là hạn chế rõ của candidate hiện tại trên lát cắt song ngữ. Corpus chủ yếu tiếng Anh và lexical query-token coverage có thể làm bất lợi câu tiếng Việt; E5 multilingual không tự khắc phục một topical policy kết hợp lexical coverage. Đây là diagnostic/rủi ro cần kiểm chứng, không phải kết luận nhân quả hoặc lý do tuning tiếp sau khi xem slice. Không chọn ngưỡng riêng theo language.",
        "",
        f"Có {summary['dataset_answerable_context_failure_count']} positive theo dataset nhưng context chưa đủ: `{', '.join(context_failures)}`. Các trường command line gốc và scope limits mở rộng chưa được consumer trả về; không lấy expected evidence để sửa đầu vào. Abstain ở ba case này được ghi là retrieval/context failure, không mặc định là gate false abstain. Theo external rubric còn 13 cases context đủ; gate giữ 5 và abstain 8, tức {fraction(summary['false_abstain_context_sufficient'])}.",
        "",
        table(["Context eligibility expected \\ Actual", "proceed", "abstain"], [["eligible", context_confusion["tp"], context_confusion["fn"]], ["ineligible", context_confusion["fp"], context_confusion["tn"]]]),
        table(["Context eligibility metric", "Tử số/mẫu số và giá trị"], metric_rows(summary["context_eligibility_metrics"])),
        "Topical label positive có 24 cases (16 có đáp án + 8 thiếu bằng chứng vẫn cùng chủ đề), negative có 8 unrelated. Không suy mọi abstain là ngoài phạm vi. Answerability có 24 nhãn áp dụng; 8 unrelated để unknown/not-applicable cho tầng này. End-to-end context eligibility vẫn phân loại unrelated là ineligible theo topical scope, không biến chúng thành nhãn answerability false.",
        "",
    ])
    for stage_name, layer in summary["layers"].items():
        lines.extend([
            f"### {stage_name}",
            "",
            table(["Số lượng", "Giá trị"], [[key, layer[key]] for key in ("case_count", "known_label_count", "unknown_label_count", "evaluated_known_label_count", "not_evaluated_count", "known_label_not_evaluated_count")]),
            "Confusion matrix chỉ trên các case có nhãn áp dụng và tầng thực sự được đánh giá:",
            "",
            fenced(layer["confusion_matrix"]),
            table(["Metric", "Tử số/mẫu số và giá trị"], metric_rows(layer["metrics"])),
        ])
    lines.extend([
        "Answerability `not_evaluated` ở 26/32 cases vì topical gate đã dừng; 18 trong số này có nhãn answerability áp dụng và 8 unrelated không có nhãn tầng này. Metrics answerability tính trên đúng 6 evaluated-known cases, không lấy 32 làm mẫu số và không coi 26 cases chưa đánh giá là pass. Recall answerability có thể 5/5 trong slice đã qua topical, nhưng không thể diễn giải thành recall end-to-end tốt. Mọi metric có mẫu số 0 được ghi N/A; JSON lưu value=null.",
        "",
        "## External rubric và sửa lỗi đánh giá",
        "",
        "Đánh giá context là conservative AI support rubric ngoài runtime, liên kết đúng object/role và nội dung thực tế. Có evidence ID, raw ref hoặc JSON pointer không chứng minh nội dung cần thiết đã được trả về. Rubric này không thay thế semantic human review hoặc tạo human labels mới.",
        "",
        "Một review ngữ nghĩa phát hiện rubric ban đầu yêu cầu quá mức ở `rp-en-technique-review`: assessment trực tiếp đã đủ giải thích trạng thái technique, không cần thêm scenario analysis_status và limitation chung. Đã sửa yêu cầu ngoài gate rồi tính lại adjudication/metrics bằng saved contexts/signals. Approved labels, queries, gate inputs, threshold grids, selected policy và retrieval không đổi; đây là sửa metric rubric, không tuning gate theo kết quả. False abstain context-good cuối là 8/13.",
        "",
        fenced(audit.get("rubric_revisions", [])),
        "## Retrieval và provenance đã cố định",
        "",
        f"Model local `{retrieval['embedding']['model_id']}`, revision `{retrieval['embedding']['model_revision']}`, dimension={retrieval['embedding']['dimension']}, cosine với L2 normalization; document prefix `{retrieval['embedding']['document_prefix']}`, query prefix `{retrieval['embedding']['query_prefix']}`. Dùng lại provisional E5 recommendation; không chọn hoặc tải model mới. Chỉ chạy query embeddings trong CPU/offline runtime đã lưu.",
        "",
        "Cấu hình thực tế được giữ nguyên cho mọi candidate:",
        "",
        fenced({key: retrieval[key] for key in ("retrieval", "fusion", "seed_mapping", "traversal", "context_budget", "runtime", "query_input_boundary")}),
        "Nguồn dữ liệu cùng SHA-256 (evaluation GT v2 được tách khỏi consumer GT v1):",
        "",
        table(["Vai trò", "Đường dẫn", "SHA-256"], [[role, repo_link(source["path"]), source["sha256"]] for role, source in retrieval["sources"].items()] + [["consumer_ground_truth", repo_link(retrieval["consumer_ground_truth"]["path"]), retrieval["consumer_ground_truth"]["sha256"]]]),
        "Audit phát hiện các mâu thuẫn/thiếu nội dung cụ thể dưới đây. Chúng đã được báo trước policy selection; không rebuild corpus/graph/index hoặc diễn giải kết quả này thành qualified policy:",
        "",
        fenced(audit["stale_evidence_findings"]),
        "Các consumer v1-only còn lại, giữ nguyên trong milestone này; evaluation loader đọc và validate GT/answers/manifest v2 riêng, không hạ artifact version:",
        "",
        table(["File", "Contract hiện tại"], [[repo_link(item["path"]), item["contract"]] for item in audit["v1_only_consumers"]]),
        "## Freeze, replay và held-out",
        "",
        "Đã khóa policy, retrieval configuration, split manifest, evaluation code, criteria và saved signals bằng SHA-256. [evaluation_code_hashes.json](evaluation_code_hashes.json) ghi các source files; [policy_freeze.json](policy_freeze.json) giữ binding hashes. Freeze chuẩn bị một thử nghiệm có thể tái lập, không chứng minh đã có held-out đủ điều kiện.",
        "",
        fenced(freeze),
        f"Replay status: `{replay['status']}`, independent_experiment={str(replay['independent_experiment']).lower()}, heldout_run={str(replay['heldout_run']).lower()}. Đây là replay với cùng saved signals/configuration, không phải lần thử nghiệm độc lập mới và không điều chỉnh threshold sau replay.",
        "",
        fenced(heldout),
        f"Bộ mới [proposed_test_set.json](proposed_test_set.json) có {proposed['metadata']['case_count']} AI-proposed cases: {proposed['metadata']['category_counts']['in_scope_sufficient_evidence']} đủ bằng chứng theo full raw, {proposed['metadata']['category_counts']['in_scope_insufficient_evidence']} thiếu bằng chứng và {proposed['metadata']['category_counts']['unrelated']} unrelated. Tất cả pending_human_review, reviewer/time null; approval cũ không áp dụng. Chưa embed/query/gate các câu mới, không dùng chúng chọn ngưỡng.",
        "",
        "Năm positive probes cần raw ngoài core (conhost, process exit, temporary deletion, background connection và log clearing), không có trong frozen corpus/graph. Không dùng abstain của chúng làm false abstain cho frozen policy. Cùng raw file đã được review và có evidence overlap nên không gọi đây là independent unseen dataset; chi tiết novelty/grouping/eligibility tại [proposed_test_notes.md](proposed_test_notes.md). Hiện vẫn chưa có positive-context held-out độc lập hợp lệ cho frozen experiment.",
        "",
        "## Lệnh và kiểm thử thực tế",
        "",
        "Nguồn chính xác là [test_results.json](test_results.json). Nội dung sau giữ nguyên các lệnh phase/test, counts, exit codes và failed attempts được ghi nhận; không suy số tests từ baseline hoặc ước lượng. `failed_attempts=[]` nghĩa không có lần test fail trong lượt này, không xóa lịch sử failures của prerequisite.",
        "",
        fenced(tests),
        "## Baseline, giới hạn và bước tiếp theo",
        "",
        f"Preflight branch `{preflight['branch']}`, HEAD `{preflight['head']}`; staging tại preflight `{preflight['staging'] or 'empty'}`. Working tree có bốn Markdown và source/tests prerequisite từ trước; không reset, stage, commit hoặc ghi đè các phần đó. Danh sách hashes trước nằm ở [preflight.json](preflight.json); kết quả hashes trước/sau, Git state cuối và ZIP payload verification được ghi trong review_inventory.json của package.",
        "",
        "Chưa sửa production CLI, chưa gọi LLM/UI, chưa mở held-out, chưa đổi raw/approved Ground Truth/corpus/graph/index/retrieval outputs. `proceed` chỉ là context eligibility; không xác nhận attack, download, C2, cmdlet completion, service state hoặc technique.",
        "",
        "Milestone hiện đạt candidate-policy calibration và review package, chưa đạt verified policy. Bước tiếp theo cần review các diagnostics và nhãn/scope của bộ đề xuất; xác định một tập kiểm tra mới có context bằng chứng phù hợp và độc lập thực chất. Mâu thuẫn consumer cần một thay đổi phạm vi/rebuild được cho phép ở bước riêng trước khi dùng chúng chứng minh chất lượng. Không mặc định approval nhãn mới cho phép thay corpus hoặc chuyển sang CLI/LLM/UI.",
        "",
        "Chi tiết đầy đủ từng query, expected/actual decision, stages, reason codes, signals và evidence diagnostics: [per_case_report.md](per_case_report.md).",
        "",
        "Hashes của các artifact review trọng yếu lúc render:",
        "",
        table(["Artifact", "SHA-256"], [[f"[{name}]({name})", file_hash(name)] for name in ("calibration_results.json", "external_context_adjudication.json", "consumer_audit.json", "selected_policy.json", "candidate_policies.json", "selection_plan.json", "split_manifest.json", "signals.json", "frozen_retrieval_configuration.json", "policy_freeze.json", "replay_result.json", "proposed_test_set.json", "test_results.json")]),
    ])
    (BASE / "report.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    (BASE / "per_case_report.md").write_text(
        render_per_case(selected, references, adjudications, signals, split["assignments"]),
        encoding="utf-8",
    )
    print("Wrote report.md and per_case_report.md from saved review artifacts.")


if __name__ == "__main__":
    main()
