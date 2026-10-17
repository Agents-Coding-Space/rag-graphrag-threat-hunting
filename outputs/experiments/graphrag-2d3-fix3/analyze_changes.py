"""External development-only case analysis after the frozen FIX3 E0--E4 run.

This report joins labels and the unchanged external AI rubric AFTER runtime.
Nothing from this script is supplied to the parser, enrichment or policy.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "outputs/experiments/graphrag-2d3-fix3"
REVIEW = ROOT / "outputs/review/graphrag-parser-policy-fix3"
ANSWERS = ROOT / "outputs/review/mshta-ground-truth/reference_answers.json"
ARMS = ("E0", "E1", "E2", "E3", "E4")


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def value_at(root: object, pointer: str) -> object:
    assert pointer.startswith("/"), pointer
    value = root
    for escaped in pointer.split("/")[1:]:
        field = escaped.replace("~1", "/").replace("~0", "~")
        value = value[int(field)] if isinstance(value, list) else value[field]
    return value


def citation(trace: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    matches = [(index, item) for index, item in enumerate(context["final_items"])
               if item["kind"] == trace["kind"] and item["item_id"] == trace["item_id"]]
    assert len(matches) == 1, "Trace does not uniquely identify an actual returned object"
    index, item = matches[0]
    pointer = f"/final_items/{index}/payload" + trace["field"]
    assert trace["context_pointer"] == pointer, "Trace field is not at the cited returned-object pointer"
    actual = value_at(context, pointer)
    assert trace["quote"] == (actual if isinstance(actual, str) else canonical(actual)), "Trace quotation changed"
    payload = item["payload"]
    assert trace["source_pointer"] == payload["source"]["json_pointer"]
    return {
        **deepcopy(trace), "actual_field_value": deepcopy(actual),
        "actual_final_context_quote_verified": True,
        "origin": item["origin"], "source_identity": deepcopy(payload["source"]),
        "source_references": deepcopy(payload["source_references"]),
        "actual_returned_evidence_ids": deepcopy(payload["evidence_ids"]),
    }


def explanation(kind: str, parameters: dict[str, Any]) -> tuple[str, list[str]]:
    common = [
        "Trace được đối chiếu với final_items thực tế; runtime support không thay thế approved label hoặc rubric ngoài.",
        "Thiếu evidence chỉ mô tả context đã kiểm tra; không chứng minh hành vi vắng mặt trên toàn hệ thống.",
    ]
    if kind == "process_relationship":
        why = ("Các quan hệ process creation có hướng được nối bằng process instance identity thực tế. "
               "Guard kiểm tra boundary, depth/cycle và mâu thuẫn identity.") if parameters.get("chain") else (
                   "Trace ràng buộc parent và child đúng chiều, có instance identities và source references của process creation.")
        if parameters.get("chain") and parameters.get("parent") is None:
            why += " Query chỉ nêu target; truy ngược tới source boundary, không đoán tên ancestor trong parser."
        return why, common + ["Parent-child creation không chứng minh completion, payload intent hoặc hành vi network."]
    if kind == "launch_command":
        return ("Original CommandLine được trích từ process-creation observation gắn với process được hỏi và instance identity.",
                common + ["Chỉ xác nhận command line khi launch; không xác nhận cmdlet hoàn tất, output hoặc service state."])
    if kind == "evidence_provenance":
        return ("Các trường/source observation thực sự được trả về gắn event/provider/timestamp với source file và raw record reference.",
                common + ["Không tự sửa xung đột TimeCreated/UtcTime hoặc suy timezone chưa được nguồn xác minh."])
    if kind == "review_limitations":
        return ("Các limitation/review-scope fields được trích đúng source identities cần cho facets; completeness guard đối chiếu tập identities, không chỉ đếm items.",
                common + ["analysis_status mô tả tình trạng phân tích của artifact; human approval không xác nhận kết luận an ninh.",
                          "Limitation prose hỗ trợ câu hỏi về giới hạn, không chứng minh một positive behavior khác."])
    if kind == "technique_assessment":
        return ("Trace giữ external technique ID, evidence_support, review_status và rationale của source-associated assessment.",
                common + ["Candidate/needs_review không được nâng thành confirmed; Sigma tags không tự chứng minh behavior."])
    if kind == "network_url":
        return ("Verifier yêu cầu actor–action–endpoint ràng buộc trong observation/fact thực tế; URL đơn lẻ trong command/reference không đủ.",
                common + ["Connect không tự chứng minh download; endpoint không chứng minh C2 hoặc exfiltration."])
    return ("Chỉ evidence riêng cho requirement mới có thể hỗ trợ requirement; launch/prose không thay thế completion hoặc state observation.",
            common + ["Các giới hạn invocation/service identity của verifier vẫn áp dụng; unknown không trở thành supported."])


def requirement_details(requirement: dict[str, Any], selected: dict[str, Any], guard: dict[str, Any],
                        context: dict[str, Any]) -> dict[str, Any]:
    why, limitations = explanation(requirement["kind"], requirement["parameters"])
    return {
        "requirement": deepcopy(requirement),
        "source_spans_available": "source_spans" in requirement,
        "support_status": selected.get("status", "unknown"),
        "support_reason_codes": deepcopy(selected.get("reason_codes", [])),
        "selected_support_citations": [citation(trace, context) for trace in selected.get("traces", [])],
        "independent_guard_status": guard.get("status"),
        "independent_completeness": deepcopy(guard.get("completeness")),
        "independent_contradiction": deepcopy(guard.get("contradiction")),
        "independent_guard_citations": [citation(trace, context) for trace in guard.get("traces", [])],
        "why_evidence_supports_the_parsed_requirement": why,
        "interpretation_requires_support_status_supported": True,
        "limitations_and_unproven_claims": limitations,
    }


def blockquote(text: str) -> str:
    return "\n".join("> " + line for line in str(text).splitlines())


def markdown_case(case: dict[str, Any]) -> str:
    lines = [f"## `{case['case_id']}` ({case['language']})", "", case["query"], "",
             f"Approved label: **{case['expected_decision']}**; category `{case['category']}`. "
             "Đây là đối chiếu ngoài runtime; không thay đổi nhãn.", "",
             "| Arm | Decision | Parser | Support | Rubric context sufficient | Reasons |",
             "| --- | --- | --- | --- | --- | --- |"]
    for arm, entry in case["arms"].items():
        reasons = ", ".join(entry["reason_codes"]) or "—"
        lines.append(f"| {arm} | {entry['decision']} | {entry['analysis_status']} | {entry['support_status']} | "
                     f"{entry['external_diagnostic']['context_sufficient']} | {reasons} |")
    lines += ["", "Nhóm thay đổi: " + ", ".join(case["change_types"]) + ".", ""]
    for arm in case["arms"]:
        entry = case["arms"][arm]
        if not entry["newly_permitted_vs_E0"] and not entry["baseline_true_positive_lost"] and not entry["false_proceed"]:
            continue
        lines += [f"### {arm}: {entry['transition_from_E0']}", "",
                  f"Legacy decision: `{entry['legacy_decision']}`; scope `{entry['scope_status']}`. "
                  f"Final context: {entry['context_metrics']['final_item_count']} items, "
                  f"{entry['context_metrics']['supplementary_item_count']} supplementary. "
                  f"Approved-label outcome: **{entry['label_outcome']}**.", "",
                  "Rubric AI ngoài runtime: " + canonical(entry["external_diagnostic"]) + ". "
                  "Rubric này còn giới hạn exact text/semantic unknown và không phải independent validation.", ""]
        for detail in entry["requirements"]:
            requirement = detail["requirement"]
            lines += [f"Requirement `{requirement['requirement_id']}` — `{requirement['kind']}`: "
                      f"`{canonical(requirement['parameters'])}`; support `{detail['support_status']}`.", ""]
            if detail["source_spans_available"]:
                lines.append("Parser source spans (exact original query offsets/text):")
                lines.append("")
                for span in requirement["source_spans"]:
                    lines.append("- " + canonical(span))
                lines.append("")
            else:
                lines += ["Requirements v1 không có source spans; không tạo trace ngôn ngữ giả cho E0/E2.", ""]
            lines += [detail["why_evidence_supports_the_parsed_requirement"] if detail["support_status"] == "supported"
                      else "Support chưa established; các citation dưới đây chỉ là trace phần evidence đã kiểm tra.", "",
                      "Completeness/contradiction guards: " + canonical({
                          "status": detail["independent_guard_status"],
                          "completeness": detail["independent_completeness"],
                          "contradiction": detail["independent_contradiction"]}) + ".", ""]
            distinct = {canonical(trace): trace for trace in detail["selected_support_citations"] + detail["independent_guard_citations"]}
            if not distinct:
                lines += ["Không có supporting quotation cho requirement này.", ""]
            for trace in distinct.values():
                lines += [f"- `{trace['kind']}:{trace['item_id']}` ({trace['origin']}), "
                          f"field `{trace['field']}`, context `{trace['context_pointer']}`, source `{trace['source_pointer']}`.",
                          "  Source binding: " + canonical(trace["source_identity"]) + "; raw references " + canonical(trace["source_references"]) + ".",
                          "  Role binding: " + canonical(trace.get("binding")) + ".", "",
                          blockquote(trace["quote"]), ""]
            lines += ["Giới hạn:", ""]
            lines.extend("- " + limitation for limitation in detail["limitations_and_unproven_claims"])
            lines.append("")
    return "\n".join(lines)


def main() -> int:
    # Require the frozen run to exist. The root agent invokes this only after its
    # evaluation-completed signal; this script performs no runtime experiment.
    freeze = read(OUT / "pre_evaluation_freeze.json")
    ablation = read(OUT / "ablation_results.json")
    assert ablation["E0_replay_matches_FIX2"] is True
    assert digest(OUT / "combined_policy.json") == freeze["combined_policy_sha256"]
    for name, expected in freeze["runtime_code_sha256"].items():
        assert digest(ROOT / name) == expected, "Analysis cannot silently use a different runtime source"
    assert digest(ROOT / "scripts/evaluate_parser_policy_fix3.py") == freeze["runner_sha256"]
    decisions, contexts, requirements, diagnostics = (
        read(OUT / name) for name in ("decisions.json", "contexts.json", "requirements.json", "external_context_adjudication.json")
    )
    records = read(OUT / "evaluation_records.json")
    record_map = {arm: {record["case_id"]: record for record in records[arm]} for arm in ARMS}
    cases = read(ANSWERS)["cases"]
    changed = []
    counts = {arm: Counter() for arm in ARMS[1:]}
    for case in cases:
        identifier = case["case_id"]
        baseline = decisions["E0"][identifier]["decision"]
        selected = any(decisions[arm][identifier]["decision"] != baseline for arm in ARMS[1:])
        selected = selected or any(case["expected_decision"] == "abstain" and decisions[arm][identifier]["decision"] == "proceed" for arm in ARMS)
        if not selected:
            continue
        entry = {field: deepcopy(case[field]) for field in ("case_id", "query", "language", "category", "expected_decision")}
        entry["change_types"] = []
        entry["arms"] = {}
        for arm in ARMS:
            decision = decisions[arm][identifier]
            actual, trace = decision["decision"], decision["trace"]
            parsed = requirements[arm][identifier]
            context = contexts[arm][identifier]
            support = trace["support_assessment"]
            guards = trace.get("verification_guards", support)
            support_map = {result["requirement_id"]: result for result in support["requirements"]}
            guard_map = {result["requirement_id"]: result for result in guards["requirements"]}
            new_proceed = baseline == "abstain" and actual == "proceed"
            lost = case["expected_decision"] == "proceed" and baseline == "proceed" and actual == "abstain"
            false_proceed = case["expected_decision"] == "abstain" and actual == "proceed"
            outcome = "TP" if actual == "proceed" and case["expected_decision"] == "proceed" else "FP" if actual == "proceed" else "FN" if case["expected_decision"] == "proceed" else "TN"
            if arm != "E0":
                counts[arm]["newly_permitted"] += new_proceed
                counts[arm]["rescued_dataset_positive"] += new_proceed and case["expected_decision"] == "proceed"
                counts[arm]["rescued_dataset_positive_vi"] += new_proceed and case["expected_decision"] == "proceed" and case["language"] == "vi"
                counts[arm]["baseline_true_positive_lost"] += lost
                counts[arm]["false_proceed"] += false_proceed
            if new_proceed and "abstain_to_proceed" not in entry["change_types"]:
                entry["change_types"].append("abstain_to_proceed")
            if lost and "baseline_true_positive_lost" not in entry["change_types"]:
                entry["change_types"].append("baseline_true_positive_lost")
            if false_proceed and "false_proceed" not in entry["change_types"]:
                entry["change_types"].append("false_proceed")
            details = [requirement_details(req, support_map.get(req["requirement_id"], {}), guard_map.get(req["requirement_id"], {}), context)
                       for req in parsed["requirements"]]
            if new_proceed:
                assert parsed["analysis_status"] == support["status"] == "supported"
                assert all(detail["support_status"] == "supported" and detail["selected_support_citations"] for detail in details)
            metrics = record_map[arm][identifier]["context_metrics"]
            entry["arms"][arm] = {
                "decision": actual, "transition_from_E0": baseline + "->" + actual,
                "newly_permitted_vs_E0": new_proceed, "baseline_true_positive_lost": lost,
                "false_proceed": false_proceed, "label_outcome": outcome,
                "analysis_status": parsed["analysis_status"], "scope_status": parsed["scope"]["status"],
                "support_status": support["status"], "legacy_decision": trace["legacy_decision"]["decision"],
                "reason_codes": deepcopy(decision["reason_codes"]),
                "requirements": details, "context_metrics": deepcopy(metrics),
                "external_diagnostic": deepcopy(diagnostics[arm][identifier]),
                "context_ground_truth_binding": deepcopy(context["initial_context"]["source_ground_truth"]),
                "ranked_context_matches_E0": context["initial_context"] == contexts["E0"][identifier]["initial_context"],
            }
        changed.append(entry)
    result = {
        "schema_version": "fix3-external-changed-case-analysis/v1",
        "development_only": True, "runtime_inputs_included_labels": False,
        "evaluation_labels_are_approved_dataset_labels": True,
        "external_rubric_is_ai_diagnostic_with_limits": True,
        "input_hashes": {name: digest(OUT / name) for name in ("requirements.json", "contexts.json", "decisions.json", "evaluation_records.json", "external_context_adjudication.json", "pre_evaluation_freeze.json")},
        "cases_with_decision_changes_or_false_proceed": len(changed),
        "per_arm_change_counts": {arm: dict(value) for arm, value in counts.items()},
        "cases": changed,
    }
    REVIEW.mkdir(parents=True, exist_ok=True)
    (REVIEW / "changed_cases.json").write_bytes((json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8"))
    assert read(REVIEW / "changed_cases.json") == result
    intro = ("# FIX3 — Phân tích các case thay đổi quyết định\n\n"
             "Đối chiếu E1–E4 với E0 trên cùng 32 development queries đã exposed. "
             "Phân tích này chạy sau frozen experiment, giữ approved labels và AI rubric ngoài runtime. "
             "Không gọi đây là held-out hoặc independent validation.\n\n"
             "Mọi quotation dưới đây được kiểm tra đúng field/item ID/source pointer trong final context thực tế. "
             "Support và guard là chẩn đoán runtime, không được dùng làm ground truth tự chấm chính nó. "
             "Các trace v1 không có parser spans được ghi rõ; không tạo source span giả.\n\n"
             "Changed counts: `" + canonical(result["per_arm_change_counts"]) + "`.\n\n")
    body = intro + "\n\n".join(markdown_case(case) for case in changed)
    (REVIEW / "changed_cases.md").write_bytes((body + "\n").encode("utf-8"))
    print(json.dumps({"changed_cases": len(changed), "per_arm_change_counts": result["per_arm_change_counts"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
