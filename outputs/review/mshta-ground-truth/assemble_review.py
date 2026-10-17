"""Reproduce the corrected MSHTA technical-review package without altering inputs."""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import logging
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.build_mshta_ground_truth import build_document
from threat_hunting.ground_truth import validate_ground_truth_document
from threat_hunting.mordor.parser import iter_jsonl
from threat_hunting.evaluation.relevance_dataset import validate_relevance_calibration_dataset
from threat_hunting.evaluation.retrieval_judgments import resolve_retrieval_judgments

REVIEW_DIR = Path(__file__).resolve().parent
BASELINE = {
    "configs/ground_truth/mshta_powershell.json": "f13f3efe1c783911ea512d98533826b4e2086349aead26795b7b6d57e49c247f",
    "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "benchmarks/graphrag/mshta_relevance_calibration.json": "6764dda887c216a8c9fd83590391f2f9079a8fc0f5e0f74959e63e95654f62a4",
    "benchmarks/retrieval/mshta_embedding_retrieval_judgments.json": "021c7a31f8244d15ba8a84258d067d8112753a26138dfb3afb57f5ae921eaf0d",
    "outputs/retrieval/mshta-powershell/retrieval_corpus.json": "53abc9e44c03c46aaf024cdb79b61ad3381d50feb82689f27074151381b9d0f3",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(name: str, value: Any) -> Path:
    path = REVIEW_DIR / name
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    path.write_text(payload, encoding="utf-8", newline="\n")
    if read_json(path) != value:
        raise ValueError(f"JSON readback mismatch: {path.name}")
    return path


def pointer(document: Any, path: str) -> Any:
    value = document
    for token in path.removeprefix("/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    original_hashes = {rel: sha256(ROOT / rel) for rel in BASELINE}
    if original_hashes != BASELINE:
        raise ValueError("Baseline input hash mismatch; review must be repeated against changed sources.")
    raw_audit = read_json(REVIEW_DIR / "raw_audit.json")
    sigma_audit = read_json(REVIEW_DIR / "sigma_mitre_audit.json")
    answer_audit = read_json(REVIEW_DIR / "reference_answers_audit.json")
    raw_path = ROOT / raw_audit["source_file"]
    raw_before = sha256(raw_path)
    if raw_before != raw_audit["baseline_sha256"]:
        raise ValueError(f"Raw SHA-256 mismatch: {raw_path.name}")
    if not sigma_audit["input_files_unchanged"] or not sigma_audit["source_hash_matches_baseline"]:
        raise ValueError("Sigma/MITRE audit failed integrity checks")
    for field in ("anchor_source_to_canonical_errors", "ground_truth_observation_errors", "intermediate_observation_errors", "raw_canonical_invariant_errors"):
        if raw_audit[field]:
            raise ValueError(f"Raw audit has unresolved errors: {field}")
    reviewed_inputs = {ROOT / rel: digest for rel, digest in sigma_audit["input_sha256"].items()}
    for item in raw_audit["input_provenance_checks"]:
        reviewed_inputs[ROOT / item["path"]] = item["expected_sha256"]
    for item in answer_audit["input_provenance"]:
        reviewed_inputs[ROOT / item["path"]] = item["sha256"]
    for path, expected in reviewed_inputs.items():
        if sha256(path) != expected:
            raise ValueError(f"Audit input changed: {path.name}")
    wanted = {"jsonl:line:4", "jsonl:line:275", "jsonl:line:30", "jsonl:line:398"}
    records: dict[str, dict[str, Any]] = {}
    count = 0
    for record in iter_jsonl(raw_path):
        count += 1
        if record.raw_record_ref in wanted:
            records[record.raw_record_ref] = record.data
    if count != 1127 or set(records) != wanted:
        raise ValueError(f"Complete raw scan or anchor count mismatch: {raw_path.name}")
    baseline_gt = read_json(ROOT / "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json")
    dataset_rel = "benchmarks/graphrag/mshta_relevance_calibration.json"
    corpus_rel = "outputs/retrieval/mshta-powershell/retrieval_corpus.json"
    dataset = read_json(ROOT / dataset_rel)
    corpus = read_json(ROOT / corpus_rel)
    judgments = read_json(ROOT / "benchmarks/retrieval/mshta_embedding_retrieval_judgments.json")
    resolved = resolve_retrieval_judgments(
        judgments, dataset, corpus,
        source_dataset_path=dataset_rel, source_dataset_bytes=(ROOT / dataset_rel).read_bytes(),
        source_corpus_path=corpus_rel, source_corpus_bytes=(ROOT / corpus_rel).read_bytes(),
    )
    config = read_json(ROOT / "configs/ground_truth/mshta_powershell.json")
    config["scenario"]["description"] = (
        "Reviewable MSHTA-PowerShell scenario in which cmd.exe launches mshta.exe and mshta.exe launches "
        "powershell.exe with -noexit -command Get-Service sysmon. Process creation records establish the "
        "launch command, not successful cmdlet completion or a finalized attack determination."
    )
    config["summary"]["observed_behavior"][2] = "PowerShell was launched with -noexit -command Get-Service sysmon."
    config["summary"]["limitations"].extend([
        "Process-creation telemetry does not establish successful cmdlet completion, output, or the Sysmon service state.",
        "Canonical timestamps follow TimeCreated; Sysmon UtcTime differs by about four hours and its timezone is unresolved.",
        "The file also contains conhost creation, event-log clearing and temporary-file deletion telemetry outside this two-group core. These must not be described as globally absent or automatically classified as a destructive payload.",
    ])
    config["review_notes"].append("Codex technical review on 2026-10-14 corrected launch-command wording and added original anchor fields; human approval remains pending. See the adjacent review report and audit files.")
    anchor_fields = {item["raw_record_ref"]: item["original_fields"] for item in raw_audit["original_anchors"]}
    for fact in config["facts"]:
        observations = []
        for ref in fact["source_references"]:
            raw_ref = ref["raw_record_ref"]
            fields = anchor_fields[raw_ref]
            if any(records[raw_ref].get(key) != value for key, value in fields.items()):
                raise ValueError(f"Audit anchor differs from raw record: {raw_ref}")
            observations.append({**ref, "original_fields": deepcopy(fields)})
        fact["attributes"]["source_observations"] = sorted(observations, key=lambda item: item["raw_record_ref"])
    config_path = write_json("review_build_config.json", config)
    gt_path = REVIEW_DIR / "scenario_ground_truth.json"
    build_document(
        scenario_evidence_path=ROOT / "outputs/evidence/mshta-powershell/scenario_evidence.json",
        sigma_review_path=ROOT / "outputs/evidence/mshta-powershell/sigma_match_review.json",
        mitre_resolution_path=ROOT / "outputs/evidence/mshta-powershell/mitre_resolution.json",
        build_config_path=config_path, output_path=gt_path,
        expected_scenario_evidence_sha256="ea56d0bb07547da85a98339491af55d5b984d96ab8558eef3f8ec530955a4905",
        expected_sigma_review_sha256="cafb455ce6ad59cc5cf5f62805a0d7354f6b88d69fc1414c6f860222fd147fe4",
        expected_mitre_resolution_sha256="f5eec09eaff36806e8567f215d9eed7edc7bc62dc3c3c9864dcbae3c6dcd608d",
        expected_build_config_sha256=sha256(config_path), overwrite=True,
    )
    reviewed_gt = read_json(gt_path)
    validate_ground_truth_document(reviewed_gt)
    reviewed_dataset = deepcopy(dataset)
    reviewed_dataset["dataset_id"] = "mshta-relevance-calibration-reviewed-v1"
    audits_by_id = {case["case_id"]: case for case in answer_audit["cases"]}
    if len(audits_by_id) != 32 or set(audits_by_id) != {case["case_id"] for case in dataset["cases"]}:
        raise ValueError("Reference answers must cover exactly the 32 baseline case IDs")
    cases = []
    for index, case in enumerate(reviewed_dataset["cases"]):
        audit = audits_by_id[case["case_id"]]
        if audit["original_query"] != case["query"]:
            raise ValueError(f"Reference question differs from baseline: {case['case_id']}")
        if (audit["reviewed_expected_decision"], audit["reviewed_category"]) != (case["expected_decision"], case["category"]):
            raise ValueError(f"Unreviewed label change: {case['case_id']}")
        case["query"] = audit["proposed_query"]
        if case["case_id"] == "rp-vi-service-action":
            case["rationale"] = "Command line records at lines 30/398 contain -noexit -command Get-Service sysmon. This supports the recorded launch command, not successful cmdlet completion or service state."
        if case["case_id"] == "ie-vi-destructive-files":
            case["query"] = "Trong hai nhóm process-creation evidence của ground truth, có bằng chứng nào cho thấy payload PowerShell cố ý phá hoại tệp không?"
            case["rationale"] = "The two-group core contains process-creation observations, not evidence establishing destructive payload intent. The full raw file includes temporary-file deletion, which must not be conflated with a destructive payload or asserted globally absent."
        for ref in audit["raw_record_references"]:
            if ref["source_file"] != raw_path.name or ref["raw_record_ref"] not in records:
                raise ValueError(f"Invalid answer raw reference: {case['case_id']}")
        for source_pointer in audit["relevant_source_pointers"]:
            pointer(reviewed_gt, source_pointer)
        cases.append({
            "case_id": case["case_id"], "source_case_pointer": f"/cases/{index}",
            "query": case["query"], "original_query": audit["original_query"],
            "language": case["language"], "category": case["category"],
            "expected_decision": case["expected_decision"], "target_kind": audit["target_kind"],
            "reference_answer": audit["reference_answer"], "reference_answer_language": "vi",
            "ground_truth_pointers": audit["relevant_source_pointers"],
            "raw_record_references": audit["raw_record_references"],
            "raw_reference_role": audit["raw_reference_role"],
            "answer_constraints": audit["answer_constraints"],
        })
        if case["case_id"] == "ie-vi-destructive-files":
            cases[-1]["reference_answer"] = "Hai nhóm process-creation evidence không chứng minh payload PowerShell cố ý phá hoại tệp. Log gốc có record xóa tệp tạm, nhưng việc xóa tệp tạm không tự chứng minh ý định phá hoại và nằm ngoài hai nhóm evidence của core này. Không suy ra toàn dataset không có thao tác xóa tệp; câu hỏi liệt kê tệp đã xóa trong raw cần một phạm vi evidence khác."
            cases[-1]["ground_truth_pointers"] = sorted(set(cases[-1]["ground_truth_pointers"] + ["/summary/limitations/6"]))
        if case["case_id"] == "rd-vi-reviewed-scope-limitations":
            cases[-1]["reference_answer"] = "Ground truth chỉ chứa hai behavior/evidence groups, không phải toàn bộ process inventory. Sysmon có timestamp_conflict: canonical dùng TimeCreated, còn UtcTime lệch khoảng bốn giờ và timezone chưa được xác nhận. Process creation không chứng minh cmdlet hoàn tất hay trạng thái dịch vụ. Log gốc có conhost creation, log clearing và temporary-file deletion ngoài core, nên không được kết luận các hành vi đó vắng mặt trên toàn dataset hoặc tự coi là destructive payload. Chưa có negative detector toàn diện; MITRE assessments còn candidate và human approval còn pending."
            cases[-1]["ground_truth_pointers"] = sorted(set(cases[-1]["ground_truth_pointers"] + [f"/summary/limitations/{i}" for i in (4, 5, 6)]))
    validate_relevance_calibration_dataset(reviewed_dataset)
    dataset_path = write_json("mshta_relevance_calibration_reviewed.json", reviewed_dataset)
    answers = {
        "schema_version": "mshta-reference-answers/v1", "scenario_id": "mshta-powershell",
        "purpose": "evaluation_reference_only_not_retrieval_or_runtime_gate_input",
        "review": deepcopy(answer_audit["review"]), "scope_policy": answer_audit["scope_policy"],
        "sources": {
            "ground_truth": {"path": gt_path.relative_to(ROOT).as_posix(), "sha256": sha256(gt_path)},
            "dataset": {"path": dataset_path.relative_to(ROOT).as_posix(), "sha256": sha256(dataset_path)},
            "raw_log": {"path": raw_path.relative_to(ROOT).as_posix(), "sha256": raw_before},
        },
        "cases": cases, "metadata": {
            "case_count": len(cases), "category_counts": dict(sorted(Counter(case["category"] for case in cases).items())),
            "decision_counts": dict(sorted(Counter(case["expected_decision"] for case in cases).items())),
            "changed_labels": 0, "changed_queries": sum(case["query"] != case["original_query"] for case in cases),
            "dataset_use": "calibration_not_final_benchmark",
        },
    }
    write_json("reference_answers.json", answers)
    markdown_lines = [
        "# Đáp án tham chiếu MSHTA–PowerShell",
        "",
        "Review kỹ thuật: Codex, 14/10/2026. Phê duyệt của con người còn pending.",
        "",
        "32 câu: 16 proceed, 8 thiếu bằng chứng, 8 ngoài phạm vi. Hai câu được làm rõ cách diễn đạt; không đổi nhãn.",
        "",
        "Đáp án chỉ dùng cho đánh giá, không đưa vào retrieval corpus hoặc runtime gate input. Đây là calibration set, chưa phải benchmark độc lập.",
        "",
    ]
    for index, case in enumerate(cases, 1):
        markdown_lines.extend([
            f"## {index}. {case['case_id']}", "",
            f"**Câu hỏi:** {case['query']}", "",
            f"**Nhãn:** `{case['category']}` / `{case['expected_decision']}`; context target `{case['target_kind']}`.", "",
            f"**Đáp án:** {case['reference_answer']}", "",
            "**Ground truth pointers:** " + (", ".join(f"`{value}`" for value in case["ground_truth_pointers"]) or "Không có chunk liên quan trong phạm vi này."), "",
        ])
        if case["raw_record_references"]:
            markdown_lines.extend(["**Log gốc:** " + ", ".join(f"`{ref['raw_record_ref']}`" for ref in case["raw_record_references"]), ""])
        if case["query"] != case["original_query"]:
            markdown_lines.extend([f"**Câu gốc được sửa:** {case['original_query']}", ""])
    (REVIEW_DIR / "reference_answers.md").write_text("\n".join(markdown_lines), encoding="utf-8", newline="\n")
    if sha256(raw_path) != raw_before or {rel: sha256(ROOT / rel) for rel in BASELINE} != original_hashes:
        raise ValueError("A baseline input changed during review")
    for path, expected in reviewed_inputs.items():
        if sha256(path) != expected:
            raise ValueError(f"Original reviewed source changed: {path.name}")
    artifact_names = ["review_build_config.json", "scenario_ground_truth.json", "mshta_relevance_calibration_reviewed.json", "reference_answers.json", "reference_answers.md", "raw_audit.json", "sigma_mitre_audit.json", "reference_answers_audit.json", "assemble_review.py", "audit_raw.py", "audit_sigma_mitre.py", "review_report.md"]
    manifest = {
        "schema_version": "mshta-technical-review/v1", "review_date": "2026-10-14",
        "scenario_id": "mshta-powershell", "reviewer": "Codex", "reviewer_type": "ai_assistant",
        "status": "technical_review_completed_with_corrections", "human_review_status": "pending_human_review",
        "raw_records_examined": count, "canonical_records_examined": raw_audit["complete_scan_records"],
        "input_hashes_unchanged": True, "baseline_inputs": original_hashes,
        "original_sources": {path.relative_to(ROOT).as_posix(): value for path, value in reviewed_inputs.items()},
        "reviewed_entities": len(reviewed_gt["entities"]), "reviewed_relationships": len(reviewed_gt["relationships"]),
        "reviewed_evidence": len(reviewed_gt["evidence"]), "resolved_baseline_cases": len(resolved),
        "resolved_baseline_relevance_pointers": sum(len(case["relevant_source_pointers"]) for case in resolved),
        "reference_answers": len(cases), "category_and_decision_changes": 0,
        "query_wording_corrections": answers["metadata"]["changed_queries"],
        "mitre_label_promotions": 0, "json_readback_passed": True,
        "artifacts": {name: sha256(REVIEW_DIR / name) for name in artifact_names},
        "consumer_note": "The existing corpus, graph, vector indexes and evaluation reports are pinned to the earlier ground truth. The corrected review artifacts are a separate version; consumers must be rebuilt with new provenance in the next milestone.",
        "baseline_ground_truth_valid": True,
    }
    validate_ground_truth_document(baseline_gt)
    write_json("review_manifest.json", manifest)
    logging.info("Reviewed %s raw records, %s reference answers; original input hashes unchanged.", count, len(cases))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
