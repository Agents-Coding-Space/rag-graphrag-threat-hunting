"""Read-only analysis/export of the final direct study, including honest not_run closure."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from threat_hunting.evaluation import experimental_comparison as p

BASE = ROOT / "outputs/final/20261031_direct_v7"
LIVE = ROOT / "outputs/experiments/integrated-final-direct-v7-live-01"
CONFIG = ROOT / "configs/evaluation/integrated_final_direct_v7.json"


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def csv_write(path: Path, rows: list[dict]) -> None:
    with path.open("x", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    pin = p._read(BASE / "runtime_pin.json")
    if p._code_manifest() != pin["code_sha256"]:
        raise ValueError("Final runtime changed; do not combine results")
    preflight = BASE / "preflight"
    prepared = p._read(preflight / "results.json")
    recorded = p._read(LIVE / "results.json")
    original = {(r["case_id"], r["branch"]): r for r in recorded["rows"]}
    ledger = p._read(BASE / "request_budget.json")
    stop = p._read(BASE / "operational_stop.json")
    benchmark = p._read(ROOT / "benchmarks/integrated/scenarios_12_v1.json")
    cases = {c["case_id"]: c for c in benchmark["cases"]}
    index, rows, records, reviews = {}, [], [], []
    for before in prepared["rows"]:
        key = (before["case_id"], before["branch"])
        name = f"{key[0]}_{key[1]}"
        origin = preflight / name
        if key in original:
            row = deepcopy(original[key])
            source = LIVE / name
            origin_type = "actual_live_attempt"
        elif before["outcome"] == "abstain":
            row = deepcopy(before)
            source = origin
            origin_type = "actual_preflight_gate_abstention_no_generation"
        else:
            row = deepcopy(before)
            row.update(outcome="not_run", llm_http_attempts=0, validation_status="not_run",
                not_run_reason="operator_stop_after_http402_before_next_request",
                derived_closeout_status=True, source_preflight_result=relative(origin / "result.json"),
                source_preflight_result_sha256=p.sha256(origin / "result.json"),
                operational_stop=relative(BASE / "operational_stop.json"))
            row.pop("end_to_end_seconds", None)
            source = BASE / "closeout_states" / name
            source.mkdir(parents=True, exist_ok=False)
            for file in origin.glob("*.json"):
                if file.name != "result.json":
                    (source / file.name).write_bytes(file.read_bytes())
            p._write(source / "result.json", row)
            origin_type = "derived_not_run_closeout_not_generation_or_fake_source"
        assert all(row[k] == before[k] for k in ("context_sha256", "messages_sha256"))
        file_hashes = {f.name: p.sha256(f) for f in source.glob("*.json")}
        index[key[0] + ":" + key[1]] = {"directory": relative(source), "result_sha256":p.sha256(source / "result.json"),
            "files_sha256":file_hashes,"origin_type":origin_type}
        gate = p._read(origin / "gate.json")
        reason = ";".join(gate.get("reason_codes", []))
        attempts = [a for a in ledger["attempts"] if a["key"] == name]
        call_seconds = sum(a["finished_utc"] - a["started_utc"] for a in attempts if a.get("finished_utc")) if attempts else None
        semantic = "not_applicable_no_generated_answer"
        note = ("Provider returned HTTP402; no model answer or provider error body retained. Detailed cause not established."
                if row["outcome"] == "provider_error" else
                "Known frozen gate abstention; no LLM attempt. Assess retrieval coverage separately from model correctness."
                if row["outcome"] == "abstain" else
                "Eligible but not sent after operational stop; status derived from frozen preflight and actual task ledger.")
        records.append({"case_id":key[0],"scenario_id":row["scenario_id"],"branch":key[1],"category":cases[key[0]]["category"],
            "profile_id":"integrated-final-direct-v7","outcome":row["outcome"],"gate_decision":before["gate_decision"],
            "eligibility_decision":before["eligibility_decision"],"actual_http_attempts":row["llm_http_attempts"],
            "http_status":row.get("provider_error",{}).get("http_status"),"retry_after_seconds":row.get("provider_error",{}).get("retry_after_seconds"),
            "recorded_client_call_seconds":call_seconds,"generation_validation_seconds":row.get("generation_validation_seconds"),
            "preflight_retrieval_context_seconds":before.get("retrieval_context_seconds"),"semantic_status":semantic,
            "semantic_correct":None,"citation_semantic_correct":None,"human_approval":"pending_human_review",
            "gate_reason_codes":reason,"artifact_origin_type":origin_type,"result_artifact":relative(source / "result.json"),
            "result_sha256":p.sha256(source / "result.json"),"context_sha256":row["context_sha256"],"messages_sha256":row["messages_sha256"],
            "model_name":pin["model"]["model_name"],"base_url":pin["model"]["base_url"],"review_notes":note})
        reviews.append({"case_id":key[0],"branch":key[1],"outcome":row["outcome"],"query":cases[key[0]]["request"]["query"],
            "locked_criteria":cases[key[0]]["criteria"],"semantic_status":semantic,"review_notes":note,
            "context_references_checked":"Canonical input hashes match frozen preflight; no generated citations exist to grade.",
            "gate_reasons":gate.get("reason_codes",[]),"result_artifact":relative(source / "result.json")})
        rows.append(row)
    counts = dict(Counter(r["outcome"] for r in rows))
    assert len(rows) == 24 and sum(r["llm_http_attempts"] for r in rows) == 1
    assert counts == {"provider_error":1,"not_run":15,"abstain":8}
    p._write(BASE / "saved_results.json", {"schema_version":"final-saved-result-index/v1",
        "config_sha256":p.sha256(CONFIG),"runtime_pin_sha256":p.sha256(BASE / "runtime_pin.json"),
        "branches":index,"generated_answers":0,"source_run_partial":relative(LIVE),
        "closeout_note":"Only not_run statuses are derived; no generation/answer/history was fabricated or overwritten."})
    p._write(BASE / "results.json", {"schema_version":"final-direct-closeout/v1","profile_id":"integrated-final-direct-v7",
        "planned":24,"eligible":16,"actual_http_attempts":1,"generated_answers":0,"outcomes":counts,
        "semantic_accuracy":None,"stopped_reason":"manual_stop_after_nonretryable_http402",
        "recovery_attempts":0,"budget_limit":20,"rows":rows})
    csv_write(BASE / "results.csv", records)
    pairs = []
    for case in benchmark["cases"]:
        pair = {r["branch"]:r for r in records if r["case_id"]==case["case_id"]}
        pairs.append({"case_id":case["case_id"],"scenario_id":case["scenario_id"],"query":case["request"]["query"],
            "rag_outcome":pair["rag"]["outcome"],"graphrag_outcome":pair["graphrag"]["outcome"],
            "rag_http_attempts":pair["rag"]["actual_http_attempts"],"graphrag_http_attempts":pair["graphrag"]["actual_http_attempts"],
            "rag_client_call_seconds":pair["rag"]["recorded_client_call_seconds"],"graphrag_client_call_seconds":pair["graphrag"]["recorded_client_call_seconds"],
            "rag_preflight_retrieval_context_seconds":pair["rag"]["preflight_retrieval_context_seconds"],
            "graphrag_preflight_retrieval_context_seconds":pair["graphrag"]["preflight_retrieval_context_seconds"],
            "rag_result_artifact":pair["rag"]["result_artifact"],"graphrag_result_artifact":pair["graphrag"]["result_artifact"],
            "paired_generation_quality_comparable":False,"reason":"No generated answers in final direct study; do not compare with v5/v6."})
    csv_write(BASE / "paired_details.csv", pairs)
    p._write(BASE / "semantic_review.json", {"review_type":"AI-assisted offline review, not human approval",
        "locked_benchmark_sha256":pin["cases_sha256"],"rubric_changed":False,"generated_answers_reviewed":0,
        "raw_presanitization_reports_present":0,"rows":reviews})
    text = ["AI-assisted semantic review — không phải human approval", "",
        "Bộ cuối chưa có câu trả lời LLM: 1 request bị HTTP402, 15 eligible branches chưa gửi, 8 gate abstentions. Không có raw pre-sanitization report/citation sinh bởi model để chấm. Semantic correctness và accuracy đều N/A, không phải 0% hay 100%.", "",
        "Rubric giữ nguyên; các tiêu chí dưới đây chỉ phục vụ review, không đi vào corpus/context/prompt/runtime.", ""]
    for case in benchmark["cases"]:
        text += ["### " + case["case_id"], "", case["request"]["query"], "", "Tiêu chí khóa:", ""]
        text += ["- " + criterion for criterion in case["criteria"]]
        text += ["", "| Branch | Outcome | Review / source |", "| --- | --- | --- |"]
        for item in [r for r in reviews if r["case_id"]==case["case_id"]]:
            text.append("| " + item["branch"] + " | " + item["outcome"] + " | " + item["review_notes"] + " Gate: " + ", ".join(item["gate_reasons"]) + ". Artifact: `" + item["result_artifact"] + "` |")
        text += ["", "Fact/actor/action/timestamp/citation/negation/CTI-attribution/completion/approval và đủ-vế-câu-hỏi: **chưa chấm model, do không có generated answer**. Chỉ xác minh source/gate/input hashes; không suy accepted draft hoặc tests thành semantic correctness.", ""]
    (BASE / "semantic_review.md").write_text("\n".join(text),encoding="utf-8")
    print(json.dumps({"rows":len(rows),"pairs":len(pairs),"outcomes":counts,"actual_http_attempts":1,"generated_answers":0}))


if __name__ == "__main__": main()
