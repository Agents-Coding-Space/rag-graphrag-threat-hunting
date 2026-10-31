"""Build an offline before/after report; annotations never enter runtime inputs."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    json.loads(path.read_text(encoding="utf-8"))


def build(before: Path, after: Path, review: Path, output: Path) -> dict:
    """Join fixed criteria, exact context views and independently authored review."""
    benchmark = read(before / "cases.json")
    old, new = read(before / "results.json"), read(after / "results.json")
    notes = read(review)
    old_rows = {(r["case_id"], r["branch"]): r for r in old["rows"]}
    new_rows = {(r["case_id"], r["branch"]): r for r in new["rows"]}
    cases, csv_rows = [], []
    md = ["# Phân tích từng ca — offline before/after", "", "Rubric review là AI technical review riêng, chưa phải human approval và không đi vào runtime.", ""]
    for case in benchmark["cases"]:
        cid = case["case_id"]
        item = {"case_id": cid, "expected_category": case["category"], "query": case["request"]["query"],
                "historical_required_facts_or_limits": case["required_facts_or_limits"],
                "rubric_note": notes["cases"][cid]["note"], "branches": {}}
        md += [f"## {cid} — {case['category']}", "", case["request"]["query"], "", "Tiêu chí lịch sử:", ""]
        md += ["- " + fact for fact in case["required_facts_or_limits"]]
        md += ["", "Đối chiếu nội dung: " + item["rubric_note"], ""]
        for branch in ("rag", "graphrag"):
            op, np = before / f"{cid}_{branch}", after / f"{cid}_{branch}"
            row_old, row_new = old_rows[cid, branch], new_rows[cid, branch]
            context = read(np / "context.json") if (np / "context.json").exists() else None
            before_gate = read(op / "gate.json") if (op / "gate.json").exists() else read(op / "scope.json")
            gate = read(np / "gate.json") if (np / "gate.json").exists() else read(np / "scope.json")
            support = gate.get("stage_results", {}).get("evidence_answerability", {})
            policy = before_gate.get("metadata", {}).get("policy", {}).get("evidence_answerability", {})
            signals = before_gate.get("stage_results", {}).get("evidence_answerability", {}).get("signals", {})
            failed_conditions = [{"setting": setting, "required": policy.get(setting), "actual": signals.get(field)}
                for setting, field in (("min_mapped_hit_count", "mapped_hit_count"), ("min_seed_node_count", "seed_node_count"), ("require_traversal", "traversal_performed"))
                if branch == "rag" and context is not None]
            chunks = [] if context is None else [{"chunk_id": h["chunk"]["chunk_id"], "type": h["chunk"]["chunk_type"],
                "source": h["chunk"]["source"], "source_references": h["chunk"]["source_references"], "content": h["chunk"]["content"]} for h in context["retrieval"]["hits"]]
            entry = {"before": row_old["gate_decision"], "after": row_new["gate_decision"],
                "before_reasons": before_gate.get("reason_codes", []), "after_reasons": gate.get("reason_codes", []),
                "original_failed_conditions": failed_conditions, "retrieved_chunks": chunks,
                "gate_source_checks": support.get("checks", []), "rubric_sufficiency": notes["cases"][cid][branch],
                "context_path": str((np / "context.json").relative_to(ROOT)) if context else None,
                "context_bytes": row_new.get("context_utf8_bytes"), "graph_nodes": row_new.get("returned_graph_nodes", 0),
                "graph_edges": row_new.get("returned_graph_edges", 0), "same_before_after_context":
                    read(op / "context.json") == context if context else None}
            item["branches"][branch] = entry
            csv_rows.append({"case_id": cid, "branch": branch, "expected_category": case["category"],
                "before": entry["before"], "after": entry["after"], "before_reasons": "|".join(entry["before_reasons"]),
                "after_reasons": "|".join(entry["after_reasons"]), "rubric_sufficiency": entry["rubric_sufficiency"]})
            md += [f"**{branch}: {entry['before']} → {entry['after']} · rubric: {entry['rubric_sufficiency']}**", "",
                   "Lý do trước: " + ", ".join(entry["before_reasons"]), "", "Lý do sau: " + (", ".join(entry["after_reasons"]) or "không chặn"), ""]
            if branch == "rag":
                md += ["Chunks retrieval (toàn bộ content/provenance trong JSON kèm theo):", ""]
                md += [f"- `{c['chunk_id']}` — {c['type']} `{c['source']['json_pointer']}`; refs: " + ", ".join(r["raw_record_ref"] for r in c["source_references"]) for c in chunks]
                if not chunks: md += ["- Không retrieval: bị scope chặn."]
                md += [""]
            for check in support.get("checks", []):
                md += [f"- {check['requirement']}: {check['status']} — {check['reason_code']}; {len(check['witnesses'])} source views."]
            md += [""]
        cases.append(item)
    payload = {"schema_version": "rag-gate-contract-audit/v1", "review_type": notes["review_type"], "runtime_uses_rubric": False,
        "benchmark_sha256": hashlib.sha256((before / "cases.json").read_bytes()).hexdigest(),
        "before_metrics": old["metrics"], "after_metrics": new["metrics"], "cases": cases,
        "all_returned_contexts_unchanged": all(b["same_before_after_context"] is not False for c in cases for b in c["branches"].values())}
    output.mkdir(parents=True, exist_ok=True)
    write(output / "per_case_review.json", payload)
    with (output / "before_after.csv").open("x", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(csv_rows[0]))
        writer.writeheader()
        writer.writerows(csv_rows)
    with (output / "per_case_report.md").open("x", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(md) + "\n")
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.before.resolve(), args.after.resolve(), args.review.resolve(), args.output.resolve())
    print(json.dumps({"cases": len(result["cases"]), "contexts_unchanged": result["all_returned_contexts_unchanged"]}))
