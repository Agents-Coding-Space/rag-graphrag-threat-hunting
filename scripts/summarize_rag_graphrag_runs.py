"""Offline-only aggregation of frozen runs and separately authored AI reviews.

This script never retrieves, embeds, generates or changes original run files.
Semantic ratings are external review inputs, not inferred from validation.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from copy import deepcopy
import csv
import hashlib
import json
from pathlib import Path
import statistics
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

BRANCHES = ("rag", "graphrag")
OUTCOMES = ("accepted_draft", "validation_failed", "abstain", "provider_error", "rate_limited", "fallback", "runtime_error")
REPORT_FIELDS = {"maximum_llm_requests", "harness_request_ceiling", "configured_request_budget", "warning"}


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path: Path) -> str:
    with path.open("rb") as handle: return hashlib.file_digest(handle, "sha256").hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def write(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")
    read(path)


def coverage(cases: list[dict], rows: list[dict]) -> dict:
    expected = {(c["case_id"], b) for c in cases for b in BRANCHES}
    keys = [(r["case_id"], r["branch"]) for r in rows]
    duplicates = [list(k) for k, count in Counter(keys).items() if count > 1]
    missing, unexpected = sorted(expected - set(keys)), sorted(set(keys) - expected)
    if duplicates or missing or unexpected:
        raise ValueError(f"Invalid coverage: duplicates={duplicates}, missing={missing}, unexpected={unexpected}")
    return {"expected_rows": len(expected), "actual_rows": len(rows), "duplicates": [], "missing": [], "unexpected": []}


class StripReporting(ast.NodeTransformer):
    """Permit only the already reviewed metadata patch when comparing code."""
    def visit_FunctionDef(self, node):
        return None if node.name == "run_reporting_metadata" else self.generic_visit(node)

    def visit_Assign(self, node):
        if any(isinstance(t, ast.Name) and t.id == "reporting" for t in node.targets): return None
        return self.generic_visit(node)

    def visit_Dict(self, node):
        pairs = []
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and key.value in REPORT_FIELDS: continue
            if key is None and isinstance(value, ast.DictComp):
                if not (isinstance(value.value, ast.Subscript) and isinstance(value.value.value, ast.Name)
                        and value.value.value.id == "reporting" and isinstance(value.generators[0].iter, ast.Tuple)
                        and {e.value for e in value.generators[0].iter.elts} <= REPORT_FIELDS):
                    raise ValueError("Unexpected dictionary expansion in reporting normalization")
                continue
            pairs.append((key, value))
        node.keys, node.values = [p[0] for p in pairs], [p[1] for p in pairs]
        return self.generic_visit(node)


def reporting_equivalent(before: str, after: str) -> bool:
    trees = [StripReporting().visit(deepcopy(ast.parse(text))) for text in (before, after)]
    return ast.dump(trees[0], include_attributes=False) == ast.dump(trees[1], include_attributes=False)


def compatibility(runs: list[Path], old_harness: Path) -> dict:
    manifests, configs, benchmarks = ([read(run / name) for run in runs]
        for name in ("manifest.json", "configuration.json", "cases.json"))
    fields = ("model", "cases_sha256", "config_sha256", "gate_policy_sha256", "gate_contract", "runtime_artifacts_config_sha256", "artifacts")
    checks = {key: manifests[0][key] == manifests[1][key] for key in fields}
    checks["copied_config_equal"] = configs[0] == configs[1]
    checks["copied_benchmark_and_rubric_equal"] = benchmarks[0] == benchmarks[1]
    if not all(checks.values()): raise ValueError("Run protocol/config/artifact/rubric mismatch")
    changed = [p for p, h in manifests[0]["code_sha256"].items() if manifests[1]["code_sha256"].get(p) != h]
    harness = "src/threat_hunting/evaluation/experimental_comparison.py"
    if changed != [harness]: raise ValueError("Code differences exceed reviewed reporting patch")
    if digest(old_harness) != manifests[0]["code_sha256"][harness]: raise ValueError("Old source snapshot not bound to pilot")
    if digest(ROOT / harness) != manifests[1]["code_sha256"][harness]: raise ValueError("Current harness not bound to remaining run")
    if not reporting_equivalent(old_harness.read_text(encoding="utf-8-sig"), (ROOT / harness).read_text(encoding="utf-8-sig")):
        raise ValueError("Harness changes affect more than reporting")
    for manifest in manifests:
        for fields_map in manifest["artifacts"].values():
            for item in fields_map.values():
                if digest(ROOT / item["path"]) != item["sha256"]: raise ValueError("Artifact mismatch: " + item["path"])
    for path, expected in manifests[1]["code_sha256"].items():
        if digest(ROOT / path) != expected: raise ValueError("Current source mismatch: " + path)
    return {"can_aggregate": True, "checks": checks, "changed_code_files": changed, "reporting_only_ast_verified": True,
        "normalized_caps": [{"batch": run.name, "effective_cap": m["limits"]["configured_request_budget"],
                             "legacy_displayed_cap": read(run / "results.json")["maximum_llm_requests"]}
                            for run, m in zip(runs, manifests)],
        "batch_effects": "Separate dates/order/cache state are retained. Compatibility is not independent validation or controlled latency evidence."}


def source_items(context: dict) -> list[tuple[dict, str]]:
    items = [(h["chunk"], f"/retrieval/hits/{i}/chunk") for i, h in enumerate(context["retrieval"]["hits"])]
    for key in ("nodes", "edges"):
        items += [(p, f"/traversal/{key}/{i}") for i, p in enumerate(context["traversal"].get(key, []))]
    return items


def walk(value: Any, pointer: str = ""):
    if isinstance(value, dict):
        yield value, pointer
        for key, item in value.items(): yield from walk(item, pointer + "/" + key.replace("~", "~0").replace("/", "~1"))
    elif isinstance(value, list):
        for i, item in enumerate(value): yield from walk(item, pointer + f"/{i}")


def pre_sanitize(directory: Path, validation: dict) -> tuple[dict | None, str]:
    path = directory / "raw_report_before_sanitize.json"
    if path.is_file(): return read(path), path.name
    if isinstance(validation.get("raw_report_before_sanitize"), dict):
        return validation["raw_report_before_sanitize"], "validation.json:/raw_report_before_sanitize"
    return None, "unknown_missing_pre_sanitization"


def branch_audit(directory: Path, row: dict, case: dict) -> dict:
    from threat_hunting.llm.prompt import ThreatHuntingPromptBuilder
    from threat_hunting.llm.guardrail import context_catalog, _assessments, _observations
    result = {"context_present": (directory / "context.json").is_file(), "new_generation": False}
    if not result["context_present"]:
        result["gate"] = read(directory / "scope.json")
        return result
    context, messages = read(directory / "context.json"), read(directory / "messages.json")["messages"]
    if messages != ThreatHuntingPromptBuilder().build_messages(case["request"]["query"], context):
        raise ValueError("Saved message mismatch: " + str(directory))
    if len(canonical(context)) != row["context_utf8_bytes"] or len(canonical(messages)) != row["messages_utf8_bytes"]:
        raise ValueError("Saved byte count mismatch")
    if hashlib.sha256(canonical(context)).hexdigest() != row["context_sha256"] or hashlib.sha256(canonical(messages)).hexdigest() != row["messages_sha256"]:
        raise ValueError("Saved context/messages hash mismatch")
    result.update(gate=read(directory / "gate.json"), eligibility=read(directory / "eligibility.json"),
        saved_messages_rebuilt_exactly=True, source_views=[], observation_views=[])
    for payload, location in source_items(context):
        result["source_views"].append({"context_pointer": location, "source": payload.get("source"),
            "type": payload.get("chunk_type", payload.get("node_type", payload.get("edge_type"))),
            "text": payload.get("content", payload.get("label")), "metadata": payload.get("metadata", payload.get("attributes")),
            "source_references": payload.get("source_references", [])})
        for item, path in walk(payload, location):
            for key in ("canonical_fields", "original_fields"):
                if isinstance(item.get(key), dict):
                    result["observation_views"].append({"context_pointer": path + "/" + key, "fields": item[key],
                        "source_file": item.get("source_file"), "raw_record_ref": item.get("raw_record_ref"), "source": payload.get("source")})
    if not row.get("llm_http_attempts"): return result
    validation = read(directory / "validation.json")
    raw, raw_source = pre_sanitize(directory, validation)
    result.update(pre_sanitization_source=raw_source, raw_report=raw, validation=validation)
    if raw is None: return result
    if validation.get("raw_report_before_sanitize") != raw: raise ValueError("Pre-sanitize snapshots disagree")
    text = read(directory / "raw_model_output.json")["text"]
    import re
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text.strip(), re.DOTALL)
    if json.loads(fenced[1] if fenced else text) != raw: raise ValueError("Raw text differs from pre-sanitize snapshot")
    catalog = context_catalog(context)
    result["citation_bindings"] = {ref: [{"source": p.get("source"), "item_id": p.get("chunk_id", p.get("node_id", p.get("edge_id"))),
        "raw_field_observations_readable_by_validator": list(_observations(p, ref)), "source_references": p.get("source_references", [])}
        for p in catalog.get(ref, [])] for ref in raw.get("evidence_refs", [])}
    result["validator_readable_assessments"] = _assessments(context)
    result["validation_issue_details"] = []
    for issue in validation["issues"]:
        detail = {**issue, "pre_sanitization_known": True}
        if issue["path"].startswith("mitre_mappings/"):
            index = int(issue["path"].split("/")[1])
            mapping = raw["mitre_mappings"][index]
            detail["actual_mapping"] = mapping
            detail["validator_source_assessment"] = result["validator_readable_assessments"].get(mapping["technique_id"])
        elif issue["path"].startswith("attack_chain/"):
            detail["actual_step"] = raw["attack_chain"][int(issue["path"].split("/")[1])]
            detail["cited_items_with_raw_fields"] = sum(bool(list(_observations(p, issue.get("reference") or ""))) for p in catalog.get(issue.get("reference"), []))
        result["validation_issue_details"].append(detail)
    return result


def stat(values: list[float]) -> dict:
    return {"n": len(values), "mean": statistics.mean(values) if values else None,
        "median": statistics.median(values) if values else None, "min": min(values) if values else None,
        "max": max(values) if values else None}


def fraction(numerator: int, denominator: int, basis: str) -> dict:
    return {"numerator": numerator, "denominator": denominator, "ratio": numerator / denominator if denominator else None, "basis": basis}


def summarize(rows: list[dict]) -> dict:
    output = {}
    for branch in BRANCHES:
        selected = [r for r in rows if r["branch"] == branch]
        generated = [r for r in selected if r.get("llm_http_attempts", 0) > 0]
        accepted = [r for r in selected if r["outcome"] == "accepted_draft"]
        abstained = [r for r in selected if r["outcome"] == "abstain"]
        outcomes = Counter(r["outcome"] for r in selected)
        answerable = [r for r in selected if r["expected_category"] == "answerable"]
        unrelated = [r for r in selected if r["expected_category"] == "out_of_scope"]
        output[branch] = {"planned": len(selected), "outcomes": {name: outcomes[name] for name in OUTCOMES},
            "recorded_llm_http_attempts": sum(r.get("llm_http_attempts", 0) for r in selected),
            "accepted_coverage": fraction(len(accepted), len(selected), "accepted drafts / planned branches; not semantic correctness"),
            "core_factual_pass_generated": fraction(sum(r["core_correctness"] == "pass" for r in generated), len(generated), "all generated raw drafts, including rejected; diagnostic only"),
            "core_citation_supported_generated": fraction(sum(r["citation_support"] == "supported" for r in generated), len(generated), "primary question claims / generated raw drafts; full claim caveats separate"),
            "core_factual_pass_accepted": fraction(sum(r["core_correctness"] == "pass" for r in accepted), len(accepted), "accepted drafts with AI-assisted factual review; not whole-report truth"),
            "whole_report_ai_clean_generated": fraction(sum(r["whole_report_review"] == "pass" for r in generated), len(generated), "AI-assisted review only; unresolved verdicts are not counted correct or automatically wrong"),
            "whole_report_ai_clean_accepted": fraction(sum(r["whole_report_review"] == "pass" for r in accepted), len(accepted), "accepted drafts reviewed clean under locked scope; pending human review"),
            "whole_report_needs_review_generated": sum(r["whole_report_review"] == "needs_human_review" for r in generated),
            "delivered_core_supported_coverage": fraction(sum(r["core_correctness"] == "pass" and r["citation_support"] == "supported" for r in accepted), len(selected), "rejected outputs and abstain are excluded from successful answers"),
            "false_abstain_benchmark": fraction(sum(r["outcome"] == "abstain" for r in answerable), len(answerable), "fixed answerable labels; contextual reasons distinguished below"),
            "false_proceed_unrelated": fraction(sum(r.get("gate_decision") == "proceed" for r in unrelated), len(unrelated), "out_of_scope only; overreach permits either path"),
            "abstain_review_counts": dict(Counter(r["abstain_review"] for r in abstained)),
            "generation_plus_validation_seconds": stat([r["generation_validation_seconds"] for r in generated if r.get("generation_validation_seconds") is not None]),
            "generated_end_to_end_seconds": stat([r["end_to_end_seconds"] for r in generated]),
            "abstain_end_to_end_seconds": stat([r["end_to_end_seconds"] for r in abstained]),
            "llm_call_only_seconds": {"status": "not_separately_recorded", "n": 0},
            "context_bytes_generated": stat([r["context_utf8_bytes"] for r in generated]),
            "messages_bytes_generated": stat([r["messages_utf8_bytes"] for r in generated])}
    return output


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("x", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def aggregate(runs: list[Path], annotations: Path, old_harness: Path, output: Path) -> dict:
    protocol = compatibility(runs, old_harness)
    benchmark = read(runs[0] / "cases.json")
    cases = {c["case_id"]: c for c in benchmark["cases"]}
    manual = read(annotations)
    rows, audits, source_hashes = [], {}, {}
    for run in runs:
        result = read(run / "results.json")
        if result["mode"] != "live" or result["stopped_reason"] is not None: raise ValueError("Incomplete/non-live run cannot be merged silently")
        for path in run.rglob("*"):
            if path.is_file(): source_hashes[path.relative_to(ROOT).as_posix()] = digest(path)
        for sequence, original in enumerate(result["rows"]):
            row = deepcopy(original)
            key = row["case_id"] + "_" + row["branch"]
            if key in audits: raise ValueError("Duplicate run branch: " + key)
            case = cases[row["case_id"]]
            audit = branch_audit(run / key, row, case)
            audits[key] = audit
            row.update(batch=run.name, batch_sequence=sequence, source_directory=(run / key).relative_to(ROOT).as_posix(),
                expected_category=case["category"], query=case["request"]["query"],
                **manual["branches"][key])
            rows.append(row)
    checked_coverage = coverage(list(cases.values()), rows)
    if set(manual["branches"]) != set(audits): raise ValueError("Review annotations do not cover exactly the observed branches")
    order = {cid: i for i, cid in enumerate(cases)}
    rows.sort(key=lambda r: (order[r["case_id"]], BRANCHES.index(r["branch"])))
    output.mkdir(parents=True, exist_ok=True)
    write(output / "compatibility_and_coverage.json", {**protocol, "coverage": checked_coverage})
    write(output / "source_audit.json", {"new_api_requests": 0, "generation_rerun": False, "branches": audits})
    write(output / "combined_results.json", {"aggregation_mode": "offline_saved_live_runs", "source_runs": [str(r.relative_to(ROOT)) for r in runs],
        "review_type": manual["review_type"], "human_approval": None, "rows": rows})
    summary = summarize(rows)
    write(output / "summary.json", summary)
    write(output / "validation_failures.json", {"failures": [{"branch": key, "pre_sanitization_source": audit.get("pre_sanitization_source"),
        "raw_report": audit.get("raw_report"), "issues": audit.get("validation_issue_details", []),
        "review": manual["branches"][key]} for key, audit in audits.items() if manual["branches"][key].get("failure_analysis")]})
    columns = ("case_id", "branch", "batch", "batch_sequence", "expected_category", "outcome", "gate_decision", "abstention_stage",
        "llm_http_attempts", "validation_status", "core_correctness", "completeness", "citation_support", "whole_report_review", "verdict_review",
        "over_inference_review", "abstain_review", "generation_validation_seconds", "end_to_end_seconds", "context_utf8_bytes", "messages_utf8_bytes", "source_directory")
    write_csv(output / "results.csv", [{name: r.get(name) for name in columns} for r in rows])
    pairs = []
    for cid, case in cases.items():
        pair = {r["branch"]: r for r in rows if r["case_id"] == cid}
        item = {"case_id": cid, "category": case["category"], "query": case["request"]["query"]}
        for b in BRANCHES:
            item.update({b + "_" + k: pair[b].get(k) for k in ("outcome", "core_correctness", "citation_support", "whole_report_review", "abstain_review")})
        pairs.append(item)
    write_csv(output / "case_pairs.csv", pairs)
    with (output / "case_pairs.md").open("x", encoding="utf-8", newline="\n") as handle:
        handle.write("# REPLAY/OFFLINE — so sánh 15 cặp câu hỏi\n\nAI-assisted review, pending human review; không generation mới.\n\n| Case | RAG | GraphRAG | Core RAG/GraphRAG | Whole RAG/GraphRAG |\n|---|---|---|---|---|\n")
        for p in pairs: handle.write(f"| {p['case_id']} | {p['rag_outcome']} | {p['graphrag_outcome']} | {p['rag_core_correctness']}/{p['graphrag_core_correctness']} | {p['rag_whole_report_review']}/{p['graphrag_whole_report_review']} |\n")
    if any(digest(ROOT / p) != h for p, h in source_hashes.items()): raise ValueError("Original artifact changed during review")
    write(output / "input_integrity.json", {"original_files_sha256": source_hashes, "all_unchanged": True, "runtime_modified": False,
        "new_api_requests": 0, "generation_rerun": False})
    return {"rows": len(rows), "generated": sum(bool(r.get("llm_http_attempts")) for r in rows), "metrics": summary}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, nargs=2, required=True)
    parser.add_argument("--annotations", type=Path, required=True)
    parser.add_argument("--old-harness", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = aggregate([p.resolve() for p in args.runs], args.annotations.resolve(), args.old_harness.resolve(), args.output.resolve())
    print(json.dumps({"rows": result["rows"], "generated_saved_outputs": result["generated"], "new_api_requests": 0}))
