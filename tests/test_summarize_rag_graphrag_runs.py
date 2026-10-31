"""Small offline aggregation fixtures; no models, retrieval or provider calls."""
import json

import pytest

from scripts.summarize_rag_graphrag_runs import coverage, pre_sanitize, reporting_equivalent, summarize


def test_coverage_rejects_duplicates_and_missing_branches():
    cases = [{"case_id": "A"}, {"case_id": "B"}]
    rows = [{"case_id": c["case_id"], "branch": b} for c in cases for b in ("rag", "graphrag")]
    assert coverage(cases, rows)["actual_rows"] == 4
    with pytest.raises(ValueError, match="duplicates"):
        coverage(cases, rows + [rows[0]])
    with pytest.raises(ValueError, match="missing"):
        coverage(cases, rows[:-1])


def test_rejected_raw_correctness_does_not_become_success_and_abstain_time_is_separate():
    def row(cid, branch, outcome, generated, seconds, whole="needs_human_review"):
        return {"case_id": cid, "branch": branch, "outcome": outcome, "expected_category": "answerable",
                "llm_http_attempts": int(generated), "core_correctness": "pass" if generated else "not_generated",
                "citation_support": "supported" if generated else "not_applicable", "whole_report_review": whole,
                "gate_decision": "proceed" if generated else "abstain", "abstain_review": "context_missing",
                "generation_validation_seconds": seconds if generated else None, "end_to_end_seconds": seconds,
                "context_utf8_bytes": 100, "messages_utf8_bytes": 200}
    rows = [row("A", "rag", "accepted_draft", True, 2), row("B", "rag", "validation_failed", True, 3),
            row("A", "graphrag", "accepted_draft", True, 5, "pass"), row("B", "graphrag", "abstain", False, .1, "not_generated")]
    result = summarize(rows)
    assert result["rag"]["core_factual_pass_generated"]["numerator"] == 2
    assert result["rag"]["core_factual_pass_generated"]["denominator"] == 2
    assert result["rag"]["accepted_coverage"]["numerator"] == 1
    assert result["rag"]["delivered_core_supported_coverage"]["numerator"] == 1
    assert result["rag"]["outcomes"]["validation_failed"] == 1
    assert result["graphrag"]["generation_plus_validation_seconds"]["mean"] == 5
    assert result["graphrag"]["generation_plus_validation_seconds"]["n"] == 1
    assert result["graphrag"]["abstain_end_to_end_seconds"]["mean"] == .1
    assert result["graphrag"]["llm_call_only_seconds"]["status"] == "not_separately_recorded"


def test_missing_pre_sanitize_stays_unknown_instead_of_using_sanitized_report(tmp_path):
    raw, origin = pre_sanitize(tmp_path, {"sanitized_report": {"verdict": "INSUFFICIENT_EVIDENCE"}})
    assert raw is None
    assert origin == "unknown_missing_pre_sanitization"
    (tmp_path / "raw_report_before_sanitize.json").write_text(json.dumps({"confidence": "candidate"}), encoding="utf-8")
    raw, origin = pre_sanitize(tmp_path, {})
    assert raw == {"confidence": "candidate"}
    assert origin == "raw_report_before_sanitize.json"


def test_ast_report_normalization_does_not_hide_generation_changes():
    before = 'def run():\n    generate(messages)\n    summary = {"maximum_llm_requests": 30, "warning": "Offline", "result": result}\n'
    after = 'def run():\n    generate(messages)\n    summary = {"maximum_llm_requests": reporting["maximum_llm_requests"], "warning": reporting["warning"], "result": result}\n'
    assert reporting_equivalent(before, after)
    assert not reporting_equivalent(before, after.replace("generate(messages)", "generate(other_messages)"))
