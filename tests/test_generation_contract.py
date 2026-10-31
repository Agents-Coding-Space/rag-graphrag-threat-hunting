"""Actual-artifact regressions for source meaning; no provider calls."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from threat_hunting.evaluation import experimental_comparison as pipeline
from threat_hunting.llm import generation_contract as meaning

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / "outputs/experiments/integrated-12x2-live-v5"
RECOVERY = ROOT / "outputs/experiments/integrated-12x2-v5-provider-recovery-01"


def load(root, key, name):
    return pipeline._read(root / key / (name + ".json"))


def checked(report, context):
    return meaning.validate_meaning(pipeline.validate_generated(report, context), report, context)


def test_sigma_namespace_correct_uuid_passes_old_wrong_ids_stay_rejected():
    key = "NET-CORRELATE_graphrag"
    context = load(RECOVERY, key, "context")
    raw = load(RECOVERY, key, "raw_report_before_sanitize")
    annotated = meaning.annotate_context(context)
    assert pipeline.validate_generated(raw, annotated)["status"] == "validation_failed"
    assert "unverified_sigma_match" in [x["code"] for x in checked(raw, annotated)["issues"]]
    allowed = meaning.project_meaning(annotated)["sigma_rule_identifiers"]
    fixed = deepcopy(raw)
    # Explicit lookup using source finding IDs: a diagnostic counterfactual only.
    fixed["sigma_matches"] = [next(x["rule_id"] for x in allowed if finding in x["finding_ids"])
                              for finding in raw["sigma_matches"]]
    assert all(not x.startswith("sigma-") for x in fixed["sigma_matches"])
    result = checked(fixed, annotated)
    assert result["status"] == "passed", result["issues"]
    assert meaning.check_narrative(fixed, annotated)["remaining_prose"].startswith("unverified")


def test_auth_clock_spans_and_pairing_kept_without_modifying_sources():
    context = load(ORIGINAL, "AUTH-CORRELATE_graphrag", "context")
    annotated = meaning.annotate_context(context)
    projection = meaning.project_meaning(annotated)
    annotated.pop("generation_evidence_contract")
    assert annotated == context
    clocks = projection["timestamp_semantics"]
    by_id = {g["event_id"]: g for g in clocks["source_clock_groups"]}
    assert by_id["4625"]["selected_observation_count"] == by_id["4776"]["selected_observation_count"] == 7
    assert by_id["4625"]["canonical_span_seconds"] == 0.012
    assert len(clocks["inferred_attempt_anchors"]) == 7
    assert all(x["status"] == "inferred" and x["limitations"] for x in clocks["inferred_attempt_anchors"])
    assert clocks["inferred_anchor_window"]["canonical_span_seconds"] == 0.012
    assert all("EventTime" in r["raw_clock_fields"] and "@timestamp" in r["raw_clock_fields"]
               for g in clocks["source_clock_groups"] for r in g["clock_observations"])
    assert "real attack/activity duration" in clocks["does_not_establish"]
    assert "cross-source clock synchronization" in clocks["does_not_establish"]
    messages = meaning.build_messages("General authentication investigation", meaning.annotate_context(context))
    assert "not real attack/activity duration" in messages[0]["content"]
    assert "14" in messages[1]["content"]


def test_creation_command_and_completion_are_distinct_and_prose_binding_is_bounded():
    raw = load(RECOVERY, "PS-LIMIT_graphrag", "raw_report_before_sanitize")
    context = meaning.annotate_context(load(RECOVERY, "PS-LIMIT_graphrag", "context"))
    rows = meaning.project_meaning(context)["process_creation_bindings"]
    assert {r["raw_record_ref"] for r in rows} == {"jsonl:line:4", "jsonl:line:275"}
    assert all(r["created_process"].lower().endswith("mshta.exe") for r in rows)
    assert all("powershell" in r["observed_command_line"] for r in rows)
    # The old validator does not check this prose. New version rejects only the bound explicit claim.
    assert pipeline.validate_generated(raw, context)["status"] == "passed"
    new = checked(raw, context)
    assert new["status"] == "validation_failed"
    assert any(i["code"] == "unsupported_narrative_creation_binding" for i in new["issues"])
    fixed = deepcopy(raw)
    fixed["technical_analysis"] = "cmd.exe tạo mshta.exe [jsonl:line:4, jsonl:line:275]. Command chứa lời gọi PowerShell; không chứng minh completion/output/service state."
    assert checked(fixed, context)["status"] == "passed"


def test_structured_creation_ref_must_witness_the_child_not_command_text():
    context = meaning.annotate_context(load(ORIGINAL, "PS-CORRELATE_graphrag", "context"))
    raw = {"verdict": "INSUFFICIENT_EVIDENCE", "executive_summary": "", "technical_analysis": "",
           "attack_chain": [{"step_number": 1, "source_entity": "mshta.exe", "target_entity": "powershell.exe",
                             "action": "process_spawn", "evidence_ref": "jsonl:line:275"}]}
    assert checked(raw, context)["status"] == "validation_failed"
    raw["attack_chain"][0]["evidence_ref"] = "jsonl:line:398"
    assert checked(raw, context)["status"] == "passed"
    for ref in ("jsonl:line:4", "jsonl:line:275"):
        raw["technical_analysis"] = f"mshta.exe khởi chạy powershell.exe [{ref}]."
        assert checked(raw, context)["status"] == "validation_failed"
    raw["technical_analysis"] = "mshta.exe khởi chạy powershell.exe [jsonl:line:30, jsonl:line:398]."
    assert checked(raw, context)["status"] == "passed"
    raw["technical_analysis"] = "Không chứng minh mshta.exe khởi chạy powershell.exe từ jsonl:line:275."
    assert checked(raw, context)["status"] == "passed"


def test_narrative_without_inline_refs_does_not_claim_verified():
    context = meaning.annotate_context(load(RECOVERY, "PS-LIMIT_graphrag", "context"))
    audit = meaning.check_narrative({"direct_answer": "mshta.exe khởi chạy powershell.exe."}, context)
    assert audit["issues"] == []
    assert audit["checks"][0]["status"] == "unverified_no_inline_binding"
    assert "unverified" in audit["remaining_prose"]


def test_shared_generator_applies_new_binding_check_only_with_version_marker():
    raw = load(RECOVERY, "PS-LIMIT_graphrag", "raw_report_before_sanitize")
    context = load(RECOVERY, "PS-LIMIT_graphrag", "context")
    class Provider:
        last_attempt_count = 1
        def __init__(self, **kwargs): pass
        def generate(self, messages): return json.dumps(raw, ensure_ascii=False)
    from threat_hunting.llm.config import LLMConfig
    config = LLMConfig(model_name="fixture")
    original, _ = pipeline.generate_branch([], context, config, Provider, lambda *a: None)
    new, _ = pipeline.generate_branch([], meaning.annotate_context(context), config, Provider, lambda *a: None)
    assert original["outcome"] == "accepted_draft"
    assert new["outcome"] == "validation_failed"
