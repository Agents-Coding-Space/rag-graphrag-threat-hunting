"""F07: a bounded review subset must reuse the shared pipeline without opening the study budget."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "src"))

from threat_hunting.evaluation import experimental_comparison as p  # noqa: E402
from threat_hunting.evaluation import final_experiment as final  # noqa: E402

V11_CONFIG = ROOT / "configs/evaluation/integrated_final_direct_v14.json"
V11_PIN = ROOT / "outputs/final/20261101_direct_v14/runtime_pin.json"
V11_PREFLIGHT = ROOT / "outputs/final/20261101_direct_v14/preflight"


def _config():
    return p._read(V11_CONFIG)


def test_selection_parsing_is_ordered_and_deduplicated():
    pairs = final.parse_review_selection("AUTH-DIRECT:rag,PS-DIRECT:graphrag,AUTH-DIRECT:rag")
    assert pairs == [("AUTH-DIRECT", "rag"), ("PS-DIRECT", "graphrag")]


@pytest.mark.parametrize("bad", ["", "AUTH-DIRECT", "AUTH-DIRECT:vector",
                                 "A:R,B:R,C:R,D:R,E:R,F:R,G:R"])
def test_selection_rejects_invalid_input(bad):
    with pytest.raises(ValueError):
        final.parse_review_selection(bad)


def test_review_budget_is_strictly_below_the_study_budget():
    config = _config()
    pairs = final.parse_review_selection("AUTH-DIRECT:rag,PS-DIRECT:graphrag,NET-CORRELATE:rag")
    policy = final.review_policy(config, pairs)
    assert policy["total_attempt_limit"] <= final.REVIEW_MAX_ATTEMPTS
    assert policy["total_attempt_limit"] <= len(pairs)
    assert policy["recovery_attempt_limit"] == 0
    assert policy["total_attempt_limit"] < config["final_run_policy"]["total_attempt_limit"]
    # A distinct ledger: a subset can never consume or reset the study ledger.
    assert policy["task_ledger"] != config["final_run_policy"]["task_ledger"]
    assert policy["task_ledger"].endswith("review_request_budget.json")


def test_review_pacing_cannot_drop_below_the_frozen_policy():
    config = _config()
    pairs = final.parse_review_selection("AUTH-DIRECT:rag")
    frozen = config["final_run_policy"]["request_interval_seconds"]
    assert final.review_policy(config, pairs, interval=1)["request_interval_seconds"] == frozen
    assert final.review_policy(config, pairs, interval=120)["request_interval_seconds"] == 120


def test_review_attempt_ceiling_cannot_be_raised():
    config = _config()
    pairs = final.parse_review_selection("AUTH-DIRECT:rag,PS-DIRECT:graphrag")
    assert final.review_policy(config, pairs, max_attempts=99)["total_attempt_limit"] == 2


def test_selection_must_come_from_the_frozen_preflight():
    prepared = p._read(V11_PREFLIGHT / "results.json")
    chosen = final.select_review_branches(prepared, [("AUTH-DIRECT", "rag")])
    assert len(chosen) == 1 and chosen[0]["case_id"] == "AUTH-DIRECT"
    with pytest.raises(ValueError, match="not part of the frozen preflight"):
        final.select_review_branches(prepared, [("NOPE-CASE", "rag")])


def test_review_run_marks_itself_as_a_subset(tmp_path):
    """A subset run must be labelled, zero-request in dry-run mode, and never claim the study."""
    output = ROOT / "outputs/experiments/review-subset-selftest"
    if output.exists():
        pytest.skip("review-subset-selftest already exists; remove it to rerun")
    try:
        result = final.run_final(V11_CONFIG, V11_PIN, V11_PREFLIGHT, output,
                                 review_selection="AUTH-DIRECT:rag,PS-DIRECT:graphrag")
        manifest = p._read(output / "manifest.json")
        assert result["execution_scope"] == "review_subset"
        assert manifest["execution_scope"] == "review_subset"
        assert manifest["review_declaration"]["declared_before_run"] is True
        assert manifest["review_declaration"]["selection"] == ["AUTH-DIRECT:rag", "PS-DIRECT:graphrag"]
        assert result["llm_http_attempts"] == 0
        assert result["planned_branch_count"] == 2
        assert all(r["outcome"] in {"dry_run_no_generation", "abstain"} for r in result["rows"])
    finally:
        import shutil
        shutil.rmtree(output, ignore_errors=True)


def test_review_subset_cannot_reuse_a_delta_pin_or_resume(tmp_path):
    with pytest.raises(ValueError, match="independent run"):
        final.run_final(V11_CONFIG, V11_PIN, V11_PREFLIGHT, tmp_path / "x",
                        review_selection="AUTH-DIRECT:rag", continue_task=True)
