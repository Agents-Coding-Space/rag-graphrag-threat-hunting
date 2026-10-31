"""Independent replay and signal separability from compact calibration artifacts."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from threat_hunting.evaluation import (
    RelevanceDiagnosticsError, analyze_relevance_separability,
    generate_policy_candidates, validate_calibration_report,
)
from threat_hunting.evaluation import relevance_calibration as calibration


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/evaluation/diagnostics"
DATASET_PATH = FIXTURES / "dataset.json"
REPORT_PATH = FIXTURES / "calibration_report.json"
COUNTS = (
    "retrieval_hit_count", "lexical_hit_count", "vector_hit_count",
    "joint_lexical_vector_hit_count", "hit_mapping_count", "mapped_hit_count",
    "seed_node_count", "traversal_node_count", "traversal_edge_count", "traversal_path_count",
)


def diagnostic_inputs():
    return tuple(json.loads(path.read_text(encoding="utf-8")) for path in (DATASET_PATH, REPORT_PATH))


def analyze(dataset, report, **changes):
    options = {
        "dataset_path": DATASET_PATH.relative_to(ROOT).as_posix(),
        "dataset_sha256": sha256(DATASET_PATH.read_bytes()).hexdigest(),
        "report_path": REPORT_PATH.relative_to(ROOT).as_posix(),
        "report_sha256": sha256(REPORT_PATH.read_bytes()).hexdigest(),
    }
    options.update(changes)
    return analyze_relevance_separability(dataset, report, **options)


def refresh_aggregates(report):
    """Keep old report internally valid even when outcomes cannot be replayed."""
    result = report["calibration"]
    candidates = []
    for candidate in result["candidate_results"]:
        policy = candidate["policy"]
        records = []
        for case in result["cases"]:
            outcome = next(item for item in case["policy_results"] if item["policy_id"] == policy["policy_id"])
            records.append({**case, "actual_decision": outcome["actual_decision"]})
        candidates.append(calibration._candidate_result(policy, records, result["selection_constraints"]))
    result["candidate_results"] = candidates
    chosen = calibration._select(candidates)
    result["selection_status"] = "selected" if chosen else "no_eligible_policy"
    result["selected_policy"] = chosen["policy"] if chosen else None
    result["selected_policy_metrics"] = chosen["metrics"] if chosen else None
    for case in result["cases"]:
        outcome = next((item for item in case["policy_results"] if chosen and item["policy_id"] == chosen["policy"]["policy_id"]), None)
        case["actual_decision"] = outcome["actual_decision"] if outcome else None
        case["reason_codes"] = deepcopy(outcome["reason_codes"]) if outcome else []
    warnings = {warning for case in result["cases"] for warning in case["warnings"]}
    if not chosen:
        warnings.add(calibration.NO_ELIGIBLE_WARNING)
    result["warnings"] = sorted(warnings)
    validate_calibration_report(report)


def fixture_outcome(signals, policy):
    """Construct small fixture outcomes independently from diagnostics code."""
    reasons = []
    for setting, observed, reason in (
        ("min_hits", "retrieval_hit_count", "insufficient_hits"),
        ("min_mapped_hits", "mapped_hit_count", "insufficient_mapped_hits"),
        ("min_seed_nodes", "seed_node_count", "insufficient_seeds"),
        ("min_traversal_nodes", "traversal_node_count", "insufficient_traversal_nodes"),
    ):
        if signals[observed] < policy[setting]:
            reasons.append(reason)
    for setting, observed, reason in (
        ("require_traversal", "traversal_performed", "traversal_required"),
        ("require_lexical_support", "lexical_hit_count", "missing_lexical_support"),
        ("require_joint_lexical_vector_support", "joint_lexical_vector_hit_count", "missing_joint_lexical_vector_support"),
    ):
        if policy[setting] and not signals[observed]:
            reasons.append(reason)
    minimum = policy["min_cosine_score"]
    if minimum is not None and (signals["top_cosine_score"] is None or signals["top_cosine_score"] < minimum):
        reasons.append("vector_score_below_threshold")
    return {"policy_id": policy["policy_id"], "actual_decision": "abstain" if reasons else "proceed", "reason_codes": sorted(reasons)}


def replay_fixture_report(report):
    for case in report["calibration"]["cases"]:
        case["policy_results"] = [fixture_outcome(case["signals"], item["policy"]) for item in report["calibration"]["candidate_results"]]
    refresh_aggregates(report)


def change_search(report, **entries):
    report["candidate_search_space"].update(entries)
    policies = generate_policy_candidates(report["candidate_search_space"], max_candidate_policies=100)
    result = report["calibration"]
    result["candidate_count"] = len(policies)
    result["candidate_results"] = [calibration._candidate_result(policy, [], result["selection_constraints"]) for policy in policies]
    replay_fixture_report(report)


def refresh_dataset_counts(dataset):
    dataset["metadata"]["case_count"] = len(dataset["cases"])
    for field, key in (("category", "category_counts"), ("language", "language_counts"), ("expected_decision", "decision_counts")):
        for group in dataset["metadata"][key]:
            dataset["metadata"][key][group] = sum(case[field] == group for case in dataset["cases"])


@pytest.fixture
def inputs():
    return diagnostic_inputs()


def test_complete_canonical_case_snapshot_and_honest_audit_metadata(inputs):
    output = analyze(*inputs)
    assert output["schema_version"] == "graphrag-relevance-diagnostics/v1"
    assert output["audit"]["signal_snapshot_scope"] == "per_case"
    assert output["audit"]["signal_snapshot_source"] == "calibration_report.case.signals"
    assert output["audit"]["historical_invariance_assurance"] == "validated_by_upstream_calibration_engine"
    assert output["audit"]["diagnostic_verification"] == "policy_outcome_replay_from_canonical_case_signals"
    assert len(output["cases"]) == 8
    assert output["metadata"]["replayed_outcome_count"] == 8 * 8
    for case in output["cases"]:
        source = next(item for item in inputs[1]["calibration"]["cases"] if item["case_id"] == case["case_id"])
        assert case["signals"] == source["signals"]
        assert "policy_results" not in case
    assert all(set(outcome) == {"policy_id", "actual_decision", "reason_codes"}
               for case in inputs[1]["calibration"]["cases"] for outcome in case["policy_results"])


@pytest.mark.parametrize("field", (*COUNTS, "top_cosine_score", "traversal_performed"))
def test_canonical_snapshot_missing_signal_fails_closed(inputs, field):
    del inputs[1]["calibration"]["cases"][0]["signals"][field]
    with pytest.raises(RelevanceDiagnosticsError):
        analyze(*inputs)


@pytest.mark.parametrize("field", COUNTS)
@pytest.mark.parametrize("value", [True, -1, 1.5, "1", None])
def test_canonical_counts_reject_boolean_negative_and_wrong_types(inputs, field, value):
    inputs[1]["calibration"]["cases"][0]["signals"][field] = value
    with pytest.raises(RelevanceDiagnosticsError):
        analyze(*inputs)


@pytest.mark.parametrize("value", [True, "0.5", float("nan"), float("inf"), float("-inf"), -1.01, 1.01])
def test_canonical_cosine_rejects_wrong_type_nonfinite_and_range(inputs, value):
    inputs[1]["calibration"]["cases"][0]["signals"]["top_cosine_score"] = value
    with pytest.raises(RelevanceDiagnosticsError):
        analyze(*inputs)


@pytest.mark.parametrize("value", [0, 1, "true", None])
def test_traversal_availability_is_strict_boolean(inputs, value):
    inputs[1]["calibration"]["cases"][0]["signals"]["traversal_performed"] = value
    with pytest.raises(RelevanceDiagnosticsError):
        analyze(*inputs)


def test_aggregate_valid_report_with_unreproducible_decision_fails_closed(inputs):
    report = inputs[1]
    outcome = next(item for item in report["calibration"]["cases"][0]["policy_results"] if item["actual_decision"] == "proceed")
    outcome["actual_decision"] = "abstain"
    outcome["reason_codes"] = ["insufficient_hits"]
    refresh_aggregates(report)
    with pytest.raises(RelevanceDiagnosticsError, match="replay|decision|outcome"):
        analyze(*inputs)


@pytest.mark.parametrize("operation", ["missing", "extra", "wrong", "unordered"])
def test_aggregate_valid_report_reason_codes_must_match_canonical_replay(inputs, operation):
    report = inputs[1]
    outcome = next(item for case in report["calibration"]["cases"] for item in case["policy_results"] if len(item["reason_codes"]) >= 2)
    if operation == "missing":
        outcome["reason_codes"].pop()
    elif operation == "extra":
        outcome["reason_codes"] = sorted(set(outcome["reason_codes"]) | {"traversal_required"})
    elif operation == "wrong":
        outcome["reason_codes"] = ["insufficient_seeds"]
    else:
        outcome["reason_codes"].reverse()
    refresh_aggregates(report)
    with pytest.raises(RelevanceDiagnosticsError, match="replay|reason|outcome"):
        analyze(*inputs)


@pytest.mark.parametrize("operation", ["missing", "duplicate", "unknown", "per_outcome_signals"])
def test_exactly_one_compact_outcome_per_known_policy(inputs, operation):
    case = inputs[1]["calibration"]["cases"][0]
    if operation == "missing":
        case["policy_results"].pop()
    elif operation == "duplicate":
        case["policy_results"][1] = deepcopy(case["policy_results"][0])
    elif operation == "unknown":
        case["policy_results"][0]["policy_id"] = "unknown-policy"
    else:
        case["policy_results"][0]["signals"] = deepcopy(case["signals"])
    with pytest.raises(RelevanceDiagnosticsError):
        analyze(*inputs)


@pytest.mark.parametrize("field,value", [("category", "relevant_paraphrase"), ("language", "vi"), ("expected_decision", "abstain")])
def test_dataset_report_case_labels_must_match(inputs, field, value):
    dataset, report = inputs
    case = next(item for item in dataset["cases"] if item["case_id"] == "direct-en")
    case[field] = value
    refresh_dataset_counts(dataset)
    with pytest.raises(RelevanceDiagnosticsError):
        analyze(dataset, report)


@pytest.mark.parametrize("operation", ["missing", "extra", "duplicate", "scenario", "dataset_id"])
def test_dataset_report_identity_mismatch_fails_closed(inputs, operation):
    dataset, report = inputs
    if operation == "missing":
        dataset["cases"].pop()
    elif operation == "extra":
        extra = deepcopy(dataset["cases"][0])
        extra["case_id"] = "extra-case"
        dataset["cases"].append(extra)
    elif operation == "duplicate":
        dataset["cases"][1] = deepcopy(dataset["cases"][0])
    else:
        dataset[operation if operation == "dataset_id" else "scenario_id"] = "different"
    refresh_dataset_counts(dataset)
    with pytest.raises(RelevanceDiagnosticsError):
        analyze(dataset, report)


@pytest.mark.parametrize("field", ["dataset_sha256", "report_sha256"])
@pytest.mark.parametrize("value", ["", "1" * 63, "g" * 64, True])
def test_input_provenance_requires_full_sha256(inputs, field, value):
    with pytest.raises(RelevanceDiagnosticsError):
        analyze(*inputs, **{field: value})


@pytest.mark.parametrize("field", ["dataset_path", "report_path"])
@pytest.mark.parametrize("value", [None, True, "", "   "])
def test_input_artifact_paths_require_nonempty_text(inputs, field, value):
    with pytest.raises(RelevanceDiagnosticsError):
        analyze(*inputs, **{field: value})


def test_dataset_hash_matches_calibration_provenance(inputs):
    with pytest.raises(RelevanceDiagnosticsError):
        analyze(*inputs, dataset_sha256="0" * 64)


def test_deterministic_output_detached_and_all_inputs_immutable(inputs):
    before = deepcopy(inputs)
    output = analyze(*inputs)
    again = analyze(*inputs)
    serialize = lambda value: json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    assert serialize(output) == serialize(again)
    assert output["analysis_id"] == again["analysis_id"]
    output["cases"][0]["signals"]["retrieval_hit_count"] = 999
    output["policies"][0]["min_hits"] = 999
    output["provenance"]["dataset"]["sha256"] = "0" * 64
    assert inputs == before


def test_diagnostics_do_not_call_models_retrievers_or_live_gate(inputs, monkeypatch):
    import threat_hunting.graphrag.relevance as gate
    from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend
    def forbidden(*args, **kwargs):
        pytest.fail("diagnostics must operate on canonical artifacts without model or live context")
    monkeypatch.setattr(gate, "assess_graphrag_relevance", forbidden)
    monkeypatch.setattr(calibration, "assess_graphrag_relevance", forbidden)
    monkeypatch.setattr(SentenceTransformerEmbeddingBackend, "__init__", forbidden)
    assert analyze(*inputs)["metadata"]["replayed_outcome_count"] == 64


def test_engine_is_in_memory_without_file_or_network_access(inputs, monkeypatch):
    import builtins
    import socket
    options = {"dataset_path": DATASET_PATH.as_posix(), "dataset_sha256": sha256(DATASET_PATH.read_bytes()).hexdigest(),
               "report_path": REPORT_PATH.as_posix(), "report_sha256": sha256(REPORT_PATH.read_bytes()).hexdigest()}
    def forbidden(*args, **kwargs):
        pytest.fail("diagnostic engine must not access files or network")
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert analyze_relevance_separability(*inputs, **options)["metadata"]["case_count"] == 8


def test_statistics_correct_mean_median_null_counts_and_boolean_rates(inputs):
    output = analyze(*inputs)
    stats = output["analysis"]["statistics"]
    values = stats["by_expected_decision"]["proceed"]
    assert values["retrieval_hit_count"] == {"count": 4, "null_count": 0, "minimum": 5, "maximum": 5, "mean": 5, "median": 5}
    assert values["top_cosine_score"]["mean"] == 0.4125
    assert values["top_cosine_score"]["median"] == 0.425
    assert values["lexical_support"] == {"count": 4, "true_count": 3, "false_count": 1, "true_rate": 0.75}
    assert stats["by_expected_decision"]["abstain"]["top_cosine_score"]["count"] == 3
    assert stats["by_expected_decision"]["abstain"]["top_cosine_score"]["null_count"] == 1
    assert stats["by_language"]["en"]["lexical_support"]["true_rate"] == 0.75
    assert stats["by_language"]["vi"]["lexical_support"]["true_rate"] == 0.5
    assert set(stats["by_category"]) == {case["category"] for case in inputs[0]["cases"]}


def test_single_label_dataset_retains_empty_other_decision_statistics(inputs):
    dataset, report = inputs
    dataset["cases"] = [next(case for case in dataset["cases"] if case["case_id"] == "direct-en")]
    refresh_dataset_counts(dataset)
    report["calibration"]["cases"] = [next(case for case in report["calibration"]["cases"] if case["case_id"] == "direct-en")]
    report["calibration"]["case_count"] = 1
    report["execution"]["graphrag_context_count"] = 1
    refresh_aggregates(report)
    output = analyze(dataset, report)
    analysis = output["analysis"]
    assert analysis["distributions"]["expected_decision"] == {"proceed": 1, "abstain": 0}
    empty = analysis["statistics"]["by_expected_decision"]["abstain"]
    assert empty["retrieval_hit_count"] == {"count": 0, "null_count": 0, "minimum": None, "maximum": None, "mean": None, "median": None}
    assert empty["top_cosine_score"] == {"count": 0, "null_count": 0, "minimum": None, "maximum": None, "mean": None, "median": None}
    assert empty["lexical_support"] == {"count": 0, "true_count": 0, "false_count": 0, "true_rate": 0.0}
    assert all(item["abstain_range"] == {"count": 0, "null_count": 0, "minimum": None, "maximum": None}
               and item["overlap"] is False for item in analysis["numeric_ranges"])
    assert analysis["collisions"] == []
    assert analysis["dominance"]["conflicts"] == []


def test_numeric_ranges_overlap_and_cross_label_policy_visible_collision(inputs):
    output = analyze(*inputs)
    ranges = {item["signal"]: item for item in output["analysis"]["numeric_ranges"]}
    assert ranges["retrieval_hit_count"]["overlap"] is True
    assert ranges["top_cosine_score"]["overlap"] is True
    collisions = output["analysis"]["collisions"]
    assert any({"direct-en", "insufficient-en"} <= set(item["case_ids"]) for item in collisions)
    assert all(item["proceed_case_ids"] and item["abstain_case_ids"] for item in collisions)


def test_boolean_overlap_explicitly_covers_every_boolean_signal(inputs):
    output = analyze(*inputs)
    records = {item["signal"]: item for item in output["analysis"]["boolean_overlap"]}
    assert set(records) == {"traversal_performed", "lexical_support", "joint_lexical_vector_support"}
    assert records["lexical_support"]["shared_values"] == [False, True]
    assert records["lexical_support"]["proceed_range"] == {
        "count": 4, "true_count": 3, "false_count": 1, "minimum": False, "maximum": True,
    }
    assert records["traversal_performed"]["shared_values"] == [True]
    assert all(item["overlap"] is True for item in records.values())


def test_boolean_support_strength_and_null_cosine_follow_gate_semantics(inputs):
    output = analyze(*inputs)
    dominance = output["analysis"]["dominance"]
    assert "lexical_support" in dominance["compared_signals"]
    assert "joint_lexical_vector_support" in dominance["compared_signals"]
    assert "lexical_hit_count" not in dominance["compared_signals"]
    assert "traversal_edge_count" not in dominance["compared_signals"]
    pairs = {(item["proceed_case_id"], item["abstain_case_id"]): item for item in dominance["conflicts"]}
    conflict = pairs[("direct-vi", "insufficient-vi")]
    assert "top_cosine_score" in conflict["strictly_stronger_signals"]
    assert ("direct-en", "insufficient-en") not in pairs
    assert not any(abstain == "unrelated-vi" for _, abstain in pairs)
    assert sum(item["count"] for item in dominance["by_category"]) == len(dominance["conflicts"])
    assert sum(item["count"] for item in dominance["by_language"]) == len(dominance["conflicts"])


def test_positive_lexical_counts_are_boolean_for_profile_and_dominance(inputs):
    case = next(item for item in inputs[1]["calibration"]["cases"] if item["case_id"] == "insufficient-en")
    case["signals"]["lexical_hit_count"] = 1
    case["signals"]["joint_lexical_vector_hit_count"] = 1
    case["signals"]["traversal_edge_count"] = 999
    case["signals"]["traversal_path_count"] = 999
    replay_fixture_report(inputs[1])
    output = analyze(*inputs)
    assert any({"direct-en", "insufficient-en"} <= set(item["case_ids"])
               for item in output["analysis"]["collisions"])
    assert not any(item["proceed_case_id"] == "direct-en" and item["abstain_case_id"] == "insufficient-en"
                   for item in output["analysis"]["dominance"]["conflicts"])


@pytest.mark.parametrize("proceed_cosine,abstain_cosine", [(0, 0.0), (0.0, -0.0), (1, 1.0)])
def test_equal_numeric_cosine_representations_collide(inputs, proceed_cosine, abstain_cosine):
    for case in inputs[1]["calibration"]["cases"]:
        if case["case_id"] == "direct-en":
            case["signals"]["top_cosine_score"] = proceed_cosine
        elif case["case_id"] == "insufficient-en":
            case["signals"]["top_cosine_score"] = abstain_cosine
    replay_fixture_report(inputs[1])
    output = analyze(*inputs)
    assert any({"direct-en", "insufficient-en"} <= set(item["case_ids"])
               for item in output["analysis"]["collisions"])


def test_finite_abstain_cosine_dominates_null_proceed_cosine(inputs):
    proceed = next(case for case in inputs[1]["calibration"]["cases"] if case["case_id"] == "direct-vi")
    proceed["signals"].update(top_cosine_score=None, vector_hit_count=0, joint_lexical_vector_hit_count=0)
    replay_fixture_report(inputs[1])
    output = analyze(*inputs)
    pairs = {(item["proceed_case_id"], item["abstain_case_id"]): item for item in output["analysis"]["dominance"]["conflicts"]}
    assert "top_cosine_score" in pairs[("direct-vi", "insufficient-vi")]["strictly_stronger_signals"]
    assert ("direct-en", "unrelated-vi") not in pairs


@pytest.mark.parametrize("signal", ["retrieval_hit_count", "mapped_hit_count", "seed_node_count", "traversal_node_count"])
def test_stronger_policy_visible_count_alone_produces_dominance(inputs, signal):
    abstain = next(case for case in inputs[1]["calibration"]["cases"] if case["case_id"] == "insufficient-en")
    abstain["signals"][signal] += 1
    if signal == "mapped_hit_count":
        abstain["signals"]["hit_mapping_count"] += 1
        abstain["signals"]["retrieval_hit_count"] += 1
    replay_fixture_report(inputs[1])
    output = analyze(*inputs)
    conflict = next(item for item in output["analysis"]["dominance"]["conflicts"]
                    if item["proceed_case_id"] == "direct-en" and item["abstain_case_id"] == "insufficient-en")
    assert signal in conflict["strictly_stronger_signals"]


@pytest.mark.parametrize("setting,values", [
    ("min_hits", [5, 6]), ("min_mapped_hits", [5, 6]), ("min_seed_nodes", [4, 5]),
    ("min_traversal_nodes", [10, 11]), ("require_traversal", [False, True]),
    ("require_lexical_support", [False, True]),
    ("require_joint_lexical_vector_support", [False, True]),
    ("min_cosine_score", [None, -1, 0.35, 1]),
])
def test_replay_handles_every_lower_bound_boolean_and_cosine_condition(inputs, setting, values):
    change_search(inputs[1], **{setting: values})
    output = analyze(*inputs)
    assert output["metadata"]["replayed_outcome_count"] == 8 * inputs[1]["calibration"]["candidate_count"]


def test_null_cosine_fails_enabled_threshold_even_at_negative_one(inputs):
    change_search(inputs[1], min_cosine_score=[None, -1])
    null_case = next(case for case in inputs[1]["calibration"]["cases"] if case["case_id"] == "unrelated-vi")
    policies = {item["policy"]["policy_id"]: item["policy"] for item in inputs[1]["calibration"]["candidate_results"]}
    assert all("vector_score_below_threshold" in item["reason_codes"]
               for item in null_case["policy_results"] if policies[item["policy_id"]]["min_cosine_score"] == -1)
    analyze(*inputs)


def test_unavailable_traversal_replays_requirement_without_fabricated_nodes(inputs):
    case = inputs[1]["calibration"]["cases"][0]
    case["signals"]["traversal_performed"] = False
    for field in ("traversal_node_count", "traversal_edge_count", "traversal_path_count"):
        case["signals"][field] = 0
    change_search(inputs[1], require_traversal=[False, True], min_traversal_nodes=[0, 1])
    assert any("traversal_required" in outcome["reason_codes"] for outcome in case["policy_results"])
    assert any("insufficient_traversal_nodes" in outcome["reason_codes"] for outcome in case["policy_results"])
    analyze(*inputs)


def test_absence_of_dominance_when_abstain_loses_a_count_signal(inputs):
    for case in inputs[1]["calibration"]["cases"]:
        if case["expected_decision"] == "abstain":
            case["signals"]["seed_node_count"] = 0
    replay_fixture_report(inputs[1])
    output = analyze(*inputs)
    assert output["analysis"]["dominance"]["conflicts"] == []
    assert output["analysis"]["collisions"] == []


def test_policy_failures_are_recounted_with_expected_best_metrics(inputs):
    output = analyze(*inputs)
    summary = output["analysis"]["policy_failures"]
    candidates = inputs[1]["calibration"]["candidate_results"]
    assert summary["eligible_policy_count"] == sum(item["eligible"] for item in candidates) == 0
    assert summary["selection_status"] == "no_eligible_policy"
    for name, value in summary["highest_metrics"].items():
        assert value == round(max(item["metrics"][name] for item in candidates), 6)
    assert summary["distinct_confusion_matrix_count"] == len({tuple(sorted(item["confusion_matrix"].items())) for item in candidates})
    assert all(item["passed"] + item["failed"] == 8 for item in summary["constraint_counts"].values())
    assert len(summary["candidate_results"]) == 8


def test_equivalent_tradeoff_policies_use_stable_lowest_policy_id(inputs):
    output = analyze(*inputs)
    frontier = output["analysis"]["trade_off_frontier"]
    assert frontier
    flattened = []
    for item in frontier:
        assert item["equivalent_policy_ids"] == sorted(item["equivalent_policy_ids"])
        assert item["representative_policy_id"] == min(item["equivalent_policy_ids"])
        flattened.extend(item["equivalent_policy_ids"])
    assert len(flattened) == len(set(flattened))
    assert any(len(item["equivalent_policy_ids"]) > 1 for item in frontier)


def test_every_frontier_member_is_nondominated_by_all_candidate_objectives(inputs):
    output = analyze(*inputs)
    candidates = inputs[1]["calibration"]["candidate_results"]
    objectives = []
    for candidate in candidates:
        objectives.append({"false_proceed_unrelated": candidate["breakdown"]["category"]["unrelated"]["confusion_matrix"]["fp"],
                           "false_proceed_insufficient_evidence": candidate["breakdown"]["category"]["insufficient_evidence"]["confusion_matrix"]["fp"],
                           **{name: round(candidate["metrics"][name], 6) for name in ("recall", "f1", "specificity", "balanced_accuracy")}})
    for item in output["analysis"]["trade_off_frontier"]:
        current = item["metrics"]
        for other in objectives:
            better_or_equal = [other[name] <= value if name.startswith("false_proceed_") else other[name] >= value
                               for name, value in current.items()]
            assert not (all(better_or_equal) and any(other[name] != value for name, value in current.items()))


def test_computed_findings_remain_needs_review_without_security_verdict(inputs):
    output = analyze(*inputs)
    codes = {item["code"] for item in output["analysis"]["findings"]}
    assert {"count_signals_have_low_variance", "numeric_ranges_overlap", "cross_label_signal_profile_collision",
            "abstain_case_dominates_proceed_case", "language_support_gap", "current_policy_family_not_separable"} <= codes
    assert all(item["status"] == "needs_review" and item["evidence"] for item in output["analysis"]["findings"])
    assert output["review"] == {"status": "pending_human_review", "reviewer": None, "reviewed_at": None}
    assert "confirmed" not in json.dumps(output)
    assert not {"answer", "confidence", "security_verdict", "selected_policy"} & set(output)


def test_engine_source_contains_no_io_model_clock_or_scenario_dependency():
    import ast
    from threat_hunting.evaluation import relevance_diagnostics as engine
    source = Path(engine.__file__).read_text(encoding="utf-8")
    calls = {node.func.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not {"open", "embed_documents", "build_graphrag_context", "uuid4", "time", "datetime", "random"} & calls
    assert "mshta" not in source.casefold()
    assert "672" not in source
    assert "32" not in source
