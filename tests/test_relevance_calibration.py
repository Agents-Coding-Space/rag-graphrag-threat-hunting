"""Pure calibration, explicit constraints, metric formulas and canonical search."""

from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path

import pytest

from threat_hunting.evaluation import (
    CalibrationConfigValidationError, RelevanceCalibrationError,
    calibrate_relevance_policies, generate_policy_candidates,
    load_calibration_config, validate_calibration_config,
)
from threat_hunting.evaluation import relevance_calibration as engine
from threat_hunting.graphrag import build_graphrag_context


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def config_document():
    config = read(ROOT / "configs/evaluation/mshta_relevance_calibration.json")
    config["calibration_id"] = "synthetic-calibration"
    config["expected_case_count"] = 4
    for name in config["candidate_search_space"]:
        config["candidate_search_space"][name] = config["candidate_search_space"][name][:1]
    config["candidate_search_space"]["min_hits"] = [1, 5]
    return config


def calibration_inputs():
    dataset = read(FIXTURES / "evaluation/relevance_calibration_minimal.json")
    corpus_path = FIXTURES / "retrieval/builder/expected_retrieval_corpus.json"
    corpus = read(corpus_path)
    index = read(FIXTURES / "retrieval/vector_builder/expected_vector_index.json")
    graph = read(FIXTURES / "graph/builder/expected_knowledge_graph.json")
    dataset["scenario_id"] = corpus["scenario_id"]
    config = config_document()
    contexts = {}
    for case in dataset["cases"]:
        contexts[case["case_id"]] = build_graphrag_context(
            corpus, index, graph, case["query"],
            corpus_sha256=sha256(corpus_path.read_bytes()).hexdigest(),
            embed_query=lambda texts: [[1.0, 0.0, 0.0] for _ in texts],
            chunk_types=None if case["expected_decision"] == "proceed" else [],
        )
    policies = generate_policy_candidates(config["candidate_search_space"], max_candidate_policies=10)
    return dataset, contexts, policies, config


@pytest.fixture
def inputs():
    return calibration_inputs()


def evaluate(inputs, **changes):
    dataset, contexts, policies, config = inputs
    return calibrate_relevance_policies(dataset, contexts, candidate_policies=changes.get("policies", policies),
                                       selection_constraints=changes.get("constraints", config["selection_constraints"]))


def test_real_gate_reused_once_for_every_context_policy_and_immutable(inputs, monkeypatch):
    before = deepcopy(inputs)
    calls = []
    real = engine.assess_graphrag_relevance
    def recording(context, *, policy):
        calls.append((id(context), policy["policy_id"]))
        return real(context, policy=policy)
    monkeypatch.setattr(engine, "assess_graphrag_relevance", recording)
    result = evaluate(inputs)
    assert len(calls) == 4 * 2
    assert len({context for context, _ in calls}) == 4
    assert inputs == before
    assert result["case_count"] == 4
    assert result["selection_status"] == "selected"
    assert result["selected_policy_metrics"]["accuracy"] == 1
    result["cases"][0]["signals"]["retrieval_hit_count"] = 999
    result["selected_policy"]["min_hits"] = 999
    assert inputs == before


def test_deterministic_case_policy_order_and_dedup(inputs):
    expected = evaluate(inputs)
    inputs[0]["cases"].reverse()
    actual = evaluate(inputs, policies=list(reversed(inputs[2])) + [deepcopy(inputs[2][0])])
    assert expected == actual


def test_no_eligible_policy_keeps_outcomes_without_selecting_nearest(inputs):
    policies = deepcopy(inputs[2])
    for policy in policies:
        policy["min_hits"] += 100
    result = evaluate(inputs, policies=policies)
    assert result["selection_status"] == "no_eligible_policy"
    assert result["selected_policy"] is None and result["selected_policy_metrics"] is None
    assert result["selection_constraints"] == inputs[3]["selection_constraints"]
    assert engine.NO_ELIGIBLE_WARNING in result["warnings"]
    assert all(case["actual_decision"] is None and case["reason_codes"] == [] for case in result["cases"])
    assert all(outcome["actual_decision"] == "abstain" for case in result["cases"] for outcome in case["policy_results"])


def test_breakdowns_cover_empty_and_single_class_groups(inputs):
    result = evaluate(inputs)
    candidate = result["candidate_results"][0]
    assert candidate["confusion_matrix"] == {"tp": 2, "tn": 2, "fp": 0, "fn": 0}
    for category, bundle in candidate["breakdown"]["category"].items():
        assert bundle["case_count"] == 1
        assert bundle["metrics"]["accuracy"] == 1
        assert bundle["metrics"]["balanced_accuracy"] == 0.5
    for bundle in candidate["breakdown"]["language"].values():
        assert bundle["case_count"] == 2
        assert bundle["metrics"]["accuracy"] == 1
    for bundle in candidate["breakdown"]["expected_decision"].values():
        assert bundle["case_count"] == 2


def test_arbitrary_one_case_dataset_and_empty_breakdown_groups(inputs):
    dataset, contexts, policies, config = inputs
    case = dataset["cases"][0]
    dataset["cases"] = [case]
    dataset["metadata"]["case_count"] = 1
    for name, key in (("category", "category_counts"), ("language", "language_counts"), ("expected_decision", "decision_counts")):
        dataset["metadata"][key] = {group: int(group == case[name]) for group in dataset["metadata"][key]}
    result = calibrate_relevance_policies(dataset, {case["case_id"]: contexts[case["case_id"]]},
                                         candidate_policies=policies, selection_constraints=config["selection_constraints"])
    assert result["case_count"] == 1
    assert result["candidate_results"][0]["breakdown"]["category"]["unrelated"]["case_count"] == 0
    assert set(result["candidate_results"][0]["breakdown"]["category"]["unrelated"]["metrics"].values()) == {0.0}


@pytest.mark.parametrize("matrix", [
    (0, 0, 0, 0), (0, 5, 0, 0), (5, 0, 0, 0), (0, 0, 5, 0), (0, 0, 0, 5),
    (3, 4, 2, 1), (2, 2, 0, 0), (0, 0, 2, 2),
])
def test_all_metric_formulas_and_zero_denominators(matrix):
    tp, tn, fp, fn = matrix
    records = []
    for count, expected, actual in [(tp, "proceed", "proceed"), (tn, "abstain", "abstain"),
                                    (fp, "abstain", "proceed"), (fn, "proceed", "abstain")]:
        records.extend({"expected_decision": expected, "actual_decision": actual} for _ in range(count))
    result = engine._summary(records)
    ratio = lambda a, b: a / b if b else 0.0
    total = sum(matrix)
    assert result["confusion_matrix"] == dict(zip(("tp", "tn", "fp", "fn"), matrix, strict=True))
    assert result["metrics"] == {
        "accuracy": ratio(tp + tn, total), "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn), "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "specificity": ratio(tn, tn + fp),
        "balanced_accuracy": (ratio(tp, tp + fn) + ratio(tn, tn + fp)) / 2,
        "proceed_rate": ratio(tp + fp, total), "abstain_rate": ratio(tn + fn, total),
    }
    assert all(math.isfinite(value) for value in result["metrics"].values())


@pytest.mark.parametrize("priority", ["f1", "recall", "specificity", "balanced_accuracy", "policy_id"])
def test_each_tie_break_priority(priority):
    names = ["f1", "recall", "specificity", "balanced_accuracy", "policy_id"]
    a = {"eligible": True, "policy": {"policy_id": "z"}, "metrics": {name: 0.5 for name in names[:-1]}}
    b = deepcopy(a)
    b["policy"]["policy_id"] = "a"
    index = names.index(priority)
    for later in names[index + 1:-1]:
        a["metrics"][later] = 0.9
    if priority != "policy_id":
        b["metrics"][priority] = 0.6
    assert engine._select([a, b]) is b
    assert engine._select([b, a]) is b


@pytest.mark.parametrize("kind", ["missing", "extra", "scenario", "query", "provenance", "malformed"])
def test_context_identity_and_gate_validation_failures(inputs, kind):
    contexts = inputs[1]
    identifier = next(iter(contexts))
    if kind == "missing":
        del contexts[identifier]
    elif kind == "extra":
        contexts["extra"] = deepcopy(contexts[identifier])
    elif kind == "scenario":
        contexts[identifier]["scenario_id"] = "other"
    elif kind == "query":
        contexts[identifier]["query"]["text"] += " changed"
    elif kind == "provenance":
        contexts[identifier]["source_ground_truth"]["sha256"] = "0" * 64
    else:
        contexts[identifier]["metadata"]["retrieval_hit_count"] = 999
    with pytest.raises(RelevanceCalibrationError):
        evaluate(inputs)


def test_duplicate_policy_id_with_conflicting_body_rejected(inputs):
    policies = deepcopy(inputs[2])
    policies[1]["policy_id"] = policies[0]["policy_id"]
    with pytest.raises(RelevanceCalibrationError, match="conflicting"):
        evaluate(inputs, policies=policies)


def test_explicit_category_false_proceed_constraints(inputs):
    result = evaluate(inputs)
    records = [{"case_id": "p", "category": "relevant_direct", "language": "en", "expected_decision": "proceed", "actual_decision": "proceed"}]
    for category in ("unrelated", "insufficient_evidence"):
        records.append({"case_id": category, "category": category, "language": "vi", "expected_decision": "abstain", "actual_decision": "proceed"})
    candidate = engine._candidate_result(inputs[2][0], records, inputs[3]["selection_constraints"])
    assert candidate["eligible"] is False
    assert candidate["false_positive_case_ids"] == ["insufficient_evidence", "unrelated"]
    assert set(candidate["ineligibility_reasons"]) >= {"false_proceed_unrelated_above_limit", "false_proceed_insufficient_evidence_above_limit"}


def test_candidate_dedup_normalized_numbers_stable_canonical_ids():
    config = config_document()
    search = config["candidate_search_space"]
    search["min_cosine_score"] = [None, 0, -0.0, 0.0, 0.3, 0.30]
    search["min_hits"] = [5, 1, 5, 1]
    snapshot = deepcopy(search)
    policies = generate_policy_candidates(search, max_candidate_policies=10)
    assert len(policies) == 6
    assert search == snapshot
    for field in search:
        search[field].reverse()
    assert policies == generate_policy_candidates(search, max_candidate_policies=10)
    assert len({policy["policy_id"] for policy in policies}) == 6
    assert all(policy["policy_id"].startswith("calibration-policy-") for policy in policies)


def test_production_config_declares_672_candidates_and_unrelaxed_constraints():
    config = load_calibration_config(ROOT / "configs/evaluation/mshta_relevance_calibration.json")
    assert len(generate_policy_candidates(config["candidate_search_space"], max_candidate_policies=config["max_candidate_policies"])) == 672
    assert config["selection_constraints"]["min_recall"] == 0.75
    assert config["selection_constraints"]["min_f1"] == 0.75
    assert config["selection_constraints"]["max_false_proceed_unrelated"] == 0
    assert config["selection_constraints"]["max_false_proceed_insufficient_evidence"] == 0


@pytest.mark.parametrize("field,invalid", [
    ("min_hits", -1), ("min_hits", True), ("min_hits", 1.5),
    ("min_mapped_hits", -1), ("min_seed_nodes", None), ("min_traversal_nodes", "1"),
    ("require_traversal", 1), ("require_lexical_support", None),
    ("require_joint_lexical_vector_support", "true"),
    ("min_cosine_score", True), ("min_cosine_score", 1.01),
    ("min_cosine_score", -1.01), ("min_cosine_score", float("nan")),
    ("min_cosine_score", float("inf")),
])
def test_search_values_reject_wrong_types_or_ranges(field, invalid):
    config = config_document()
    config["candidate_search_space"][field] = [invalid]
    with pytest.raises(CalibrationConfigValidationError):
        validate_calibration_config(config)


@pytest.mark.parametrize("section,field,invalid", [
    (None, "schema_version", "bad"), (None, "calibration_id", ""),
    (None, "expected_case_count", 0), (None, "expected_case_count", True),
    (None, "max_candidate_policies", 1), (None, "max_candidate_policies", 0),
    ("selection_constraints", "min_recall", -0.01), ("selection_constraints", "min_f1", 1.01),
    ("selection_constraints", "max_false_proceed_unrelated", True),
    ("selection_constraints", "max_false_proceed_insufficient_evidence", -1),
    ("selection_constraints", "tie_break_order", []),
    ("retrieval", "top_k", 0), ("retrieval", "candidate_k", 1),
    ("retrieval", "chunk_types", ["unknown"]), ("retrieval", "required_dimensions", ["x", "x"]),
    ("traversal", "direction", "sideways"), ("traversal", "max_depth", 65),
    ("traversal", "max_nodes", 0), ("traversal", "max_edges", True),
    ("traversal", "allowed_edge_types", ["Bad-Identifier"]),
    ("embedding_runtime", "device", "cuda"), ("embedding_runtime", "batch_size", 0),
    ("embedding_runtime", "show_progress_bar", 0), ("embedding_runtime", "offline", False),
])
def test_strict_config_fields(section, field, invalid):
    config = config_document()
    target = config if section is None else config[section]
    target[field] = invalid
    with pytest.raises(CalibrationConfigValidationError):
        validate_calibration_config(config)


@pytest.mark.parametrize("section", [None, "candidate_search_space", "selection_constraints", "retrieval", "traversal", "embedding_runtime"])
@pytest.mark.parametrize("operation", ["extra", "missing"])
def test_config_exact_keys(section, operation):
    config = config_document()
    target = config if section is None else config[section]
    if operation == "extra":
        target["extra"] = 1
    else:
        del target[next(iter(target))]
    with pytest.raises(CalibrationConfigValidationError):
        validate_calibration_config(config)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'\xff', b'{'])
def test_config_strict_file_loader(tmp_path, raw):
    path = tmp_path / "config.json"
    path.write_bytes(raw)
    with pytest.raises(CalibrationConfigValidationError, match="config.json"):
        load_calibration_config(path)


def test_engine_has_no_io_model_or_scenario_dependency():
    import ast
    source = Path(engine.__file__).read_text(encoding="utf-8")
    names = {node.func.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert "assess_graphrag_relevance" in names
    assert not {"open", "build_graphrag_context", "embed_documents"} & names
    assert "mshta" not in source.casefold()
    assert "32" not in source
