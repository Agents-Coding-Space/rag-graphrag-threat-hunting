"""Independent synthetic expectations for the two-stage policy contract.

Fixtures are hand-authored; the evaluator is never used to generate expected
decisions. Legacy fixture helpers supply only existing regression inputs.
"""

from __future__ import annotations

import ast
import builtins
from collections.abc import Mapping
from copy import deepcopy
import io
import json
from pathlib import Path
import random
import socket
import time
from types import MappingProxyType
import uuid

import pytest

import test_graphrag_gate_signals as signal_tests
import test_graphrag_relevance as legacy_tests
from threat_hunting import graphrag
from threat_hunting.graphrag import (
    GRAPHRAG_TWO_STAGE_GATE_DECISION_SCHEMA_VERSION,
    GRAPHRAG_TWO_STAGE_GATE_POLICY_SCHEMA_VERSION,
    GraphRAGGateSignalError,
    GraphRAGTwoStageGateError,
    assess_graphrag_relevance,
    assess_graphrag_two_stage_gate,
    extract_graphrag_gate_signals,
    extract_graphrag_relevance_signals,
    validate_graphrag_gate_signals,
)
from threat_hunting.graphrag import two_stage_gate


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PATH = ROOT / "tests/fixtures/graphrag/two_stage_gate/expected_two_stage_gate_decisions.json"
IMPLEMENTATION_PATH = ROOT / "src/threat_hunting/graphrag/two_stage_gate.py"
SIGNAL_OBJECT_PATHS = (
    (), ("source_ground_truth",), ("query",), ("query", "filters"),
    ("topical_relevance",), ("evidence_answerability",),
    ("evidence_answerability", "chunk_type_counts"),
    ("evidence_answerability", "status_counts"),
    ("metadata",), ("metadata", "score_interpretations"),
)
POLICY_OBJECT_PATHS = ((), ("topical_relevance",), ("evidence_answerability",))


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture() -> dict:
    return _read(EXPECTED_PATH)


def _merge(target: dict, overrides: dict) -> None:
    for key, value in overrides.items():
        if isinstance(value, dict):
            _merge(target[key], value)
        else:
            target[key] = deepcopy(value)


def _case(name: str = "both_stages_pass") -> tuple[dict, dict, dict]:
    fixture = _fixture()
    entry = fixture["cases"][name]
    signals, policy = fixture["base_signals"], fixture["base_policy"]
    _merge(signals, entry["signal_overrides"])
    _merge(policy, entry["policy_overrides"])
    return signals, policy, entry["expected"]


def _expected(signals: dict, policy: dict, fragment: dict) -> dict:
    """Expand manually specified statuses/reasons with contract-required echoes."""
    return {
        "schema_version": "graphrag-two-stage-gate-decision/v1",
        "corpus_id": signals["corpus_id"], "graph_id": signals["graph_id"],
        "scenario_id": signals["scenario_id"], "query": deepcopy(signals["query"]),
        "policy_id": policy["policy_id"], "decision": fragment["decision"],
        "abstention_stage": fragment["abstention_stage"],
        "reason_codes": fragment["topical_reasons"] + fragment["answerability_reasons"],
        "stage_results": {
            "topical_relevance": {
                "status": fragment["topical_status"],
                "reason_codes": deepcopy(fragment["topical_reasons"]),
                "signals": deepcopy(signals["topical_relevance"]),
            },
            "evidence_answerability": {
                "status": fragment["answerability_status"],
                "reason_codes": deepcopy(fragment["answerability_reasons"]),
                "signals": deepcopy(signals["evidence_answerability"]),
            },
        },
        "warnings": deepcopy(signals["warnings"]),
        "metadata": {
            "signal_schema_version": signals["schema_version"],
            "policy_schema_version": policy["schema_version"], "policy": deepcopy(policy),
            "score_interpretations": deepcopy(signals["metadata"]["score_interpretations"]),
            "decision_interpretation": "context_eligibility_only", "security_conclusion_made": False,
            "source_ground_truth": deepcopy(signals["source_ground_truth"]),
        },
    }


def _serialize(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _at(root: object, path: tuple) -> object:
    for key in path:
        root = root[key]
    return root


def _containers(value: object) -> set[int]:
    if not isinstance(value, (Mapping, list)):
        return set()
    result = {id(value)}
    for child in value.values() if isinstance(value, Mapping) else value:
        result.update(_containers(child))
    return result


def _integer_paths(value: object, path: tuple = ()) -> list[tuple]:
    if type(value) is int:
        return [path]
    if isinstance(value, dict):
        return [item for key, child in value.items() for item in _integer_paths(child, (*path, key))]
    return []


FIXTURE = _fixture()
CASE_NAMES = tuple(FIXTURE["cases"])
POLICY_PATHS = tuple((path[0], name) for path in POLICY_OBJECT_PATHS[1:]
                     for name in FIXTURE["base_policy"][path[0]])
SIGNAL_INTEGER_PATHS = tuple(_integer_paths(FIXTURE["base_signals"]))


@pytest.mark.parametrize("name", CASE_NAMES)
def test_manual_cases_cover_decisions_stages_reason_order_and_exact_echoes(name: str) -> None:
    signals, policy, fragment = _case(name)
    before = deepcopy((signals, policy))
    assert validate_graphrag_gate_signals(signals) is None
    result = assess_graphrag_two_stage_gate(signals, policy=policy)
    expected = _expected(signals, policy, fragment)
    assert _serialize(result) == _serialize(expected)
    assert (signals, policy) == before
    assert set(result) == {
        "schema_version", "corpus_id", "graph_id", "scenario_id", "query", "policy_id",
        "decision", "abstention_stage", "reason_codes", "stage_results", "warnings", "metadata",
    }
    assert set(result["stage_results"]) == {"topical_relevance", "evidence_answerability"}
    assert all(set(stage) == {"status", "reason_codes", "signals"}
               for stage in result["stage_results"].values())
    assert json.loads(_serialize(result)) == result
    assert "confirmed" not in _serialize(result).decode("utf-8").casefold()
    assert result["metadata"]["security_conclusion_made"] is False


def test_public_api_schema_versions_and_validator_nonmutation() -> None:
    signals, policy, _ = _case()
    before = deepcopy(signals)
    assert validate_graphrag_gate_signals(MappingProxyType(signals)) is None
    assert signals == before
    assert GRAPHRAG_TWO_STAGE_GATE_POLICY_SCHEMA_VERSION == "graphrag-two-stage-gate-policy/v1"
    assert GRAPHRAG_TWO_STAGE_GATE_DECISION_SCHEMA_VERSION == "graphrag-two-stage-gate-decision/v1"
    assert graphrag.assess_graphrag_two_stage_gate is two_stage_gate.assess_graphrag_two_stage_gate
    assert graphrag.GraphRAGTwoStageGateError is two_stage_gate.GraphRAGTwoStageGateError
    assert issubclass(GraphRAGTwoStageGateError, ValueError)
    assert assess_graphrag_two_stage_gate(signals, policy=policy)["metadata"]["decision_interpretation"] == "context_eligibility_only"


def test_topical_failure_does_not_execute_answerability_conditions(monkeypatch) -> None:
    signals, policy, fragment = _case("topical_conditions_fail")
    def forbidden(*args, **kwargs):
        pytest.fail("Answerability must not execute after topical failure")
    monkeypatch.setattr(two_stage_gate, "_answerability_reasons", forbidden)
    result = assess_graphrag_two_stage_gate(signals, policy=policy)
    assert result == _expected(signals, policy, fragment)
    assert result["stage_results"]["evidence_answerability"]["signals"] == signals["evidence_answerability"]


def test_null_thresholds_disable_missing_scores_but_zero_thresholds_remain_enabled() -> None:
    signals, policy, _ = _case("missing_returned_scores")
    assert len(assess_graphrag_two_stage_gate(signals, policy=policy)["reason_codes"]) == 3
    for name in ("rrf", "bm25", "cosine"):
        policy["topical_relevance"][f"min_returned_top_{name}_score"] = None
    assert assess_graphrag_two_stage_gate(signals, policy=policy)["decision"] == "proceed"


@pytest.mark.parametrize("cosine", [-1, 0, 1])
def test_numeric_score_domain_boundaries_and_equality(cosine: int) -> None:
    signals, policy, _ = _case()
    signals["topical_relevance"].update(returned_top_rrf_score=0, returned_top_bm25_score=0,
                                        returned_top_cosine_score=cosine)
    policy["topical_relevance"].update(min_returned_top_rrf_score=0,
                                       min_returned_top_bm25_score=0,
                                       min_returned_top_cosine_score=cosine)
    assert assess_graphrag_two_stage_gate(signals, policy=policy)["decision"] == "proceed"


def test_unique_references_and_seed_nodes_can_exceed_hit_count() -> None:
    signals, policy, _ = _case()
    signals["evidence_answerability"].update(unique_source_reference_count=7, seed_node_count=5,
                                              traversal_node_count=6, traversal_path_count=6)
    assert validate_graphrag_gate_signals(signals) is None
    assert assess_graphrag_two_stage_gate(signals, policy=policy)["decision"] == "proceed"


@pytest.mark.parametrize("path", SIGNAL_OBJECT_PATHS)
def test_signals_reject_unknown_fields_and_every_missing_structural_field(path: tuple) -> None:
    original, policy, _ = _case()
    keys = tuple(_at(original, path))
    mutated = deepcopy(original)
    _at(mutated, path)["unexpected"] = "synthetic"
    with pytest.raises(GraphRAGGateSignalError):
        validate_graphrag_gate_signals(mutated)
    with pytest.raises(GraphRAGTwoStageGateError):
        assess_graphrag_two_stage_gate(mutated, policy=policy)
    for key in keys:
        mutated = deepcopy(original)
        del _at(mutated, path)[key]
        with pytest.raises(GraphRAGGateSignalError):
            validate_graphrag_gate_signals(mutated)


@pytest.mark.parametrize("path", POLICY_OBJECT_PATHS)
def test_policy_rejects_unknown_fields_and_every_missing_field_without_defaults(path: tuple) -> None:
    signals, original, _ = _case()
    keys = tuple(_at(original, path))
    mutated = deepcopy(original)
    _at(mutated, path)["unexpected"] = "synthetic"
    with pytest.raises(GraphRAGTwoStageGateError):
        assess_graphrag_two_stage_gate(signals, policy=mutated)
    for key in keys:
        mutated = deepcopy(original)
        del _at(mutated, path)[key]
        with pytest.raises(GraphRAGTwoStageGateError):
            assess_graphrag_two_stage_gate(signals, policy=mutated)


@pytest.mark.parametrize("path", POLICY_PATHS)
def test_every_policy_field_rejects_wrong_types_nonfinite_numbers_and_out_of_range_values(path: tuple) -> None:
    signals, policy, _ = _case()
    name = path[-1]
    if name == "require_traversal":
        invalid = (0, None, "false")
    elif name == "max_traversed_limitation_node_count":
        invalid = (True, -1, 0.5, float("nan"), float("inf"))
    elif "score" in name:
        invalid = (True, "1", float("nan"), float("inf"), -float("inf"),
                   -1.1 if "cosine" in name else -0.1)
        if "cosine" in name:
            invalid += (1.1,)
    elif name == "min_query_token_coverage":
        invalid = (True, None, -0.1, 1.1, float("nan"), float("inf"))
    else:
        invalid = (True, None, -1, 0.5, float("nan"), float("inf"))
    for value in invalid:
        mutated = deepcopy(policy)
        _at(mutated, path[:-1])[name] = value
        with pytest.raises(GraphRAGTwoStageGateError):
            assess_graphrag_two_stage_gate(signals, policy=mutated)


@pytest.mark.parametrize("path", SIGNAL_INTEGER_PATHS)
def test_every_signal_integer_field_rejects_bool_negative_fractional_and_null(path: tuple) -> None:
    signals, _, _ = _case()
    for value in (True, -1, 0.5, None):
        mutated = deepcopy(signals)
        _at(mutated, path[:-1])[path[-1]] = value
        with pytest.raises(GraphRAGGateSignalError):
            validate_graphrag_gate_signals(mutated)


@pytest.mark.parametrize("field", ["returned_top_rrf_score", "returned_top_bm25_score",
                                   "returned_top_cosine_score", "query_token_coverage"])
def test_signal_scores_and_coverage_reject_nonfinite_boolean_and_out_of_range_values(field: str) -> None:
    signals, _, _ = _case()
    invalid = (True, float("nan"), float("inf"), -float("inf"), "0.5")
    if field == "returned_top_cosine_score":
        invalid += (-1.1, 1.1)
    elif field == "query_token_coverage":
        invalid += (-0.1, 1.1, None)
    else:
        invalid += (-0.1,)
    for value in invalid:
        mutated = deepcopy(signals)
        mutated["topical_relevance"][field] = value
        with pytest.raises(GraphRAGGateSignalError):
            validate_graphrag_gate_signals(mutated)


INCONSISTENT_SIGNALS = (
    {"schema_version": "graphrag-gate-signals/v2"},
    {"topical_relevance": {"lexical_hit_count": 4}},
    {"topical_relevance": {"joint_lexical_vector_hit_count": 3}},
    {"topical_relevance": {"vector_hit_count": 2}},
    {"evidence_answerability": {"chunk_type_counts": {"fact": 1}}},
    {"evidence_answerability": {"status_counts": {"candidate": 1}}},
    {"evidence_answerability": {"hits_with_evidence_ids": 4}},
    {"evidence_answerability": {"hits_with_source_references": 4}},
    {"evidence_answerability": {"mapped_hit_count": 4}},
    {"evidence_answerability": {"unique_source_reference_count": 0}},
    {"evidence_answerability": {"hits_with_source_references": 0}},
    {"topical_relevance": {"matched_query_token_count": 4}},
    {"topical_relevance": {"query_token_count": 4, "query_token_coverage": 0.5}},
    {"topical_relevance": {"query_token_coverage": 0.66666668}},
    {"topical_relevance": {"lexical_hit_count": 0, "joint_lexical_vector_hit_count": 0}},
    {"topical_relevance": {"lexical_hit_count": 3, "vector_hit_count": 0, "joint_lexical_vector_hit_count": 0}},
    {"evidence_answerability": {"traversal_performed": False}},
    {"evidence_answerability": {"traversal_performed": 1}},
    {"evidence_answerability": {"traversed_evidence_node_count": 5}},
    {"evidence_answerability": {"traversed_limitation_node_count": 5}},
    {"evidence_answerability": {"traversed_evidence_node_count": 3, "traversed_limitation_node_count": 2}},
    {"evidence_answerability": {"support_edge_count": 4}},
    {"query": {"top_k": 2}},
    {"metadata": {"decision_made": True}},
    {"metadata": {"decision_made": 0}},
    {"metadata": {"topical_signal_count": 9}},
    {"metadata": {"answerability_signal_count": 13}},
    {"metadata": {"score_interpretations": {"rrf": "probability"}}},
    {"source_ground_truth": {"scenario_id": "different-synthetic-scenario"}},
)


@pytest.mark.parametrize("overrides", INCONSISTENT_SIGNALS)
def test_invalid_signal_relationships_fail_closed_in_validator_and_evaluator(overrides: dict) -> None:
    signals, policy, _ = _case()
    _merge(signals, overrides)
    before = deepcopy(signals)
    with pytest.raises(GraphRAGGateSignalError):
        validate_graphrag_gate_signals(signals)
    with pytest.raises(GraphRAGTwoStageGateError):
        assess_graphrag_two_stage_gate(signals, policy=policy)
    assert signals == before


@pytest.mark.parametrize("field", ["traversal_node_count", "traversal_edge_count", "traversal_path_count",
                                   "traversed_evidence_node_count", "traversed_limitation_node_count", "support_edge_count"])
def test_every_traversal_count_must_be_zero_when_not_performed(field: str) -> None:
    signals, _, _ = _case("traversal_optional")
    signals["evidence_answerability"][field] = 1
    with pytest.raises(GraphRAGGateSignalError):
        validate_graphrag_gate_signals(signals)


def test_performed_traversal_requires_seed_nodes_and_their_returned_self_paths() -> None:
    signals, _, _ = _case()
    for overrides in ({"seed_node_count": 0}, {"traversal_node_count": 1},
                      {"traversal_path_count": 1}):
        mutated = deepcopy(signals)
        mutated["evidence_answerability"].update(overrides)
        with pytest.raises(GraphRAGGateSignalError):
            validate_graphrag_gate_signals(mutated)


@pytest.mark.parametrize("field", ["returned_top_rrf_score", "returned_top_bm25_score", "returned_top_cosine_score"])
def test_empty_hits_require_null_returned_scores(field: str) -> None:
    signals, _, _ = _case("disabled_requirements_empty_hits")
    signals["topical_relevance"][field] = 0
    with pytest.raises(GraphRAGGateSignalError):
        validate_graphrag_gate_signals(signals)


@pytest.mark.parametrize("path", [("corpus_id",), ("graph_id",), ("scenario_id",),
                                  ("source_ground_truth", "path"), ("source_ground_truth", "sha256"),
                                  ("query", "text")])
def test_malformed_scalar_identifiers_provenance_and_query_text_are_rejected(path: tuple) -> None:
    signals, _, _ = _case()
    for value in ("", "  ", 1, None):
        mutated = deepcopy(signals)
        _at(mutated, path[:-1])[path[-1]] = value
        with pytest.raises(GraphRAGGateSignalError):
            validate_graphrag_gate_signals(mutated)


def test_duplicate_terms_dimensions_warnings_and_upstream_object_ids_fail_closed() -> None:
    signals, _, _ = _case()
    variants = (
        {"query": {"normalized_terms": ["synthetic", "synthetic"]}},
        {"query": {"filters": {"required_dimensions": ["evidence", "evidence"]}}},
        {"warnings": ["duplicate", "duplicate"]},
    )
    for overrides in variants:
        mutated = deepcopy(signals)
        _merge(mutated, overrides)
        with pytest.raises(GraphRAGGateSignalError):
            validate_graphrag_gate_signals(mutated)
    for container, field in (("hits", "chunk_id"), ("nodes", "node_id"), ("seeds", None)):
        context = signal_tests._context()
        if container == "hits":
            hits = context["retrieval"]["hits"]
            hits[1]["chunk"][field] = hits[0]["chunk"][field]
        elif container == "nodes":
            nodes = context["traversal"]["nodes"]
            nodes[1][field] = nodes[0][field]
        else:
            context["seed_mapping"]["seed_node_ids"].append(context["seed_mapping"]["seed_node_ids"][0])
        with pytest.raises(GraphRAGGateSignalError):
            extract_graphrag_gate_signals(context)


@pytest.mark.parametrize("value", [None, [], "signals", 1, {}])
def test_malformed_signal_and_policy_roots_fail_closed(value: object) -> None:
    signals, policy, _ = _case()
    with pytest.raises(GraphRAGGateSignalError):
        validate_graphrag_gate_signals(value)
    with pytest.raises(GraphRAGTwoStageGateError):
        assess_graphrag_two_stage_gate(value, policy=policy)
    with pytest.raises(GraphRAGTwoStageGateError):
        assess_graphrag_two_stage_gate(signals, policy=value)


def test_forbidden_states_answers_benchmark_fields_nonjson_values_and_cycles_fail_closed() -> None:
    signals, policy, _ = _case()
    for key, value in (("review_status", "confirmed"), ("expected_answer", "synthetic text"),
                       ("evaluation_questions", []), ("category", "relevant"), ("case_id", "benchmark"),
                       ("language", "vi"), ("expected_decision", "proceed")):
        for original, as_policy in ((signals, False), (policy, True)):
            mutated = deepcopy(original)
            mutated[key] = value
            with pytest.raises(GraphRAGTwoStageGateError):
                assess_graphrag_two_stage_gate(signals if as_policy else mutated,
                                               policy=mutated if as_policy else policy)
    for value in ((1, 2), {1: "value"}, "\ud800", object(), float("nan")):
        mutated = deepcopy(signals)
        mutated["warnings"] = [value]
        with pytest.raises(GraphRAGGateSignalError):
            validate_graphrag_gate_signals(mutated)
    mutated = deepcopy(signals)
    mutated["warnings"].append(mutated)
    with pytest.raises(GraphRAGGateSignalError):
        validate_graphrag_gate_signals(mutated)
    assert mutated["warnings"][-1] is mutated


def test_output_is_detached_nonmutating_deterministic_and_finite_json() -> None:
    signals, policy, fragment = _case()
    before = deepcopy((signals, policy))
    first = assess_graphrag_two_stage_gate(signals, policy=policy)
    second = assess_graphrag_two_stage_gate(MappingProxyType(signals), policy=MappingProxyType(policy))
    assert _serialize(first) == _serialize(second)
    assert (signals, policy) == before
    assert _containers(first).isdisjoint(_containers(signals) | _containers(policy) | _containers(second))
    first["query"]["normalized_terms"].append("changed")
    first["metadata"]["policy"]["topical_relevance"]["min_retrieval_hit_count"] = 99
    first["metadata"]["source_ground_truth"]["path"] = "changed.json"
    first["metadata"]["score_interpretations"]["cosine"] = "changed"
    first["stage_results"]["evidence_answerability"]["signals"]["status_counts"]["observed"] = 99
    first["warnings"].append("changed")
    assert (signals, policy) == before
    assert second == _expected(signals, policy, fragment)


def test_mapping_insertion_order_has_no_effect_on_serialized_output() -> None:
    def reordered(value: object) -> object:
        if isinstance(value, dict):
            return {key: reordered(item) for key, item in reversed(list(value.items()))}
        if isinstance(value, list):
            return [reordered(item) for item in value]
        return value
    signals, policy, _ = _case()
    assert _serialize(assess_graphrag_two_stage_gate(signals, policy=policy)) == _serialize(
        assess_graphrag_two_stage_gate(reordered(signals), policy=reordered(policy)),
    )


def test_no_files_network_clock_random_uuid_or_model_operations(monkeypatch) -> None:
    signals, policy, _ = _case()
    from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend
    def forbidden(*args, **kwargs):
        pytest.fail("The validator/evaluator attempted an external or nondeterministic operation")
    for owner, name in ((builtins, "open"), (io, "open"), (Path, "open"), (socket, "socket"),
                        (socket, "create_connection"), (time, "time"), (time, "monotonic"),
                        (random, "random"), (uuid, "uuid4"), (SentenceTransformerEmbeddingBackend, "__init__")):
        monkeypatch.setattr(owner, name, forbidden)
    assert validate_graphrag_gate_signals(signals) is None
    assert assess_graphrag_two_stage_gate(signals, policy=policy)["decision"] == "proceed"


@pytest.mark.parametrize("exception", [KeyboardInterrupt("synthetic cancellation"), SystemExit(7)])
def test_baseexceptions_propagate_without_wrapping(monkeypatch, exception: BaseException) -> None:
    signals, policy, _ = _case()
    def interrupted(*args, **kwargs):
        raise exception
    monkeypatch.setattr(two_stage_gate, "_validated_gate_signals", interrupted)
    with pytest.raises(type(exception)) as caught:
        assess_graphrag_two_stage_gate(signals, policy=policy)
    assert caught.value is exception


def test_technical_exception_is_wrapped_with_its_original_cause(monkeypatch) -> None:
    signals, policy, _ = _case()
    failure = RuntimeError("synthetic validation failure")
    def broken(*args, **kwargs):
        raise failure
    monkeypatch.setattr(two_stage_gate, "_validated_gate_signals", broken)
    with pytest.raises(GraphRAGTwoStageGateError, match="synthetic validation failure") as caught:
        assess_graphrag_two_stage_gate(signals, policy=policy)
    assert caught.value.__cause__ is failure


def test_evaluator_has_no_benchmark_or_model_dependencies_or_default_thresholds() -> None:
    source = IMPLEMENTATION_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
    assert not any(name and any(part in name for part in (
        "calibration", "evaluation", "embedding_backend", "sentence_transformers", "requests",
        "socket", "subprocess", "random", "uuid", "datetime", "time",
    )) for name in imports)
    for forbidden in ("expected_decision", "expected_answer", "case_id", "mshta", "powershell", "outputs/"):
        assert forbidden not in source.casefold()
    with pytest.raises(TypeError):
        assess_graphrag_two_stage_gate(_case()[0])


def test_existing_gate_signal_output_remains_byte_for_byte() -> None:
    context = signal_tests._context()
    expected = _read(signal_tests.EXPECTED_PATH)
    before = deepcopy(context)
    result = extract_graphrag_gate_signals(context)
    assert _serialize(result) == _serialize(expected)
    assert validate_graphrag_gate_signals(result) is None
    assert context == before


@pytest.mark.parametrize("name", legacy_tests.CASE_NAMES)
def test_all_legacy_relevance_signals_and_full_decisions_remain_byte_for_byte(name: str) -> None:
    context, policy = legacy_tests._case(name)
    fragment = _read(legacy_tests.EXPECTED_PATH)["cases"][name]
    expected = {
        "schema_version": "graphrag-relevance-decision/v1", "scenario_id": context["scenario_id"],
        "query": context["query"], "policy_id": policy["policy_id"], **fragment,
        "warnings": sorted(set(context["warnings"] + context["retrieval"]["warnings"]
                               + context["seed_mapping"]["warnings"]
                               + (context["traversal"]["warnings"] if context["traversal"] is not None else []))),
        "metadata": {
            "context_schema_version": context["schema_version"], "policy_schema_version": policy["schema_version"],
            "corpus_id": context["corpus_id"], "graph_id": context["graph_id"],
            "source_ground_truth": context["source_ground_truth"], "policy": policy,
            "score_interpretation": "bm25_cosine_rrf_not_probabilities",
            "decision_interpretation": "context_eligibility_only",
        },
    }
    assert _serialize(extract_graphrag_relevance_signals(context)) == _serialize(fragment["signals"])
    assert _serialize(assess_graphrag_relevance(context, policy=policy)) == _serialize(expected)
