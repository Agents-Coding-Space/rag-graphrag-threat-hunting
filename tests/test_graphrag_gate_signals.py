"""Synthetic, manually reviewed expectations for the two-stage signal core.

The input is an existing synthetic orchestrator fixture. Its transformations
below are test data, never production telemetry or expected security answers.
The expected JSON is hand-written independently of the extractor.
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

import test_graphrag_relevance as legacy_tests
from threat_hunting import graphrag
from threat_hunting.graphrag import (
    GRAPHRAG_GATE_SIGNALS_SCHEMA_VERSION,
    GraphRAGGateSignalError,
    assess_graphrag_relevance,
    extract_graphrag_gate_signals,
    extract_graphrag_relevance_signals,
)
from threat_hunting.graphrag import gate_signals, relevance
from threat_hunting.retrieval.lexical import tokenize_retrieval_text


ROOT = Path(__file__).resolve().parents[1]
INPUT_PATH = ROOT / "tests/fixtures/graphrag/orchestrator/expected_graphrag_context.json"
EXPECTED_PATH = ROOT / "tests/fixtures/graphrag/gate_signals/expected_gate_signals.json"
LEGACY_EXPECTED_PATH = ROOT / "tests/fixtures/graphrag/relevance/expected_relevance_decisions.json"
IMPLEMENTATION_PATH = ROOT / "src/threat_hunting/graphrag/gate_signals.py"
CHUNK_TYPES = (
    "scenario_summary", "entity", "fact", "relationship", "evidence",
    "sigma_finding", "mitre_assessment", "limitation",
)
STATUSES = ("observed", "inferred", "candidate", "reviewable")
TOPICAL_FIELDS = (
    "retrieval_hit_count", "lexical_hit_count", "vector_hit_count",
    "joint_lexical_vector_hit_count", "returned_top_rrf_score",
    "returned_top_bm25_score", "returned_top_cosine_score", "query_token_count",
    "matched_query_token_count", "query_token_coverage",
)
ANSWERABILITY_FIELDS = (
    "chunk_type_counts", "status_counts", "hits_with_evidence_ids",
    "hits_with_source_references", "unique_source_reference_count",
    "mapped_hit_count", "seed_node_count", "traversal_performed",
    "traversal_node_count", "traversal_edge_count", "traversal_path_count",
    "traversed_evidence_node_count", "traversed_limitation_node_count", "support_edge_count",
)


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _serialize(value: object) -> bytes:
    return (json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False,
        separators=(",", ":"),
    ) + "\n").encode("utf-8")


def _at(root: object, path: tuple) -> object:
    value = root
    for key in path:
        value = value[key]
    return value


def _sync(context: dict) -> None:
    """Update synthetic echoes/counters after changing returned evidence."""
    hits = context["retrieval"]["hits"]
    mappings = context["seed_mapping"]["hit_mappings"]
    seeds = context["seed_mapping"]["seed_node_ids"]
    lookup = {hit["chunk"]["chunk_id"]: hit for hit in hits}
    metadata = context["retrieval"]["metadata"]
    metadata["returned_hits"] = metadata["union_candidate_count"] = len(hits)
    for name in ("lexical", "vector"):
        rank = 0
        for hit in hits:
            component = hit["components"][name]
            if component is not None:
                rank += 1
                component["rank"] = rank
        metadata[f"{name}_candidate_count"] = rank
    for rank, hit in enumerate(hits, 1):
        hit["rank"] = rank
    for mapping in mappings:
        hit = lookup[mapping["chunk_id"]]
        mapping["hit_rank"] = hit["rank"]
        mapping["hit_score"] = hit["score"]
        mapping["components"] = deepcopy(hit["components"])
    direct = sum(mapping["mapping_kind"] == "direct_node" for mapping in mappings)
    context["seed_mapping"]["metadata"] = {
        "retrieval_hit_count": len(hits), "mapped_hit_count": len(mappings),
        "direct_node_mapping_count": direct,
        "relationship_edge_mapping_count": len(mappings) - direct,
        "seed_node_count": len(seeds),
    }
    traversal = context["traversal"]
    counts = {name: len(traversal[name]) if traversal is not None else 0
              for name in ("nodes", "edges", "paths")}
    if traversal is not None:
        traversal["metadata"].update(
            node_count=counts["nodes"], edge_count=counts["edges"],
            path_count=counts["paths"],
            max_reached_depth=max((path["depth"] for path in traversal["paths"]), default=0),
        )
    context["metadata"] = {
        "retrieval_hit_count": len(hits), "mapped_hit_count": len(mappings),
        "seed_node_count": len(seeds), "traversal_performed": traversal is not None,
        "traversed_node_count": counts["nodes"], "traversed_edge_count": counts["edges"],
        "traversed_path_count": counts["paths"],
    }
    for stage in (context["retrieval"], context["seed_mapping"]):
        stage["query"] = deepcopy(context["query"])


def _context() -> dict:
    """Add observable synthetic cases absent from the existing joint fixture."""
    context = _read(INPUT_PATH)
    context["query"].update(
        text="ＳＹＮＴＨＥＴＩＣ synthetic Ω unmatched",
        normalized_terms=["synthetic", "ω", "unmatched"],
    )
    hits = context["retrieval"]["hits"]
    hits[0]["chunk"]["title"] += " Ω"
    hits[4]["components"]["lexical"] = None
    hits[2]["chunk"]["status"] = "inferred"
    mapped_id = context["seed_mapping"]["hit_mappings"][2]["matched_node_ids"][0]
    traversal = context["traversal"]
    for node in traversal["nodes"]:
        if node["node_id"] == mapped_id:
            node["status"] = "inferred"
    # The same reference occurs across chunks in opposite key insertion order.
    reference = hits[1]["chunk"]["source_references"][0]
    hits[1]["chunk"]["source_references"][0] = {
        "source_file": reference["source_file"], "raw_record_ref": reference["raw_record_ref"],
    }
    scenario_node = next(node["node_id"] for node in traversal["nodes"]
                         if node["node_type"] == "scenario")
    limitation_id, edge_id = "gate-synthetic-limitation", "gate-synthetic-limitation-edge"
    source = {"object_type": "limitation", "object_id": None, "json_pointer": "/limitations"}
    traversal["nodes"].append({
        "node_id": limitation_id, "node_type": "limitation",
        "label": "Synthetic evidence scope requires review", "status": "reviewable",
        "source": deepcopy(source), "attributes": {"review_status": "needs_review"},
        "evidence_ids": [], "source_references": [], "dimensions": ["limitations"],
    })
    traversal["edges"].append({
        "edge_id": edge_id, "edge_type": "has_limitation",
        "source_node_id": scenario_node, "target_node_id": limitation_id,
        "directed": True, "status": "reviewable", "source": deepcopy(source),
        "supporting_node_ids": [], "evidence_ids": [], "source_references": [],
        "attributes": {}, "dimensions": ["limitations"],
    })
    traversal["paths"].append({
        "seed_node_id": scenario_node, "target_node_id": limitation_id, "depth": 1,
        "node_ids": [scenario_node, limitation_id], "edge_ids": [edge_id],
    })
    traversal["nodes"].sort(key=lambda node: node["node_id"])
    traversal["edges"].sort(key=lambda edge: edge["edge_id"])
    _sync(context)
    return context


def _containers(value: object) -> set[int]:
    if not isinstance(value, (Mapping, list)):
        return set()
    result = {id(value)}
    for child in value.values() if isinstance(value, Mapping) else value:
        result.update(_containers(child))
    return result


def test_manually_reviewed_fixture_and_public_contract() -> None:
    context, expected = _context(), _read(EXPECTED_PATH)
    result = extract_graphrag_gate_signals(context)
    assert result == expected
    assert set(result) == {
        "schema_version", "corpus_id", "graph_id", "scenario_id", "source_ground_truth",
        "query", "topical_relevance", "evidence_answerability", "warnings", "metadata",
    }
    assert result["schema_version"] == GRAPHRAG_GATE_SIGNALS_SCHEMA_VERSION == "graphrag-gate-signals/v1"
    assert set(result["topical_relevance"]) == set(TOPICAL_FIELDS)
    assert set(result["evidence_answerability"]) == set(ANSWERABILITY_FIELDS)
    assert result["query"] == context["query"]
    assert result["source_ground_truth"] == context["source_ground_truth"]
    assert result["metadata"] == {
        "decision_made": False,
        "score_interpretations": {
            "rrf": "reciprocal_rank_fusion_not_probability",
            "bm25": "bm25_relevance_not_probability",
            "cosine": "cosine_similarity_not_probability",
        },
        "topical_signal_count": 10, "answerability_signal_count": 14,
    }
    for name in TOPICAL_FIELDS:
        value = result["topical_relevance"][name]
        if name.endswith("_count"):
            assert type(value) is int
        elif value is not None:
            assert type(value) in (int, float)
    answerability = result["evidence_answerability"]
    assert type(answerability["traversal_performed"]) is bool
    for name in ANSWERABILITY_FIELDS:
        if name.endswith("_count") or name.startswith("hits_with_"):
            assert type(answerability[name]) is int
    assert json.loads(_serialize(result)) == result
    assert "confirmed" not in _serialize(result).decode("utf-8").casefold()
    assert graphrag.extract_graphrag_gate_signals is gate_signals.extract_graphrag_gate_signals
    assert graphrag.extract_graphrag_relevance_signals is relevance.extract_graphrag_relevance_signals
    assert graphrag.GraphRAGGateSignalError is gate_signals.GraphRAGGateSignalError
    assert issubclass(GraphRAGGateSignalError, ValueError)


def test_chunk_and_status_vocabularies_include_observed_counts_and_zeroes() -> None:
    result = extract_graphrag_gate_signals(_context())["evidence_answerability"]
    assert list(result["chunk_type_counts"]) == list(CHUNK_TYPES)
    assert result["chunk_type_counts"] == dict(zip(CHUNK_TYPES, (1, 0, 1, 0, 0, 2, 1, 0)))
    assert list(result["status_counts"]) == sorted(STATUSES)
    assert result["status_counts"] == dict(zip(STATUSES, (1, 1, 2, 1)))
    assert all(type(value) is int for value in result["chunk_type_counts"].values())
    assert all(type(value) is int for value in result["status_counts"].values())


def test_top_component_scores_use_maximum_among_returned_hits_without_recomputation() -> None:
    context = _context()
    context["retrieval"]["metadata"].update(
        lexical_candidate_count=9, vector_candidate_count=9, union_candidate_count=10,
    )
    # These provided scores deliberately do not reproduce component ranks/RRF.
    context["retrieval"]["hits"][4]["score"] = 0.7
    context["retrieval"]["hits"][3]["components"]["lexical"]["score"] = 12.5
    context["retrieval"]["hits"][2]["components"]["vector"]["score"] = 0.91
    for hit, mapping in zip(context["retrieval"]["hits"], context["seed_mapping"]["hit_mappings"]):
        mapping["hit_score"] = hit["score"]
        mapping["components"] = deepcopy(hit["components"])
    signals = extract_graphrag_gate_signals(context)["topical_relevance"]
    assert signals["retrieval_hit_count"] == 5
    assert signals["returned_top_rrf_score"] == 0.7
    assert signals["returned_top_bm25_score"] == 12.5
    assert signals["returned_top_cosine_score"] == 0.91


@pytest.mark.parametrize("mode,counts", [
    ("lexical", (5, 0, 0)), ("vector", (0, 5, 0)), ("joint", (5, 5, 5)),
])
def test_lexical_vector_and_joint_membership_with_absent_scores(mode: str, counts: tuple) -> None:
    context = _context()
    original = context["retrieval"]["hits"][0]["components"]["lexical"]
    for hit in context["retrieval"]["hits"]:
        if mode == "lexical":
            hit["components"]["vector"] = None
        if mode == "vector":
            hit["components"]["lexical"] = None
        elif hit["components"]["lexical"] is None:
            hit["components"]["lexical"] = deepcopy(original)
    _sync(context)
    result = extract_graphrag_gate_signals(context)["topical_relevance"]
    assert tuple(result[name] for name in (
        "lexical_hit_count", "vector_hit_count", "joint_lexical_vector_hit_count",
    )) == counts
    assert (result["returned_top_bm25_score"] is None) == (mode == "vector")
    assert (result["returned_top_cosine_score"] is None) == (mode == "lexical")


def test_query_coverage_uses_unique_nfkc_casefolded_exact_title_and_content_tokens() -> None:
    context = _context()
    context["query"].update(
        text="ＡＬＰＨＡ alpha β absent absent", normalized_terms=["alpha", "β", "absent"],
    )
    for hit in context["retrieval"]["hits"]:
        hit["chunk"]["title"] = "alphabet"
        hit["chunk"]["content"] = "unrelated"
    context["retrieval"]["hits"][0]["chunk"]["title"] = "Alpha alphabet"
    context["retrieval"]["hits"][1]["chunk"]["content"] = "β beta"
    # Token-like opaque metadata/labels are not retrieval text support.
    context["retrieval"]["hits"][2]["chunk"]["metadata"]["narrative"] = "absent"
    context["traversal"]["nodes"][0]["label"] = "absent"
    _sync(context)
    result = extract_graphrag_gate_signals(context)["topical_relevance"]
    assert set(tokenize_retrieval_text(context["query"]["text"])) == {"alpha", "β", "absent"}
    assert result["query_token_count"] == 3
    assert result["matched_query_token_count"] == 2
    assert result["query_token_coverage"] == 0.66666667


def test_tokenless_text_has_zero_coverage_without_trusting_normalized_term_echo() -> None:
    context = _context()
    context["query"]["text"] = "!!!"
    # The legacy contract validates a nonempty term echo but does not retokenize.
    _sync(context)
    result = extract_graphrag_gate_signals(context)["topical_relevance"]
    assert result["query_token_count"] == result["matched_query_token_count"] == 0
    assert result["query_token_coverage"] == 0.0


def test_source_reference_dedup_is_canonical_and_includes_source_file() -> None:
    context = _context()
    hits = context["retrieval"]["hits"]
    assert list(hits[0]["chunk"]["source_references"][0]) != list(hits[1]["chunk"]["source_references"][0])
    baseline = extract_graphrag_gate_signals(context)["evidence_answerability"]
    assert (baseline["hits_with_evidence_ids"], baseline["hits_with_source_references"],
            baseline["unique_source_reference_count"]) == (3, 4, 4)
    hits[4]["chunk"]["source_references"] = [{
        "raw_record_ref": "fixture:record:1", "source_file": "another_synthetic.jsonl",
    }]
    result = extract_graphrag_gate_signals(context)["evidence_answerability"]
    assert result["hits_with_source_references"] == 5
    assert result["unique_source_reference_count"] == 5


def test_traversal_counts_use_returned_node_and_edge_types_only() -> None:
    context = _context()
    result = extract_graphrag_gate_signals(context)["evidence_answerability"]
    assert tuple(result[name] for name in (
        "mapped_hit_count", "seed_node_count", "traversal_node_count",
        "traversal_edge_count", "traversal_path_count", "traversed_evidence_node_count",
        "traversed_limitation_node_count", "support_edge_count",
    )) == (5, 5, 13, 17, 26, 2, 1, 11)
    for edge in context["traversal"]["edges"]:
        if edge["edge_type"] == "supports_assessment":
            edge["edge_type"] = "supports_assessment_like"
    assert extract_graphrag_gate_signals(context)["evidence_answerability"]["support_edge_count"] == 9


def test_empty_hits_give_null_scores_and_zero_answerability_counts() -> None:
    context = _context()
    context["retrieval"]["hits"] = []
    context["seed_mapping"]["hit_mappings"] = []
    context["seed_mapping"]["seed_node_ids"] = []
    context["traversal"] = None
    _sync(context)
    result = extract_graphrag_gate_signals(context)
    for name, value in result["topical_relevance"].items():
        if name.startswith("returned_top_"):
            assert value is None
        elif name == "query_token_count":
            assert value == 3
        else:
            assert value == 0
    for name, value in result["evidence_answerability"].items():
        if isinstance(value, dict):
            assert set(value.values()) == {0}
        else:
            assert value == 0
    assert result["warnings"] == context["warnings"]


@pytest.mark.parametrize("mapping_state,expected_mapped", [("none", 0), ("retained", 5), ("partial", 4)])
def test_hits_without_seeds_or_traversal_and_partial_successful_mappings(
    mapping_state: str, expected_mapped: int,
) -> None:
    context = _context()
    if mapping_state == "none":
        context["seed_mapping"]["hit_mappings"] = []
    elif mapping_state == "partial":
        context["seed_mapping"]["hit_mappings"][0]["matched_node_ids"] = []
    context["seed_mapping"]["seed_node_ids"] = []
    context["traversal"] = None
    _sync(context)
    result = extract_graphrag_gate_signals(context)
    assert result["topical_relevance"]["retrieval_hit_count"] == 5
    answerability = result["evidence_answerability"]
    assert answerability["mapped_hit_count"] == expected_mapped
    assert answerability["seed_node_count"] == 0
    assert answerability["traversal_performed"] is False
    assert all(answerability[name] == 0 for name in ANSWERABILITY_FIELDS
               if name.startswith("traversal_") or name.startswith("traversed_") or name == "support_edge_count")


def test_warnings_keep_stage_order_and_deduplicate_without_making_a_decision() -> None:
    context = _context()
    context["warnings"] = ["z root", "shared", "z root"]
    context["retrieval"]["warnings"] = ["a retrieval", "shared"]
    context["seed_mapping"]["warnings"] = ["c mapping", "shared"]
    context["traversal"]["warnings"] = ["b traversal", "a retrieval"]
    result = extract_graphrag_gate_signals(context)
    assert result["warnings"] == ["z root", "shared", "a retrieval", "c mapping", "b traversal"]
    assert result["metadata"]["decision_made"] is False


@pytest.mark.parametrize("value", [None, [], 1, "context", {}])
def test_malformed_context_roots_fail_closed(value: object) -> None:
    with pytest.raises(GraphRAGGateSignalError):
        extract_graphrag_gate_signals(value)


@pytest.mark.parametrize("path,value", [
    (("schema_version",), "graphrag-context/v2"),
    (("query",), []),
    (("source_ground_truth", "sha256"), "invalid"),
    (("retrieval", "hits", 0, "components"), {"lexical": None, "vector": None}),
    (("retrieval", "hits", 0, "chunk", "chunk_type"), "unknown"),
    (("retrieval", "hits", 0, "chunk", "status"), "unsupported"),
    (("retrieval", "hits", 0, "chunk", "source_references"), {}),
    (("seed_mapping", "hit_mappings", 0, "hit_score"), 0.9),
    (("traversal", "edges", 0, "target_node_id"), "dangling"),
    (("traversal", "paths", 0, "target_node_id"), "dangling"),
])
def test_malformed_nested_values_fail_closed_without_input_repair(path: tuple, value: object) -> None:
    context = _context()
    _at(context, path[:-1])[path[-1]] = value
    before = deepcopy(context)
    with pytest.raises(GraphRAGGateSignalError):
        extract_graphrag_gate_signals(context)
    assert context == before


@pytest.mark.parametrize("path", [
    (), ("query",), ("source_ground_truth",), ("retrieval", "hits", 0),
    ("retrieval", "hits", 0, "chunk"), ("seed_mapping",), ("traversal",),
])
def test_unknown_structural_fields_are_rejected(path: tuple) -> None:
    context = _context()
    _at(context, path)["unexpected"] = "synthetic"
    with pytest.raises(GraphRAGGateSignalError):
        extract_graphrag_gate_signals(context)


@pytest.mark.parametrize("path", [
    ("metadata", "retrieval_hit_count"), ("metadata", "mapped_hit_count"),
    ("metadata", "traversed_node_count"), ("retrieval", "metadata", "union_candidate_count"),
    ("seed_mapping", "metadata", "seed_node_count"), ("traversal", "metadata", "edge_count"),
])
def test_inconsistent_source_counts_are_rejected(path: tuple) -> None:
    context = _context()
    _at(context, path[:-1])[path[-1]] += 1
    with pytest.raises(GraphRAGGateSignalError):
        extract_graphrag_gate_signals(context)


@pytest.mark.parametrize("path,value", [
    (("query", "top_k"), True),
    (("metadata", "retrieval_hit_count"), True),
    (("metadata", "traversal_performed"), 1),
    (("retrieval", "hits", 0, "score"), True),
    (("retrieval", "hits", 0, "components", "lexical", "score"), float("nan")),
    (("retrieval", "hits", 0, "components", "vector", "score"), float("inf")),
    (("retrieval", "hits", 0, "components", "vector", "score"), -float("inf")),
    (("seed_mapping", "metadata", "seed_node_count"), True),
    (("traversal", "paths", 0, "depth"), True),
    (("traversal", "edges", 0, "directed"), 1),
])
def test_bool_as_integer_nonfinite_numbers_and_invalid_booleans_fail_closed(path: tuple, value: object) -> None:
    context = _context()
    _at(context, path[:-1])[path[-1]] = value
    with pytest.raises(GraphRAGGateSignalError):
        extract_graphrag_gate_signals(context)


@pytest.mark.parametrize("duplicate", ["hit", "mapping", "seed", "node", "edge", "reference"])
def test_duplicate_identity_and_reference_structures_are_rejected(duplicate: str) -> None:
    context = _context()
    targets = {
        "hit": context["retrieval"]["hits"],
        "mapping": context["seed_mapping"]["hit_mappings"],
        "seed": context["seed_mapping"]["seed_node_ids"],
        "node": context["traversal"]["nodes"],
        "edge": context["traversal"]["edges"],
        "reference": context["retrieval"]["hits"][0]["chunk"]["source_references"],
    }
    targets[duplicate].append(deepcopy(targets[duplicate][0]))
    if duplicate == "hit":
        context["query"]["top_k"] = len(context["retrieval"]["hits"])
    _sync(context)
    with pytest.raises(GraphRAGGateSignalError):
        extract_graphrag_gate_signals(context)


@pytest.mark.parametrize("path,value", [
    (("retrieval", "hits", 0, "chunk", "status"), "confirmed"),
    (("traversal", "nodes", 0, "status"), "confirmed"),
    (("traversal", "edges", 0, "status"), "confirmed"),
    (("retrieval", "hits", 0, "chunk", "metadata"), {"nested": [{"review_status": " ConFirMed "}]}),
    (("traversal", "nodes", 0, "attributes"), {"nested": {"status": ["confirmed"]}}),
    (("traversal", "edges", 0, "attributes"), {"nested": {"analysis_status": "confirmed"}}),
])
def test_recursive_status_guard_rejects_confirmed(path: tuple, value: object) -> None:
    context = _context()
    _at(context, path[:-1])[path[-1]] = value
    with pytest.raises(GraphRAGGateSignalError):
        extract_graphrag_gate_signals(context)


@pytest.mark.parametrize("value", [(1, 2), {1: "value"}, "\ud800", object(), float("nan")])
def test_opaque_values_still_require_native_finite_utf8_json(value: object) -> None:
    context = _context()
    context["retrieval"]["hits"][0]["chunk"]["metadata"]["opaque"] = value
    with pytest.raises(GraphRAGGateSignalError):
        extract_graphrag_gate_signals(context)


def test_circular_opaque_input_fails_closed_without_mutation() -> None:
    context = _context()
    opaque = context["retrieval"]["hits"][0]["chunk"]["metadata"]
    opaque["cycle"] = opaque
    with pytest.raises(GraphRAGGateSignalError):
        extract_graphrag_gate_signals(context)
    assert opaque["cycle"] is opaque


def test_benchmark_labels_in_opaque_metadata_cannot_supply_production_signals() -> None:
    context = _context()
    before = extract_graphrag_gate_signals(context)
    for hit in context["retrieval"]["hits"]:
        hit["chunk"]["metadata"]["benchmark_only"] = {
            "expected_decision": "proceed", "category": "relevant_direct",
            "language": "vi", "case_id": "synthetic-benchmark-label",
            "relevance_judgments": [99], "count_claim": 999999,
        }
    for node in context["traversal"]["nodes"]:
        node["attributes"]["benchmark_only"] = {"expected_decision": "abstain", "case_id": "other"}
    assert extract_graphrag_gate_signals(context) == before


@pytest.mark.parametrize("key", ["expected_answer", "reference-answer"])
def test_answer_fields_are_rejected_or_remain_unavailable_to_the_extractor(key: str) -> None:
    context = _context()
    baseline = extract_graphrag_gate_signals(context)
    context["retrieval"]["hits"][0]["chunk"]["metadata"][key] = "synthetic benchmark text"
    if key == "expected_answer":
        with pytest.raises(GraphRAGGateSignalError):
            extract_graphrag_gate_signals(context)
    else:
        assert extract_graphrag_gate_signals(context) == baseline


def test_output_is_detached_immutable_byte_deterministic_and_json_safe() -> None:
    context = _context()
    before = deepcopy(context)
    first = extract_graphrag_gate_signals(context)
    second = extract_graphrag_gate_signals(context)
    assert context == before
    assert _serialize(first) == _serialize(second)
    assert _containers(first).isdisjoint(_containers(context))
    assert _containers(first).isdisjoint(_containers(second))
    first["query"]["filters"]["chunk_types"] = ["evidence"]
    first["source_ground_truth"]["path"] = "changed-synthetic.json"
    first["topical_relevance"]["retrieval_hit_count"] = 999
    first["evidence_answerability"]["chunk_type_counts"]["entity"] = 999
    first["warnings"].append("changed")
    first["metadata"]["score_interpretations"]["rrf"] = "changed"
    assert context == before
    assert second == extract_graphrag_gate_signals(context)


def test_mapping_insertion_order_does_not_change_canonical_serialization() -> None:
    def reordered(value: object) -> object:
        if isinstance(value, dict):
            return {key: reordered(item) for key, item in reversed(list(value.items()))}
        if isinstance(value, list):
            return [reordered(item) for item in value]
        return value

    context = _context()
    assert _serialize(extract_graphrag_gate_signals(context)) == _serialize(
        extract_graphrag_gate_signals(reordered(context)),
    )
    assert extract_graphrag_gate_signals(MappingProxyType(context)) == extract_graphrag_gate_signals(context)


def test_extraction_needs_no_files_network_model_clock_random_or_uuid(monkeypatch) -> None:
    context = _context()

    def forbidden(*args, **kwargs):
        pytest.fail("The signal extractor attempted an external or nondeterministic operation")

    from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend
    for owner, name in (
        (builtins, "open"), (io, "open"), (Path, "open"), (socket, "socket"),
        (socket, "create_connection"), (time, "time"), (time, "monotonic"),
        (random, "random"), (uuid, "uuid4"), (SentenceTransformerEmbeddingBackend, "__init__"),
    ):
        monkeypatch.setattr(owner, name, forbidden)
    assert extract_graphrag_gate_signals(context)["topical_relevance"]["retrieval_hit_count"] == 5


def test_generic_implementation_avoids_benchmarks_decisions_and_component_algorithms() -> None:
    source = IMPLEMENTATION_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for alias in node.names)
    assert not any(name and any(part in name for part in (
        "calibration", "evaluation", "embedding_backend", "sentence_transformers", "requests",
        "socket", "subprocess", "random", "uuid", "datetime", "time",
    )) for name in imports)
    calls = {node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert calls.isdisjoint({
        "open", "retrieve_hybrid", "retrieve_lexical", "retrieve_vector",
        "map_hybrid_hits_to_graph_seeds", "traverse_knowledge_graph", "embed_query",
        "assess_graphrag_relevance", "uuid4",
    })
    for forbidden in ("expected_decision", "expected_answer", "case_id", "mshta", "powershell", "outputs/"):
        assert forbidden not in source.casefold()
    result = extract_graphrag_gate_signals(_context())
    keys = set()
    def collect(value: object) -> None:
        if isinstance(value, dict):
            keys.update(value)
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)
    collect(result)
    assert keys.isdisjoint({"policy", "policy_id", "decision", "reason_codes", "threshold", "security_conclusion"})
    assert result["metadata"]["decision_made"] is False


def test_unexpected_internal_exception_is_wrapped_in_gate_signal_error(monkeypatch) -> None:
    context = _context()
    def broken(*args, **kwargs):
        raise RuntimeError("synthetic tokenizer failure")
    monkeypatch.setattr(gate_signals, "tokenize_retrieval_text", broken)
    with pytest.raises(GraphRAGGateSignalError, match="synthetic tokenizer failure"):
        extract_graphrag_gate_signals(context)


@pytest.mark.parametrize("name", legacy_tests.CASE_NAMES)
def test_public_legacy_signals_and_existing_decisions_remain_byte_for_byte(name: str) -> None:
    context, policy = legacy_tests._case(name)
    expected_fragment = _read(LEGACY_EXPECTED_PATH)["cases"][name]
    public_signals = extract_graphrag_relevance_signals(context)
    assert _serialize(public_signals) == _serialize(expected_fragment["signals"])
    expected = {
        "schema_version": "graphrag-relevance-decision/v1",
        "scenario_id": context["scenario_id"], "query": context["query"],
        "policy_id": policy["policy_id"], **expected_fragment,
        "warnings": sorted(set(context["warnings"] + context["retrieval"]["warnings"]
                               + context["seed_mapping"]["warnings"]
                               + (context["traversal"]["warnings"] if context["traversal"] is not None else []))),
        "metadata": {
            "context_schema_version": context["schema_version"],
            "policy_schema_version": policy["schema_version"],
            "corpus_id": context["corpus_id"], "graph_id": context["graph_id"],
            "source_ground_truth": context["source_ground_truth"], "policy": policy,
            "score_interpretation": "bm25_cosine_rrf_not_probabilities",
            "decision_interpretation": "context_eligibility_only",
        },
    }
    assert _serialize(assess_graphrag_relevance(context, policy=policy)) == _serialize(expected)


def test_public_legacy_signal_api_detaches_containers_and_rejects_malformed_contexts() -> None:
    context = _context()
    before = deepcopy(context)
    first = extract_graphrag_relevance_signals(context)
    second = extract_graphrag_relevance_signals(MappingProxyType(context))
    assert first == second
    assert context == before
    assert _containers(first).isdisjoint(_containers(context))
    assert _containers(first).isdisjoint(_containers(second))
    first["retrieval_hit_count"] = 999
    assert second["retrieval_hit_count"] == 5
    context["metadata"]["retrieval_hit_count"] = True
    with pytest.raises(relevance.GraphRAGRelevanceError):
        extract_graphrag_relevance_signals(context)
