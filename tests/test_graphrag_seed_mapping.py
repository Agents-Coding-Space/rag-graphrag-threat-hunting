"""Exact provenance contracts with read-only fixtures and synthetic hybrid hits."""

from __future__ import annotations

import ast
import builtins
from collections import Counter
from collections.abc import Iterator
from copy import deepcopy
from hashlib import sha256
import io
import json
import math
import os
from pathlib import Path
import random
import socket
import sys
import time
from typing import Any
import uuid

import pytest

from threat_hunting import graph as graph_package
from threat_hunting import retrieval as retrieval_package
from threat_hunting.graph import validate_knowledge_graph
from threat_hunting.graphrag import (
    GRAPH_SEED_MAP_SCHEMA_VERSION,
    GraphSeedMappingError,
    map_hybrid_hits_to_graph_seeds,
)
from threat_hunting.graphrag import seed_mapping as mapping_module
from threat_hunting.retrieval import tokenize_retrieval_text, validate_retrieval_corpus


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "tests/fixtures/retrieval/builder/expected_retrieval_corpus.json"
GRAPH_PATH = ROOT / "tests/fixtures/graph/builder/expected_knowledge_graph.json"
DECISIONS_PATH = ROOT / "configs/ground_truth/mshta_powershell.json"
IMPLEMENTATION_PATH = ROOT / "src/threat_hunting/graphrag/seed_mapping.py"
RESULT_FIELDS = {
    "schema_version", "corpus_id", "graph_id", "scenario_id", "source_ground_truth",
    "retrieval_method", "query", "hit_mappings", "seed_node_ids", "warnings", "metadata",
}
MAPPING_FIELDS = {
    "hit_rank", "hit_score", "components", "chunk_id", "chunk_type", "source",
    "mapping_kind", "matched_node_ids", "matched_edge_ids",
}
DIRECT_TYPES = (
    "scenario_summary", "entity", "fact", "evidence", "sigma_finding",
    "mitre_assessment", "limitation",
)


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def artifacts() -> tuple[dict[str, Any], dict[str, Any]]:
    corpus, graph = _json(CORPUS_PATH), _json(GRAPH_PATH)
    validate_retrieval_corpus(corpus)
    validate_knowledge_graph(graph)
    assert corpus["source_ground_truth"] == graph["source_ground_truth"]
    return corpus, graph


def _chunk(corpus: dict[str, Any], chunk_type: str) -> dict[str, Any]:
    return next(chunk for chunk in corpus["chunks"] if chunk["chunk_type"] == chunk_type)


def _key(source: dict[str, Any]) -> tuple[str, str | None, str]:
    return source["object_type"], source["object_id"], source["json_pointer"]


def _matching(graph: dict[str, Any], chunk: dict[str, Any]) -> dict[str, Any]:
    collection = "edges" if chunk["chunk_type"] == "relationship" else "nodes"
    matches = [item for item in graph[collection] if _key(item["source"]) == _key(chunk["source"])]
    assert len(matches) == 1
    return matches[0]


def _counts(graph: dict[str, Any]) -> None:
    graph["metadata"].update(
        node_count=len(graph["nodes"]), edge_count=len(graph["edges"]),
        node_type_counts=dict(Counter(node["node_type"] for node in graph["nodes"])),
        edge_type_counts=dict(Counter(edge["edge_type"] for edge in graph["edges"])),
    )


def _hybrid(
    corpus: dict[str, Any], chunks: list[dict[str, Any]],
    *, query: str = "synthetic", branch: str = "both",
) -> dict[str, Any]:
    """Build the returned Hybrid contract, without executing any retriever."""
    hits = []
    for rank, chunk in enumerate(chunks, start=1):
        components = {
            "lexical": {"rank": rank, "score": 2.0 / rank, "contribution": 0.016 / rank},
            "vector": {"rank": rank, "score": 0.5 / rank, "contribution": 0.015 / rank},
        }
        if branch in {"lexical", "vector"}:
            components["vector" if branch == "lexical" else "lexical"] = None
        hits.append({
            "rank": rank, "score": 0.5 / rank, "components": components,
            "chunk": deepcopy(chunk),
        })
    return {
        "schema_version": "retrieval-result/v1", "retrieval_method": "hybrid-rrf/v1",
        "corpus_id": corpus["corpus_id"], "scenario_id": corpus["scenario_id"],
        "query": {
            "text": query, "normalized_terms": list(dict.fromkeys(tokenize_retrieval_text(query))),
            "top_k": max(1, len(chunks)), "candidate_k": max(20, len(chunks)),
            "filters": {"chunk_types": None, "required_dimensions": None},
        },
        "hits": hits, "warnings": [],
        "metadata": {
            "total_chunks": len(corpus["chunks"]), "eligible_chunks": len(corpus["chunks"]),
            "returned_hits": len(hits),
            "lexical_candidate_count": 0 if branch == "vector" else len(hits),
            "vector_candidate_count": 0 if branch == "lexical" else len(hits),
            "union_candidate_count": len(hits), "rrf_k": 60, "score_precision": 12,
            "score_interpretation": "reciprocal_rank_fusion_not_probability",
            "component_methods": {"lexical": "bm25/v1", "vector": "vector-cosine/v1"},
        },
    }


def _mapped(
    artifacts: tuple[dict[str, Any], dict[str, Any]], chunk_type: str = "entity",
    **kwargs: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, chunk_type)], **kwargs)
    return map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph), hybrid


def _serialized(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"),
    ).encode("utf-8")


def _walk(value: object) -> Iterator[object]:
    yield value
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _assert_detached(copied: object, original: object) -> None:
    assert copied == original
    if isinstance(original, dict):
        assert copied is not original
        for key, value in original.items():
            _assert_detached(copied[key], value)
    elif isinstance(original, list):
        assert copied is not original
        for copied_item, original_item in zip(copied, original, strict=True):
            _assert_detached(copied_item, original_item)


def _reverse_objects(value: object) -> object:
    if isinstance(value, dict):
        return {key: _reverse_objects(item) for key, item in reversed(list(value.items()))}
    if isinstance(value, list):
        return [_reverse_objects(item) for item in value]
    return value


def test_public_exports_and_output_contract(artifacts) -> None:
    result, hybrid = _mapped(artifacts)
    corpus, graph = artifacts
    assert GRAPH_SEED_MAP_SCHEMA_VERSION == "graphrag-seed-map/v1"
    assert issubclass(GraphSeedMappingError, ValueError)
    assert map_hybrid_hits_to_graph_seeds is mapping_module.map_hybrid_hits_to_graph_seeds
    assert GraphSeedMappingError is mapping_module.GraphSeedMappingError
    assert set(result) == RESULT_FIELDS
    assert result["schema_version"] == GRAPH_SEED_MAP_SCHEMA_VERSION
    assert result["corpus_id"] == corpus["corpus_id"]
    assert result["graph_id"] == graph["graph_id"]
    assert result["scenario_id"] == corpus["scenario_id"]
    assert result["source_ground_truth"] == corpus["source_ground_truth"]
    assert result["query"] == hybrid["query"]
    assert result["retrieval_method"] == "hybrid-rrf/v1"
    assert result["metadata"] == {
        "retrieval_hit_count": 1, "mapped_hit_count": 1,
        "direct_node_mapping_count": 1, "relationship_edge_mapping_count": 0,
        "seed_node_count": 1,
    }


@pytest.mark.parametrize("chunk_type", DIRECT_TYPES)
def test_each_direct_chunk_type_maps_one_exact_node(artifacts, chunk_type: str) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, chunk_type)
    node = _matching(graph, chunk)
    result, hybrid = _mapped(artifacts, chunk_type)
    mapping = result["hit_mappings"][0]
    assert set(mapping) == MAPPING_FIELDS
    assert mapping == {
        "hit_rank": 1, "hit_score": hybrid["hits"][0]["score"],
        "components": hybrid["hits"][0]["components"], "chunk_id": chunk["chunk_id"],
        "chunk_type": chunk_type, "source": chunk["source"], "mapping_kind": "direct_node",
        "matched_node_ids": [node["node_id"]], "matched_edge_ids": [],
    }
    assert result["seed_node_ids"] == [node["node_id"]]
    if chunk_type in {"scenario_summary", "limitation"}:
        assert mapping["source"]["object_id"] is None


def test_original_fixture_scenario_maps_directly_without_input_changes(artifacts) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, "scenario_summary")
    scenario = _matching(graph, chunk)
    hybrid = _hybrid(corpus, [chunk])
    before = deepcopy((corpus, hybrid, graph))
    result = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    mapping = result["hit_mappings"][0]
    assert scenario["node_type"] == "scenario"
    assert _key(chunk["source"]) == _key(scenario["source"])
    assert chunk["source"]["object_id"] is None
    assert scenario["source"]["object_id"] is None
    assert len(result["hit_mappings"]) == 1
    assert mapping["mapping_kind"] == "direct_node"
    assert mapping["matched_node_ids"] == [scenario["node_id"]]
    assert mapping["matched_edge_ids"] == []
    assert result["seed_node_ids"] == [scenario["node_id"]]
    assert result["metadata"]["mapped_hit_count"] == 1
    assert result["metadata"]["seed_node_count"] == 1
    assert (corpus, hybrid, graph) == before


def test_scenario_source_mismatch_still_fails_closed_without_fallback(artifacts) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, "scenario_summary")
    scenario = _matching(graph, chunk)
    scenario["source"]["object_id"] = corpus["scenario_id"]
    validate_knowledge_graph(graph)
    hybrid = _hybrid(corpus, [chunk])
    before = deepcopy((corpus, hybrid, graph))
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    assert (corpus, hybrid, graph) == before


def test_every_fixture_chunk_has_one_exact_graph_match_and_mapping(artifacts) -> None:
    corpus, graph = artifacts
    # The synthetic builder fixture has 15 chunks; production coverage is checked
    # separately against the complete production corpus, which has 19 chunks.
    assert len(corpus["chunks"]) == 15
    indexes: dict[str, dict[tuple[str, str | None, str], list[dict[str, Any]]]] = {
        "nodes": {}, "edges": {},
    }
    for collection in indexes:
        for item in graph[collection]:
            indexes[collection].setdefault(_key(item["source"]), []).append(item)
    unmatched = ambiguous = 0
    matched_by_chunk = {}
    for chunk in corpus["chunks"]:
        collection = "edges" if chunk["chunk_type"] == "relationship" else "nodes"
        matches = indexes[collection].get(_key(chunk["source"]), [])
        unmatched += len(matches) == 0
        ambiguous += len(matches) > 1
        if len(matches) == 1:
            matched_by_chunk[chunk["chunk_id"]] = matches[0]
    assert unmatched == ambiguous == 0
    assert len(matched_by_chunk) == len(corpus["chunks"])
    hybrid = _hybrid(corpus, corpus["chunks"])
    before = deepcopy((corpus, hybrid, graph))
    result = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    expected_seeds = set()
    for mapping, chunk in zip(result["hit_mappings"], corpus["chunks"], strict=True):
        item = matched_by_chunk[chunk["chunk_id"]]
        assert mapping["chunk_id"] == chunk["chunk_id"]
        assert mapping["source"] == chunk["source"]
        assert _key(mapping["source"]) == _key(item["source"])
        if chunk["chunk_type"] == "relationship":
            node_ids = sorted({item["source_node_id"], item["target_node_id"]})
            assert mapping["mapping_kind"] == "relationship_edge"
            assert mapping["matched_edge_ids"] == [item["edge_id"]]
        else:
            node_ids = [item["node_id"]]
            assert mapping["mapping_kind"] == "direct_node"
            assert mapping["matched_edge_ids"] == []
            assert item["node_type"] == chunk["source"]["object_type"]
        assert mapping["matched_node_ids"] == node_ids
        expected_seeds.update(node_ids)
    assert result["seed_node_ids"] == sorted(expected_seeds)
    assert result["metadata"]["retrieval_hit_count"] == len(corpus["chunks"])
    assert result["metadata"]["mapped_hit_count"] == len(corpus["chunks"])
    assert result["metadata"]["direct_node_mapping_count"] == 13
    assert result["metadata"]["relationship_edge_mapping_count"] == 2
    assert (corpus, hybrid, graph) == before


def test_relationship_hit_retains_edge_and_only_its_two_endpoints(artifacts) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, "relationship")
    edge = _matching(graph, chunk)
    result, _ = _mapped(artifacts, "relationship")
    seeds = sorted({edge["source_node_id"], edge["target_node_id"]})
    assert len(seeds) == 2
    assert result["seed_node_ids"] == seeds
    assert result["hit_mappings"][0]["mapping_kind"] == "relationship_edge"
    assert result["hit_mappings"][0]["matched_edge_ids"] == [edge["edge_id"]]
    assert result["hit_mappings"][0]["matched_node_ids"] == seeds
    assert set(edge["supporting_node_ids"]).isdisjoint(seeds)
    assert result["metadata"] == {
        "retrieval_hit_count": 1, "mapped_hit_count": 1,
        "direct_node_mapping_count": 0, "relationship_edge_mapping_count": 1,
        "seed_node_count": 2,
    }


def test_relationship_predicate_and_direction_are_not_security_inferences(artifacts) -> None:
    corpus, graph = artifacts
    edge = _matching(graph, _chunk(corpus, "relationship"))
    edge.update(edge_type="supports", directed=False)
    _counts(graph)
    before = deepcopy(graph)
    result, _ = _mapped(artifacts, "relationship")
    assert result["hit_mappings"][0]["matched_edge_ids"] == [edge["edge_id"]]
    assert graph == before
    assert "supports" not in list(_walk(result))


def test_multiple_hits_to_same_node_deduplicate_without_losing_provenance(artifacts) -> None:
    corpus, graph = artifacts
    original = _chunk(corpus, "entity")
    duplicate = deepcopy(original)
    duplicate["chunk_id"] = "synthetic-alternative-chunk"
    corpus["chunks"].append(duplicate)
    corpus["metadata"]["chunk_count"] = len(corpus["chunks"])
    hybrid = _hybrid(corpus, [original, duplicate])
    result = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    node = _matching(graph, original)
    assert result["seed_node_ids"] == [node["node_id"]]
    assert len(result["hit_mappings"]) == 2
    assert [mapping["chunk_id"] for mapping in result["hit_mappings"]] == [
        original["chunk_id"], duplicate["chunk_id"],
    ]
    assert result["metadata"]["mapped_hit_count"] == 2
    assert result["metadata"]["seed_node_count"] == 1


def test_overlapping_relationship_and_direct_hits_keep_separate_mappings(artifacts) -> None:
    corpus, graph = artifacts
    relationships = [chunk for chunk in corpus["chunks"] if chunk["chunk_type"] == "relationship"]
    direct = _chunk(corpus, "entity")
    hybrid = _hybrid(corpus, [*relationships, direct])
    result = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    expected = {_matching(graph, direct)["node_id"]}
    for chunk in relationships:
        edge = _matching(graph, chunk)
        expected.update((edge["source_node_id"], edge["target_node_id"]))
    assert result["seed_node_ids"] == sorted(expected)
    assert len(result["hit_mappings"]) == 3
    assert result["metadata"]["direct_node_mapping_count"] == 1
    assert result["metadata"]["relationship_edge_mapping_count"] == 2


@pytest.mark.parametrize("branch", ["both", "lexical", "vector"])
def test_rank_scores_components_and_branch_absence_are_preserved(artifacts, branch: str) -> None:
    corpus, graph = artifacts
    chunks = [_chunk(corpus, "evidence"), _chunk(corpus, "entity")]
    hybrid = _hybrid(corpus, chunks, branch=branch)
    # These scores intentionally do not equal a recalculated RRF sum.
    hybrid["hits"][0]["score"] = 0.875
    result = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    for mapping, hit in zip(result["hit_mappings"], hybrid["hits"], strict=True):
        assert mapping["hit_rank"] == hit["rank"]
        assert mapping["hit_score"] == hit["score"]
        _assert_detached(mapping["components"], hit["components"])
        assert not {"probability", "confidence"}.intersection(mapping)


def test_empty_hits_return_empty_seeds_zero_counts_and_clear_warning(artifacts) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [])
    hybrid["warnings"] = ["hybrid: Neither lexical nor vector retrieval returned candidate hits."]
    result = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    assert result["hit_mappings"] == result["seed_node_ids"] == []
    assert set(result["metadata"].values()) == {0}
    assert any("hit" in warning.casefold() and "seed" in warning.casefold()
               for warning in result["warnings"])
    assert set(hybrid["warnings"]).issubset(result["warnings"])


def test_inputs_are_unchanged_and_every_output_container_is_detached(artifacts) -> None:
    corpus, graph = artifacts
    chunks = corpus["chunks"]
    hybrid = _hybrid(corpus, chunks, query="  Hành vi synthetic?  ")
    hybrid["warnings"] = ["Synthetic audit warning."]
    before = deepcopy((corpus, hybrid, graph))
    first = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    second = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    assert (corpus, hybrid, graph) == before
    _assert_detached(first["source_ground_truth"], corpus["source_ground_truth"])
    _assert_detached(first["query"], hybrid["query"])
    for mapping, hit in zip(first["hit_mappings"], hybrid["hits"], strict=True):
        _assert_detached(mapping["source"], hit["chunk"]["source"])
        _assert_detached(mapping["components"], hit["components"])
        mapping["source"]["json_pointer"] = "/changed"
        mapping["components"]["lexical"]["score"] = 999.0
        mapping["matched_node_ids"].append("changed")
        mapping["matched_edge_ids"].append("changed")
    first["source_ground_truth"]["path"] = "changed.json"
    first["query"]["normalized_terms"].append("changed")
    first["query"]["filters"]["chunk_types"] = ["evidence"]
    first["warnings"].append("changed")
    first["seed_node_ids"].append("changed")
    first["metadata"]["mapped_hit_count"] = -1
    assert (corpus, hybrid, graph) == before
    assert second == map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


def test_repeat_runs_reversed_nodes_edges_and_dict_order_are_byte_identical(artifacts) -> None:
    corpus, graph = artifacts
    chunks = [_chunk(corpus, name) for name in ("relationship", "entity", "mitre_assessment")]
    hybrid = _hybrid(corpus, chunks)
    first = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    graph["nodes"].reverse()
    graph["edges"].reverse()
    second = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    reversed_inputs = [_reverse_objects(value) for value in (corpus, hybrid, graph)]
    third = map_hybrid_hits_to_graph_seeds(*reversed_inputs)
    assert first == second == third
    assert _serialized(first) == _serialized(second) == _serialized(third)
    assert json.loads(_serialized(first)) == first
    assert [mapping["hit_rank"] for mapping in first["hit_mappings"]] == [1, 2, 3]


def test_source_warnings_are_deep_copied_with_original_order(artifacts) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["warnings"] = ["vector: z warning", "lexical: a warning"]
    result = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    assert result["warnings"] == hybrid["warnings"]
    assert result["warnings"] is not hybrid["warnings"]


@pytest.mark.parametrize("kind", ["corpus", "graph"])
@pytest.mark.parametrize("failure", ["root", "schema", "missing_field", "bad_nested", "duplicate_id"])
def test_existing_input_validators_reject_invalid_artifacts(artifacts, kind: str, failure: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    target = corpus if kind == "corpus" else graph
    if failure == "root":
        if kind == "corpus":
            corpus = []
        else:
            graph = []
    elif failure == "schema":
        target["schema_version"] = "invalid/v1"
    elif failure == "missing_field":
        del target["warnings"]
    elif failure == "bad_nested":
        target["source_ground_truth"]["sha256"] = "bad"
    else:
        items, field = (target["chunks"], "chunk_id") if kind == "corpus" else (target["nodes"], "node_id")
        items[1][field] = items[0][field]
    before = deepcopy((corpus, hybrid, graph))
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    assert (corpus, hybrid, graph) == before


@pytest.mark.parametrize("operation", ["validate_retrieval_corpus", "validate_knowledge_graph"])
def test_existing_validators_are_called_and_their_errors_are_wrapped(artifacts, monkeypatch, operation) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    failure = RuntimeError("Synthetic validator failure")

    def reject(value: object) -> None:
        assert value is (corpus if operation == "validate_retrieval_corpus" else graph)
        raise failure

    monkeypatch.setattr(mapping_module, operation, reject)
    with pytest.raises(GraphSeedMappingError) as error:
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    assert error.value.__cause__ is failure


@pytest.mark.parametrize("kind", ["schema_version", "lexical", "vector", "corpus_id", "scenario_id"])
def test_wrong_retrieval_schema_method_or_identity_is_rejected(artifacts, kind: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    field = "retrieval_method" if kind in {"lexical", "vector"} else kind
    hybrid[field] = {"lexical": "bm25/v1", "vector": "vector-cosine/v1"}.get(kind, "wrong/v1")
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("location", ["graph", "hybrid", "corpus_chunk", "hit_chunk"])
def test_scenario_id_must_match_every_artifact_and_chunk(artifacts, location: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    if location == "graph":
        graph["scenario_id"] = graph["source_ground_truth"]["scenario_id"] = "scenario-other"
        validate_knowledge_graph(graph)
    elif location == "hybrid":
        hybrid["scenario_id"] = "scenario-other"
    elif location == "corpus_chunk":
        corpus["chunks"][0]["scenario_id"] = "scenario-other"
    else:
        hybrid["hits"][0]["chunk"]["scenario_id"] = "scenario-other"
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("field", ["path", "schema_version", "sha256", "scenario_id"])
def test_ground_truth_provenance_mismatches_fail_closed(artifacts, field: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    graph["source_ground_truth"][field] = {
        "path": "another/logical_ground_truth.json", "schema_version": "other/v1",
        "sha256": "0" * 64, "scenario_id": "scenario-other",
    }[field]
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


def test_ground_truth_hash_casing_is_exact_and_not_normalized(artifacts) -> None:
    corpus, graph = artifacts
    graph["source_ground_truth"]["sha256"] = corpus["source_ground_truth"]["sha256"].upper()
    assert graph["source_ground_truth"]["sha256"] != corpus["source_ground_truth"]["sha256"]
    validate_knowledge_graph(graph)
    with pytest.raises(GraphSeedMappingError):
        _mapped(artifacts)


@pytest.mark.parametrize("rank", [0, 2, -1, True, 1.0, "1", None])
def test_hit_ranks_are_consecutive_integers_excluding_bool(artifacts, rank: object) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["hits"][0]["rank"] = rank
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


def test_duplicate_hit_chunk_ids_are_rejected(artifacts) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, "entity")
    hybrid = _hybrid(corpus, [chunk, chunk])
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("score", [math.nan, math.inf, -math.inf, 0, -1, True, False, "1", None, 10**1000])
def test_hit_scores_must_be_finite_positive_numbers(artifacts, score: object) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["hits"][0]["score"] = score
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("field", [
    "title", "content", "status", "source", "entity_ids", "fact_ids", "relationship_ids",
    "evidence_ids", "sigma_rule_ids", "mitre_external_ids", "source_references", "metadata",
])
def test_full_chunk_must_match_corpus_including_all_provenance(artifacts, field: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    changed = hybrid["hits"][0]["chunk"]
    original = changed[field]
    if isinstance(original, str):
        changed[field] = original + " changed"
    elif isinstance(original, dict):
        original["synthetic_extension"] = "changed"
    else:
        original.append("changed")
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("original,changed", [(1, True), (1, 1.0), (False, 0), (0.0, 0)])
def test_full_chunk_equality_preserves_json_scalar_types(artifacts, original: object, changed: object) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, "entity")
    chunk["metadata"]["typed_extension"] = {"items": [original]}
    hybrid = _hybrid(corpus, [chunk])
    hybrid["hits"][0]["chunk"]["metadata"]["typed_extension"]["items"][0] = changed
    assert hybrid["hits"][0]["chunk"] == chunk  # Python equality alone loses type distinctions.
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("field", ["object_type", "object_id", "json_pointer"])
@pytest.mark.parametrize("chunk_type", ["entity", "relationship"])
def test_missing_match_for_any_source_key_field_fails_closed(artifacts, field: str, chunk_type: str) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, chunk_type)
    item = _matching(graph, chunk)
    item["source"][field] = "/changed" if field == "json_pointer" else "changed"
    validate_knowledge_graph(graph)
    with pytest.raises(GraphSeedMappingError):
        _mapped(artifacts, chunk_type)


@pytest.mark.parametrize("chunk_type", ["entity", "relationship"])
def test_ambiguous_source_matches_fail_even_when_content_is_identical(artifacts, chunk_type: str) -> None:
    corpus, graph = artifacts
    item = deepcopy(_matching(graph, _chunk(corpus, chunk_type)))
    id_field, collection = ("edge_id", "edges") if chunk_type == "relationship" else ("node_id", "nodes")
    item[id_field] = "synthetic-ambiguous-object"
    graph[collection].append(item)
    _counts(graph)
    validate_knowledge_graph(graph)
    with pytest.raises(GraphSeedMappingError):
        _mapped(artifacts, chunk_type)


def test_wrong_node_type_cannot_be_hidden_by_correct_source_key(artifacts) -> None:
    corpus, graph = artifacts
    node = _matching(graph, _chunk(corpus, "entity"))
    node["node_type"] = "fact"
    _counts(graph)
    validate_knowledge_graph(graph)
    with pytest.raises(GraphSeedMappingError):
        _mapped(artifacts)


def test_ambiguity_is_not_resolved_by_filtering_wrong_node_type(artifacts) -> None:
    corpus, graph = artifacts
    extra = deepcopy(_matching(graph, _chunk(corpus, "entity")))
    extra.update(node_id="synthetic-ambiguous-wrong-type", node_type="fact")
    graph["nodes"].append(extra)
    _counts(graph)
    validate_knowledge_graph(graph)
    with pytest.raises(GraphSeedMappingError):
        _mapped(artifacts)


def test_relationship_source_on_node_does_not_substitute_for_missing_edge(artifacts) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, "relationship")
    edge = _matching(graph, chunk)
    edge["source"]["json_pointer"] += "/not_the_relationship"
    node = deepcopy(graph["nodes"][0])
    node.update(node_id="synthetic-relationship-node", node_type="relationship")
    node["source"] = {field: chunk["source"][field] for field in ("object_type", "object_id", "json_pointer")}
    graph["nodes"].append(node)
    _counts(graph)
    validate_knowledge_graph(graph)
    with pytest.raises(GraphSeedMappingError):
        _mapped(artifacts, "relationship")


def test_direct_source_on_edge_does_not_substitute_for_missing_node(artifacts) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, "entity")
    _matching(graph, chunk)["source"]["json_pointer"] += "/not_the_entity"
    graph["edges"][0]["source"] = {
        field: chunk["source"][field] for field in ("object_type", "object_id", "json_pointer")
    }
    validate_knowledge_graph(graph)
    with pytest.raises(GraphSeedMappingError):
        _mapped(artifacts)


@pytest.mark.parametrize("chunk_type", ["entity", "relationship", "mitre_assessment", "sigma_finding"])
def test_title_content_names_and_related_ids_do_not_replace_source_key(artifacts, chunk_type: str) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, chunk_type)
    item = _matching(graph, chunk)
    item["source"]["object_id"] += "-different"
    if chunk_type != "relationship":
        item["label"] = chunk["title"]
        item["attributes"]["content"] = chunk["content"]
    validate_knowledge_graph(graph)
    with pytest.raises(GraphSeedMappingError):
        _mapped(artifacts, chunk_type)


@pytest.mark.parametrize("chunk_type", ["entity", "evidence", "mitre_assessment", "relationship"])
def test_related_ids_and_source_references_do_not_expand_seeds(artifacts, chunk_type: str) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, chunk_type)
    for field in ("entity_ids", "fact_ids", "relationship_ids", "evidence_ids", "sigma_rule_ids", "mitre_external_ids"):
        chunk[field] = [node["node_id"] for node in graph["nodes"]]
    result, _ = _mapped(artifacts, chunk_type)
    item = _matching(graph, chunk)
    expected = sorted({item["source_node_id"], item["target_node_id"]}) if chunk_type == "relationship" else [item["node_id"]]
    assert result["seed_node_ids"] == expected


@pytest.mark.parametrize("value", [None, [], "hybrid", 1, True])
def test_hybrid_result_must_be_an_object(artifacts, value: object) -> None:
    corpus, graph = artifacts
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, value, graph)


@pytest.mark.parametrize("location,field", [
    *( ("root", field) for field in ("schema_version", "retrieval_method", "corpus_id", "scenario_id", "query", "hits", "warnings", "metadata") ),
    *( ("query", field) for field in ("text", "normalized_terms", "top_k", "candidate_k", "filters") ),
    *( ("filters", field) for field in ("chunk_types", "required_dimensions") ),
    *( ("hit", field) for field in ("rank", "score", "components", "chunk") ),
    *( ("components", field) for field in ("lexical", "vector") ),
    *( ("component", field) for field in ("rank", "score", "contribution") ),
    *( ("metadata", field) for field in ("total_chunks", "eligible_chunks", "returned_hits", "lexical_candidate_count", "vector_candidate_count", "union_candidate_count", "rrf_k", "score_precision", "score_interpretation", "component_methods") ),
])
def test_missing_hybrid_contract_fields_fail_closed(artifacts, location: str, field: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    owners = {
        "root": hybrid, "query": hybrid["query"], "filters": hybrid["query"]["filters"],
        "hit": hybrid["hits"][0], "components": hybrid["hits"][0]["components"],
        "component": hybrid["hits"][0]["components"]["lexical"], "metadata": hybrid["metadata"],
    }
    del owners[location][field]
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("location", ["root", "query", "filters", "hit", "components", "component", "metadata", "component_methods"])
def test_extra_hybrid_contract_fields_fail_closed(artifacts, location: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    owners = {
        "root": hybrid, "query": hybrid["query"], "filters": hybrid["query"]["filters"],
        "hit": hybrid["hits"][0], "components": hybrid["hits"][0]["components"],
        "component": hybrid["hits"][0]["components"]["lexical"], "metadata": hybrid["metadata"],
        "component_methods": hybrid["metadata"]["component_methods"],
    }
    owners[location]["unexpected"] = "synthetic"
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("location", ["query", "filters", "hit", "components", "component", "metadata"])
def test_nested_hybrid_objects_reject_nonobjects(artifacts, location: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    if location in {"query", "metadata"}:
        hybrid[location] = []
    elif location == "filters":
        hybrid["query"]["filters"] = []
    elif location == "hit":
        hybrid["hits"][0] = []
    elif location == "components":
        hybrid["hits"][0]["components"] = []
    else:
        hybrid["hits"][0]["components"]["lexical"] = []
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("text", [None, True, 42, "", " \t\n", "?! … —", "\ud800"])
def test_query_text_must_be_valid_nonempty_tokenizable_utf8(artifacts, text: object) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["query"]["text"] = text
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("terms", [None, [], "synthetic", [True], [""], ["wrong"], ["synthetic", "synthetic"]])
def test_normalized_terms_must_match_existing_tokenizer_exactly(artifacts, terms: object) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["query"]["normalized_terms"] = terms
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("field", ["top_k", "candidate_k"])
@pytest.mark.parametrize("value", [None, True, False, "1", 1.0, 0, -1])
def test_query_limits_are_positive_integers(artifacts, field: str, value: object) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["query"][field] = value
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


def test_candidate_k_cannot_be_smaller_than_top_k(artifacts) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["query"].update(top_k=2, candidate_k=1)
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("field", ["chunk_types", "required_dimensions"])
@pytest.mark.parametrize("value", ["entity", {}, [True], [None], [""], ["unknown"], ("entity",)])
def test_filters_require_canonical_lists_of_known_strings(artifacts, field: str, value: object) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["query"]["filters"][field] = value
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("field", ["chunk_types", "required_dimensions"])
def test_duplicate_or_unsorted_filter_echoes_are_rejected(artifacts, field: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    value = "entity" if field == "chunk_types" else "provenance"
    hybrid["query"]["filters"][field] = [value, value]
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    values = ["fact", "entity"] if field == "chunk_types" else sorted(corpus["queryable_dimensions"])[-2:][::-1]
    hybrid["query"]["filters"][field] = values
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


def test_valid_filters_preserve_query_and_have_consistent_eligible_counts(artifacts) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["query"]["filters"] = {"chunk_types": ["entity"], "required_dimensions": ["provenance"]}
    hybrid["metadata"]["eligible_chunks"] = sum(
        chunk["chunk_type"] == "entity" and "provenance" in chunk["queryable_dimensions"]
        for chunk in corpus["chunks"]
    )
    result = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    assert result["query"] == hybrid["query"]


def test_valid_empty_filters_allow_empty_results(artifacts) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [])
    hybrid["query"]["filters"] = {"chunk_types": [], "required_dimensions": []}
    hybrid["metadata"]["eligible_chunks"] = 0
    assert map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)["seed_node_ids"] == []


def test_hit_cannot_violate_filters_even_with_exact_corpus_chunk(artifacts) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["query"]["filters"]["chunk_types"] = ["evidence"]
    hybrid["metadata"]["eligible_chunks"] = 2
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
@pytest.mark.parametrize("field,value", [
    ("rank", 0), ("rank", True), ("rank", 1.0), ("rank", 21), ("rank", None),
    ("score", math.nan), ("score", math.inf), ("score", -1), ("score", 0),
    ("score", True), ("score", "1"), ("score", None),
    ("contribution", math.nan), ("contribution", math.inf), ("contribution", 0),
    ("contribution", -1), ("contribution", 1.001), ("contribution", True),
    ("contribution", "0.1"), ("contribution", None),
])
def test_malformed_branch_components_are_rejected(artifacts, branch: str, field: str, value: object) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["hits"][0]["components"][branch][field] = value
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


def test_vector_component_score_cannot_exceed_cosine_range(artifacts) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["hits"][0]["components"]["vector"]["score"] = 1.0001
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


def test_hit_must_have_at_least_one_nonnull_branch(artifacts) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["hits"][0]["components"] = {"lexical": None, "vector": None}
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
def test_component_ranks_cannot_exceed_candidate_counts_or_repeat(artifacts, branch: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity"), _chunk(corpus, "evidence")])
    hybrid["hits"][0]["components"][branch]["rank"] = 3
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    hybrid["hits"][0]["components"][branch]["rank"] = 2
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("field", ["total_chunks", "eligible_chunks", "returned_hits", "lexical_candidate_count", "vector_candidate_count", "union_candidate_count"])
@pytest.mark.parametrize("value", [None, True, -1, "1", 1.0])
def test_metadata_counts_are_nonnegative_integers(artifacts, field: str, value: object) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["metadata"][field] = value
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("field,value", [
    ("total_chunks", 16), ("eligible_chunks", 14), ("returned_hits", 0),
    ("lexical_candidate_count", 0), ("vector_candidate_count", 0),
    ("lexical_candidate_count", 21), ("vector_candidate_count", 21),
    ("union_candidate_count", 0), ("union_candidate_count", 3),
    ("rrf_k", 61), ("rrf_k", True), ("rrf_k", 60.0),
    ("score_precision", 10), ("score_precision", 12.0),
    ("score_interpretation", "probability"),
    ("component_methods", {"lexical": "wrong", "vector": "vector-cosine/v1"}),
    ("component_methods", {"lexical": "bm25/v1"}),
])
def test_inconsistent_metadata_and_rrf_contract_are_rejected(artifacts, field: str, value: object) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    hybrid["metadata"][field] = value
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("branch,lexical,vector,union", [
    ("both", 1, 1, 2), ("lexical", 1, 1, 1), ("vector", 1, 1, 1),
])
def test_visible_branch_membership_must_agree_with_candidate_set_cardinalities(
    artifacts, branch: str, lexical: int, vector: int, union: int,
) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")], branch=branch)
    hybrid["metadata"].update(
        lexical_candidate_count=lexical, vector_candidate_count=vector,
        union_candidate_count=union,
    )
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


def test_full_chunk_nonstring_key_cannot_hide_behind_json_key_coercion(artifacts) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, "entity")
    chunk["metadata"]["numeric_keys"] = {"1": "synthetic"}
    hybrid = _hybrid(corpus, [chunk])
    hybrid["hits"][0]["chunk"]["metadata"]["numeric_keys"] = {1: "synthetic"}
    assert json.dumps(hybrid["hits"][0]["chunk"], sort_keys=True) == json.dumps(chunk, sort_keys=True)
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


def test_full_chunk_tuple_cannot_hide_behind_json_array_coercion(artifacts) -> None:
    corpus, graph = artifacts
    chunk = _chunk(corpus, "entity")
    chunk["metadata"]["sequence"] = ["synthetic", 1]
    hybrid = _hybrid(corpus, [chunk])
    hybrid["hits"][0]["chunk"]["metadata"]["sequence"] = ("synthetic", 1)
    assert json.dumps(hybrid["hits"][0]["chunk"], sort_keys=True) == json.dumps(chunk, sort_keys=True)
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("kind", ["hits_type", "warnings_type", "warnings_item", "unknown_chunk", "chunk_nonobject", "rank_order"])
def test_other_malformed_hybrid_shapes_fail_closed(artifacts, kind: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    if kind == "hits_type":
        hybrid["hits"] = {}
    elif kind == "warnings_type":
        hybrid["warnings"] = "warning"
    elif kind == "warnings_item":
        hybrid["warnings"] = [None]
    elif kind == "unknown_chunk":
        hybrid["hits"][0]["chunk"]["chunk_id"] = "missing-chunk"
    elif kind == "chunk_nonobject":
        hybrid["hits"][0]["chunk"] = []
    else:
        hybrid = _hybrid(corpus, [_chunk(corpus, "entity"), _chunk(corpus, "evidence")])
        hybrid["hits"].reverse()
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("location", ["corpus", "graph", "hybrid"])
@pytest.mark.parametrize("value", [math.nan, math.inf, b"not-json", ("tuple",)])
def test_nonfinite_or_non_json_nested_values_fail_closed(artifacts, location: str, value: object) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    target = {"corpus": corpus["metadata"], "graph": graph["nodes"][0]["attributes"], "hybrid": hybrid["hits"][0]["chunk"]["metadata"]}[location]
    target["nested"] = {"value": value}
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)


@pytest.mark.parametrize("location", ["corpus", "graph", "hybrid"])
def test_cyclic_inputs_fail_closed_without_repairs(artifacts, location: str) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity")])
    cycle: list[Any] = []
    cycle.append(cycle)
    target = {"corpus": corpus["metadata"], "graph": graph["metadata"], "hybrid": hybrid["hits"][0]["chunk"]["metadata"]}[location]
    target["cycle"] = cycle
    with pytest.raises(GraphSeedMappingError):
        map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    assert target["cycle"] is cycle and cycle[0] is cycle


def test_mitre_positive_and_negative_support_decisions_remain_unchanged(artifacts) -> None:
    corpus, graph = artifacts
    decisions = _json(DECISIONS_PATH)["mitre_decisions"]
    expected = {"T1059.007": "not_supported_by_observed_command", "T1218.005": "supported_by_observed_behavior"}
    template_chunk = _chunk(corpus, "mitre_assessment")
    template_node = _matching(graph, template_chunk)
    chunks = []
    for index, decision in enumerate(decisions):
        if decision["external_id"] not in expected:
            continue
        chunk, node = deepcopy(template_chunk), deepcopy(template_node)
        source = {"object_type": "mitre_assessment", "object_id": f"synthetic-decision-{index}", "json_pointer": f"/mitre_decisions/{index}"}
        chunk.update(chunk_id=f"synthetic-decision-chunk-{index}", mitre_external_ids=[decision["external_id"]])
        chunk["source"].update(source)
        chunk["metadata"].update(deepcopy(decision))
        node.update(node_id=f"synthetic-decision-node-{index}", source=deepcopy(source))
        node["attributes"].update(deepcopy(decision))
        assert node["status"] == chunk["status"] == "candidate"
        corpus["chunks"].append(chunk)
        graph["nodes"].append(node)
        chunks.append(chunk)
    assert len(chunks) == 2
    corpus["metadata"]["chunk_count"] = len(corpus["chunks"])
    _counts(graph)
    hybrid = _hybrid(corpus, chunks)
    before = deepcopy((corpus, hybrid, graph))
    result = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    assert (corpus, hybrid, graph) == before
    for chunk in chunks:
        node = _matching(graph, chunk)
        technique = chunk["mitre_external_ids"][0]
        assert chunk["metadata"]["evidence_support"] == node["attributes"]["evidence_support"] == expected[technique]
        assert node["status"] == "candidate"
        assert node["attributes"]["review_status"] == "needs_review"
        assert node["attributes"]["rationale"]
    assert not any(isinstance(value, str) and value.strip().casefold() == "confirmed" for value in _walk(result))
    strings = {value for value in _walk(result) if isinstance(value, str)}
    assert not strings.intersection({"malicious", "benign", "security_conclusion", "technique_confirmed", "answer", "confidence", "evidence_support"})


def test_no_question_or_expected_answer_contract_or_generated_conclusion(artifacts) -> None:
    result, _ = _mapped(artifacts, query="What is the synthetic provenance?")
    keys = {key for value in _walk(result) if isinstance(value, dict) for key in value}
    assert not keys.intersection({
        "question", "questions", "expected_answer", "expected_answers", "evaluation_questions",
        "question_id", "question_text", "answer", "llm_response", "security_conclusion",
        "malicious", "benign", "confirmed", "confidence", "probability",
    })
    assert result["query"]["text"] == "What is the synthetic provenance?"


def test_fixture_and_decision_bytes_remain_unchanged(artifacts) -> None:
    paths = (CORPUS_PATH, GRAPH_PATH, DECISIONS_PATH)
    before = {path: sha256(path.read_bytes()).hexdigest() for path in paths}
    _mapped(artifacts)
    _mapped(artifacts, "relationship")
    assert before == {path: sha256(path.read_bytes()).hexdigest() for path in paths}


def test_mapper_performs_no_file_network_retrieval_model_traversal_clock_rng_or_uuid(monkeypatch, artifacts) -> None:
    corpus, graph = artifacts
    hybrid = _hybrid(corpus, [_chunk(corpus, "entity"), _chunk(corpus, "relationship")])
    expected = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    calls = []

    def forbidden(*args: Any, **kwargs: Any) -> None:
        calls.append(True)
        raise AssertionError("Mapper attempted an external or nondeterministic operation")

    with monkeypatch.context() as patch:
        for owner, names in (
            (builtins, ("open",)), (io, ("open",)),
            (Path, ("open", "read_text", "read_bytes", "write_text", "write_bytes", "exists", "resolve")),
            (os, ("open", "stat", "listdir")),
            (socket, ("socket", "create_connection", "getaddrinfo")),
            (time, ("time", "time_ns", "monotonic", "perf_counter")),
            (random, ("random", "randint", "randrange", "choice", "choices", "shuffle", "getrandbits")),
            (uuid, ("uuid1", "uuid4")),
            (retrieval_package, ("retrieve_lexical", "retrieve_vector", "retrieve_hybrid", "build_vector_index")),
            (retrieval_package.SentenceTransformerEmbeddingBackend,
             ("__init__", "load", "embedding_dimension", "embed_documents", "__call__")),
            (graph_package, ("traverse_knowledge_graph", "build_knowledge_graph")),
        ):
            for name in names:
                patch.setattr(owner, name, forbidden)
        for module in (retrieval_package.hybrid, retrieval_package.lexical, retrieval_package.vector_search):
            for name in ("retrieve_hybrid", "retrieve_lexical", "retrieve_vector"):
                if hasattr(module, name):
                    patch.setattr(module, name, forbidden)
        actual = map_hybrid_hits_to_graph_seeds(corpus, hybrid, graph)
    assert calls == []
    assert actual == expected


def test_implementation_is_generic_and_imports_no_external_or_model_dependencies() -> None:
    source = IMPLEMENTATION_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots = set()
    calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else None
            calls.add(name)
    assert imported_roots <= sys.stdlib_module_names | {"threat_hunting", "__future__"}
    assert imported_roots.isdisjoint({
        "time", "datetime", "random", "uuid", "socket", "urllib", "http", "requests",
        "networkx", "neo4j", "sentence_transformers", "openai", "transformers", "torch",
    })
    assert calls.isdisjoint({
        "open", "read_text", "read_bytes", "write_text", "write_bytes", "retrieve_hybrid",
        "retrieve_lexical", "retrieve_vector", "traverse_knowledge_graph", "embed_query",
        "SentenceTransformerEmbeddingBackend", "embed_documents", "build_vector_index",
        "uuid1", "uuid4", "randint", "randrange",
    })
    for forbidden in (
        "mshta", "powershell", "cmd.exe", "t1059.007", "t1218.005", "t1140",
        "jsonl:line:", "proc_creation_win_", "outputs/", "d:/", "c:/",
    ):
        assert forbidden not in source.casefold()
    corpus, graph = _json(CORPUS_PATH), _json(GRAPH_PATH)
    for item in corpus["chunks"]:
        assert item["chunk_id"] not in source
    for item in graph["nodes"] + graph["edges"]:
        assert item.get("node_id", item.get("edge_id")) not in source
