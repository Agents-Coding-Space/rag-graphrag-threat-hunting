"""Synthetic contract tests for the in-memory GraphRAG relevance gate."""

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

from threat_hunting.graphrag import (
    GraphRAGRelevanceError,
    assess_graphrag_relevance,
)
from threat_hunting.graphrag import relevance


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PATH = ROOT / "tests/fixtures/graphrag/relevance/expected_relevance_decisions.json"
IMPLEMENTATION_PATH = ROOT / "src/threat_hunting/graphrag/relevance.py"


def _policy(**overrides: object) -> dict[str, object]:
    result = {
        "schema_version": "graphrag-relevance-policy/v1",
        "policy_id": "synthetic-strict",
        "min_hits": 2,
        "min_mapped_hits": 2,
        "min_seed_nodes": 2,
        "require_traversal": True,
        "min_traversal_nodes": 2,
        "require_lexical_support": True,
        "min_cosine_score": 0.5,
        "require_joint_lexical_vector_support": True,
    }
    result.update(overrides)
    return result


def _context() -> dict:
    scenario = "synthetic-relevance"
    query = {
        "text": "  synthetic tín hiệu Ω  ",
        "normalized_terms": ["synthetic", "tín", "hiệu", "ω"],
        "top_k": 2,
        "candidate_k": 4,
        "filters": {"chunk_types": None, "required_dimensions": None},
    }
    ground_truth = {
        "path": "synthetic_ground_truth.json",
        "schema_version": "scenario-ground-truth/v1",
        "sha256": "a" * 64,
        "scenario_id": scenario,
    }
    hits, mappings, nodes = [], [], []
    for index, cosine in enumerate((0.2, 0.8), 1):
        source = {
            "artifact_type": "scenario_ground_truth",
            "object_type": "evidence",
            "object_id": f"synthetic-evidence-{index}",
            "json_pointer": f"/evidence/{index - 1}",
        }
        chunk = {
            "chunk_id": f"synthetic-chunk-{index}",
            "chunk_type": "evidence",
            "scenario_id": scenario,
            "title": f"Synthetic signal {index}",
            "content": "A synthetic observation requiring human review.",
            "status": "candidate",
            "source": source,
            "entity_ids": [],
            "fact_ids": [],
            "relationship_ids": [],
            "evidence_ids": [f"synthetic-evidence-{index}"],
            "sigma_rule_ids": [],
            "mitre_external_ids": [],
            "source_references": [{"source_file": "synthetic.jsonl", "raw_record_ref": f"fixture:{index}"}],
            "queryable_dimensions": ["evidence", "provenance"],
            "metadata": {"review_status": "needs_review", "nested": {"values": [None, True, 3]}},
        }
        components = {
            "lexical": {"rank": index, "score": 2.0 / index, "contribution": 0.01},
            "vector": {"rank": index, "score": cosine, "contribution": 0.01},
        }
        hits.append({"rank": index, "score": 0.02, "components": components, "chunk": chunk})
        mappings.append({
            "hit_rank": index,
            "hit_score": 0.02,
            "components": deepcopy(components),
            "chunk_id": chunk["chunk_id"],
            "chunk_type": chunk["chunk_type"],
            "source": deepcopy(source),
            "mapping_kind": "direct_node",
            "matched_node_ids": [f"synthetic-node-{index}"],
            "matched_edge_ids": [],
        })
        nodes.append({
            "node_id": f"synthetic-node-{index}",
            "node_type": "evidence",
            "label": f"Synthetic observation {index}",
            "status": "candidate",
            "source": {key: value for key, value in source.items() if key != "artifact_type"},
            "attributes": {"review_status": "needs_review", "basis": "supported_by_observed_behavior"},
            "evidence_ids": deepcopy(chunk["evidence_ids"]),
            "source_references": deepcopy(chunk["source_references"]),
            "dimensions": ["evidence", "provenance"],
        })
    seed_ids = [node["node_id"] for node in nodes]
    paths = [{
        "seed_node_id": identifier, "target_node_id": identifier,
        "node_ids": [identifier], "edge_ids": [], "depth": 0,
    } for identifier in seed_ids]
    paths.append({
        "seed_node_id": seed_ids[0], "target_node_id": seed_ids[1],
        "node_ids": seed_ids[:], "edge_ids": ["synthetic-edge-1"], "depth": 1,
    })
    traversal = {
        "schema_version": "graph-traversal-result/v1",
        "graph_id": "synthetic-graph", "scenario_id": scenario,
        "seed_node_ids": seed_ids[:],
        "request": {
            "seed_node_ids": seed_ids[:], "direction": "outgoing", "max_depth": 2,
            "allowed_edge_types": None, "max_nodes": 4, "max_edges": 4,
        },
        "nodes": nodes,
        "edges": [{
            "edge_id": "synthetic-edge-1", "edge_type": "supports",
            "source_node_id": seed_ids[0], "target_node_id": seed_ids[1],
            "directed": True, "status": "candidate",
            "source": {"object_type": "relationship", "object_id": "synthetic-relationship", "json_pointer": "/relationships/0"},
            "supporting_node_ids": [], "evidence_ids": [], "source_references": [],
            "attributes": {"review_status": "needs_review"}, "dimensions": ["evidence"],
        }],
        "paths": paths, "warnings": ["synthetic traversal review"],
        "metadata": {},
    }
    context = {
        "schema_version": "graphrag-context/v1",
        "corpus_id": "synthetic-corpus", "graph_id": "synthetic-graph",
        "scenario_id": scenario, "source_ground_truth": ground_truth, "query": query,
        "retrieval": {
            "schema_version": "retrieval-result/v1", "retrieval_method": "hybrid-rrf/v1",
            "corpus_id": "synthetic-corpus", "scenario_id": scenario,
            "query": deepcopy(query), "hits": hits, "warnings": ["synthetic retrieval review"],
            "metadata": {
                "total_chunks": 2, "eligible_chunks": 2, "returned_hits": 2,
                "lexical_candidate_count": 2, "vector_candidate_count": 2, "union_candidate_count": 2,
                "rrf_k": 60, "score_precision": 12,
                "score_interpretation": "reciprocal_rank_fusion_not_probability",
                "component_methods": {"lexical": "bm25/v1", "vector": "vector-cosine/v1"},
            },
        },
        "seed_mapping": {
            "schema_version": "graphrag-seed-map/v1", "retrieval_method": "hybrid-rrf/v1",
            "corpus_id": "synthetic-corpus", "graph_id": "synthetic-graph", "scenario_id": scenario,
            "source_ground_truth": deepcopy(ground_truth), "query": deepcopy(query),
            "hit_mappings": mappings, "seed_node_ids": seed_ids[:],
            "warnings": ["synthetic mapping review"], "metadata": {},
        },
        "traversal": traversal, "warnings": [], "metadata": {},
    }
    _sync(context)
    return context


def _sync(context: dict) -> None:
    """Keep synthetic bookkeeping consistent after deliberate evidence removal."""
    hits = context["retrieval"]["hits"]
    mappings = context["seed_mapping"]["hit_mappings"]
    seeds = context["seed_mapping"]["seed_node_ids"]
    retrieval_metadata = context["retrieval"]["metadata"]
    retrieval_metadata["returned_hits"] = len(hits)
    for name in ("lexical", "vector"):
        retrieval_metadata[f"{name}_candidate_count"] = sum(hit["components"][name] is not None for hit in hits)
    retrieval_metadata["union_candidate_count"] = len(hits)
    direct = sum(item["mapping_kind"] == "direct_node" for item in mappings)
    context["seed_mapping"]["metadata"] = {
        "retrieval_hit_count": len(hits), "mapped_hit_count": len(mappings),
        "direct_node_mapping_count": direct,
        "relationship_edge_mapping_count": len(mappings) - direct,
        "seed_node_count": len(seeds),
    }
    traversal = context["traversal"]
    counts = {name: len(traversal[name]) if traversal is not None else 0 for name in ("nodes", "edges", "paths")}
    if traversal is not None:
        traversal["metadata"] = {
            "node_count": counts["nodes"], "edge_count": counts["edges"], "path_count": counts["paths"],
            "max_reached_depth": max((path["depth"] for path in traversal["paths"]), default=0),
            "truncated": False, "applied_limits": [],
        }
    context["metadata"] = {
        "retrieval_hit_count": len(hits), "mapped_hit_count": len(mappings), "seed_node_count": len(seeds),
        "traversal_performed": traversal is not None, "traversed_node_count": counts["nodes"],
        "traversed_edge_count": counts["edges"], "traversed_path_count": counts["paths"],
    }
    warnings = set(context["retrieval"]["warnings"] + context["seed_mapping"]["warnings"])
    if traversal is not None:
        warnings.update(traversal["warnings"])
    else:
        warnings.add("Graph traversal skipped: no retrieval hits or graph seeds are available.")
    context["warnings"] = sorted(warnings)


def _set_components(context: dict, mode: str) -> None:
    for index, hit in enumerate(context["retrieval"]["hits"]):
        if mode == "vector_only" or mode == "split" and index == 1:
            hit["components"]["lexical"] = None
        if mode == "lexical_only" or mode == "split" and index == 0:
            hit["components"]["vector"] = None
    for name in ("lexical", "vector"):
        rank = 0
        for hit in context["retrieval"]["hits"]:
            if hit["components"][name] is not None:
                rank += 1
                hit["components"][name]["rank"] = rank
    for mapping, hit in zip(context["seed_mapping"]["hit_mappings"], context["retrieval"]["hits"]):
        mapping["components"] = deepcopy(hit["components"])
    _sync(context)


def _case(name: str) -> tuple[dict, dict]:
    context, policy = _context(), _policy()
    if name in {"vector_only_requires_lexical", "vector_only_allowed"}:
        _set_components(context, "vector_only")
        policy["require_joint_lexical_vector_support"] = False
        if name == "vector_only_allowed":
            policy["require_lexical_support"] = False
    elif name in {"no_hits", "all_conditions_fail"}:
        context["retrieval"]["hits"] = []
        context["seed_mapping"]["hit_mappings"] = []
        context["seed_mapping"]["seed_node_ids"] = []
        context["traversal"] = None
    elif name == "no_mappings":
        context["seed_mapping"]["hit_mappings"] = []
        context["seed_mapping"]["seed_node_ids"] = []
        context["traversal"] = None
    elif name == "mappings_no_seeds":
        context["seed_mapping"]["seed_node_ids"] = []
        context["traversal"] = None
    elif name == "traversal_absent":
        context["traversal"] = None
    elif name == "too_few_traversal_nodes":
        context["retrieval"]["hits"] = context["retrieval"]["hits"][:1]
        context["retrieval"]["hits"][0]["components"]["vector"]["score"] = 0.8
        context["seed_mapping"]["hit_mappings"] = context["seed_mapping"]["hit_mappings"][:1]
        context["seed_mapping"]["hit_mappings"][0]["components"] = deepcopy(context["retrieval"]["hits"][0]["components"])
        context["seed_mapping"]["seed_node_ids"] = ["synthetic-node-1"]
        traversal = context["traversal"]
        traversal["seed_node_ids"] = ["synthetic-node-1"]
        traversal["request"]["seed_node_ids"] = ["synthetic-node-1"]
        traversal["nodes"] = traversal["nodes"][:1]
        traversal["edges"] = []
        traversal["paths"] = traversal["paths"][:1]
        policy.update(min_hits=1, min_mapped_hits=1, min_seed_nodes=1)
    elif name == "low_cosine":
        for index, hit in enumerate(context["retrieval"]["hits"]):
            hit["components"]["vector"]["score"] = 0.3 + index / 10
            context["seed_mapping"]["hit_mappings"][index]["components"] = deepcopy(hit["components"])
    elif name == "split_support_joint":
        _set_components(context, "split")
    elif name == "lexical_only_optional_vector":
        _set_components(context, "lexical_only")
        policy.update(min_cosine_score=None, require_joint_lexical_vector_support=False)
    elif name != "joint_supported":
        raise AssertionError(f"Unknown synthetic case {name}")
    _sync(context)
    return context, policy


CASE_NAMES = (
    "joint_supported", "vector_only_requires_lexical", "vector_only_allowed", "no_hits",
    "no_mappings", "mappings_no_seeds", "traversal_absent", "too_few_traversal_nodes",
    "low_cosine", "split_support_joint", "all_conditions_fail", "lexical_only_optional_vector",
)


def _serialize(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")


@pytest.mark.parametrize("name", CASE_NAMES)
def test_principal_synthetic_decisions_match_pinned_fixture(name: str) -> None:
    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))["cases"][name]
    context, policy = _case(name)
    result = assess_graphrag_relevance(context, policy=policy)
    assert result["schema_version"] == "graphrag-relevance-decision/v1"
    assert result["scenario_id"] == context["scenario_id"]
    assert result["policy_id"] == policy["policy_id"]
    assert result["query"] == context["query"]
    assert {key: result[key] for key in ("decision", "reason_codes", "signals")} == expected
    assert result["reason_codes"] == sorted(set(result["reason_codes"]))


def test_top_cosine_is_maximum_returned_component_not_top_rrf_hit() -> None:
    context = _context()
    assert context["retrieval"]["hits"][0]["components"]["vector"]["score"] == 0.2
    result = assess_graphrag_relevance(context, policy=_policy())
    assert result["signals"]["top_cosine_score"] == 0.8
    assert result["decision"] == "proceed"


def test_existing_synthetic_orchestrator_context_is_compatible() -> None:
    fixture_path = ROOT / "tests/fixtures/graphrag/orchestrator/expected_graphrag_context.json"
    source_bytes = fixture_path.read_bytes()
    context = json.loads(source_bytes)
    before = deepcopy(context)
    result = assess_graphrag_relevance(context, policy=_policy())
    assert result["decision"] == "proceed"
    assert result["reason_codes"] == []
    assert result["signals"] == {
        "retrieval_hit_count": 5, "lexical_hit_count": 5, "vector_hit_count": 5,
        "joint_lexical_vector_hit_count": 5, "top_cosine_score": 0.5280169,
        "hit_mapping_count": 5, "mapped_hit_count": 5, "seed_node_count": 5,
        "traversal_performed": True, "traversal_node_count": 12,
        "traversal_edge_count": 16, "traversal_path_count": 25,
    }
    assert context == before
    assert fixture_path.read_bytes() == source_bytes


@pytest.mark.parametrize("field,value", [("rrf_k", 61), ("rrf_k", 999), ("score_precision", 13), ("score_precision", 999)])
def test_retrieval_method_numeric_descriptors_match_actual_v1_contract(field: str, value: int) -> None:
    context = _context()
    context["retrieval"]["metadata"][field] = value
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


def test_empty_normalized_terms_in_all_query_echoes_fail_structurally() -> None:
    context = _context()
    for query in (context["query"], context["retrieval"]["query"], context["seed_mapping"]["query"]):
        query["normalized_terms"] = []
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


@pytest.mark.parametrize("field,value", [
    ("node_type", "entity"),
    ("object_type", "entity"),
    ("object_id", "synthetic-different-evidence"),
    ("json_pointer", "/evidence/99"),
])
def test_visible_direct_mapping_preserves_node_type_and_exact_source(field: str, value: str) -> None:
    context = _context()
    node = context["traversal"]["nodes"][0]
    if field == "node_type":
        node[field] = value
    else:
        node["source"][field] = value
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


def _relationship_context() -> dict:
    context = _context()
    chunk = context["retrieval"]["hits"][0]["chunk"]
    chunk["chunk_type"] = "relationship"
    chunk["source"] = {
        "artifact_type": "scenario_ground_truth", "object_type": "relationship",
        "object_id": "synthetic-relationship", "json_pointer": "/relationships/0",
    }
    mapping = context["seed_mapping"]["hit_mappings"][0]
    mapping.update(
        chunk_type="relationship", source=deepcopy(chunk["source"]),
        mapping_kind="relationship_edge", matched_node_ids=["synthetic-node-1", "synthetic-node-2"],
        matched_edge_ids=["synthetic-edge-1"],
    )
    _sync(context)
    return context


def test_visible_relationship_mapping_accepts_exact_edge_source_and_endpoints() -> None:
    result = assess_graphrag_relevance(_relationship_context(), policy=_policy())
    assert result["decision"] == "proceed"
    assert result["signals"]["mapped_hit_count"] == 2
    assert result["signals"]["seed_node_count"] == 2


@pytest.mark.parametrize("field,value", [
    ("object_type", "fact"),
    ("object_id", "synthetic-different-relationship"),
    ("json_pointer", "/relationships/99"),
])
def test_visible_relationship_mapping_preserves_exact_edge_source(field: str, value: str) -> None:
    context = _relationship_context()
    context["traversal"]["edges"][0]["source"][field] = value
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


def test_visible_relationship_mapping_cannot_omit_a_real_edge_endpoint() -> None:
    context = _relationship_context()
    context["seed_mapping"]["hit_mappings"][0]["matched_node_ids"] = ["synthetic-node-1"]
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


@pytest.mark.parametrize("field", ["hit_score", "lexical_score", "vector_score", "contribution"])
def test_mapping_score_copies_preserve_exact_json_numeric_type(field: str) -> None:
    context = _context()
    hit = context["retrieval"]["hits"][0]
    mapping = context["seed_mapping"]["hit_mappings"][0]
    if field == "hit_score":
        hit["score"], mapping["hit_score"] = 2.0, 2
    elif field == "lexical_score":
        hit["components"]["lexical"]["score"] = 2.0
        mapping["components"]["lexical"]["score"] = 2
    elif field == "vector_score":
        hit["components"]["vector"]["score"] = 1.0
        mapping["components"]["vector"]["score"] = 1
    else:
        hit["components"]["vector"]["contribution"] = 1.0
        mapping["components"]["vector"]["contribution"] = 1
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


def test_unserializable_large_integer_in_opaque_metadata_fails_closed() -> None:
    context = _context()
    context["retrieval"]["hits"][0]["chunk"]["metadata"]["large_integer"] = 10 ** 5000
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


def test_supporting_node_provenance_may_refer_outside_traversed_neighborhood() -> None:
    context = _context()
    context["traversal"]["edges"][0]["supporting_node_ids"] = ["synthetic-outside-neighborhood"]
    result = assess_graphrag_relevance(context, policy=_policy())
    assert result["decision"] == "proceed"
    assert result["signals"]["traversal_node_count"] == 2


def test_empty_matches_count_raw_mappings_separately_from_successful_hits() -> None:
    context = _context()
    for mapping in context["seed_mapping"]["hit_mappings"]:
        mapping["matched_node_ids"] = []
    context["seed_mapping"]["seed_node_ids"] = []
    context["traversal"] = None
    _sync(context)
    result = assess_graphrag_relevance(context, policy=_policy())
    assert result["signals"]["hit_mapping_count"] == 2
    assert result["signals"]["mapped_hit_count"] == 0
    assert "insufficient_mapped_hits" in result["reason_codes"]


def test_partial_mapping_is_valid_insufficient_evidence() -> None:
    context = _context()
    context["seed_mapping"]["hit_mappings"] = context["seed_mapping"]["hit_mappings"][:1]
    context["seed_mapping"]["seed_node_ids"] = []
    context["traversal"] = None
    _sync(context)
    result = assess_graphrag_relevance(context, policy=_policy())
    assert result["signals"]["hit_mapping_count"] == result["signals"]["mapped_hit_count"] == 1
    assert result["decision"] == "abstain"


@pytest.mark.parametrize("threshold,expected", [(0.8, "proceed"), (0.80001, "abstain"), (-1, "proceed"), (1, "abstain"), (None, "proceed")])
def test_cosine_threshold_is_inclusive_and_optional(threshold: object, expected: str) -> None:
    result = assess_graphrag_relevance(_context(), policy=_policy(min_cosine_score=threshold))
    assert result["decision"] == expected


def test_negative_cosine_is_valid_signal_and_never_a_probability() -> None:
    context = _context()
    for index, hit in enumerate(context["retrieval"]["hits"]):
        hit["components"]["vector"]["score"] = -0.9 + index / 10
        context["seed_mapping"]["hit_mappings"][index]["components"] = deepcopy(hit["components"])
    result = assess_graphrag_relevance(context, policy=_policy(min_cosine_score=-0.8))
    assert result["decision"] == "proceed"
    assert result["signals"]["top_cosine_score"] == -0.8
    assert result["metadata"]["score_interpretation"] == "bm25_cosine_rrf_not_probabilities"


def test_all_requirements_disabled_accepts_structurally_valid_empty_context() -> None:
    context, _ = _case("no_hits")
    policy = _policy(min_hits=0, min_mapped_hits=0, min_seed_nodes=0, require_traversal=False,
                     min_traversal_nodes=0, require_lexical_support=False, min_cosine_score=None,
                     require_joint_lexical_vector_support=False)
    result = assess_graphrag_relevance(context, policy=policy)
    assert result["decision"] == "proceed"
    assert result["reason_codes"] == []


def test_min_traversal_nodes_applies_when_require_traversal_is_false() -> None:
    context, _ = _case("traversal_absent")
    result = assess_graphrag_relevance(context, policy=_policy(require_traversal=False))
    assert result["reason_codes"] == ["insufficient_traversal_nodes"]


@pytest.mark.parametrize("field", ["min_hits", "min_mapped_hits", "min_seed_nodes", "min_traversal_nodes"])
@pytest.mark.parametrize("value", [True, False, -1, 0.5, "2", None, float("nan"), float("inf")])
def test_invalid_policy_counts_fail_closed(field: str, value: object) -> None:
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(_context(), policy=_policy(**{field: value}))


@pytest.mark.parametrize("field", ["require_traversal", "require_lexical_support", "require_joint_lexical_vector_support"])
@pytest.mark.parametrize("value", [0, 1, "true", None, [], {}])
def test_policy_requires_real_booleans(field: str, value: object) -> None:
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(_context(), policy=_policy(**{field: value}))


@pytest.mark.parametrize("value", [True, False, -1.001, 1.001, "0.5", [], {}, float("nan"), float("inf"), -float("inf")])
def test_invalid_cosine_thresholds_fail_closed(value: object) -> None:
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(_context(), policy=_policy(min_cosine_score=value))


@pytest.mark.parametrize("field", list(_policy()))
def test_missing_policy_fields_have_no_implicit_defaults(field: str) -> None:
    policy = _policy()
    del policy[field]
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(_context(), policy=policy)


@pytest.mark.parametrize("policy", [None, [], "policy", 1, {}, {"schema_version": "unexpected/v1"}])
def test_malformed_policy_root_fails_closed(policy: object) -> None:
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(_context(), policy=policy)


@pytest.mark.parametrize("field,value", [("policy_id", ""), ("policy_id", "  "), ("policy_id", 1), ("schema_version", "unexpected/v1"), ("thresholds", {})])
def test_policy_identity_schema_and_unknown_fields_fail_closed(field: str, value: object) -> None:
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(_context(), policy=_policy(**{field: value}))


def _at(value: dict, path: tuple) -> object:
    for field in path:
        value = value[field]
    return value


STRUCTURAL_OBJECT_PATHS = [
    (), ("query",), ("query", "filters"), ("source_ground_truth",), ("metadata",),
    ("retrieval",), ("retrieval", "metadata"), ("retrieval", "metadata", "component_methods"),
    ("retrieval", "hits", 0), ("retrieval", "hits", 0, "chunk"),
    ("retrieval", "hits", 0, "chunk", "source"), ("retrieval", "hits", 0, "chunk", "source_references", 0),
    ("retrieval", "hits", 0, "components"), ("retrieval", "hits", 0, "components", "vector"),
    ("seed_mapping",), ("seed_mapping", "metadata"), ("seed_mapping", "hit_mappings", 0),
    ("traversal",), ("traversal", "request"), ("traversal", "metadata"),
    ("traversal", "nodes", 0), ("traversal", "nodes", 0, "source"),
    ("traversal", "edges", 0), ("traversal", "paths", 0),
]


@pytest.mark.parametrize("path", STRUCTURAL_OBJECT_PATHS)
def test_unknown_structural_fields_fail_closed(path: tuple) -> None:
    context = _context()
    _at(context, path)["unexpected_field"] = "synthetic"
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


@pytest.mark.parametrize("path", STRUCTURAL_OBJECT_PATHS[1:])
def test_malformed_nested_objects_fail_closed(path: tuple) -> None:
    context = _context()
    _at(context, path[:-1])[path[-1]] = []
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


@pytest.mark.parametrize("field", list(_context()))
def test_missing_context_structure_fails_closed(field: str) -> None:
    context = _context()
    del context[field]
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


@pytest.mark.parametrize("context", [None, [], 1, "context", {}])
def test_malformed_context_root_fails_closed(context: object) -> None:
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


NUMERIC_CONTEXT_PATHS = [
    ("query", "top_k"), ("query", "candidate_k"), ("metadata", "retrieval_hit_count"),
    ("metadata", "mapped_hit_count"), ("metadata", "seed_node_count"),
    ("metadata", "traversed_node_count"), ("metadata", "traversed_edge_count"), ("metadata", "traversed_path_count"),
    ("retrieval", "metadata", "returned_hits"), ("retrieval", "metadata", "total_chunks"),
    ("retrieval", "hits", 0, "rank"), ("retrieval", "hits", 0, "score"),
    ("retrieval", "hits", 0, "components", "lexical", "score"),
    ("retrieval", "hits", 0, "components", "vector", "score"),
    ("retrieval", "hits", 0, "components", "vector", "rank"),
    ("retrieval", "hits", 0, "components", "vector", "contribution"),
    ("seed_mapping", "metadata", "seed_node_count"), ("seed_mapping", "hit_mappings", 0, "hit_rank"),
    ("traversal", "request", "max_depth"), ("traversal", "metadata", "node_count"),
    ("traversal", "paths", 0, "depth"),
]


@pytest.mark.parametrize("path", NUMERIC_CONTEXT_PATHS)
@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), -float("inf")])
def test_invalid_context_numbers_fail_closed(path: tuple, value: object) -> None:
    context = _context()
    _at(context, path[:-1])[path[-1]] = value
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


@pytest.mark.parametrize("path,value", [
    (("metadata", "traversal_performed"), 1),
    (("traversal", "metadata", "truncated"), 0),
    (("traversal", "edges", 0, "directed"), 1),
    (("retrieval", "hits", 0, "components", "vector", "score"), 1.1),
    (("retrieval", "hits", 0, "components", "vector", "score"), -1.1),
    (("retrieval", "hits", 0, "components", "lexical", "score"), 0),
    (("retrieval", "hits", 0, "components", "vector", "contribution"), 0),
    (("retrieval", "hits", 0, "components", "vector", "contribution"), 1.1),
    (("retrieval", "hits", 0, "score"), -1),
    (("query", "top_k"), 0),
    (("query", "candidate_k"), 1),
    (("traversal", "request", "direction"), "sideways"),
    (("traversal", "nodes", 0, "status"), "confirmed"),
    (("retrieval", "hits", 0, "chunk", "status"), "confirmed"),
    (("retrieval", "hits", 0, "chunk", "metadata"), []),
    (("traversal", "nodes", 0, "attributes"), []),
    (("source_ground_truth", "sha256"), "a" * 63),
    (("source_ground_truth", "sha256"), "g" * 64),
    (("retrieval", "hits", 0, "chunk", "source", "json_pointer"), "/bad~2"),
])
def test_invalid_values_fail_closed(path: tuple, value: object) -> None:
    context = _context()
    _at(context, path[:-1])[path[-1]] = value
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


@pytest.mark.parametrize("path", [
    ("metadata", "retrieval_hit_count"), ("metadata", "mapped_hit_count"), ("metadata", "seed_node_count"),
    ("metadata", "traversed_node_count"), ("metadata", "traversed_edge_count"), ("metadata", "traversed_path_count"),
    ("retrieval", "metadata", "returned_hits"), ("seed_mapping", "metadata", "mapped_hit_count"),
    ("seed_mapping", "metadata", "direct_node_mapping_count"), ("seed_mapping", "metadata", "seed_node_count"),
    ("traversal", "metadata", "node_count"), ("traversal", "metadata", "edge_count"), ("traversal", "metadata", "path_count"),
])
def test_source_counters_cannot_claim_evidence_absent_from_lists(path: tuple) -> None:
    context = _context()
    _at(context, path[:-1])[path[-1]] += 1
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


@pytest.mark.parametrize("path", [
    ("retrieval", "corpus_id"), ("retrieval", "scenario_id"), ("seed_mapping", "graph_id"),
    ("seed_mapping", "source_ground_truth", "sha256"), ("seed_mapping", "query", "text"),
    ("traversal", "graph_id"), ("traversal", "scenario_id"),
    ("retrieval", "hits", 0, "chunk", "scenario_id"),
    ("seed_mapping", "hit_mappings", 0, "chunk_id"), ("seed_mapping", "hit_mappings", 0, "hit_score"),
    ("seed_mapping", "hit_mappings", 0, "source", "object_id"),
    ("seed_mapping", "hit_mappings", 0, "components", "vector", "score"),
])
def test_cross_component_identity_query_provenance_and_hit_copy_mismatches_fail_closed(path: tuple) -> None:
    context = _context()
    original = _at(context, path)
    _at(context, path[:-1])[path[-1]] = original + 0.1 if isinstance(original, (int, float)) else "b" * 64
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


@pytest.mark.parametrize("corruption", [
    "duplicate_hit", "duplicate_mapping", "unknown_seed", "duplicate_seed", "duplicate_node", "duplicate_edge",
    "unknown_edge_endpoint", "unknown_path_node", "unknown_path_edge", "wrong_path_depth",
    "wrong_path_seed", "wrong_path_target", "wrong_path_orientation", "both_components_absent",
])
def test_invalid_reference_and_rank_structures_fail_closed(corruption: str) -> None:
    context = _context()
    traversal = context["traversal"]
    if corruption == "duplicate_hit":
        context["retrieval"]["hits"][1] = deepcopy(context["retrieval"]["hits"][0])
    elif corruption == "duplicate_mapping":
        context["seed_mapping"]["hit_mappings"][1] = deepcopy(context["seed_mapping"]["hit_mappings"][0])
    elif corruption == "unknown_seed":
        context["seed_mapping"]["seed_node_ids"][0] = "unknown"
    elif corruption == "duplicate_seed":
        context["seed_mapping"]["seed_node_ids"][1] = context["seed_mapping"]["seed_node_ids"][0]
    elif corruption == "duplicate_node":
        traversal["nodes"][1] = deepcopy(traversal["nodes"][0])
    elif corruption == "duplicate_edge":
        traversal["edges"].append(deepcopy(traversal["edges"][0]))
        _sync(context)
    elif corruption == "unknown_edge_endpoint":
        traversal["edges"][0]["source_node_id"] = "unknown"
    elif corruption == "unknown_path_node":
        traversal["paths"][-1]["node_ids"][1] = "unknown"
    elif corruption == "unknown_path_edge":
        traversal["paths"][-1]["edge_ids"][0] = "unknown"
    elif corruption == "wrong_path_depth":
        traversal["paths"][-1]["depth"] = 2
    elif corruption == "wrong_path_seed":
        traversal["paths"][-1]["seed_node_id"] = "unknown"
    elif corruption == "wrong_path_target":
        traversal["paths"][-1]["target_node_id"] = "synthetic-node-1"
    elif corruption == "wrong_path_orientation":
        traversal["edges"][0]["source_node_id"], traversal["edges"][0]["target_node_id"] = "synthetic-node-2", "synthetic-node-1"
    else:
        context["retrieval"]["hits"][0]["components"] = {"lexical": None, "vector": None}
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


@pytest.mark.parametrize("value", [float("nan"), float("inf"), (1, 2), {1: "value"}, "\ud800", object()])
def test_opaque_metadata_still_requires_finite_native_json(value: object) -> None:
    context = _context()
    context["retrieval"]["hits"][0]["chunk"]["metadata"]["opaque"] = value
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())


def test_cycles_fail_closed_without_mutating_the_cycle() -> None:
    context = _context()
    opaque = context["retrieval"]["hits"][0]["chunk"]["metadata"]
    opaque["cycle"] = opaque
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=_policy())
    assert opaque["cycle"] is opaque


def _containers(value: object) -> set[int]:
    result = set()
    if isinstance(value, (Mapping, list)):
        result.add(id(value))
        for child in value.values() if isinstance(value, Mapping) else value:
            result.update(_containers(child))
    return result


@pytest.mark.parametrize("name", CASE_NAMES)
def test_decision_is_immutable_detached_byte_deterministic_and_json_safe(name: str) -> None:
    context, policy = _case(name)
    before = deepcopy((context, policy))
    first = assess_graphrag_relevance(context, policy=policy)
    second = assess_graphrag_relevance(context, policy=policy)
    assert (context, policy) == before
    assert _serialize(first) == _serialize(second)
    assert json.loads(_serialize(first)) == first
    assert _containers(first).isdisjoint(_containers(context))
    assert _containers(first).isdisjoint(_containers(policy))
    assert _containers(first).isdisjoint(_containers(second))
    first["query"]["text"] = "synthetic output edit"
    first["metadata"]["source_ground_truth"]["path"] = "changed.json"
    first["metadata"]["policy"]["min_hits"] = 99
    assert (context, policy) == before
    assert second == assess_graphrag_relevance(context, policy=policy)


def test_metadata_preserves_policy_provenance_and_limits_decision_meaning() -> None:
    context, policy = _context(), _policy()
    result = assess_graphrag_relevance(context, policy=policy)
    assert result["metadata"] == {
        "context_schema_version": context["schema_version"],
        "policy_schema_version": policy["schema_version"],
        "corpus_id": context["corpus_id"], "graph_id": context["graph_id"],
        "source_ground_truth": context["source_ground_truth"], "policy": policy,
        "score_interpretation": "bm25_cosine_rrf_not_probabilities",
        "decision_interpretation": "context_eligibility_only",
    }
    assert set(result) == {"schema_version", "scenario_id", "query", "policy_id", "decision", "reason_codes", "signals", "warnings", "metadata"}
    assert "confirmed" not in _serialize(result).decode("utf-8").casefold()


def test_warnings_merge_all_stages_without_becoming_decision_logic() -> None:
    context = _context()
    context["warnings"] = ["z source warning", "shared", "shared"]
    context["retrieval"]["warnings"] = ["a warning", "shared"]
    context["seed_mapping"]["warnings"] = ["c warning", "shared"]
    context["traversal"]["warnings"] = ["b warning"]
    result = assess_graphrag_relevance(context, policy=_policy())
    assert result["warnings"] == ["a warning", "b warning", "c warning", "shared", "z source warning"]
    assert result["decision"] == "proceed"


def test_text_labels_and_opaque_metadata_cannot_change_decision() -> None:
    context = _context()
    original = assess_graphrag_relevance(context, policy=_policy())
    for hit in context["retrieval"]["hits"]:
        hit["chunk"].update(title="unrelated narrative", content="Completely unrelated synthetic text.")
        hit["chunk"]["metadata"]["extra_opaque"] = {"signal_claim": 9999}
    for node in context["traversal"]["nodes"]:
        node["label"] = "Unrelated synthetic label"
        node["attributes"]["extra_opaque"] = [None, False, {"count_claim": 9999}]
    changed = assess_graphrag_relevance(context, policy=_policy())
    assert changed == original


def test_input_scores_are_observed_without_recomputing_fusion_or_contributions() -> None:
    context = _context()
    expected = assess_graphrag_relevance(context, policy=_policy())
    for hit, mapping in zip(context["retrieval"]["hits"], context["seed_mapping"]["hit_mappings"]):
        hit["score"] = mapping["hit_score"] = 0.123
        for name in ("lexical", "vector"):
            hit["components"][name]["contribution"] = 0.4
        mapping["components"] = deepcopy(hit["components"])
    before = deepcopy(context)
    assert assess_graphrag_relevance(context, policy=_policy()) == expected
    assert context == before


@pytest.mark.parametrize("invalid", ["policy", "nested_context", "counter"])
def test_rejected_inputs_are_not_repaired_or_mutated(invalid: str) -> None:
    context, policy = _context(), _policy()
    if invalid == "policy":
        policy["min_hits"] = True
    elif invalid == "nested_context":
        context["retrieval"]["hits"][0]["components"]["vector"]["unknown"] = "synthetic"
    else:
        context["metadata"]["seed_node_count"] = 99
    before = deepcopy((context, policy))
    with pytest.raises(GraphRAGRelevanceError):
        assess_graphrag_relevance(context, policy=policy)
    assert (context, policy) == before


def test_mapping_insertion_order_does_not_change_serialized_decision() -> None:
    def reordered(value: object) -> object:
        if isinstance(value, dict):
            return {key: reordered(item) for key, item in reversed(list(value.items()))}
        if isinstance(value, list):
            return [reordered(item) for item in value]
        return value

    context, policy = _context(), _policy()
    first = assess_graphrag_relevance(context, policy=policy)
    second = assess_graphrag_relevance(reordered(context), policy=reordered(policy))
    assert _serialize(first) == _serialize(second)


def test_mapping_root_inputs_are_accepted_without_mutation() -> None:
    context, policy = _context(), _policy()
    assert assess_graphrag_relevance(MappingProxyType(context), policy=MappingProxyType(policy)) == assess_graphrag_relevance(context, policy=policy)


def test_evaluator_needs_no_files_network_embedding_clock_random_or_uuid(monkeypatch) -> None:
    context, policy = _context(), _policy()

    def forbidden(*args, **kwargs):
        pytest.fail("The relevance gate attempted an external or nondeterministic operation")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(io, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(time, "time", forbidden)
    monkeypatch.setattr(time, "monotonic", forbidden)
    monkeypatch.setattr(random, "random", forbidden)
    monkeypatch.setattr(uuid, "uuid4", forbidden)
    from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend
    monkeypatch.setattr(SentenceTransformerEmbeddingBackend, "__init__", forbidden)
    assert assess_graphrag_relevance(context, policy=policy)["decision"] == "proceed"


def test_implementation_is_generic_and_does_not_run_component_algorithms() -> None:
    source = IMPLEMENTATION_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
    assert not any(name and any(part in name for part in (
        "sentence_transformers", "embedding_backend", "requests", "socket", "subprocess", "random", "uuid", "datetime", "time",
    )) for name in imports)
    calls = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert calls.isdisjoint({"open", "retrieve_hybrid", "retrieve_lexical", "retrieve_vector", "map_hybrid_hits_to_graph_seeds", "traverse_knowledge_graph", "tokenize_retrieval_text", "embed_query", "uuid4"})
    for forbidden in ("mshta", "powershell", "t1218.005", "outputs/", "jsonl:line:", "What process chain led", "What evidence supports ATT&CK"):
        assert forbidden.casefold() not in source.casefold()
    for identifier in ("synthetic-corpus", "synthetic-graph", "synthetic-chunk-1", "synthetic-node-1", "synthetic-edge-1"):
        assert identifier not in source
    assert GraphRAGRelevanceError is relevance.GraphRAGRelevanceError
    assert assess_graphrag_relevance is relevance.assess_graphrag_relevance
    assert issubclass(GraphRAGRelevanceError, ValueError)
