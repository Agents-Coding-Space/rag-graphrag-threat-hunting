"""Generic traversal contracts using existing, read-only synthetic graph fixtures."""

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

from threat_hunting.graph import (
    KnowledgeGraphTraversalError,
    traverse_knowledge_graph,
    validate_knowledge_graph,
)
from threat_hunting.graph import traversal as traversal_module


ROOT = Path(__file__).resolve().parents[1]
GRAPH1_FIXTURE = ROOT / "tests/fixtures/graph/knowledge_graph_minimal.json"
GRAPH2_FIXTURE = ROOT / "tests/fixtures/graph/builder/expected_knowledge_graph.json"
DECISIONS_CONFIG = ROOT / "configs/ground_truth/mshta_powershell.json"
TRAVERSAL_PATH = ROOT / "src/threat_hunting/graph/traversal.py"
RESULT_FIELDS = {
    "schema_version", "graph_id", "scenario_id", "request", "seed_node_ids",
    "nodes", "edges", "paths", "warnings", "metadata",
}
PATH_FIELDS = {"seed_node_id", "target_node_id", "depth", "node_ids", "edge_ids"}


def _fixture(path: Path = GRAPH1_FIXTURE) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _counts(graph: dict[str, Any]) -> None:
    graph["metadata"].update(
        node_count=len(graph["nodes"]),
        edge_count=len(graph["edges"]),
        node_type_counts=dict(Counter(node["node_type"] for node in graph["nodes"])),
        edge_type_counts=dict(Counter(edge["edge_type"] for edge in graph["edges"])),
    )


def _topology(
    node_ids: tuple[str, ...],
    connections: tuple[tuple[str, str, str, str], ...],
) -> dict[str, Any]:
    """Clone fixture objects in memory; these topologies have no production meaning."""
    graph = _fixture()
    node_template = next(node for node in graph["nodes"] if node["node_type"] == "entity")
    edge_template = graph["edges"][0]
    graph["nodes"] = []
    for node_id in node_ids:
        node = deepcopy(node_template)
        node.update(node_id=node_id, label=f"Synthetic vertex {node_id}")
        node["source"]["object_id"] = f"synthetic-object-{node_id}"
        graph["nodes"].append(node)
    graph["edges"] = []
    for edge_id, source, target, edge_type in connections:
        edge = deepcopy(edge_template)
        edge.update(
            edge_id=edge_id, source_node_id=source, target_node_id=target,
            edge_type=edge_type, supporting_node_ids=[],
        )
        edge["source"]["object_id"] = f"synthetic-object-{edge_id}"
        graph["edges"].append(edge)
    _counts(graph)
    validate_knowledge_graph(graph)
    return graph


def _chain() -> dict[str, Any]:
    return _topology(
        ("node-a", "node-b", "node-c", "node-isolated"),
        (("edge-ab", "node-a", "node-b", "flows_to"),
         ("edge-bc", "node-b", "node-c", "flows_to")),
    )


def _nodes(result: dict[str, Any]) -> set[str]:
    return {node["node_id"] for node in result["nodes"]}


def _path(result: dict[str, Any], seed: str, target: str) -> dict[str, Any]:
    paths = [path for path in result["paths"]
             if path["seed_node_id"] == seed and path["target_node_id"] == target]
    assert len(paths) == 1
    return paths[0]


def _serialized(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _walk(value: object) -> Iterator[object]:
    yield value
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested)


def _assert_coherent(result: dict[str, Any]) -> None:
    node_ids = _nodes(result)
    edge_lookup = {edge["edge_id"]: edge for edge in result["edges"]}
    assert len(node_ids) == len(result["nodes"])
    assert len(edge_lookup) == len(result["edges"])
    assert result["seed_node_ids"] == sorted(result["seed_node_ids"])
    assert set(result["seed_node_ids"]).issubset(node_ids)
    assert [node["node_id"] for node in result["nodes"]] == sorted(node_ids)
    assert [edge["edge_id"] for edge in result["edges"]] == sorted(edge_lookup)
    for edge in edge_lookup.values():
        assert {edge["source_node_id"], edge["target_node_id"]}.issubset(node_ids)
    pairs = set()
    for path in result["paths"]:
        assert set(path) == PATH_FIELDS
        pair = (path["seed_node_id"], path["target_node_id"])
        assert pair not in pairs
        pairs.add(pair)
        assert path["seed_node_id"] in result["seed_node_ids"]
        assert path["node_ids"][0] == path["seed_node_id"]
        assert path["node_ids"][-1] == path["target_node_id"]
        assert len(path["node_ids"]) == path["depth"] + 1
        assert len(path["edge_ids"]) == path["depth"]
        assert len(set(path["node_ids"])) == len(path["node_ids"])
        assert set(path["node_ids"]).issubset(node_ids)
        assert set(path["edge_ids"]).issubset(edge_lookup)
        for index, edge_id in enumerate(path["edge_ids"]):
            left, right = path["node_ids"][index:index + 2]
            edge = edge_lookup[edge_id]
            source, target = edge["source_node_id"], edge["target_node_id"]
            direction = result["request"]["direction"]
            if direction == "outgoing":
                assert (left, right) == (source, target)
            elif direction == "incoming":
                assert (left, right) == (target, source)
            else:
                assert {left, right} == {source, target}
    assert result["metadata"]["node_count"] == len(result["nodes"])
    assert result["metadata"]["edge_count"] == len(result["edges"])
    assert result["metadata"]["path_count"] == len(result["paths"])
    assert result["metadata"]["max_reached_depth"] == max(
        (path["depth"] for path in result["paths"]), default=0,
    )
    assert len(result["nodes"]) <= result["request"]["max_nodes"]
    assert len(result["edges"]) <= result["request"]["max_edges"]
    _serialized(result)


def _assert_original_items(graph: dict[str, Any], result: dict[str, Any]) -> None:
    for collection, id_field in (("nodes", "node_id"), ("edges", "edge_id")):
        originals = {item[id_field]: item for item in graph[collection]}
        for item in result[collection]:
            assert item == originals[item[id_field]]
            assert item is not originals[item[id_field]]


def test_public_api_and_default_result_contract() -> None:
    graph = _chain()
    result = traverse_knowledge_graph(graph, seed_node_ids=["node-b"])
    assert issubclass(KnowledgeGraphTraversalError, ValueError)
    assert set(result) == RESULT_FIELDS
    assert result["schema_version"] == "graph-traversal-result/v1"
    assert result["graph_id"] == graph["graph_id"]
    assert result["scenario_id"] == graph["scenario_id"]
    assert result["request"] == {
        "seed_node_ids": ["node-b"], "direction": "both", "max_depth": 2,
        "allowed_edge_types": None, "max_nodes": 100, "max_edges": 200,
    }
    assert result["metadata"]["truncated"] is False
    assert result["metadata"]["applied_limits"] == []
    assert result["warnings"] == []
    _assert_coherent(result)


@pytest.mark.parametrize("direction, expected", [
    ("outgoing", {"node-b", "node-c"}),
    ("incoming", {"node-a", "node-b"}),
    ("both", {"node-a", "node-b", "node-c"}),
])
def test_all_directions_visit_only_allowed_endpoints(direction: str, expected: set[str]) -> None:
    result = traverse_knowledge_graph(_chain(), seed_node_ids=["node-b"], direction=direction)
    assert _nodes(result) == expected
    _assert_coherent(result)


@pytest.mark.parametrize("depth, expected", [
    (0, {"node-a"}), (1, {"node-a", "node-b"}),
    (2, {"node-a", "node-b", "node-c"}),
])
def test_depth_zero_one_two(depth: int, expected: set[str]) -> None:
    result = traverse_knowledge_graph(
        _chain(), seed_node_ids=["node-a"], direction="outgoing", max_depth=depth,
    )
    assert _nodes(result) == expected
    assert result["metadata"]["max_reached_depth"] == depth
    assert len(result["edges"]) == depth
    _assert_coherent(result)


def test_depth_zero_keeps_all_seeds_without_edges_or_nonseed_paths() -> None:
    result = traverse_knowledge_graph(
        _chain(), seed_node_ids=["node-c", "node-a"], max_depth=0,
    )
    assert _nodes(result) == {"node-a", "node-c"}
    assert result["edges"] == []
    assert result["paths"] == [
        {"seed_node_id": seed, "target_node_id": seed, "depth": 0,
         "node_ids": [seed], "edge_ids": []}
        for seed in ("node-a", "node-c")
    ]
    _assert_coherent(result)


def test_incoming_paths_use_traversal_order_while_edges_keep_original_direction() -> None:
    graph = _chain()
    result = traverse_knowledge_graph(graph, seed_node_ids=["node-c"], direction="incoming")
    assert _path(result, "node-c", "node-a") == {
        "seed_node_id": "node-c", "target_node_id": "node-a", "depth": 2,
        "node_ids": ["node-c", "node-b", "node-a"],
        "edge_ids": ["edge-bc", "edge-ab"],
    }
    _assert_original_items(graph, result)
    _assert_coherent(result)


@pytest.mark.parametrize("direction", ["outgoing", "incoming", "both"])
def test_directed_false_is_preserved_and_request_still_controls_direction(direction: str) -> None:
    graph = _chain()
    for edge in graph["edges"]:
        edge["directed"] = False
    result = traverse_knowledge_graph(graph, seed_node_ids=["node-b"], direction=direction)
    assert _nodes(result) == {
        "outgoing": {"node-b", "node-c"},
        "incoming": {"node-a", "node-b"},
        "both": {"node-a", "node-b", "node-c"},
    }[direction]
    assert all(edge["directed"] is False for edge in result["edges"])
    _assert_original_items(graph, result)
    _assert_coherent(result)


def test_each_seed_gets_its_own_canonical_shortest_paths() -> None:
    result = traverse_knowledge_graph(
        _chain(), seed_node_ids=["node-c", "node-a"], direction="both", max_depth=2,
    )
    assert result["seed_node_ids"] == ["node-a", "node-c"]
    assert _path(result, "node-a", "node-b")["node_ids"] == ["node-a", "node-b"]
    assert _path(result, "node-c", "node-b")["node_ids"] == ["node-c", "node-b"]
    assert _path(result, "node-a", "node-c")["depth"] == 2
    assert _path(result, "node-c", "node-a")["depth"] == 2
    assert result["metadata"]["path_count"] == 6
    _assert_coherent(result)


@pytest.mark.parametrize("collection", [list, tuple, set, frozenset])
def test_seed_collections_are_normalized_without_order_dependence(collection: type) -> None:
    graph = _chain()
    expected = traverse_knowledge_graph(graph, seed_node_ids=["node-a", "node-c"])
    actual = traverse_knowledge_graph(graph, seed_node_ids=collection(["node-c", "node-a"]))
    assert actual == expected
    assert _serialized(actual) == _serialized(expected)


def test_disconnected_seed_is_retained_and_does_not_invent_connections() -> None:
    result = traverse_knowledge_graph(_chain(), seed_node_ids=["node-isolated"])
    assert _nodes(result) == {"node-isolated"}
    assert result["edges"] == []
    assert _path(result, "node-isolated", "node-isolated")["depth"] == 0
    _assert_coherent(result)


@pytest.mark.parametrize("edge_types, expected_nodes, expected_edges", [
    (None, {"node-a", "node-b", "node-c"}, {"edge-ab", "edge-bc"}),
    ([], {"node-a"}, set()),
    (["flows_to"], {"node-a", "node-b"}, {"edge-ab"}),
    (["related_to"], {"node-a"}, set()),
    (["future_type"], {"node-a"}, set()),
])
def test_edge_filter_is_exact_and_does_not_guess_similar_types(
    edge_types: object, expected_nodes: set[str], expected_edges: set[str],
) -> None:
    graph = _chain()
    graph["edges"][1]["edge_type"] = "related_to"
    _counts(graph)
    result = traverse_knowledge_graph(
        graph, seed_node_ids=["node-a"], direction="outgoing", allowed_edge_types=edge_types,
    )
    assert _nodes(result) == expected_nodes
    assert {edge["edge_id"] for edge in result["edges"]} == expected_edges
    _assert_coherent(result)


@pytest.mark.parametrize("collection", [list, tuple, set, frozenset])
def test_filter_collections_have_canonical_sorted_request(collection: type) -> None:
    result = traverse_knowledge_graph(
        _chain(), seed_node_ids=["node-a"],
        allowed_edge_types=collection(["z_future", "flows_to"]),
    )
    assert result["request"]["allowed_edge_types"] == ["flows_to", "z_future"]


def test_cycle_and_self_loop_terminate_without_repeated_path_nodes() -> None:
    graph = _topology(
        ("node-a", "node-b", "node-c"),
        (("edge-ab", "node-a", "node-b", "links"),
         ("edge-bc", "node-b", "node-c", "links"),
         ("edge-ca", "node-c", "node-a", "links"),
         ("edge-aa", "node-a", "node-a", "links")),
    )
    result = traverse_knowledge_graph(
        graph, seed_node_ids=["node-a"], direction="outgoing", max_depth=64,
    )
    assert _nodes(result) == {"node-a", "node-b", "node-c"}
    assert len(result["edges"]) == 4
    assert len(result["paths"]) == 3
    assert _path(result, "node-a", "node-c")["depth"] == 2
    _assert_coherent(result)


def test_shortest_path_tie_uses_node_ids_before_edge_ids() -> None:
    graph = _topology(
        ("node-a", "node-b", "node-c", "node-d"),
        (("edge-z1", "node-a", "node-b", "links"),
         ("edge-z2", "node-b", "node-d", "links"),
         ("edge-a1", "node-a", "node-c", "links"),
         ("edge-a2", "node-c", "node-d", "links")),
    )
    result = traverse_knowledge_graph(graph, seed_node_ids=["node-a"], direction="outgoing")
    assert _path(result, "node-a", "node-d")["node_ids"] == ["node-a", "node-b", "node-d"]
    assert _path(result, "node-a", "node-d")["edge_ids"] == ["edge-z1", "edge-z2"]
    graph["nodes"].reverse()
    graph["edges"].reverse()
    assert traverse_knowledge_graph(graph, seed_node_ids=["node-a"], direction="outgoing") == result
    _assert_coherent(result)


def test_parallel_edge_tie_uses_edge_ids_and_retains_both_original_edges() -> None:
    graph = _topology(
        ("node-a", "node-b", "node-c"),
        (("edge-z", "node-a", "node-b", "links"),
         ("edge-a", "node-a", "node-b", "links"),
         ("edge-bc", "node-b", "node-c", "links")),
    )
    result = traverse_knowledge_graph(graph, seed_node_ids=["node-a"], direction="outgoing")
    assert _path(result, "node-a", "node-b")["edge_ids"] == ["edge-a"]
    assert _path(result, "node-a", "node-c")["edge_ids"] == ["edge-a", "edge-bc"]
    assert len(result["edges"]) == 3
    _assert_coherent(result)


def test_bfs_prefers_shorter_path_over_lexicographically_smaller_long_path() -> None:
    graph = _topology(
        ("node-a", "node-b", "node-c", "node-d"),
        (("edge-ab", "node-a", "node-b", "links"),
         ("edge-bc", "node-b", "node-c", "links"),
         ("edge-cd", "node-c", "node-d", "links"),
         ("edge-ad", "node-a", "node-d", "links")),
    )
    result = traverse_knowledge_graph(
        graph, seed_node_ids=["node-a"], direction="outgoing", max_depth=3,
    )
    assert _path(result, "node-a", "node-d")["node_ids"] == ["node-a", "node-d"]
    _assert_coherent(result)


@pytest.mark.parametrize("budget", [{"max_nodes": 2}, {"max_edges": 1}])
def test_truncation_admits_bfs_prefix_before_independent_edge_sort(budget: dict[str, int]) -> None:
    graph = _topology(
        ("node-a", "node-b", "node-c"),
        (("edge-z", "node-a", "node-b", "links"),
         ("edge-a", "node-a", "node-c", "links")),
    )
    result = traverse_knowledge_graph(graph, seed_node_ids=["node-a"], **budget)
    assert _nodes(result) == {"node-a", "node-b"}
    assert [edge["edge_id"] for edge in result["edges"]] == ["edge-z"]
    assert result["metadata"]["truncated"] is True
    assert result["metadata"]["applied_limits"] == sorted(budget)
    assert result["warnings"]
    assert any(next(iter(budget)) in warning for warning in result["warnings"])
    _assert_coherent(result)


@pytest.mark.parametrize("max_nodes", [1, 2, 3])
@pytest.mark.parametrize("max_edges", [1, 2])
def test_truncated_chain_never_returns_dangling_edges_or_paths(
    max_nodes: int, max_edges: int,
) -> None:
    graph = _chain()
    result = traverse_knowledge_graph(
        graph, seed_node_ids=["node-a"], direction="outgoing",
        max_nodes=max_nodes, max_edges=max_edges,
    )
    assert result == traverse_knowledge_graph(
        graph, seed_node_ids=["node-a"], direction="outgoing",
        max_nodes=max_nodes, max_edges=max_edges,
    )
    assert result["metadata"]["truncated"] is (max_nodes < 3 or max_edges < 2)
    _assert_coherent(result)
    _assert_original_items(graph, result)


def test_exact_result_limits_do_not_claim_truncation() -> None:
    result = traverse_knowledge_graph(
        _chain(), seed_node_ids=["node-a"], direction="outgoing", max_nodes=3, max_edges=2,
    )
    assert result["metadata"]["truncated"] is False
    assert result["metadata"]["applied_limits"] == []
    assert result["warnings"] == []


def test_all_seeds_are_retained_at_node_limit_and_order_is_stable() -> None:
    graph = _chain()
    first = traverse_knowledge_graph(
        graph, seed_node_ids=["node-c", "node-a"], max_nodes=2,
    )
    second = traverse_knowledge_graph(
        graph, seed_node_ids=["node-a", "node-c"], max_nodes=2,
    )
    assert first == second
    assert _nodes(first) == {"node-a", "node-c"}
    assert first["edges"] == []
    assert first["metadata"]["truncated"] is True
    assert first["metadata"]["applied_limits"] == ["max_nodes"]
    _assert_coherent(first)


def test_limited_edge_budget_keeps_shortest_paths_in_returned_subgraph() -> None:
    graph = _topology(
        ("node-a", "node-b", "node-c"),
        (("edge-ab", "node-a", "node-b", "links"),
         ("edge-bc", "node-b", "node-c", "links"),
         ("edge-ac", "node-a", "node-c", "links")),
    )
    result = traverse_knowledge_graph(
        graph, seed_node_ids=["node-a"], direction="outgoing", max_edges=2,
    )
    assert _path(result, "node-a", "node-c")["edge_ids"] == ["edge-ac"]
    assert result["metadata"]["truncated"] is True
    assert result["metadata"]["applied_limits"] == ["max_edges"]
    _assert_coherent(result)


def test_supporting_ids_remain_source_provenance_without_expanding_neighborhood() -> None:
    graph = _fixture()
    relationship = next(edge for edge in graph["edges"] if edge["edge_type"] == "synthetic_interaction")
    result = traverse_knowledge_graph(
        graph, seed_node_ids=[relationship["source_node_id"]],
        direction="outgoing", allowed_edge_types=["synthetic_interaction"], max_nodes=2,
    )
    assert _nodes(result) == {relationship["source_node_id"], relationship["target_node_id"]}
    assert set(relationship["supporting_node_ids"]).isdisjoint(_nodes(result))
    assert result["edges"] == [relationship]
    assert result["metadata"]["truncated"] is False
    _assert_coherent(result)


def test_source_warnings_are_preserved_and_detached_from_input() -> None:
    graph = _chain()
    graph["warnings"] = ["Synthetic source warning.", "Synthetic source warning."]
    result = traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    assert result["warnings"] == graph["warnings"]
    result["warnings"].append("changed")
    assert graph["warnings"] == ["Synthetic source warning.", "Synthetic source warning."]


def test_input_and_output_items_preserve_all_provenance_and_status() -> None:
    graph = _fixture(GRAPH2_FIXTURE)
    before = deepcopy(graph)
    # Starting at all nodes exercises every original item without fixture edits.
    result = traverse_knowledge_graph(
        graph, seed_node_ids=[node["node_id"] for node in graph["nodes"]], max_depth=1,
    )
    assert graph == before
    assert len(result["nodes"]) == len(graph["nodes"])
    assert len(result["edges"]) == len(graph["edges"])
    _assert_original_items(graph, result)
    _assert_coherent(result)


def test_deep_copies_detach_nested_attributes_source_references_and_independent_results() -> None:
    graph = _chain()
    for item in graph["nodes"] + graph["edges"]:
        item["attributes"]["nested"] = {"values": ["Dữ liệu tổng quát", None]}
        item["source_references"] = [
            {"source_file": "synthetic_events.jsonl", "raw_record_ref": "fixture:record:1"},
        ]
    before = deepcopy(graph)
    first = traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    second = traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    for item in first["nodes"] + first["edges"]:
        item["attributes"]["nested"]["values"].append("changed")
        item["source"]["json_pointer"] = "/changed"
        item["source_references"][0]["raw_record_ref"] = "changed"
        item["evidence_ids"].append("changed")
        item["dimensions"].append("changed")
        item["status"] = "reviewable"
    first["request"]["seed_node_ids"].append("changed")
    assert graph == before
    assert second == traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    assert first != second


def test_repeated_traversals_are_json_serializable_and_byte_identical() -> None:
    graph = _fixture(GRAPH2_FIXTURE)
    seeds = [node["node_id"] for node in graph["nodes"] if node["node_type"] == "evidence"]
    first = traverse_knowledge_graph(graph, seed_node_ids=seeds)
    graph["nodes"].reverse()
    graph["edges"].reverse()
    second = traverse_knowledge_graph(graph, seed_node_ids=list(reversed(seeds)))
    assert _serialized(first) == _serialized(second)
    assert json.loads(_serialized(first)) == first
    _assert_coherent(first)


@pytest.mark.parametrize("failure", ["root", "schema", "metadata", "endpoint", "supporter", "duplicate_node"])
def test_invalid_graphs_raise_traversal_error_without_repairs(failure: str) -> None:
    graph: Any = _chain()
    if failure == "root":
        graph = []
    elif failure == "schema":
        graph["schema_version"] = "wrong/v1"
    elif failure == "metadata":
        graph["metadata"]["node_count"] += 1
    elif failure == "endpoint":
        graph["edges"][0]["target_node_id"] = "node-missing"
    elif failure == "supporter":
        graph["edges"][0]["supporting_node_ids"] = ["node-missing"]
    else:
        graph["nodes"][1]["node_id"] = graph["nodes"][0]["node_id"]
    before = deepcopy(graph)
    with pytest.raises(KnowledgeGraphTraversalError):
        traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    assert graph == before


def test_existing_graph_validator_is_called_before_traversing(monkeypatch: pytest.MonkeyPatch) -> None:
    graph = _chain()
    calls = []

    def validate(value: object) -> None:
        assert value is graph
        calls.append(value)
        validate_knowledge_graph(value)

    monkeypatch.setattr(traversal_module, "validate_knowledge_graph", validate)
    traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    assert calls == [graph]


def test_invalid_graph_is_rejected_before_seed_collection_is_iterated() -> None:
    graph = _chain()
    graph["schema_version"] = "invalid/v0"

    class UnreadableSeeds(list):
        def __iter__(self) -> Iterator[str]:
            pytest.fail("Seed collection was inspected before validating the graph")

    with pytest.raises(KnowledgeGraphTraversalError, match="schema_version"):
        traverse_knowledge_graph(graph, seed_node_ids=UnreadableSeeds(["node-a"]))


@pytest.mark.parametrize("collection_name", ["seed_node_ids", "allowed_edge_types"])
def test_lazy_generators_are_rejected_without_consuming_them(collection_name: str) -> None:
    consumed = []

    def values() -> Iterator[str]:
        consumed.append(True)
        yield "node-a" if collection_name == "seed_node_ids" else "flows_to"

    request = {"seed_node_ids": ["node-a"], collection_name: values()}
    with pytest.raises(KnowledgeGraphTraversalError, match=collection_name):
        traverse_knowledge_graph(_chain(), **request)
    assert consumed == []


@pytest.mark.parametrize("failure", [
    "missing_seed", "dangling_edge_endpoint", "dangling_path_node", "dangling_path_edge",
    "repeated_path_node", "unknown_path_seed", "changed_node", "changed_edge",
    "duplicate_path", "missing_path", "metadata_count", "metadata_depth",
    "truncated_mismatch", "bad_limit_name",
])
def test_internal_result_integrity_errors_fail_closed(failure: str) -> None:
    graph = _chain()
    result = traverse_knowledge_graph(graph, seed_node_ids=["node-a"], direction="outgoing")
    if failure == "missing_seed":
        result["nodes"] = [node for node in result["nodes"] if node["node_id"] != "node-a"]
    elif failure == "dangling_edge_endpoint":
        result["nodes"] = [node for node in result["nodes"] if node["node_id"] != "node-b"]
    elif failure == "dangling_path_node":
        _path(result, "node-a", "node-c")["node_ids"][1] = "node-missing"
    elif failure == "dangling_path_edge":
        _path(result, "node-a", "node-c")["edge_ids"][0] = "edge-missing"
    elif failure == "repeated_path_node":
        _path(result, "node-a", "node-c")["node_ids"] = ["node-a", "node-a", "node-c"]
    elif failure == "unknown_path_seed":
        _path(result, "node-a", "node-c")["seed_node_id"] = "node-b"
    elif failure == "changed_node":
        result["nodes"][0]["attributes"]["technique_confirmed"] = True
    elif failure == "changed_edge":
        result["edges"][0]["source_node_id"] = "node-c"
    elif failure == "duplicate_path":
        result["paths"].append(deepcopy(result["paths"][0]))
    elif failure == "missing_path":
        result["paths"] = [path for path in result["paths"] if path["target_node_id"] != "node-c"]
    elif failure == "metadata_count":
        result["metadata"]["node_count"] += 1
    elif failure == "metadata_depth":
        result["metadata"]["max_reached_depth"] = 0
    elif failure == "truncated_mismatch":
        result["metadata"]["truncated"] = True
    else:
        result["metadata"].update(truncated=True, applied_limits=["unknown_limit"])
    before = deepcopy(graph)
    with pytest.raises(KnowledgeGraphTraversalError):
        traversal_module._validate_result(result, graph)
    assert graph == before


def test_internal_nonshortest_path_is_rejected_even_with_valid_endpoints_and_edges() -> None:
    graph = _topology(
        ("node-a", "node-b", "node-c"),
        (("edge-ab", "node-a", "node-b", "links"),
         ("edge-bc", "node-b", "node-c", "links"),
         ("edge-ac", "node-a", "node-c", "links")),
    )
    result = traverse_knowledge_graph(graph, seed_node_ids=["node-a"], direction="outgoing")
    _path(result, "node-a", "node-c").update(
        depth=2, node_ids=["node-a", "node-b", "node-c"], edge_ids=["edge-ab", "edge-bc"],
    )
    result["metadata"]["max_reached_depth"] = 2
    with pytest.raises(KnowledgeGraphTraversalError, match="canonical|shortest"):
        traversal_module._validate_result(result, graph)


@pytest.mark.parametrize("error_type", [TypeError, ValueError, UnicodeError, RecursionError])
def test_output_serialization_errors_are_wrapped_without_returning_partial_results(
    error_type: type[Exception], monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph = _chain()
    before = deepcopy(graph)
    failure = error_type("synthetic JSON serialization failure")

    def fail_serialize(*args: Any, **kwargs: Any) -> str:
        raise failure

    monkeypatch.setattr(traversal_module.json, "dumps", fail_serialize)
    with pytest.raises(KnowledgeGraphTraversalError) as error:
        traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    assert error.value.__cause__ is failure
    assert graph == before


@pytest.mark.parametrize("seeds", [[], (), set(), frozenset()])
def test_empty_seed_collections_are_rejected(seeds: object) -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match="seed"):
        traverse_knowledge_graph(_chain(), seed_node_ids=seeds)


@pytest.mark.parametrize("seeds", [None, "node-a", b"node-a", {"node-a": True}, 1, True])
def test_seed_collection_types_are_checked(seeds: object) -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match="seed"):
        traverse_knowledge_graph(_chain(), seed_node_ids=seeds)


@pytest.mark.parametrize("seed", ["node-missing", " node-a", "node-a ", "", "  ", None, 1, True])
def test_missing_or_invalid_seed_ids_are_rejected_without_fuzzy_matching(seed: object) -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match="seed"):
        traverse_knowledge_graph(_chain(), seed_node_ids=[seed])


def test_duplicate_seed_ids_are_rejected_before_normalization() -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match="duplicate"):
        traverse_knowledge_graph(_chain(), seed_node_ids=["node-a", "node-a"])


@pytest.mark.parametrize("direction", ["", "Outgoing", "out", " outgoing", "both ", None, True, 1, []])
def test_direction_requires_exact_supported_value(direction: object) -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match="direction"):
        traverse_knowledge_graph(_chain(), seed_node_ids=["node-a"], direction=direction)


@pytest.mark.parametrize("depth", [True, False, -1, 65, 1000000, 1.0, "1", None, math.nan, math.inf])
def test_max_depth_requires_safe_integer_excluding_bool(depth: object) -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match="max_depth"):
        traverse_knowledge_graph(_chain(), seed_node_ids=["node-a"], max_depth=depth)


@pytest.mark.parametrize("field", ["max_nodes", "max_edges"])
@pytest.mark.parametrize("value", [True, False, 0, -1, 1.0, "1", None, math.nan, math.inf])
def test_result_limits_require_positive_integer_excluding_bool(field: str, value: object) -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match=field):
        traverse_knowledge_graph(_chain(), seed_node_ids=["node-a"], **{field: value})


def test_node_budget_smaller_than_seed_count_is_rejected() -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match="max_nodes|seed"):
        traverse_knowledge_graph(_chain(), seed_node_ids=["node-a", "node-c"], max_nodes=1)


@pytest.mark.parametrize("edge_types", ["flows_to", b"flows_to", {"flows_to": True}, True, 1])
def test_edge_filter_requires_a_collection_of_types(edge_types: object) -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match="allowed_edge_types"):
        traverse_knowledge_graph(_chain(), seed_node_ids=["node-a"], allowed_edge_types=edge_types)


@pytest.mark.parametrize("edge_type", ["", " ", "Flows_to", "flows-to", "flows.to", "flows to", "1flows", "flows_to\n", None, True, 1])
def test_edge_filter_identifiers_require_exact_normalized_syntax(edge_type: object) -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match="allowed_edge_types"):
        traverse_knowledge_graph(_chain(), seed_node_ids=["node-a"], allowed_edge_types=[edge_type])


def test_duplicate_filter_types_are_rejected_without_silent_deduplication() -> None:
    with pytest.raises(KnowledgeGraphTraversalError, match="duplicate"):
        traverse_knowledge_graph(
            _chain(), seed_node_ids=["node-a"], allowed_edge_types=["flows_to", "flows_to"],
        )


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, b"not-json", ("tuple",), {1, 2}])
def test_nonfinite_or_non_json_graph_attributes_fail_closed(value: object) -> None:
    graph = _chain()
    graph["nodes"][0]["attributes"]["nested"] = [{"value": value}]
    with pytest.raises(KnowledgeGraphTraversalError):
        traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    assert graph["nodes"][0]["attributes"]["nested"][0]["value"] is value


def test_circular_graph_extension_fails_without_mutating_cycle() -> None:
    graph = _chain()
    cycle: list[Any] = []
    cycle.append(cycle)
    graph["nodes"][0]["attributes"]["cycle"] = cycle
    with pytest.raises(KnowledgeGraphTraversalError):
        traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    assert cycle[0] is cycle


@pytest.mark.parametrize("location", ["status", "nested_attributes", "warning"])
def test_confirmed_values_are_rejected_instead_of_promoted_or_repaired(location: str) -> None:
    graph = _chain()
    if location == "status":
        graph["nodes"][0]["status"] = "confirmed"
    elif location == "nested_attributes":
        graph["edges"][0]["attributes"]["review"] = {"status": " ConFiRmEd "}
    else:
        graph["warnings"] = ["confirmed"]
    before = deepcopy(graph)
    with pytest.raises(KnowledgeGraphTraversalError):
        traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    assert graph == before


def test_mitre_positive_and_negative_decisions_are_preserved_without_security_conclusions() -> None:
    graph = _fixture()
    config = _fixture(DECISIONS_CONFIG)
    template = next(node for node in graph["nodes"] if node["node_type"] == "mitre_assessment")
    evidence = next(node for node in graph["nodes"] if node["node_type"] == "evidence")
    edge_template = next(edge for edge in graph["edges"] if edge["target_node_id"] == template["node_id"])
    # Only in-memory clones: semantics come from the existing reviewed config.
    # Original fixture bytes and source decisions are never changed by this test.
    for index, decision in enumerate(config["mitre_decisions"]):
        if decision["external_id"] not in {"T1059.007", "T1218.005"}:
            continue
        node = deepcopy(template)
        node["node_id"] = f"node-synthetic-decision-{index}"
        node["source"]["object_id"] = f"assessment-synthetic-decision-{index}"
        node["source"]["json_pointer"] = f"/mitre_decisions/{index}"
        node["attributes"].update(deepcopy(decision))
        node["attributes"]["review_status"] = template["attributes"]["review_status"]
        graph["nodes"].append(node)
        edge = deepcopy(edge_template)
        edge.update(
            edge_id=f"edge-synthetic-decision-{index}", edge_type="supports",
            target_node_id=node["node_id"],
        )
        graph["edges"].append(edge)
    _counts(graph)
    before = deepcopy(graph)
    result = traverse_knowledge_graph(
        graph, seed_node_ids=[evidence["node_id"]], direction="outgoing",
        allowed_edge_types=["supports"], max_depth=1,
    )
    expected_support = {
        "T1059.007": "not_supported_by_observed_command",
        "T1218.005": "supported_by_observed_behavior",
    }
    originals = {node["node_id"]: node for node in graph["nodes"]}
    assessments = [node for node in result["nodes"] if node["node_type"] == "mitre_assessment"]
    assert {node["attributes"]["external_id"] for node in assessments} == set(expected_support)
    for node in assessments:
        attributes = node["attributes"]
        assert attributes["evidence_support"] == expected_support[attributes["external_id"]]
        assert node == originals[node["node_id"]]
        assert node["status"] == "candidate"
        assert attributes["review_status"] == "needs_review"
        assert attributes["rationale"]
        assert "technique_confirmed" not in attributes
    assert graph == before
    assert not any(isinstance(value, str) and value.strip().casefold() == "confirmed"
                   for value in _walk(result))
    assert not {"technique_confirmed", "technique_supported", "security_conclusion"}.intersection(
        value for value in _walk(result) if isinstance(value, str)
    )
    _assert_coherent(result)


def test_original_fixture_assessments_are_preserved_without_any_semantic_rewrite() -> None:
    graph = _fixture(GRAPH2_FIXTURE)
    seeds = [node["node_id"] for node in graph["nodes"] if node["node_type"] == "mitre_assessment"]
    result = traverse_knowledge_graph(graph, seed_node_ids=seeds, direction="incoming")
    _assert_original_items(graph, result)
    assert not any(isinstance(value, str) and value.strip().casefold() == "confirmed"
                   for value in _walk(result))


def test_fixture_and_config_files_remain_byte_identical() -> None:
    paths = (GRAPH1_FIXTURE, GRAPH2_FIXTURE, DECISIONS_CONFIG)
    before = {path: sha256(path.read_bytes()).hexdigest() for path in paths}
    for path in paths[:2]:
        graph = _fixture(path)
        traverse_knowledge_graph(graph, seed_node_ids=[node["node_id"] for node in graph["nodes"]])
    assert before == {path: sha256(path.read_bytes()).hexdigest() for path in paths}


def test_traversal_has_no_file_network_clock_random_or_uuid_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    graph = _chain()
    expected = traverse_knowledge_graph(graph, seed_node_ids=["node-a"])

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Traversal attempted an external or nondeterministic operation")

    with monkeypatch.context() as patch:
        for owner, names in (
            (builtins, ("open",)), (io, ("open",)),
            (Path, ("open", "read_text", "read_bytes", "write_text", "write_bytes", "exists", "resolve")),
            (os, ("open", "stat", "listdir")),
            (socket, ("socket", "create_connection", "getaddrinfo")),
            (time, ("time", "time_ns", "monotonic", "perf_counter")),
            (random, ("random", "randint", "randrange", "choice", "shuffle", "getrandbits")),
            (uuid, ("uuid1", "uuid4")),
        ):
            for name in names:
                patch.setattr(owner, name, forbidden)
        actual = traverse_knowledge_graph(graph, seed_node_ids=["node-a"])
    assert actual == expected


def test_traversal_module_is_generic_and_uses_only_stdlib_and_graph_contracts() -> None:
    source = TRAVERSAL_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    assert imported_roots <= sys.stdlib_module_names | {"threat_hunting", "__future__"}
    assert not imported_roots.intersection({
        "time", "datetime", "random", "uuid", "socket", "urllib", "http",
        "requests", "networkx", "neo4j", "sentence_transformers", "openai",
    })
    for forbidden in (
        "mshta-powershell", "cmd.exe", "mshta.exe", "powershell.exe", "t1059.007",
        "t1218.005", "jsonl:line:275", "jsonl:line:398", "proc_creation_win_",
    ):
        assert forbidden not in source.casefold()
