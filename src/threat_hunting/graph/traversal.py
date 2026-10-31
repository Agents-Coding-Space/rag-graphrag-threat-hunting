"""Deterministic, bounded traversal of an already validated in-memory graph.

This module selects existing graph objects without interpreting their content.
Supporting node IDs remain provenance references into the complete source graph;
they are not traversal endpoints and do not expand the selected neighborhood.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from copy import deepcopy
import json
from typing import Any, cast

from .schema import IDENTIFIER_PATTERN, validate_knowledge_graph


TRAVERSAL_RESULT_SCHEMA_VERSION = "graph-traversal-result/v1"
MAX_TRAVERSAL_DEPTH = 64
_DIRECTIONS = frozenset({"outgoing", "incoming", "both"})
_RESULT_FIELDS = frozenset({
    "schema_version", "graph_id", "scenario_id", "request", "seed_node_ids",
    "nodes", "edges", "paths", "warnings", "metadata",
})
_PATH_FIELDS = frozenset({
    "seed_node_id", "target_node_id", "depth", "node_ids", "edge_ids",
})
_METADATA_FIELDS = frozenset({
    "node_count", "edge_count", "path_count", "max_reached_depth",
    "truncated", "applied_limits",
})
_Adjacency = dict[str, list[tuple[str, str]]]
_PathState = tuple[tuple[str, ...], tuple[str, ...]]


class KnowledgeGraphTraversalError(ValueError):
    """Raised when graph traversal cannot preserve a valid bounded result."""


def _string_collection(value: object, name: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, Collection) or isinstance(
        value, (str, bytes, bytearray, Mapping),
    ):
        raise KnowledgeGraphTraversalError(f"{name} must be a collection of strings")
    items = list(value)
    if not items and not allow_empty:
        raise KnowledgeGraphTraversalError(f"{name} must not be empty")
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise KnowledgeGraphTraversalError(f"{name} must contain non-empty strings")
        if item in seen:
            raise KnowledgeGraphTraversalError(f"{name} contains duplicate value {item!r}")
        seen.add(item)
    return sorted(items)


def _integer(value: object, name: str, *, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise KnowledgeGraphTraversalError(
            f"{name} must be an integer >= {minimum}, excluding bool"
        )
    if maximum is not None and value > maximum:
        raise KnowledgeGraphTraversalError(f"{name} must not exceed {maximum}")
    return value


def _normalize_request(
    *, seed_node_ids: object, direction: object, max_depth: object,
    allowed_edge_types: object, max_nodes: object, max_edges: object,
    existing_node_ids: set[str],
) -> dict[str, Any]:
    seeds = _string_collection(seed_node_ids, "seed_node_ids", allow_empty=False)
    unknown = sorted(set(seeds) - existing_node_ids)
    if unknown:
        raise KnowledgeGraphTraversalError(f"seed node IDs do not exist: {unknown!r}")
    if not isinstance(direction, str) or direction not in _DIRECTIONS:
        raise KnowledgeGraphTraversalError(
            "direction must be exactly 'outgoing', 'incoming', or 'both'"
        )
    depth = _integer(max_depth, "max_depth", minimum=0, maximum=MAX_TRAVERSAL_DEPTH)
    node_limit = _integer(max_nodes, "max_nodes", minimum=1)
    edge_limit = _integer(max_edges, "max_edges", minimum=1)
    if node_limit < len(seeds):
        raise KnowledgeGraphTraversalError("max_nodes must accommodate every seed node")
    edge_types = None
    if allowed_edge_types is not None:
        edge_types = _string_collection(
            allowed_edge_types, "allowed_edge_types", allow_empty=True,
        )
        if any(IDENTIFIER_PATTERN.fullmatch(item) is None for item in edge_types):
            raise KnowledgeGraphTraversalError(
                "allowed_edge_types must contain normalized identifiers "
                "matching [a-z][a-z0-9_]*"
            )
    return {
        "seed_node_ids": seeds, "direction": direction, "max_depth": depth,
        "allowed_edge_types": edge_types, "max_nodes": node_limit, "max_edges": edge_limit,
    }


def _adjacency(
    edges: Collection[Mapping[str, Any]], request: Mapping[str, Any],
) -> _Adjacency:
    neighbors: dict[str, set[tuple[str, str]]] = {}
    allowed = request["allowed_edge_types"]
    allowed_types = None if allowed is None else set(allowed)
    for edge in edges:
        if allowed_types is not None and edge["edge_type"] not in allowed_types:
            continue
        source, target, edge_id = (
            edge["source_node_id"], edge["target_node_id"], edge["edge_id"],
        )
        if request["direction"] in {"outgoing", "both"}:
            neighbors.setdefault(source, set()).add((target, edge_id))
        if request["direction"] in {"incoming", "both"}:
            neighbors.setdefault(target, set()).add((source, edge_id))
    return {node_id: sorted(items) for node_id, items in neighbors.items()}


def _select_neighborhood(
    adjacency: _Adjacency, request: Mapping[str, Any],
) -> tuple[set[str], set[str], list[str]]:
    """Admit nodes with their discovery edges, rather than slicing arrays."""
    node_ids = set(request["seed_node_ids"])
    edge_ids: set[str] = set()
    applied_limits: set[str] = set()
    frontier = set(node_ids)
    for _ in range(request["max_depth"]):
        candidates = sorted({
            (neighbor, edge_id, source)
            for source in frontier
            for neighbor, edge_id in adjacency.get(source, [])
        })
        next_frontier: set[str] = set()
        for neighbor, edge_id, _source in candidates:
            if edge_id in edge_ids:
                continue
            needs_node = neighbor not in node_ids
            node_blocked = needs_node and len(node_ids) >= request["max_nodes"]
            edge_blocked = len(edge_ids) >= request["max_edges"]
            if node_blocked:
                applied_limits.add("max_nodes")
            if edge_blocked:
                applied_limits.add("max_edges")
            if node_blocked or edge_blocked:
                continue
            edge_ids.add(edge_id)
            if needs_node:
                node_ids.add(neighbor)
                next_frontier.add(neighbor)
        frontier = next_frontier
        if not frontier:
            break
    return node_ids, edge_ids, sorted(applied_limits)


def _canonical_paths(adjacency: _Adjacency, request: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Find one shortest path per seed/target with full node-path tie breaks."""
    paths: list[dict[str, Any]] = []
    for seed in request["seed_node_ids"]:
        best: dict[str, _PathState] = {seed: ((seed,), ())}
        frontier = dict(best)
        for _ in range(request["max_depth"]):
            candidates: dict[str, _PathState] = {}
            for source, (node_path, edge_path) in frontier.items():
                for neighbor, edge_id in adjacency.get(source, []):
                    if neighbor in best:
                        continue
                    candidate = (node_path + (neighbor,), edge_path + (edge_id,))
                    previous = candidates.get(neighbor)
                    if previous is None or candidate < previous:
                        candidates[neighbor] = candidate
            if not candidates:
                break
            best.update(candidates)
            frontier = candidates
        for target, (node_path, edge_path) in best.items():
            paths.append({
                "seed_node_id": seed, "target_node_id": target,
                "depth": len(edge_path), "node_ids": list(node_path), "edge_ids": list(edge_path),
            })
    return sorted(paths, key=lambda path: (
        path["depth"], path["seed_node_id"], path["target_node_id"],
        path["node_ids"], path["edge_ids"],
    ))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise KnowledgeGraphTraversalError(f"Invalid traversal result: {message}")


def _validate_result(result: Mapping[str, Any], graph: Mapping[str, Any]) -> None:
    """Check source preservation, result references, path direction and JSON."""
    _require(set(result) == _RESULT_FIELDS, "unexpected or missing fields")
    _require(result["schema_version"] == TRAVERSAL_RESULT_SCHEMA_VERSION, "schema_version")
    for field in ("graph_id", "scenario_id"):
        _require(result[field] == graph[field], f"{field} differs from source graph")
    original_nodes = {node["node_id"]: node for node in graph["nodes"]}
    original_edges = {edge["edge_id"]: edge for edge in graph["edges"]}
    request = result["request"]
    normalized = _normalize_request(**request, existing_node_ids=set(original_nodes))
    _require(request == normalized, "request is not normalized")
    _require(result["seed_node_ids"] == request["seed_node_ids"], "seed list differs from request")
    for field in ("nodes", "edges", "paths", "warnings"):
        _require(isinstance(result[field], list), f"{field} must be a list")
    node_ids = [node["node_id"] for node in result["nodes"]]
    edge_ids = [edge["edge_id"] for edge in result["edges"]]
    _require(node_ids == sorted(set(node_ids)), "node IDs must be unique and sorted")
    _require(edge_ids == sorted(set(edge_ids)), "edge IDs must be unique and sorted")
    _require(set(request["seed_node_ids"]).issubset(node_ids), "missing seed nodes")
    _require(len(node_ids) <= request["max_nodes"], "max_nodes exceeded")
    _require(len(edge_ids) <= request["max_edges"], "max_edges exceeded")
    for node in result["nodes"]:
        _require(node == original_nodes.get(node["node_id"]), "node differs from source graph")
    returned_nodes = set(node_ids)
    returned_edges = {edge["edge_id"]: edge for edge in result["edges"]}
    for edge in result["edges"]:
        _require(edge == original_edges.get(edge["edge_id"]), "edge differs from source graph")
        _require(
            {edge["source_node_id"], edge["target_node_id"]}.issubset(returned_nodes),
            "dangling edge endpoint",
        )
        _require(
            set(edge["supporting_node_ids"]).issubset(original_nodes),
            "dangling supporting provenance reference in source graph",
        )
        allowed = request["allowed_edge_types"]
        _require(allowed is None or edge["edge_type"] in allowed, "edge type violates filter")
    reached: set[str] = set()
    seed_target_pairs: set[tuple[str, str]] = set()
    for path in result["paths"]:
        _require(set(path) == _PATH_FIELDS, "unexpected or missing path fields")
        depth = _integer(path["depth"], "path.depth", minimum=0, maximum=request["max_depth"])
        nodes, edges = path["node_ids"], path["edge_ids"]
        _require(isinstance(nodes, list) and isinstance(edges, list), "path IDs must be lists")
        _require(len(nodes) == depth + 1 and len(edges) == depth, "path depth mismatch")
        _require(len(nodes) == len(set(nodes)), "path repeats a node")
        _require(set(nodes).issubset(returned_nodes), "dangling path node")
        _require(set(edges).issubset(returned_edges), "dangling path edge")
        _require(path["seed_node_id"] in request["seed_node_ids"], "unknown path seed")
        _require(nodes[0] == path["seed_node_id"], "path starts at another node")
        _require(nodes[-1] == path["target_node_id"], "path ends at another node")
        pair = (path["seed_node_id"], path["target_node_id"])
        _require(pair not in seed_target_pairs, "duplicate seed/target path")
        seed_target_pairs.add(pair)
        reached.update(nodes)
        for index, edge_id in enumerate(edges):
            edge = returned_edges[edge_id]
            step = (nodes[index], nodes[index + 1])
            original_step = (edge["source_node_id"], edge["target_node_id"])
            permitted = []
            if request["direction"] in {"outgoing", "both"}:
                permitted.append(original_step)
            if request["direction"] in {"incoming", "both"}:
                permitted.append(original_step[::-1])
            _require(step in permitted, "path edge orientation violates direction")
    _require(reached == returned_nodes, "node has no returned seed path")
    expected_paths = _canonical_paths(_adjacency(result["edges"], request), request)
    _require(result["paths"] == expected_paths, "paths are not complete canonical shortest paths")
    _require(request["max_depth"] != 0 or not edge_ids, "depth zero must not return edges")
    metadata = result["metadata"]
    _require(set(metadata) == _METADATA_FIELDS, "unexpected or missing metadata fields")
    expected_counts = {
        "node_count": len(node_ids), "edge_count": len(edge_ids),
        "path_count": len(result["paths"]),
        "max_reached_depth": max(path["depth"] for path in result["paths"]),
    }
    for field, expected in expected_counts.items():
        _require(type(metadata[field]) is int and metadata[field] == expected, f"incorrect {field}")
    limits = metadata["applied_limits"]
    _require(
        isinstance(limits, list) and limits == sorted(set(limits))
        and set(limits).issubset({"max_nodes", "max_edges"}),
        "invalid applied_limits",
    )
    _require(type(metadata["truncated"]) is bool, "truncated must be bool")
    _require(metadata["truncated"] == bool(limits), "truncated and applied_limits disagree")
    _require(
        all(isinstance(warning, str) and warning.strip() for warning in result["warnings"]),
        "warnings must contain non-empty strings",
    )
    if limits:
        _require(any("truncated" in warning for warning in result["warnings"]), "truncation warning missing")
    try:
        json.dumps(result, ensure_ascii=False, allow_nan=False, sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise KnowledgeGraphTraversalError(f"Traversal result is not finite UTF-8 JSON: {exc}") from exc


def traverse_knowledge_graph(
    graph: object, *, seed_node_ids: Collection[str], direction: str = "both",
    max_depth: int = 2, allowed_edge_types: Collection[str] | None = None,
    max_nodes: int = 100, max_edges: int = 200,
) -> dict[str, Any]:
    """Return existing nodes, original edges and bounded canonical shortest paths.

    Depth is an integer from zero through 64. All unique seeds are retained;
    max_nodes smaller than their count is an error. Collections are normalized
    by sorting, without trimming IDs or substituting unknown valid edge types.
    An empty edge-type collection permits no edges.

    Neighborhood admission is a multi-source breadth-first search. At each
    depth, candidates are ordered by traversal target node ID, edge ID, then
    source node ID. A new node is admitted together with its discovery edge.
    Other eligible edges, including cycles and self-loops, consume the same
    edge budget. Only nodes below max_depth are expanded; depth zero has no
    edges. Incoming traversal never reverses the copied source edge fields;
    the directed flag is preserved and does not override requested direction.

    One shortest path per seed/target is then computed within the returned
    bounded subgraph, including zero-length seed paths. Ties compare the full
    node-ID sequence before the edge-ID sequence. Paths never repeat a node.
    With truncation these paths can differ from paths in the complete graph.
    No edge name, status or attribute is interpreted as a security conclusion.
    """
    try:
        try:
            validate_knowledge_graph(graph)
        except Exception as exc:
            raise KnowledgeGraphTraversalError(f"Invalid Knowledge Graph: {exc}") from exc
        source = cast(Mapping[str, Any], graph)
        node_lookup = {node["node_id"]: node for node in source["nodes"]}
        edge_lookup = {edge["edge_id"]: edge for edge in source["edges"]}
        request = _normalize_request(
            seed_node_ids=seed_node_ids, direction=direction, max_depth=max_depth,
            allowed_edge_types=allowed_edge_types, max_nodes=max_nodes, max_edges=max_edges,
            existing_node_ids=set(node_lookup),
        )
        node_ids, edge_ids, limits = _select_neighborhood(_adjacency(source["edges"], request), request)
        nodes = [deepcopy(node_lookup[node_id]) for node_id in sorted(node_ids)]
        edges = [deepcopy(edge_lookup[edge_id]) for edge_id in sorted(edge_ids)]
        paths = _canonical_paths(_adjacency(edges, request), request)
        warnings = sorted(deepcopy(source["warnings"]) + [
            f"Traversal result truncated by {limit}={request[limit]}." for limit in limits
        ])
        result = {
            "schema_version": TRAVERSAL_RESULT_SCHEMA_VERSION,
            "graph_id": source["graph_id"], "scenario_id": source["scenario_id"],
            "request": request, "seed_node_ids": list(request["seed_node_ids"]),
            "nodes": nodes, "edges": edges, "paths": paths, "warnings": warnings,
            "metadata": {
                "node_count": len(nodes), "edge_count": len(edges), "path_count": len(paths),
                "max_reached_depth": max(path["depth"] for path in paths),
                "truncated": bool(limits), "applied_limits": limits,
            },
        }
        _validate_result(result, source)
        return result
    except KnowledgeGraphTraversalError:
        raise
    except Exception as exc:
        raise KnowledgeGraphTraversalError(f"Knowledge Graph traversal failed: {exc}") from exc


__all__ = ("KnowledgeGraphTraversalError", "traverse_knowledge_graph")
