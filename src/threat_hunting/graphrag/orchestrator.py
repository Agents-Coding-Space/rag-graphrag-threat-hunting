"""Compose existing in-memory retrieval, exact seed mapping and graph traversal.

Each component owns its algorithm and validation. This module preserves their
complete results and validates only the assembled context and shared identities.
Traversal options are validated by traversal when seeds are available.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from copy import deepcopy
import json
from typing import Any, cast

from ..graph.traversal import TRAVERSAL_RESULT_SCHEMA_VERSION, traverse_knowledge_graph
from ..retrieval.hybrid import retrieve_hybrid
from .seed_mapping import map_hybrid_hits_to_graph_seeds


GRAPHRAG_CONTEXT_SCHEMA_VERSION = "graphrag-context/v1"
_CONTEXT_FIELDS = frozenset({
    "schema_version", "corpus_id", "graph_id", "scenario_id", "source_ground_truth",
    "query", "retrieval", "seed_mapping", "traversal", "warnings", "metadata",
})
_METADATA_FIELDS = frozenset({
    "retrieval_hit_count", "mapped_hit_count", "seed_node_count", "traversal_performed",
    "traversed_node_count", "traversed_edge_count", "traversed_path_count",
})
_SKIPPED_TRAVERSAL_WARNING = (
    "Graph traversal skipped: no retrieval hits or graph seeds are available."
)


class GraphRAGOrchestrationError(ValueError):
    """Raised when a component or assembled context cannot preserve its contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _json_bytes(value: object) -> bytes:
    """Check finite native JSON and strict UTF-8 without repairing Python values."""
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")
    # JSON encoding detects cycles, but also accepts tuples and numeric keys.
    # Reject those conversions so provenance cannot change during serialization.
    pending = [value]
    visited: set[int] = set()
    while pending:
        item = pending.pop()
        if isinstance(item, (dict, list)):
            if id(item) in visited:
                continue
            visited.add(id(item))
            if isinstance(item, dict):
                _require(all(isinstance(key, str) for key in item), "Non-string JSON key")
                pending.extend(item.values())
            else:
                pending.extend(item)
        else:
            _require(
                item is None or isinstance(item, (str, bool, int, float)),
                "Non-native JSON value in GraphRAG context",
            )
    return encoded


def _merged_warnings(
    retrieval: Mapping[str, Any], seed_mapping: Mapping[str, Any],
    traversal: Mapping[str, Any] | None,
) -> list[str]:
    stages = [retrieval, seed_mapping]
    if traversal is not None:
        stages.append(traversal)
    warnings: set[str] = set()
    for stage in stages:
        items = stage["warnings"]
        _require(isinstance(items, list), "Component warnings must be a list")
        _require(
            all(isinstance(item, str) and item.strip() for item in items),
            "Component warnings must contain non-empty strings",
        )
        warnings.update(items)
    if traversal is None:
        warnings.add(_SKIPPED_TRAVERSAL_WARNING)
    return sorted(warnings)


def _check_count(metadata: Mapping[str, Any], field: str, expected: int) -> None:
    value = metadata[field]
    _require(type(value) is int and value == expected, f"Incorrect {field}")


def _validate_context(
    context: dict[str, Any], corpus: Mapping[str, Any], graph: Mapping[str, Any],
) -> None:
    """Validate envelope coherence; component algorithms are never rerun."""
    _json_bytes(context)
    _require(set(context) == _CONTEXT_FIELDS, "Unexpected or missing context fields")
    _require(
        context["schema_version"] == GRAPHRAG_CONTEXT_SCHEMA_VERSION,
        "Context schema_version mismatch",
    )
    retrieval, seeds, traversal = (
        context["retrieval"], context["seed_mapping"], context["traversal"],
    )
    for field in ("corpus_id", "scenario_id"):
        _require(
            context[field] == retrieval[field] == seeds[field] == corpus[field],
            f"Context {field} mismatch",
        )
    _require(context["graph_id"] == seeds["graph_id"] == graph["graph_id"], "Graph ID mismatch")
    _require(context["scenario_id"] == graph["scenario_id"], "Graph scenario ID mismatch")
    for source in (seeds["source_ground_truth"], corpus["source_ground_truth"], graph["source_ground_truth"]):
        _require(
            _json_bytes(context["source_ground_truth"]) == _json_bytes(source),
            "Source Ground Truth mismatch",
        )
    _require(
        _json_bytes(context["query"]) == _json_bytes(retrieval["query"])
        == _json_bytes(seeds["query"]),
        "Context query mismatch",
    )
    seed_ids = seeds["seed_node_ids"]
    _require(isinstance(seed_ids, list), "Seed node IDs must be a list")
    _require(
        all(isinstance(item, str) and item.strip() for item in seed_ids)
        and seed_ids == sorted(set(seed_ids)),
        "Seed node IDs must be unique and sorted",
    )
    hit_count, mapped_count = len(retrieval["hits"]), len(seeds["hit_mappings"])
    _require(hit_count == mapped_count, "Incomplete retrieval hit mapping")
    _check_count(retrieval["metadata"], "returned_hits", hit_count)
    for field, count in (
        ("retrieval_hit_count", hit_count), ("mapped_hit_count", mapped_count),
        ("seed_node_count", len(seed_ids)),
    ):
        _check_count(seeds["metadata"], field, count)
    performed = bool(retrieval["hits"] and seed_ids)
    _require((traversal is not None) == performed, "Traversal presence differs from seeds/hits")
    traversed_counts = {"node": 0, "edge": 0, "path": 0}
    if traversal is not None:
        _require(
            traversal["schema_version"] == TRAVERSAL_RESULT_SCHEMA_VERSION,
            "Traversal schema_version mismatch",
        )
        for field in ("graph_id", "scenario_id"):
            _require(traversal[field] == context[field], f"Traversal {field} mismatch")
        _require(
            traversal["seed_node_ids"] == traversal["request"]["seed_node_ids"] == seed_ids,
            "Traversal must retain every mapped seed",
        )
        for singular, plural, identifier in (
            ("node", "nodes", "node_id"), ("edge", "edges", "edge_id"),
        ):
            original = {item[identifier]: item for item in graph[plural]}
            for item in traversal[plural]:
                _require(
                    item[identifier] in original
                    and _json_bytes(item) == _json_bytes(original[item[identifier]]),
                    f"Traversal {singular} differs from source graph",
                )
        for singular, plural in (("node", "nodes"), ("edge", "edges"), ("path", "paths")):
            traversed_counts[singular] = len(traversal[plural])
            _check_count(traversal["metadata"], f"{singular}_count", traversed_counts[singular])
    metadata = context["metadata"]
    _require(set(metadata) == _METADATA_FIELDS, "Unexpected or missing context metadata fields")
    _require(
        type(metadata["traversal_performed"]) is bool
        and metadata["traversal_performed"] == performed,
        "Incorrect traversal_performed",
    )
    for field, count in (
        ("retrieval_hit_count", hit_count), ("mapped_hit_count", mapped_count),
        ("seed_node_count", len(seed_ids)),
        *((f"traversed_{name}_count", count) for name, count in traversed_counts.items()),
    ):
        _check_count(metadata, field, count)
    _require(
        context["warnings"] == _merged_warnings(retrieval, seeds, traversal),
        "Context warnings must be merged, unique and sorted",
    )


def build_graphrag_context(
    retrieval_corpus: object, vector_index: object, knowledge_graph: object, query: object,
    *, corpus_sha256: object, embed_query: Callable[[list[str]], object],
    top_k: object = 5, candidate_k: object = 20,
    chunk_types: object = None, required_dimensions: object = None,
    direction: str = "both", max_depth: int = 2,
    allowed_edge_types: Collection[str] | None = None,
    max_nodes: int = 100, max_edges: int = 200,
) -> dict[str, Any]:
    """Return detached component results without interpreting scores or claims.

    Components run once in order. Every mapped seed is passed to traversal;
    no hits or seeds skip traversal and retain an explicit warning instead.
    Exceptions retain their cause and phase; process-control exceptions escape.
    """
    try:
        retrieval = retrieve_hybrid(
            retrieval_corpus, vector_index, query, corpus_sha256=corpus_sha256,
            embed_query=embed_query, top_k=top_k, candidate_k=candidate_k,
            chunk_types=chunk_types, required_dimensions=required_dimensions,
        )
    except Exception as exc:
        raise GraphRAGOrchestrationError(f"Hybrid retrieval failed: {exc}") from exc
    try:
        seed_mapping = map_hybrid_hits_to_graph_seeds(
            retrieval_corpus, retrieval, knowledge_graph,
        )
        seed_ids = seed_mapping["seed_node_ids"]
        should_traverse = bool(retrieval["hits"] and seed_ids)
    except Exception as exc:
        raise GraphRAGOrchestrationError(f"Graph seed mapping failed: {exc}") from exc
    traversal = None
    if should_traverse:
        try:
            traversal = traverse_knowledge_graph(
                knowledge_graph, seed_node_ids=seed_ids, direction=direction,
                max_depth=max_depth, allowed_edge_types=allowed_edge_types,
                max_nodes=max_nodes, max_edges=max_edges,
            )
        except Exception as exc:
            raise GraphRAGOrchestrationError(f"Graph traversal failed: {exc}") from exc
    try:
        corpus = cast(Mapping[str, Any], retrieval_corpus)
        graph = cast(Mapping[str, Any], knowledge_graph)
        context = {
            "schema_version": GRAPHRAG_CONTEXT_SCHEMA_VERSION,
            "corpus_id": deepcopy(corpus["corpus_id"]),
            "graph_id": deepcopy(graph["graph_id"]),
            "scenario_id": deepcopy(corpus["scenario_id"]),
            "source_ground_truth": deepcopy(corpus["source_ground_truth"]),
            "query": deepcopy(retrieval["query"]),
            "retrieval": deepcopy(retrieval), "seed_mapping": deepcopy(seed_mapping),
            "traversal": deepcopy(traversal),
            "warnings": _merged_warnings(retrieval, seed_mapping, traversal),
            "metadata": {
                "retrieval_hit_count": len(retrieval["hits"]),
                "mapped_hit_count": len(seed_mapping["hit_mappings"]),
                "seed_node_count": len(seed_ids), "traversal_performed": traversal is not None,
                "traversed_node_count": len(traversal["nodes"]) if traversal is not None else 0,
                "traversed_edge_count": len(traversal["edges"]) if traversal is not None else 0,
                "traversed_path_count": len(traversal["paths"]) if traversal is not None else 0,
            },
        }
        _validate_context(context, corpus, graph)
        return context
    except Exception as exc:
        raise GraphRAGOrchestrationError(f"GraphRAG output validation failed: {exc}") from exc


__all__ = (
    "GRAPHRAG_CONTEXT_SCHEMA_VERSION", "GraphRAGOrchestrationError", "build_graphrag_context",
)
