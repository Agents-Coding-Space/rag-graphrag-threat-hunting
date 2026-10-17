"""Map Hybrid retrieval hits to graph seeds using exact source provenance only."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import json
import math
from typing import Any, cast

from ..graph.schema import validate_knowledge_graph
from ..retrieval.hybrid import (
    HYBRID_RETRIEVAL_METHOD,
    RRF_K,
    SCORE_INTERPRETATION,
    SCORE_PRECISION,
)
from ..retrieval.lexical import (
    LEXICAL_RETRIEVAL_METHOD,
    RETRIEVAL_RESULT_SCHEMA_VERSION,
    tokenize_retrieval_text,
)
from ..retrieval.schema import CHUNK_SOURCE_OBJECT_TYPES, validate_retrieval_corpus


GRAPH_SEED_MAP_SCHEMA_VERSION = "graphrag-seed-map/v1"
_RESULT_FIELDS = (
    "schema_version", "retrieval_method", "corpus_id", "scenario_id",
    "query", "hits", "warnings", "metadata",
)
_QUERY_FIELDS = ("text", "normalized_terms", "top_k", "candidate_k", "filters")
_METADATA_FIELDS = (
    "total_chunks", "eligible_chunks", "returned_hits", "lexical_candidate_count",
    "vector_candidate_count", "union_candidate_count", "rrf_k", "score_precision",
    "score_interpretation", "component_methods",
)
_COMPONENT_METHODS = {"lexical": LEXICAL_RETRIEVAL_METHOD, "vector": "vector-cosine/v1"}
_SourceKey = tuple[str, str | None, str]


class GraphSeedMappingError(ValueError):
    """Raised when inputs cannot be mapped without exact provenance integrity."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GraphSeedMappingError(message)


def _object(value: object, context: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), f"{context} must be an object")
    return cast(Mapping[str, Any], value)


def _fields(value: Mapping[str, Any], fields: tuple[str, ...], context: str) -> None:
    _require(set(value) == set(fields), f"{context} has missing or unexpected fields")


def _integer(value: object, context: str, *, minimum: int = 0) -> int:
    _require(
        isinstance(value, int) and not isinstance(value, bool) and value >= minimum,
        f"{context} must be an integer >= {minimum}, excluding bool",
    )
    return cast(int, value)


def _positive_number(value: object, context: str, *, maximum: float | None = None) -> None:
    _require(
        isinstance(value, (int, float)) and not isinstance(value, bool),
        f"{context} must be a finite positive number",
    )
    try:
        finite = math.isfinite(cast(float, value))
    except OverflowError:
        finite = False
    _require(finite and cast(float, value) > 0, f"{context} must be a finite positive number")
    _require(maximum is None or cast(float, value) <= maximum, f"{context} exceeds {maximum}")


def _strings(value: object, context: str, *, unique: bool = True) -> list[str]:
    _require(isinstance(value, list), f"{context} must be a list")
    items = cast(list[Any], value)
    _require(
        all(isinstance(item, str) and item.strip() for item in items),
        f"{context} must contain non-empty strings",
    )
    _require(not unique or len(set(items)) == len(items), f"{context} contains duplicates")
    return items


def _canonical_json(value: object) -> bytes:
    """Compare JSON values without bool/int coercion or dictionary-order effects."""
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")
    # The encoder also accepts tuples and numeric object keys. Neither is a
    # native JSON value, and key coercion could conceal a changed full chunk.
    pending = [value]
    visited: set[int] = set()
    while pending:
        item = pending.pop()
        if isinstance(item, (dict, list)):
            if id(item) in visited:
                continue
            visited.add(id(item))
            if isinstance(item, dict):
                _require(all(isinstance(key, str) for key in item), "JSON object keys must be strings")
                pending.extend(item.values())
            else:
                pending.extend(item)
        else:
            _require(item is None or isinstance(item, (str, bool, int, float)), "Non-JSON value in mapping inputs or output")
    return encoded


def _validate_query(
    value: object, corpus: Mapping[str, Any],
) -> tuple[Mapping[str, Any], set[str]]:
    query = _object(value, "hybrid.query")
    _fields(query, _QUERY_FIELDS, "hybrid.query")
    text = query["text"]
    _require(isinstance(text, str) and bool(text.strip()), "hybrid.query.text must be non-empty text")
    terms = _strings(query["normalized_terms"], "hybrid.query.normalized_terms")
    _require(
        bool(terms) and terms == list(dict.fromkeys(tokenize_retrieval_text(text))),
        "hybrid.query.normalized_terms must match query text",
    )
    top_k = _integer(query["top_k"], "hybrid.query.top_k", minimum=1)
    candidate_k = _integer(query["candidate_k"], "hybrid.query.candidate_k", minimum=1)
    _require(candidate_k >= top_k, "hybrid.query.candidate_k must be >= top_k")
    filters = _object(query["filters"], "hybrid.query.filters")
    _fields(filters, ("chunk_types", "required_dimensions"), "hybrid.query.filters")
    for name, allowed in (
        ("chunk_types", set(CHUNK_SOURCE_OBJECT_TYPES)),
        ("required_dimensions", set(corpus["queryable_dimensions"])),
    ):
        if filters[name] is not None:
            items = _strings(filters[name], f"hybrid.query.filters.{name}")
            _require(items == sorted(items), f"hybrid.query.filters.{name} must be sorted")
            _require(set(items).issubset(allowed), f"hybrid.query.filters.{name} has unsupported values")
    types, dimensions = filters["chunk_types"], filters["required_dimensions"]
    eligible = {
        chunk["chunk_id"] for chunk in corpus["chunks"]
        if (types is None or chunk["chunk_type"] in types)
        and set(dimensions or []).issubset(chunk["queryable_dimensions"])
    }
    return query, eligible


def _validate_metadata(
    value: object, *, total: int, eligible: int, hit_count: int, query: Mapping[str, Any],
) -> Mapping[str, Any]:
    metadata = _object(value, "hybrid.metadata")
    _fields(metadata, _METADATA_FIELDS, "hybrid.metadata")
    count_fields = (
        "total_chunks", "eligible_chunks", "returned_hits", "lexical_candidate_count",
        "vector_candidate_count", "union_candidate_count", "rrf_k", "score_precision",
    )
    for field in count_fields:
        _integer(metadata[field], f"hybrid.metadata.{field}")
    _require(
        metadata["total_chunks"] == total and metadata["eligible_chunks"] == eligible
        and metadata["returned_hits"] == hit_count,
        "hybrid.metadata chunk/hit counts mismatch",
    )
    lexical, vector, union = (
        metadata["lexical_candidate_count"], metadata["vector_candidate_count"],
        metadata["union_candidate_count"],
    )
    _require(
        max(lexical, vector) <= min(query["candidate_k"], eligible)
        and max(lexical, vector) <= union <= min(lexical + vector, eligible)
        and hit_count == min(query["top_k"], union),
        "hybrid.metadata candidate/hit counts are inconsistent",
    )
    _require(
        metadata["rrf_k"] == RRF_K and metadata["score_precision"] == SCORE_PRECISION
        and metadata["score_interpretation"] == SCORE_INTERPRETATION
        and metadata["component_methods"] == _COMPONENT_METHODS,
        "hybrid.metadata retrieval method descriptors mismatch",
    )
    return metadata


def _validate_components(
    value: object, *, metadata: Mapping[str, Any], seen_ranks: dict[str, set[int]],
    context: str,
) -> None:
    components = _object(value, context)
    _fields(components, ("lexical", "vector"), context)
    _require(any(item is not None for item in components.values()), f"{context} has no component")
    for name in ("lexical", "vector"):
        if components[name] is None:
            continue
        component = _object(components[name], f"{context}.{name}")
        _fields(component, ("rank", "score", "contribution"), f"{context}.{name}")
        rank = _integer(component["rank"], f"{context}.{name}.rank", minimum=1)
        _require(
            rank <= metadata[f"{name}_candidate_count"] and rank not in seen_ranks[name],
            f"{context}.{name}.rank exceeds candidate count or is duplicated",
        )
        seen_ranks[name].add(rank)
        _positive_number(
            component["score"], f"{context}.{name}.score",
            maximum=1.0 if name == "vector" else None,
        )
        _positive_number(component["contribution"], f"{context}.{name}.contribution", maximum=1.0)


def _validate_hybrid(
    value: object, corpus: Mapping[str, Any],
) -> Mapping[str, Any]:
    result = _object(value, "hybrid result")
    _fields(result, _RESULT_FIELDS, "hybrid result")
    _require(result["schema_version"] == RETRIEVAL_RESULT_SCHEMA_VERSION, "hybrid schema_version mismatch")
    _require(result["retrieval_method"] == HYBRID_RETRIEVAL_METHOD, "retrieval_method must be hybrid-rrf/v1")
    for field in ("corpus_id", "scenario_id"):
        _require(result[field] == corpus[field], f"hybrid {field} mismatch with Retrieval Corpus")
    query, eligible = _validate_query(result["query"], corpus)
    _strings(result["warnings"], "hybrid.warnings", unique=False)
    hits = result["hits"]
    _require(isinstance(hits, list), "hybrid.hits must be a list")
    metadata = _validate_metadata(
        result["metadata"], total=len(corpus["chunks"]), eligible=len(eligible),
        hit_count=len(hits), query=query,
    )
    chunks = {chunk["chunk_id"]: chunk for chunk in corpus["chunks"]}
    seen_chunks: set[str] = set()
    seen_ranks: dict[str, set[int]] = {"lexical": set(), "vector": set()}
    observed_memberships = {"lexical_only": 0, "vector_only": 0, "both": 0}
    for rank, value in enumerate(hits, 1):
        context = f"hybrid.hits[{rank - 1}]"
        hit = _object(value, context)
        _fields(hit, ("rank", "score", "components", "chunk"), context)
        _require(_integer(hit["rank"], f"{context}.rank", minimum=1) == rank, f"{context}.rank must be consecutive from 1")
        _positive_number(hit["score"], f"{context}.score")
        _validate_components(hit["components"], metadata=metadata, seen_ranks=seen_ranks, context=f"{context}.components")
        lexical_present = hit["components"]["lexical"] is not None
        vector_present = hit["components"]["vector"] is not None
        membership = "both" if lexical_present and vector_present else (
            "lexical_only" if lexical_present else "vector_only"
        )
        observed_memberships[membership] += 1
        chunk = _object(hit["chunk"], f"{context}.chunk")
        chunk_id = chunk.get("chunk_id")
        _require(isinstance(chunk_id, str) and chunk_id in chunks, f"{context}.chunk_id does not exist in corpus")
        _require(chunk_id not in seen_chunks, f"{context}: duplicate chunk ID")
        _require(chunk_id in eligible, f"{context}.chunk violates query filters")
        _require(
            _canonical_json(chunk) == _canonical_json(chunks[chunk_id]),
            f"{context}: full chunk differs from Retrieval Corpus",
        )
        seen_chunks.add(chunk_id)
    lexical = metadata["lexical_candidate_count"]
    vector = metadata["vector_candidate_count"]
    union = metadata["union_candidate_count"]
    _require(
        observed_memberships["both"] <= lexical + vector - union
        and observed_memberships["lexical_only"] <= union - vector
        and observed_memberships["vector_only"] <= union - lexical,
        "hybrid.metadata candidate overlap counts conflict with hit components",
    )
    # Check only JSON structure and finite UTF-8 values, never recalculate scores.
    _canonical_json(result)
    return result


def _source_key(source: Mapping[str, Any]) -> _SourceKey:
    return source["object_type"], source["object_id"], source["json_pointer"]


def _source_index(items: list[Mapping[str, Any]]) -> dict[_SourceKey, list[Mapping[str, Any]]]:
    index: dict[_SourceKey, list[Mapping[str, Any]]] = {}
    for item in items:
        index.setdefault(_source_key(item["source"]), []).append(item)
    return index


def _map_hybrid_hits_to_graph_seeds(
    retrieval_corpus: object, hybrid_result: object, knowledge_graph: object,
) -> dict[str, Any]:
    validate_retrieval_corpus(retrieval_corpus)
    validate_knowledge_graph(knowledge_graph)
    corpus = cast(Mapping[str, Any], retrieval_corpus)
    graph = cast(Mapping[str, Any], knowledge_graph)
    _require(graph["scenario_id"] == corpus["scenario_id"], "Graph and Corpus scenario_id mismatch")
    _require(
        _canonical_json(graph["source_ground_truth"]) == _canonical_json(corpus["source_ground_truth"]),
        "Graph and Corpus source_ground_truth mismatch",
    )
    hybrid = _validate_hybrid(hybrid_result, corpus)
    node_index, edge_index = _source_index(graph["nodes"]), _source_index(graph["edges"])
    mappings: list[dict[str, Any]] = []
    seeds: set[str] = set()
    direct_count = 0
    for hit in hybrid["hits"]:
        chunk = hit["chunk"]
        key = _source_key(chunk["source"])
        expected_type = CHUNK_SOURCE_OBJECT_TYPES[chunk["chunk_type"]]
        _require(key[0] == expected_type, f"Chunk {chunk['chunk_id']!r}: incompatible source object type")
        if chunk["chunk_type"] == "relationship":
            matches = edge_index.get(key, [])
            _require(len(matches) == 1, f"Chunk {chunk['chunk_id']!r}: expected exactly one graph edge source match, got {len(matches)}")
            edge = matches[0]
            node_ids = sorted({edge["source_node_id"], edge["target_node_id"]})
            edge_ids = [edge["edge_id"]]
            kind = "relationship_edge"
        else:
            matches = node_index.get(key, [])
            _require(len(matches) == 1, f"Chunk {chunk['chunk_id']!r}: expected exactly one graph node source match, got {len(matches)}")
            node = matches[0]
            _require(node["node_type"] == expected_type, f"Chunk {chunk['chunk_id']!r}: wrong graph node mapping type")
            node_ids, edge_ids, kind = [node["node_id"]], [], "direct_node"
            direct_count += 1
        seeds.update(node_ids)
        mappings.append({
            "hit_rank": deepcopy(hit["rank"]), "hit_score": deepcopy(hit["score"]),
            "components": deepcopy(hit["components"]),
            "chunk_id": deepcopy(chunk["chunk_id"]), "chunk_type": deepcopy(chunk["chunk_type"]),
            "source": deepcopy(chunk["source"]), "mapping_kind": kind,
            "matched_node_ids": deepcopy(node_ids), "matched_edge_ids": deepcopy(edge_ids),
        })
    warnings = deepcopy(hybrid["warnings"])
    if not mappings:
        warnings.append("No retrieval hits are available to create graph seeds.")
    result = {
        "schema_version": GRAPH_SEED_MAP_SCHEMA_VERSION,
        "corpus_id": deepcopy(corpus["corpus_id"]), "graph_id": deepcopy(graph["graph_id"]),
        "scenario_id": deepcopy(corpus["scenario_id"]),
        "source_ground_truth": deepcopy(corpus["source_ground_truth"]),
        "retrieval_method": deepcopy(hybrid["retrieval_method"]), "query": deepcopy(hybrid["query"]),
        "hit_mappings": mappings, "seed_node_ids": sorted(seeds), "warnings": warnings,
        "metadata": {
            "retrieval_hit_count": len(hybrid["hits"]), "mapped_hit_count": len(mappings),
            "direct_node_mapping_count": direct_count,
            "relationship_edge_mapping_count": len(mappings) - direct_count,
            "seed_node_count": len(seeds),
        },
    }
    _canonical_json(result)
    return result


def map_hybrid_hits_to_graph_seeds(
    retrieval_corpus: object, hybrid_result: object, knowledge_graph: object,
) -> dict[str, Any]:
    """Validate linked inputs and preserve one mapping per ranked Hybrid hit.

    Source keys include object_type, object_id and json_pointer without
    normalization or fallback. Direct hits must match one node of the correct
    type; relationship hits must match one edge and select only its endpoints.
    Null IDs are compared literally. Scores and components are copied without
    computing retrieval scores or interpreting graph relationships.
    """
    try:
        return _map_hybrid_hits_to_graph_seeds(retrieval_corpus, hybrid_result, knowledge_graph)
    except GraphSeedMappingError:
        raise
    except Exception as exc:
        raise GraphSeedMappingError(f"Graph seed mapping failed: {exc}") from exc


__all__ = (
    "GRAPH_SEED_MAP_SCHEMA_VERSION", "GraphSeedMappingError", "map_hybrid_hits_to_graph_seeds",
)
