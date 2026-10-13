"""Assess context eligibility using only observed signals and an explicit policy.

Count minima of zero disable those count requirements; a null cosine minimum
disables the vector-score requirement. There are no default relevance thresholds.
Malformed inputs raise GraphRAGRelevanceError, while valid insufficient evidence
returns abstain. Neither decision assesses the truth of a security claim.

Structural v1 objects have exact fields. Source chunk metadata and graph
attributes remain opaque JSON maps, as specified by their existing contracts.
They never supply relevance signals. No scores, tokens or paths are recomputed.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
import re
from typing import Any, cast

from ..graph.schema import EDGE_FIELDS, GRAPH_STATUSES, IDENTIFIER_PATTERN, NODE_FIELDS
from ..retrieval.hybrid import RRF_K, SCORE_PRECISION
from ..retrieval.schema import (
    AGGREGATE_CHUNK_TYPES, CHUNK_FIELDS, CHUNK_REFERENCE_LIST_FIELDS,
    CHUNK_SOURCE_OBJECT_TYPES, CHUNK_STATUSES,
)


GRAPHRAG_RELEVANCE_POLICY_SCHEMA_VERSION = "graphrag-relevance-policy/v1"
GRAPHRAG_RELEVANCE_DECISION_SCHEMA_VERSION = "graphrag-relevance-decision/v1"
_POLICY_FIELDS = (
    "schema_version", "policy_id", "min_hits", "min_mapped_hits", "min_seed_nodes",
    "require_traversal", "min_traversal_nodes", "require_lexical_support",
    "min_cosine_score", "require_joint_lexical_vector_support",
)
_CONTEXT_FIELDS = (
    "schema_version", "corpus_id", "graph_id", "scenario_id", "source_ground_truth",
    "query", "retrieval", "seed_mapping", "traversal", "warnings", "metadata",
)
_QUERY_FIELDS = ("text", "normalized_terms", "top_k", "candidate_k", "filters")
_RETRIEVAL_FIELDS = (
    "schema_version", "retrieval_method", "corpus_id", "scenario_id", "query",
    "hits", "warnings", "metadata",
)
_RETRIEVAL_METADATA_FIELDS = (
    "total_chunks", "eligible_chunks", "returned_hits", "lexical_candidate_count",
    "vector_candidate_count", "union_candidate_count", "rrf_k", "score_precision",
    "score_interpretation", "component_methods",
)
_SEED_FIELDS = (
    "schema_version", "corpus_id", "graph_id", "scenario_id", "source_ground_truth",
    "retrieval_method", "query", "hit_mappings", "seed_node_ids", "warnings", "metadata",
)
_MAPPING_FIELDS = (
    "hit_rank", "hit_score", "components", "chunk_id", "chunk_type", "source",
    "mapping_kind", "matched_node_ids", "matched_edge_ids",
)
_SEED_METADATA_FIELDS = (
    "retrieval_hit_count", "mapped_hit_count", "direct_node_mapping_count",
    "relationship_edge_mapping_count", "seed_node_count",
)
_CONTEXT_METADATA_FIELDS = (
    "retrieval_hit_count", "mapped_hit_count", "seed_node_count", "traversal_performed",
    "traversed_node_count", "traversed_edge_count", "traversed_path_count",
)
_TRAVERSAL_FIELDS = (
    "schema_version", "graph_id", "scenario_id", "request", "seed_node_ids",
    "nodes", "edges", "paths", "warnings", "metadata",
)
_REQUEST_FIELDS = (
    "seed_node_ids", "direction", "max_depth", "allowed_edge_types", "max_nodes", "max_edges",
)
_PATH_FIELDS = ("seed_node_id", "target_node_id", "depth", "node_ids", "edge_ids")
_TRAVERSAL_METADATA_FIELDS = (
    "node_count", "edge_count", "path_count", "max_reached_depth", "truncated", "applied_limits",
)
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_INVALID_POINTER_ESCAPE = re.compile(r"~(?![01])")


class GraphRAGRelevanceError(ValueError):
    """Raised when context or policy cannot be assessed without trusting bad data."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GraphRAGRelevanceError(message)


def _snapshot(value: object, path: str, active: set[int]) -> Any:
    """Detach native finite UTF-8 JSON, accepting read-only Mapping inputs."""
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return value
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        _require(math.isfinite(value), f"{path} must contain finite numbers")
        return value
    _require(isinstance(value, (Mapping, list)), f"{path} must contain native JSON values")
    _require(id(value) not in active, f"{path} contains a circular reference")
    active.add(id(value))
    try:
        if isinstance(value, Mapping):
            result = {}
            for key, item in value.items():
                _require(isinstance(key, str), f"{path} contains a non-string key")
                key.encode("utf-8", errors="strict")
                result[key] = _snapshot(item, f"{path}.{key}", active)
            return result
        return [_snapshot(item, f"{path}[{index}]", active) for index, item in enumerate(value)]
    finally:
        active.remove(id(value))


def _object(value: object, path: str, fields: tuple[str, ...] | None = None) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{path} must be an object")
    result = cast(dict[str, Any], value)
    if fields is not None:
        _require(set(result) == set(fields), f"{path} has missing or unknown fields")
    return result


def _json_bytes(value: object) -> bytes:
    """Validate serialization and compare echoes without numeric type coercion."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _list(value: object, path: str) -> list[Any]:
    _require(isinstance(value, list), f"{path} must be a list")
    return cast(list[Any], value)


def _text(value: object, path: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()), f"{path} must be non-empty text")
    return cast(str, value)


def _integer(value: object, path: str, minimum: int = 0, maximum: int | None = None) -> int:
    _require(type(value) is int and value >= minimum, f"{path} must be an integer >= {minimum}, excluding bool")
    _require(maximum is None or cast(int, value) <= maximum, f"{path} exceeds its valid range")
    return cast(int, value)


def _boolean(value: object, path: str) -> bool:
    _require(type(value) is bool, f"{path} must be a boolean")
    return cast(bool, value)


def _number(value: object, path: str, *, cosine: bool = False, contribution: bool = False) -> int | float:
    _require(type(value) in (int, float), f"{path} must be numeric, excluding bool")
    number = cast(int | float, value)
    try:
        finite = math.isfinite(number)
    except OverflowError:
        finite = False
    _require(finite, f"{path} must be finite")
    if cosine:
        _require(-1 <= number <= 1, f"{path} must be in [-1, 1]")
    else:
        _require(number > 0, f"{path} must be positive")
    if contribution:
        _require(number <= 1, f"{path} contribution must not exceed 1")
    return number


def _strings(value: object, path: str, *, sorted_unique: bool = False, unique: bool = True) -> list[str]:
    items = [_text(item, f"{path}[{index}]") for index, item in enumerate(_list(value, path))]
    _require(not unique or len(items) == len(set(items)), f"{path} contains duplicates")
    _require(not sorted_unique or items == sorted(set(items)), f"{path} must be sorted and unique")
    return items


def _counts(value: object, path: str, expected: Mapping[str, int], fields: tuple[str, ...]) -> dict[str, Any]:
    metadata = _object(value, path, fields)
    for name, count in expected.items():
        _require(_integer(metadata[name], f"{path}.{name}") == count, f"{path}.{name} disagrees with observed data")
    return metadata


def _provenance(value: object, scenario: str, path: str) -> None:
    source = _object(value, path, ("path", "schema_version", "sha256", "scenario_id"))
    _text(source["path"], f"{path}.path")
    _require(source["schema_version"] == "scenario-ground-truth/v1", f"{path}.schema_version is unsupported")
    _require(_SHA256.fullmatch(_text(source["sha256"], f"{path}.sha256")) is not None, f"{path}.sha256 must be 64 hexadecimal characters")
    _require(source["scenario_id"] == scenario, f"{path}.scenario_id mismatch")


def _source(value: object, path: str, chunk_type: str | None = None) -> None:
    fields = ("object_type", "object_id", "json_pointer")
    source = _object(value, path, ("artifact_type", *fields) if chunk_type is not None else fields)
    _text(source["object_type"], f"{path}.object_type")
    if source["object_id"] is not None:
        _text(source["object_id"], f"{path}.object_id")
    pointer = _text(source["json_pointer"], f"{path}.json_pointer")
    _require(pointer.startswith("/") and _INVALID_POINTER_ESCAPE.search(pointer) is None, f"{path}.json_pointer is invalid")
    if chunk_type is not None:
        _require(source["artifact_type"] == "scenario_ground_truth", f"{path}.artifact_type mismatch")
        _require(source["object_type"] == CHUNK_SOURCE_OBJECT_TYPES[chunk_type], f"{path}.object_type mismatch")
        _require((source["object_id"] is None) == (chunk_type in AGGREGATE_CHUNK_TYPES), f"{path}.object_id is invalid for chunk_type")


def _references(value: object, path: str) -> None:
    seen = set()
    for index, item in enumerate(_list(value, path)):
        where = f"{path}[{index}]"
        reference = _object(item, where, ("source_file", "raw_record_ref"))
        pair = tuple(_text(reference[key], f"{where}.{key}") for key in ("source_file", "raw_record_ref"))
        _require(pair not in seen, f"{path} contains duplicate references")
        seen.add(pair)


def _query(value: object, path: str) -> dict[str, Any]:
    query = _object(value, path, _QUERY_FIELDS)
    _text(query["text"], f"{path}.text")
    terms = _strings(query["normalized_terms"], f"{path}.normalized_terms")
    _require(bool(terms), f"{path}.normalized_terms must not be empty")
    top = _integer(query["top_k"], f"{path}.top_k", 1)
    _integer(query["candidate_k"], f"{path}.candidate_k", top)
    filters = _object(query["filters"], f"{path}.filters", ("chunk_types", "required_dimensions"))
    for key, items in filters.items():
        if items is not None:
            values = _strings(items, f"{path}.filters.{key}", sorted_unique=True)
            if key == "chunk_types":
                _require(set(values).issubset(CHUNK_SOURCE_OBJECT_TYPES), f"{path}.filters.chunk_types is unsupported")
    return query


def _components(value: object, path: str) -> dict[str, Any]:
    components = _object(value, path, ("lexical", "vector"))
    _require(any(item is not None for item in components.values()), f"{path} has no component")
    for name, raw in components.items():
        if raw is None:
            continue
        where = f"{path}.{name}"
        component = _object(raw, where, ("rank", "score", "contribution"))
        _integer(component["rank"], f"{where}.rank", 1)
        _number(component["score"], f"{where}.score", cosine=name == "vector")
        _number(component["contribution"], f"{where}.contribution", contribution=True)
    return components


def _chunk(value: object, root: Mapping[str, Any], path: str) -> dict[str, Any]:
    chunk = _object(value, path, CHUNK_FIELDS)
    for key in ("chunk_id", "chunk_type", "title", "content"):
        _text(chunk[key], f"{path}.{key}")
    _require(chunk["chunk_type"] in CHUNK_SOURCE_OBJECT_TYPES, f"{path}.chunk_type is unsupported")
    _require(chunk["scenario_id"] == root["scenario_id"], f"{path}.scenario_id mismatch")
    _require(chunk["status"] in CHUNK_STATUSES, f"{path}.status is unsupported")
    _source(chunk["source"], f"{path}.source", chunk["chunk_type"])
    for key in (*CHUNK_REFERENCE_LIST_FIELDS, "queryable_dimensions"):
        _strings(chunk[key], f"{path}.{key}")
    _references(chunk["source_references"], f"{path}.source_references")
    _object(chunk["metadata"], f"{path}.metadata")
    filters = root["query"]["filters"]
    _require(filters["chunk_types"] is None or chunk["chunk_type"] in filters["chunk_types"], f"{path} violates chunk_types filter")
    _require(set(filters["required_dimensions"] or []).issubset(chunk["queryable_dimensions"]), f"{path} violates required_dimensions filter")
    return chunk


def _retrieval(root: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result = _object(root["retrieval"], "context.retrieval", _RETRIEVAL_FIELDS)
    _require(result["schema_version"] == "retrieval-result/v1", "context.retrieval.schema_version is unsupported")
    _require(result["retrieval_method"] == "hybrid-rrf/v1", "context.retrieval.retrieval_method is unsupported")
    for key in ("corpus_id", "scenario_id"):
        _require(result[key] == root[key], f"context.retrieval.{key} mismatch")
    _require(_query(result["query"], "context.retrieval.query") == root["query"], "context.retrieval.query mismatch")
    _strings(result["warnings"], "context.retrieval.warnings", unique=False)
    hits = _list(result["hits"], "context.retrieval.hits")
    metadata = _object(result["metadata"], "context.retrieval.metadata", _RETRIEVAL_METADATA_FIELDS)
    for key in _RETRIEVAL_METADATA_FIELDS[:8]:
        _integer(metadata[key], f"context.retrieval.metadata.{key}")
    _require(metadata["returned_hits"] == len(hits), "retrieval returned_hits mismatch")
    total, eligible = metadata["total_chunks"], metadata["eligible_chunks"]
    lexical, vector, union = (metadata[f"{name}_candidate_count"] for name in ("lexical", "vector", "union"))
    _require(len(hits) <= eligible <= total, "retrieval chunk counts are inconsistent")
    _require(max(lexical, vector) <= min(root["query"]["candidate_k"], eligible), "retrieval candidate counts exceed limits")
    _require(max(lexical, vector) <= union <= min(lexical + vector, eligible), "retrieval candidate union is inconsistent")
    _require(len(hits) == min(root["query"]["top_k"], union), "retrieval hit count disagrees with top_k/union")
    _require(metadata["rrf_k"] == RRF_K and metadata["score_precision"] == SCORE_PRECISION, "retrieval RRF descriptors mismatch")
    _require(metadata["score_interpretation"] == "reciprocal_rank_fusion_not_probability", "retrieval score_interpretation mismatch")
    methods = _object(metadata["component_methods"], "retrieval.metadata.component_methods", ("lexical", "vector"))
    _require(methods == {"lexical": "bm25/v1", "vector": "vector-cosine/v1"}, "retrieval component_methods mismatch")
    lookup: dict[str, dict[str, Any]] = {}
    seen_ranks: dict[str, set[int]] = {"lexical": set(), "vector": set()}
    memberships = {"lexical": 0, "vector": 0, "both": 0}
    for rank, raw in enumerate(hits, 1):
        path = f"context.retrieval.hits[{rank - 1}]"
        hit = _object(raw, path, ("rank", "score", "components", "chunk"))
        _require(_integer(hit["rank"], f"{path}.rank", 1) == rank, f"{path}.rank must be consecutive")
        _number(hit["score"], f"{path}.score")
        components = _components(hit["components"], f"{path}.components")
        for name, component in components.items():
            if component is not None:
                component_rank = component["rank"]
                _require(component_rank <= metadata[f"{name}_candidate_count"] and component_rank not in seen_ranks[name], f"{path}.{name} rank is duplicated or exceeds candidate count")
                seen_ranks[name].add(component_rank)
        membership = "both" if all(item is not None for item in components.values()) else (
            "lexical" if components["lexical"] is not None else "vector"
        )
        memberships[membership] += 1
        chunk = _chunk(hit["chunk"], root, f"{path}.chunk")
        _require(chunk["chunk_id"] not in lookup, f"{path} contains a duplicate chunk ID")
        lookup[chunk["chunk_id"]] = hit
    _require(memberships["both"] <= lexical + vector - union and memberships["lexical"] <= union - vector and memberships["vector"] <= union - lexical, "retrieval candidate overlap disagrees with hit components")
    return lookup


def _seeds(root: Mapping[str, Any], hits: Mapping[str, Any]) -> int:
    result = _object(root["seed_mapping"], "context.seed_mapping", _SEED_FIELDS)
    _require(result["schema_version"] == "graphrag-seed-map/v1", "seed_mapping.schema_version is unsupported")
    for key in ("corpus_id", "graph_id", "scenario_id"):
        _require(result[key] == root[key], f"seed_mapping.{key} mismatch")
    _provenance(result["source_ground_truth"], root["scenario_id"], "seed_mapping.source_ground_truth")
    _require(result["source_ground_truth"] == root["source_ground_truth"], "seed_mapping provenance mismatch")
    _require(result["retrieval_method"] == root["retrieval"]["retrieval_method"], "seed_mapping.retrieval_method mismatch")
    _require(_query(result["query"], "seed_mapping.query") == root["query"], "seed_mapping.query mismatch")
    _strings(result["warnings"], "seed_mapping.warnings", unique=False)
    seed_ids = _strings(result["seed_node_ids"], "seed_mapping.seed_node_ids", sorted_unique=True)
    mappings = _list(result["hit_mappings"], "seed_mapping.hit_mappings")
    seen: set[str] = set()
    matched_nodes: set[str] = set()
    successful = direct = 0
    for index, raw in enumerate(mappings):
        path = f"seed_mapping.hit_mappings[{index}]"
        mapping = _object(raw, path, _MAPPING_FIELDS)
        chunk_id = _text(mapping["chunk_id"], f"{path}.chunk_id")
        _require(chunk_id in hits and chunk_id not in seen, f"{path} has unknown or duplicate hit")
        seen.add(chunk_id)
        hit = hits[chunk_id]
        _require(_integer(mapping["hit_rank"], f"{path}.hit_rank", 1) == hit["rank"], f"{path}.hit_rank mismatch")
        _number(mapping["hit_score"], f"{path}.hit_score")
        _require(_json_bytes(mapping["hit_score"]) == _json_bytes(hit["score"]), f"{path}.hit_score mismatch")
        _components(mapping["components"], f"{path}.components")
        _require(_json_bytes(mapping["components"]) == _json_bytes(hit["components"]), f"{path}.components mismatch")
        _require(mapping["chunk_type"] == hit["chunk"]["chunk_type"], f"{path}.chunk_type mismatch")
        _source(mapping["source"], f"{path}.source", mapping["chunk_type"])
        _require(mapping["source"] == hit["chunk"]["source"], f"{path}.source mismatch")
        nodes = _strings(mapping["matched_node_ids"], f"{path}.matched_node_ids", sorted_unique=True)
        edges = _strings(mapping["matched_edge_ids"], f"{path}.matched_edge_ids", sorted_unique=True)
        kind = mapping["mapping_kind"]
        _require(kind in ("direct_node", "relationship_edge"), f"{path}.mapping_kind is unsupported")
        if kind == "direct_node":
            _require(mapping["chunk_type"] != "relationship" and len(nodes) <= 1 and not edges, f"{path} has invalid direct mapping")
            direct += 1
        else:
            _require(mapping["chunk_type"] == "relationship" and ((not nodes and not edges) or (1 <= len(nodes) <= 2 and len(edges) == 1)), f"{path} has invalid relationship mapping")
        successful += bool(nodes)
        matched_nodes.update(nodes)
    _require(set(seed_ids).issubset(matched_nodes), "seed IDs have no successful hit mapping")
    _counts(result["metadata"], "seed_mapping.metadata", {
        "retrieval_hit_count": len(hits), "mapped_hit_count": len(mappings),
        "direct_node_mapping_count": direct, "relationship_edge_mapping_count": len(mappings) - direct,
        "seed_node_count": len(seed_ids),
    }, _SEED_METADATA_FIELDS)
    return successful


def _graph_item(raw: object, path: str, *, edge: bool) -> dict[str, Any]:
    item = _object(raw, path, EDGE_FIELDS if edge else NODE_FIELDS)
    prefix = "edge" if edge else "node"
    _text(item[f"{prefix}_id"], f"{path}.{prefix}_id")
    kind = _text(item[f"{prefix}_type"], f"{path}.{prefix}_type")
    _require(IDENTIFIER_PATTERN.fullmatch(kind) is not None, f"{path}.{prefix}_type is invalid")
    _require(item["status"] in GRAPH_STATUSES, f"{path}.status is unsupported")
    _source(item["source"], f"{path}.source")
    _object(item["attributes"], f"{path}.attributes")
    for key in ("evidence_ids", "dimensions"):
        _strings(item[key], f"{path}.{key}")
    _references(item["source_references"], f"{path}.source_references")
    if edge:
        _boolean(item["directed"], f"{path}.directed")
        _strings(item["supporting_node_ids"], f"{path}.supporting_node_ids")
        for key in ("source_node_id", "target_node_id"):
            _text(item[key], f"{path}.{key}")
    else:
        _text(item["label"], f"{path}.label")
    return item


def _traversal(root: Mapping[str, Any]) -> tuple[int, int, int]:
    if root["traversal"] is None:
        return 0, 0, 0
    result = _object(root["traversal"], "context.traversal", _TRAVERSAL_FIELDS)
    _require(result["schema_version"] == "graph-traversal-result/v1", "traversal.schema_version is unsupported")
    for key in ("graph_id", "scenario_id"):
        _require(result[key] == root[key], f"traversal.{key} mismatch")
    seeds = _strings(result["seed_node_ids"], "traversal.seed_node_ids", sorted_unique=True)
    _require(bool(seeds) and seeds == root["seed_mapping"]["seed_node_ids"], "traversal seeds mismatch or empty")
    request = _object(result["request"], "traversal.request", _REQUEST_FIELDS)
    _require(_strings(request["seed_node_ids"], "traversal.request.seed_node_ids", sorted_unique=True) == seeds, "traversal request seeds mismatch")
    _require(request["direction"] in ("outgoing", "incoming", "both"), "traversal direction is invalid")
    depth_limit = _integer(request["max_depth"], "traversal.request.max_depth", 0, 64)
    node_limit = _integer(request["max_nodes"], "traversal.request.max_nodes", 1)
    edge_limit = _integer(request["max_edges"], "traversal.request.max_edges", 1)
    allowed = request["allowed_edge_types"]
    if allowed is not None:
        for kind in _strings(allowed, "traversal.request.allowed_edge_types", sorted_unique=True):
            _require(IDENTIFIER_PATTERN.fullmatch(kind) is not None, "traversal allowed edge type is invalid")
    nodes: dict[str, Any] = {}
    edges: dict[str, Any] = {}
    for plural, edge, lookup in (("nodes", False, nodes), ("edges", True, edges)):
        identifier = "edge_id" if edge else "node_id"
        identifiers = []
        for index, raw in enumerate(_list(result[plural], f"traversal.{plural}")):
            item = _graph_item(raw, f"traversal.{plural}[{index}]", edge=edge)
            identifiers.append(item[identifier])
            lookup[item[identifier]] = item
        _require(identifiers == sorted(set(identifiers)), f"traversal.{plural} IDs must be sorted and unique")
    _require(set(seeds).issubset(nodes), "traversal is missing seed nodes")
    _require(len(nodes) <= node_limit and len(edges) <= edge_limit, "traversal exceeds request limits")
    _require(depth_limit != 0 or not edges, "traversal depth zero contains edges")
    for edge in edges.values():
        _require({edge["source_node_id"], edge["target_node_id"]}.issubset(nodes), "traversal edge has dangling endpoints")
        _require(allowed is None or edge["edge_type"] in allowed, "traversal edge violates type filter")
    paths = _list(result["paths"], "traversal.paths")
    pairs: set[tuple[str, str]] = set()
    reached: set[str] = set()
    max_depth = 0
    for index, raw in enumerate(paths):
        where = f"traversal.paths[{index}]"
        path = _object(raw, where, _PATH_FIELDS)
        depth = _integer(path["depth"], f"{where}.depth", 0, depth_limit)
        node_ids = _strings(path["node_ids"], f"{where}.node_ids")
        edge_ids = _strings(path["edge_ids"], f"{where}.edge_ids")
        _require(len(node_ids) == depth + 1 and len(edge_ids) == depth, f"{where} has inconsistent depth")
        _require(set(node_ids).issubset(nodes) and set(edge_ids).issubset(edges), f"{where} has dangling references")
        _require(path["seed_node_id"] in seeds and node_ids[0] == path["seed_node_id"] and node_ids[-1] == path["target_node_id"], f"{where} has invalid endpoints")
        pair = (path["seed_node_id"], path["target_node_id"])
        _require(pair not in pairs, f"{where} repeats a seed/target pair")
        pairs.add(pair)
        reached.update(node_ids)
        max_depth = max(max_depth, depth)
        for step, edge_id in enumerate(edge_ids):
            edge = edges[edge_id]
            original = (edge["source_node_id"], edge["target_node_id"])
            actual = (node_ids[step], node_ids[step + 1])
            permitted = []
            if request["direction"] in ("outgoing", "both"):
                permitted.append(original)
            if request["direction"] in ("incoming", "both"):
                permitted.append(original[::-1])
            _require(actual in permitted, f"{where} violates traversal direction")
    _require(reached == set(nodes) and all((seed, seed) in pairs for seed in seeds), "traversal paths omit nodes or seed paths")
    metadata = _counts(result["metadata"], "traversal.metadata", {
        "node_count": len(nodes), "edge_count": len(edges), "path_count": len(paths), "max_reached_depth": max_depth,
    }, _TRAVERSAL_METADATA_FIELDS)
    limits = _strings(metadata["applied_limits"], "traversal.metadata.applied_limits", sorted_unique=True)
    _require(set(limits).issubset({"max_nodes", "max_edges"}), "traversal applied_limits are invalid")
    _require(_boolean(metadata["truncated"], "traversal.metadata.truncated") == bool(limits), "traversal truncation metadata mismatch")
    _strings(result["warnings"], "traversal.warnings", unique=False)
    return len(nodes), len(edges), len(paths)


def _signals(root: dict[str, Any]) -> dict[str, Any]:
    _object(root, "context", _CONTEXT_FIELDS)
    _require(root["schema_version"] == "graphrag-context/v1", "context.schema_version is unsupported")
    for key in ("corpus_id", "graph_id", "scenario_id"):
        _text(root[key], f"context.{key}")
    _provenance(root["source_ground_truth"], root["scenario_id"], "context.source_ground_truth")
    _query(root["query"], "context.query")
    _strings(root["warnings"], "context.warnings", unique=False)
    hits = _retrieval(root)
    mapped = _seeds(root, hits)
    nodes, edges, paths = _traversal(root)
    _visible_mapping_provenance(root)
    mappings = root["seed_mapping"]["hit_mappings"]
    seeds = root["seed_mapping"]["seed_node_ids"]
    performed = root["traversal"] is not None
    metadata = _counts(root["metadata"], "context.metadata", {
        "retrieval_hit_count": len(hits), "mapped_hit_count": len(mappings), "seed_node_count": len(seeds),
        "traversed_node_count": nodes, "traversed_edge_count": edges, "traversed_path_count": paths,
    }, _CONTEXT_METADATA_FIELDS)
    _require(_boolean(metadata["traversal_performed"], "context.metadata.traversal_performed") == performed, "context traversal_performed mismatch")
    lexical_count = vector_count = joint_count = 0
    vector_scores = []
    for hit in hits.values():
        lexical, vector = hit["components"]["lexical"], hit["components"]["vector"]
        lexical_count += lexical is not None
        vector_count += vector is not None
        joint_count += lexical is not None and vector is not None
        if vector is not None:
            vector_scores.append(vector["score"])
    return {
        "retrieval_hit_count": len(hits), "lexical_hit_count": lexical_count,
        "vector_hit_count": vector_count, "joint_lexical_vector_hit_count": joint_count,
        "top_cosine_score": max(vector_scores) if vector_scores else None,
        "hit_mapping_count": len(mappings), "mapped_hit_count": mapped, "seed_node_count": len(seeds),
        "traversal_performed": performed, "traversal_node_count": nodes,
        "traversal_edge_count": edges, "traversal_path_count": paths,
    }


def _visible_mapping_provenance(root: Mapping[str, Any]) -> None:
    """Check returned source copies; absent neighborhoods cannot authenticate IDs."""
    traversal = root["traversal"]
    if traversal is None:
        return
    nodes = {node["node_id"]: node for node in traversal["nodes"]}
    edges = {edge["edge_id"]: edge for edge in traversal["edges"]}
    for mapping in root["seed_mapping"]["hit_mappings"]:
        source = {key: value for key, value in mapping["source"].items() if key != "artifact_type"}
        if mapping["mapping_kind"] == "direct_node":
            for node_id in mapping["matched_node_ids"]:
                if node_id in nodes:
                    node = nodes[node_id]
                    _require(node["source"] == source and node["node_type"] == CHUNK_SOURCE_OBJECT_TYPES[mapping["chunk_type"]], "returned mapped node provenance/type mismatch")
        else:
            for edge_id in mapping["matched_edge_ids"]:
                if edge_id in edges:
                    edge = edges[edge_id]
                    endpoints = sorted({edge["source_node_id"], edge["target_node_id"]})
                    _require(edge["source"] == source and endpoints == mapping["matched_node_ids"], "returned mapped edge provenance/endpoints mismatch")


def _policy(value: object) -> dict[str, Any]:
    policy = _object(value, "policy", _POLICY_FIELDS)
    _require(policy["schema_version"] == GRAPHRAG_RELEVANCE_POLICY_SCHEMA_VERSION, "policy.schema_version is unsupported")
    _text(policy["policy_id"], "policy.policy_id")
    for key in ("min_hits", "min_mapped_hits", "min_seed_nodes", "min_traversal_nodes"):
        _integer(policy[key], f"policy.{key}")
    for key in ("require_traversal", "require_lexical_support", "require_joint_lexical_vector_support"):
        _boolean(policy[key], f"policy.{key}")
    if policy["min_cosine_score"] is not None:
        _number(policy["min_cosine_score"], "policy.min_cosine_score", cosine=True)
    return policy


def _validated_context_and_signals(context: object) -> tuple[dict[str, Any], dict[str, Any]]:
    """Detach and validate the existing context contract before reading signals."""
    root = _object(_snapshot(context, "context", set()), "context")
    _json_bytes(root)
    return root, _signals(root)


def extract_graphrag_relevance_signals(
    context: Mapping[str, object],
) -> dict[str, Any]:
    """Return the twelve observed signals used by the existing relevance policy.

    This API validates and detaches finite native JSON without applying a policy
    or making a decision. Counts and the top returned vector score keep their
    existing meanings; chunk metadata and graph attributes remain opaque.
    """
    try:
        _, signals = _validated_context_and_signals(context)
        _json_bytes(signals)
        return signals
    except GraphRAGRelevanceError:
        raise
    except Exception as exc:
        raise GraphRAGRelevanceError(f"Invalid GraphRAG relevance input: {exc}") from exc


def assess_graphrag_relevance(
    context: Mapping[str, object], *, policy: Mapping[str, object],
) -> dict[str, object]:
    """Return proceed iff every explicit policy condition passes, else abstain.

    Mapped-hit counts use nonempty matched_node_ids; upstream mapped counters
    describe mapping records, which may carry no successful match. Partial
    mappings, missing seeds and null traversal are valid insufficient evidence.
    The cosine minimum applies to the maximum vector component score among
    returned hits. With that minimum enabled, no vector component also fails.
    A joint-support requirement needs both components on the same returned hit.

    Unknown structural fields, inconsistent identities/counters/references and
    non-native, nonfinite or malformed values raise GraphRAGRelevanceError.
    Caller data and all source scores, ranks, provenance and statuses remain
    untouched. Output containers are detached and deterministic finite JSON.
    """
    try:
        configured = _policy(_snapshot(policy, "policy", set()))
        _json_bytes(configured)
        root, signals = _validated_context_and_signals(context)
        reasons = []
        for setting, observed, reason in (
            ("min_hits", "retrieval_hit_count", "insufficient_hits"),
            ("min_mapped_hits", "mapped_hit_count", "insufficient_mapped_hits"),
            ("min_seed_nodes", "seed_node_count", "insufficient_seeds"),
            ("min_traversal_nodes", "traversal_node_count", "insufficient_traversal_nodes"),
        ):
            if signals[observed] < configured[setting]:
                reasons.append(reason)
        for setting, observed, reason in (
            ("require_traversal", "traversal_performed", "traversal_required"),
            ("require_lexical_support", "lexical_hit_count", "missing_lexical_support"),
            ("require_joint_lexical_vector_support", "joint_lexical_vector_hit_count", "missing_joint_lexical_vector_support"),
        ):
            if configured[setting] and not signals[observed]:
                reasons.append(reason)
        minimum = configured["min_cosine_score"]
        if minimum is not None and (signals["top_cosine_score"] is None or signals["top_cosine_score"] < minimum):
            reasons.append("vector_score_below_threshold")
        stages = [root, root["retrieval"], root["seed_mapping"]]
        if root["traversal"] is not None:
            stages.append(root["traversal"])
        result = {
            "schema_version": GRAPHRAG_RELEVANCE_DECISION_SCHEMA_VERSION,
            "scenario_id": root["scenario_id"], "query": root["query"],
            "policy_id": configured["policy_id"], "decision": "abstain" if reasons else "proceed",
            "reason_codes": sorted(reasons), "signals": signals,
            "warnings": sorted({warning for stage in stages for warning in stage["warnings"]}),
            "metadata": {
                "context_schema_version": root["schema_version"],
                "policy_schema_version": configured["schema_version"],
                "corpus_id": root["corpus_id"], "graph_id": root["graph_id"],
                "source_ground_truth": root["source_ground_truth"], "policy": configured,
                "score_interpretation": "bm25_cosine_rrf_not_probabilities",
                "decision_interpretation": "context_eligibility_only",
            },
        }
        _json_bytes(result)
        return result
    except GraphRAGRelevanceError:
        raise
    except Exception as exc:
        raise GraphRAGRelevanceError(f"Invalid GraphRAG relevance input: {exc}") from exc


__all__ = (
    "GRAPHRAG_RELEVANCE_POLICY_SCHEMA_VERSION", "GRAPHRAG_RELEVANCE_DECISION_SCHEMA_VERSION",
    "GraphRAGRelevanceError", "extract_graphrag_relevance_signals", "assess_graphrag_relevance",
)
