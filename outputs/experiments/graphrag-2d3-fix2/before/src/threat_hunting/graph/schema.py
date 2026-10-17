"""Strict, scenario-independent Knowledge Graph Core validation.

This contract retains Ground Truth provenance and reviewable claims. It does
not construct relationships, resolve source documents, traverse a graph, or
promote claims to a final determination.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
import json
import math
from pathlib import Path
import re
from typing import Any, NoReturn

from ..ground_truth.schema import SUPPORTED_GROUND_TRUTH_SCHEMA_VERSIONS


KNOWLEDGE_GRAPH_SCHEMA_VERSION = "knowledge-graph/v1"

TOP_LEVEL_FIELDS = (
    "schema_version", "graph_id", "scenario_id", "source_ground_truth",
    "nodes", "edges", "queryable_dimensions", "review", "warnings", "metadata",
)
SOURCE_GROUND_TRUTH_FIELDS = ("path", "schema_version", "sha256", "scenario_id")
NODE_FIELDS = (
    "node_id", "node_type", "label", "status", "source", "attributes",
    "evidence_ids", "source_references", "dimensions",
)
EDGE_FIELDS = (
    "edge_id", "edge_type", "source_node_id", "target_node_id", "directed",
    "status", "source", "supporting_node_ids", "evidence_ids",
    "source_references", "attributes", "dimensions",
)
SOURCE_FIELDS = ("object_type", "object_id", "json_pointer")
SOURCE_REFERENCE_FIELDS = ("source_file", "raw_record_ref")
REVIEW_FIELDS = ("status", "reviewer", "reviewed_at")
METADATA_REQUIRED_FIELDS = (
    "node_count", "edge_count", "node_type_counts", "edge_type_counts",
)
GRAPH_STATUSES = frozenset({"observed", "inferred", "candidate", "reviewable"})
FORBIDDEN_QUESTION_FIELDS = frozenset({
    "question", "questions", "expected_answer", "expected_answers",
    "reference_answer", "reference_answers", "gold_answer", "gold_answers",
    "evaluation_questions", "question_id", "question_text", "answer_id",
})
SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")
IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_]*\Z")
INVALID_POINTER_ESCAPE = re.compile(r"~(?![01])")
QUESTION_LABEL_PREFIX = re.compile(
    r"^(?:questions?|(?:expected|reference|gold)[\s_-]*answers?)\s*:",
    re.IGNORECASE,
)


class KnowledgeGraphValidationError(ValueError):
    """Raised when a Knowledge Graph Core document violates its contract."""


def _require_object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KnowledgeGraphValidationError(f"{path} must be a JSON object")
    return value


def _require_list(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise KnowledgeGraphValidationError(f"{path} must be a list")
    return value


def _require_fields(
    value: Mapping[str, Any], fields: tuple[str, ...], path: str,
    *, exact: bool = True,
) -> None:
    expected, actual = set(fields), set(value)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected) if exact else []
    details = []
    if missing:
        details.append(f"missing {missing!r}")
    if unexpected:
        details.append(f"unexpected {unexpected!r}")
    if details:
        raise KnowledgeGraphValidationError(
            f"{path} fields do not match the contract: {'; '.join(details)}"
        )


def _require_string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise KnowledgeGraphValidationError(f"{path} must be a non-empty string")
    return value


def _require_identifier(value: object, path: str) -> str:
    identifier = _require_string(value, path)
    if IDENTIFIER_PATTERN.fullmatch(identifier) is None:
        raise KnowledgeGraphValidationError(
            f"{path} must be a normalized identifier matching [a-z][a-z0-9_]*"
        )
    return identifier


def _require_strings(value: object, path: str, *, unique: bool = True) -> list[str]:
    items = _require_list(value, path)
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        text = _require_string(item, f"{path}[{index}]")
        if unique and text in seen:
            raise KnowledgeGraphValidationError(
                f"{path} must not contain duplicate value {text!r}"
            )
        seen.add(text)
        result.append(text)
    return result


def _validate_utf8_string(value: str, path: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise KnowledgeGraphValidationError(
            f"{path} must contain valid UTF-8 text"
        ) from exc


def _validate_json_and_guards(document: object) -> None:
    """Check JSON values and recursive guards, including cyclic Python inputs."""
    stack: list[tuple[object, str, bool]] = [(document, "$", False)]
    active: set[int] = set()
    while stack:
        value, path, exiting = stack.pop()
        if exiting:
            active.remove(id(value))
            continue
        if isinstance(value, str):
            _validate_utf8_string(value, path)
            if value.strip().casefold() == "confirmed":
                raise KnowledgeGraphValidationError(
                    f"{path} must not contain the value 'confirmed'"
                )
            continue
        if value is None or isinstance(value, (bool, int)):
            continue
        if isinstance(value, float):
            if not math.isfinite(value):
                raise KnowledgeGraphValidationError(
                    f"{path} must contain finite JSON numbers"
                )
            continue
        if not isinstance(value, (Mapping, list)):
            raise KnowledgeGraphValidationError(
                f"{path} contains a value that cannot be represented in JSON"
            )
        if id(value) in active:
            raise KnowledgeGraphValidationError(
                f"{path} contains a circular reference, not a JSON value"
            )
        active.add(id(value))
        stack.append((value, path, True))
        if isinstance(value, Mapping):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise KnowledgeGraphValidationError(
                        f"{path} contains a non-string object key"
                    )
                _validate_utf8_string(key, path)
                normalized = key.strip().casefold().replace("-", "_").replace(" ", "_")
                if normalized in FORBIDDEN_QUESTION_FIELDS:
                    raise KnowledgeGraphValidationError(
                        f"{path}.{key} is forbidden in Knowledge Graph Core"
                    )
                stack.append((item, f"{path}.{key}", False))
        else:
            for index, item in enumerate(value):
                stack.append((item, f"{path}[{index}]", False))


def _validate_source_ground_truth(value: object, scenario_id: str) -> None:
    path = "$.source_ground_truth"
    source = _require_object(value, path)
    _require_fields(source, SOURCE_GROUND_TRUTH_FIELDS, path)
    _require_string(source["path"], f"{path}.path")
    schema_version = _require_string(source["schema_version"], f"{path}.schema_version")
    if schema_version not in SUPPORTED_GROUND_TRUTH_SCHEMA_VERSIONS:
        raise KnowledgeGraphValidationError(
            f"{path}.schema_version must be one of "
            f"{sorted(SUPPORTED_GROUND_TRUTH_SCHEMA_VERSIONS)!r}"
        )
    digest = _require_string(source["sha256"], f"{path}.sha256")
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise KnowledgeGraphValidationError(
            f"{path}.sha256 must contain exactly 64 hexadecimal characters"
        )
    source_scenario = _require_string(source["scenario_id"], f"{path}.scenario_id")
    if source_scenario != scenario_id:
        raise KnowledgeGraphValidationError(
            f"{path}.scenario_id must match $.scenario_id"
        )


def _validate_source(value: object, path: str) -> None:
    source = _require_object(value, path)
    _require_fields(source, SOURCE_FIELDS, path)
    _require_string(source["object_type"], f"{path}.object_type")
    if source["object_id"] is not None:
        _require_string(source["object_id"], f"{path}.object_id")
    pointer = _require_string(source["json_pointer"], f"{path}.json_pointer")
    if not pointer.startswith("/") or INVALID_POINTER_ESCAPE.search(pointer):
        raise KnowledgeGraphValidationError(
            f"{path}.json_pointer must start with '/' and use valid '~0'/'~1' escapes"
        )


def _validate_source_references(value: object, path: str) -> None:
    seen: set[tuple[str, str]] = set()
    for index, raw_reference in enumerate(_require_list(value, path)):
        reference_path = f"{path}[{index}]"
        reference = _require_object(raw_reference, reference_path)
        _require_fields(reference, SOURCE_REFERENCE_FIELDS, reference_path)
        pair = tuple(
            _require_string(reference[field], f"{reference_path}.{field}")
            for field in SOURCE_REFERENCE_FIELDS
        )
        if pair in seen:
            raise KnowledgeGraphValidationError(
                f"{path} must not contain duplicate source reference {pair!r}"
            )
        seen.add(pair)


def _validate_item_provenance(
    item: Mapping[str, Any], path: str, graph_dimensions: set[str],
) -> None:
    status = _require_string(item["status"], f"{path}.status")
    if status not in GRAPH_STATUSES:
        raise KnowledgeGraphValidationError(
            f"{path}.status has unsupported value {status!r}; "
            f"allowed: {sorted(GRAPH_STATUSES)!r}"
        )
    _validate_source(item["source"], f"{path}.source")
    _require_object(item["attributes"], f"{path}.attributes")
    _require_strings(item["evidence_ids"], f"{path}.evidence_ids")
    _validate_source_references(item["source_references"], f"{path}.source_references")
    dimensions = _require_strings(item["dimensions"], f"{path}.dimensions")
    unknown = sorted(set(dimensions) - graph_dimensions)
    if unknown:
        raise KnowledgeGraphValidationError(
            f"{path}.dimensions contains dimensions not declared by the graph: {unknown!r}"
        )


def _validate_nodes(value: object, dimensions: set[str]) -> tuple[set[str], Counter[str]]:
    node_ids: set[str] = set()
    counts: Counter[str] = Counter()
    for index, raw_node in enumerate(_require_list(value, "$.nodes")):
        path = f"$.nodes[{index}]"
        node = _require_object(raw_node, path)
        _require_fields(node, NODE_FIELDS, path)
        node_id = _require_string(node["node_id"], f"{path}.node_id")
        if node_id in node_ids:
            raise KnowledgeGraphValidationError(f"Duplicate node_id {node_id!r} at {path}")
        node_ids.add(node_id)
        node_type = _require_identifier(node["node_type"], f"{path}.node_type")
        label = _require_string(node["label"], f"{path}.label")
        if label.strip().endswith("?") or QUESTION_LABEL_PREFIX.match(label.strip()):
            raise KnowledgeGraphValidationError(
                f"{path}.label must be narrative content, not a question or answer"
            )
        _validate_item_provenance(node, path, dimensions)
        counts[node_type] += 1
    return node_ids, counts


def _validate_edges(
    value: object, node_ids: set[str], dimensions: set[str],
) -> Counter[str]:
    edge_ids: set[str] = set()
    counts: Counter[str] = Counter()
    for index, raw_edge in enumerate(_require_list(value, "$.edges")):
        path = f"$.edges[{index}]"
        edge = _require_object(raw_edge, path)
        _require_fields(edge, EDGE_FIELDS, path)
        edge_id = _require_string(edge["edge_id"], f"{path}.edge_id")
        if edge_id in edge_ids:
            raise KnowledgeGraphValidationError(f"Duplicate edge_id {edge_id!r} at {path}")
        edge_ids.add(edge_id)
        edge_type = _require_identifier(edge["edge_type"], f"{path}.edge_type")
        for field in ("source_node_id", "target_node_id"):
            node_id = _require_string(edge[field], f"{path}.{field}")
            if node_id not in node_ids:
                raise KnowledgeGraphValidationError(
                    f"{path}.{field} references unknown node_id {node_id!r}"
                )
        if type(edge["directed"]) is not bool:
            raise KnowledgeGraphValidationError(f"{path}.directed must be a boolean")
        for supporting_id in _require_strings(
            edge["supporting_node_ids"], f"{path}.supporting_node_ids"
        ):
            if supporting_id not in node_ids:
                raise KnowledgeGraphValidationError(
                    f"{path}.supporting_node_ids references unknown node_id {supporting_id!r}"
                )
        _validate_item_provenance(edge, path, dimensions)
        counts[edge_type] += 1
    return counts


def _require_count(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise KnowledgeGraphValidationError(f"{path} must be a non-negative integer")
    return value


def _validate_metadata(
    value: object, node_counts: Counter[str], edge_counts: Counter[str],
) -> None:
    path = "$.metadata"
    metadata = _require_object(value, path)
    _require_fields(metadata, METADATA_REQUIRED_FIELDS, path, exact=False)
    for prefix, expected_counts in (("node", node_counts), ("edge", edge_counts)):
        count_field = f"{prefix}_count"
        count = _require_count(metadata[count_field], f"{path}.{count_field}")
        if count != sum(expected_counts.values()):
            raise KnowledgeGraphValidationError(
                f"{path}.{count_field} must match the number of {prefix}s"
            )
        types_field = f"{prefix}_type_counts"
        type_counts = _require_object(metadata[types_field], f"{path}.{types_field}")
        for type_name, type_count in type_counts.items():
            _require_count(type_count, f"{path}.{types_field}.{type_name}")
        if dict(type_counts) != dict(expected_counts):
            raise KnowledgeGraphValidationError(
                f"{path}.{types_field} must match the actual {prefix} type counts exactly"
            )


def validate_knowledge_graph(document: object) -> None:
    """Validate the complete contract without changing the supplied document.

    Evidence IDs and source pointers identify Ground Truth objects. This
    structural validator does not open that artifact or authenticate its hash.
    """
    root = _require_object(document, "$")
    _validate_json_and_guards(root)
    _require_fields(root, TOP_LEVEL_FIELDS, "$")
    if root["schema_version"] != KNOWLEDGE_GRAPH_SCHEMA_VERSION:
        raise KnowledgeGraphValidationError(
            f"$.schema_version must be {KNOWLEDGE_GRAPH_SCHEMA_VERSION!r}"
        )
    _require_string(root["graph_id"], "$.graph_id")
    scenario_id = _require_string(root["scenario_id"], "$.scenario_id")
    _validate_source_ground_truth(root["source_ground_truth"], scenario_id)
    dimensions = set(_require_strings(root["queryable_dimensions"], "$.queryable_dimensions"))
    node_ids, node_counts = _validate_nodes(root["nodes"], dimensions)
    edge_counts = _validate_edges(root["edges"], node_ids, dimensions)
    review = _require_object(root["review"], "$.review")
    _require_fields(review, REVIEW_FIELDS, "$.review")
    if review["status"] != "pending_human_review":
        raise KnowledgeGraphValidationError("$.review.status must be 'pending_human_review'")
    for field in ("reviewer", "reviewed_at"):
        if review[field] is not None:
            raise KnowledgeGraphValidationError(f"$.review.{field} must be null")
    _require_strings(root["warnings"], "$.warnings", unique=False)
    _validate_metadata(root["metadata"], node_counts, edge_counts)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_json_number(value: str) -> NoReturn:
    raise ValueError(f"non-standard JSON number {value!r}")


def load_knowledge_graph(path: Path) -> dict[str, Any]:
    """Read UTF-8 JSON and validate it, including the source path in errors."""
    source_path = Path(path)
    try:
        with source_path.open("r", encoding="utf-8") as handle:
            document = json.load(
                handle, object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_number,
            )
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise KnowledgeGraphValidationError(
            f"Cannot read knowledge graph {source_path}: {exc}"
        ) from exc
    try:
        validate_knowledge_graph(document)
    except KnowledgeGraphValidationError as exc:
        raise KnowledgeGraphValidationError(
            f"Invalid knowledge graph {source_path}: {exc}"
        ) from exc
    return document


__all__ = (
    "KNOWLEDGE_GRAPH_SCHEMA_VERSION", "KnowledgeGraphValidationError",
    "load_knowledge_graph", "validate_knowledge_graph",
)
