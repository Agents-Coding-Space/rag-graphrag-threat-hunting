"""Strict validation for scenario-independent Vector Index documents.

The contract records corpus provenance, embedding configuration, and vectors.
It does not create embeddings, access a model, search vectors, or perform
cross-artifact referential-integrity checks.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
from pathlib import Path
import re
from typing import Any, NoReturn

from .schema import CHUNK_SOURCE_OBJECT_TYPES, RETRIEVAL_CORPUS_SCHEMA_VERSION


VECTOR_INDEX_SCHEMA_VERSION = "vector-index/v1"

TOP_LEVEL_FIELDS = (
    "schema_version",
    "index_id",
    "corpus_provenance",
    "embedding",
    "records",
    "review",
    "warnings",
    "metadata",
)
CORPUS_PROVENANCE_FIELDS = (
    "path",
    "schema_version",
    "sha256",
    "corpus_id",
    "scenario_id",
)
EMBEDDING_FIELDS = (
    "provider",
    "model_id",
    "model_revision",
    "dimension",
    "distance_metric",
    "normalization",
    "document_prefix",
    "query_prefix",
)
VECTOR_RECORD_FIELDS = (
    "chunk_id",
    "chunk_type",
    "content_sha256",
    "vector",
)
REVIEW_FIELDS = (
    "review_status",
    "reviewer",
    "reviewed_at",
    "notes",
)
METADATA_FIELDS = (
    "record_count",
    "vector_dimension",
    "complete_corpus_coverage",
)

SUPPORTED_CHUNK_TYPES = frozenset(CHUNK_SOURCE_OBJECT_TYPES)
SUPPORTED_DISTANCE_METRICS = frozenset({"cosine"})
SUPPORTED_NORMALIZATIONS = frozenset({"none", "l2"})
DOCUMENT_REVIEW_STATUSES = frozenset({"pending_human_review"})
L2_NORM_TOLERANCE = 1e-6
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class VectorIndexValidationError(ValueError):
    """Raised when a Vector Index document violates its contract."""


def _require_object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VectorIndexValidationError(f"{path} must be a JSON object")
    return value


def _require_list(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise VectorIndexValidationError(f"{path} must be a list")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected_fields: tuple[str, ...], path: str
) -> None:
    expected = set(expected_fields)
    actual = set(value)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    details: list[str] = []
    if missing:
        details.append(f"missing {missing!r}")
    if unexpected:
        details.append(f"unexpected {unexpected!r}")
    if details:
        raise VectorIndexValidationError(
            f"{path} fields do not match the contract: {'; '.join(details)}"
        )


def _require_nonempty_string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VectorIndexValidationError(f"{path} must be a non-empty string")
    return value


def _require_string(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise VectorIndexValidationError(f"{path} must be a string")
    return value


def _require_sha256(value: object, path: str) -> str:
    digest = _require_nonempty_string(value, path)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise VectorIndexValidationError(
            f"{path} must contain exactly 64 hexadecimal characters"
        )
    return digest


def _require_integer(
    value: object,
    path: str,
    *,
    minimum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise VectorIndexValidationError(f"{path} must be a {qualifier} integer")
    return value


def _require_string_list(
    value: object,
    path: str,
    *,
    unique: bool,
) -> list[str]:
    items = _require_list(value, path)
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        text = _require_nonempty_string(item, f"{path}[{index}]")
        if unique and text in seen:
            raise VectorIndexValidationError(
                f"{path} must not contain duplicate value {text!r}"
            )
        seen.add(text)
        result.append(text)
    return result


def _validate_json_value(value: object, path: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise VectorIndexValidationError(
                f"{path} must contain finite JSON numbers"
            )
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise VectorIndexValidationError(
                    f"{path} contains a non-string object key"
                )
            _validate_json_value(item, f"{path}.{key}")
        return
    raise VectorIndexValidationError(
        f"{path} contains a value that cannot be represented in JSON"
    )


def _is_status_like_field(field_name: str) -> bool:
    normalized = field_name.casefold().replace("-", "_")
    return "status" in normalized or "review" in normalized


def _contains_confirmed(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() == "confirmed"
    if isinstance(value, list):
        return any(_contains_confirmed(item) for item in value)
    if isinstance(value, Mapping):
        return any(_contains_confirmed(item) for item in value.values())
    return False


def _scan_status_guards(value: object, path: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _is_status_like_field(key) and _contains_confirmed(item):
                raise VectorIndexValidationError(
                    f"{path}.{key} must not contain the value 'confirmed'"
                )
            _scan_status_guards(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_status_guards(item, f"{path}[{index}]")


def _validate_corpus_provenance(value: object) -> None:
    path = "$.corpus_provenance"
    provenance = _require_object(value, path)
    _require_exact_fields(provenance, CORPUS_PROVENANCE_FIELDS, path)
    _require_nonempty_string(provenance["path"], f"{path}.path")
    schema_version = _require_nonempty_string(
        provenance["schema_version"], f"{path}.schema_version"
    )
    if schema_version != RETRIEVAL_CORPUS_SCHEMA_VERSION:
        raise VectorIndexValidationError(
            f"{path}.schema_version must be {RETRIEVAL_CORPUS_SCHEMA_VERSION!r}"
        )
    _require_sha256(provenance["sha256"], f"{path}.sha256")
    _require_nonempty_string(provenance["corpus_id"], f"{path}.corpus_id")
    _require_nonempty_string(provenance["scenario_id"], f"{path}.scenario_id")


def _validate_embedding(value: object) -> tuple[int, str]:
    path = "$.embedding"
    embedding = _require_object(value, path)
    _require_exact_fields(embedding, EMBEDDING_FIELDS, path)
    for field in ("provider", "model_id", "model_revision"):
        _require_nonempty_string(embedding[field], f"{path}.{field}")
    dimension = _require_integer(embedding["dimension"], f"{path}.dimension", minimum=1)
    distance_metric = _require_nonempty_string(
        embedding["distance_metric"], f"{path}.distance_metric"
    )
    if distance_metric not in SUPPORTED_DISTANCE_METRICS:
        raise VectorIndexValidationError(
            f"{path}.distance_metric has unsupported value {distance_metric!r}; "
            f"allowed: {sorted(SUPPORTED_DISTANCE_METRICS)!r}"
        )
    normalization = _require_nonempty_string(
        embedding["normalization"], f"{path}.normalization"
    )
    if normalization not in SUPPORTED_NORMALIZATIONS:
        raise VectorIndexValidationError(
            f"{path}.normalization has unsupported value {normalization!r}; "
            f"allowed: {sorted(SUPPORTED_NORMALIZATIONS)!r}"
        )
    _require_string(embedding["document_prefix"], f"{path}.document_prefix")
    _require_string(embedding["query_prefix"], f"{path}.query_prefix")
    return dimension, normalization


def _finite_vector_number(value: object, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise VectorIndexValidationError(f"{path} must be a finite JSON number")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise VectorIndexValidationError(
            f"{path} must be a finite JSON number"
        ) from exc
    if not math.isfinite(number):
        raise VectorIndexValidationError(f"{path} must be a finite JSON number")
    return number


def _validate_vector(
    value: object,
    *,
    dimension: int,
    normalization: str,
    path: str,
) -> None:
    vector = _require_list(value, path)
    if not vector:
        raise VectorIndexValidationError(f"{path} must not be empty")
    if len(vector) != dimension:
        raise VectorIndexValidationError(
            f"{path} must contain exactly {dimension} values"
        )
    numbers = [
        _finite_vector_number(item, f"{path}[{index}]")
        for index, item in enumerate(vector)
    ]
    if normalization == "l2":
        norm = math.hypot(*numbers)
        if norm == 0.0:
            raise VectorIndexValidationError(
                f"{path} must not be a zero vector when normalization is 'l2'"
            )
        if not math.isclose(
            norm,
            1.0,
            rel_tol=L2_NORM_TOLERANCE,
            abs_tol=L2_NORM_TOLERANCE,
        ):
            raise VectorIndexValidationError(
                f"{path} must have L2 norm 1 within tolerance "
                f"{L2_NORM_TOLERANCE}"
            )


def _validate_records(
    value: object,
    *,
    dimension: int,
    normalization: str,
) -> int:
    records = _require_list(value, "$.records")
    seen_chunk_ids: set[str] = set()
    for index, raw_record in enumerate(records):
        path = f"$.records[{index}]"
        record = _require_object(raw_record, path)
        _require_exact_fields(record, VECTOR_RECORD_FIELDS, path)
        chunk_id = _require_nonempty_string(record["chunk_id"], f"{path}.chunk_id")
        if chunk_id in seen_chunk_ids:
            raise VectorIndexValidationError(
                f"Duplicate chunk_id {chunk_id!r} at {path}"
            )
        seen_chunk_ids.add(chunk_id)
        chunk_type = _require_nonempty_string(
            record["chunk_type"], f"{path}.chunk_type"
        )
        if chunk_type not in SUPPORTED_CHUNK_TYPES:
            raise VectorIndexValidationError(
                f"{path}.chunk_type has unsupported value {chunk_type!r}; "
                f"allowed: {sorted(SUPPORTED_CHUNK_TYPES)!r}"
            )
        _require_sha256(record["content_sha256"], f"{path}.content_sha256")
        _validate_vector(
            record["vector"],
            dimension=dimension,
            normalization=normalization,
            path=f"{path}.vector",
        )
    return len(records)


def _validate_review(value: object) -> None:
    path = "$.review"
    review = _require_object(value, path)
    _require_exact_fields(review, REVIEW_FIELDS, path)
    review_status = _require_nonempty_string(
        review["review_status"], f"{path}.review_status"
    )
    if review_status not in DOCUMENT_REVIEW_STATUSES:
        raise VectorIndexValidationError(
            f"{path}.review_status has unsupported value {review_status!r}; "
            f"allowed: {sorted(DOCUMENT_REVIEW_STATUSES)!r}"
        )
    if review["reviewer"] is not None:
        raise VectorIndexValidationError(f"{path}.reviewer must be null")
    if review["reviewed_at"] is not None:
        raise VectorIndexValidationError(f"{path}.reviewed_at must be null")
    _require_string_list(review["notes"], f"{path}.notes", unique=True)


def _validate_metadata(
    value: object,
    *,
    record_count: int,
    dimension: int,
) -> None:
    path = "$.metadata"
    metadata = _require_object(value, path)
    _require_exact_fields(metadata, METADATA_FIELDS, path)
    declared_count = _require_integer(
        metadata["record_count"], f"{path}.record_count", minimum=0
    )
    if declared_count != record_count:
        raise VectorIndexValidationError(
            f"{path}.record_count must equal len($.records) ({record_count})"
        )
    declared_dimension = _require_integer(
        metadata["vector_dimension"], f"{path}.vector_dimension", minimum=1
    )
    if declared_dimension != dimension:
        raise VectorIndexValidationError(
            f"{path}.vector_dimension must equal $.embedding.dimension ({dimension})"
        )
    if not isinstance(metadata["complete_corpus_coverage"], bool):
        raise VectorIndexValidationError(
            f"{path}.complete_corpus_coverage must be a boolean"
        )


def validate_vector_index(document: object) -> None:
    """Validate a Vector Index document without changing it."""

    root = _require_object(document, "$")
    _validate_json_value(root, "$")
    _scan_status_guards(root, "$")
    _require_exact_fields(root, TOP_LEVEL_FIELDS, "$")

    schema_version = _require_nonempty_string(root["schema_version"], "$.schema_version")
    if schema_version != VECTOR_INDEX_SCHEMA_VERSION:
        raise VectorIndexValidationError(
            f"$.schema_version must be {VECTOR_INDEX_SCHEMA_VERSION!r}"
        )
    _require_nonempty_string(root["index_id"], "$.index_id")
    _validate_corpus_provenance(root["corpus_provenance"])
    dimension, normalization = _validate_embedding(root["embedding"])
    record_count = _validate_records(
        root["records"],
        dimension=dimension,
        normalization=normalization,
    )
    _validate_review(root["review"])
    _require_string_list(root["warnings"], "$.warnings", unique=True)
    _validate_metadata(
        root["metadata"],
        record_count=record_count,
        dimension=dimension,
    )


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_json_number(value: str) -> NoReturn:
    raise ValueError(f"non-standard JSON number {value!r}")


def load_vector_index(path: Path) -> dict[str, Any]:
    """Load and validate a UTF-8 Vector Index JSON document."""

    source_path = Path(path)
    try:
        with source_path.open("r", encoding="utf-8") as handle:
            document = json.load(
                handle,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_number,
            )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise VectorIndexValidationError(
            f"Cannot read vector index {source_path}: {exc}"
        ) from exc

    try:
        validate_vector_index(document)
    except VectorIndexValidationError as exc:
        raise VectorIndexValidationError(
            f"Invalid vector index {source_path}: {exc}"
        ) from exc
    return document


__all__ = (
    "VECTOR_INDEX_SCHEMA_VERSION",
    "VectorIndexValidationError",
    "load_vector_index",
    "validate_vector_index",
)
