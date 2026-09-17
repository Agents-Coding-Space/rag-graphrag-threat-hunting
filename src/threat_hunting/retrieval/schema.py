"""Strict validation for scenario-independent Retrieval Corpus documents.

The contract describes retrieval-ready text and provenance only. It does not
generate chunks, create embeddings, query a store, traverse a graph, or invoke
language models.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
from pathlib import Path
import re
from typing import Any, NoReturn


RETRIEVAL_CORPUS_SCHEMA_VERSION = "retrieval-corpus/v1"
SOURCE_GROUND_TRUTH_SCHEMA_VERSION = "scenario-ground-truth/v1"

TOP_LEVEL_FIELDS = (
    "schema_version",
    "corpus_id",
    "scenario_id",
    "source_ground_truth",
    "chunks",
    "queryable_dimensions",
    "review",
    "warnings",
    "metadata",
)
SOURCE_GROUND_TRUTH_FIELDS = (
    "path",
    "schema_version",
    "sha256",
    "scenario_id",
)
CHUNK_FIELDS = (
    "chunk_id",
    "chunk_type",
    "scenario_id",
    "title",
    "content",
    "status",
    "source",
    "entity_ids",
    "fact_ids",
    "relationship_ids",
    "evidence_ids",
    "sigma_rule_ids",
    "mitre_external_ids",
    "source_references",
    "queryable_dimensions",
    "metadata",
)
CHUNK_SOURCE_FIELDS = (
    "artifact_type",
    "object_type",
    "object_id",
    "json_pointer",
)
SOURCE_REFERENCE_FIELDS = ("source_file", "raw_record_ref")
REVIEW_FIELDS = (
    "review_status",
    "reviewer",
    "reviewed_at",
    "notes",
)
CHUNK_REFERENCE_LIST_FIELDS = (
    "entity_ids",
    "fact_ids",
    "relationship_ids",
    "evidence_ids",
    "sigma_rule_ids",
    "mitre_external_ids",
)

CHUNK_SOURCE_OBJECT_TYPES = {
    "scenario_summary": "scenario",
    "entity": "entity",
    "fact": "fact",
    "relationship": "relationship",
    "evidence": "evidence",
    "sigma_finding": "sigma_finding",
    "mitre_assessment": "mitre_assessment",
    "limitation": "limitation",
}
AGGREGATE_CHUNK_TYPES = frozenset({"scenario_summary", "limitation"})
CHUNK_STATUSES = frozenset({"observed", "inferred", "candidate", "reviewable"})
DOCUMENT_REVIEW_STATUSES = frozenset({"pending_human_review"})

FORBIDDEN_FIELDS = frozenset(
    {
        "questions",
        "evaluation_questions",
        "expected_answers",
        "question_id",
        "question_text",
        "expected_answer",
        "answer_id",
        "embedding",
        "embeddings",
        "embedding_model",
        "vector",
        "vectors",
        "llm",
        "llm_response",
    }
)
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
QUESTION_CONTENT_PREFIX = re.compile(
    r"^(?:question|expected[\s_-]*answer)\s*:", re.IGNORECASE
)


class RetrievalCorpusValidationError(ValueError):
    """Raised when a Retrieval Corpus document violates its contract."""


def _require_object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RetrievalCorpusValidationError(f"{path} must be a JSON object")
    return value


def _require_list(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise RetrievalCorpusValidationError(f"{path} must be a list")
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
        raise RetrievalCorpusValidationError(
            f"{path} fields do not match the contract: {'; '.join(details)}"
        )


def _require_nonempty_string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RetrievalCorpusValidationError(f"{path} must be a non-empty string")
    return value


def _require_sha256(value: object, path: str) -> str:
    digest = _require_nonempty_string(value, path)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise RetrievalCorpusValidationError(
            f"{path} must contain exactly 64 hexadecimal characters"
        )
    return digest


def _require_status(value: object, allowed: frozenset[str], path: str) -> str:
    status = _require_nonempty_string(value, path)
    if status not in allowed:
        raise RetrievalCorpusValidationError(
            f"{path} has unsupported value {status!r}; allowed: {sorted(allowed)!r}"
        )
    return status


def _require_string_list(
    value: object,
    path: str,
    *,
    unique: bool = False,
    nonempty: bool = False,
) -> list[str]:
    items = _require_list(value, path)
    if nonempty and not items:
        raise RetrievalCorpusValidationError(f"{path} must not be empty")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        text = _require_nonempty_string(item, f"{path}[{index}]")
        if unique and text in seen:
            raise RetrievalCorpusValidationError(
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
            raise RetrievalCorpusValidationError(
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
                raise RetrievalCorpusValidationError(
                    f"{path} contains a non-string object key"
                )
            _validate_json_value(item, f"{path}.{key}")
        return
    raise RetrievalCorpusValidationError(
        f"{path} contains a value that cannot be represented in JSON"
    )


def _normalized_field_name(field_name: str) -> str:
    return field_name.casefold().replace("-", "_")


def _is_status_like_field(field_name: str) -> bool:
    normalized = _normalized_field_name(field_name)
    return "status" in normalized or "review" in normalized


def _contains_confirmed(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() == "confirmed"
    if isinstance(value, list):
        return any(_contains_confirmed(item) for item in value)
    return False


def _scan_contract_guards(value: object, path: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized_key = _normalized_field_name(key)
            if normalized_key in FORBIDDEN_FIELDS:
                raise RetrievalCorpusValidationError(
                    f"{path}.{key} is forbidden in Retrieval Corpus v1"
                )
            if _is_status_like_field(key) and _contains_confirmed(item):
                raise RetrievalCorpusValidationError(
                    f"{path}.{key} must not contain the value 'confirmed'"
                )
            _scan_contract_guards(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_contract_guards(item, f"{path}[{index}]")


def _require_content(value: object, path: str) -> str:
    content = _require_nonempty_string(value, path)
    stripped = content.strip()
    if stripped.endswith("?") or QUESTION_CONTENT_PREFIX.match(stripped):
        raise RetrievalCorpusValidationError(
            f"{path} must be retrieval content, not a question or expected answer"
        )
    return content


def _validate_source_ground_truth(value: object, scenario_id: str) -> None:
    path = "$.source_ground_truth"
    source = _require_object(value, path)
    _require_exact_fields(source, SOURCE_GROUND_TRUTH_FIELDS, path)
    _require_nonempty_string(source["path"], f"{path}.path")
    schema_version = _require_nonempty_string(
        source["schema_version"], f"{path}.schema_version"
    )
    if schema_version != SOURCE_GROUND_TRUTH_SCHEMA_VERSION:
        raise RetrievalCorpusValidationError(
            f"{path}.schema_version must be {SOURCE_GROUND_TRUTH_SCHEMA_VERSION!r}"
        )
    _require_sha256(source["sha256"], f"{path}.sha256")
    source_scenario_id = _require_nonempty_string(
        source["scenario_id"], f"{path}.scenario_id"
    )
    if source_scenario_id != scenario_id:
        raise RetrievalCorpusValidationError(
            f"{path}.scenario_id must match $.scenario_id"
        )


def _validate_chunk_source(
    value: object,
    *,
    chunk_type: str,
    path: str,
) -> None:
    source = _require_object(value, path)
    _require_exact_fields(source, CHUNK_SOURCE_FIELDS, path)
    artifact_type = _require_nonempty_string(
        source["artifact_type"], f"{path}.artifact_type"
    )
    if artifact_type != "scenario_ground_truth":
        raise RetrievalCorpusValidationError(
            f"{path}.artifact_type must be 'scenario_ground_truth'"
        )
    object_type = _require_nonempty_string(
        source["object_type"], f"{path}.object_type"
    )
    expected_object_type = CHUNK_SOURCE_OBJECT_TYPES[chunk_type]
    if object_type != expected_object_type:
        raise RetrievalCorpusValidationError(
            f"{path}.object_type must be {expected_object_type!r} "
            f"for chunk_type {chunk_type!r}"
        )
    object_id = source["object_id"]
    if chunk_type in AGGREGATE_CHUNK_TYPES:
        if object_id is not None:
            raise RetrievalCorpusValidationError(
                f"{path}.object_id must be null for aggregate chunk_type {chunk_type!r}"
            )
    else:
        _require_nonempty_string(object_id, f"{path}.object_id")
    json_pointer = _require_nonempty_string(
        source["json_pointer"], f"{path}.json_pointer"
    )
    if not json_pointer.startswith("/"):
        raise RetrievalCorpusValidationError(
            f"{path}.json_pointer must start with '/'"
        )


def _validate_source_references(value: object, path: str) -> None:
    references = _require_list(value, path)
    seen: set[tuple[str, str]] = set()
    for index, raw_reference in enumerate(references):
        reference_path = f"{path}[{index}]"
        reference = _require_object(raw_reference, reference_path)
        _require_exact_fields(reference, SOURCE_REFERENCE_FIELDS, reference_path)
        pair = (
            _require_nonempty_string(
                reference["source_file"], f"{reference_path}.source_file"
            ),
            _require_nonempty_string(
                reference["raw_record_ref"], f"{reference_path}.raw_record_ref"
            ),
        )
        if pair in seen:
            raise RetrievalCorpusValidationError(
                f"{path} must not contain duplicate source reference {pair!r}"
            )
        seen.add(pair)


def _validate_chunks(
    value: object,
    *,
    scenario_id: str,
    corpus_dimensions: set[str],
) -> None:
    chunks = _require_list(value, "$.chunks")
    if not chunks:
        raise RetrievalCorpusValidationError("$.chunks must not be empty")
    seen_chunk_ids: set[str] = set()
    for index, raw_chunk in enumerate(chunks):
        path = f"$.chunks[{index}]"
        chunk = _require_object(raw_chunk, path)
        _require_exact_fields(chunk, CHUNK_FIELDS, path)
        chunk_id = _require_nonempty_string(chunk["chunk_id"], f"{path}.chunk_id")
        if chunk_id in seen_chunk_ids:
            raise RetrievalCorpusValidationError(
                f"Duplicate chunk_id {chunk_id!r} at {path}"
            )
        seen_chunk_ids.add(chunk_id)

        chunk_type = _require_nonempty_string(
            chunk["chunk_type"], f"{path}.chunk_type"
        )
        if chunk_type not in CHUNK_SOURCE_OBJECT_TYPES:
            raise RetrievalCorpusValidationError(
                f"{path}.chunk_type has unsupported value {chunk_type!r}; "
                f"allowed: {sorted(CHUNK_SOURCE_OBJECT_TYPES)!r}"
            )
        chunk_scenario_id = _require_nonempty_string(
            chunk["scenario_id"], f"{path}.scenario_id"
        )
        if chunk_scenario_id != scenario_id:
            raise RetrievalCorpusValidationError(
                f"{path}.scenario_id must match $.scenario_id"
            )
        _require_nonempty_string(chunk["title"], f"{path}.title")
        _require_content(chunk["content"], f"{path}.content")
        _require_status(chunk["status"], CHUNK_STATUSES, f"{path}.status")
        _validate_chunk_source(
            chunk["source"], chunk_type=chunk_type, path=f"{path}.source"
        )
        for field in CHUNK_REFERENCE_LIST_FIELDS:
            _require_string_list(
                chunk[field], f"{path}.{field}", unique=True
            )
        _validate_source_references(
            chunk["source_references"], f"{path}.source_references"
        )
        chunk_dimensions = _require_string_list(
            chunk["queryable_dimensions"],
            f"{path}.queryable_dimensions",
            unique=True,
        )
        unknown_dimensions = sorted(set(chunk_dimensions) - corpus_dimensions)
        if unknown_dimensions:
            raise RetrievalCorpusValidationError(
                f"{path}.queryable_dimensions contains dimensions not declared "
                f"by the corpus: {unknown_dimensions!r}"
            )
        _require_object(chunk["metadata"], f"{path}.metadata")


def _validate_review(value: object) -> None:
    path = "$.review"
    review = _require_object(value, path)
    _require_exact_fields(review, REVIEW_FIELDS, path)
    _require_status(
        review["review_status"],
        DOCUMENT_REVIEW_STATUSES,
        f"{path}.review_status",
    )
    if review["reviewer"] is not None:
        raise RetrievalCorpusValidationError(f"{path}.reviewer must be null")
    if review["reviewed_at"] is not None:
        raise RetrievalCorpusValidationError(f"{path}.reviewed_at must be null")
    _require_string_list(review["notes"], f"{path}.notes")


def validate_retrieval_corpus(document: object) -> None:
    """Validate a Retrieval Corpus document without changing it."""

    root = _require_object(document, "$")
    _validate_json_value(root, "$")
    _scan_contract_guards(root, "$")
    _require_exact_fields(root, TOP_LEVEL_FIELDS, "$")

    schema_version = _require_nonempty_string(root["schema_version"], "$.schema_version")
    if schema_version != RETRIEVAL_CORPUS_SCHEMA_VERSION:
        raise RetrievalCorpusValidationError(
            f"$.schema_version must be {RETRIEVAL_CORPUS_SCHEMA_VERSION!r}"
        )
    _require_nonempty_string(root["corpus_id"], "$.corpus_id")
    scenario_id = _require_nonempty_string(root["scenario_id"], "$.scenario_id")
    _validate_source_ground_truth(root["source_ground_truth"], scenario_id)
    dimensions = _require_string_list(
        root["queryable_dimensions"],
        "$.queryable_dimensions",
        unique=True,
        nonempty=True,
    )
    _validate_chunks(
        root["chunks"],
        scenario_id=scenario_id,
        corpus_dimensions=set(dimensions),
    )
    _validate_review(root["review"])
    _require_string_list(root["warnings"], "$.warnings")
    _require_object(root["metadata"], "$.metadata")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_json_number(value: str) -> NoReturn:
    raise ValueError(f"non-standard JSON number {value!r}")


def load_retrieval_corpus(path: Path) -> dict[str, Any]:
    """Load and validate a UTF-8 Retrieval Corpus JSON document."""

    source_path = Path(path)
    try:
        with source_path.open("r", encoding="utf-8") as handle:
            document = json.load(
                handle,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_number,
            )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise RetrievalCorpusValidationError(
            f"Cannot read retrieval corpus {source_path}: {exc}"
        ) from exc

    try:
        validate_retrieval_corpus(document)
    except RetrievalCorpusValidationError as exc:
        raise RetrievalCorpusValidationError(
            f"Invalid retrieval corpus {source_path}: {exc}"
        ) from exc
    return document


__all__ = (
    "RETRIEVAL_CORPUS_SCHEMA_VERSION",
    "RetrievalCorpusValidationError",
    "load_retrieval_corpus",
    "validate_retrieval_corpus",
)
