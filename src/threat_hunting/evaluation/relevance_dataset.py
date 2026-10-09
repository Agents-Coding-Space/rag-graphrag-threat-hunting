"""Strict, scenario-independent datasets for offline relevance-gate evaluation.

The v1 contract has six exact document fields and seven exact case fields.
Languages are ``en`` and ``vi``. Metadata declares a nonnegative integer
``case_count`` and exact category, language, and decision count dictionaries,
including zero counts. Dataset size and balance are benchmark-specific checks,
not restrictions of this generic contract.

``expected_decision`` labels context eligibility only. It is neither an attack
determination nor an answer for a language model. This module only validates or
loads evaluation JSON; production pipelines do not depend on it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
import json
import math
from pathlib import Path
import unicodedata
from typing import Any


RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION = (
    "graphrag-relevance-calibration-dataset/v1"
)
_PURPOSE = "relevance_gate_calibration"
_DOCUMENT_FIELDS = (
    "schema_version", "dataset_id", "scenario_id", "purpose", "cases", "metadata",
)
_CASE_FIELDS = (
    "case_id", "category", "language", "query", "expected_decision", "rationale", "tags",
)
_METADATA_FIELDS = (
    "case_count", "category_counts", "language_counts", "decision_counts",
)
_CATEGORY_DECISIONS = {
    "relevant_direct": "proceed",
    "relevant_paraphrase": "proceed",
    "insufficient_evidence": "abstain",
    "unrelated": "abstain",
}
_LANGUAGES = ("en", "vi")
_DECISIONS = ("proceed", "abstain")
_FORBIDDEN_FIELDS = frozenset({
    "expected_answer", "reference_answer", "gold_answer", "generated_answer",
    "policy", "production_policy", "relevance_policy",
})


class RelevanceCalibrationDatasetValidationError(ValueError):
    """Raised when evaluation data violates the calibration dataset contract."""


def _field_path(path: str, key: str) -> str:
    if key.isidentifier():
        return f"{path}.{key}"
    return f"{path}[{json.dumps(key, ensure_ascii=True)}]"


def _normalized_field(key: str) -> str:
    return unicodedata.normalize("NFKC", key).casefold().replace("-", "_")


def _scan_json(
    value: object,
    path: str,
    ancestors: set[int],
    *,
    status_like: bool = False,
) -> None:
    """Check JSON representability and guards before checking exact fields."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise RelevanceCalibrationDatasetValidationError(
                f"{path} must be valid UTF-8 text"
            ) from exc
        if status_like and value.strip().casefold() == "confirmed":
            raise RelevanceCalibrationDatasetValidationError(
                f"{path} must not contain 'confirmed' in a status-like field"
            )
        return
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RelevanceCalibrationDatasetValidationError(
                f"{path} must contain finite JSON numbers"
            )
        return
    if not isinstance(value, (Mapping, list)):
        raise RelevanceCalibrationDatasetValidationError(
            f"{path} must contain only JSON values"
        )
    identity = id(value)
    if identity in ancestors:
        raise RelevanceCalibrationDatasetValidationError(
            f"{path} must not contain a cyclic JSON value"
        )
    ancestors.add(identity)
    try:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise RelevanceCalibrationDatasetValidationError(
                        f"{path} must have string object keys"
                    )
                key_path = _field_path(path, key)
                _scan_json(key, key_path, ancestors)
                normalized = _normalized_field(key)
                if normalized in _FORBIDDEN_FIELDS or "threshold" in normalized:
                    raise RelevanceCalibrationDatasetValidationError(
                        f"{key_path} is forbidden in evaluation dataset v1"
                    )
                _scan_json(
                    item, key_path, ancestors,
                    status_like=(status_like or "status" in normalized
                                 or "review" in normalized),
                )
        else:
            for index, item in enumerate(value):
                _scan_json(
                    item, f"{path}[{index}]", ancestors, status_like=status_like,
                )
    finally:
        ancestors.remove(identity)


def _object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelevanceCalibrationDatasetValidationError(
            f"{path} must be a JSON object"
        )
    return value


def _exact_fields(
    value: Mapping[str, Any], fields: tuple[str, ...], path: str,
) -> None:
    missing = sorted(set(fields) - set(value))
    unknown = sorted(set(value) - set(fields))
    if missing or unknown:
        raise RelevanceCalibrationDatasetValidationError(
            f"{path} fields must match the contract: missing {missing!r}; "
            f"unexpected {unknown!r}"
        )


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RelevanceCalibrationDatasetValidationError(
            f"{path} must be a non-empty string"
        )
    return value


def _choice(value: object, choices: tuple[str, ...], path: str) -> str:
    text = _text(value, path)
    if text not in choices:
        raise RelevanceCalibrationDatasetValidationError(
            f"{path} has unsupported value {text!r}; allowed: {choices!r}"
        )
    return text


def _count(value: object, expected: int, path: str) -> None:
    if type(value) is not int or value < 0:
        raise RelevanceCalibrationDatasetValidationError(
            f"{path} must be a nonnegative integer, not a boolean"
        )
    if value != expected:
        raise RelevanceCalibrationDatasetValidationError(
            f"{path} must match the actual count {expected}"
        )


def _validate_cases(value: object) -> tuple[Counter[str], Counter[str], Counter[str]]:
    if not isinstance(value, list) or not value:
        raise RelevanceCalibrationDatasetValidationError(
            "$.cases must be a non-empty list"
        )
    ids: set[str] = set()
    queries: set[str] = set()
    categories: Counter[str] = Counter()
    languages: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    for index, raw_case in enumerate(value):
        path = f"$.cases[{index}]"
        case = _object(raw_case, path)
        _exact_fields(case, _CASE_FIELDS, path)
        case_id = _text(case["case_id"], f"{path}.case_id")
        if case_id in ids:
            raise RelevanceCalibrationDatasetValidationError(
                f"{path}.case_id contains duplicate case ID {case_id!r}"
            )
        ids.add(case_id)
        category = _choice(
            case["category"], tuple(_CATEGORY_DECISIONS), f"{path}.category",
        )
        language = _choice(case["language"], _LANGUAGES, f"{path}.language")
        decision = _choice(
            case["expected_decision"], _DECISIONS, f"{path}.expected_decision",
        )
        if decision != _CATEGORY_DECISIONS[category]:
            raise RelevanceCalibrationDatasetValidationError(
                f"{path}.expected_decision must be {_CATEGORY_DECISIONS[category]!r} "
                f"for category {category!r}"
            )
        query = _text(case["query"], f"{path}.query")
        normalized = " ".join(unicodedata.normalize("NFKC", query).casefold().split())
        if not normalized or normalized in queries:
            raise RelevanceCalibrationDatasetValidationError(
                f"{path}.query is empty or duplicates another query after "
                "NFKC, casefold and whitespace normalization"
            )
        queries.add(normalized)
        _text(case["rationale"], f"{path}.rationale")
        tags = case["tags"]
        if not isinstance(tags, list):
            raise RelevanceCalibrationDatasetValidationError(
                f"{path}.tags must be a list"
            )
        seen_tags: set[str] = set()
        for tag_index, tag in enumerate(tags):
            tag_path = f"{path}.tags[{tag_index}]"
            tag_text = _text(tag, tag_path)
            if tag_text in seen_tags:
                raise RelevanceCalibrationDatasetValidationError(
                    f"{tag_path} contains duplicate tag {tag_text!r}"
                )
            seen_tags.add(tag_text)
        categories[category] += 1
        languages[language] += 1
        decisions[decision] += 1
    return categories, languages, decisions


def validate_relevance_calibration_dataset(document: object) -> None:
    """Validate an evaluation document without modifying any input value."""
    try:
        _scan_json(document, "$", set())
    except RecursionError as exc:
        raise RelevanceCalibrationDatasetValidationError(
            "$ nesting exceeds the supported JSON depth"
        ) from exc
    root = _object(document, "$")
    _exact_fields(root, _DOCUMENT_FIELDS, "$")
    if root["schema_version"] != RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION:
        raise RelevanceCalibrationDatasetValidationError(
            f"$.schema_version must be {RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION!r}"
        )
    _text(root["dataset_id"], "$.dataset_id")
    _text(root["scenario_id"], "$.scenario_id")
    if root["purpose"] != _PURPOSE:
        raise RelevanceCalibrationDatasetValidationError(
            f"$.purpose must be {_PURPOSE!r}"
        )
    categories, languages, decisions = _validate_cases(root["cases"])
    metadata = _object(root["metadata"], "$.metadata")
    _exact_fields(metadata, _METADATA_FIELDS, "$.metadata")
    _count(metadata["case_count"], len(root["cases"]), "$.metadata.case_count")
    for field, choices, actual in (
        ("category_counts", tuple(_CATEGORY_DECISIONS), categories),
        ("language_counts", _LANGUAGES, languages),
        ("decision_counts", _DECISIONS, decisions),
    ):
        path = f"$.metadata.{field}"
        counts = _object(metadata[field], path)
        _exact_fields(counts, choices, path)
        for key in choices:
            _count(counts[key], actual[key], f"{path}.{key}")


class _ObjectPairs(list[tuple[str, object]]):
    """Keep duplicate object keys until their complete JSON path is known."""


class _NonstandardNumber:
    def __init__(self, text: str) -> None:
        self.text = text


def _materialize_json(value: object, path: str) -> Any:
    if isinstance(value, _NonstandardNumber):
        raise RelevanceCalibrationDatasetValidationError(
            f"{path} contains non-standard JSON number {value.text!r}"
        )
    if isinstance(value, _ObjectPairs):
        result: dict[str, Any] = {}
        for key, item in value:
            child_path = _field_path(path, key)
            if key in result:
                raise RelevanceCalibrationDatasetValidationError(
                    f"{child_path} contains duplicate JSON object key {key!r}"
                )
            result[key] = _materialize_json(item, child_path)
        return result
    if isinstance(value, list):
        return [
            _materialize_json(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    return value


def load_relevance_calibration_dataset(path: Path) -> dict[str, Any]:
    """Read strict UTF-8 JSON, validate it, and return a fresh evaluation document.

    Duplicate keys and non-standard numbers retain their JSON paths. File,
    encoding, syntax, and validation errors always include the source filename
    and a JSON path. No output files or production artifacts are written.
    """
    source_path = Path(path)
    try:
        with source_path.open("r", encoding="utf-8") as handle:
            parsed = json.load(
                handle, object_pairs_hook=_ObjectPairs,
                parse_constant=_NonstandardNumber,
            )
        document = _materialize_json(parsed, "$")
        validate_relevance_calibration_dataset(document)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise RelevanceCalibrationDatasetValidationError(
            f"Cannot load relevance calibration dataset {source_path} at $: {exc}"
        ) from exc
    return document


__all__ = (
    "RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION",
    "RelevanceCalibrationDatasetValidationError",
    "load_relevance_calibration_dataset",
    "validate_relevance_calibration_dataset",
)
