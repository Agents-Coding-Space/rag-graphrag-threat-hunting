"""Evaluation-only annotations for exact Retrieval Corpus source pointers.

Judgments describe useful context, including context supporting abstention;
they contain neither queries nor answers. Generic validation does not impose a
particular benchmark size. Category and language counts are checked against a
calibration dataset when supplied, and always during resolution.

The resolver uses caller-supplied source bytes to verify raw-file provenance
without performing file I/O. Parsed documents cannot reproduce a file's byte
hash because JSON whitespace and key order are lost during parsing.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from hashlib import sha256
import json
import math
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Any
import unicodedata

from ..retrieval.schema import (
    RETRIEVAL_CORPUS_SCHEMA_VERSION,
    validate_retrieval_corpus,
)
from .relevance_dataset import (
    RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION,
    validate_relevance_calibration_dataset,
)


RETRIEVAL_JUDGMENTS_SCHEMA_VERSION = "retrieval-relevance-judgments/v1"
_PURPOSE = "retrieval_relevance_evaluation"
_DOCUMENT_FIELDS = (
    "schema_version", "judgment_set_id", "scenario_id", "purpose",
    "source_dataset", "source_corpus", "cases", "review", "metadata",
)
_CASE_FIELDS = (
    "case_id", "target_kind", "relevant_source_pointers", "annotation_note",
)
_REVIEW_FIELDS = ("review_status", "reviewer", "reviewed_at")
_METADATA_FIELDS = (
    "case_count", "target_kind_counts", "category_counts", "language_counts",
    "total_relevant_pointer_count", "cases_with_multiple_relevant_chunks",
)
_TARGET_KINDS = ("answer_support", "abstention_support", "no_relevant_chunk")
_CATEGORY_TARGETS = {
    "relevant_direct": "answer_support",
    "relevant_paraphrase": "answer_support",
    "insufficient_evidence": "abstention_support",
    "unrelated": "no_relevant_chunk",
}
_CATEGORY_DECISIONS = {
    "relevant_direct": "proceed",
    "relevant_paraphrase": "proceed",
    "insufficient_evidence": "abstain",
    "unrelated": "abstain",
}
_LANGUAGES = ("en", "vi")
_FORBIDDEN_FIELDS = frozenset({
    "query", "queries", "question", "questions", "question_text",
    "question_id", "expected_decision", "expected_answer", "expected_answers",
    "answer", "answers", "reference_answer", "gold_answer", "generated_answer",
    "model_output", "model_id", "embedding_model", "embedding", "embeddings",
    "vector", "vectors", "score", "scores", "rank", "ranking", "threshold",
})
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_POINTER_PATTERN = re.compile(r"^/(?:[^~]|~[01])*$")


class RetrievalJudgmentsValidationError(ValueError):
    """Raised when judgments or their source linkage violate the contract."""


def _field_path(path: str, key: str) -> str:
    if key.isidentifier():
        return f"{path}.{key}"
    return f"{path}[{json.dumps(key, ensure_ascii=True)}]"


def _snapshot_json(
    value: object,
    path: str = "$",
    active: set[int] | None = None,
    *,
    judgment_guards: bool = True,
) -> Any:
    """Detach JSON values while checking cycles, encoding, and recursive guards."""
    if active is None:
        active = set()
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise RetrievalJudgmentsValidationError(
                f"{path} must contain valid UTF-8 text"
            ) from exc
        if judgment_guards and value.strip().casefold() == "confirmed":
            raise RetrievalJudgmentsValidationError(
                f"{path} must not contain 'confirmed'"
            )
        return value
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise RetrievalJudgmentsValidationError(
                f"{path} must contain finite JSON numbers"
            )
        return value
    if not isinstance(value, (Mapping, list)):
        raise RetrievalJudgmentsValidationError(f"{path} must contain only JSON values")
    if id(value) in active:
        raise RetrievalJudgmentsValidationError(f"{path} contains a cyclic JSON value")
    active.add(id(value))
    try:
        if isinstance(value, Mapping):
            detached: dict[str, Any] = {}
            for key, child in value.items():
                if not isinstance(key, str):
                    raise RetrievalJudgmentsValidationError(
                        f"{path} must have string object keys"
                    )
                child_path = _field_path(path, key)
                _snapshot_json(key, child_path, active, judgment_guards=judgment_guards)
                normalized = unicodedata.normalize("NFKC", key).casefold().replace("-", "_")
                if judgment_guards and normalized in _FORBIDDEN_FIELDS:
                    raise RetrievalJudgmentsValidationError(
                        f"{child_path} is forbidden in retrieval judgments"
                    )
                detached[key] = _snapshot_json(
                    child, child_path, active, judgment_guards=judgment_guards,
                )
            return detached
        return [
            _snapshot_json(
                child, f"{path}[{index}]", active, judgment_guards=judgment_guards,
            )
            for index, child in enumerate(value)
        ]
    finally:
        active.remove(id(value))


def _object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RetrievalJudgmentsValidationError(f"{path} must be a JSON object")
    return value


def _exact_fields(value: Mapping[str, Any], fields: tuple[str, ...], path: str) -> None:
    missing = sorted(set(fields) - set(value))
    unexpected = sorted(set(value) - set(fields))
    if missing or unexpected:
        raise RetrievalJudgmentsValidationError(
            f"{path} fields must match the contract: missing {missing!r}; "
            f"unexpected {unexpected!r}"
        )


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RetrievalJudgmentsValidationError(f"{path} must be a non-empty string")
    return value


def _safe_path(value: object, path: str) -> str:
    text = _text(value, path)
    parts = text.split("/")
    if (
        "\\" in text or PurePosixPath(text).is_absolute()
        or PureWindowsPath(text).drive
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise RetrievalJudgmentsValidationError(
            f"{path} must be a safe repository-relative path using '/'"
        )
    return text


def _count(value: object, path: str, *, expected: int | None = None) -> int:
    if type(value) is not int or value < 0:
        raise RetrievalJudgmentsValidationError(
            f"{path} must be a nonnegative integer, not a boolean"
        )
    if expected is not None and value != expected:
        raise RetrievalJudgmentsValidationError(
            f"{path} must match the actual count {expected}"
        )
    return value


def _counts(
    value: object, choices: tuple[str, ...], path: str,
    *, actual: Mapping[str, int] | None = None,
) -> dict[str, int]:
    counts = _object(value, path)
    _exact_fields(counts, choices, path)
    return {
        key: _count(
            counts[key], f"{path}.{key}",
            expected=None if actual is None else actual.get(key, 0),
        )
        for key in choices
    }


def _validate_source(
    value: object, *, field: str, identifier: str, schema_version: str,
    scenario_id: str,
) -> None:
    path = f"$.{field}"
    source = _object(value, path)
    _exact_fields(source, ("path", "schema_version", "sha256", identifier, "scenario_id"), path)
    _safe_path(source["path"], f"{path}.path")
    if source["schema_version"] != schema_version:
        raise RetrievalJudgmentsValidationError(
            f"{path}.schema_version must be {schema_version!r}"
        )
    digest = _text(source["sha256"], f"{path}.sha256")
    if _SHA256_PATTERN.fullmatch(digest) is None:
        raise RetrievalJudgmentsValidationError(
            f"{path}.sha256 must contain a lowercase full SHA-256"
        )
    _text(source[identifier], f"{path}.{identifier}")
    if source["scenario_id"] != scenario_id:
        raise RetrievalJudgmentsValidationError(
            f"{path}.scenario_id must match $.scenario_id"
        )


def _validate_cases(value: object) -> tuple[list[Mapping[str, Any]], Counter[str], int, int]:
    if not isinstance(value, list) or not value:
        raise RetrievalJudgmentsValidationError("$.cases must be a non-empty list")
    cases: list[Mapping[str, Any]] = []
    case_ids: list[str] = []
    kinds: Counter[str] = Counter()
    pointer_count = 0
    multiple_count = 0
    for index, value_case in enumerate(value):
        path = f"$.cases[{index}]"
        case = _object(value_case, path)
        _exact_fields(case, _CASE_FIELDS, path)
        case_id = _text(case["case_id"], f"{path}.case_id")
        if case_id in case_ids:
            raise RetrievalJudgmentsValidationError(
                f"{path}.case_id contains duplicate case ID {case_id!r}"
            )
        case_ids.append(case_id)
        target_kind = _text(case["target_kind"], f"{path}.target_kind")
        if target_kind not in _TARGET_KINDS:
            raise RetrievalJudgmentsValidationError(
                f"{path}.target_kind has unsupported value {target_kind!r}"
            )
        _text(case["annotation_note"], f"{path}.annotation_note")
        pointers = case["relevant_source_pointers"]
        if not isinstance(pointers, list):
            raise RetrievalJudgmentsValidationError(
                f"{path}.relevant_source_pointers must be a list"
            )
        for pointer_index, pointer in enumerate(pointers):
            where = f"{path}.relevant_source_pointers[{pointer_index}]"
            pointer = _text(pointer, where)
            if _POINTER_PATTERN.fullmatch(pointer) is None:
                raise RetrievalJudgmentsValidationError(
                    f"{where} must be an absolute RFC 6901 JSON pointer"
                )
        if len(set(pointers)) != len(pointers):
            raise RetrievalJudgmentsValidationError(
                f"{path}.relevant_source_pointers contains duplicate pointers"
            )
        if pointers != sorted(pointers):
            raise RetrievalJudgmentsValidationError(
                f"{path}.relevant_source_pointers must be stably sorted"
            )
        if (target_kind == "no_relevant_chunk") != (len(pointers) == 0):
            raise RetrievalJudgmentsValidationError(
                f"{path}.relevant_source_pointers must be empty only for "
                "no_relevant_chunk; support targets require at least one pointer"
            )
        kinds[target_kind] += 1
        pointer_count += len(pointers)
        multiple_count += int(len(pointers) > 1)
        cases.append(case)
    if case_ids != sorted(case_ids):
        raise RetrievalJudgmentsValidationError("$.cases must be stably sorted by case_id")
    return cases, kinds, pointer_count, multiple_count


def _validate_dataset_links(
    root: Mapping[str, Any], dataset: object, cases: list[Mapping[str, Any]],
) -> tuple[Counter[str], Counter[str]]:
    validate_relevance_calibration_dataset(dataset)
    source = _object(dataset, "$.calibration_dataset")
    provenance = root["source_dataset"]
    for field in ("schema_version", "dataset_id", "scenario_id"):
        if provenance[field] != source[field]:
            raise RetrievalJudgmentsValidationError(
                f"$.source_dataset.{field} must match the calibration dataset"
            )
    if root["scenario_id"] != source["scenario_id"]:
        raise RetrievalJudgmentsValidationError(
            "$.scenario_id must match the calibration dataset"
        )
    dataset_cases = {case["case_id"]: case for case in source["cases"]}
    judgment_ids = {case["case_id"] for case in cases}
    missing = sorted(set(dataset_cases) - judgment_ids)
    extra = sorted(judgment_ids - set(dataset_cases))
    if missing or extra:
        raise RetrievalJudgmentsValidationError(
            f"$.cases must match dataset case IDs: missing {missing!r}; extra {extra!r}"
        )
    for index, case in enumerate(cases):
        dataset_case = dataset_cases[case["case_id"]]
        category = dataset_case["category"]
        if case["target_kind"] != _CATEGORY_TARGETS[category]:
            raise RetrievalJudgmentsValidationError(
                f"$.cases[{index}].target_kind must be {_CATEGORY_TARGETS[category]!r} "
                f"for category {category!r}"
            )
        if dataset_case["language"] not in _LANGUAGES:
            raise RetrievalJudgmentsValidationError(
                f"$.calibration_dataset.cases[{index}].language is unsupported"
            )
        if dataset_case["expected_decision"] != _CATEGORY_DECISIONS[category]:
            raise RetrievalJudgmentsValidationError(
                f"$.calibration_dataset.cases[{index}].expected_decision is inconsistent"
            )
    return (
        Counter(case["category"] for case in source["cases"]),
        Counter(case["language"] for case in source["cases"]),
    )


def validate_retrieval_judgments_document(
    document: object, *, calibration_dataset: object | None = None,
) -> None:
    """Validate without mutation; optional dataset enables exact source counts.

    Judgments do not repeat source categories or languages. Without the dataset,
    their declared counts are checked for type, totals, and target consistency.
    Supplying it additionally verifies every case, category, language, and count.
    """
    try:
        root = _object(_snapshot_json(document), "$")
        _exact_fields(root, _DOCUMENT_FIELDS, "$")
        if root["schema_version"] != RETRIEVAL_JUDGMENTS_SCHEMA_VERSION:
            raise RetrievalJudgmentsValidationError(
                f"$.schema_version must be {RETRIEVAL_JUDGMENTS_SCHEMA_VERSION!r}"
            )
        _text(root["judgment_set_id"], "$.judgment_set_id")
        scenario_id = _text(root["scenario_id"], "$.scenario_id")
        if root["purpose"] != _PURPOSE:
            raise RetrievalJudgmentsValidationError(f"$.purpose must be {_PURPOSE!r}")
        for field, identifier, schema in (
            ("source_dataset", "dataset_id", RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION),
            ("source_corpus", "corpus_id", RETRIEVAL_CORPUS_SCHEMA_VERSION),
        ):
            _validate_source(
                root[field], field=field, identifier=identifier,
                schema_version=schema, scenario_id=scenario_id,
            )
        cases, kinds, pointer_count, multiple_count = _validate_cases(root["cases"])
        review = _object(root["review"], "$.review")
        _exact_fields(review, _REVIEW_FIELDS, "$.review")
        if review["review_status"] != "pending_human_review":
            raise RetrievalJudgmentsValidationError(
                "$.review.review_status must be 'pending_human_review'"
            )
        for field in ("reviewer", "reviewed_at"):
            if review[field] is not None:
                raise RetrievalJudgmentsValidationError(f"$.review.{field} must be null")
        metadata = _object(root["metadata"], "$.metadata")
        _exact_fields(metadata, _METADATA_FIELDS, "$.metadata")
        count = len(cases)
        _count(metadata["case_count"], "$.metadata.case_count", expected=count)
        _counts(metadata["target_kind_counts"], _TARGET_KINDS,
                "$.metadata.target_kind_counts", actual=kinds)
        actual_categories = actual_languages = None
        if calibration_dataset is not None:
            actual_categories, actual_languages = _validate_dataset_links(
                root, calibration_dataset, cases,
            )
        categories = _counts(
            metadata["category_counts"], tuple(_CATEGORY_TARGETS),
            "$.metadata.category_counts", actual=actual_categories,
        )
        languages = _counts(
            metadata["language_counts"], _LANGUAGES,
            "$.metadata.language_counts", actual=actual_languages,
        )
        if sum(categories.values()) != count:
            raise RetrievalJudgmentsValidationError(
                "$.metadata.category_counts must sum to case_count"
            )
        if sum(languages.values()) != count:
            raise RetrievalJudgmentsValidationError(
                "$.metadata.language_counts must sum to case_count"
            )
        for kind in _TARGET_KINDS:
            category_total = sum(
                categories[category] for category, target in _CATEGORY_TARGETS.items()
                if target == kind
            )
            if category_total != kinds[kind]:
                raise RetrievalJudgmentsValidationError(
                    f"$.metadata.category_counts do not match target kind {kind!r}"
                )
        _count(metadata["total_relevant_pointer_count"],
               "$.metadata.total_relevant_pointer_count", expected=pointer_count)
        _count(metadata["cases_with_multiple_relevant_chunks"],
               "$.metadata.cases_with_multiple_relevant_chunks", expected=multiple_count)
    except RetrievalJudgmentsValidationError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise RetrievalJudgmentsValidationError(f"$ cannot validate judgments: {exc}") from exc


class _ObjectPairs(list[tuple[str, object]]):
    """Preserve duplicate JSON keys until their full paths can be reported."""


class _NonstandardNumber:
    def __init__(self, text: str) -> None:
        self.text = text


def _materialize_json(value: object, path: str) -> Any:
    if isinstance(value, _NonstandardNumber):
        raise RetrievalJudgmentsValidationError(
            f"{path} contains non-standard JSON number {value.text!r}"
        )
    if isinstance(value, _ObjectPairs):
        result: dict[str, Any] = {}
        for key, child in value:
            child_path = _field_path(path, key)
            if key in result:
                raise RetrievalJudgmentsValidationError(
                    f"{child_path} contains duplicate JSON object key {key!r}"
                )
            result[key] = _materialize_json(child, child_path)
        return result
    if isinstance(value, list):
        return [
            _materialize_json(child, f"{path}[{index}]")
            for index, child in enumerate(value)
        ]
    return value


def _parse_json_bytes(payload: bytes) -> Any:
    parsed = json.loads(
        payload.decode("utf-8", errors="strict"),
        object_pairs_hook=_ObjectPairs, parse_constant=_NonstandardNumber,
    )
    return _snapshot_json(_materialize_json(parsed, "$"), judgment_guards=False)


def load_retrieval_judgments_document(
    path: Path, *, calibration_dataset: object | None = None,
) -> dict[str, Any]:
    """Load strict UTF-8 JSON; every error identifies the filename and JSON path."""
    source_path = path
    try:
        source_path = Path(path)
        document = _parse_json_bytes(source_path.read_bytes())
        validate_retrieval_judgments_document(document, calibration_dataset=calibration_dataset)
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise RetrievalJudgmentsValidationError(
            f"Cannot load retrieval judgments {source_path} at $: {exc}"
        ) from exc
    return document


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _verify_source_bytes(
    source: Mapping[str, Any], document: Mapping[str, Any], *,
    source_path: str | Path, source_bytes: bytes, field: str,
) -> None:
    path = f"$.{field}"
    supplied_path = source_path.as_posix() if isinstance(source_path, Path) else source_path
    supplied_path = _safe_path(supplied_path, f"{path}.supplied_path")
    if source["path"] != supplied_path:
        raise RetrievalJudgmentsValidationError(f"{path}.path does not match supplied source path")
    if type(source_bytes) is not bytes:
        raise RetrievalJudgmentsValidationError(f"{path}.source_bytes must be bytes")
    if source["sha256"] != sha256(source_bytes).hexdigest():
        raise RetrievalJudgmentsValidationError(f"{path}.sha256 does not match supplied source bytes")
    try:
        parsed = _parse_json_bytes(source_bytes)
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise RetrievalJudgmentsValidationError(
            f"{path} cannot parse source {supplied_path} at $: {exc}"
        ) from exc
    if _canonical_json(parsed) != _canonical_json(document):
        raise RetrievalJudgmentsValidationError(
            f"{path} supplied source bytes do not match the input document"
        )


def resolve_retrieval_judgments(
    document: object,
    calibration_dataset: object,
    retrieval_corpus: object,
    *,
    source_dataset_path: str | Path,
    source_dataset_bytes: bytes,
    source_corpus_path: str | Path,
    source_corpus_bytes: bytes,
) -> list[dict[str, Any]]:
    """Resolve exact source pointers into detached, deterministic case records.

    All three documents are validated. Source byte payloads must be the exact
    UTF-8 files represented by the dataset and corpus documents: both their
    SHA-256 digests and their parsed contents are verified. Paths are provenance
    labels only; this function never reads or writes files or runs retrieval.
    Resolved chunk types correspond positionally to sorted resolved chunk IDs.
    """
    try:
        dataset = _object(_snapshot_json(calibration_dataset, judgment_guards=False), "$.dataset")
        corpus = _object(_snapshot_json(retrieval_corpus, judgment_guards=False), "$.corpus")
        validate_relevance_calibration_dataset(dataset)
        validate_retrieval_corpus(corpus)
        validate_retrieval_judgments_document(document, calibration_dataset=dataset)
        root = _object(_snapshot_json(document), "$")
        for field in ("schema_version", "corpus_id", "scenario_id"):
            if root["source_corpus"][field] != corpus[field]:
                raise RetrievalJudgmentsValidationError(
                    f"$.source_corpus.{field} must match the retrieval corpus"
                )
        if root["scenario_id"] != corpus["scenario_id"]:
            raise RetrievalJudgmentsValidationError("$.scenario_id must match the retrieval corpus")
        _verify_source_bytes(
            root["source_dataset"], dataset, source_path=source_dataset_path,
            source_bytes=source_dataset_bytes, field="source_dataset",
        )
        _verify_source_bytes(
            root["source_corpus"], corpus, source_path=source_corpus_path,
            source_bytes=source_corpus_bytes, field="source_corpus",
        )
        chunks_by_pointer: dict[str, list[Mapping[str, Any]]] = {}
        for chunk in corpus["chunks"]:
            chunks_by_pointer.setdefault(chunk["source"]["json_pointer"], []).append(chunk)
        dataset_cases = {case["case_id"]: case for case in dataset["cases"]}
        result: list[dict[str, Any]] = []
        for index, case in enumerate(root["cases"]):
            source_case = dataset_cases[case["case_id"]]
            resolved: list[Mapping[str, Any]] = []
            for pointer in case["relevant_source_pointers"]:
                matches = chunks_by_pointer.get(pointer, [])
                if len(matches) != 1:
                    reason = "missing" if not matches else "ambiguous"
                    raise RetrievalJudgmentsValidationError(
                        f"$.cases[{index}].relevant_source_pointers has {reason} "
                        f"exact corpus source pointer {pointer!r}"
                    )
                resolved.append(matches[0])
            resolved.sort(key=lambda chunk: chunk["chunk_id"])
            chunk_ids = [chunk["chunk_id"] for chunk in resolved]
            if len(set(chunk_ids)) != len(chunk_ids):
                raise RetrievalJudgmentsValidationError(
                    f"$.cases[{index}] contains duplicate resolved chunk IDs"
                )
            result.append({
                "case_id": case["case_id"],
                "category": source_case["category"],
                "language": source_case["language"],
                "expected_decision": source_case["expected_decision"],
                "target_kind": case["target_kind"],
                "relevant_source_pointers": sorted(case["relevant_source_pointers"]),
                "resolved_chunk_ids": chunk_ids,
                "resolved_chunk_types": [chunk["chunk_type"] for chunk in resolved],
            })
        return sorted(result, key=lambda case: case["case_id"])
    except RetrievalJudgmentsValidationError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise RetrievalJudgmentsValidationError(f"$ cannot resolve judgments: {exc}") from exc


__all__ = (
    "RETRIEVAL_JUDGMENTS_SCHEMA_VERSION",
    "RetrievalJudgmentsValidationError",
    "validate_retrieval_judgments_document",
    "load_retrieval_judgments_document",
    "resolve_retrieval_judgments",
)
