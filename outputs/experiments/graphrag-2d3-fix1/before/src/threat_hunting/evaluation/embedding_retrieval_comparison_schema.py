"""Strict contracts for deterministic, offline embedding retrieval comparisons.

This module validates supplied rankings and replays report calculations. It
performs no file I/O, retrieval, model execution, or threshold selection.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Any
import unicodedata

from ..retrieval.vector_schema import EMBEDDING_FIELDS
from ..retrieval.schema import CHUNK_SOURCE_OBJECT_TYPES, RETRIEVAL_CORPUS_SCHEMA_VERSION
from .relevance_dataset import RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION
from .retrieval_judgments import RETRIEVAL_JUDGMENTS_SCHEMA_VERSION


EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION = "embedding-retrieval-comparison/v1"
FIXED_CUTOFFS = (1, 3, 5, 10)
_RUN_FIELDS = (
    "candidate_id", "index_id", "index_sha256", "embedding", "ranking_limit", "rankings",
)
_RANKING_FIELDS = ("case_id", "hits")
_HIT_FIELDS = ("chunk_id", "score")
_FORBIDDEN_FIELDS = frozenset({
    "expected_answer", "expected_answers", "generated_answer", "generated_answers",
    "reference_answer", "reference_answers", "gold_answer", "gold_answers",
    "answer", "answers", "model_output", "llm_output", "llm_response",
})
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_POINTER_PATTERN = re.compile(r"^/(?:[^~]|~[01])*$")
_REPORT_FIELDS = (
    "schema_version", "evaluation_id", "scenario_id", "dataset_provenance",
    "judgments_provenance", "corpus_provenance", "cutoffs", "baseline_candidate_id",
    "candidates", "corpus_catalog", "cases", "aggregates", "comparisons",
    "metric_policy", "warnings", "metadata", "review",
)
_DESCRIPTOR_FIELDS = _RUN_FIELDS[:-1]
_CATALOG_FIELDS = ("chunk_id", "chunk_type", "source_json_pointer")
_CASE_FIELDS = (
    "case_id", "category", "language", "target_kind", "relevant_chunk_ids",
    "relevant_source_pointers", "relevant_pointer_count", "relevant_total", "rankings",
)
_REPORT_RANKING_FIELDS = (
    "candidate_id", "hits", "returned_hit_count", "top_cosine_score", "metrics",
)
_REPORT_HIT_FIELDS = (
    "rank", "chunk_id", "chunk_type", "source_json_pointer", "score", "is_relevant",
)
_CATEGORY_TARGETS = {
    "relevant_direct": "answer_support",
    "relevant_paraphrase": "answer_support",
    "insufficient_evidence": "abstention_support",
    "unrelated": "no_relevant_chunk",
}


class EmbeddingRetrievalComparisonError(ValueError):
    """Raised when rankings, source linkage, or comparison reports are invalid."""


def _field_path(path: str, key: str) -> str:
    if key.isidentifier():
        return f"{path}.{key}"
    return f"{path}[{json.dumps(key, ensure_ascii=True)}]"


def _normalized(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold().replace("-", "_")


def _snapshot(value: object, path: str, active: set[int]) -> Any:
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        if _normalized(value.strip()) == "confirmed":
            raise EmbeddingRetrievalComparisonError(f"{path} must not contain confirmed")
        return value
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise EmbeddingRetrievalComparisonError(f"{path} must contain finite JSON numbers")
        return value
    if not isinstance(value, (Mapping, list)):
        raise EmbeddingRetrievalComparisonError(f"{path} must contain only native JSON values")
    if id(value) in active:
        raise EmbeddingRetrievalComparisonError(f"{path} contains a cyclic JSON value")
    active.add(id(value))
    try:
        if isinstance(value, Mapping):
            detached: dict[str, Any] = {}
            for key, child in value.items():
                if not isinstance(key, str):
                    raise EmbeddingRetrievalComparisonError(f"{path} must have string object keys")
                where = _field_path(path, key)
                _snapshot(key, where, active)
                normalized = _normalized(key)
                if (
                    normalized in _FORBIDDEN_FIELDS
                    or "threshold" in normalized or "probability" in normalized
                ):
                    raise EmbeddingRetrievalComparisonError(f"{where} is forbidden in comparison data")
                detached[key] = _snapshot(child, where, active)
            return detached
        return [_snapshot(child, f"{path}[{index}]", active) for index, child in enumerate(value)]
    finally:
        active.remove(id(value))


def snapshot_json(value: object, path: str = "$") -> Any:
    """Return detached finite JSON, checking encoding, cycles, and recursive guards.

    Queries and expected decisions are allowed in source dataset snapshots;
    answer/model outputs and probability or threshold fields are rejected.
    """
    try:
        return _snapshot(value, path, set())
    except EmbeddingRetrievalComparisonError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise EmbeddingRetrievalComparisonError(f"{path} cannot snapshot JSON: {exc}") from exc


def _object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EmbeddingRetrievalComparisonError(f"{path} must be a JSON object")
    return value


def _list(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise EmbeddingRetrievalComparisonError(f"{path} must be a JSON list")
    return value


def _exact_fields(value: Mapping[str, Any], fields: tuple[str, ...], path: str) -> None:
    missing = sorted(set(fields) - set(value))
    unexpected = sorted(set(value) - set(fields))
    if missing or unexpected:
        raise EmbeddingRetrievalComparisonError(
            f"{path} fields must match the contract: missing {missing!r}; "
            f"unexpected {unexpected!r}"
        )


def _text(value: object, path: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value.strip()):
        qualifier = "a string" if empty else "a non-empty string"
        raise EmbeddingRetrievalComparisonError(f"{path} must be {qualifier}")
    return value


def _integer(value: object, path: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise EmbeddingRetrievalComparisonError(
            f"{path} must be an integer >= {minimum}, not a boolean"
        )
    return value


def _digest(value: object, path: str) -> str:
    digest = _text(value, path)
    if _SHA256_PATTERN.fullmatch(digest) is None:
        raise EmbeddingRetrievalComparisonError(f"{path} must be a lowercase full SHA-256")
    return digest


def _safe_path(value: object, path: str) -> str:
    text = _text(value, path)
    if (
        "\\" in text or PurePosixPath(text).is_absolute()
        or PureWindowsPath(text).drive
        or any(part in ("", ".", "..") for part in text.split("/"))
    ):
        raise EmbeddingRetrievalComparisonError(
            f"{path} must be a safe repository-relative path using '/'"
        )
    return text


def _score(value: object, path: str) -> int | float:
    if type(value) not in (int, float):
        raise EmbeddingRetrievalComparisonError(f"{path} must be a finite numeric cosine score")
    try:
        finite = math.isfinite(value)
    except OverflowError as exc:
        raise EmbeddingRetrievalComparisonError(f"{path} must be a finite numeric cosine score") from exc
    if not finite or not -1 <= value <= 1:
        raise EmbeddingRetrievalComparisonError(f"{path} must be a cosine score in [-1, 1]")
    return value


def validate_cutoffs(value: object) -> list[int]:
    """Validate the fixed evaluation cutoffs, preserving an explicit policy."""
    try:
        if not isinstance(value, (list, tuple)):
            raise EmbeddingRetrievalComparisonError("$.cutoffs must be a list or tuple")
        cutoffs = [_integer(item, f"$.cutoffs[{index}]", minimum=1) for index, item in enumerate(value)]
        if cutoffs != sorted(set(cutoffs)):
            raise EmbeddingRetrievalComparisonError("$.cutoffs must be unique and strictly increasing")
        if tuple(cutoffs) != FIXED_CUTOFFS:
            raise EmbeddingRetrievalComparisonError(f"$.cutoffs must equal {FIXED_CUTOFFS!r}")
        return cutoffs
    except EmbeddingRetrievalComparisonError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise EmbeddingRetrievalComparisonError(f"$.cutoffs cannot validate: {exc}") from exc


def _validate_embedding(value: object, path: str) -> None:
    embedding = _object(value, path)
    _exact_fields(embedding, EMBEDDING_FIELDS, path)
    for field in ("provider", "model_id", "model_revision"):
        _text(embedding[field], f"{path}.{field}")
    _integer(embedding["dimension"], f"{path}.dimension", minimum=1)
    if embedding["distance_metric"] != "cosine":
        raise EmbeddingRetrievalComparisonError(f"{path}.distance_metric must be 'cosine'")
    if embedding["normalization"] not in ("none", "l2"):
        raise EmbeddingRetrievalComparisonError(f"{path}.normalization must be 'none' or 'l2'")
    for field in ("document_prefix", "query_prefix"):
        _text(embedding[field], f"{path}.{field}", empty=True)


def _validate_hits(
    value: object, *, chunk_ids: set[str], limit: int, path: str,
) -> None:
    hits = _list(value, path)
    if len(hits) > limit:
        raise EmbeddingRetrievalComparisonError(f"{path} ranking exceeds its declared ranking_limit {limit}")
    identifiers: set[str] = set()
    ordering: list[tuple[int | float, str]] = []
    for index, raw_hit in enumerate(hits):
        where = f"{path}[{index}]"
        hit = _object(raw_hit, where)
        _exact_fields(hit, _HIT_FIELDS, where)
        identifier = _text(hit["chunk_id"], f"{where}.chunk_id")
        if identifier not in chunk_ids:
            raise EmbeddingRetrievalComparisonError(f"{where}.chunk_id is not present in the corpus")
        if identifier in identifiers:
            raise EmbeddingRetrievalComparisonError(f"{where}.chunk_id duplicates a ranking chunk")
        identifiers.add(identifier)
        ordering.append((-_score(hit["score"], f"{where}.score"), identifier))
    if ordering != sorted(ordering):
        raise EmbeddingRetrievalComparisonError(
            f"{path} must be ordered by score descending, then chunk_id ascending for ties"
        )


def validate_candidate_runs(
    runs: object, case_ids: set[str], chunk_ids: set[str],
) -> list[dict[str, Any]]:
    """Validate complete rankings and return detached, stably sorted candidates."""
    try:
        candidates = _list(snapshot_json(runs, "$.candidate_runs"), "$.candidate_runs")
        if len(candidates) < 2:
            raise EmbeddingRetrievalComparisonError("$.candidate_runs requires at least two candidates")
        candidate_ids: set[str] = set()
        index_ids: set[str] = set()
        for index, raw_run in enumerate(candidates):
            path = f"$.candidate_runs[{index}]"
            run = _object(raw_run, path)
            _exact_fields(run, _RUN_FIELDS, path)
            for field, seen in (("candidate_id", candidate_ids), ("index_id", index_ids)):
                identifier = _text(run[field], f"{path}.{field}")
                if identifier in seen:
                    raise EmbeddingRetrievalComparisonError(f"{path}.{field} must be unique")
                seen.add(identifier)
            _digest(run["index_sha256"], f"{path}.index_sha256")
            _validate_embedding(run["embedding"], f"{path}.embedding")
            limit = _integer(run["ranking_limit"], f"{path}.ranking_limit", minimum=1)
            rankings = _list(run["rankings"], f"{path}.rankings")
            ranking_ids: set[str] = set()
            for ranking_index, raw_ranking in enumerate(rankings):
                where = f"{path}.rankings[{ranking_index}]"
                ranking = _object(raw_ranking, where)
                _exact_fields(ranking, _RANKING_FIELDS, where)
                identifier = _text(ranking["case_id"], f"{where}.case_id")
                if identifier in ranking_ids:
                    raise EmbeddingRetrievalComparisonError(f"{where}.case_id duplicates a candidate case")
                if identifier not in case_ids:
                    raise EmbeddingRetrievalComparisonError(f"{where}.case_id is not present in the dataset")
                ranking_ids.add(identifier)
                _validate_hits(ranking["hits"], chunk_ids=chunk_ids, limit=limit, path=f"{where}.hits")
            if ranking_ids != case_ids:
                raise EmbeddingRetrievalComparisonError(
                    f"{path}.rankings must cover every case exactly: "
                    f"missing {sorted(case_ids - ranking_ids)!r}; extra {sorted(ranking_ids - case_ids)!r}"
                )
            run["rankings"] = sorted(rankings, key=lambda ranking: ranking["case_id"])
        return sorted(candidates, key=lambda candidate: candidate["candidate_id"])
    except EmbeddingRetrievalComparisonError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise EmbeddingRetrievalComparisonError(f"$.candidate_runs cannot validate: {exc}") from exc


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _sorted_strings(value: object, path: str) -> list[str]:
    values = [_text(item, f"{path}[{index}]") for index, item in enumerate(_list(value, path))]
    if values != sorted(set(values)):
        raise EmbeddingRetrievalComparisonError(f"{path} must be unique and stably sorted")
    return values


def _pointer(value: object, path: str) -> str:
    pointer = _text(value, path)
    if _POINTER_PATTERN.fullmatch(pointer) is None:
        raise EmbeddingRetrievalComparisonError(f"{path} must be an absolute RFC 6901 JSON pointer")
    return pointer


def _validate_provenance(value: object, *, path: str, schema: str, identifier: str, scenario: str) -> None:
    source = _object(value, path)
    _exact_fields(source, ("path", "schema_version", "sha256", identifier, "scenario_id"), path)
    _safe_path(source["path"], f"{path}.path")
    _digest(source["sha256"], f"{path}.sha256")
    _text(source[identifier], f"{path}.{identifier}")
    if source["schema_version"] != schema:
        raise EmbeddingRetrievalComparisonError(f"{path}.schema_version must be {schema!r}")
    if source["scenario_id"] != scenario:
        raise EmbeddingRetrievalComparisonError(f"{path}.scenario_id must match $.scenario_id")


def _validate_catalog(value: object) -> tuple[dict[str, Mapping[str, Any]], dict[str, list[str]]]:
    catalog = _list(value, "$.corpus_catalog")
    if not catalog:
        raise EmbeddingRetrievalComparisonError("$.corpus_catalog must not be empty")
    by_id: dict[str, Mapping[str, Any]] = {}
    by_pointer: dict[str, list[str]] = {}
    for index, raw_chunk in enumerate(catalog):
        path = f"$.corpus_catalog[{index}]"
        chunk = _object(raw_chunk, path)
        _exact_fields(chunk, _CATALOG_FIELDS, path)
        identifier = _text(chunk["chunk_id"], f"{path}.chunk_id")
        if identifier in by_id:
            raise EmbeddingRetrievalComparisonError(f"{path}.chunk_id must be unique")
        chunk_type = _text(chunk["chunk_type"], f"{path}.chunk_type")
        if chunk_type not in CHUNK_SOURCE_OBJECT_TYPES:
            raise EmbeddingRetrievalComparisonError(f"{path}.chunk_type is unsupported")
        pointer = _pointer(chunk["source_json_pointer"], f"{path}.source_json_pointer")
        by_id[identifier] = chunk
        by_pointer.setdefault(pointer, []).append(identifier)
    if list(by_id) != sorted(by_id):
        raise EmbeddingRetrievalComparisonError("$.corpus_catalog must be stably sorted by chunk_id")
    return by_id, by_pointer


def _validate_descriptors(value: object, baseline_id: str) -> list[Mapping[str, Any]]:
    descriptors = _list(value, "$.candidates")
    if len(descriptors) < 2:
        raise EmbeddingRetrievalComparisonError("$.candidates requires at least two candidates")
    ids: list[str] = []
    index_ids: set[str] = set()
    for index, raw_descriptor in enumerate(descriptors):
        path = f"$.candidates[{index}]"
        descriptor = _object(raw_descriptor, path)
        _exact_fields(descriptor, _DESCRIPTOR_FIELDS, path)
        identifier = _text(descriptor["candidate_id"], f"{path}.candidate_id")
        if identifier in ids:
            raise EmbeddingRetrievalComparisonError(f"{path}.candidate_id must be unique")
        ids.append(identifier)
        index_id = _text(descriptor["index_id"], f"{path}.index_id")
        if index_id in index_ids:
            raise EmbeddingRetrievalComparisonError(f"{path}.index_id must be unique")
        index_ids.add(index_id)
        _digest(descriptor["index_sha256"], f"{path}.index_sha256")
        _validate_embedding(descriptor["embedding"], f"{path}.embedding")
        _integer(descriptor["ranking_limit"], f"{path}.ranking_limit", minimum=1)
    if ids != sorted(ids):
        raise EmbeddingRetrievalComparisonError("$.candidates must be stably sorted by candidate_id")
    if baseline_id not in ids:
        raise EmbeddingRetrievalComparisonError("$.baseline_candidate_id must identify a declared candidate")
    return descriptors


def _validate_relevant_targets(
    case: Mapping[str, Any], path: str,
    by_id: dict[str, Mapping[str, Any]], by_pointer: dict[str, list[str]],
) -> set[str]:
    relevant_ids = _sorted_strings(case["relevant_chunk_ids"], f"{path}.relevant_chunk_ids")
    pointers = _sorted_strings(case["relevant_source_pointers"], f"{path}.relevant_source_pointers")
    for pointer in pointers:
        _pointer(pointer, f"{path}.relevant_source_pointers")
        if len(by_pointer.get(pointer, [])) != 1:
            raise EmbeddingRetrievalComparisonError(
                f"{path}.relevant_source_pointers must resolve exactly once in corpus_catalog: {pointer!r}"
            )
    if any(identifier not in by_id for identifier in relevant_ids):
        raise EmbeddingRetrievalComparisonError(f"{path}.relevant_chunk_ids contains unknown corpus chunks")
    resolved_ids = sorted(by_pointer[pointer][0] for pointer in pointers)
    if relevant_ids != resolved_ids:
        raise EmbeddingRetrievalComparisonError(
            f"{path}.relevant_chunk_ids must match the exact relevant_source_pointers"
        )
    for field, expected in (("relevant_pointer_count", len(pointers)), ("relevant_total", len(relevant_ids))):
        if _integer(case[field], f"{path}.{field}") != expected:
            raise EmbeddingRetrievalComparisonError(f"{path}.{field} must match actual targets {expected}")
    if (case["target_kind"] == "no_relevant_chunk") != (len(relevant_ids) == 0):
        raise EmbeddingRetrievalComparisonError(
            f"{path} must have no targets only for no_relevant_chunk"
        )
    return set(relevant_ids)


def _raw_report_hits(
    value: object, path: str, *, relevant_ids: set[str], by_id: dict[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    hits = _list(value, path)
    raw_hits: list[dict[str, Any]] = []
    for index, raw_hit in enumerate(hits):
        where = f"{path}[{index}]"
        hit = _object(raw_hit, where)
        _exact_fields(hit, _REPORT_HIT_FIELDS, where)
        if _integer(hit["rank"], f"{where}.rank", minimum=1) != index + 1:
            raise EmbeddingRetrievalComparisonError(f"{where}.rank must match its one-based position")
        identifier = _text(hit["chunk_id"], f"{where}.chunk_id")
        if identifier not in by_id:
            raise EmbeddingRetrievalComparisonError(f"{where}.chunk_id is absent from corpus_catalog")
        chunk = by_id[identifier]
        for field in ("chunk_type", "source_json_pointer"):
            if hit[field] != chunk[field]:
                raise EmbeddingRetrievalComparisonError(f"{where}.{field} must match corpus_catalog")
        if type(hit["is_relevant"]) is not bool or hit["is_relevant"] != (identifier in relevant_ids):
            raise EmbeddingRetrievalComparisonError(f"{where}.is_relevant must match the case's relevant chunks")
        raw_hits.append({"chunk_id": identifier, "score": _score(hit["score"], f"{where}.score")})
    return raw_hits


def _validate_report_cases(
    value: object, descriptors: list[Mapping[str, Any]],
    by_id: dict[str, Mapping[str, Any]], by_pointer: dict[str, list[str]],
) -> None:
    cases = _list(value, "$.cases")
    if not cases:
        raise EmbeddingRetrievalComparisonError("$.cases must not be empty")
    candidate_ids = [descriptor["candidate_id"] for descriptor in descriptors]
    raw_rankings: dict[str, list[dict[str, Any]]] = {identifier: [] for identifier in candidate_ids}
    case_ids: list[str] = []
    support_groups: set[tuple[str, str]] = set()
    for index, raw_case in enumerate(cases):
        path = f"$.cases[{index}]"
        case = _object(raw_case, path)
        _exact_fields(case, _CASE_FIELDS, path)
        identifier = _text(case["case_id"], f"{path}.case_id")
        if identifier in case_ids:
            raise EmbeddingRetrievalComparisonError(f"{path}.case_id must be unique")
        case_ids.append(identifier)
        category = _text(case["category"], f"{path}.category")
        if category not in _CATEGORY_TARGETS:
            raise EmbeddingRetrievalComparisonError(f"{path}.category is unsupported")
        language = _text(case["language"], f"{path}.language")
        if language not in ("en", "vi"):
            raise EmbeddingRetrievalComparisonError(f"{path}.language must be 'en' or 'vi'")
        if case["target_kind"] != _CATEGORY_TARGETS[category]:
            raise EmbeddingRetrievalComparisonError(f"{path}.target_kind must match its category")
        relevant_ids = _validate_relevant_targets(case, path, by_id, by_pointer)
        if relevant_ids:
            support_groups.add((category, language))
        rankings = _list(case["rankings"], f"{path}.rankings")
        seen_candidates: list[str] = []
        for ranking_index, raw_ranking in enumerate(rankings):
            where = f"{path}.rankings[{ranking_index}]"
            ranking = _object(raw_ranking, where)
            _exact_fields(ranking, _REPORT_RANKING_FIELDS, where)
            candidate_id = _text(ranking["candidate_id"], f"{where}.candidate_id")
            if candidate_id not in raw_rankings or candidate_id in seen_candidates:
                raise EmbeddingRetrievalComparisonError(f"{where}.candidate_id is unknown or duplicated")
            seen_candidates.append(candidate_id)
            raw_hits = _raw_report_hits(
                ranking["hits"], f"{where}.hits", relevant_ids=relevant_ids, by_id=by_id,
            )
            raw_rankings[candidate_id].append({"case_id": identifier, "hits": raw_hits})
        if seen_candidates != candidate_ids:
            raise EmbeddingRetrievalComparisonError(
                f"{path}.rankings must contain every candidate once, stably sorted"
            )
    if case_ids != sorted(case_ids):
        raise EmbeddingRetrievalComparisonError("$.cases must be stably sorted by case_id")
    required_groups = {
        (category, language) for category in _CATEGORY_TARGETS if category != "unrelated"
        for language in ("en", "vi")
    }
    missing = sorted(required_groups - support_groups)
    if missing:
        raise EmbeddingRetrievalComparisonError(f"$.cases is missing support groups required for Pareto comparison: {missing!r}")
    runs = [
        {**descriptor, "rankings": raw_rankings[descriptor["candidate_id"]]}
        for descriptor in descriptors
    ]
    validate_candidate_runs(runs, set(case_ids), set(by_id))


def _validate_report_seed(root: Mapping[str, Any]) -> None:
    _exact_fields(root, _REPORT_FIELDS, "$")
    if root["schema_version"] != EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION:
        raise EmbeddingRetrievalComparisonError(
            f"$.schema_version must be {EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION!r}"
        )
    _text(root["evaluation_id"], "$.evaluation_id")
    scenario = _text(root["scenario_id"], "$.scenario_id")
    for field, schema, identifier in (
        ("dataset_provenance", RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION, "dataset_id"),
        ("judgments_provenance", RETRIEVAL_JUDGMENTS_SCHEMA_VERSION, "judgment_set_id"),
        ("corpus_provenance", RETRIEVAL_CORPUS_SCHEMA_VERSION, "corpus_id"),
    ):
        _validate_provenance(root[field], path=f"$.{field}", schema=schema, identifier=identifier, scenario=scenario)
    validate_cutoffs(root["cutoffs"])
    baseline = _text(root["baseline_candidate_id"], "$.baseline_candidate_id")
    descriptors = _validate_descriptors(root["candidates"], baseline)
    by_id, by_pointer = _validate_catalog(root["corpus_catalog"])
    _validate_report_cases(root["cases"], descriptors, by_id, by_pointer)


def _require_replay_match(actual: object, expected: object, path: str = "$") -> None:
    """Check every derived object's exact fields and every JSON scalar's type."""
    if isinstance(expected, Mapping):
        supplied = _object(actual, path)
        _exact_fields(supplied, tuple(expected), path)
        for key, child in expected.items():
            _require_replay_match(supplied[key], child, _field_path(path, key))
        return
    if isinstance(expected, list):
        supplied_list = _list(actual, path)
        if len(supplied_list) != len(expected):
            raise EmbeddingRetrievalComparisonError(f"{path} must match recomputed list length {len(expected)}")
        for index, (supplied, child) in enumerate(zip(supplied_list, expected)):
            _require_replay_match(supplied, child, f"{path}[{index}]")
        return
    if _canonical(actual) != _canonical(expected):
        raise EmbeddingRetrievalComparisonError(f"{path} must match its recomputed value")


def validate_embedding_retrieval_comparison_report(report: object) -> None:
    """Replay counts and metrics from validated per-case rankings without mutation.

    The catalog checks enriched hit type/pointer consistency. Report validation
    verifies internal integrity; source bytes are verified by the comparison
    engine when the report is built.
    """
    try:
        root = _object(snapshot_json(report), "$")
        _validate_report_seed(root)
        # The computation helper never invokes this public validator. Importing
        # lazily keeps contract and engine modules separate without recursion.
        from .embedding_retrieval_comparison import _complete_report

        expected = _complete_report(root)
        _require_replay_match(root, expected)
        if _canonical(root) != _canonical(expected):
            raise EmbeddingRetrievalComparisonError("$ must match the complete deterministic report replay")
    except EmbeddingRetrievalComparisonError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise EmbeddingRetrievalComparisonError(f"$ cannot validate comparison report: {exc}") from exc


def serialize_embedding_retrieval_comparison_report(report: object) -> bytes:
    """Validate and return canonical UTF-8 JSON bytes with nonfinite values forbidden."""
    try:
        validate_embedding_retrieval_comparison_report(report)
        return _canonical(snapshot_json(report))
    except EmbeddingRetrievalComparisonError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise EmbeddingRetrievalComparisonError(f"$ cannot serialize comparison report: {exc}") from exc


__all__ = (
    "EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION",
    "EmbeddingRetrievalComparisonError",
    "validate_embedding_retrieval_comparison_report",
    "serialize_embedding_retrieval_comparison_report",
)
