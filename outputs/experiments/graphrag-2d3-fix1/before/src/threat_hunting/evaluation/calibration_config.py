"""Explicit, strict search and execution settings for offline calibration."""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from itertools import product
import json
import math
from pathlib import Path
import re
from typing import Any
import unicodedata

from ..retrieval.schema import CHUNK_SOURCE_OBJECT_TYPES


CALIBRATION_CONFIG_SCHEMA_VERSION = "graphrag-relevance-calibration-config/v1"
SEARCH_FIELDS = (
    "min_hits", "min_mapped_hits", "min_seed_nodes", "min_traversal_nodes",
    "require_traversal", "require_lexical_support", "require_joint_lexical_vector_support",
    "min_cosine_score",
)
COUNT_FIELDS = SEARCH_FIELDS[:4]
BOOLEAN_FIELDS = SEARCH_FIELDS[4:7]
TIE_BREAK_ORDER = (
    "f1_desc", "recall_desc", "specificity_desc", "balanced_accuracy_desc", "policy_id_asc",
)
SELECTION_FIELDS = (
    "max_false_proceed_unrelated", "max_false_proceed_insufficient_evidence",
    "min_recall", "min_f1", "tie_break_order",
)


class CalibrationConfigValidationError(ValueError):
    """Raised when search or execution settings violate their explicit contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CalibrationConfigValidationError(message)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":")).encode("utf-8", errors="strict")


def _snapshot(value: object, path: str = "$", active: set[int] | None = None) -> Any:
    """Detach finite native JSON and enforce answer/status guards recursively."""
    if active is None:
        active = set()
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return value
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        _require(math.isfinite(value), f"{path} must contain finite numbers")
        return value
    _require(isinstance(value, (Mapping, list)), f"{path} must contain native JSON values")
    _require(id(value) not in active, f"{path} contains a cyclic value")
    active.add(id(value))
    try:
        if isinstance(value, Mapping):
            result = {}
            for key, child in value.items():
                _require(isinstance(key, str), f"{path} contains a non-string key")
                key.encode("utf-8", errors="strict")
                normalized = unicodedata.normalize("NFKC", key).casefold().replace("-", "_")
                where = f"{path}.{key}"
                _require(normalized not in {"expected_answer", "reference_answer", "gold_answer", "generated_answer"}, f"{where} is forbidden")
                detached = _snapshot(child, where, active)
                if "status" in normalized or "review" in normalized:
                    _reject_confirmed(detached, where)
                result[key] = detached
            return result
        return [_snapshot(child, f"{path}[{index}]", active) for index, child in enumerate(value)]
    finally:
        active.remove(id(value))


def _reject_confirmed(value: object, path: str) -> None:
    if isinstance(value, str):
        _require(value.strip().casefold() != "confirmed", f"{path} must not contain confirmed status")
    elif isinstance(value, dict):
        for child in value.values():
            _reject_confirmed(child, path)
    elif isinstance(value, list):
        for child in value:
            _reject_confirmed(child, path)


def _json_document(value: object) -> Any:
    try:
        detached = _snapshot(value)
        _canonical(detached)
        return detached
    except CalibrationConfigValidationError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise CalibrationConfigValidationError(f"$ invalid JSON: {exc}") from exc


def _object(value: object, fields: tuple[str, ...], path: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{path} must be an object")
    _require(set(value) == set(fields), f"{path} has missing or unknown fields")
    return value


def _text(value: object, path: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()), f"{path} must be nonempty text")
    return value


def _integer(value: object, path: str, minimum: int = 0, maximum: int | None = None) -> int:
    _require(type(value) is int and value >= minimum, f"{path} must be an integer >= {minimum}, excluding bool")
    _require(maximum is None or value <= maximum, f"{path} exceeds allowed range")
    return value


def _boolean(value: object, path: str) -> bool:
    _require(type(value) is bool, f"{path} must be bool")
    return value


def _bounded_number(value: object, path: str, minimum: float, maximum: float) -> float:
    _require(type(value) in (int, float), f"{path} must be numeric, excluding bool")
    try:
        valid = math.isfinite(value) and minimum <= value <= maximum
    except OverflowError:
        valid = False
    _require(valid, f"{path} must be finite in [{minimum}, {maximum}]")
    return float(value)


def _search_values(search_space: object) -> dict[str, list[Any]]:
    space = _object(_json_document(search_space), SEARCH_FIELDS, "$.candidate_search_space")
    result = {}
    for name in SEARCH_FIELDS:
        items = space[name]
        _require(isinstance(items, list) and bool(items), f"$.candidate_search_space.{name} must be a nonempty list")
        values = {}
        for item in items:
            path = f"$.candidate_search_space.{name}"
            if name in COUNT_FIELDS:
                normalized = _integer(item, path)
            elif name in BOOLEAN_FIELDS:
                normalized = _boolean(item, path)
            else:
                normalized = None if item is None else _bounded_number(item, path, -1, 1)
                if normalized == 0:
                    normalized = 0.0
            values[_canonical(normalized)] = normalized
        result[name] = [values[key] for key in sorted(values)]
    return result


def validate_relevance_policy(policy: object) -> None:
    """Check complete policy shape; decisions remain owned by the existing gate."""
    root = _object(_json_document(policy), ("schema_version", "policy_id", *SEARCH_FIELDS), "$.policy")
    _require(root["schema_version"] == "graphrag-relevance-policy/v1", "$.policy.schema_version mismatch")
    _text(root["policy_id"], "$.policy.policy_id")
    for name in COUNT_FIELDS:
        _integer(root[name], f"$.policy.{name}")
    for name in BOOLEAN_FIELDS:
        _boolean(root[name], f"$.policy.{name}")
    if root["min_cosine_score"] is not None:
        _bounded_number(root["min_cosine_score"], "$.policy.min_cosine_score", -1, 1)


def generate_policy_candidates(search_space: object, *, max_candidate_policies: int) -> list[dict[str, Any]]:
    """Generate the full explicit Cartesian search, deduplicated and canonically sorted.

    Numeric cosine values normalize to float (including signed zero); count and
    bool values retain their strict types. Logically redundant bool combinations
    remain separate explicit policies rather than silently pruning the config.
    """
    cap = _integer(max_candidate_policies, "$.max_candidate_policies", 1)
    values = _search_values(search_space)
    count = math.prod(len(values[name]) for name in SEARCH_FIELDS)
    _require(count <= cap, "$.candidate_search_space exceeds max_candidate_policies")
    candidates = []
    for combination in product(*(values[name] for name in SEARCH_FIELDS)):
        body = {"schema_version": "graphrag-relevance-policy/v1", **dict(zip(SEARCH_FIELDS, combination, strict=True))}
        policy = {**body, "policy_id": "calibration-policy-" + sha256(_canonical(body)).hexdigest()}
        candidates.append(policy)
    return sorted(candidates, key=_canonical)


def validate_selection_constraints(value: object) -> None:
    root = _object(_json_document(value), SELECTION_FIELDS, "$.selection_constraints")
    for name in SELECTION_FIELDS[:2]:
        _integer(root[name], f"$.selection_constraints.{name}")
    for name in ("min_recall", "min_f1"):
        _bounded_number(root[name], f"$.selection_constraints.{name}", 0, 1)
    _require(root["tie_break_order"] == list(TIE_BREAK_ORDER), "$.selection_constraints.tie_break_order must declare the required deterministic order")


def _optional_strings(value: object, path: str, *, vocabulary: set[str] | None = None) -> None:
    if value is None:
        return
    _require(isinstance(value, list), f"{path} must be a list or null")
    for item in value:
        _text(item, path)
    _require(len(set(value)) == len(value), f"{path} contains duplicates")
    if vocabulary is not None:
        _require(set(value).issubset(vocabulary), f"{path} contains unsupported values")


def validate_execution_settings(retrieval: object, traversal: object, embedding_runtime: object) -> None:
    retrieval = _object(_json_document(retrieval), ("top_k", "candidate_k", "chunk_types", "required_dimensions"), "$.retrieval")
    top = _integer(retrieval["top_k"], "$.retrieval.top_k", 1)
    _integer(retrieval["candidate_k"], "$.retrieval.candidate_k", top)
    _optional_strings(retrieval["chunk_types"], "$.retrieval.chunk_types", vocabulary=set(CHUNK_SOURCE_OBJECT_TYPES))
    _optional_strings(retrieval["required_dimensions"], "$.retrieval.required_dimensions")
    traversal = _object(_json_document(traversal), ("direction", "max_depth", "allowed_edge_types", "max_nodes", "max_edges"), "$.traversal")
    _require(traversal["direction"] in ("outgoing", "incoming", "both"), "$.traversal.direction unsupported")
    _integer(traversal["max_depth"], "$.traversal.max_depth", 0, 64)
    _integer(traversal["max_nodes"], "$.traversal.max_nodes", 1)
    _integer(traversal["max_edges"], "$.traversal.max_edges", 1)
    _optional_strings(traversal["allowed_edge_types"], "$.traversal.allowed_edge_types")
    if traversal["allowed_edge_types"] is not None:
        _require(all(re.fullmatch(r"[a-z][a-z0-9_]*", item) for item in traversal["allowed_edge_types"]), "$.traversal.allowed_edge_types must be normalized identifiers")
    runtime = _object(_json_document(embedding_runtime), ("device", "batch_size", "show_progress_bar", "offline"), "$.embedding_runtime")
    _require(runtime["device"] == "cpu", "$.embedding_runtime.device must be cpu")
    _integer(runtime["batch_size"], "$.embedding_runtime.batch_size", 1)
    _boolean(runtime["show_progress_bar"], "$.embedding_runtime.show_progress_bar")
    _require(_boolean(runtime["offline"], "$.embedding_runtime.offline") is True, "$.embedding_runtime.offline must be true")


def validate_calibration_config(document: object) -> None:
    root = _object(_json_document(document), (
        "schema_version", "calibration_id", "expected_case_count", "candidate_search_space",
        "selection_constraints", "retrieval", "traversal", "embedding_runtime", "max_candidate_policies",
    ), "$")
    _require(root["schema_version"] == CALIBRATION_CONFIG_SCHEMA_VERSION, "$.schema_version mismatch")
    _text(root["calibration_id"], "$.calibration_id")
    _integer(root["expected_case_count"], "$.expected_case_count", 1)
    generate_policy_candidates(root["candidate_search_space"], max_candidate_policies=root["max_candidate_policies"])
    validate_selection_constraints(root["selection_constraints"])
    validate_execution_settings(root["retrieval"], root["traversal"], root["embedding_runtime"])


class _Pairs(list):
    pass


class _Nonfinite:
    def __init__(self, value: str) -> None:
        self.value = value


def _materialize(value: object, path: str) -> Any:
    if isinstance(value, _Nonfinite):
        raise CalibrationConfigValidationError(f"{path} contains non-standard number {value.value}")
    if isinstance(value, _Pairs):
        result = {}
        for key, item in value:
            child_path = f"{path}.{key}"
            _require(key not in result, f"{child_path} contains duplicate JSON key")
            result[key] = _materialize(item, child_path)
        return result
    if isinstance(value, list):
        return [_materialize(item, f"{path}[{index}]") for index, item in enumerate(value)]
    return value


def _load_json(path: Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        parsed = json.load(handle, object_pairs_hook=_Pairs, parse_constant=_Nonfinite)
    return _materialize(parsed, "$")


def load_calibration_config(path: Path) -> dict[str, Any]:
    try:
        document = _load_json(path)
        validate_calibration_config(document)
        return document
    except (OSError, ValueError, UnicodeError, RecursionError, TypeError, OverflowError) as exc:
        raise CalibrationConfigValidationError(f"Cannot load calibration config {path} at $: {exc}") from exc


__all__ = (
    "CALIBRATION_CONFIG_SCHEMA_VERSION", "CalibrationConfigValidationError",
    "generate_policy_candidates", "validate_calibration_config", "load_calibration_config",
    "validate_selection_constraints", "validate_execution_settings", "validate_relevance_policy",
)
