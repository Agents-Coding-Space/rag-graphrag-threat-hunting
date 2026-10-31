"""Evaluation-only E5 calibration settings reuse the reviewed MiniLM search."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

import pytest

from threat_hunting.evaluation.calibration_config import (
    CALIBRATION_CONFIG_SCHEMA_VERSION,
    CalibrationConfigValidationError,
    generate_policy_candidates,
    load_calibration_config,
    validate_calibration_config,
    validate_relevance_policy,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "configs/evaluation/mshta_e5_relevance_calibration.json"
MINILM_CONFIG_PATH = ROOT / "configs/evaluation/mshta_relevance_calibration.json"


@pytest.fixture
def config_document() -> dict[str, Any]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def minilm_document() -> dict[str, Any]:
    return json.loads(MINILM_CONFIG_PATH.read_text(encoding="utf-8"))


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _walk(value: object) -> Iterator[object]:
    yield value
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield key
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _candidates(document: dict[str, Any]) -> list[dict[str, Any]]:
    return generate_policy_candidates(
        document["candidate_search_space"],
        max_candidate_policies=document["max_candidate_policies"],
    )


def test_config_is_strict_utf8_and_finite_standard_json(
    config_document: dict[str, Any],
) -> None:
    original_bytes = CONFIG_PATH.read_bytes()
    text = original_bytes.decode("utf-8", errors="strict")

    assert not original_bytes.startswith(b"\xef\xbb\xbf")
    assert text.encode("utf-8", errors="strict") == original_bytes
    assert json.loads(_canonical_bytes(config_document)) == config_document


@pytest.mark.parametrize(
    "prefix", [b"\xff", b"\xef\xbb\xbf"], ids=["invalid-utf8", "utf8-bom"]
)
def test_existing_loader_rejects_invalid_encoding_or_bom(
    prefix: bytes, tmp_path: Path
) -> None:
    path = tmp_path / "invalid_encoding_config.json"
    path.write_bytes(prefix + CONFIG_PATH.read_bytes())

    with pytest.raises(CalibrationConfigValidationError, match=path.name):
        load_calibration_config(path)


@pytest.mark.parametrize(
    "field",
    ["calibration_id", "min_hits", "min_recall", "top_k", "direction", "offline"],
)
def test_existing_loader_rejects_duplicate_keys_in_every_section(
    field: str, tmp_path: Path
) -> None:
    original_bytes = CONFIG_PATH.read_bytes()
    text = original_bytes.decode("utf-8", errors="strict")
    duplicate = text.replace(f'"{field}":', f'"{field}": null, "{field}":', 1)
    assert duplicate != text
    path = tmp_path / "duplicate_config.json"
    path.write_text(duplicate, encoding="utf-8")

    with pytest.raises(CalibrationConfigValidationError, match="duplicate JSON key"):
        load_calibration_config(path)

    assert CONFIG_PATH.read_bytes() == original_bytes


@pytest.mark.parametrize(
    "number", [float("nan"), float("inf"), float("-inf")], ids=["nan", "inf", "-inf"]
)
def test_existing_loader_rejects_nonstandard_json_numbers(
    number: float, config_document: dict[str, Any], tmp_path: Path
) -> None:
    config_document["candidate_search_space"]["min_cosine_score"] = [number]
    path = tmp_path / "nonstandard_number_config.json"
    path.write_text(json.dumps(config_document), encoding="utf-8")

    with pytest.raises(CalibrationConfigValidationError, match="non-standard number"):
        load_calibration_config(path)


def test_config_passes_existing_loader_and_validator(
    config_document: dict[str, Any],
) -> None:
    loaded = load_calibration_config(CONFIG_PATH)

    validate_calibration_config(loaded)
    assert loaded == config_document
    assert loaded["schema_version"] == CALIBRATION_CONFIG_SCHEMA_VERSION
    assert loaded["schema_version"] == "graphrag-relevance-calibration-config/v1"


def test_config_generates_exactly_672_unique_valid_policy_candidates(
    config_document: dict[str, Any],
) -> None:
    candidates = _candidates(config_document)

    assert config_document["max_candidate_policies"] == 1000
    assert len(candidates) == 672
    assert len({candidate["policy_id"] for candidate in candidates}) == 672
    for candidate in candidates:
        validate_relevance_policy(candidate)


def test_search_space_matches_minilm_without_additional_cosine_thresholds(
    config_document: dict[str, Any], minilm_document: dict[str, Any]
) -> None:
    search_space = config_document["candidate_search_space"]

    assert search_space == minilm_document["candidate_search_space"]
    assert search_space == {
        "min_hits": [1, 5],
        "min_mapped_hits": [1, 3],
        "min_seed_nodes": [1, 3],
        "min_traversal_nodes": [0, 3, 5],
        "require_traversal": [True],
        "require_lexical_support": [False, True],
        "require_joint_lexical_vector_support": [False, True],
        "min_cosine_score": [None, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45],
    }


def test_selection_constraints_match_minilm_without_relaxation(
    config_document: dict[str, Any], minilm_document: dict[str, Any]
) -> None:
    constraints = config_document["selection_constraints"]

    assert constraints == minilm_document["selection_constraints"]
    assert constraints == {
        "max_false_proceed_unrelated": 0,
        "max_false_proceed_insufficient_evidence": 0,
        "min_recall": 0.75,
        "min_f1": 0.75,
        "tie_break_order": [
            "f1_desc", "recall_desc", "specificity_desc",
            "balanced_accuracy_desc", "policy_id_asc",
        ],
    }


def test_only_calibration_id_differs_from_minilm_config(
    config_document: dict[str, Any], minilm_document: dict[str, Any]
) -> None:
    assert config_document.keys() == minilm_document.keys()
    assert {
        key for key in config_document if config_document[key] != minilm_document[key]
    } == {"calibration_id"}
    assert config_document["calibration_id"] == "mshta-e5-relevance-calibration-grid-v1"
    assert minilm_document["calibration_id"] == "mshta-relevance-calibration-grid-v1"


def test_expected_case_count_remains_32(config_document: dict[str, Any]) -> None:
    assert type(config_document["expected_case_count"]) is int
    assert config_document["expected_case_count"] == 32


def test_retrieval_keeps_top_5_and_20_candidates(
    config_document: dict[str, Any],
) -> None:
    assert config_document["retrieval"] == {
        "top_k": 5,
        "candidate_k": 20,
        "chunk_types": None,
        "required_dimensions": None,
    }


def test_runtime_is_offline_cpu_with_batch_1_and_no_progress(
    config_document: dict[str, Any],
) -> None:
    runtime = config_document["embedding_runtime"]

    assert runtime == {
        "device": "cpu", "batch_size": 1,
        "show_progress_bar": False, "offline": True,
    }
    assert type(runtime["batch_size"]) is int
    assert runtime["show_progress_bar"] is False
    assert runtime["offline"] is True


def test_config_contains_no_artifact_paths_or_cache_locations(
    config_document: dict[str, Any],
) -> None:
    strings = [value for value in _walk(config_document) if isinstance(value, str)]

    for value in strings:
        normalized = value.casefold().replace("\\", "/")
        assert not normalized.endswith(("_path", "_dir", "_sha256", ".json", ".zip"))
        assert not any(marker in normalized for marker in ("outputs/", "cache_dir", "file://"))
        assert re.search(r"(?:^|\s)[a-z]:/", normalized) is None
        assert not normalized.startswith(("/", "../", "./", "~/"))


def test_config_does_not_hardcode_a_model_descriptor(
    config_document: dict[str, Any],
) -> None:
    strings = {value.casefold() for value in _walk(config_document) if isinstance(value, str)}

    assert strings.isdisjoint({
        "model_id", "model_revision", "provider", "embedding", "dimension",
        "document_prefix", "query_prefix", "normalization", "distance_metric",
    })
    assert not any(
        marker in value
        for value in strings
        for marker in ("intfloat/", "sentence-transformers/", "all-minilm-l6-v2")
    )
    assert not any(re.fullmatch(r"[0-9a-f]{40}", value) for value in strings)


def test_config_contains_no_confirmed_status(config_document: dict[str, Any]) -> None:
    assert "confirmed" not in _canonical_bytes(config_document).decode("utf-8").casefold()


def test_config_contains_no_expected_answers_or_case_labels(
    config_document: dict[str, Any],
) -> None:
    strings = {
        value.casefold().replace("-", "_")
        for value in _walk(config_document)
        if isinstance(value, str)
    }

    assert strings.isdisjoint({
        "expected_answer", "expected_answers", "reference_answer", "gold_answer",
        "generated_answer", "answer", "answers", "cases", "query", "question",
        "expected_decision", "relevant_direct", "relevant_paraphrase",
        "insufficient_evidence", "unrelated",
    })


def test_loading_validation_and_generation_preserve_config_and_source_bytes(
    config_document: dict[str, Any],
) -> None:
    original = deepcopy(config_document)
    source_bytes = {path: path.read_bytes() for path in (CONFIG_PATH, MINILM_CONFIG_PATH)}
    loaded = load_calibration_config(CONFIG_PATH)

    validate_calibration_config(config_document)
    candidates = _candidates(config_document)
    assert loaded == original
    assert config_document == original

    loaded["candidate_search_space"]["min_hits"][0] = 999
    candidates[0]["min_hits"] = 999
    assert config_document == original
    assert load_calibration_config(CONFIG_PATH) == original
    assert {path: path.read_bytes() for path in source_bytes} == source_bytes


def test_candidate_generation_is_stable_across_reloads_and_search_order(
    config_document: dict[str, Any], minilm_document: dict[str, Any]
) -> None:
    first = _candidates(config_document)
    reordered = deepcopy(config_document)
    reordered["candidate_search_space"] = {
        field: list(reversed(values))
        for field, values in reversed(list(reordered["candidate_search_space"].items()))
    }

    assert first == _candidates(load_calibration_config(CONFIG_PATH))
    assert first == _candidates(reordered)
    assert first == _candidates(minilm_document)
    serialized = [_canonical_bytes(candidate) for candidate in first]
    assert serialized == sorted(serialized)
    for candidate in first:
        body = {key: value for key, value in candidate.items() if key != "policy_id"}
        assert candidate["policy_id"] == "calibration-policy-" + sha256(_canonical_bytes(body)).hexdigest()
