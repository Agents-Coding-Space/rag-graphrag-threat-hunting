from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any

import pytest


REPOSITORY_ROOT = Path(__file__).parents[1]
CONFIG_PATH = (
    REPOSITORY_ROOT
    / "configs"
    / "evaluation"
    / "mshta_multilingual_e5_vector_index.json"
)
PINNED_REVISION = "614241f622f53c4eeff9890bdc4f31cfecc418b3"

SPEC = importlib.util.spec_from_file_location(
    "testable_multilingual_e5_build_config",
    REPOSITORY_ROOT / "scripts" / "build_vector_index.py",
)
assert SPEC is not None and SPEC.loader is not None
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)


@pytest.fixture
def config_document() -> dict[str, Any]:
    document = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _write_config(tmp_path: Path, document: dict[str, Any]) -> Path:
    path = tmp_path / "candidate_config.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_candidate_loads_with_existing_strict_utf8_loader(
    config_document: dict[str, Any],
) -> None:
    loaded = cli.load_build_config(CONFIG_PATH)

    assert loaded == config_document
    assert loaded["schema_version"] == cli.CONFIG_SCHEMA_VERSION
    assert loaded["schema_version"] == "vector-index-build-config/v1"


def test_top_level_fields_match_existing_config_contract(
    config_document: dict[str, Any],
) -> None:
    assert set(config_document) == set(cli.CONFIG_FIELDS)
    assert set(config_document) == {"schema_version", "embedding", "runtime"}


def test_artifact_paths_and_hash_are_absent_from_config(
    config_document: dict[str, Any],
) -> None:
    for section in (
        config_document,
        config_document["embedding"],
        config_document["runtime"],
    ):
        assert {"corpus_path", "corpus_sha256", "output_path"}.isdisjoint(section)


def test_embedding_fields_match_existing_descriptor_contract(
    config_document: dict[str, Any],
) -> None:
    assert set(config_document["embedding"]) == set(cli.EMBEDDING_FIELDS)


def test_provider_and_model_id_use_reviewed_evaluation_candidate(
    config_document: dict[str, Any],
) -> None:
    embedding = config_document["embedding"]

    assert embedding["provider"] == "sentence-transformers"
    assert embedding["model_id"] == "intfloat/multilingual-e5-small"


def test_revision_is_the_exact_verified_immutable_commit(
    config_document: dict[str, Any],
) -> None:
    revision = config_document["embedding"]["model_revision"]

    assert revision == PINNED_REVISION
    assert re.fullmatch(r"[0-9a-f]{40}", revision) is not None
    assert revision not in {"main", "master", "latest", "HEAD"}


def test_dimension_is_384_and_is_not_boolean(
    config_document: dict[str, Any],
) -> None:
    dimension = config_document["embedding"]["dimension"]

    assert type(dimension) is int
    assert dimension == 384


def test_distance_metric_is_cosine(config_document: dict[str, Any]) -> None:
    assert config_document["embedding"]["distance_metric"] == "cosine"


def test_normalization_is_l2(config_document: dict[str, Any]) -> None:
    assert config_document["embedding"]["normalization"] == "l2"


@pytest.mark.parametrize(
    ("field", "expected"),
    [("document_prefix", "passage: "), ("query_prefix", "query: ")],
)
def test_e5_prefixes_preserve_the_required_trailing_space(
    field: str,
    expected: str,
    config_document: dict[str, Any],
) -> None:
    assert config_document["embedding"][field] == expected


def test_runtime_uses_cpu_batch_32_without_progress(
    config_document: dict[str, Any],
) -> None:
    runtime = config_document["runtime"]

    assert set(runtime) == set(cli.RUNTIME_FIELDS)
    assert runtime == {
        "device": "cpu",
        "batch_size": 32,
        "show_progress_bar": False,
    }
    assert type(runtime["batch_size"]) is int
    assert runtime["show_progress_bar"] is False


def test_config_contains_no_credentials_or_cache_location() -> None:
    serialized = CONFIG_PATH.read_text(encoding="utf-8").casefold()

    for forbidden in ("token", "credential", "secret", "cache", "api_key"):
        assert forbidden not in serialized


def test_config_contains_no_confirmed_status() -> None:
    assert "confirmed" not in CONFIG_PATH.read_text(encoding="utf-8").casefold()


def test_config_is_representable_as_finite_standard_json(
    config_document: dict[str, Any],
) -> None:
    serialized = json.dumps(config_document, allow_nan=False, sort_keys=True)

    assert json.loads(serialized) == cli._validate_build_config(config_document)


def test_loader_preserves_config_bytes_and_is_deterministic() -> None:
    original_bytes = CONFIG_PATH.read_bytes()

    first = cli.load_build_config(CONFIG_PATH)
    second = cli.load_build_config(CONFIG_PATH)

    assert first == second
    assert CONFIG_PATH.read_bytes() == original_bytes


def test_validator_does_not_mutate_input_when_normalizing_revision(
    config_document: dict[str, Any],
) -> None:
    config_document["embedding"]["model_revision"] = PINNED_REVISION.upper()
    original = deepcopy(config_document)

    validated = cli._validate_build_config(config_document)

    assert config_document == original
    assert validated["embedding"]["model_revision"] == PINNED_REVISION
    validated["embedding"]["query_prefix"] = "changed: "
    validated["runtime"]["batch_size"] = 1
    assert config_document == original


@pytest.mark.parametrize("field", ["corpus_path", "corpus_sha256", "output_path"])
def test_existing_loader_rejects_artifact_fields_in_config(
    field: str,
    config_document: dict[str, Any],
    tmp_path: Path,
) -> None:
    config_document[field] = "must remain a CLI argument"

    with pytest.raises(cli.VectorIndexCliError, match="unexpected"):
        cli.load_build_config(_write_config(tmp_path, config_document))


@pytest.mark.parametrize("field", ["schema_version", "model_id", "batch_size"])
def test_strict_loader_rejects_duplicate_keys_in_each_config_section(
    field: str,
    tmp_path: Path,
) -> None:
    original_bytes = CONFIG_PATH.read_bytes()
    original_text = original_bytes.decode("utf-8")
    duplicated = original_text.replace(
        f'"{field}":', f'"{field}": null, "{field}":', 1
    )
    assert duplicated != original_text
    path = tmp_path / "duplicate_config.json"
    path.write_text(duplicated, encoding="utf-8")

    with pytest.raises(cli.VectorIndexCliError, match="duplicate JSON object key"):
        cli.load_build_config(path)

    assert CONFIG_PATH.read_bytes() == original_bytes


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_strict_loader_rejects_nonfinite_json_numbers(
    value: float,
    config_document: dict[str, Any],
    tmp_path: Path,
) -> None:
    config_document["embedding"]["dimension"] = value

    with pytest.raises(cli.VectorIndexCliError, match="non-standard JSON number"):
        cli.load_build_config(_write_config(tmp_path, config_document))


@pytest.mark.parametrize("value", [True, False])
def test_existing_validator_rejects_boolean_dimension(
    value: bool,
    config_document: dict[str, Any],
) -> None:
    config_document["embedding"]["dimension"] = value

    with pytest.raises(cli.VectorIndexCliError, match="dimension"):
        cli._validate_build_config(config_document)


@pytest.mark.parametrize("revision", ["main", "latest", "614241f", "g" * 40])
def test_existing_loader_rejects_floating_short_or_nonhex_revision(
    revision: str,
    config_document: dict[str, Any],
    tmp_path: Path,
) -> None:
    config_document["embedding"]["model_revision"] = revision

    with pytest.raises(cli.VectorIndexCliError, match="40-character"):
        cli.load_build_config(_write_config(tmp_path, config_document))
