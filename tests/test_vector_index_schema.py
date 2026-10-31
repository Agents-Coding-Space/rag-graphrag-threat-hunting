from __future__ import annotations

from copy import deepcopy
import inspect
import json
import math
from pathlib import Path
from typing import Any

import pytest

import threat_hunting.retrieval as retrieval
from threat_hunting.retrieval import (
    VECTOR_INDEX_SCHEMA_VERSION,
    VectorIndexValidationError,
    load_vector_index,
    validate_vector_index,
)
from threat_hunting.retrieval import vector_schema


FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "retrieval"
    / "vector_index_minimal.json"
)
ALLOWED_CHUNK_TYPES = {
    "scenario_summary",
    "entity",
    "fact",
    "relationship",
    "evidence",
    "sigma_finding",
    "mitre_assessment",
    "limitation",
}


def _document() -> dict[str, Any]:
    value = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _walk_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.add(key)
            keys.update(_walk_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            keys.update(_walk_keys(nested))
    return keys


def test_schema_version_and_package_exports_are_stable() -> None:
    assert VECTOR_INDEX_SCHEMA_VERSION == "vector-index/v1"
    assert vector_schema.__all__ == (
        "VECTOR_INDEX_SCHEMA_VERSION",
        "VectorIndexValidationError",
        "load_vector_index",
        "validate_vector_index",
    )
    for name in vector_schema.__all__:
        assert getattr(retrieval, name) is getattr(vector_schema, name)
        assert name in retrieval.__all__


def test_minimal_fixture_is_valid_and_has_three_record_types() -> None:
    document = _document()

    validate_vector_index(document)

    assert document["metadata"]["record_count"] == 3
    assert {record["chunk_type"] for record in document["records"]} == {
        "scenario_summary",
        "entity",
        "evidence",
    }


def test_validator_does_not_mutate_input() -> None:
    document = _document()
    before = deepcopy(document)

    validate_vector_index(document)

    assert document == before


def test_loader_reads_fixture_without_normalizing_content() -> None:
    assert load_vector_index(FIXTURE_PATH) == _document()


@pytest.mark.parametrize("location", ("top_level", "nested"))
def test_loader_rejects_duplicate_json_keys_at_every_level(
    tmp_path: Path,
    location: str,
) -> None:
    text = FIXTURE_PATH.read_text(encoding="utf-8")
    if location == "top_level":
        text = text.replace(
            '"schema_version": "vector-index/v1",',
            '"schema_version": "vector-index/v1",\n'
            '  "schema_version": "vector-index/v1",',
            1,
        )
    else:
        text = text.replace(
            '"provider": "synthetic-provider",',
            '"provider": "synthetic-provider",\n'
            '    "provider": "synthetic-provider",',
            1,
        )
    path = tmp_path / f"duplicate-{location}.json"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(VectorIndexValidationError) as exc_info:
        load_vector_index(path)

    assert "duplicate JSON object key" in str(exc_info.value)
    assert str(path) in str(exc_info.value)


def test_loader_rejects_malformed_json_with_filename(tmp_path: Path) -> None:
    path = tmp_path / "malformed.json"
    path.write_text('{"schema_version":', encoding="utf-8")

    with pytest.raises(VectorIndexValidationError) as exc_info:
        load_vector_index(path)

    assert str(path) in str(exc_info.value)


def test_loader_rejects_non_object_root_with_filename(tmp_path: Path) -> None:
    path = tmp_path / "array.json"
    path.write_text("[]\n", encoding="utf-8")

    with pytest.raises(VectorIndexValidationError) as exc_info:
        load_vector_index(path)

    assert "must be a JSON object" in str(exc_info.value)
    assert str(path) in str(exc_info.value)


def test_loader_rejects_utf8_bom(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + FIXTURE_PATH.read_bytes())

    with pytest.raises(VectorIndexValidationError) as exc_info:
        load_vector_index(path)

    assert str(path) in str(exc_info.value)


@pytest.mark.parametrize("mode", ("missing", "unexpected"))
def test_top_level_field_set_is_strict(mode: str) -> None:
    document = _document()
    if mode == "missing":
        del document["warnings"]
    else:
        document["extra"] = None

    with pytest.raises(VectorIndexValidationError, match=mode):
        validate_vector_index(document)


def test_wrong_schema_version_is_rejected() -> None:
    document = _document()
    document["schema_version"] = "vector-index/v999"

    with pytest.raises(VectorIndexValidationError, match="schema_version"):
        validate_vector_index(document)


@pytest.mark.parametrize("value", ("", "   ", None))
def test_index_id_must_be_a_nonempty_string(value: object) -> None:
    document = _document()
    document["index_id"] = value

    with pytest.raises(VectorIndexValidationError, match="index_id"):
        validate_vector_index(document)


@pytest.mark.parametrize("mode", ("missing", "unexpected"))
def test_corpus_provenance_field_set_is_strict(mode: str) -> None:
    document = _document()
    if mode == "missing":
        del document["corpus_provenance"]["corpus_id"]
    else:
        document["corpus_provenance"]["extra"] = "value"

    with pytest.raises(VectorIndexValidationError, match=mode):
        validate_vector_index(document)


def test_corpus_provenance_schema_version_is_fixed() -> None:
    document = _document()
    document["corpus_provenance"]["schema_version"] = "retrieval-corpus/v2"

    with pytest.raises(VectorIndexValidationError, match="retrieval-corpus/v1"):
        validate_vector_index(document)


@pytest.mark.parametrize("field", ("path", "corpus_id", "scenario_id"))
def test_corpus_provenance_identifiers_are_nonempty(field: str) -> None:
    document = _document()
    document["corpus_provenance"][field] = " "

    with pytest.raises(VectorIndexValidationError, match=field):
        validate_vector_index(document)


@pytest.mark.parametrize(
    "digest",
    ("a" * 63, "a" * 65, "g" * 64, ""),
)
@pytest.mark.parametrize("location", ("corpus", "record"))
def test_sha256_fields_require_exact_hex(location: str, digest: str) -> None:
    document = _document()
    if location == "corpus":
        document["corpus_provenance"]["sha256"] = digest
    else:
        document["records"][0]["content_sha256"] = digest

    with pytest.raises(VectorIndexValidationError, match="sha256"):
        validate_vector_index(document)


@pytest.mark.parametrize("mode", ("missing", "unexpected"))
def test_embedding_field_set_is_strict(mode: str) -> None:
    document = _document()
    if mode == "missing":
        del document["embedding"]["model_revision"]
    else:
        document["embedding"]["credential"] = "not-allowed"

    with pytest.raises(VectorIndexValidationError, match=mode):
        validate_vector_index(document)


@pytest.mark.parametrize("field", ("provider", "model_id", "model_revision"))
@pytest.mark.parametrize("value", ("", "   "))
def test_embedding_identity_fields_are_nonempty(field: str, value: str) -> None:
    document = _document()
    document["embedding"][field] = value

    with pytest.raises(VectorIndexValidationError, match=field):
        validate_vector_index(document)


def test_embedding_provider_and_model_are_runtime_configurable() -> None:
    document = _document()
    document["embedding"].update(
        {
            "provider": "runtime-provider-x",
            "model_id": "runtime/model-x",
            "model_revision": "revision-x",
        }
    )

    validate_vector_index(document)


@pytest.mark.parametrize("dimension", (0, -1, 1.5, "4", True))
def test_embedding_dimension_must_be_a_positive_integer(dimension: object) -> None:
    document = _document()
    document["embedding"]["dimension"] = dimension

    with pytest.raises(VectorIndexValidationError, match="positive integer"):
        validate_vector_index(document)


def test_unsupported_distance_metric_is_rejected() -> None:
    document = _document()
    document["embedding"]["distance_metric"] = "euclidean"

    with pytest.raises(VectorIndexValidationError, match="distance_metric"):
        validate_vector_index(document)


def test_unsupported_normalization_is_rejected() -> None:
    document = _document()
    document["embedding"]["normalization"] = "unit"

    with pytest.raises(VectorIndexValidationError, match="normalization"):
        validate_vector_index(document)


@pytest.mark.parametrize("field", ("document_prefix", "query_prefix"))
def test_embedding_prefix_must_be_a_string_but_may_be_empty(field: str) -> None:
    document = _document()
    document["embedding"][field] = ""
    validate_vector_index(document)

    document["embedding"][field] = None
    with pytest.raises(VectorIndexValidationError, match=field):
        validate_vector_index(document)


@pytest.mark.parametrize("mode", ("missing", "unexpected"))
def test_vector_record_field_set_is_strict(mode: str) -> None:
    document = _document()
    if mode == "missing":
        del document["records"][0]["content_sha256"]
    else:
        document["records"][0]["extra"] = "value"

    with pytest.raises(VectorIndexValidationError, match=mode):
        validate_vector_index(document)


def test_records_must_be_a_json_array() -> None:
    document = _document()
    document["records"] = {}

    with pytest.raises(VectorIndexValidationError, match="must be a list"):
        validate_vector_index(document)


def test_duplicate_chunk_id_is_rejected() -> None:
    document = _document()
    document["records"][1]["chunk_id"] = document["records"][0]["chunk_id"]

    with pytest.raises(VectorIndexValidationError, match="Duplicate chunk_id"):
        validate_vector_index(document)


@pytest.mark.parametrize("chunk_type", sorted(ALLOWED_CHUNK_TYPES))
def test_all_retrieval_corpus_chunk_types_are_supported(chunk_type: str) -> None:
    document = _document()
    document["records"][0]["chunk_type"] = chunk_type

    validate_vector_index(document)


def test_unsupported_chunk_type_is_rejected() -> None:
    document = _document()
    document["records"][0]["chunk_type"] = "runtime_specific_type"

    with pytest.raises(VectorIndexValidationError, match="chunk_type"):
        validate_vector_index(document)


def test_vector_dimension_must_match_embedding_dimension() -> None:
    document = _document()
    document["records"][0]["vector"] = [1.0, 0.0, 0.0]

    with pytest.raises(VectorIndexValidationError, match="exactly 4"):
        validate_vector_index(document)


def test_vector_must_not_be_empty() -> None:
    document = _document()
    document["embedding"]["dimension"] = 1
    document["metadata"]["vector_dimension"] = 1
    document["records"][0]["vector"] = []

    with pytest.raises(VectorIndexValidationError, match="must not be empty"):
        validate_vector_index(document)


@pytest.mark.parametrize("value", (math.nan, math.inf, -math.inf))
def test_validator_rejects_nonfinite_vector_values(value: float) -> None:
    document = _document()
    document["records"][0]["vector"][0] = value

    with pytest.raises(VectorIndexValidationError, match="finite"):
        validate_vector_index(document)


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_loader_rejects_nonstandard_vector_numbers(
    tmp_path: Path,
    constant: str,
) -> None:
    text = FIXTURE_PATH.read_text(encoding="utf-8")
    text = text.replace("1.0,", f"{constant},", 1)
    path = tmp_path / f"nonfinite-{constant}.json"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(VectorIndexValidationError) as exc_info:
        load_vector_index(path)

    assert "non-standard JSON number" in str(exc_info.value)
    assert str(path) in str(exc_info.value)


@pytest.mark.parametrize("value", ("1.0", None, True, False))
def test_vector_rejects_non_numeric_values(value: object) -> None:
    document = _document()
    document["records"][0]["vector"][0] = value

    with pytest.raises(VectorIndexValidationError, match="finite JSON number"):
        validate_vector_index(document)


def test_l2_normalization_rejects_zero_vector() -> None:
    document = _document()
    document["records"][0]["vector"] = [0, 0, 0, 0]

    with pytest.raises(VectorIndexValidationError, match="zero vector"):
        validate_vector_index(document)


def test_l2_normalization_rejects_non_unit_vector() -> None:
    document = _document()
    document["records"][0]["vector"] = [0.5, 0.0, 0.0, 0.0]

    with pytest.raises(VectorIndexValidationError, match="L2 norm 1"):
        validate_vector_index(document)


def test_l2_norm_within_tolerance_is_accepted() -> None:
    document = _document()
    document["records"][0]["vector"] = [1.0000005, 0.0, 0.0, 0.0]

    validate_vector_index(document)


def test_zero_vector_is_allowed_without_normalization() -> None:
    document = _document()
    document["embedding"]["normalization"] = "none"
    document["records"][0]["vector"] = [0, 0, 0, 0]

    validate_vector_index(document)


@pytest.mark.parametrize("value", (0, 2, -1, 1.5, "3", True))
def test_record_count_must_match_records(value: object) -> None:
    document = _document()
    document["metadata"]["record_count"] = value

    with pytest.raises(VectorIndexValidationError, match="record_count"):
        validate_vector_index(document)


@pytest.mark.parametrize("value", (0, 3, -1, 4.0, "4", True))
def test_vector_dimension_metadata_must_match_embedding(value: object) -> None:
    document = _document()
    document["metadata"]["vector_dimension"] = value

    with pytest.raises(VectorIndexValidationError, match="vector_dimension"):
        validate_vector_index(document)


@pytest.mark.parametrize("value", (0, 1, "false", None))
def test_complete_corpus_coverage_must_be_boolean(value: object) -> None:
    document = _document()
    document["metadata"]["complete_corpus_coverage"] = value

    with pytest.raises(VectorIndexValidationError, match="boolean"):
        validate_vector_index(document)


@pytest.mark.parametrize("mode", ("missing", "unexpected"))
def test_metadata_field_set_is_strict(mode: str) -> None:
    document = _document()
    if mode == "missing":
        del document["metadata"]["record_count"]
    else:
        document["metadata"]["extra"] = False

    with pytest.raises(VectorIndexValidationError, match=mode):
        validate_vector_index(document)


@pytest.mark.parametrize("mode", ("missing", "unexpected"))
def test_review_field_set_is_strict(mode: str) -> None:
    document = _document()
    if mode == "missing":
        del document["review"]["notes"]
    else:
        document["review"]["extra"] = None

    with pytest.raises(VectorIndexValidationError, match=mode):
        validate_vector_index(document)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("review_status", "approved"),
        ("reviewer", "analyst"),
        ("reviewed_at", "2026-01-01T00:00:00Z"),
    ),
)
def test_review_contract_remains_pending_and_unreviewed(
    field: str,
    value: str,
) -> None:
    document = _document()
    document["review"][field] = value

    with pytest.raises(VectorIndexValidationError, match=field):
        validate_vector_index(document)


@pytest.mark.parametrize("field", ("warnings", "notes"))
@pytest.mark.parametrize("mode", ("empty", "duplicate"))
def test_warning_and_note_entries_are_nonempty_and_unique(
    field: str,
    mode: str,
) -> None:
    document = _document()
    target = document["warnings"] if field == "warnings" else document["review"]["notes"]
    target[:] = ["first"]
    if mode == "empty":
        target[0] = " "
    else:
        target.append("first")

    with pytest.raises(VectorIndexValidationError, match=("non-empty" if mode == "empty" else "duplicate")):
        validate_vector_index(document)


@pytest.mark.parametrize("value", ("confirmed", "CONFIRMED", "ConFiRmEd"))
def test_confirmed_is_rejected_in_status_like_fields(value: str) -> None:
    document = _document()
    document["review"]["review_status"] = value

    with pytest.raises(VectorIndexValidationError, match="confirmed"):
        validate_vector_index(document)


def test_document_is_strict_json_serializable() -> None:
    document = _document()
    serialized = json.dumps(document, ensure_ascii=False, allow_nan=False)

    assert json.loads(serialized) == document


def test_validator_rejects_values_not_representable_in_json() -> None:
    document = _document()
    document["warnings"] = ("not", "a", "JSON", "array")

    with pytest.raises(VectorIndexValidationError, match="cannot be represented"):
        validate_vector_index(document)


def test_fixture_is_synthetic_and_has_no_questions_answers_or_confirmed() -> None:
    document = _document()
    text = FIXTURE_PATH.read_text(encoding="utf-8").casefold()
    keys = {key.casefold() for key in _walk_keys(document)}

    assert "synthetic" in text
    for forbidden in (
        "mshta",
        "powershell",
        "t1218.005",
        "jsonl:line:",
        "question_id",
        "question_text",
        "expected_answer",
        "expected_answers",
        "confirmed",
    ):
        assert forbidden not in text
        assert forbidden not in keys


def test_schema_source_has_no_scenario_model_or_production_constants() -> None:
    source = Path(vector_schema.__file__).read_text(encoding="utf-8").casefold()

    for forbidden in (
        "mshta",
        "powershell",
        "t1218.005",
        "sentence-transformers",
        "huggingface",
        "openai",
        "53abc9e44c03c46aaf024cdb79b61ad3381d50feb82689f27074151381b9d0f3",
    ):
        assert forbidden not in source


def test_validator_has_no_file_network_clock_random_or_uuid_logic() -> None:
    validator_source = inspect.getsource(vector_schema.validate_vector_index).casefold()
    module_source = Path(vector_schema.__file__).read_text(encoding="utf-8").casefold()

    assert ".open(" not in validator_source
    for forbidden in (
        ".write_text(",
        ".write_bytes(",
        "urlopen",
        "requests.",
        "socket.",
        "datetime.now",
        "time.time",
        "import random",
        "import uuid",
        "uuid4",
    ):
        assert forbidden not in module_source
