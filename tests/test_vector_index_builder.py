from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path
from typing import Any

import pytest

import threat_hunting.retrieval as retrieval_package
from threat_hunting.retrieval import (
    VectorIndexBuildError,
    build_vector_index,
    validate_vector_index,
)
from threat_hunting.retrieval import vector_builder


CORPUS_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "retrieval"
    / "builder"
    / "expected_retrieval_corpus.json"
)
EXPECTED_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "retrieval"
    / "vector_builder"
    / "expected_vector_index.json"
)
SOURCE_PATH = CORPUS_PATH.relative_to(Path(__file__).parents[1]).as_posix()
SOURCE_SHA256 = sha256(CORPUS_PATH.read_bytes()).hexdigest()


class DeterministicFakeEmbeddingBackend:
    """Position-based fake used only to exercise the embedding contract."""

    def __init__(self, dimension: int = 3) -> None:
        self.dimension = dimension
        self.calls: list[list[str]] = []

    def __call__(self, texts: list[str]) -> list[list[float]]:
        self.calls.append(list(texts))
        return [
            [float(index + offset + 1) for offset in range(self.dimension)]
            for index, _ in enumerate(texts)
        ]


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _corpus() -> dict[str, Any]:
    return _json(CORPUS_PATH)


def _expected() -> dict[str, Any]:
    return _json(EXPECTED_PATH)


def _embedding() -> dict[str, object]:
    return {
        "provider": "synthetic-provider",
        "model_id": "deterministic-contract-fixture",
        "model_revision": "revision-001",
        "dimension": 3,
        "distance_metric": "cosine",
        "normalization": "none",
        "document_prefix": "document: ",
        "query_prefix": "query: ",
    }


def _build(
    corpus: object | None = None,
    *,
    embedding: dict[str, object] | None = None,
    backend: object | None = None,
    corpus_path: object = SOURCE_PATH,
    corpus_sha256: object = SOURCE_SHA256,
) -> dict[str, object]:
    descriptor = _embedding() if embedding is None else embedding
    selected_backend = (
        DeterministicFakeEmbeddingBackend(int(descriptor.get("dimension", 3)))
        if backend is None
        else backend
    )
    return build_vector_index(
        _corpus() if corpus is None else corpus,
        corpus_path=corpus_path,  # type: ignore[arg-type]
        corpus_sha256=corpus_sha256,  # type: ignore[arg-type]
        embedding=descriptor,
        embed_documents=selected_backend,  # type: ignore[arg-type]
    )


def _walk(value: object) -> list[object]:
    values = [value]
    if isinstance(value, dict):
        for key, nested in value.items():
            values.extend((key, *_walk(nested)))
    elif isinstance(value, list):
        for nested in value:
            values.extend(_walk(nested))
    return values


def test_builder_and_error_are_exported_by_retrieval_package() -> None:
    assert retrieval_package.build_vector_index is build_vector_index
    assert retrieval_package.VectorIndexBuildError is VectorIndexBuildError
    assert "build_vector_index" in retrieval_package.__all__
    assert "VectorIndexBuildError" in retrieval_package.__all__


def test_build_matches_complete_expected_fixture() -> None:
    assert _build() == _expected()


def test_built_index_passes_vector_index_validator() -> None:
    validate_vector_index(_build())


def test_expected_fixture_is_valid() -> None:
    validate_vector_index(_expected())


def test_every_corpus_chunk_has_exactly_one_matching_record() -> None:
    corpus = _corpus()
    index = _build(corpus)
    chunks_by_id = {chunk["chunk_id"]: chunk for chunk in corpus["chunks"]}
    records_by_id = {record["chunk_id"]: record for record in index["records"]}

    assert len(index["records"]) == len(corpus["chunks"]) == 15
    assert len(records_by_id) == len(chunks_by_id)
    assert records_by_id.keys() == chunks_by_id.keys()
    for chunk_id, chunk in chunks_by_id.items():
        record = records_by_id[chunk_id]
        assert record["chunk_type"] == chunk["chunk_type"]
        assert record["content_sha256"] == sha256(
            chunk["content"].encode("utf-8")
        ).hexdigest()


def test_corpus_provenance_and_coverage_are_exact() -> None:
    corpus = _corpus()
    index = _build(corpus)

    assert index["corpus_provenance"] == {
        "path": SOURCE_PATH,
        "schema_version": "retrieval-corpus/v1",
        "sha256": SOURCE_SHA256,
        "corpus_id": corpus["corpus_id"],
        "scenario_id": corpus["scenario_id"],
    }
    assert index["metadata"] == {
        "record_count": len(corpus["chunks"]),
        "vector_dimension": 3,
        "complete_corpus_coverage": True,
    }


def test_builder_does_not_mutate_retrieval_corpus() -> None:
    corpus = _corpus()
    before = deepcopy(corpus)

    _build(corpus)

    assert corpus == before


def test_builder_does_not_mutate_embedding_descriptor() -> None:
    descriptor = _embedding()
    before = deepcopy(descriptor)

    _build(embedding=descriptor)

    assert descriptor == before


def test_builder_does_not_mutate_backend_vectors() -> None:
    vectors = [[1, 2, 3] for _ in _corpus()["chunks"]]
    before = deepcopy(vectors)

    _build(backend=lambda _: vectors)

    assert vectors == before


def test_two_builds_are_equal_and_byte_equivalent() -> None:
    first = _build()
    second = _build()

    assert first == second
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_reordering_chunks_does_not_change_output() -> None:
    corpus = _corpus()
    reversed_corpus = deepcopy(corpus)
    reversed_corpus["chunks"].reverse()

    assert _build(reversed_corpus) == _build(corpus)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("provider", "alternate-synthetic-provider"),
        ("model_id", "alternate-contract-fixture"),
        ("model_revision", "revision-002"),
        ("dimension", 4),
        ("normalization", "l2"),
        ("document_prefix", "alternate-document: "),
        ("query_prefix", "alternate-query: "),
    ),
)
def test_changing_valid_embedding_descriptor_component_changes_index_id(
    field: str, replacement: object
) -> None:
    original = _build()
    descriptor = _embedding()
    descriptor[field] = replacement

    changed = _build(embedding=descriptor)

    assert changed["index_id"] != original["index_id"]


def test_index_id_uses_canonical_json_identity() -> None:
    corpus = _corpus()
    descriptor = _embedding()
    identity = {
        "corpus_id": corpus["corpus_id"],
        "scenario_id": corpus["scenario_id"],
        "corpus_sha256": SOURCE_SHA256,
        "embedding": descriptor,
    }
    canonical = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

    assert _build()["index_id"] == f"vector-index--{sha256(canonical).hexdigest()}"


def test_backend_receives_prefixed_content_in_sorted_chunk_order() -> None:
    corpus = _corpus()
    backend = DeterministicFakeEmbeddingBackend()

    _build(corpus, backend=backend)

    sorted_chunks = sorted(corpus["chunks"], key=lambda item: item["chunk_id"])
    assert backend.calls == [
        [f"document: {chunk['content']}" for chunk in sorted_chunks]
    ]
    assert all(not text.startswith("query: ") for text in backend.calls[0])


def test_query_prefix_is_stored_but_not_sent_to_document_backend() -> None:
    descriptor = _embedding()
    descriptor["query_prefix"] = "query-only-marker: "
    backend = DeterministicFakeEmbeddingBackend()

    index = _build(embedding=descriptor, backend=backend)

    assert index["embedding"]["query_prefix"] == "query-only-marker: "
    assert all("query-only-marker: " not in text for text in backend.calls[0])


def test_content_hash_uses_unprefixed_content_only() -> None:
    corpus = _corpus()
    index = _build(corpus)
    chunks_by_id = {chunk["chunk_id"]: chunk for chunk in corpus["chunks"]}

    for record in index["records"]:
        content = chunks_by_id[record["chunk_id"]]["content"]
        assert record["content_sha256"] == sha256(
            content.encode("utf-8")
        ).hexdigest()
        assert record["content_sha256"] != sha256(
            f"document: {content}".encode("utf-8")
        ).hexdigest()


def test_record_order_is_lexicographic_by_chunk_id() -> None:
    record_ids = [record["chunk_id"] for record in _build()["records"]]

    assert record_ids == sorted(record_ids)


def test_none_normalization_preserves_values_after_safe_number_conversion() -> None:
    vectors = [[1, -2, 0] for _ in _corpus()["chunks"]]

    index = _build(backend=lambda _: vectors)

    assert all(record["vector"] == [1.0, -2.0, 0.0] for record in index["records"])


def test_l2_normalization_produces_unit_vectors_without_mutating_backend_values() -> None:
    descriptor = _embedding()
    descriptor["normalization"] = "l2"
    vectors = [[3.0, 4.0, 0.0] for _ in _corpus()["chunks"]]
    before = deepcopy(vectors)

    index = _build(embedding=descriptor, backend=lambda _: vectors)

    assert vectors == before
    assert all(record["vector"] == [0.6, 0.8, 0.0] for record in index["records"])
    assert all(
        math.isclose(math.hypot(*record["vector"]), 1.0)
        for record in index["records"]
    )


def test_invalid_retrieval_corpus_is_wrapped_before_backend_call() -> None:
    corpus = _corpus()
    del corpus["scenario_id"]
    calls = 0

    def backend(_: list[str]) -> list[list[float]]:
        nonlocal calls
        calls += 1
        return []

    with pytest.raises(VectorIndexBuildError, match="Invalid Retrieval Corpus"):
        _build(corpus, backend=backend)

    assert calls == 0


@pytest.mark.parametrize("digest", ("", "a" * 63, "a" * 65, "g" * 64, None, 42))
def test_invalid_corpus_sha256_is_rejected_before_backend_call(
    digest: object,
) -> None:
    calls = 0

    def backend(_: list[str]) -> list[list[float]]:
        nonlocal calls
        calls += 1
        return []

    with pytest.raises(VectorIndexBuildError, match="corpus_sha256"):
        _build(corpus_sha256=digest, backend=backend)

    assert calls == 0


@pytest.mark.parametrize("path", ("", "   ", None, 42))
def test_invalid_corpus_path_is_rejected(path: object) -> None:
    with pytest.raises(VectorIndexBuildError, match="corpus_path"):
        _build(corpus_path=path)


def test_path_and_uppercase_hash_are_normalized_without_file_access() -> None:
    index = _build(
        corpus_path=Path("logical") / "corpus.json",
        corpus_sha256=SOURCE_SHA256.upper(),
    )

    assert index["corpus_provenance"]["path"] == "logical/corpus.json"
    assert index["corpus_provenance"]["sha256"] == SOURCE_SHA256


def test_noncallable_backend_is_rejected() -> None:
    with pytest.raises(VectorIndexBuildError, match="must be callable"):
        _build(backend=None if False else 42)


def test_backend_exception_is_wrapped() -> None:
    def reject(_: list[str]) -> list[list[float]]:
        raise RuntimeError("synthetic backend failure")

    with pytest.raises(
        VectorIndexBuildError, match="Embedding backend failed.*synthetic backend failure"
    ):
        _build(backend=reject)


@pytest.mark.parametrize("value", (None, "not-vectors", 42))
def test_backend_result_must_be_a_vector_sequence(value: object) -> None:
    with pytest.raises(VectorIndexBuildError, match="sequence of vectors"):
        _build(backend=lambda _: value)


@pytest.mark.parametrize("count_delta", (-1, 1))
def test_backend_vector_count_must_equal_chunk_count(count_delta: int) -> None:
    count = len(_corpus()["chunks"]) + count_delta

    with pytest.raises(VectorIndexBuildError, match="vectors for 15 chunks"):
        _build(backend=lambda _: [[1.0, 2.0, 3.0] for _ in range(count)])


@pytest.mark.parametrize("value", (None, "not-a-vector", 7))
def test_each_backend_vector_must_be_a_sequence(value: object) -> None:
    vectors: list[object] = [[1.0, 2.0, 3.0] for _ in _corpus()["chunks"]]
    vectors[4] = value

    with pytest.raises(VectorIndexBuildError, match=r"output\[4\].*vector sequence"):
        _build(backend=lambda _: vectors)


def test_empty_vector_is_rejected_with_chunk_context() -> None:
    vectors = [[1.0, 2.0, 3.0] for _ in _corpus()["chunks"]]
    vectors[2] = []

    with pytest.raises(VectorIndexBuildError, match=r"output\[2\].*must not be empty"):
        _build(backend=lambda _: vectors)


def test_wrong_vector_dimension_is_rejected_with_chunk_context() -> None:
    vectors = [[1.0, 2.0, 3.0] for _ in _corpus()["chunks"]]
    vectors[3] = [1.0, 2.0]

    with pytest.raises(
        VectorIndexBuildError, match=r"output\[3\].*exactly 3 values"
    ):
        _build(backend=lambda _: vectors)


@pytest.mark.parametrize(
    "value", ("1.0", None, True, float("nan"), float("inf"), float("-inf"))
)
def test_non_json_or_nonfinite_vector_value_is_rejected(value: object) -> None:
    vectors: list[list[object]] = [
        [1.0, 2.0, 3.0] for _ in _corpus()["chunks"]
    ]
    vectors[5][1] = value

    with pytest.raises(
        VectorIndexBuildError, match=r"output\[5\].*\[1\].*finite JSON number"
    ):
        _build(backend=lambda _: vectors)


def test_too_large_integer_vector_value_is_rejected() -> None:
    vectors = [[1.0, 2.0, 3.0] for _ in _corpus()["chunks"]]
    vectors[0][0] = 10**10000

    with pytest.raises(VectorIndexBuildError, match="finite JSON number"):
        _build(backend=lambda _: vectors)


def test_zero_vector_is_rejected_for_l2_normalization() -> None:
    descriptor = _embedding()
    descriptor["normalization"] = "l2"

    with pytest.raises(VectorIndexBuildError, match="zero vector"):
        _build(
            embedding=descriptor,
            backend=lambda texts: [[0.0, 0.0, 0.0] for _ in texts],
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("distance_metric", "euclidean", "distance_metric.*unsupported"),
        ("normalization", "unit", "normalization.*unsupported"),
        ("dimension", 0, "dimension.*positive integer"),
        ("dimension", True, "dimension.*positive integer"),
    ),
)
def test_unsupported_or_invalid_embedding_configuration_is_rejected(
    field: str, value: object, message: str
) -> None:
    descriptor = _embedding()
    descriptor[field] = value

    with pytest.raises(VectorIndexBuildError, match=message):
        _build(embedding=descriptor)


@pytest.mark.parametrize("mode", ("missing", "unexpected"))
def test_embedding_field_set_is_strict(mode: str) -> None:
    descriptor = _embedding()
    if mode == "missing":
        del descriptor["query_prefix"]
    else:
        descriptor["extra"] = "not-allowed"

    with pytest.raises(VectorIndexBuildError, match=f"embedding fields.*{mode}"):
        _build(embedding=descriptor)


def test_duplicate_chunk_id_is_rejected_before_embedding() -> None:
    corpus = _corpus()
    corpus["chunks"][1]["chunk_id"] = corpus["chunks"][0]["chunk_id"]

    with pytest.raises(VectorIndexBuildError, match="Duplicate chunk_id"):
        _build(corpus)


def test_non_utf8_json_embedding_data_is_rejected() -> None:
    descriptor = _embedding()
    descriptor["model_id"] = "\ud800"

    with pytest.raises(VectorIndexBuildError, match="UTF-8 JSON"):
        _build(embedding=descriptor)


def test_non_utf8_chunk_content_is_rejected_without_partial_output() -> None:
    corpus = _corpus()
    corpus["chunks"][0]["content"] = "valid-prefix-\ud800"

    with pytest.raises(VectorIndexBuildError, match="cannot be encoded as UTF-8"):
        _build(corpus)


def test_vector_validation_failure_is_wrapped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(_: object) -> None:
        raise vector_builder.VectorIndexValidationError("synthetic rejection")

    monkeypatch.setattr(vector_builder, "validate_vector_index", reject)

    with pytest.raises(VectorIndexBuildError, match="synthetic rejection"):
        _build()


def test_review_warnings_and_metadata_policy_is_deterministic() -> None:
    corpus = _corpus()
    corpus["warnings"].append(corpus["warnings"][0])
    index = _build(corpus)

    assert index["warnings"] == sorted(set(corpus["warnings"]))
    assert index["review"] == {
        "review_status": "pending_human_review",
        "reviewer": None,
        "reviewed_at": None,
        "notes": [
            "This vector index was generated automatically from a validated Retrieval Corpus document.",
            "The embedding output and corpus coverage have not been reviewed by a human.",
        ],
    }
    assert "confirmed" not in {
        value.casefold() for value in _walk(index) if isinstance(value, str)
    }


def test_built_index_is_strict_utf8_json_serializable() -> None:
    encoded = json.dumps(
        _build(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

    assert json.loads(encoded.decode("utf-8")) == _build()


def test_builder_source_has_no_file_network_clock_random_or_uuid_logic() -> None:
    source = Path(vector_builder.__file__).read_text(encoding="utf-8").casefold()

    for forbidden in (
        ".open(",
        ".read_text(",
        ".read_bytes(",
        ".write_text(",
        ".write_bytes(",
        "json.load(",
        "requests",
        "urllib",
        "httpx",
        "socket",
        "datetime.now",
        "time.time",
        "import random",
        "import uuid",
        "uuid4",
    ):
        assert forbidden not in source


def test_builder_source_has_no_production_model_scenario_or_ids() -> None:
    source = Path(vector_builder.__file__).read_text(encoding="utf-8").casefold()

    for forbidden in (
        "mshta",
        "powershell",
        "cmd.exe",
        "t1059.007",
        "t1140",
        "t1218.005",
        "jsonl:line:",
        "openai",
        "huggingface",
    ):
        assert forbidden not in source


def test_expected_vector_fixture_is_synthetic_and_scope_limited() -> None:
    text = EXPECTED_PATH.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "mshta",
        "powershell",
        "cmd.exe",
        "t1059.007",
        "t1140",
        "t1218.005",
        "jsonl:line:",
        "raw_record_ref",
        "source_references",
        "question",
        "expected_answer",
        "confirmed",
    ):
        assert forbidden not in text


def test_expected_fixture_uses_small_complete_vectors_for_all_chunks() -> None:
    fixture = _expected()

    assert fixture["embedding"]["dimension"] == 3
    assert len(fixture["records"]) == len(_corpus()["chunks"]) == 15
    assert fixture["metadata"]["complete_corpus_coverage"] is True
