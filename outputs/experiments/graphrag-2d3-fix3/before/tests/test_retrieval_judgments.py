"""Evaluation labels, byte-bound provenance and exact corpus-pointer resolution.

Synthetic sources are embedded or built from tracked fixtures; their logical
provenance paths label in-memory serialized sources and are never opened.
Clean clones do not need ignored outputs; when available, the pinned production
corpus also receives the complete resolution and byte-preservation check.
"""

from __future__ import annotations

import ast
import builtins
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import socket
from typing import Any

import pytest

from threat_hunting.evaluation import (
    RETRIEVAL_JUDGMENTS_SCHEMA_VERSION,
    RetrievalJudgmentsValidationError,
    load_relevance_calibration_dataset,
    load_retrieval_judgments_document,
    resolve_retrieval_judgments,
    validate_relevance_calibration_dataset,
    validate_retrieval_judgments_document,
)
from threat_hunting.retrieval import validate_retrieval_corpus


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "tests/fixtures/evaluation/retrieval_judgments_minimal.json"
CORPUS_FIXTURE_PATH = ROOT / "tests/fixtures/retrieval/retrieval_corpus_minimal.json"
BENCHMARK_PATH = ROOT / "benchmarks/retrieval/mshta_embedding_retrieval_judgments.json"
DATASET_PATH = ROOT / "benchmarks/graphrag/mshta_relevance_calibration.json"
PRODUCTION_CORPUS_PATH = ROOT / "outputs/retrieval/mshta-powershell/retrieval_corpus.json"
IMPLEMENTATION_PATH = ROOT / "src/threat_hunting/evaluation/retrieval_judgments.py"
SOURCE_DATASET_PATH = "tests/fixtures/evaluation/synthetic_dataset.json"
SOURCE_CORPUS_PATH = "tests/fixtures/evaluation/synthetic_corpus.json"
CATEGORY_KINDS = {
    "relevant_direct": "answer_support",
    "relevant_paraphrase": "answer_support",
    "insufficient_evidence": "abstention_support",
    "unrelated": "no_relevant_chunk",
}
OUTPUT_FIELDS = {
    "case_id", "category", "language", "expected_decision", "target_kind",
    "relevant_source_pointers", "resolved_chunk_ids", "resolved_chunk_types",
}


def _bytes(document: object) -> bytes:
    return json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _document() -> dict[str, Any]:
    return _json(FIXTURE_PATH)


def _dataset() -> dict[str, Any]:
    specifications = (
        ("relevant_direct", "en", "Which evidence supports the synthetic relation?"),
        ("relevant_paraphrase", "vi", "Dấu vết nào giải thích liên hệ giả lập?"),
        ("insufficient_evidence", "en", "Who authored the activity outside the reviewed scope?"),
        ("unrelated", "vi", "Cách chăm sóc cây trong nhà là gì?"),
    )
    cases = [
        {
            "case_id": f"synthetic-case-{index:02d}",
            "category": category,
            "language": language,
            "query": query,
            "expected_decision": "proceed" if category.startswith("relevant_") else "abstain",
            "rationale": "Synthetic context eligibility within the reviewed record scope.",
            "tags": ["synthetic"],
        }
        for index, (category, language, query) in enumerate(specifications, start=1)
    ]
    return {
        "schema_version": "graphrag-relevance-calibration-dataset/v1",
        "dataset_id": "synthetic-retrieval-calibration",
        "scenario_id": "scenario-synthetic-review-001",
        "purpose": "relevance_gate_calibration",
        "cases": cases,
        "metadata": {
            "case_count": 4,
            "category_counts": {category: 1 for category in CATEGORY_KINDS},
            "language_counts": {"en": 2, "vi": 2},
            "decision_counts": {"proceed": 2, "abstain": 2},
        },
    }


def _corpus() -> dict[str, Any]:
    return _json(CORPUS_FIXTURE_PATH)


def _counts(document: dict[str, Any], dataset: dict[str, Any] | None = None) -> None:
    cases = document["cases"]
    metadata = document["metadata"]
    metadata["case_count"] = len(cases)
    kinds = Counter(case["target_kind"] for case in cases)
    metadata["target_kind_counts"] = {
        name: kinds[name] for name in ("answer_support", "abstention_support", "no_relevant_chunk")
    }
    metadata["total_relevant_pointer_count"] = sum(len(case["relevant_source_pointers"]) for case in cases)
    metadata["cases_with_multiple_relevant_chunks"] = sum(len(case["relevant_source_pointers"]) > 1 for case in cases)
    if dataset is not None:
        metadata["category_counts"] = {
            name: sum(case["category"] == name for case in dataset["cases"])
            for name in CATEGORY_KINDS
        }
        metadata["language_counts"] = {
            name: sum(case["language"] == name for case in dataset["cases"])
            for name in ("en", "vi")
        }


def _bind_sources(document: dict[str, Any], dataset: dict[str, Any], corpus: dict[str, Any]) -> None:
    document["source_dataset"]["sha256"] = sha256(_bytes(dataset)).hexdigest()
    document["source_corpus"]["sha256"] = sha256(_bytes(corpus)).hexdigest()


def _resolve(
    document: dict[str, Any] | None = None,
    dataset: dict[str, Any] | None = None,
    corpus: dict[str, Any] | None = None,
    **overrides: Any,
) -> list[dict[str, Any]]:
    dataset = _dataset() if dataset is None else dataset
    corpus = _corpus() if corpus is None else corpus
    arguments = {
        "source_dataset_path": SOURCE_DATASET_PATH,
        "source_dataset_bytes": _bytes(dataset),
        "source_corpus_path": SOURCE_CORPUS_PATH,
        "source_corpus_bytes": _bytes(corpus),
    }
    arguments.update(overrides)
    return resolve_retrieval_judgments(
        _document() if document is None else document, dataset, corpus, **arguments,
    )


def _at(document: dict[str, Any], path: tuple) -> Any:
    item: Any = document
    for key in path:
        item = item[key]
    return item


def _set(document: dict[str, Any], path: tuple, value: object) -> None:
    _at(document, path[:-1])[path[-1]] = value


def _walk(value: object):
    yield value
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested)


def test_public_schema_and_fixture_sources_are_valid() -> None:
    assert RETRIEVAL_JUDGMENTS_SCHEMA_VERSION == "retrieval-relevance-judgments/v1"
    document, dataset, corpus = _document(), _dataset(), _corpus()
    validate_relevance_calibration_dataset(dataset)
    validate_retrieval_corpus(corpus)
    assert validate_retrieval_judgments_document(document) is None
    assert validate_retrieval_judgments_document(document, calibration_dataset=dataset) is None
    assert document["source_dataset"]["sha256"] == sha256(_bytes(dataset)).hexdigest()
    assert document["source_corpus"]["sha256"] == sha256(_bytes(corpus)).hexdigest()
    assert len(document["cases"]) == 4
    assert document["metadata"]["cases_with_multiple_relevant_chunks"] == 1
    assert {case["target_kind"] for case in document["cases"]} == set(document["metadata"]["target_kind_counts"])
    assert {case["language"] for case in dataset["cases"]} == {"en", "vi"}
    assert "mshta" not in FIXTURE_PATH.read_text(encoding="utf-8").casefold()


@pytest.mark.parametrize("path", [
    (), ("source_dataset",), ("source_corpus",), ("cases", 0), ("review",),
    ("metadata",), ("metadata", "target_kind_counts"),
    ("metadata", "category_counts"), ("metadata", "language_counts"),
])
@pytest.mark.parametrize("operation", ["missing", "extra"])
def test_strict_fields_at_every_object(path: tuple, operation: str) -> None:
    document = _document()
    target = _at(document, path)
    if operation == "missing":
        del target[next(iter(target))]
    else:
        target["unexpected_field"] = None
    with pytest.raises(RetrievalJudgmentsValidationError, match=r"\$"):
        validate_retrieval_judgments_document(document)


@pytest.mark.parametrize("path", [
    ("judgment_set_id",), ("scenario_id",),
    ("source_dataset", "dataset_id"), ("source_corpus", "corpus_id"),
    ("cases", 0, "case_id"), ("cases", 0, "annotation_note"),
    ("cases", 0, "relevant_source_pointers", 0),
])
@pytest.mark.parametrize("value", ["", "   ", None])
def test_empty_identifiers_pointers_and_notes(path: tuple, value: object) -> None:
    document = _document()
    _set(document, path, value)
    with pytest.raises(RetrievalJudgmentsValidationError):
        validate_retrieval_judgments_document(document)


@pytest.mark.parametrize("name", ["query", "question", "question_text", "questions", "expected_decision", "expected_answer", "answer", "generated_answer", "model_output", "model_id", "rank", "score", "vector", "threshold", "Expected-Answer", "ＭＯＤＥＬ＿ＯＵＴＰＵＴ"])
@pytest.mark.parametrize("path", [(), ("cases", 0), ("metadata",)])
def test_forbidden_question_answer_and_model_fields(name: str, path: tuple) -> None:
    document = _document()
    _at(document, path)[name] = "copied label"
    with pytest.raises(RetrievalJudgmentsValidationError):
        validate_retrieval_judgments_document(document)


@pytest.mark.parametrize("value", ["confirmed", "CONFIRMED", " ConFiRmEd "])
@pytest.mark.parametrize("path", [
    ("judgment_set_id",), ("cases", 0, "annotation_note"),
    ("review", "review_status"), ("metadata", "language_counts", "en"),
])
def test_recursive_confirmed_guard(value: str, path: tuple) -> None:
    document = _document()
    _set(document, path, value)
    with pytest.raises(RetrievalJudgmentsValidationError, match="confirmed"):
        validate_retrieval_judgments_document(document)


def test_confirmed_guard_checks_object_keys_and_nested_lists() -> None:
    for value in ({"CONFIRMED": "pending"}, [{"note": ["CONFIRMED"]}]):
        document = _document()
        document["metadata"]["unexpected"] = value
        with pytest.raises(RetrievalJudgmentsValidationError, match="confirmed"):
            validate_retrieval_judgments_document(document)


@pytest.mark.parametrize("field", ["query", "expected_decision", "generated_answer", "model_output"])
def test_forbidden_fields_are_rejected_deep_inside_arbitrary_objects(field: str) -> None:
    document = _document()
    document["metadata"]["unknown"] = [{"nested": [{field: "copied content"}]}]
    with pytest.raises(RetrievalJudgmentsValidationError) as error:
        validate_retrieval_judgments_document(document)
    assert f"$.metadata.unknown[0].nested[0].{field}" in str(error.value)
    assert "forbidden" in str(error.value)


@pytest.mark.parametrize("pointer", ["facts/0", "/facts/~2", "/facts/~", " /facts/0"])
def test_invalid_rfc6901_pointer_syntax(pointer: str) -> None:
    document = _document()
    document["cases"][0]["relevant_source_pointers"] = [pointer]
    _counts(document)
    with pytest.raises(RetrievalJudgmentsValidationError):
        validate_retrieval_judgments_document(document)


@pytest.mark.parametrize("path,value", [
    (("schema_version",), "wrong-schema"),
    (("purpose",), "production_runtime"),
    (("source_dataset", "schema_version"), "wrong-schema"),
    (("source_corpus", "schema_version"), "wrong-schema"),
    (("source_dataset", "scenario_id"), "other-scenario"),
    (("source_corpus", "scenario_id"), "other-scenario"),
    (("cases", 0, "target_kind"), "invalid-kind"),
    (("review", "review_status"), "reviewed"),
    (("review", "reviewer"), "reviewer"),
    (("review", "reviewed_at"), "2026-01-01"),
    (("source_dataset", "sha256"), "bad-digest"),
    (("source_corpus", "sha256"), "g" * 64),
])
def test_schema_scenario_kind_and_review_contract(path: tuple, value: object) -> None:
    document = _document()
    _set(document, path, value)
    with pytest.raises(RetrievalJudgmentsValidationError):
        validate_retrieval_judgments_document(document)


@pytest.mark.parametrize("path", [("source_dataset", "path"), ("source_corpus", "path")])
@pytest.mark.parametrize("value", ["/absolute.json", "../outside.json", "nested/../outside.json", "C:/private/file.json", "C:\\private\\file.json", "https://example.org/file.json", "folder\\file.json", "folder//file.json"])
def test_provenance_paths_are_safe_relative(path: tuple, value: str) -> None:
    document = _document()
    _set(document, path, value)
    with pytest.raises(RetrievalJudgmentsValidationError):
        validate_retrieval_judgments_document(document)


@pytest.mark.parametrize("mutation", ["duplicate_case", "duplicate_pointer", "unsorted_cases", "unsorted_pointers"])
def test_unique_sorted_case_and_pointer_lists(mutation: str) -> None:
    document = _document()
    if mutation == "duplicate_case":
        document["cases"][1]["case_id"] = document["cases"][0]["case_id"]
    elif mutation == "duplicate_pointer":
        document["cases"][0]["relevant_source_pointers"] *= 2
    elif mutation == "unsorted_cases":
        document["cases"].reverse()
    else:
        document["cases"][0]["relevant_source_pointers"].reverse()
    _counts(document)
    with pytest.raises(RetrievalJudgmentsValidationError):
        validate_retrieval_judgments_document(document)


@pytest.mark.parametrize("index,targets", [(0, []), (2, []), (3, ["/scenario"])])
def test_target_presence_matches_target_kind(index: int, targets: list[str]) -> None:
    document = _document()
    document["cases"][index]["relevant_source_pointers"] = targets
    _counts(document)
    with pytest.raises(RetrievalJudgmentsValidationError):
        validate_retrieval_judgments_document(document)


@pytest.mark.parametrize("path", [
    ("case_count",), ("target_kind_counts", "answer_support"),
    ("category_counts", "relevant_direct"), ("language_counts", "en"),
    ("total_relevant_pointer_count",), ("cases_with_multiple_relevant_chunks",),
])
@pytest.mark.parametrize("value", [99, -1, True, 1.5])
def test_metadata_counts_are_recomputed(path: tuple, value: object) -> None:
    document = _document()
    _set(document["metadata"], path, value)
    with pytest.raises(RetrievalJudgmentsValidationError):
        validate_retrieval_judgments_document(document)


@pytest.mark.parametrize("field,replacements", [
    ("category_counts", {"relevant_direct": 2, "relevant_paraphrase": 0, "insufficient_evidence": 1, "unrelated": 1}),
    ("language_counts", {"en": 3, "vi": 1}),
])
def test_source_aware_validation_recomputes_categories_and_languages(field: str, replacements: dict) -> None:
    document = _document()
    document["metadata"][field] = replacements
    # Aggregate standalone counts cannot recover categories or languages that
    # are intentionally absent from judgments; source-aware validation can.
    assert validate_retrieval_judgments_document(document) is None
    with pytest.raises(RetrievalJudgmentsValidationError):
        validate_retrieval_judgments_document(document, calibration_dataset=_dataset())


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_in_memory_values_are_rejected(value: float) -> None:
    document = _document()
    document["metadata"]["case_count"] = value
    with pytest.raises(RetrievalJudgmentsValidationError, match=r"\$\.metadata\.case_count"):
        validate_retrieval_judgments_document(document)


def test_loader_preserves_unicode_and_raw_bytes_and_returns_fresh_data(tmp_path: Path) -> None:
    path = tmp_path / "judgments_unicode.json"
    document = _document()
    path.write_bytes(_bytes(document))
    before = path.read_bytes()
    first = load_retrieval_judgments_document(path, calibration_dataset=_dataset())
    second = load_retrieval_judgments_document(path)
    assert first == second == document
    first["cases"][0]["relevant_source_pointers"].clear()
    assert second == document
    assert path.read_bytes() == before
    assert "giả lập" in second["cases"][1]["annotation_note"]


@pytest.mark.parametrize("payload,error_path", [
    (b'{"schema_version":"one","schema_version":"two"}', "$.schema_version"),
    (b'{"cases":[{"case_id":"one","case_id":"two"}]}', "$.cases[0].case_id"),
    (b'{"metadata":{"case_count":NaN}}', "$.metadata.case_count"),
    (b'{"metadata":{"case_count":Infinity}}', "$.metadata.case_count"),
    (b'{"metadata":{"case_count":-Infinity}}', "$.metadata.case_count"),
    (b'{"metadata":{"case_count":1e999}}', "$.metadata.case_count"),
    (b'\xff\xfe', "$"),
    (b'{"broken":', "$"),
    (b'{"cases":[{"annotation_note":"\\ud800"}]}', "$.cases[0].annotation_note"),
])
def test_loader_reports_filename_and_json_path(tmp_path: Path, payload: bytes, error_path: str) -> None:
    path = tmp_path / "invalid_judgments.json"
    path.write_bytes(payload)
    with pytest.raises(RetrievalJudgmentsValidationError) as error:
        load_retrieval_judgments_document(path)
    assert str(path) in str(error.value)
    assert error_path in str(error.value)


def test_loader_missing_file_is_a_filename_qualified_domain_error(tmp_path: Path) -> None:
    path = tmp_path / "missing_judgments.json"
    with pytest.raises(RetrievalJudgmentsValidationError) as error:
        load_retrieval_judgments_document(path)
    assert str(path) in str(error.value) and "$" in str(error.value)


def test_validation_failure_does_not_mutate_document() -> None:
    document = _document()
    document["metadata"]["case_count"] = 99
    before = deepcopy(document)
    with pytest.raises(RetrievalJudgmentsValidationError):
        validate_retrieval_judgments_document(document)
    assert document == before


def test_all_synthetic_cases_resolve_to_expected_detached_result() -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    before = deepcopy((document, dataset, corpus))
    result = _resolve(document, dataset, corpus)
    assert (document, dataset, corpus) == before
    assert [case["case_id"] for case in result] == [f"synthetic-case-{index:02d}" for index in range(1, 5)]
    assert all(set(case) == OUTPUT_FIELDS for case in result)
    assert result[0]["resolved_chunk_ids"] == ["chunk-synthetic-evidence-001", "chunk-synthetic-relationship-001"]
    assert result[0]["resolved_chunk_types"] == ["evidence", "relationship"]
    assert result[1]["resolved_chunk_ids"] == ["chunk-synthetic-fact-001"]
    assert result[2]["resolved_chunk_ids"] == ["chunk-synthetic-limitation-001"]
    assert result[3]["resolved_chunk_ids"] == result[3]["resolved_chunk_types"] == []
    assert result[2]["expected_decision"] == result[3]["expected_decision"] == "abstain"
    result[0]["relevant_source_pointers"].clear()
    result[1]["resolved_chunk_ids"].append("detached-only")
    assert (document, dataset, corpus) == before


def test_resolver_is_in_memory_and_calls_no_network_or_models(monkeypatch) -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    kwargs = {
        "source_dataset_path": SOURCE_DATASET_PATH,
        "source_dataset_bytes": _bytes(dataset),
        "source_corpus_path": SOURCE_CORPUS_PATH,
        "source_corpus_bytes": _bytes(corpus),
    }

    def forbidden(*args, **kwargs):
        raise AssertionError("Resolver must perform no filesystem, network or model operation")

    for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
        monkeypatch.setattr(Path, name, forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert len(resolve_retrieval_judgments(document, dataset, corpus, **kwargs)) == 4


@pytest.mark.parametrize("source", ["dataset", "corpus"])
@pytest.mark.parametrize("field", ["path", "schema_version", "sha256", "id", "scenario_id"])
def test_source_provenance_mismatch(source: str, field: str) -> None:
    document = _document()
    key = f"source_{source}"
    actual_field = f"{source}_id" if field == "id" else field
    value = "f" * 64 if field == "sha256" else "wrong-value"
    document[key][actual_field] = value
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document)


@pytest.mark.parametrize("source", ["dataset", "corpus"])
@pytest.mark.parametrize("mutation", ["schema", "scenario", "invalid_content"])
def test_resolver_uses_both_existing_source_validators(source: str, mutation: str) -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    target = dataset if source == "dataset" else corpus
    if mutation == "schema":
        target["schema_version"] = "invalid-schema"
    elif mutation == "scenario":
        target["scenario_id"] = "wrong-scenario"
    elif source == "dataset":
        target["cases"][0]["query"] = ""
    else:
        target["chunks"][0]["chunk_type"] = "invalid-type"
    _bind_sources(document, dataset, corpus)
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document, dataset, corpus)


@pytest.mark.parametrize("source", ["dataset", "corpus"])
def test_actual_bytes_hash_is_verified_even_when_supplied_documents_match(source: str) -> None:
    target = _dataset() if source == "dataset" else _corpus()
    # Whitespace preserves JSON semantics but changes the pinned source bytes.
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(**{f"source_{source}_bytes": _bytes(target) + b"\n"})


@pytest.mark.parametrize("source", ["dataset", "corpus"])
def test_alternative_json_whitespace_resolves_after_actual_hash_is_updated(source: str) -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    target = dataset if source == "dataset" else corpus
    payload = (json.dumps(target, ensure_ascii=False, indent=4) + "\n").encode("utf-8")
    assert json.loads(payload) == target
    assert sha256(payload).hexdigest() != document[f"source_{source}"]["sha256"]
    document[f"source_{source}"]["sha256"] = sha256(payload).hexdigest()
    assert len(_resolve(document, dataset, corpus, **{f"source_{source}_bytes": payload})) == 4


@pytest.mark.parametrize("source", ["dataset", "corpus"])
@pytest.mark.parametrize("payload", ["JSON text", bytearray(b"{}"), None])
def test_provenance_payload_requires_immutable_bytes(source: str, payload: object) -> None:
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(**{f"source_{source}_bytes": payload})


@pytest.mark.parametrize("source", ["dataset", "corpus"])
def test_source_bytes_must_represent_the_supplied_document(source: str) -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    target = deepcopy(dataset if source == "dataset" else corpus)
    if source == "dataset":
        target["cases"][0]["query"] += " Altered source text."
    else:
        target["chunks"][0]["content"] += " Altered source content."
    payload = _bytes(target)
    document[f"source_{source}"]["sha256"] = sha256(payload).hexdigest()
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document, dataset, corpus, **{f"source_{source}_bytes": payload})


@pytest.mark.parametrize("source", ["dataset", "corpus"])
@pytest.mark.parametrize("payload", [b'{"duplicate":1,"duplicate":2}', b'{"nonfinite":NaN}', b'\xff', b'{'])
def test_resolver_strictly_parses_provenance_bytes(source: str, payload: bytes) -> None:
    document = _document()
    document[f"source_{source}"]["sha256"] = sha256(payload).hexdigest()
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document, **{f"source_{source}_bytes": payload})


def test_source_json_types_must_match_even_when_python_equal() -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    altered = deepcopy(corpus)
    altered["chunks"][0]["metadata"]["fixture"] = 1
    assert altered == corpus  # bool/int equality must not hide source tampering.
    payload = _bytes(altered)
    document["source_corpus"]["sha256"] = sha256(payload).hexdigest()
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document, dataset, corpus, source_corpus_bytes=payload)


@pytest.mark.parametrize("mutation", ["missing", "extra", "unknown_id"])
def test_exact_dataset_case_coverage(mutation: str) -> None:
    document = _document()
    if mutation == "missing":
        document["cases"].pop()
    elif mutation == "extra":
        new_case = deepcopy(document["cases"][-1])
        new_case["case_id"] = "synthetic-case-05"
        document["cases"].append(new_case)
    else:
        document["cases"][-1]["case_id"] = "synthetic-unknown"
    _counts(document)
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document)


@pytest.mark.parametrize("index,kind,targets", [
    (0, "abstention_support", ["/summary/limitations/0"]),
    (1, "no_relevant_chunk", []),
    (2, "answer_support", ["/facts/0"]),
    (3, "abstention_support", ["/summary/limitations/0"]),
])
def test_category_target_kind_mismatch(index: int, kind: str, targets: list[str]) -> None:
    document = _document()
    document["cases"][index].update(target_kind=kind, relevant_source_pointers=targets)
    _counts(document)
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document)


@pytest.mark.parametrize("field,value", [("language", "fr"), ("expected_decision", "abstain"), ("category", "unknown")])
def test_invalid_source_case_semantics(field: str, value: str) -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    dataset["cases"][0][field] = value
    _bind_sources(document, dataset, corpus)
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document, dataset, corpus)


@pytest.mark.parametrize("pointer", ["/missing/0", "/facts", "/relationships", "/review/notes", "/summary/observed_behavior", "/evidence/0/observations"])
def test_only_exact_existing_chunk_pointers_resolve(pointer: str) -> None:
    document = _document()
    document["cases"][0]["relevant_source_pointers"] = [pointer]
    _counts(document)
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document)


def test_ambiguous_pointer_is_rejected_with_otherwise_valid_corpus() -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    duplicate = deepcopy(next(chunk for chunk in corpus["chunks"] if chunk["source"]["json_pointer"] == "/evidence/0"))
    duplicate["chunk_id"] = "chunk-synthetic-extra-evidence"
    corpus["chunks"].append(duplicate)
    validate_retrieval_corpus(corpus)
    _bind_sources(document, dataset, corpus)
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document, dataset, corpus)


def test_duplicate_resolved_chunk_is_rejected() -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    relationship = next(chunk for chunk in corpus["chunks"] if chunk["source"]["json_pointer"] == "/relationships/0")
    relationship["chunk_id"] = "chunk-synthetic-evidence-001"
    _bind_sources(document, dataset, corpus)
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document, dataset, corpus)


def test_resolver_failure_preserves_all_three_documents() -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    document["cases"][0]["relevant_source_pointers"] = ["/missing/0"]
    _counts(document)
    before = deepcopy((document, dataset, corpus))
    with pytest.raises(RetrievalJudgmentsValidationError):
        _resolve(document, dataset, corpus)
    assert (document, dataset, corpus) == before


def test_cyclic_input_raises_domain_error() -> None:
    document = _document()
    document["metadata"]["cycle"] = document
    with pytest.raises(RetrievalJudgmentsValidationError, match="cyclic"):
        validate_retrieval_judgments_document(document)


def test_output_is_stable_under_source_ordering_and_detached_between_calls() -> None:
    document, dataset, corpus = _document(), _dataset(), _corpus()
    first = _resolve(document, dataset, corpus)
    dataset["cases"].reverse()
    corpus["chunks"].reverse()
    _bind_sources(document, dataset, corpus)
    second = _resolve(document, dataset, corpus)
    assert _bytes(first) == _bytes(second)
    second[0]["resolved_chunk_ids"].clear()
    assert first[0]["resolved_chunk_ids"]
    for case in first:
        assert case["relevant_source_pointers"] == sorted(case["relevant_source_pointers"])
        assert case["resolved_chunk_ids"] == sorted(case["resolved_chunk_ids"])


def _production_synthetic_corpus() -> dict[str, Any]:
    """Build an independent exact-pointer profile from generic tracked chunks.

    This checks clean-clone referential mechanics. It does not claim synthetic
    text is production evidence or substitute for the pinned local corpus audit.
    """
    corpus = _corpus()
    corpus["scenario_id"] = "mshta-powershell"
    corpus["corpus_id"] = "synthetic-production-pointer-profile"
    corpus["source_ground_truth"]["scenario_id"] = corpus["scenario_id"]
    profile = {
        "scenario_summary": ["/scenario"],
        "entity": ["/entities/0", "/entities/1", "/entities/2"],
        "fact": ["/facts/0", "/facts/1"],
        "relationship": ["/relationships/0", "/relationships/1"],
        "evidence": ["/evidence/0", "/evidence/1"],
        "sigma_finding": ["/sigma_findings/0", "/sigma_findings/1"],
        "mitre_assessment": ["/mitre_assessments/0", "/mitre_assessments/1", "/mitre_assessments/2"],
        "limitation": [f"/summary/limitations/{index}" for index in range(4)],
    }
    originals = {chunk["chunk_type"]: chunk for chunk in corpus["chunks"]}
    chunks = []
    for chunk_type, pointers in profile.items():
        for index, pointer in enumerate(pointers):
            chunk = deepcopy(originals[chunk_type])
            chunk["chunk_id"] = f"synthetic-profile-{chunk_type}-{index}"
            chunk["scenario_id"] = corpus["scenario_id"]
            chunk["source"]["json_pointer"] = pointer
            chunks.append(chunk)
    corpus["chunks"] = chunks
    validate_retrieval_corpus(corpus)
    return corpus


def test_production_benchmark_case_counts_and_evaluation_only_content() -> None:
    document = load_retrieval_judgments_document(BENCHMARK_PATH, calibration_dataset=load_relevance_calibration_dataset(DATASET_PATH))
    dataset = load_relevance_calibration_dataset(DATASET_PATH)
    assert len(document["cases"]) == len(dataset["cases"]) == 32
    assert {case["case_id"] for case in document["cases"]} == {case["case_id"] for case in dataset["cases"]}
    assert document["metadata"]["target_kind_counts"] == {"answer_support": 16, "abstention_support": 8, "no_relevant_chunk": 8}
    assert document["metadata"]["category_counts"] == {name: 8 for name in CATEGORY_KINDS}
    assert document["metadata"]["language_counts"] == {"en": 16, "vi": 16}
    assert document["review"] == {"review_status": "pending_human_review", "reviewer": None, "reviewed_at": None}
    serialized = BENCHMARK_PATH.read_text(encoding="utf-8")
    assert all(case["query"] not in serialized for case in dataset["cases"])
    keys = {value.casefold() for value in _walk(document) if isinstance(value, str)}
    assert not keys.intersection({"query", "question", "expected_answer", "answer", "generated_answer", "model_output", "model_id", "score", "rank", "vector", "threshold", "confirmed"})
    assert "all-minilm" not in serialized.casefold()
    assert "multilingual-e5" not in serialized.casefold()
    unrelated_ids = {case["case_id"] for case in dataset["cases"] if case["category"] == "unrelated"}
    unrelated = [case for case in document["cases"] if case["case_id"] in unrelated_ids]
    assert len(unrelated) == 8
    assert all(case["target_kind"] == "no_relevant_chunk" and case["relevant_source_pointers"] == [] for case in unrelated)


def test_all_production_cases_resolve_with_independent_tracked_pointer_profile() -> None:
    document = load_retrieval_judgments_document(BENCHMARK_PATH)
    dataset_bytes = DATASET_PATH.read_bytes()
    dataset = load_relevance_calibration_dataset(DATASET_PATH)
    corpus = _production_synthetic_corpus()
    corpus_bytes = _bytes(corpus)
    document["source_corpus"]["corpus_id"] = corpus["corpus_id"]
    document["source_corpus"]["sha256"] = sha256(corpus_bytes).hexdigest()
    result = resolve_retrieval_judgments(
        document, dataset, corpus,
        source_dataset_path=DATASET_PATH.relative_to(ROOT), source_dataset_bytes=dataset_bytes,
        source_corpus_path=document["source_corpus"]["path"], source_corpus_bytes=corpus_bytes,
    )
    assert len(result) == 32
    assert all(len(case["resolved_chunk_ids"]) == len(case["relevant_source_pointers"]) for case in result)
    assert sum(len(case["resolved_chunk_ids"]) for case in result) == document["metadata"]["total_relevant_pointer_count"]


def test_production_pinned_corpus_resolves_all_cases_when_local_artifact_exists() -> None:
    document = load_retrieval_judgments_document(BENCHMARK_PATH)
    dataset_bytes = DATASET_PATH.read_bytes()
    assert sha256(dataset_bytes).hexdigest() == "6764dda887c216a8c9fd83590391f2f9079a8fc0f5e0f74959e63e95654f62a4"
    assert document["source_dataset"]["sha256"] == sha256(dataset_bytes).hexdigest()
    assert document["source_corpus"]["sha256"] == "53abc9e44c03c46aaf024cdb79b61ad3381d50feb82689f27074151381b9d0f3"
    if not PRODUCTION_CORPUS_PATH.is_file():
        # All-case resolution still runs above using tracked synthetic sources.
        return
    paths = (FIXTURE_PATH, CORPUS_FIXTURE_PATH, BENCHMARK_PATH, DATASET_PATH, PRODUCTION_CORPUS_PATH)
    before = {path: path.read_bytes() for path in paths}
    corpus_bytes = before[PRODUCTION_CORPUS_PATH]
    assert sha256(corpus_bytes).hexdigest() == document["source_corpus"]["sha256"]
    dataset, corpus = json.loads(dataset_bytes), json.loads(corpus_bytes)
    result = resolve_retrieval_judgments(
        document, dataset, corpus,
        source_dataset_path=DATASET_PATH.relative_to(ROOT), source_dataset_bytes=dataset_bytes,
        source_corpus_path=PRODUCTION_CORPUS_PATH.relative_to(ROOT), source_corpus_bytes=corpus_bytes,
    )
    assert len(result) == 32
    by_pointer = {chunk["source"]["json_pointer"]: chunk for chunk in corpus["chunks"]}
    for case in result:
        expected = sorted((by_pointer[pointer] for pointer in case["relevant_source_pointers"]), key=lambda chunk: chunk["chunk_id"])
        assert case["resolved_chunk_ids"] == [chunk["chunk_id"] for chunk in expected]
        assert case["resolved_chunk_types"] == [chunk["chunk_type"] for chunk in expected]
    assert before == {path: path.read_bytes() for path in paths}


def test_clean_clone_checks_use_no_ignored_outputs(monkeypatch) -> None:
    def guard(operation):
        def checked(path, *args, **kwargs):
            assert "outputs" not in {part.casefold() for part in path.parts}
            return operation(path, *args, **kwargs)
        return checked

    for name in ("open", "read_bytes", "read_text"):
        monkeypatch.setattr(Path, name, guard(getattr(Path, name)))
    test_production_benchmark_case_counts_and_evaluation_only_content()
    test_all_production_cases_resolve_with_independent_tracked_pointer_profile()


def test_module_has_no_model_or_ranking_dependency() -> None:
    tree = ast.parse(IMPLEMENTATION_PATH.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not any(any(token in name.casefold() for token in ("sentence_transformers", "torch", "transformers", "embedding", "vector_search", "llm")) for name in imported)
