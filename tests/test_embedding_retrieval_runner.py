"""Query-only vector evaluation using injected callbacks and tracked fixtures.

The shared helpers also support CLI tests. All indexes/configs are synthetic
in-memory documents derived from the existing comparison fixture; no model or
additional fixture file is needed.
"""

from __future__ import annotations

import ast
import builtins
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import random
import socket
import time
from typing import Any
import uuid

import pytest

from threat_hunting.evaluation import (
    EMBEDDING_RETRIEVAL_RUN_CONFIG_SCHEMA_VERSION,
    EmbeddingRetrievalRunnerError,
    parse_embedding_retrieval_json_bytes,
    prepare_embedding_retrieval_run,
    run_embedding_retrieval_comparison,
    serialize_embedding_retrieval_comparison_report,
    validate_embedding_retrieval_run_config,
)
from threat_hunting.evaluation import embedding_retrieval_runner as runner
from threat_hunting.retrieval import validate_vector_index


ROOT = Path(__file__).resolve().parents[1]
INPUT_PATH = ROOT / "tests/fixtures/evaluation/embedding_retrieval_comparison/input_comparison.json"
SOURCE_DATASET_PATH = "fixtures/synthetic_dataset.json"
SOURCE_JUDGMENTS_PATH = "fixtures/synthetic_judgments.json"
SOURCE_CORPUS_PATH = "fixtures/synthetic_corpus.json"
DIMENSION = 6


def _bytes(document: object) -> bytes:
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _synthetic_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, bytes]]:
    fixture = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    dataset = deepcopy(fixture["calibration_dataset"])
    judgments = deepcopy(fixture["retrieval_judgments"])
    corpus = deepcopy(fixture["retrieval_corpus"])
    judgments["source_dataset"].update(path=SOURCE_DATASET_PATH, sha256=sha256(_bytes(dataset)).hexdigest())
    judgments["source_corpus"].update(path=SOURCE_CORPUS_PATH, sha256=sha256(_bytes(corpus)).hexdigest())
    documents = {
        SOURCE_DATASET_PATH: dataset, SOURCE_JUDGMENTS_PATH: judgments,
        SOURCE_CORPUS_PATH: corpus,
    }
    candidates = []
    for index, candidate_id in enumerate(("baseline", "candidate"), start=1):
        descriptor = {
            "provider": "sentence-transformers",
            "model_id": f"organization/synthetic-{candidate_id}",
            "model_revision": str(index) * 40,
            "dimension": DIMENSION,
            "distance_metric": "cosine",
            "normalization": "l2",
            "document_prefix": "" if candidate_id == "baseline" else "passage: ",
            "query_prefix": "" if candidate_id == "baseline" else "query: ",
        }
        build_config_path = f"fixtures/{candidate_id}_build_config.json"
        vector_index_path = f"fixtures/{candidate_id}_vector_index.json"
        build_config = {
            "schema_version": "vector-index-build-config/v1",
            "embedding": deepcopy(descriptor),
            "runtime": {"device": "cpu", "batch_size": 4, "show_progress_bar": False},
        }
        records = []
        for position, chunk in enumerate(sorted(corpus["chunks"], key=lambda item: item["chunk_id"])):
            vector = [float(coordinate == position) for coordinate in range(DIMENSION)]
            records.append({"chunk_id": chunk["chunk_id"], "chunk_type": chunk["chunk_type"], "content_sha256": sha256(chunk["content"].encode("utf-8")).hexdigest(), "vector": vector})
        vector_index = {
            "schema_version": "vector-index/v1",
            "index_id": f"vector-index-synthetic-{candidate_id}",
            "corpus_provenance": {
                "path": SOURCE_CORPUS_PATH, "schema_version": corpus["schema_version"],
                "sha256": sha256(_bytes(corpus)).hexdigest(), "corpus_id": corpus["corpus_id"], "scenario_id": corpus["scenario_id"],
            },
            "embedding": deepcopy(descriptor), "records": records,
            "review": {"review_status": "pending_human_review", "reviewer": None, "reviewed_at": None, "notes": []},
            "warnings": [], "metadata": {"record_count": DIMENSION, "vector_dimension": DIMENSION, "complete_corpus_coverage": True},
        }
        documents[build_config_path] = build_config
        documents[vector_index_path] = vector_index
        candidates.append({
            "candidate_id": candidate_id, "build_config_path": build_config_path,
            "build_config_sha256": sha256(_bytes(build_config)).hexdigest(),
            "vector_index_path": vector_index_path,
            "vector_index_sha256": sha256(_bytes(vector_index)).hexdigest(),
        })
    source_bytes = {path: _bytes(document) for path, document in documents.items()}
    config = {
        "schema_version": "embedding-retrieval-run-config/v1",
        "baseline_candidate_id": "baseline", "ranking_limit": 10,
        "sources": {
            "calibration_dataset": {"path": SOURCE_DATASET_PATH, "sha256": sha256(source_bytes[SOURCE_DATASET_PATH]).hexdigest()},
            "retrieval_judgments": {"path": SOURCE_JUDGMENTS_PATH, "sha256": sha256(source_bytes[SOURCE_JUDGMENTS_PATH]).hexdigest()},
            "retrieval_corpus": {"path": SOURCE_CORPUS_PATH, "sha256": sha256(source_bytes[SOURCE_CORPUS_PATH]).hexdigest()},
        },
        "candidates": candidates,
    }
    return config, documents, source_bytes


class FakeQueryEmbedding:
    def __init__(self, vector: object | None = None, *, error: BaseException | None = None) -> None:
        self.vector = [3.0, 4.0, 0.0, 0.0, 0.0, 0.0] if vector is None else deepcopy(vector)
        self.error = error
        self.calls: list[list[str]] = []

    def __call__(self, texts: list[str]) -> object:
        self.calls.append(list(texts))
        if self.error is not None:
            raise self.error
        return [deepcopy(self.vector) for _ in texts]


def _callbacks(config: dict[str, Any], *, vector: object | None = None) -> dict[str, FakeQueryEmbedding]:
    return {candidate["candidate_id"]: FakeQueryEmbedding(vector) for candidate in config["candidates"]}


def _candidate_documents(config: dict[str, Any], documents: dict[str, Any], candidate_id: str = "baseline") -> tuple[dict[str, Any], dict[str, Any]]:
    descriptor = next(candidate for candidate in config["candidates"] if candidate["candidate_id"] == candidate_id)
    return documents[descriptor["build_config_path"]], documents[descriptor["vector_index_path"]]


def _refresh(config: dict[str, Any], documents: dict[str, Any], source_bytes: dict[str, bytes]) -> None:
    """Bind intentional synthetic mutations to exact bytes, including judgments."""
    dataset_path = config["sources"]["calibration_dataset"]["path"]
    corpus_path = config["sources"]["retrieval_corpus"]["path"]
    judgments_path = config["sources"]["retrieval_judgments"]["path"]
    judgments = documents[judgments_path]
    judgments["source_dataset"]["sha256"] = sha256(_bytes(documents[dataset_path])).hexdigest()
    judgments["source_corpus"]["sha256"] = sha256(_bytes(documents[corpus_path])).hexdigest()
    source_bytes.update({path: _bytes(document) for path, document in documents.items()})
    for source in config["sources"].values():
        source["sha256"] = sha256(source_bytes[source["path"]]).hexdigest()
    for candidate in config["candidates"]:
        candidate["build_config_sha256"] = sha256(source_bytes[candidate["build_config_path"]]).hexdigest()
        candidate["vector_index_sha256"] = sha256(source_bytes[candidate["vector_index_path"]]).hexdigest()


def _rankings(report: dict[str, Any]) -> dict[tuple[str, str], list[tuple[str, float]]]:
    return {(case["case_id"], ranking["candidate_id"]): [(hit["chunk_id"], hit["score"]) for hit in ranking["hits"]] for case in report["cases"] for ranking in case["rankings"]}


def _assert_preflight_failure(config: dict[str, Any], documents: dict[str, Any], source_bytes: dict[str, bytes], *, match: str | None = None) -> None:
    callbacks = _callbacks(config)
    before = deepcopy((config, documents, source_bytes))
    with pytest.raises(EmbeddingRetrievalRunnerError, match=match):
        run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=callbacks)
    assert (config, documents, source_bytes) == before
    assert all(callback.calls == [] for callback in callbacks.values())


def test_valid_config_preflight_plan_is_detached_and_sources_remain_unchanged() -> None:
    config, documents, source_bytes = _synthetic_inputs()
    before = deepcopy((config, documents, source_bytes))
    assert EMBEDDING_RETRIEVAL_RUN_CONFIG_SCHEMA_VERSION == "embedding-retrieval-run-config/v1"
    assert validate_embedding_retrieval_run_config(config) is None
    for candidate in config["candidates"]:
        validate_vector_index(documents[candidate["vector_index_path"]])
    plan = prepare_embedding_retrieval_run(config, documents, source_bytes)
    assert set(plan) == {"config", "dataset", "judgments", "corpus", "candidates"}
    assert [candidate["candidate_id"] for candidate in plan["candidates"]] == ["baseline", "candidate"]
    assert all(set(candidate) == {"candidate_id", "build_config", "vector_index", "embedding", "index_sha256"} for candidate in plan["candidates"])
    plan["corpus"]["chunks"][0]["content"] = "detached"
    plan["config"]["candidates"].clear()
    assert (config, documents, source_bytes) == before


def test_all_queries_run_once_with_one_reused_callback_per_candidate_and_prefix_once() -> None:
    config, documents, source_bytes = _synthetic_inputs()
    callbacks = _callbacks(config)
    report = run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=callbacks)
    queries = [case["query"] for case in documents[SOURCE_DATASET_PATH]["cases"]]
    assert report["metadata"]["case_count"] == 8 and report["metadata"]["candidate_count"] == 2
    assert report["metadata"]["ranking_count"] == 16
    for candidate_id, callback in callbacks.items():
        prefix = _candidate_documents(config, documents, candidate_id)[0]["embedding"]["query_prefix"]
        assert len(callback.calls) == 8
        assert all(len(batch) == 1 for batch in callback.calls)
        assert Counter(batch[0] for batch in callback.calls) == Counter(prefix + query for query in queries)
    for case in report["cases"]:
        for ranking in case["rankings"]:
            assert [hit["score"] for hit in ranking["hits"]] == [0.8, 0.6]
            assert len(ranking["hits"]) <= 10
    assert callbacks["baseline"].vector == [3.0, 4.0, 0.0, 0.0, 0.0, 0.0]


def test_real_vector_retriever_receives_query_only_top10_and_no_filters(monkeypatch) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    callbacks = _callbacks(config)
    original = runner.retrieve_vector
    calls = []

    def checked(corpus, index, query, **kwargs):
        calls.append((query, dict(kwargs)))
        assert query in {case["query"] for case in documents[SOURCE_DATASET_PATH]["cases"]}
        assert kwargs["top_k"] == 10
        assert kwargs.get("chunk_types") is None and kwargs.get("required_dimensions") is None
        assert not set(kwargs).intersection({"category", "language", "expected_decision", "rationale", "relevant_chunk_ids", "judgments"})
        return original(corpus, index, query, **kwargs)

    monkeypatch.setattr(runner, "retrieve_vector", checked)
    run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=callbacks)
    assert len(calls) == 16


def test_judgments_and_case_labels_do_not_change_rankings() -> None:
    config, documents, source_bytes = _synthetic_inputs()
    before = run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=_callbacks(config))
    dataset = documents[SOURCE_DATASET_PATH]
    by_id = {case["case_id"]: case for case in dataset["cases"]}
    direct, paraphrase = by_id["comparison-direct-en"], by_id["comparison-paraphrase-en"]
    direct["category"], paraphrase["category"] = paraphrase["category"], direct["category"]
    for case in dataset["cases"]:
        case["rationale"] = "Different eligibility rationale unused by retrieval."
    judgments = documents[SOURCE_JUDGMENTS_PATH]
    changed = next(case for case in judgments["cases"] if case["case_id"] == "comparison-direct-en")
    changed["relevant_source_pointers"] = ["/facts/0"]
    judgments["metadata"]["total_relevant_pointer_count"] -= 1
    judgments["metadata"]["cases_with_multiple_relevant_chunks"] -= 1
    _refresh(config, documents, source_bytes)
    after = run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=_callbacks(config))
    assert _rankings(before) == _rankings(after)
    assert before["cases"] != after["cases"]


def test_metric_core_is_called_only_after_all_rankings_are_complete(monkeypatch) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    callbacks = _callbacks(config)
    original = runner.compare_embedding_retrieval_rankings
    calls = []

    def checked(*args, **kwargs):
        assert all(len(callback.calls) == 8 for callback in callbacks.values())
        calls.append((args, kwargs))
        assert all(run["ranking_limit"] == 10 and len(run["rankings"]) == 8 for run in args[3])
        return original(*args, **kwargs)

    monkeypatch.setattr(runner, "compare_embedding_retrieval_rankings", checked)
    report = run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=callbacks)
    assert len(calls) == 1 and report["review"]["review_status"] == "pending_human_review"


def test_tied_cosine_scores_use_stable_chunk_id_order() -> None:
    config, documents, source_bytes = _synthetic_inputs()
    report = run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=_callbacks(config, vector=[1.0] * DIMENSION))
    expected_ids = sorted(chunk["chunk_id"] for chunk in documents[SOURCE_CORPUS_PATH]["chunks"])
    for case in report["cases"]:
        for ranking in case["rankings"]:
            assert [hit["chunk_id"] for hit in ranking["hits"]] == expected_ids
            assert {hit["score"] for hit in ranking["hits"]} == {0.40824829}


def test_success_is_immutable_detached_and_byte_deterministic() -> None:
    config, documents, source_bytes = _synthetic_inputs()
    original = deepcopy((config, documents, source_bytes))
    first = run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=_callbacks(config))
    second = run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=_callbacks(config))
    assert serialize_embedding_retrieval_comparison_report(first) == serialize_embedding_retrieval_comparison_report(second)
    first["cases"][0]["rankings"][0]["hits"].clear()
    first["candidates"][0]["embedding"]["model_id"] = "detached"
    assert (config, documents, source_bytes) == original
    assert second["cases"][0]["rankings"][0]["hits"]


@pytest.mark.parametrize("path", [(), ("sources",), ("sources", "calibration_dataset"), ("sources", "retrieval_judgments"), ("sources", "retrieval_corpus"), ("candidates", 0)])
@pytest.mark.parametrize("operation", ["missing", "extra"])
def test_strict_config_fields_at_every_object(path: tuple, operation: str) -> None:
    config, _, _ = _synthetic_inputs()
    target = config
    for component in path:
        target = target[component]
    if operation == "missing":
        del target[next(iter(target))]
    else:
        target["unexpected"] = None
    with pytest.raises(EmbeddingRetrievalRunnerError):
        validate_embedding_retrieval_run_config(config)


@pytest.mark.parametrize("mutation", ["missing_baseline", "one_candidate", "duplicate_candidate", "duplicate_index_path", "unsorted_candidates", "ranking_limit", "uppercase_hash", "unsafe_path", "absolute_path"])
def test_config_identity_sort_limit_and_safe_path_guards(mutation: str) -> None:
    config, _, _ = _synthetic_inputs()
    if mutation == "missing_baseline":
        config["baseline_candidate_id"] = "missing"
    elif mutation == "one_candidate":
        config["candidates"].pop()
    elif mutation == "duplicate_candidate":
        config["candidates"][1]["candidate_id"] = config["candidates"][0]["candidate_id"]
    elif mutation == "duplicate_index_path":
        config["candidates"][1]["vector_index_path"] = config["candidates"][0]["vector_index_path"]
    elif mutation == "unsorted_candidates":
        config["candidates"].reverse()
    elif mutation == "ranking_limit":
        config["ranking_limit"] = True
    elif mutation == "uppercase_hash":
        config["sources"]["calibration_dataset"]["sha256"] = "A" * 64
    else:
        config["candidates"][0]["build_config_path"] = "../outside.json" if mutation == "unsafe_path" else "C:/private/config.json"
    with pytest.raises(EmbeddingRetrievalRunnerError):
        validate_embedding_retrieval_run_config(config)


@pytest.mark.parametrize("limit", [9, 11, 10.0])
def test_ranking_limit_must_be_exact_integer_ten(limit: object) -> None:
    config, _, _ = _synthetic_inputs()
    config["ranking_limit"] = limit
    with pytest.raises(EmbeddingRetrievalRunnerError):
        validate_embedding_retrieval_run_config(config)


@pytest.mark.parametrize("field", ["query", "expected_answer", "generated_answer", "model_output", "credential", "token"])
def test_config_recursive_forbidden_fields(field: str) -> None:
    config, _, _ = _synthetic_inputs()
    config["sources"]["calibration_dataset"]["unknown"] = [{field: "copied content"}]
    with pytest.raises(EmbeddingRetrievalRunnerError):
        validate_embedding_retrieval_run_config(config)


@pytest.mark.parametrize("value", ["confirmed", "CONFIRMED", " ConFiRmEd "])
def test_config_recursive_confirmed_guard(value: str) -> None:
    config, _, _ = _synthetic_inputs()
    config["candidates"][0]["candidate_id"] = value
    with pytest.raises(EmbeddingRetrievalRunnerError):
        validate_embedding_retrieval_run_config(config)


def test_json_parser_preserves_utf8_and_does_not_open_provenance_label() -> None:
    config, _, _ = _synthetic_inputs()
    config["note"] = "Dữ liệu giả lập"
    parsed = parse_embedding_retrieval_json_bytes(_bytes(config), source_path="fixtures/config.json")
    assert parsed == config and parsed["note"] == "Dữ liệu giả lập"


@pytest.mark.parametrize("payload", [b'{"a":1,"a":2}', b'{"nested":{"a":1,"a":2}}', b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}', b'{"value":1e999}', b'\xff', b'{"broken":', b'{"value":"\\ud800"}'])
def test_json_parser_wraps_duplicate_nonfinite_syntax_and_encoding_errors(payload: bytes) -> None:
    with pytest.raises(EmbeddingRetrievalRunnerError) as error:
        parse_embedding_retrieval_json_bytes(payload, source_path="fixtures/bad.json")
    assert "fixtures/bad.json" in str(error.value)


@pytest.mark.parametrize("source", ["dataset", "judgments", "corpus", "build_config", "vector_index"])
def test_source_hash_mismatch_fails_before_any_query(source: str) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    if source in {"dataset", "judgments", "corpus"}:
        key = {"dataset": "calibration_dataset", "judgments": "retrieval_judgments", "corpus": "retrieval_corpus"}[source]
        config["sources"][key]["sha256"] = "0" * 64
    else:
        config["candidates"][0][f"{source}_sha256"] = "0" * 64
    _assert_preflight_failure(config, documents, source_bytes)


@pytest.mark.parametrize("mutation", ["missing_document", "extra_document", "missing_bytes", "extra_bytes", "non_bytes", "parsed_mismatch"])
def test_source_maps_and_exact_byte_parse_integrity(mutation: str) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    if mutation == "missing_document":
        documents.pop(SOURCE_DATASET_PATH)
    elif mutation == "extra_document":
        documents["fixtures/extra.json"] = {}
    elif mutation == "missing_bytes":
        source_bytes.pop(SOURCE_DATASET_PATH)
    elif mutation == "extra_bytes":
        source_bytes["fixtures/extra.json"] = b"{}"
    elif mutation == "non_bytes":
        source_bytes[SOURCE_DATASET_PATH] = bytearray(source_bytes[SOURCE_DATASET_PATH])
    else:
        documents[SOURCE_DATASET_PATH]["cases"][0]["query"] += " Changed only parsed document."
    _assert_preflight_failure(config, documents, source_bytes)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra"])
def test_changed_dataset_case_coverage_fails_before_queries_with_repinned_bytes(mutation: str) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    dataset = documents[SOURCE_DATASET_PATH]
    if mutation == "missing":
        dataset["cases"].pop()
    else:
        new_case = deepcopy(dataset["cases"][-1])
        new_case["query"] = "An additional synthetic query outside the original case list?"
        if mutation == "extra":
            new_case["case_id"] = "comparison-unrelated-extra"
        dataset["cases"].append(new_case)
    dataset["metadata"]["case_count"] = len(dataset["cases"])
    for count_field, case_field in (("category_counts", "category"), ("language_counts", "language"), ("decision_counts", "expected_decision")):
        dataset["metadata"][count_field] = {name: sum(case[case_field] == name for case in dataset["cases"]) for name in dataset["metadata"][count_field]}
    # Hashes represent the actual changed source. Existing judgment case IDs
    # remain untouched, so validation must reject stale coverage before work.
    _refresh(config, documents, source_bytes)
    _assert_preflight_failure(config, documents, source_bytes)


@pytest.mark.parametrize("mutation", ["scenario", "corpus_id", "corpus_hash", "corpus_path", "coverage_false", "missing_record", "unknown_record", "record_type", "content_hash", "descriptor", "zero_vector"])
def test_index_referential_integrity_is_checked_before_callbacks(mutation: str) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    _, index = _candidate_documents(config, documents)
    if mutation in {"scenario", "corpus_id", "corpus_hash", "corpus_path"}:
        field = {"scenario": "scenario_id", "corpus_id": "corpus_id", "corpus_hash": "sha256", "corpus_path": "path"}[mutation]
        index["corpus_provenance"][field] = "0" * 64 if mutation == "corpus_hash" else "different"
    elif mutation == "coverage_false":
        index["metadata"]["complete_corpus_coverage"] = False
    elif mutation == "missing_record":
        index["records"].pop()
        index["metadata"]["record_count"] -= 1
    elif mutation == "unknown_record":
        index["records"][0]["chunk_id"] = "unknown-chunk"
    elif mutation == "record_type":
        index["records"][0]["chunk_type"] = "fact"
    elif mutation == "content_hash":
        index["records"][0]["content_sha256"] = "0" * 64
    elif mutation == "descriptor":
        index["embedding"]["query_prefix"] = "wrong-prefix: "
    else:
        index["records"][0]["vector"] = [0.0] * DIMENSION
    _refresh(config, documents, source_bytes)
    _assert_preflight_failure(config, documents, source_bytes)


def test_duplicate_index_ids_in_distinct_files_fail_before_callbacks() -> None:
    config, documents, source_bytes = _synthetic_inputs()
    _, baseline = _candidate_documents(config, documents)
    _, candidate = _candidate_documents(config, documents, "candidate")
    candidate["index_id"] = baseline["index_id"]
    _refresh(config, documents, source_bytes)
    _assert_preflight_failure(config, documents, source_bytes, match="duplicate index_id")


def test_declared_corpus_chunk_count_is_recomputed_before_callbacks() -> None:
    config, documents, source_bytes = _synthetic_inputs()
    documents[SOURCE_CORPUS_PATH]["metadata"]["chunk_count"] += 1
    _refresh(config, documents, source_bytes)
    for candidate in config["candidates"]:
        documents[candidate["vector_index_path"]]["corpus_provenance"]["sha256"] = config["sources"]["retrieval_corpus"]["sha256"]
    _refresh(config, documents, source_bytes)
    _assert_preflight_failure(config, documents, source_bytes, match="chunk_count")


@pytest.mark.parametrize("mutation", ["schema", "revision", "cpu", "progress", "normalization", "dimension"])
def test_invalid_build_configs_fail_before_callbacks(mutation: str) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    build_config, _ = _candidate_documents(config, documents)
    if mutation == "schema":
        build_config["schema_version"] = "wrong-schema"
    elif mutation == "revision":
        build_config["embedding"]["model_revision"] = "main"
    elif mutation == "cpu":
        build_config["runtime"]["device"] = "cuda"
    elif mutation == "progress":
        build_config["runtime"]["show_progress_bar"] = True
    elif mutation == "normalization":
        build_config["embedding"]["normalization"] = "unit"
    else:
        build_config["embedding"]["dimension"] = DIMENSION + 1
    _refresh(config, documents, source_bytes)
    _assert_preflight_failure(config, documents, source_bytes)


@pytest.mark.parametrize("mutation", ["missing_callback", "extra_callback", "noncallable"])
def test_callback_mapping_matches_candidates_exactly(mutation: str) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    callbacks = _callbacks(config)
    if mutation == "missing_callback":
        callbacks.pop("candidate")
    elif mutation == "extra_callback":
        callbacks["extra"] = FakeQueryEmbedding()
    else:
        callbacks["candidate"] = None
    with pytest.raises(EmbeddingRetrievalRunnerError):
        run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=callbacks)
    assert all(callback.calls == [] for callback in callbacks.values() if isinstance(callback, FakeQueryEmbedding))


@pytest.mark.parametrize("batch", [None, [], [[]], [[1.0]], [[True] * DIMENSION], [["1"] * DIMENSION], [[None] * DIMENSION], [[float("nan")] * DIMENSION], [[float("inf")] * DIMENSION], [[0.0] * DIMENSION]])
def test_invalid_query_embedding_batches_are_domain_errors_without_input_mutation(batch: object) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    original = deepcopy((config, documents, source_bytes))
    callbacks = _callbacks(config)
    callbacks["baseline"] = lambda texts: batch
    with pytest.raises(EmbeddingRetrievalRunnerError):
        run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=callbacks)
    assert (config, documents, source_bytes) == original


def test_callback_exception_is_wrapped_with_cause_and_preserves_inputs() -> None:
    config, documents, source_bytes = _synthetic_inputs()
    original = deepcopy((config, documents, source_bytes))
    callbacks = _callbacks(config)
    callbacks["baseline"] = FakeQueryEmbedding(error=RuntimeError("synthetic model failure"))
    with pytest.raises(EmbeddingRetrievalRunnerError, match="synthetic model failure") as error:
        run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=callbacks)
    assert error.value.__cause__ is not None
    assert (config, documents, source_bytes) == original


@pytest.mark.parametrize("score", [float("nan"), float("inf")])
def test_invalid_returned_scores_are_rejected_by_core_and_wrapped(monkeypatch, score: float) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    original_inputs = deepcopy((config, documents, source_bytes))
    original_retriever = runner.retrieve_vector

    def corrupt_score(*args, **kwargs):
        result = original_retriever(*args, **kwargs)
        result["hits"][0]["score"] = score
        return result

    monkeypatch.setattr(runner, "retrieve_vector", corrupt_score)
    with pytest.raises(EmbeddingRetrievalRunnerError):
        run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=_callbacks(config))
    assert (config, documents, source_bytes) == original_inputs


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
def test_process_control_exceptions_are_not_caught(exception: type[BaseException]) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    callbacks = _callbacks(config)
    callbacks["baseline"] = FakeQueryEmbedding(error=exception("stop"))
    with pytest.raises(exception):
        run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=callbacks)


def test_runner_performs_no_io_network_clock_random_or_uuid(monkeypatch) -> None:
    config, documents, source_bytes = _synthetic_inputs()
    callbacks = _callbacks(config)

    def forbidden(*args, **kwargs):
        raise AssertionError("In-memory runner attempted external or nondeterministic operation")

    for name in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
        monkeypatch.setattr(Path, name, forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    for name in ("time", "monotonic", "perf_counter"):
        monkeypatch.setattr(time, name, forbidden)
    monkeypatch.setattr(random, "random", forbidden)
    monkeypatch.setattr(uuid, "uuid4", forbidden)
    report = run_embedding_retrieval_comparison(config, documents, source_bytes, embedding_callbacks=callbacks)
    assert report["metadata"]["ranking_count"] == 16


def test_runner_does_not_import_models_other_retrievers_or_duplicate_metric_formulas() -> None:
    path = ROOT / "src/threat_hunting/evaluation/embedding_retrieval_runner.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
    modules += [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any(any(token in module.casefold() for token in ("sentence_transformers", "torch", "transformers", "embedding_backend", "lexical", "hybrid", "graphrag", "datetime", "random", "uuid")) for module in modules)
    assert not any(isinstance(node, ast.Attribute) and node.attr in {"log2", "log", "log10"} for node in ast.walk(tree))
