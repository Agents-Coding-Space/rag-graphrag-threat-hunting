"""Vector retrieval contracts using existing fixtures and fake embeddings only."""

from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path

import pytest

from threat_hunting.retrieval import (
    VectorRetrievalError, load_retrieval_corpus, load_vector_index, retrieve_vector,
)
from threat_hunting.retrieval import vector_search

FIXTURES = Path(__file__).parent / "fixtures/retrieval"
CORPUS_PATH = FIXTURES / "builder/expected_retrieval_corpus.json"
INDEX_PATH = FIXTURES / "vector_builder/expected_vector_index.json"


@pytest.fixture
def artifacts():
    corpus = load_retrieval_corpus(CORPUS_PATH)
    index = load_vector_index(INDEX_PATH)
    digest = hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()
    assert digest == index["corpus_provenance"]["sha256"]
    return corpus, index, digest


def search(artifacts, vector=None, **kwargs):
    corpus, index, digest = artifacts
    return retrieve_vector(
        corpus, index, kwargs.pop("query", "Hành vi?"),
        corpus_sha256=kwargs.pop("corpus_sha256", digest),
        embed_query=kwargs.pop("embed_query", lambda texts: [vector or [1, 0, 0]]),
        **kwargs,
    )


def set_vectors(index, vectors):
    for position, record in enumerate(index["records"]):
        record["vector"] = list(vectors[position % len(vectors)])


def test_ranking_precision_metadata_and_json_readback(artifacts):
    corpus, index, _ = artifacts
    result = search(artifacts, top_k=50)
    expected = sorted(
        [(round(record["vector"][0] / math.hypot(*record["vector"]), 8), record["chunk_id"])
         for record in index["records"]], key=lambda item: (-item[0], item[1]),
    )
    assert [(hit["score"], hit["chunk"]["chunk_id"]) for hit in result["hits"]] == expected
    assert [hit["rank"] for hit in result["hits"]] == list(range(1, 16))
    assert result["schema_version"] == "retrieval-result/v1"
    assert result["retrieval_method"] == "vector-cosine/v1"
    assert result["metadata"] == {
        "index_id": index["index_id"], "total_chunks": 15, "eligible_chunks": 15,
        "scored_vectors": 15, "returned_hits": 15, "dimension": 3,
        "normalization": "none", "score_precision": 8,
        "score_interpretation": "cosine_similarity_not_probability",
    }
    assert result["corpus_id"] == corpus["corpus_id"]
    assert result["scenario_id"] == corpus["scenario_id"]
    assert json.loads(json.dumps(result, allow_nan=False)) == result


def test_tie_break_and_record_order_independence(artifacts):
    set_vectors(artifacts[1], [[1, 0, 0]])
    result = search(artifacts)
    artifacts[1]["records"].reverse()
    assert search(artifacts) == result
    assert [hit["chunk"]["chunk_id"] for hit in result["hits"]] == sorted(
        record["chunk_id"] for record in artifacts[1]["records"]
    )[:5]


def test_rounding_precedes_tie_break(artifacts):
    index = artifacts[1]
    set_vectors(index, [[1, 1, 0]])
    # A slightly higher raw cosine still ties at eight decimal places.
    index["records"][-1]["vector"] = [1.000000001, 1, 0]
    result = search(artifacts, top_k=50)
    assert all(hit["score"] == 0.70710678 for hit in result["hits"])
    assert [hit["chunk"]["chunk_id"] for hit in result["hits"]] == sorted(
        record["chunk_id"] for record in index["records"]
    )


def test_search_exception_wrapped_with_context(artifacts):
    def broken_filter():
        raise RuntimeError("synthetic filter failure")
        yield "evidence"

    with pytest.raises(VectorRetrievalError, match="Vector retrieval failed.*filter"):
        search(artifacts, chunk_types=broken_filter())


def test_l2_record_rounding_drift_uses_true_cosine(artifacts):
    artifacts[1]["embedding"]["normalization"] = "l2"
    set_vectors(artifacts[1], [[1.0000005, 0, 0]])
    assert search(artifacts, vector=[20, 0, 0])["hits"][0]["score"] == 1


def test_prefix_once_original_query_and_no_mutation(artifacts):
    corpus, index, _ = artifacts
    before = deepcopy(artifacts)
    batch = [[2.0, 3.0, 4.0]]
    batch_before = deepcopy(batch)
    types = ["relationship", "evidence"]
    calls = []

    def callback(texts):
        calls.append(texts)
        return batch

    result = search(artifacts, query="  câu hỏi  ", embed_query=callback, chunk_types=types)
    assert calls == [[index["embedding"]["query_prefix"] + "  câu hỏi  "]]
    assert result["query"]["text"] == "  câu hỏi  "
    assert result["query"]["filters"]["chunk_types"] == sorted(types)
    assert artifacts == before and batch == batch_before
    assert types == ["relationship", "evidence"]
    original = next(chunk for chunk in corpus["chunks"] if chunk["chunk_id"] == result["hits"][0]["chunk"]["chunk_id"])
    assert result["hits"][0]["chunk"] == original
    result["hits"][0]["chunk"]["source_references"].clear()
    result["hits"][0]["chunk"]["content"] = "changed"
    assert artifacts == before


@pytest.mark.parametrize("normalization", ["none", "l2"])
def test_normalizations(artifacts, normalization):
    index = artifacts[1]
    index["embedding"]["normalization"] = normalization
    set_vectors(index, [[0.6, 0.8, 0], [-1, 0, 0], [0, 0, 1]])
    result = search(artifacts, vector=[3, 4, 0], top_k=50)
    assert all(hit["score"] == 1 for hit in result["hits"])
    assert len(result["hits"]) == 5
    assert result["metadata"]["normalization"] == normalization


@pytest.mark.parametrize("vector", [[1e308, 1e308, 0], [1e-320, 1e-320, 0]])
def test_extreme_finite_vectors(artifacts, vector):
    set_vectors(artifacts[1], [vector])
    assert search(artifacts, vector=vector)["hits"][0]["score"] == 1.0


def test_type_and_all_dimension_filters(artifacts):
    corpus = artifacts[0]
    target = next(chunk for chunk in corpus["chunks"] if chunk["queryable_dimensions"])
    dimensions = list(reversed(target["queryable_dimensions"]))
    result = search(artifacts, chunk_types=(target["chunk_type"],), required_dimensions=iter(dimensions), top_k=50)
    expected = {chunk["chunk_id"] for chunk in corpus["chunks"]
                if chunk["chunk_type"] == target["chunk_type"]
                and set(dimensions).issubset(chunk["queryable_dimensions"])}
    assert {hit["chunk"]["chunk_id"] for hit in result["hits"]} == expected
    assert result["query"]["filters"]["required_dimensions"] == sorted(dimensions)


def test_empty_eligible_still_calls_callback_once(artifacts):
    calls = []

    def callback(texts):
        calls.append(texts)
        return [[1, 0, 0]]

    result = search(artifacts, chunk_types=[], embed_query=callback)
    assert len(calls) == 1
    assert result["hits"] == [] and result["metadata"]["scored_vectors"] == 0
    assert "No eligible" in result["warnings"][-1]


@pytest.mark.parametrize("vector", [[-1, 0, 0], [0, 0, 1], [1e-10, 1, 0]])
def test_no_positive_or_rounding_to_zero(artifacts, vector):
    set_vectors(artifacts[1], [[1, 0, 0]])
    result = search(artifacts, vector=vector)
    assert result["hits"] == []
    assert "No positive" in result["warnings"][-1]


@pytest.mark.parametrize("top_k", [True, False, 0, -1, 1.5, "5", None])
def test_invalid_top_k(artifacts, top_k):
    with pytest.raises(VectorRetrievalError, match="top_k"):
        search(artifacts, top_k=top_k)


@pytest.mark.parametrize("query", ["", " \t\n", None, 12, True])
def test_invalid_query(artifacts, query):
    with pytest.raises(VectorRetrievalError, match="query"):
        search(artifacts, query=query)


@pytest.mark.parametrize("name", ["chunk_types", "required_dimensions"])
@pytest.mark.parametrize("value", ["evidence", b"evidence", {}, 4, [True], [None], [""], ["bogus"]])
def test_invalid_filters(artifacts, name, value):
    with pytest.raises(VectorRetrievalError, match=name):
        search(artifacts, **{name: value})


@pytest.mark.parametrize("name", ["chunk_types", "required_dimensions"])
def test_duplicate_filters(artifacts, name):
    value = "evidence" if name == "chunk_types" else artifacts[0]["queryable_dimensions"][0]
    with pytest.raises(VectorRetrievalError, match="duplicate"):
        search(artifacts, **{name: [value, value]})


@pytest.mark.parametrize("batch", [None, [], [[1, 0, 0], [1, 0, 0]], "bad", [1], [None], ["bad"], [[1, 2]], [[1, 2, 3, 4]], [[True, 0, 0]], [["1", 0, 0]], [[None, 0, 0]], [[float("nan"), 0, 0]], [[float("inf"), 0, 0]], [[-float("inf"), 0, 0]], [[0, 0, 0]], [[10**1000, 0, 0]]])
def test_invalid_callback_output(artifacts, batch):
    with pytest.raises(VectorRetrievalError):
        search(artifacts, embed_query=lambda texts: batch)


def test_callback_exception_and_noncallable(artifacts):
    def failing(texts):
        raise RuntimeError("synthetic embedding failure")

    with pytest.raises(VectorRetrievalError, match="callback failed.*synthetic"):
        search(artifacts, embed_query=failing)
    with pytest.raises(VectorRetrievalError, match="callable"):
        search(artifacts, embed_query=None)


@pytest.mark.parametrize("digest", [None, True, "bad", "g" * 64, "0" * 64])
def test_invalid_or_mismatched_corpus_hash(artifacts, digest):
    with pytest.raises(VectorRetrievalError, match="corpus_sha256"):
        search(artifacts, corpus_sha256=digest)


@pytest.mark.parametrize("field", ["corpus_id", "scenario_id"])
def test_mismatched_identity(artifacts, field):
    artifacts[1]["corpus_provenance"][field] = "different"
    with pytest.raises(VectorRetrievalError, match=field):
        search(artifacts)


@pytest.mark.parametrize("kind", ["corpus", "index", "metric", "normalization", "duplicate_record", "missing_field", "record_dimension", "record_nan", "record_bool"])
def test_schema_validation_before_callback(artifacts, kind):
    corpus, index, _ = artifacts
    if kind == "corpus":
        corpus["schema_version"] = "bad"
    elif kind == "index":
        index["schema_version"] = "bad"
    elif kind == "metric":
        index["embedding"]["distance_metric"] = "euclidean"
    elif kind == "normalization":
        index["embedding"]["normalization"] = "bad"
    elif kind == "duplicate_record":
        index["records"].append(deepcopy(index["records"][0]))
        index["metadata"]["record_count"] += 1
    elif kind == "missing_field":
        del index["records"][0]["content_sha256"]
    elif kind == "record_dimension":
        index["records"][0]["vector"] = [1]
    else:
        index["records"][0]["vector"][0] = float("nan") if kind == "record_nan" else True
    calls = []
    with pytest.raises(VectorRetrievalError, match="Invalid"):
        search(artifacts, embed_query=lambda texts: calls.append(texts))
    assert not calls


@pytest.mark.parametrize("kind", ["unknown", "extra", "type", "hash", "missing"])
@pytest.mark.parametrize("complete", [True, False])
def test_referential_integrity_and_coverage(artifacts, kind, complete):
    index = artifacts[1]
    index["metadata"]["complete_corpus_coverage"] = complete
    if kind == "unknown":
        index["records"][0]["chunk_id"] = "nonexistent"
    elif kind == "extra":
        record = deepcopy(index["records"][0])
        record["chunk_id"] = "extra"
        index["records"].append(record)
    elif kind == "type":
        index["records"][0]["chunk_type"] = "evidence"
    elif kind == "hash":
        index["records"][0]["content_sha256"] = "0" * 64
    else:
        index["records"].pop()
    index["metadata"]["record_count"] = len(index["records"])
    if kind == "missing" and not complete:
        assert search(artifacts, top_k=50)["metadata"]["scored_vectors"] == 14
    else:
        with pytest.raises(VectorRetrievalError):
            search(artifacts)


def test_empty_incomplete_index(artifacts):
    index = artifacts[1]
    index["records"] = []
    index["metadata"].update(record_count=0, complete_corpus_coverage=False)
    result = search(artifacts)
    assert result["hits"] == [] and "No indexed vectors" in result["warnings"][-1]


def test_zero_record_only_rejected_if_scored(artifacts):
    record = artifacts[1]["records"][0]
    record["vector"] = [0, 0, 0]
    with pytest.raises(VectorRetrievalError, match="zero vector"):
        search(artifacts)
    assert search(artifacts, chunk_types=[])["hits"] == []
    artifacts[1]["embedding"]["normalization"] = "l2"
    with pytest.raises(VectorRetrievalError, match="Invalid Vector Index"):
        search(artifacts, chunk_types=[])


def test_no_confirmed_status_or_generated_answer(artifacts):
    result = search(artifacts)

    def check(value):
        if isinstance(value, dict):
            assert not {"answer", "confidence", "hybrid_score", "llm_output"}.intersection(value)
            for key, item in value.items():
                if "status" in key:
                    assert item != "confirmed"
                check(item)
        elif isinstance(value, list):
            for item in value:
                check(item)

    check(result)


def test_cosine_clamp_and_failure(monkeypatch):
    monkeypatch.setattr(vector_search.math, "fsum", lambda values: 1 + 5e-13)
    assert vector_search._cosine([1], [1], "test") == 1
    monkeypatch.setattr(vector_search.math, "fsum", lambda values: -1 - 5e-13)
    assert vector_search._cosine([1], [1], "test") == -1
    for invalid in (1.01, -1.01, float("nan"), float("inf")):
        monkeypatch.setattr(vector_search.math, "fsum", lambda values: invalid)
        with pytest.raises(VectorRetrievalError, match="invalid cosine"):
            vector_search._cosine([1], [1], "test")


def test_production_structural_smoke_without_model():
    root = Path(__file__).resolve().parents[1]
    corpus_path = root / "outputs/retrieval/mshta-powershell/retrieval_corpus.json"
    index_path = root / "outputs/retrieval/mshta-powershell/vector_index.json"
    if not corpus_path.exists() or not index_path.exists():
        pytest.skip("Production artifacts are optional local, untracked files")
    paths = [corpus_path, index_path, CORPUS_PATH, INDEX_PATH]
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    assert before[corpus_path] == "53abc9e44c03c46aaf024cdb79b61ad3381d50feb82689f27074151381b9d0f3"
    assert before[index_path] == "94705156295740dfbf835a867c031213975481ec0bee68275c886be9d8cf2116"
    corpus = load_retrieval_corpus(corpus_path)
    index = load_vector_index(index_path)
    record = index["records"][0]
    vector = deepcopy(record["vector"])
    result = retrieve_vector(corpus, index, "structural smoke", corpus_sha256=before[corpus_path], embed_query=lambda texts: [vector])
    assert result == retrieve_vector(corpus, index, "structural smoke", corpus_sha256=before[corpus_path], embed_query=lambda texts: [vector])
    assert result["hits"][0]["chunk"]["chunk_id"] == record["chunk_id"]
    assert result["hits"][0]["score"] == pytest.approx(1.0, abs=1e-8)
    assert vector == record["vector"]
    assert before == {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
