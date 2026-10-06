"""Hybrid retrieval contracts using synthetic fixtures and fake embeddings only."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.retrieval import (
    HybridRetrievalError,
    LexicalRetrievalError,
    VectorRetrievalError,
    load_retrieval_corpus,
    load_vector_index,
    retrieve_hybrid,
    retrieve_lexical,
    retrieve_vector,
)
from threat_hunting.retrieval import hybrid


FIXTURES = Path(__file__).parent / "fixtures/retrieval"
CORPUS_PATH = FIXTURES / "builder/expected_retrieval_corpus.json"
INDEX_PATH = FIXTURES / "vector_builder/expected_vector_index.json"


@pytest.fixture
def artifacts() -> tuple[dict[str, Any], dict[str, Any], str]:
    corpus = load_retrieval_corpus(CORPUS_PATH)
    index = load_vector_index(INDEX_PATH)
    digest = hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()
    assert digest == index["corpus_provenance"]["sha256"]
    return corpus, index, digest


def _search(
    artifacts: tuple[dict[str, Any], dict[str, Any], str],
    vector: list[float] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    corpus, index, digest = artifacts
    return retrieve_hybrid(
        corpus,
        index,
        kwargs.pop("query", "synthetic"),
        corpus_sha256=kwargs.pop("corpus_sha256", digest),
        embed_query=kwargs.pop(
            "embed_query", lambda texts: [vector if vector is not None else [1, 0, 0]]
        ),
        **kwargs,
    )


def _set_vectors(index: dict[str, Any], vector: list[float]) -> None:
    for record in index["records"]:
        record["vector"] = list(vector)


def _component_results(
    artifacts: tuple[dict[str, Any], dict[str, Any], str],
    *,
    candidate_k: int = 20,
) -> tuple[dict[str, Any], dict[str, Any]]:
    corpus, index, digest = artifacts
    return (
        retrieve_lexical(corpus, "synthetic", top_k=candidate_k),
        retrieve_vector(
            corpus,
            index,
            "synthetic",
            corpus_sha256=digest,
            embed_query=lambda texts: [[1, 0, 0]],
            top_k=candidate_k,
        ),
    )


def _replace_hits(
    result: dict[str, Any],
    chunks: list[dict[str, Any]],
    scores: list[float] | None = None,
) -> None:
    template = deepcopy(result["hits"][0])
    result["hits"] = []
    for rank, chunk in enumerate(chunks, start=1):
        hit = deepcopy(template)
        hit.update(
            rank=rank,
            score=scores[rank - 1] if scores is not None else 1.0 / rank,
            chunk=deepcopy(chunk),
        )
        result["hits"].append(hit)
    result["metadata"]["returned_hits"] = len(chunks)


def _patch_components(
    monkeypatch: pytest.MonkeyPatch,
    lexical: object,
    vector: object,
) -> None:
    monkeypatch.setattr(hybrid, "retrieve_lexical", lambda *args, **kwargs: lexical)
    monkeypatch.setattr(hybrid, "retrieve_vector", lambda *args, **kwargs: vector)


def _signature(result: dict[str, Any]) -> list[tuple[str, float]]:
    return [(hit["chunk"]["chunk_id"], hit["score"]) for hit in result["hits"]]


def _walk(value: object):
    yield value
    if isinstance(value, dict):
        for nested in value.values():
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested)


def _assert_deep_copy(copy: object, original: object) -> None:
    assert copy == original
    if isinstance(original, dict):
        assert copy is not original
        for key, nested in original.items():
            _assert_deep_copy(copy[key], nested)
    elif isinstance(original, list):
        assert copy is not original
        for copied_item, original_item in zip(copy, original, strict=True):
            _assert_deep_copy(copied_item, original_item)


def test_public_exports_and_result_contract(artifacts) -> None:
    result = _search(artifacts)
    corpus, _, _ = artifacts
    lexical, vector = _component_results(artifacts)
    union = {
        hit["chunk"]["chunk_id"]
        for component in (lexical, vector)
        for hit in component["hits"]
    }

    assert retrieve_hybrid is hybrid.retrieve_hybrid
    assert HybridRetrievalError is hybrid.HybridRetrievalError
    assert result["schema_version"] == "retrieval-result/v1"
    assert result["retrieval_method"] == "hybrid-rrf/v1"
    assert result["corpus_id"] == corpus["corpus_id"]
    assert result["scenario_id"] == corpus["scenario_id"]
    assert result["query"] == {
        "text": "synthetic",
        "normalized_terms": lexical["query"]["normalized_terms"],
        "top_k": 5,
        "candidate_k": 20,
        "filters": {"chunk_types": None, "required_dimensions": None},
    }
    assert result["metadata"] == {
        "total_chunks": len(corpus["chunks"]),
        "eligible_chunks": len(corpus["chunks"]),
        "returned_hits": len(result["hits"]),
        "lexical_candidate_count": len(lexical["hits"]),
        "vector_candidate_count": len(vector["hits"]),
        "union_candidate_count": len(union),
        "rrf_k": 60,
        "score_precision": 12,
        "score_interpretation": "reciprocal_rank_fusion_not_probability",
        "component_methods": {"lexical": "bm25/v1", "vector": "vector-cosine/v1"},
    }


def test_rrf_overlap_single_branch_components_and_deduplication(
    artifacts, monkeypatch
) -> None:
    lexical, vector = _component_results(artifacts)
    target, lexical_only, vector_only = artifacts[0]["chunks"][:3]
    _replace_hits(lexical, [target, lexical_only], [8.37555764, 2.0])
    _replace_hits(vector, [vector_only, target], [0.9, 0.31735063])
    before = deepcopy((lexical, vector))
    _patch_components(monkeypatch, lexical, vector)

    result = _search(artifacts, top_k=20)
    by_id = {hit["chunk"]["chunk_id"]: hit for hit in result["hits"]}
    supported = by_id[target["chunk_id"]]

    assert len(result["hits"]) == len(by_id) == 3
    assert supported["rank"] == 1
    assert supported["score"] == round(1 / 61 + 1 / 62, 12)
    assert supported["components"] == {
        "lexical": {"rank": 1, "score": 8.37555764, "contribution": round(1 / 61, 12)},
        "vector": {"rank": 2, "score": 0.31735063, "contribution": round(1 / 62, 12)},
    }
    assert by_id[lexical_only["chunk_id"]]["components"]["vector"] is None
    assert by_id[lexical_only["chunk_id"]]["score"] == round(1 / 62, 12)
    assert by_id[vector_only["chunk_id"]]["components"]["lexical"] is None
    assert by_id[vector_only["chunk_id"]]["score"] == round(1 / 61, 12)
    assert result["metadata"]["lexical_candidate_count"] == 2
    assert result["metadata"]["vector_candidate_count"] == 2
    assert result["metadata"]["union_candidate_count"] == 3
    assert (lexical, vector) == before


def test_rrf_uses_ranks_without_adding_raw_scores(artifacts, monkeypatch) -> None:
    lexical, vector = _component_results(artifacts)
    first, second = artifacts[0]["chunks"][:2]
    _replace_hits(lexical, [first, second], [100000.0, 0.00001])
    _replace_hits(vector, [second, first], [0.999, 0.01])
    _patch_components(monkeypatch, lexical, vector)
    before = _search(artifacts)
    lexical["hits"][0]["score"] = 1e100
    vector["hits"][0]["score"] = 0.1

    after = _search(artifacts)

    assert _signature(before) == _signature(after)
    assert all(hit["score"] == round(1 / 61 + 1 / 62, 12) for hit in before["hits"])


def test_equal_rrf_scores_use_chunk_id_tie_break(artifacts, monkeypatch) -> None:
    lexical, vector = _component_results(artifacts)
    first, second = sorted(artifacts[0]["chunks"][:2], key=lambda chunk: chunk["chunk_id"])
    _replace_hits(lexical, [second, first])
    _replace_hits(vector, [first, second])
    _patch_components(monkeypatch, lexical, vector)

    result = _search(artifacts)

    assert result["hits"][0]["score"] == result["hits"][1]["score"]
    assert [hit["chunk"]["chunk_id"] for hit in result["hits"]] == [
        first["chunk_id"], second["chunk_id"]
    ]


def test_rounds_contributions_and_final_sum_independently(artifacts, monkeypatch) -> None:
    lexical, vector = _component_results(artifacts)
    chunk = artifacts[0]["chunks"][0]
    _replace_hits(lexical, [chunk])
    _replace_hits(vector, [*artifacts[0]["chunks"][1:6], chunk])
    _patch_components(monkeypatch, lexical, vector)

    hit = _search(artifacts)["hits"][0]

    assert hit["components"]["lexical"]["contribution"] == 0.016393442623
    assert hit["components"]["vector"]["contribution"] == 0.015151515152
    assert hit["score"] == round(1 / 61 + 1 / 66, 12) == 0.031544957774
    assert hit["score"] != round(sum(
        component["contribution"] for component in hit["components"].values()
    ), 12)
    assert all(
        value == round(value, 12)
        for value in [hit["score"], *(component["contribution"] for component in hit["components"].values())]
    )


@pytest.mark.parametrize("top_k", [1, 2, 5, 20])
def test_top_k_limits_final_fusion(artifacts, top_k) -> None:
    result = _search(artifacts, top_k=top_k)
    assert len(result["hits"]) == min(top_k, result["metadata"]["union_candidate_count"])
    assert result["metadata"]["returned_hits"] == len(result["hits"])
    assert [hit["rank"] for hit in result["hits"]] == list(range(1, len(result["hits"]) + 1))


@pytest.mark.parametrize("candidate_k", [1, 3, 20, 100])
def test_candidate_k_passed_unchanged_to_both_retrievers(
    artifacts, monkeypatch, candidate_k
) -> None:
    calls = []

    def lexical(*args, **kwargs):
        calls.append(("lexical", args[1], kwargs["top_k"]))
        return retrieve_lexical(*args, **kwargs)

    def vector(*args, **kwargs):
        calls.append(("vector", args[2], kwargs["top_k"]))
        return retrieve_vector(*args, **kwargs)

    monkeypatch.setattr(hybrid, "retrieve_lexical", lexical)
    monkeypatch.setattr(hybrid, "retrieve_vector", vector)
    result = _search(artifacts, top_k=1, candidate_k=candidate_k)

    assert calls == [("lexical", "synthetic", candidate_k), ("vector", "synthetic", candidate_k)]
    assert result["query"]["candidate_k"] == candidate_k
    assert result["metadata"]["lexical_candidate_count"] <= candidate_k
    assert result["metadata"]["vector_candidate_count"] <= candidate_k


def test_candidate_limit_changes_the_union_not_only_output_length(artifacts) -> None:
    small = _search(artifacts, top_k=1, candidate_k=1)
    large = _search(artifacts, top_k=1, candidate_k=20)
    assert len(small["hits"]) == len(large["hits"]) == 1
    assert small["metadata"]["union_candidate_count"] < large["metadata"]["union_candidate_count"]


@pytest.mark.parametrize("identifier", ["T1218.005", "mshta.exe", "jsonl:line:30"])
def test_exact_identifiers_use_existing_lexical_tokenizer(artifacts, identifier) -> None:
    target = artifacts[0]["chunks"][0]
    target["title"] = identifier
    _set_vectors(artifacts[1], [-1, 0, 0])

    result = _search(artifacts, query=identifier)

    assert result["query"]["normalized_terms"] == [identifier.casefold()]
    assert result["hits"][0]["chunk"]["chunk_id"] == target["chunk_id"]
    assert result["hits"][0]["components"]["lexical"]["rank"] == 1


@pytest.mark.parametrize("limit", ["top_k", "candidate_k"])
@pytest.mark.parametrize("value", [True, False, "5", 0, -1, 1.5, None])
def test_invalid_limits_fail_before_component_calls(artifacts, monkeypatch, limit, value) -> None:
    calls = []
    monkeypatch.setattr(hybrid, "retrieve_lexical", lambda *args, **kwargs: calls.append("lexical"))
    monkeypatch.setattr(hybrid, "retrieve_vector", lambda *args, **kwargs: calls.append("vector"))
    with pytest.raises(HybridRetrievalError, match=limit):
        _search(artifacts, **{limit: value})
    assert calls == []


def test_candidate_k_smaller_than_top_k_is_rejected(artifacts) -> None:
    with pytest.raises(HybridRetrievalError, match="candidate_k"):
        _search(artifacts, top_k=5, candidate_k=4)


@pytest.mark.parametrize("filter_kind", ["list", "tuple", "generator"])
def test_same_filter_semantics_are_passed_to_both_branches(
    artifacts, monkeypatch, filter_kind
) -> None:
    calls = []
    types = ["fact", "entity"]
    dimensions = ["provenance", "entity"]

    def lexical(*args, **kwargs):
        result = retrieve_lexical(*args, **kwargs)
        calls.append((args[1], result["query"]["filters"]))
        return result

    def vector(*args, **kwargs):
        result = retrieve_vector(*args, **kwargs)
        calls.append((args[2], result["query"]["filters"]))
        return result

    monkeypatch.setattr(hybrid, "retrieve_lexical", lexical)
    monkeypatch.setattr(hybrid, "retrieve_vector", vector)
    conversion = {"list": list, "tuple": tuple, "generator": iter}[filter_kind]
    result = _search(
        artifacts,
        query="  SYNTHETIC  ",
        chunk_types=conversion(types),
        required_dimensions=conversion(dimensions),
    )
    expected_filters = {
        "chunk_types": sorted(types), "required_dimensions": sorted(dimensions)
    }

    assert calls == [("  SYNTHETIC  ", expected_filters)] * 2
    assert result["query"]["filters"] == expected_filters
    assert result["query"]["text"] == "  SYNTHETIC  "
    assert all(
        hit["chunk"]["chunk_type"] in types
        and set(dimensions).issubset(hit["chunk"]["queryable_dimensions"])
        for hit in result["hits"]
    )
    assert types == ["fact", "entity"] and dimensions == ["provenance", "entity"]


def test_embedding_callback_once_and_inputs_unchanged(artifacts) -> None:
    before = deepcopy(artifacts)
    types = ["evidence", "relationship"]
    dimensions = ["provenance"]
    batch = [[2.0, 3.0, 4.0]]
    batch_before = deepcopy(batch)
    calls = []

    def callback(texts):
        calls.append(texts)
        return batch

    result = _search(
        artifacts, query="  Hành vi synthetic?  ", embed_query=callback,
        chunk_types=types, required_dimensions=dimensions,
    )

    assert calls == [[artifacts[1]["embedding"]["query_prefix"] + "  Hành vi synthetic?  "]]
    assert result["query"]["text"] == "  Hành vi synthetic?  "
    assert artifacts == before and batch == batch_before
    assert types == ["evidence", "relationship"] and dimensions == ["provenance"]


def test_empty_dimension_filter_preserves_unfiltered_semantics(artifacts) -> None:
    unfiltered = _search(artifacts, top_k=20)
    empty_dimensions = _search(artifacts, top_k=20, required_dimensions=[])

    assert unfiltered["hits"] == empty_dimensions["hits"]
    assert unfiltered["metadata"] == empty_dimensions["metadata"]
    assert empty_dimensions["query"]["filters"]["required_dimensions"] == []


def test_all_chunk_fields_and_nested_provenance_are_preserved_and_deep_copied(artifacts) -> None:
    before = deepcopy(artifacts)
    result = _search(artifacts, top_k=20)
    chunks = {chunk["chunk_id"]: chunk for chunk in artifacts[0]["chunks"]}

    for hit in result["hits"]:
        original = chunks[hit["chunk"]["chunk_id"]]
        _assert_deep_copy(hit["chunk"], original)
        for key in (
            "status", "source", "source_references", "entity_ids", "fact_ids",
            "relationship_ids", "evidence_ids", "sigma_rule_ids", "mitre_external_ids",
        ):
            assert hit["chunk"][key] == original[key]
        hit["chunk"]["source"]["json_pointer"] = "/changed"
        hit["chunk"]["source_references"].clear()
        hit["chunk"]["metadata"].clear()
        hit["chunk"]["content"] = "changed"
    assert artifacts == before


def test_lexical_no_hit_can_use_vector_candidates(artifacts) -> None:
    result = _search(artifacts, query="absent_unique_lexical_token_7a")
    assert result["hits"]
    assert result["metadata"]["lexical_candidate_count"] == 0
    assert all(hit["components"]["lexical"] is None for hit in result["hits"])
    assert all(hit["components"]["vector"] is not None for hit in result["hits"])
    assert any(warning.startswith("lexical:") for warning in result["warnings"])


def test_vector_no_positive_hit_can_use_lexical_candidates(artifacts) -> None:
    _set_vectors(artifacts[1], [-1, 0, 0])
    result = _search(artifacts)
    assert result["hits"]
    assert result["metadata"]["vector_candidate_count"] == 0
    assert all(hit["components"]["vector"] is None for hit in result["hits"])
    assert all(hit["components"]["lexical"] is not None for hit in result["hits"])
    assert any(warning.startswith("vector:") for warning in result["warnings"])


@pytest.mark.parametrize("empty_filters", [False, True])
def test_both_branches_no_hits_return_empty_result_and_hybrid_warning(
    artifacts, empty_filters
) -> None:
    _set_vectors(artifacts[1], [-1, 0, 0])
    calls = []
    result = _search(
        artifacts, query="absent_unique_lexical_token_7a",
        chunk_types=[] if empty_filters else None,
        embed_query=lambda texts: calls.append(texts) or [[1, 0, 0]],
    )
    assert len(calls) == 1
    assert result["hits"] == []
    assert result["metadata"]["returned_hits"] == 0
    assert result["metadata"]["union_candidate_count"] == 0
    assert all(result["metadata"][field] == 0 for field in ("lexical_candidate_count", "vector_candidate_count"))
    assert any(warning.startswith("hybrid:") for warning in result["warnings"])
    assert any(warning.startswith("lexical:") for warning in result["warnings"])
    assert any(warning.startswith("vector:") for warning in result["warnings"])
    if empty_filters:
        assert result["metadata"]["eligible_chunks"] == 0


def test_warnings_are_source_prefixed_and_deduplicated_deterministically(
    artifacts, monkeypatch
) -> None:
    lexical, vector = _component_results(artifacts)
    lexical["warnings"] = ["shared warning", "lexical warning", "shared warning"]
    vector["warnings"] = ["shared warning", "vector warning", "shared warning"]
    _patch_components(monkeypatch, lexical, vector)

    first = _search(artifacts)
    second = _search(artifacts)

    assert first == second
    assert len(first["warnings"]) == len(set(first["warnings"])) == 4
    assert set(first["warnings"]) == {
        "lexical: shared warning", "lexical: lexical warning",
        "vector: shared warning", "vector: vector warning",
    }


@pytest.mark.parametrize("branch", ["lexical", "vector"])
@pytest.mark.parametrize("unexpected", [False, True])
def test_component_errors_are_wrapped_and_fail_closed(
    artifacts, monkeypatch, branch, unexpected
) -> None:
    error_type = RuntimeError if unexpected else (
        LexicalRetrievalError if branch == "lexical" else VectorRetrievalError
    )

    def broken(*args, **kwargs):
        raise error_type("synthetic component failure")

    monkeypatch.setattr(hybrid, "retrieve_" + branch, broken)
    with pytest.raises(HybridRetrievalError, match=branch + ".*synthetic component failure") as raised:
        _search(artifacts)
    assert raised.value.__cause__ is not None


@pytest.mark.parametrize("kind", ["corpus", "index", "hash", "corpus_id", "scenario_id", "content", "coverage"])
def test_linked_artifact_validation_is_reused_and_wrapped(artifacts, kind) -> None:
    corpus, index, _ = artifacts
    kwargs = {}
    if kind == "corpus":
        corpus["schema_version"] = "invalid"
    elif kind == "index":
        index["schema_version"] = "invalid"
    elif kind == "hash":
        kwargs["corpus_sha256"] = "0" * 64
    elif kind in {"corpus_id", "scenario_id"}:
        index["corpus_provenance"][kind] = "different"
    elif kind == "content":
        index["records"][0]["content_sha256"] = "0" * 64
    else:
        index["records"].pop()
        index["metadata"]["record_count"] -= 1
    calls = []

    with pytest.raises(HybridRetrievalError):
        _search(artifacts, embed_query=lambda texts: calls.append(texts) or [[1, 0, 0]], **kwargs)
    assert calls == []


@pytest.mark.parametrize("query", ["", " \t\n", "?! … —", None, 42, True])
def test_invalid_queries_fail_closed(artifacts, query) -> None:
    with pytest.raises(HybridRetrievalError, match="query"):
        _search(artifacts, query=query)


@pytest.mark.parametrize("name", ["chunk_types", "required_dimensions"])
@pytest.mark.parametrize("value", ["evidence", b"evidence", {}, 4, [True], [None], [""], ["bogus"]])
def test_invalid_filters_reuse_component_validation(artifacts, name, value) -> None:
    with pytest.raises(HybridRetrievalError, match=name):
        _search(artifacts, **{name: value})


@pytest.mark.parametrize("name", ["chunk_types", "required_dimensions"])
def test_duplicate_filters_are_not_silently_deduplicated(artifacts, name) -> None:
    value = "evidence" if name == "chunk_types" else "provenance"
    with pytest.raises(HybridRetrievalError, match="duplicate"):
        _search(artifacts, **{name: [value, value]})


def test_filter_iteration_failure_is_wrapped(artifacts) -> None:
    def failing_filter():
        raise RuntimeError("synthetic filter iteration failure")
        yield "evidence"

    with pytest.raises(HybridRetrievalError, match="synthetic filter iteration failure"):
        _search(artifacts, chunk_types=failing_filter())


@pytest.mark.parametrize("batch", [None, [], [[1, 0]], [[True, 0, 0]], [[float("nan"), 0, 0]], [[0, 0, 0]]])
def test_embedding_validation_errors_fail_closed(artifacts, batch) -> None:
    with pytest.raises(HybridRetrievalError):
        _search(artifacts, embed_query=lambda texts: batch)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
@pytest.mark.parametrize("rank", [0, 2, True, "1", 1.5, None])
def test_invalid_component_ranks_are_rejected(artifacts, monkeypatch, branch, rank) -> None:
    results = _component_results(artifacts)
    component = results[0 if branch == "lexical" else 1]
    component["hits"][0]["rank"] = rank
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match=branch + ".*rank"):
        _search(artifacts)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
def test_duplicate_component_ids_are_rejected(artifacts, monkeypatch, branch) -> None:
    results = _component_results(artifacts)
    component = results[0 if branch == "lexical" else 1]
    component["hits"][1]["chunk"] = deepcopy(component["hits"][0]["chunk"])
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match=branch + ".*duplicate"):
        _search(artifacts)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
@pytest.mark.parametrize("score", [float("nan"), float("inf"), -float("inf"), True, False, "1", None, 0, -1])
def test_invalid_component_scores_are_rejected(artifacts, monkeypatch, branch, score) -> None:
    results = _component_results(artifacts)
    component = results[0 if branch == "lexical" else 1]
    component["hits"][0]["score"] = score
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match=branch + ".*score"):
        _search(artifacts)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
@pytest.mark.parametrize("field", ["corpus_id", "scenario_id"])
def test_component_identity_must_match_input_corpus(artifacts, monkeypatch, branch, field) -> None:
    results = _component_results(artifacts)
    results[0 if branch == "lexical" else 1][field] = "different"
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match=branch + ".*" + field):
        _search(artifacts)


def test_identically_wrong_component_identities_still_fail(artifacts, monkeypatch) -> None:
    results = _component_results(artifacts)
    for result in results:
        result["corpus_id"] = "same-wrong-corpus"
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match="corpus_id"):
        _search(artifacts)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
def test_unknown_component_chunk_is_rejected(artifacts, monkeypatch, branch) -> None:
    results = _component_results(artifacts)
    component = results[0 if branch == "lexical" else 1]
    component["hits"][0]["chunk"]["chunk_id"] = "unknown-chunk"
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match=branch + ".*chunk"):
        _search(artifacts)


def test_shared_chunk_with_different_branch_content_is_rejected(artifacts, monkeypatch) -> None:
    results = _component_results(artifacts)
    target = artifacts[0]["chunks"][0]
    for component in results:
        _replace_hits(component, [target])
    results[1]["hits"][0]["chunk"]["content"] += " changed"
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match="chunk"):
        _search(artifacts)


def test_identically_modified_chunks_must_still_match_corpus(artifacts, monkeypatch) -> None:
    results = _component_results(artifacts)
    target = deepcopy(artifacts[0]["chunks"][0])
    target["source"]["json_pointer"] = "/wrong"
    for component in results:
        _replace_hits(component, [target])
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match="chunk"):
        _search(artifacts)


@pytest.mark.parametrize("filters", [
    {"chunk_types": ["evidence"], "required_dimensions": None},
    {"chunk_types": True, "required_dimensions": None},
    {"chunk_types": None, "required_dimensions": "provenance"},
    {"chunk_types": None},
])
def test_matching_but_wrong_component_filters_are_rejected(
    artifacts, monkeypatch, filters
) -> None:
    results = _component_results(artifacts)
    for component in results:
        component["query"]["filters"] = deepcopy(filters)
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match="filters"):
        _search(artifacts)


def test_matching_but_wrong_component_eligible_counts_are_rejected(
    artifacts, monkeypatch
) -> None:
    results = _component_results(artifacts)
    for component in results:
        _replace_hits(component, [artifacts[0]["chunks"][0]])
        component["metadata"]["eligible_chunks"] = 1
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match="metadata"):
        _search(artifacts)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
def test_filtered_out_chunk_cannot_leak_from_component(artifacts, monkeypatch, branch) -> None:
    corpus, index, digest = artifacts
    lexical = retrieve_lexical(corpus, "synthetic", top_k=20, chunk_types=["evidence"])
    vector = retrieve_vector(
        corpus, index, "synthetic", corpus_sha256=digest,
        embed_query=lambda texts: [[1, 0, 0]], top_k=20, chunk_types=["evidence"],
    )
    component = lexical if branch == "lexical" else vector
    _replace_hits(component, [corpus["chunks"][0]])
    _patch_components(monkeypatch, lexical, vector)
    with pytest.raises(HybridRetrievalError, match=branch + ".*filters"):
        _search(artifacts, chunk_types=["evidence"])


@pytest.mark.parametrize("branch", ["lexical", "vector"])
def test_component_hit_count_cannot_exceed_candidate_k(artifacts, monkeypatch, branch) -> None:
    results = _component_results(artifacts, candidate_k=1)
    component = results[0 if branch == "lexical" else 1]
    _replace_hits(component, artifacts[0]["chunks"][:2])
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match=branch + ".*candidate_k"):
        _search(artifacts, top_k=1, candidate_k=1)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
def test_component_score_order_must_agree_with_ranks(artifacts, monkeypatch, branch) -> None:
    results = _component_results(artifacts)
    component = results[0 if branch == "lexical" else 1]
    first, second = artifacts[0]["chunks"][:2]
    _replace_hits(component, [first, second], [0.1, 0.9])
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match=branch + ".*order"):
        _search(artifacts)


@pytest.mark.parametrize("terms", [None, [], [""], "synthetic", [True], ["synthetic", "synthetic"], ["wrong"]])
def test_malformed_or_wrong_normalized_lexical_terms_are_rejected(
    artifacts, monkeypatch, terms
) -> None:
    results = _component_results(artifacts)
    results[0]["query"]["normalized_terms"] = terms
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match="lexical.*normalized_terms"):
        _search(artifacts)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
def test_component_score_interpretation_is_validated(artifacts, monkeypatch, branch) -> None:
    results = _component_results(artifacts)
    results[0 if branch == "lexical" else 1]["metadata"]["score_interpretation"] = "probability"
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match=branch + ".*score_interpretation"):
        _search(artifacts)


@pytest.mark.parametrize("kind", ["index_id", "dimension", "normalization", "negative_scored", "excess_scored", "too_few_scored", "bool_scored", "string_scored", "wrong_scored"])
def test_vector_metadata_must_match_linked_index(artifacts, monkeypatch, kind) -> None:
    results = _component_results(artifacts)
    metadata = results[1]["metadata"]
    if kind in {"index_id", "normalization"}:
        metadata[kind] = "different"
    elif kind == "dimension":
        metadata["dimension"] += 1
    else:
        metadata["scored_vectors"] = {
            "negative_scored": -1,
            "excess_scored": metadata["eligible_chunks"] + 1,
            "too_few_scored": metadata["returned_hits"] - 1,
            "bool_scored": True,
            "string_scored": "15",
            "wrong_scored": metadata["scored_vectors"] - 1,
        }[kind]
        if kind == "wrong_scored":
            _replace_hits(results[1], [artifacts[0]["chunks"][0]])
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match="vector.*metadata|vector.*scored_vectors"):
        _search(artifacts)


def test_vector_component_score_above_cosine_range_is_rejected(artifacts, monkeypatch) -> None:
    results = _component_results(artifacts)
    results[1]["hits"][0]["score"] = 1.0001
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match="vector.*score"):
        _search(artifacts)


def test_partial_index_still_allows_lexical_only_chunk(artifacts) -> None:
    corpus, index, _ = artifacts
    target = retrieve_lexical(corpus, "synthetic", top_k=1)["hits"][0]["chunk"]
    index["records"] = [
        record for record in index["records"] if record["chunk_id"] != target["chunk_id"]
    ]
    index["metadata"].update(
        record_count=len(index["records"]), complete_corpus_coverage=False
    )

    result = _search(artifacts, top_k=20)
    hit = next(hit for hit in result["hits"] if hit["chunk"]["chunk_id"] == target["chunk_id"])

    assert result["metadata"]["vector_candidate_count"] == len(index["records"])
    assert hit["components"]["lexical"] is not None
    assert hit["components"]["vector"] is None


def test_partial_index_cannot_return_vector_hit_without_record(artifacts, monkeypatch) -> None:
    corpus, index, _ = artifacts
    removed = index["records"].pop()
    index["metadata"].update(
        record_count=len(index["records"]), complete_corpus_coverage=False
    )
    target = next(chunk for chunk in corpus["chunks"] if chunk["chunk_id"] == removed["chunk_id"])
    results = _component_results(artifacts)
    _replace_hits(results[1], [target])
    _patch_components(monkeypatch, *results)

    with pytest.raises(HybridRetrievalError, match="vector.*index"):
        _search(artifacts)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
@pytest.mark.parametrize(
    "kind",
    [
        "schema_version", "retrieval_method", "query_text", "query_top_k",
        "query_filters", "returned_hits", "total_chunks", "eligible_chunks",
        "negative_eligible", "bool_total", "missing_metadata", "warnings_type",
        "warnings_item", "hits_type", "missing_chunk", "nonmapping_chunk",
    ],
)
def test_inconsistent_component_contract_is_rejected(
    artifacts, monkeypatch, branch, kind
) -> None:
    results = _component_results(artifacts)
    component = results[0 if branch == "lexical" else 1]
    if kind in {"schema_version", "retrieval_method"}:
        component[kind] = "invalid"
    elif kind == "query_text":
        component["query"]["text"] = "different"
    elif kind == "query_top_k":
        component["query"]["top_k"] = 5
    elif kind == "query_filters":
        component["query"]["filters"]["chunk_types"] = ["evidence"]
    elif kind == "returned_hits":
        component["metadata"]["returned_hits"] += 1
    elif kind == "total_chunks":
        component["metadata"]["total_chunks"] += 1
    elif kind == "eligible_chunks":
        component["metadata"]["eligible_chunks"] -= 1
    elif kind == "negative_eligible":
        component["metadata"]["eligible_chunks"] = -1
    elif kind == "bool_total":
        component["metadata"]["total_chunks"] = True
    elif kind == "missing_metadata":
        del component["metadata"]
    elif kind == "warnings_type":
        component["warnings"] = "not a warning list"
    elif kind == "warnings_item":
        component["warnings"] = [None]
    elif kind == "hits_type":
        component["hits"] = {}
    elif kind == "missing_chunk":
        del component["hits"][0]["chunk"]
    else:
        component["hits"][0]["chunk"] = []
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match=branch):
        _search(artifacts)


@pytest.mark.parametrize("branch", ["lexical", "vector"])
@pytest.mark.parametrize("value", [None, [], "invalid"])
def test_nonmapping_component_result_is_rejected(artifacts, monkeypatch, branch, value) -> None:
    results = list(_component_results(artifacts))
    results[0 if branch == "lexical" else 1] = value
    _patch_components(monkeypatch, *results)
    with pytest.raises(HybridRetrievalError, match=branch):
        _search(artifacts)


def test_strict_json_serialization_and_no_generated_security_conclusion(artifacts) -> None:
    result = _search(artifacts, top_k=20)
    assert json.loads(json.dumps(result, ensure_ascii=False, allow_nan=False)) == result
    assert all(math.isfinite(hit["score"]) and hit["score"] > 0 for hit in result["hits"])
    for value in _walk(result):
        if isinstance(value, dict):
            assert not {"answer", "confidence", "confirmed", "llm_output", "expected_answer", "expected_answers"}.intersection(value)
            assert all(item != "confirmed" for key, item in value.items() if "status" in key)


def test_repeat_runs_and_reversed_chunk_record_orders_are_identical(artifacts) -> None:
    before = deepcopy(artifacts)
    first = _search(artifacts, top_k=20)
    second = _search(artifacts, top_k=20)
    corpus, index, digest = deepcopy(artifacts)
    corpus["chunks"].reverse()
    index["records"].reverse()
    reordered = _search((corpus, index, digest), top_k=20)

    assert first == second == reordered
    assert artifacts == before


def test_synthetic_quality_target_lexical_first_vector_third_hybrid_first(artifacts) -> None:
    corpus, index, digest = artifacts
    target = corpus["chunks"][0]
    target["title"] = "synthetic_rank_target_7a"
    _set_vectors(index, [-1, 0, 0])
    records = {record["chunk_id"]: record for record in index["records"]}
    records[corpus["chunks"][1]["chunk_id"]]["vector"] = [1, 0, 0]
    records[corpus["chunks"][2]["chunk_id"]]["vector"] = [4, 3, 0]
    records[target["chunk_id"]]["vector"] = [3, 4, 0]
    query = "synthetic_rank_target_7a"
    lexical = retrieve_lexical(corpus, query, top_k=20)
    vector = retrieve_vector(
        corpus, index, query, corpus_sha256=digest,
        embed_query=lambda texts: [[1, 0, 0]], top_k=20,
    )
    result = _search(artifacts, query=query)

    assert lexical["hits"][0]["chunk"]["chunk_id"] == target["chunk_id"]
    assert vector["hits"][2]["chunk"]["chunk_id"] == target["chunk_id"]
    assert result["hits"][0]["chunk"]["chunk_id"] == target["chunk_id"]
    assert result["hits"][0]["components"]["lexical"]["rank"] == 1
    assert result["hits"][0]["components"]["vector"]["rank"] == 3
    assert result["hits"][0]["score"] == round(1 / 61 + 1 / 63, 12)
