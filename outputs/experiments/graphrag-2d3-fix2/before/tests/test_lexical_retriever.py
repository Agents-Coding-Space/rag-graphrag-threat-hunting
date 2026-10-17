from __future__ import annotations

from copy import deepcopy
import json
import math
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.retrieval import (
    LEXICAL_RETRIEVAL_METHOD,
    RETRIEVAL_RESULT_SCHEMA_VERSION,
    LexicalRetrievalError,
    retrieve_lexical,
    tokenize_retrieval_text,
)
from threat_hunting.retrieval import lexical


CORPUS_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "retrieval"
    / "builder"
    / "expected_retrieval_corpus.json"
)
FORBIDDEN_RESULT_FIELDS = {
    "answer_id",
    "evaluation_questions",
    "expected_answer",
    "expected_answers",
    "question_id",
    "question_text",
}


def _corpus() -> dict[str, Any]:
    value = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _walk(value: object) -> list[object]:
    values = [value]
    if isinstance(value, dict):
        for key, nested in value.items():
            values.extend((key, *_walk(nested)))
    elif isinstance(value, list):
        for nested in value:
            values.extend(_walk(nested))
    return values


def _hit_signature(result: dict[str, Any]) -> list[tuple[str, float]]:
    return [
        (hit["chunk"]["chunk_id"], hit["score"])
        for hit in result["hits"]
    ]


def test_valid_corpus_returns_ranked_hits() -> None:
    result = retrieve_lexical(_corpus(), "synthetic activity")

    assert result["schema_version"] == RETRIEVAL_RESULT_SCHEMA_VERSION
    assert result["retrieval_method"] == LEXICAL_RETRIEVAL_METHOD
    assert result["corpus_id"] == _corpus()["corpus_id"]
    assert result["scenario_id"] == _corpus()["scenario_id"]
    assert result["hits"]
    assert [hit["rank"] for hit in result["hits"]] == list(
        range(1, len(result["hits"]) + 1)
    )


def test_question_mark_query_is_accepted() -> None:
    result = retrieve_lexical(_corpus(), "Which synthetic activity?")

    assert result["hits"]
    assert result["query"]["text"].endswith("?")


def test_vietnamese_query_is_accepted() -> None:
    corpus = _corpus()
    corpus["chunks"][0]["content"] = "Hành vi tổng hợp cần được xem xét."

    result = retrieve_lexical(corpus, "HÀNH VI nào cần xem xét?")

    assert result["query"]["normalized_terms"][:2] == ["hành", "vi"]
    assert result["hits"]


def test_matching_is_case_insensitive() -> None:
    upper = retrieve_lexical(_corpus(), "SYNTHETIC ALPHA")
    lower = retrieve_lexical(_corpus(), "synthetic alpha")

    assert _hit_signature(upper) == _hit_signature(lower)
    assert upper["query"]["normalized_terms"] == ["synthetic", "alpha"]


def test_unicode_nfkc_normalization_affects_matching() -> None:
    normalized = retrieve_lexical(_corpus(), "ALPHA")
    compatibility = retrieve_lexical(_corpus(), "ＡＬＰＨＡ")

    assert _hit_signature(compatibility) == _hit_signature(normalized)
    assert compatibility["query"]["normalized_terms"] == ["alpha"]


@pytest.mark.parametrize(
    ("text", "expected"),
    (
        ("mshta.exe", ["mshta.exe"]),
        ("T1218.005", ["t1218.005"]),
        ("jsonl:line:4", ["jsonl:line:4"]),
        ("process_spawn", ["process_spawn"]),
    ),
)
def test_tokenizer_preserves_technical_tokens(
    text: str, expected: list[str]
) -> None:
    assert tokenize_retrieval_text(text) == expected


def test_tokenizer_is_deterministic_with_whitespace_and_punctuation() -> None:
    text = "  Alpha,\tBETA... process_spawn  "

    assert tokenize_retrieval_text(text) == ["alpha", "beta", "process_spawn"]
    assert tokenize_retrieval_text(text) == tokenize_retrieval_text(text)


def test_scores_are_finite_nonnegative_and_positive_for_hits() -> None:
    result = retrieve_lexical(_corpus(), "synthetic activity", top_k=20)

    assert all(
        math.isfinite(hit["score"]) and hit["score"] > 0.0
        for hit in result["hits"]
    )


def test_ranking_is_deterministic() -> None:
    first = retrieve_lexical(_corpus(), "synthetic transition", top_k=20)
    second = retrieve_lexical(_corpus(), "synthetic transition", top_k=20)

    assert first == second


def test_reversing_chunks_does_not_change_ranking() -> None:
    original = _corpus()
    reversed_corpus = deepcopy(original)
    reversed_corpus["chunks"].reverse()

    first = retrieve_lexical(original, "synthetic transition", top_k=20)
    second = retrieve_lexical(reversed_corpus, "synthetic transition", top_k=20)

    assert _hit_signature(first) == _hit_signature(second)


def test_equal_scores_use_chunk_id_tie_break() -> None:
    corpus = _corpus()
    entities = [
        chunk for chunk in corpus["chunks"] if chunk["chunk_type"] == "entity"
    ]
    for chunk in entities[:2]:
        chunk["title"] = "Tie token"
        chunk["content"] = "Tie token content."

    result = retrieve_lexical(
        corpus,
        "tie",
        top_k=3,
        chunk_types=["entity"],
    )

    assert len(result["hits"]) == 2
    assert result["hits"][0]["score"] == result["hits"][1]["score"]
    assert [hit["chunk"]["chunk_id"] for hit in result["hits"]] == sorted(
        chunk["chunk_id"] for chunk in entities[:2]
    )


def test_top_k_limits_results() -> None:
    result = retrieve_lexical(_corpus(), "synthetic", top_k=2)

    assert len(result["hits"]) == 2
    assert result["metadata"]["returned_hits"] == 2


def test_chunk_type_filter_limits_eligible_chunks() -> None:
    result = retrieve_lexical(
        _corpus(),
        "synthetic",
        top_k=20,
        chunk_types=["evidence"],
    )

    assert result["hits"]
    assert all(hit["chunk"]["chunk_type"] == "evidence" for hit in result["hits"])
    assert result["metadata"]["eligible_chunks"] == 2


def test_required_dimensions_filter_requires_every_dimension() -> None:
    required = ["evidence", "mitre_technique"]

    result = retrieve_lexical(
        _corpus(),
        "synthetic",
        top_k=20,
        required_dimensions=required,
    )

    assert result["hits"]
    assert all(
        set(required).issubset(hit["chunk"]["queryable_dimensions"])
        for hit in result["hits"]
    )


def test_filter_values_are_sorted_in_result_contract() -> None:
    result = retrieve_lexical(
        _corpus(),
        "synthetic",
        chunk_types=["fact", "entity"],
        required_dimensions=["provenance", "entity"],
    )

    assert result["query"]["filters"] == {
        "chunk_types": ["entity", "fact"],
        "required_dimensions": ["entity", "provenance"],
    }


def test_invalid_chunk_type_is_rejected() -> None:
    with pytest.raises(LexicalRetrievalError, match="unsupported value"):
        retrieve_lexical(_corpus(), "synthetic", chunk_types=["unknown_type"])


def test_invalid_dimension_is_rejected() -> None:
    with pytest.raises(LexicalRetrievalError, match="unsupported value"):
        retrieve_lexical(
            _corpus(),
            "synthetic",
            required_dimensions=["unknown_dimension"],
        )


@pytest.mark.parametrize(
    ("keyword", "value"),
    (
        ("chunk_types", ["entity", "entity"]),
        ("required_dimensions", ["entity", "entity"]),
    ),
)
def test_duplicate_filter_values_are_rejected(
    keyword: str, value: list[str]
) -> None:
    with pytest.raises(LexicalRetrievalError, match="duplicate"):
        retrieve_lexical(_corpus(), "synthetic", **{keyword: value})


@pytest.mark.parametrize("query", ("", "   ", None, 42))
def test_empty_or_non_string_query_is_rejected(query: object) -> None:
    with pytest.raises(LexicalRetrievalError, match="query"):
        retrieve_lexical(_corpus(), query)


def test_query_without_tokens_is_rejected() -> None:
    with pytest.raises(LexicalRetrievalError, match="at least one lexical token"):
        retrieve_lexical(_corpus(), "?! … —")


@pytest.mark.parametrize("top_k", (0, -1, 1.5, True, "5"))
def test_invalid_top_k_is_rejected(top_k: object) -> None:
    with pytest.raises(LexicalRetrievalError, match="positive integer"):
        retrieve_lexical(_corpus(), "synthetic", top_k=top_k)


def test_zero_match_returns_empty_hits_and_warning() -> None:
    result = retrieve_lexical(_corpus(), "no_such_synthetic_token_987654321")

    assert result["hits"] == []
    assert result["warnings"] == [
        "No eligible chunks matched the normalized lexical query terms."
    ]
    assert result["metadata"]["returned_hits"] == 0


def test_empty_filter_returns_no_eligible_chunks_without_guessing() -> None:
    result = retrieve_lexical(_corpus(), "synthetic", chunk_types=[])

    assert result["hits"] == []
    assert result["metadata"]["eligible_chunks"] == 0
    assert result["warnings"]


def test_result_is_strict_json_serializable() -> None:
    result = retrieve_lexical(_corpus(), "synthetic activity")

    serialized = json.dumps(
        result,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    )
    assert json.loads(serialized) == result


def test_hit_preserves_complete_source_chunk_and_provenance() -> None:
    corpus = _corpus()
    result = retrieve_lexical(corpus, "worker-beta.bin", top_k=20)
    source = next(
        chunk
        for chunk in corpus["chunks"]
        if chunk["chunk_id"] == result["hits"][0]["chunk"]["chunk_id"]
    )

    assert result["hits"][0]["chunk"] == source
    assert result["hits"][0]["chunk"] is not source
    assert "source_references" in result["hits"][0]["chunk"]
    assert "json_pointer" in result["hits"][0]["chunk"]["source"]


def test_retrieval_does_not_mutate_corpus() -> None:
    corpus = _corpus()
    before = deepcopy(corpus)

    retrieve_lexical(
        corpus,
        "synthetic transition",
        top_k=10,
        chunk_types=["relationship", "fact"],
        required_dimensions=["relationship"],
    )

    assert corpus == before


def test_mutating_returned_chunk_does_not_mutate_corpus() -> None:
    corpus = _corpus()
    before = deepcopy(corpus)
    result = retrieve_lexical(corpus, "synthetic")

    result["hits"][0]["chunk"]["title"] = "changed outside retriever"

    assert corpus == before


def test_result_contains_no_confirmed_value() -> None:
    result = retrieve_lexical(_corpus(), "synthetic", top_k=20)

    assert all(
        not (isinstance(value, str) and value.casefold() == "confirmed")
        for value in _walk(result)
    )


def test_result_contains_no_expected_answer_contract() -> None:
    result = retrieve_lexical(_corpus(), "synthetic", top_k=20)
    strings = {value for value in _walk(result) if isinstance(value, str)}

    assert FORBIDDEN_RESULT_FIELDS.isdisjoint(strings)


def test_lexical_source_has_no_query_lookup_or_production_constants() -> None:
    source = Path(lexical.__file__).read_text(encoding="utf-8").casefold()

    for forbidden in (
        "mshta",
        "powershell",
        "t1059.007",
        "t1140",
        "t1218.005",
        "53abc9e44c03c46aaf024cdb79b61ad3381d50feb82689f27074151381b9d0f3",
        "expected_answer",
        "expected_answers",
    ):
        assert forbidden not in source


def test_lexical_source_has_no_file_network_clock_random_or_uuid_io() -> None:
    source = Path(lexical.__file__).read_text(encoding="utf-8").casefold()

    for forbidden in (
        ".open(",
        ".read_text(",
        ".write_text(",
        "urlopen",
        "requests.",
        "datetime.now",
        "time.time",
        "import random",
        "import uuid",
        "uuid4",
    ):
        assert forbidden not in source


def test_invalid_corpus_schema_is_rejected() -> None:
    corpus = _corpus()
    corpus["schema_version"] = "retrieval-corpus/v0"

    with pytest.raises(LexicalRetrievalError, match="Invalid Retrieval Corpus"):
        retrieve_lexical(corpus, "synthetic")


def test_score_is_described_as_relevance_not_probability() -> None:
    result = retrieve_lexical(_corpus(), "synthetic")

    assert result["metadata"]["score_interpretation"] == (
        "bm25_relevance_not_probability"
    )
    assert "probability" not in result["metadata"]
    assert "confidence" not in result["metadata"]


def test_title_and_content_are_both_indexed() -> None:
    corpus = _corpus()
    first, second = corpus["chunks"][:2]
    first["title"] = "unique_title_term"
    first["content"] = "Neutral content."
    second["title"] = "Neutral title"
    second["content"] = "Contains unique_content_term here."

    title_result = retrieve_lexical(corpus, "unique_title_term", top_k=20)
    content_result = retrieve_lexical(corpus, "unique_content_term", top_k=20)

    assert [hit["chunk"]["chunk_id"] for hit in title_result["hits"]] == [
        first["chunk_id"]
    ]
    assert [hit["chunk"]["chunk_id"] for hit in content_result["hits"]] == [
        second["chunk_id"]
    ]


def test_matched_terms_follow_unique_normalized_query_order() -> None:
    result = retrieve_lexical(
        _corpus(),
        "activity synthetic activity",
        top_k=1,
    )

    assert result["query"]["normalized_terms"] == ["activity", "synthetic"]
    assert result["hits"][0]["matched_terms"] == ["activity", "synthetic"]


@pytest.mark.parametrize(
    ("keyword", "value"),
    (
        ("chunk_types", "entity"),
        ("required_dimensions", "entity"),
        ("chunk_types", [1]),
        ("required_dimensions", [None]),
    ),
)
def test_malformed_filter_container_or_item_is_rejected(
    keyword: str, value: object
) -> None:
    with pytest.raises(LexicalRetrievalError):
        retrieve_lexical(_corpus(), "synthetic", **{keyword: value})


def test_default_filters_are_explicitly_null_in_result() -> None:
    result = retrieve_lexical(_corpus(), "synthetic")

    assert result["query"]["filters"] == {
        "chunk_types": None,
        "required_dimensions": None,
    }
    assert result["metadata"]["total_chunks"] == len(_corpus()["chunks"])


def test_bm25_parameters_and_score_precision_are_stable() -> None:
    result = retrieve_lexical(_corpus(), "synthetic")

    assert result["metadata"]["bm25"] == {
        "k1": 1.5,
        "b": 0.75,
        "title_term_weight": 2,
        "score_precision": 8,
    }
    assert all(
        hit["score"] == round(hit["score"], 8) for hit in result["hits"]
    )
