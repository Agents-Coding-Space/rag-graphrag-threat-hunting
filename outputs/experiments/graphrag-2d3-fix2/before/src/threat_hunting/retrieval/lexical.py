"""Deterministic in-memory BM25 retrieval over Retrieval Corpus chunks."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
import copy
import math
import re
from typing import Any, cast
import unicodedata

from .schema import (
    CHUNK_SOURCE_OBJECT_TYPES,
    RetrievalCorpusValidationError,
    validate_retrieval_corpus,
)


RETRIEVAL_RESULT_SCHEMA_VERSION = "retrieval-result/v1"
LEXICAL_RETRIEVAL_METHOD = "bm25/v1"

BM25_K1 = 1.5
BM25_B = 0.75
TITLE_TERM_WEIGHT = 2
SCORE_PRECISION = 8
SCORE_INTERPRETATION = "bm25_relevance_not_probability"

_TOKEN_PATTERN = re.compile(r"\w+(?:[.:-]\w+)*", flags=re.UNICODE)
_ALLOWED_CHUNK_TYPES = frozenset(CHUNK_SOURCE_OBJECT_TYPES)


class LexicalRetrievalError(ValueError):
    """Raised when lexical retrieval cannot run without ambiguous inputs."""


def tokenize_retrieval_text(text: object) -> list[str]:
    """Return deterministic NFKC/casefolded lexical tokens from text."""

    if not isinstance(text, str):
        raise LexicalRetrievalError("retrieval text must be a string")
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return _TOKEN_PATTERN.findall(normalized)


def _unique_in_order(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _filter_values(
    value: object,
    *,
    name: str,
    allowed: frozenset[str],
) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise LexicalRetrievalError(f"{name} must be an iterable of strings or null")

    items = list(value)
    seen: set[str] = set()
    normalized: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str) or not item.strip():
            raise LexicalRetrievalError(
                f"{name}[{index}] must be a non-empty string"
            )
        if item in seen:
            raise LexicalRetrievalError(
                f"{name} must not contain duplicate value {item!r}"
            )
        if item not in allowed:
            raise LexicalRetrievalError(
                f"{name} contains unsupported value {item!r}; "
                f"allowed: {sorted(allowed)!r}"
            )
        seen.add(item)
        normalized.append(item)
    return sorted(normalized)


def _validate_top_k(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise LexicalRetrievalError("top_k must be a positive integer")
    return value


def _validate_query(value: object) -> tuple[str, list[str]]:
    if not isinstance(value, str) or not value.strip():
        raise LexicalRetrievalError("query must be a non-empty string")
    terms = _unique_in_order(tokenize_retrieval_text(value))
    if not terms:
        raise LexicalRetrievalError("query must produce at least one lexical token")
    return value, terms


def _document_terms(chunk: Mapping[str, Any]) -> Counter[str]:
    title_terms = tokenize_retrieval_text(chunk["title"])
    content_terms = tokenize_retrieval_text(chunk["content"])
    frequencies: Counter[str] = Counter(content_terms)
    for term, frequency in Counter(title_terms).items():
        frequencies[term] += frequency * TITLE_TERM_WEIGHT
    return frequencies


def _bm25_score(
    query_terms: list[str],
    frequencies: Counter[str],
    *,
    document_length: int,
    average_document_length: float,
    document_count: int,
    document_frequencies: Counter[str],
) -> float:
    score = 0.0
    length_ratio = document_length / average_document_length
    normalization = BM25_K1 * (1.0 - BM25_B + BM25_B * length_ratio)
    for term in query_terms:
        term_frequency = frequencies.get(term, 0)
        if term_frequency == 0:
            continue
        document_frequency = document_frequencies[term]
        inverse_document_frequency = math.log(
            1.0
            + (document_count - document_frequency + 0.5)
            / (document_frequency + 0.5)
        )
        score += inverse_document_frequency * (
            term_frequency * (BM25_K1 + 1.0)
            / (term_frequency + normalization)
        )
    if not math.isfinite(score) or score < 0.0:
        raise LexicalRetrievalError("BM25 produced an invalid relevance score")
    return round(score, SCORE_PRECISION)


def retrieve_lexical(
    corpus: object,
    query: object,
    *,
    top_k: object = 5,
    chunk_types: object = None,
    required_dimensions: object = None,
) -> dict[str, Any]:
    """Rank eligible corpus chunks for a dynamic runtime query using BM25."""

    try:
        validate_retrieval_corpus(corpus)
    except RetrievalCorpusValidationError as exc:
        raise LexicalRetrievalError(f"Invalid Retrieval Corpus: {exc}") from exc

    root = cast(Mapping[str, Any], corpus)
    query_text, query_terms = _validate_query(query)
    result_limit = _validate_top_k(top_k)
    selected_chunk_types = _filter_values(
        chunk_types,
        name="chunk_types",
        allowed=_ALLOWED_CHUNK_TYPES,
    )
    corpus_dimensions = frozenset(cast(list[str], root["queryable_dimensions"]))
    selected_dimensions = _filter_values(
        required_dimensions,
        name="required_dimensions",
        allowed=corpus_dimensions,
    )

    chunk_type_set = (
        None if selected_chunk_types is None else set(selected_chunk_types)
    )
    dimension_set = (
        set() if selected_dimensions is None else set(selected_dimensions)
    )
    all_chunks = cast(list[Mapping[str, Any]], root["chunks"])
    eligible_chunks = [
        chunk
        for chunk in all_chunks
        if (chunk_type_set is None or chunk["chunk_type"] in chunk_type_set)
        and dimension_set.issubset(set(chunk["queryable_dimensions"]))
    ]

    term_frequencies = [_document_terms(chunk) for chunk in eligible_chunks]
    document_lengths = [sum(frequencies.values()) for frequencies in term_frequencies]
    document_count = len(eligible_chunks)
    average_document_length = (
        sum(document_lengths) / document_count if document_count else 0.0
    )
    document_frequencies: Counter[str] = Counter()
    for frequencies in term_frequencies:
        document_frequencies.update(frequencies.keys())

    scored: list[tuple[float, str, list[str], Mapping[str, Any]]] = []
    for chunk, frequencies, document_length in zip(
        eligible_chunks,
        term_frequencies,
        document_lengths,
        strict=True,
    ):
        score = _bm25_score(
            query_terms,
            frequencies,
            document_length=document_length,
            average_document_length=average_document_length,
            document_count=document_count,
            document_frequencies=document_frequencies,
        )
        if score <= 0.0:
            continue
        matched_terms = [term for term in query_terms if term in frequencies]
        scored.append((score, str(chunk["chunk_id"]), matched_terms, chunk))

    scored.sort(key=lambda item: (-item[0], item[1]))
    hits = [
        {
            "rank": rank,
            "score": score,
            "matched_terms": matched_terms,
            "chunk": copy.deepcopy(dict(chunk)),
        }
        for rank, (score, _, matched_terms, chunk) in enumerate(
            scored[:result_limit], start=1
        )
    ]
    warnings = []
    if not hits:
        warnings.append(
            "No eligible chunks matched the normalized lexical query terms."
        )

    return {
        "schema_version": RETRIEVAL_RESULT_SCHEMA_VERSION,
        "retrieval_method": LEXICAL_RETRIEVAL_METHOD,
        "corpus_id": root["corpus_id"],
        "scenario_id": root["scenario_id"],
        "query": {
            "text": query_text,
            "normalized_terms": query_terms,
            "top_k": result_limit,
            "filters": {
                "chunk_types": selected_chunk_types,
                "required_dimensions": selected_dimensions,
            },
        },
        "hits": hits,
        "warnings": warnings,
        "metadata": {
            "total_chunks": len(all_chunks),
            "eligible_chunks": document_count,
            "returned_hits": len(hits),
            "score_interpretation": SCORE_INTERPRETATION,
            "bm25": {
                "k1": BM25_K1,
                "b": BM25_B,
                "title_term_weight": TITLE_TERM_WEIGHT,
                "score_precision": SCORE_PRECISION,
            },
        },
    }


__all__ = (
    "RETRIEVAL_RESULT_SCHEMA_VERSION",
    "LEXICAL_RETRIEVAL_METHOD",
    "LexicalRetrievalError",
    "retrieve_lexical",
    "tokenize_retrieval_text",
)
