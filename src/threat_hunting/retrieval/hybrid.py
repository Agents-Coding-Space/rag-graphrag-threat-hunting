"""Deterministic in-memory reciprocal rank fusion of BM25 and cosine retrieval."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import copy
import math
from typing import Any, cast

from .lexical import (
    LEXICAL_RETRIEVAL_METHOD,
    RETRIEVAL_RESULT_SCHEMA_VERSION,
    SCORE_INTERPRETATION as LEXICAL_SCORE_INTERPRETATION,
    retrieve_lexical,
    tokenize_retrieval_text,
)
from .vector_search import (
    SCORE_INTERPRETATION as VECTOR_SCORE_INTERPRETATION,
    retrieve_vector,
)


HYBRID_RETRIEVAL_METHOD = "hybrid-rrf/v1"
RRF_K = 60
SCORE_PRECISION = 12
SCORE_INTERPRETATION = "reciprocal_rank_fusion_not_probability"
_COMPONENT_METHODS = {"lexical": LEXICAL_RETRIEVAL_METHOD, "vector": "vector-cosine/v1"}


class HybridRetrievalError(ValueError):
    """Raised when either retrieval branch or fusion cannot safely produce a result."""


def _positive_limit(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise HybridRetrievalError(f"{name} must be a positive integer")
    return value


def _replayable_filter(value: object) -> object:
    """Snapshot iterables once; leave validation to the component retrievers."""

    if isinstance(value, Iterable) and not isinstance(value, (str, bytes, Mapping)):
        return tuple(value)
    return value


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HybridRetrievalError(f"{context} must be an object")
    return value


def _count(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HybridRetrievalError(f"{context} must be a nonnegative integer")
    return value


def _validate_component(
    value: object,
    *,
    name: str,
    corpus: Mapping[str, Any],
    chunks: Mapping[str, Mapping[str, Any]],
    query: object,
    candidate_k: int,
    filters: Mapping[str, list[str] | None],
    eligible_ids: set[str],
    vector_index: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Check the returned branch contract, without repeating input validation."""

    context = f"{name} result"
    result = _mapping(value, context)
    if result.get("schema_version") != RETRIEVAL_RESULT_SCHEMA_VERSION:
        raise HybridRetrievalError(f"{context}: invalid schema_version")
    if result.get("retrieval_method") != _COMPONENT_METHODS[name]:
        raise HybridRetrievalError(f"{context}: invalid retrieval_method")
    for field in ("corpus_id", "scenario_id"):
        if result.get(field) != corpus[field]:
            raise HybridRetrievalError(f"{context}: {field} mismatch with input corpus")

    query_info = _mapping(result.get("query"), f"{context}.query")
    if query_info.get("text") != query:
        raise HybridRetrievalError(f"{context}: query text mismatch")
    if _count(query_info.get("top_k"), f"{context}.query.top_k") != candidate_k:
        raise HybridRetrievalError(f"{context}: query top_k must equal candidate_k")
    echoed_filters = _mapping(query_info.get("filters"), f"{context}.query.filters")
    if dict(echoed_filters) != dict(filters):
        raise HybridRetrievalError(f"{context}: query filters mismatch with requested filters")
    if name == "lexical":
        terms = query_info.get("normalized_terms")
        if (
            not isinstance(terms, list)
            or not terms
            or any(not isinstance(term, str) or not term for term in terms)
            or len(set(terms)) != len(terms)
            or terms != list(dict.fromkeys(tokenize_retrieval_text(query)))
        ):
            raise HybridRetrievalError(f"{context}: invalid normalized_terms")

    hits = result.get("hits")
    if not isinstance(hits, list):
        raise HybridRetrievalError(f"{context}.hits must be a list")
    if len(hits) > candidate_k:
        raise HybridRetrievalError(f"{context}: hit count exceeds candidate_k")
    metadata = _mapping(result.get("metadata"), f"{context}.metadata")
    total = _count(metadata.get("total_chunks"), f"{context}.metadata.total_chunks")
    eligible = _count(
        metadata.get("eligible_chunks"), f"{context}.metadata.eligible_chunks"
    )
    returned = _count(metadata.get("returned_hits"), f"{context}.metadata.returned_hits")
    if (
        total != len(chunks)
        or eligible != len(eligible_ids)
        or not len(hits) <= eligible <= total
        or returned != len(hits)
    ):
        raise HybridRetrievalError(f"{context}: inconsistent metadata chunk/hit counts")
    interpretation = (
        LEXICAL_SCORE_INTERPRETATION if name == "lexical" else VECTOR_SCORE_INTERPRETATION
    )
    if metadata.get("score_interpretation") != interpretation:
        raise HybridRetrievalError(f"{context}: invalid score_interpretation")
    indexed_ids: set[str] = set()
    if name == "vector":
        indexed_ids = {record["chunk_id"] for record in vector_index["records"]}
        scored = _count(metadata.get("scored_vectors"), f"{context}.metadata.scored_vectors")
        indexed_eligible = len(indexed_ids & eligible_ids)
        if not returned <= scored <= eligible or scored != indexed_eligible:
            raise HybridRetrievalError(f"{context}: inconsistent scored_vectors count")
        if metadata.get("index_id") != vector_index["index_id"]:
            raise HybridRetrievalError(f"{context}: metadata index_id mismatch")
        dimension = _count(metadata.get("dimension"), f"{context}.metadata.dimension")
        if dimension != vector_index["embedding"]["dimension"]:
            raise HybridRetrievalError(f"{context}: metadata dimension mismatch")
        if metadata.get("normalization") != vector_index["embedding"]["normalization"]:
            raise HybridRetrievalError(f"{context}: metadata normalization mismatch")

    seen: set[str] = set()
    ordering: list[tuple[float, str]] = []
    for expected_rank, value in enumerate(hits, start=1):
        hit_context = f"{context}.hits[{expected_rank - 1}]"
        hit = _mapping(value, hit_context)
        rank = hit.get("rank")
        if isinstance(rank, bool) or not isinstance(rank, int) or rank != expected_rank:
            raise HybridRetrievalError(f"{hit_context}: rank must be consecutive from 1")
        score = hit.get("score")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise HybridRetrievalError(f"{hit_context}: score must be a finite positive number")
        try:
            finite = math.isfinite(score)
        except OverflowError as exc:
            raise HybridRetrievalError(f"{hit_context}: score must be finite") from exc
        if not finite or score <= 0 or (name == "vector" and score > 1):
            raise HybridRetrievalError(f"{hit_context}: invalid finite positive {name} score")
        chunk = _mapping(hit.get("chunk"), f"{hit_context}.chunk")
        chunk_id = chunk.get("chunk_id")
        if not isinstance(chunk_id, str) or chunk_id not in chunks:
            raise HybridRetrievalError(f"{hit_context}: chunk_id does not exist in corpus")
        if chunk_id in seen:
            raise HybridRetrievalError(f"{hit_context}: duplicate chunk_id {chunk_id!r}")
        if chunk_id not in eligible_ids:
            raise HybridRetrievalError(f"{hit_context}: chunk_id violates requested filters")
        if name == "vector" and chunk_id not in indexed_ids:
            raise HybridRetrievalError(f"{hit_context}: chunk_id has no indexed vector record")
        if chunk != chunks[chunk_id]:
            raise HybridRetrievalError(f"{hit_context}: chunk {chunk_id!r} differs from corpus")
        seen.add(chunk_id)
        ordering.append((-score, chunk_id))
    if ordering != sorted(ordering):
        raise HybridRetrievalError(f"{context}: hits are not in score/chunk_id rank order")
    warnings = result.get("warnings")
    if not isinstance(warnings, list) or any(not isinstance(item, str) for item in warnings):
        raise HybridRetrievalError(f"{context}.warnings must be a list of strings")
    return result


def _retrieve_hybrid(
    corpus: object,
    vector_index: object,
    query: object,
    *,
    corpus_sha256: object,
    embed_query: Callable[[list[str]], object],
    top_k: object,
    candidate_k: object,
    chunk_types: object,
    required_dimensions: object,
) -> dict[str, Any]:
    result_limit = _positive_limit(top_k, "top_k")
    candidate_limit = _positive_limit(candidate_k, "candidate_k")
    if candidate_limit < result_limit:
        raise HybridRetrievalError("candidate_k must be greater than or equal to top_k")
    types = _replayable_filter(chunk_types)
    dimensions = _replayable_filter(required_dimensions)
    try:
        lexical_result = retrieve_lexical(
            corpus, query, top_k=candidate_limit,
            chunk_types=types, required_dimensions=dimensions,
        )
    except Exception as exc:
        raise HybridRetrievalError(f"lexical retrieval failed: {exc}") from exc
    try:
        vector_result = retrieve_vector(
            corpus, vector_index, query, corpus_sha256=corpus_sha256,
            embed_query=embed_query, top_k=candidate_limit,
            chunk_types=types, required_dimensions=dimensions,
        )
    except Exception as exc:
        raise HybridRetrievalError(f"vector retrieval failed: {exc}") from exc

    # Both retrievers validate the inputs; fusion validates their result contracts.
    root = cast(Mapping[str, Any], corpus)
    chunks = {chunk["chunk_id"]: chunk for chunk in root["chunks"]}
    # Audit filter echoes and membership. Allowed values were checked by both APIs.
    filters = {
        "chunk_types": None if types is None else sorted(cast(Iterable[str], types)),
        "required_dimensions": (
            None if dimensions is None else sorted(cast(Iterable[str], dimensions))
        ),
    }
    eligible_ids = {
        chunk_id
        for chunk_id, chunk in chunks.items()
        if (filters["chunk_types"] is None or chunk["chunk_type"] in filters["chunk_types"])
        and set(filters["required_dimensions"] or []).issubset(chunk["queryable_dimensions"])
    }
    results = {
        name: _validate_component(
            result, name=name, corpus=root, chunks=chunks,
            query=query, candidate_k=candidate_limit, filters=filters,
            eligible_ids=eligible_ids, vector_index=cast(Mapping[str, Any], vector_index),
        )
        for name, result in (("lexical", lexical_result), ("vector", vector_result))
    }
    lexical = results["lexical"]
    vector = results["vector"]
    if lexical["query"]["filters"] != vector["query"]["filters"]:
        raise HybridRetrievalError("lexical/vector query filters mismatch")
    if lexical["metadata"]["eligible_chunks"] != vector["metadata"]["eligible_chunks"]:
        raise HybridRetrievalError("lexical/vector eligible_chunks mismatch")

    components: dict[str, dict[str, Any]] = {}
    raw_contributions: dict[str, list[float]] = {}
    for name, result in results.items():
        for hit in result["hits"]:
            chunk_id = hit["chunk"]["chunk_id"]
            contribution = 1.0 / (RRF_K + hit["rank"])
            components.setdefault(chunk_id, {"lexical": None, "vector": None})[name] = {
                "rank": hit["rank"],
                "score": hit["score"],
                "contribution": round(contribution, SCORE_PRECISION),
            }
            raw_contributions.setdefault(chunk_id, []).append(contribution)
    # Round the mathematical RRF sum once, independently of displayed contributions.
    scores = {
        chunk_id: round(math.fsum(values), SCORE_PRECISION)
        for chunk_id, values in raw_contributions.items()
    }
    ranked_ids = sorted(scores, key=lambda chunk_id: (-scores[chunk_id], chunk_id))
    hits = [
        {
            "rank": rank,
            "score": scores[chunk_id],
            "components": components[chunk_id],
            "chunk": copy.deepcopy(dict(chunks[chunk_id])),
        }
        for rank, chunk_id in enumerate(ranked_ids[:result_limit], start=1)
    ]
    warnings = sorted({
        f"{name}: {warning}"
        for name, result in results.items()
        for warning in result["warnings"]
    })
    if not ranked_ids:
        warnings.append("hybrid: Neither lexical nor vector retrieval returned candidate hits.")
    return {
        "schema_version": RETRIEVAL_RESULT_SCHEMA_VERSION,
        "retrieval_method": HYBRID_RETRIEVAL_METHOD,
        "corpus_id": root["corpus_id"],
        "scenario_id": root["scenario_id"],
        "query": {
            "text": lexical["query"]["text"],
            "normalized_terms": copy.deepcopy(lexical["query"]["normalized_terms"]),
            "top_k": result_limit,
            "candidate_k": candidate_limit,
            "filters": copy.deepcopy(dict(lexical["query"]["filters"])),
        },
        "hits": hits,
        "warnings": warnings,
        "metadata": {
            "total_chunks": len(chunks),
            "eligible_chunks": lexical["metadata"]["eligible_chunks"],
            "returned_hits": len(hits),
            "lexical_candidate_count": len(lexical["hits"]),
            "vector_candidate_count": len(vector["hits"]),
            "union_candidate_count": len(ranked_ids),
            "rrf_k": RRF_K,
            "score_precision": SCORE_PRECISION,
            "score_interpretation": SCORE_INTERPRETATION,
            "component_methods": dict(_COMPONENT_METHODS),
        },
    }


def retrieve_hybrid(
    corpus: object,
    vector_index: object,
    query: object,
    *,
    corpus_sha256: object,
    embed_query: Callable[[list[str]], object],
    top_k: object = 5,
    candidate_k: object = 20,
    chunk_types: object = None,
    required_dimensions: object = None,
) -> dict[str, Any]:
    """Retrieve candidates with both existing retrievers, then apply fixed RRF.

    Embedding is injected and called once by vector retrieval. Each branch uses
    candidate_k; scores are fused by rank, never by adding BM25 and cosine scores.
    Contributions and the unrounded RRF sum are independently rounded to twelve
    decimal places. Empty branches are valid; technical errors fail closed.
    """

    try:
        return _retrieve_hybrid(
            corpus, vector_index, query, corpus_sha256=corpus_sha256,
            embed_query=embed_query, top_k=top_k, candidate_k=candidate_k,
            chunk_types=chunk_types, required_dimensions=required_dimensions,
        )
    except HybridRetrievalError:
        raise
    except Exception as exc:
        raise HybridRetrievalError(f"Hybrid retrieval failed: {exc}") from exc


__all__ = ("HybridRetrievalError", "retrieve_hybrid")
