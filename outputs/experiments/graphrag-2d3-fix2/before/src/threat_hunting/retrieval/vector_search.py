"""Deterministic, model-independent in-memory cosine retrieval."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
import copy
import hashlib
import math
from typing import Any, cast

from .schema import CHUNK_SOURCE_OBJECT_TYPES, validate_retrieval_corpus
from .vector_schema import SHA256_PATTERN, validate_vector_index

SCORE_PRECISION = 8
SCORE_INTERPRETATION = "cosine_similarity_not_probability"
COSINE_TOLERANCE = 1e-12


class VectorRetrievalError(ValueError):
    """Raised when vector retrieval cannot safely produce a result."""


def _filters(value: object, name: str, allowed: set[str]) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise VectorRetrievalError(f"{name} must be an iterable of strings or null")
    items = list(value)
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str) or not item.strip() or item not in allowed:
            raise VectorRetrievalError(f"{name} contains invalid value {item!r}")
        if item in seen:
            raise VectorRetrievalError(f"{name} contains duplicate value {item!r}")
        seen.add(item)
    return sorted(seen)


def _unit_vector(vector: Sequence[object], context: str) -> list[float]:
    numbers: list[float] = []
    for position, value in enumerate(vector):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise VectorRetrievalError(f"{context}[{position}] must be a finite number")
        try:
            number = float(value)
        except (OverflowError, ValueError) as exc:
            raise VectorRetrievalError(
                f"{context}[{position}] must be a finite number"
            ) from exc
        if not math.isfinite(number):
            raise VectorRetrievalError(f"{context}[{position}] must be a finite number")
        numbers.append(number)
    # Scaling first avoids overflow/underflow for finite extreme inputs.
    scale = max(abs(value) for value in numbers)
    if scale == 0:
        raise VectorRetrievalError(f"{context} must not be a zero vector")
    scaled = [value / scale for value in numbers]
    norm = math.hypot(*scaled)
    return [value / norm for value in scaled]


def _cosine(query: list[float], record: list[float], context: str) -> float:
    score = math.fsum(a * b for a, b in zip(query, record, strict=True))
    if not math.isfinite(score) or abs(score) > 1 + COSINE_TOLERANCE:
        raise VectorRetrievalError(f"{context}: invalid cosine similarity {score!r}")
    return max(-1.0, min(1.0, score))


def _retrieve(
    corpus: object,
    vector_index: object,
    query: object,
    *,
    corpus_sha256: object,
    embed_query: Callable[[list[str]], object],
    top_k: object,
    chunk_types: object,
    required_dimensions: object,
) -> dict[str, Any]:
    try:
        validate_retrieval_corpus(corpus)
    except Exception as exc:
        raise VectorRetrievalError(f"Invalid Retrieval Corpus: {exc}") from exc
    try:
        validate_vector_index(vector_index)
    except Exception as exc:
        raise VectorRetrievalError(f"Invalid Vector Index: {exc}") from exc
    root = cast(Mapping[str, Any], corpus)
    index = cast(Mapping[str, Any], vector_index)
    provenance = index["corpus_provenance"]
    if (
        not isinstance(corpus_sha256, str)
        or SHA256_PATTERN.fullmatch(corpus_sha256) is None
    ):
        raise VectorRetrievalError("corpus_sha256 must be a valid SHA-256 digest")
    if corpus_sha256.lower() != provenance["sha256"].lower():
        raise VectorRetrievalError("corpus_sha256 does not match index corpus provenance")
    for field in ("corpus_id", "scenario_id"):
        if root[field] != provenance[field]:
            raise VectorRetrievalError(f"Corpus/index {field} mismatch")
    chunks = {chunk["chunk_id"]: chunk for chunk in root["chunks"]}
    records = index["records"]
    for record in records:
        chunk_id = record["chunk_id"]
        if chunk_id not in chunks:
            raise VectorRetrievalError(
                f"Vector record {chunk_id!r} references nonexistent chunk"
            )
        chunk = chunks[chunk_id]
        if record["chunk_type"] != chunk["chunk_type"]:
            raise VectorRetrievalError(f"Vector record {chunk_id!r}: chunk_type mismatch")
        digest = hashlib.sha256(chunk["content"].encode("utf-8")).hexdigest()
        if record["content_sha256"].lower() != digest:
            raise VectorRetrievalError(f"Vector record {chunk_id!r}: content_sha256 mismatch")
    if index["metadata"]["complete_corpus_coverage"] and {
        record["chunk_id"] for record in records
    } != set(chunks):
        raise VectorRetrievalError("Complete corpus coverage requires exactly all corpus chunks")
    if not isinstance(query, str) or not query.strip():
        raise VectorRetrievalError("query must be a non-empty string")
    if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k <= 0:
        raise VectorRetrievalError("top_k must be a positive integer")
    types = _filters(chunk_types, "chunk_types", set(CHUNK_SOURCE_OBJECT_TYPES))
    dimensions = _filters(
        required_dimensions, "required_dimensions", set(root["queryable_dimensions"])
    )
    eligible = {
        key
        for key, chunk in chunks.items()
        if (types is None or chunk["chunk_type"] in types)
        and set(dimensions or []).issubset(chunk["queryable_dimensions"])
    }
    embedding = index["embedding"]
    if not callable(embed_query):
        raise VectorRetrievalError("embed_query must be callable")
    try:
        batch = embed_query([embedding["query_prefix"] + query])
    except Exception as exc:
        raise VectorRetrievalError(f"embed_query callback failed: {exc}") from exc
    if (
        isinstance(batch, (str, bytes))
        or not isinstance(batch, Sequence)
        or len(batch) != 1
    ):
        raise VectorRetrievalError("embed_query must return exactly one vector")
    vector = batch[0]
    if isinstance(vector, (str, bytes)) or not isinstance(vector, Sequence):
        raise VectorRetrievalError("embed_query output[0] must be a vector sequence")
    if len(vector) != embedding["dimension"]:
        raise VectorRetrievalError(
            "Query vector dimension does not match index embedding dimension"
        )
    query_unit = _unit_vector(vector, "Query vector")
    scored: list[tuple[float, str]] = []
    scored_count = 0
    for record in records:
        chunk_id = record["chunk_id"]
        if chunk_id not in eligible:
            continue
        # True cosine uses both norms, including permitted L2 rounding drift.
        record_unit = _unit_vector(record["vector"], f"Vector record {chunk_id!r}")
        score = _cosine(query_unit, record_unit, f"Vector record {chunk_id!r}")
        scored_count += 1
        rounded = round(score, SCORE_PRECISION)
        if rounded > 0:
            scored.append((rounded, chunk_id))
    scored.sort(key=lambda item: (-item[0], item[1]))
    hits = [
        {"rank": rank, "score": score, "chunk": copy.deepcopy(chunks[chunk_id])}
        for rank, (score, chunk_id) in enumerate(scored[:top_k], start=1)
    ]
    warnings = list(dict.fromkeys([*root["warnings"], *index["warnings"]]))
    if not eligible:
        warnings.append("No eligible corpus chunks satisfy the filters.")
    elif not scored_count:
        warnings.append("No indexed vectors are available for the eligible corpus chunks.")
    elif not hits:
        warnings.append("No positive cosine similarity hits at the configured score precision.")
    return {
        "schema_version": "retrieval-result/v1",
        "retrieval_method": "vector-cosine/v1",
        "corpus_id": root["corpus_id"],
        "scenario_id": root["scenario_id"],
        "query": {
            "text": query,
            "top_k": top_k,
            "filters": {
                "chunk_types": types,
                "required_dimensions": dimensions,
            },
        },
        "hits": hits,
        "warnings": warnings,
        "metadata": {
            "index_id": index["index_id"],
            "total_chunks": len(chunks),
            "eligible_chunks": len(eligible),
            "scored_vectors": scored_count,
            "returned_hits": len(hits),
            "dimension": embedding["dimension"],
            "normalization": embedding["normalization"],
            "score_precision": SCORE_PRECISION,
            "score_interpretation": SCORE_INTERPRETATION,
        },
    }


def retrieve_vector(
    corpus: object,
    vector_index: object,
    query: object,
    *,
    corpus_sha256: object,
    embed_query: Callable[[list[str]], object],
    top_k: object = 5,
    chunk_types: object = None,
    required_dimensions: object = None,
) -> dict[str, Any]:
    """Validate linked artifacts and rank chunks with one injected query embedding.

    The caller supplies the SHA-256 of the original corpus bytes; this in-memory
    API checks it against provenance, without reserializing or reading files.
    Scores are rounded before ranking; values rounding to zero are omitted.
    No model loading, fallback search, or security conclusion is performed.
    """
    try:
        return _retrieve(
            corpus,
            vector_index,
            query,
            corpus_sha256=corpus_sha256,
            embed_query=embed_query,
            top_k=top_k,
            chunk_types=chunk_types,
            required_dimensions=required_dimensions,
        )
    except VectorRetrievalError:
        raise
    except Exception as exc:
        raise VectorRetrievalError(f"Vector retrieval failed: {exc}") from exc


__all__ = ("VectorRetrievalError", "retrieve_vector")
