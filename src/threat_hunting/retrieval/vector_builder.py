"""Pure in-memory Retrieval Corpus to Vector Index transformation."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from hashlib import sha256
import json
import math
from pathlib import Path
import re
from typing import Any

from .schema import (
    RETRIEVAL_CORPUS_SCHEMA_VERSION,
    RetrievalCorpusValidationError,
    validate_retrieval_corpus,
)
from .vector_schema import (
    EMBEDDING_FIELDS,
    SUPPORTED_DISTANCE_METRICS,
    SUPPORTED_NORMALIZATIONS,
    VECTOR_INDEX_SCHEMA_VERSION,
    VectorIndexValidationError,
    validate_vector_index,
)


SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class VectorIndexBuildError(ValueError):
    """Raised when a valid Vector Index cannot be built without guessing."""


def _corpus_path_text(value: object) -> str:
    if isinstance(value, Path):
        text = value.as_posix()
    elif isinstance(value, str):
        text = value
    else:
        raise VectorIndexBuildError(
            "corpus_path must be a non-empty string or Path"
        )
    if not text.strip():
        raise VectorIndexBuildError(
            "corpus_path must be a non-empty string or Path"
        )
    return text


def _corpus_hash_text(value: object) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise VectorIndexBuildError(
            "corpus_sha256 must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _embedding_document(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise VectorIndexBuildError("embedding must be a JSON object")
    if not all(isinstance(key, str) for key in value):
        raise VectorIndexBuildError("embedding contains a non-string object key")

    expected = set(EMBEDDING_FIELDS)
    actual = set(value)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    details: list[str] = []
    if missing:
        details.append(f"missing {missing!r}")
    if unexpected:
        details.append(f"unexpected {unexpected!r}")
    if details:
        raise VectorIndexBuildError(
            "embedding fields do not match the contract: " + "; ".join(details)
        )

    descriptor = {field: value[field] for field in EMBEDDING_FIELDS}
    for field in ("provider", "model_id", "model_revision"):
        item = descriptor[field]
        if not isinstance(item, str) or not item.strip():
            raise VectorIndexBuildError(
                f"embedding.{field} must be a non-empty string"
            )

    dimension = descriptor["dimension"]
    if (
        isinstance(dimension, bool)
        or not isinstance(dimension, int)
        or dimension < 1
    ):
        raise VectorIndexBuildError(
            "embedding.dimension must be a positive integer"
        )

    distance_metric = descriptor["distance_metric"]
    if (
        not isinstance(distance_metric, str)
        or distance_metric not in SUPPORTED_DISTANCE_METRICS
    ):
        raise VectorIndexBuildError(
            "embedding.distance_metric has unsupported value "
            f"{distance_metric!r}; allowed: {sorted(SUPPORTED_DISTANCE_METRICS)!r}"
        )

    normalization = descriptor["normalization"]
    if (
        not isinstance(normalization, str)
        or normalization not in SUPPORTED_NORMALIZATIONS
    ):
        raise VectorIndexBuildError(
            "embedding.normalization has unsupported value "
            f"{normalization!r}; allowed: {sorted(SUPPORTED_NORMALIZATIONS)!r}"
        )

    for field in ("document_prefix", "query_prefix"):
        if not isinstance(descriptor[field], str):
            raise VectorIndexBuildError(f"embedding.{field} must be a string")

    try:
        json.dumps(
            descriptor,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise VectorIndexBuildError(
            f"embedding cannot be represented as UTF-8 JSON: {exc}"
        ) from exc
    return descriptor


def _deterministic_index_id(
    *,
    corpus_id: str,
    scenario_id: str,
    corpus_sha256: str,
    embedding: Mapping[str, object],
) -> str:
    identity = {
        "corpus_id": corpus_id,
        "scenario_id": scenario_id,
        "corpus_sha256": corpus_sha256,
        "embedding": dict(embedding),
    }
    try:
        canonical = json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise VectorIndexBuildError(
            f"Vector index identity cannot be represented as UTF-8 JSON: {exc}"
        ) from exc
    return f"vector-index--{sha256(canonical).hexdigest()}"


def _is_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    )


def _finite_number(value: object, *, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise VectorIndexBuildError(f"{path} must be a finite JSON number")
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise VectorIndexBuildError(
            f"{path} must be a finite JSON number"
        ) from exc
    if not math.isfinite(number):
        raise VectorIndexBuildError(f"{path} must be a finite JSON number")
    return number


def _vector_document(
    value: object,
    *,
    chunk_id: str,
    position: int,
    dimension: int,
    normalization: str,
) -> list[float]:
    path = f"embedding output[{position}] for chunk {chunk_id!r}"
    if not _is_sequence(value):
        raise VectorIndexBuildError(f"{path} must be a vector sequence")
    assert isinstance(value, Sequence)
    if not value:
        raise VectorIndexBuildError(f"{path} must not be empty")
    if len(value) != dimension:
        raise VectorIndexBuildError(
            f"{path} must contain exactly {dimension} values"
        )

    numbers = [
        _finite_number(item, path=f"{path}[{index}]")
        for index, item in enumerate(value)
    ]
    if normalization == "none":
        return numbers

    norm = math.hypot(*numbers)
    if norm == 0.0:
        raise VectorIndexBuildError(
            f"{path} must not be a zero vector when normalization is 'l2'"
        )
    if not math.isfinite(norm):
        raise VectorIndexBuildError(f"{path} has a non-finite L2 norm")
    return [number / norm for number in numbers]


def _embedding_vectors(
    *,
    embed_documents: Callable[[list[str]], object],
    texts: list[str],
    chunks: Sequence[Mapping[str, Any]],
    dimension: int,
    normalization: str,
) -> list[list[float]]:
    try:
        result = embed_documents(list(texts))
    except Exception as exc:
        raise VectorIndexBuildError(f"Embedding backend failed: {exc}") from exc

    if not _is_sequence(result):
        raise VectorIndexBuildError(
            "Embedding backend output must be a sequence of vectors"
        )
    assert isinstance(result, Sequence)
    if len(result) != len(chunks):
        raise VectorIndexBuildError(
            "Embedding backend returned "
            f"{len(result)} vectors for {len(chunks)} chunks"
        )

    return [
        _vector_document(
            vector,
            chunk_id=str(chunks[index]["chunk_id"]),
            position=index,
            dimension=dimension,
            normalization=normalization,
        )
        for index, vector in enumerate(result)
    ]


def _content_sha256(content: str, *, chunk_id: str) -> str:
    try:
        encoded = content.encode("utf-8")
    except UnicodeError as exc:
        raise VectorIndexBuildError(
            f"Content for chunk {chunk_id!r} cannot be encoded as UTF-8: {exc}"
        ) from exc
    return sha256(encoded).hexdigest()


def build_vector_index(
    retrieval_corpus: object,
    *,
    corpus_path: str | Path,
    corpus_sha256: str,
    embedding: Mapping[str, object],
    embed_documents: Callable[[list[str]], object],
) -> dict[str, object]:
    """Build one validated Vector Index using an injected embedding backend."""

    try:
        validate_retrieval_corpus(retrieval_corpus)
    except RetrievalCorpusValidationError as exc:
        raise VectorIndexBuildError(
            f"Invalid Retrieval Corpus input: {exc}"
        ) from exc

    if not callable(embed_documents):
        raise VectorIndexBuildError("embed_documents must be callable")

    source_path = _corpus_path_text(corpus_path)
    source_hash = _corpus_hash_text(corpus_sha256)
    descriptor = _embedding_document(embedding)
    assert isinstance(retrieval_corpus, Mapping)
    root: Mapping[str, Any] = retrieval_corpus
    chunks = sorted(root["chunks"], key=lambda item: item["chunk_id"])
    document_prefix = str(descriptor["document_prefix"])
    texts = [document_prefix + str(chunk["content"]) for chunk in chunks]
    vectors = _embedding_vectors(
        embed_documents=embed_documents,
        texts=texts,
        chunks=chunks,
        dimension=int(descriptor["dimension"]),
        normalization=str(descriptor["normalization"]),
    )

    records = [
        {
            "chunk_id": str(chunk["chunk_id"]),
            "chunk_type": str(chunk["chunk_type"]),
            "content_sha256": _content_sha256(
                str(chunk["content"]), chunk_id=str(chunk["chunk_id"])
            ),
            "vector": vector,
        }
        for chunk, vector in zip(chunks, vectors, strict=True)
    ]
    corpus_id = str(root["corpus_id"])
    scenario_id = str(root["scenario_id"])
    output: dict[str, object] = {
        "schema_version": VECTOR_INDEX_SCHEMA_VERSION,
        "index_id": _deterministic_index_id(
            corpus_id=corpus_id,
            scenario_id=scenario_id,
            corpus_sha256=source_hash,
            embedding=descriptor,
        ),
        "corpus_provenance": {
            "path": source_path,
            "schema_version": RETRIEVAL_CORPUS_SCHEMA_VERSION,
            "sha256": source_hash,
            "corpus_id": corpus_id,
            "scenario_id": scenario_id,
        },
        "embedding": descriptor,
        "records": records,
        "review": {
            "review_status": "pending_human_review",
            "reviewer": None,
            "reviewed_at": None,
            "notes": [
                "This vector index was generated automatically from a validated Retrieval Corpus document.",
                "The embedding output and corpus coverage have not been reviewed by a human.",
            ],
        },
        "warnings": sorted(set(root["warnings"])),
        "metadata": {
            "record_count": len(records),
            "vector_dimension": descriptor["dimension"],
            "complete_corpus_coverage": True,
        },
    }
    try:
        json.dumps(
            output,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise VectorIndexBuildError(
            f"Built Vector Index cannot be represented as UTF-8 JSON: {exc}"
        ) from exc

    try:
        validate_vector_index(output)
    except VectorIndexValidationError as exc:
        raise VectorIndexBuildError(
            f"Built Vector Index failed validation: {exc}"
        ) from exc
    return output


__all__ = ("VectorIndexBuildError", "build_vector_index")
