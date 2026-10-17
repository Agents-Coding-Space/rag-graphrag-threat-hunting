#!/usr/bin/env python3
"""Query a validated Vector Index using its pinned local embedding model."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import redirect_stdout
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, NoReturn


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPOSITORY_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from threat_hunting.retrieval import (  # noqa: E402
    SentenceTransformerEmbeddingBackend,
    load_retrieval_corpus,
    load_vector_index,
    retrieve_vector,
)


_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")
_REVISION_PATTERN = re.compile(r"[0-9a-fA-F]{40}\Z")


class VectorQueryCliError(ValueError):
    """Raised when a vector query cannot safely produce a complete result."""


def _expected_hash(value: str, option: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise VectorQueryCliError(
            f"{option} must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise VectorQueryCliError(f"cannot hash input {path}: {exc}") from exc
    return digest.hexdigest()


def _assert_hash(path: Path, actual: str, expected: str) -> None:
    if actual != expected:
        raise VectorQueryCliError(
            f"SHA-256 mismatch before query for {path}: "
            f"expected {expected}, got {actual}"
        )


def query_vector_index(
    *,
    corpus_path: Path,
    vector_index_path: Path,
    query: str,
    top_k: int,
    chunk_types: list[str] | None,
    required_dimensions: list[str] | None,
    expected_corpus_sha256: str,
    expected_index_sha256: str,
    backend_factory: Callable[..., Any] = SentenceTransformerEmbeddingBackend,
) -> dict[str, Any]:
    """Retrieve without writing inputs; check both hashes before and after.

    Backend construction is deferred to the retriever's embedding callback so
    schema, provenance, linkage, query and filters are checked before creating
    the backend. The retriever alone applies the index's query prefix.
    """

    try:
        expected_corpus = _expected_hash(
            expected_corpus_sha256, "--expected-corpus-sha256"
        )
        expected_index = _expected_hash(
            expected_index_sha256, "--expected-index-sha256"
        )
        corpus_path = Path(corpus_path)
        vector_index_path = Path(vector_index_path)
        corpus_before = _sha256_file(corpus_path)
        index_before = _sha256_file(vector_index_path)
        _assert_hash(corpus_path, corpus_before, expected_corpus)
        _assert_hash(vector_index_path, index_before, expected_index)

        # Third-party model messages must never contaminate JSON stdout.
        with redirect_stdout(sys.stderr):
            corpus = load_retrieval_corpus(corpus_path)
            index = load_vector_index(vector_index_path)
            embedding = index["embedding"]
            if embedding["provider"] != "sentence-transformers":
                raise VectorQueryCliError(
                    f"Vector Index {vector_index_path}: embedding.provider "
                    "must be 'sentence-transformers'"
                )
            revision = embedding["model_revision"]
            if _REVISION_PATTERN.fullmatch(revision) is None:
                raise VectorQueryCliError(
                    f"Vector Index {vector_index_path}: model_revision must be "
                    "a full 40-character hexadecimal commit SHA"
                )

            def embed_query(texts: list[str]) -> object:
                try:
                    backend = backend_factory(
                        model_id=embedding["model_id"],
                        model_revision=revision,
                        dimension=embedding["dimension"],
                        device="cpu",
                        batch_size=1,
                        show_progress_bar=False,
                    )
                    callback = getattr(backend, "embed_documents", None)
                    if not callable(callback):
                        raise VectorQueryCliError(
                            "embedding backend must provide embed_documents()"
                        )
                except Exception as exc:
                    raise VectorQueryCliError(
                        f"embedding backend initialization failed: {exc}"
                    ) from exc
                return callback(texts)

            result = retrieve_vector(
                corpus,
                index,
                query,
                corpus_sha256=corpus_before,
                embed_query=embed_query,
                top_k=top_k,
                chunk_types=chunk_types,
                required_dimensions=required_dimensions,
            )

        corpus_after = _sha256_file(corpus_path)
        index_after = _sha256_file(vector_index_path)
        for path, before, after in (
            (corpus_path, corpus_before, corpus_after),
            (vector_index_path, index_before, index_after),
        ):
            if after != before:
                raise VectorQueryCliError(
                    f"input changed during query for {path}: "
                    f"before {before}, after {after}"
                )
        return result
    except VectorQueryCliError:
        raise
    except Exception as exc:
        raise VectorQueryCliError(f"vector query failed: {exc}") from exc


def _serialize(result: dict[str, Any]) -> str:
    try:
        output = json.dumps(
            result,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        # Validate encoding before any output is written, including surrogates.
        output.encode("utf-8", errors="strict")
        return output
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise VectorQueryCliError(
            f"cannot serialize retrieval result as UTF-8 JSON: {exc}"
        ) from exc


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise VectorQueryCliError(message)


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        description=(
            "Query a Vector Index with its pinned Sentence Transformers model "
            "on CPU. Scores are cosine similarities, not probabilities."
        )
    )
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--vector-index", type=Path, required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--chunk-type", action="append", dest="chunk_types")
    parser.add_argument(
        "--required-dimension", action="append", dest="required_dimensions"
    )
    parser.add_argument("--expected-corpus-sha256", required=True)
    parser.add_argument("--expected-index-sha256", required=True)
    return parser


def _configure_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict", newline="\n")


def main(
    argv: list[str] | None = None,
    *,
    backend_factory: Callable[..., Any] = SentenceTransformerEmbeddingBackend,
) -> int:
    try:
        _configure_utf8_streams()
        args = _build_parser().parse_args(argv)
        result = query_vector_index(
            corpus_path=args.corpus,
            vector_index_path=args.vector_index,
            query=args.query,
            top_k=args.top_k,
            chunk_types=args.chunk_types,
            required_dimensions=args.required_dimensions,
            expected_corpus_sha256=args.expected_corpus_sha256,
            expected_index_sha256=args.expected_index_sha256,
            backend_factory=backend_factory,
        )
        output = _serialize(result)
        sys.stdout.write(output + "\n")
        sys.stdout.flush()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
