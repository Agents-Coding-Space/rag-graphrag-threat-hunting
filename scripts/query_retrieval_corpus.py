#!/usr/bin/env python3
"""Query a validated Retrieval Corpus with the lexical retriever."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPOSITORY_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from threat_hunting.retrieval import (  # noqa: E402
    LexicalRetrievalError,
    RetrievalCorpusValidationError,
    load_retrieval_corpus,
    retrieve_lexical,
)


_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")


class RetrievalQueryCliError(ValueError):
    """Raised when the CLI cannot safely complete a corpus query."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise RetrievalQueryCliError(f"cannot hash corpus {path}: {exc}") from exc
    return digest.hexdigest()


def _normalize_expected_hash(value: str | None) -> str | None:
    if value is None:
        return None
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise RetrievalQueryCliError(
            "--expected-corpus-sha256 must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _assert_expected_hash(
    path: Path,
    actual_hash: str,
    expected_hash: str | None,
    *,
    phase: str,
) -> None:
    if expected_hash is not None and actual_hash != expected_hash:
        raise RetrievalQueryCliError(
            f"corpus SHA-256 mismatch {phase} for {path}: "
            f"expected {expected_hash}, got {actual_hash}"
        )


def query_corpus(
    *,
    corpus_path: Path,
    query: str,
    top_k: int,
    chunk_types: list[str] | None,
    required_dimensions: list[str] | None,
    expected_corpus_sha256: str | None,
) -> dict[str, Any]:
    """Load and query one corpus while verifying that its bytes stay unchanged."""

    expected_hash = _normalize_expected_hash(expected_corpus_sha256)
    hash_before = _sha256_file(corpus_path)
    _assert_expected_hash(
        corpus_path,
        hash_before,
        expected_hash,
        phase="before query",
    )

    corpus = load_retrieval_corpus(corpus_path)
    result = retrieve_lexical(
        corpus,
        query,
        top_k=top_k,
        chunk_types=chunk_types,
        required_dimensions=required_dimensions,
    )

    hash_after = _sha256_file(corpus_path)
    if hash_after != hash_before:
        raise RetrievalQueryCliError(
            f"corpus changed during query for {corpus_path}: "
            f"before {hash_before}, after {hash_after}"
        )
    _assert_expected_hash(
        corpus_path,
        hash_after,
        expected_hash,
        phase="after query",
    )
    return result


def _serialize(result: dict[str, Any]) -> str:
    return json.dumps(
        result,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Query a validated Retrieval Corpus with deterministic lexical BM25 "
            "retrieval. Scores represent retrieval relevance, not probability."
        )
    )
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument(
        "--chunk-type",
        action="append",
        dest="chunk_types",
        help="Restrict retrieval to this chunk type; may be repeated.",
    )
    parser.add_argument(
        "--required-dimension",
        action="append",
        dest="required_dimensions",
        help="Require this queryable dimension; may be repeated.",
    )
    parser.add_argument("--expected-corpus-sha256")
    return parser


def _configure_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict", newline="\n")


def main(argv: list[str] | None = None) -> int:
    _configure_utf8_streams()
    args = _build_parser().parse_args(argv)
    try:
        result = query_corpus(
            corpus_path=args.corpus,
            query=args.query,
            top_k=args.top_k,
            chunk_types=args.chunk_types,
            required_dimensions=args.required_dimensions,
            expected_corpus_sha256=args.expected_corpus_sha256,
        )
        output = _serialize(result)
    except (
        LexicalRetrievalError,
        RetrievalCorpusValidationError,
        RetrievalQueryCliError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
