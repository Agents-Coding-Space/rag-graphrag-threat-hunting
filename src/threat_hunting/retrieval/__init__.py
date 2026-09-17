"""Retrieval Corpus contracts for scenario-independent RAG inputs."""

from .schema import (
    RETRIEVAL_CORPUS_SCHEMA_VERSION,
    RetrievalCorpusValidationError,
    load_retrieval_corpus,
    validate_retrieval_corpus,
)

__all__ = (
    "RETRIEVAL_CORPUS_SCHEMA_VERSION",
    "RetrievalCorpusValidationError",
    "load_retrieval_corpus",
    "validate_retrieval_corpus",
)
