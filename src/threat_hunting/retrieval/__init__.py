"""Retrieval Corpus contracts for scenario-independent RAG inputs."""

from .builder import RetrievalCorpusBuildError, build_retrieval_corpus
from .schema import (
    RETRIEVAL_CORPUS_SCHEMA_VERSION,
    RetrievalCorpusValidationError,
    load_retrieval_corpus,
    validate_retrieval_corpus,
)

__all__ = (
    "RETRIEVAL_CORPUS_SCHEMA_VERSION",
    "RetrievalCorpusBuildError",
    "RetrievalCorpusValidationError",
    "build_retrieval_corpus",
    "load_retrieval_corpus",
    "validate_retrieval_corpus",
)
