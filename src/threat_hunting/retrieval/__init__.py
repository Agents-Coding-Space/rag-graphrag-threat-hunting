"""Retrieval Corpus contracts for scenario-independent RAG inputs."""

from .builder import RetrievalCorpusBuildError, build_retrieval_corpus
from .lexical import (
    LEXICAL_RETRIEVAL_METHOD,
    RETRIEVAL_RESULT_SCHEMA_VERSION,
    LexicalRetrievalError,
    retrieve_lexical,
    tokenize_retrieval_text,
)
from .schema import (
    RETRIEVAL_CORPUS_SCHEMA_VERSION,
    RetrievalCorpusValidationError,
    load_retrieval_corpus,
    validate_retrieval_corpus,
)

__all__ = (
    "LEXICAL_RETRIEVAL_METHOD",
    "RETRIEVAL_CORPUS_SCHEMA_VERSION",
    "RETRIEVAL_RESULT_SCHEMA_VERSION",
    "LexicalRetrievalError",
    "RetrievalCorpusBuildError",
    "RetrievalCorpusValidationError",
    "build_retrieval_corpus",
    "load_retrieval_corpus",
    "retrieve_lexical",
    "tokenize_retrieval_text",
    "validate_retrieval_corpus",
)
