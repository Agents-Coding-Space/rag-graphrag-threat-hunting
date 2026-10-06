"""Retrieval Corpus contracts for scenario-independent RAG inputs."""

from .builder import RetrievalCorpusBuildError, build_retrieval_corpus
from .embedding_backend import (
    EmbeddingBackendError,
    SentenceTransformerEmbeddingBackend,
)
from .hybrid import HybridRetrievalError, retrieve_hybrid
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
from .vector_schema import (
    VECTOR_INDEX_SCHEMA_VERSION,
    VectorIndexValidationError,
    load_vector_index,
    validate_vector_index,
)
from .vector_builder import VectorIndexBuildError, build_vector_index
from .vector_search import VectorRetrievalError, retrieve_vector

__all__ = (
    "EmbeddingBackendError",
    "HybridRetrievalError",
    "LEXICAL_RETRIEVAL_METHOD",
    "RETRIEVAL_CORPUS_SCHEMA_VERSION",
    "RETRIEVAL_RESULT_SCHEMA_VERSION",
    "VECTOR_INDEX_SCHEMA_VERSION",
    "LexicalRetrievalError",
    "RetrievalCorpusBuildError",
    "RetrievalCorpusValidationError",
    "SentenceTransformerEmbeddingBackend",
    "VectorIndexBuildError",
    "VectorIndexValidationError",
    "VectorRetrievalError",
    "build_retrieval_corpus",
    "build_vector_index",
    "load_retrieval_corpus",
    "load_vector_index",
    "retrieve_hybrid",
    "retrieve_lexical",
    "retrieve_vector",
    "tokenize_retrieval_text",
    "validate_retrieval_corpus",
    "validate_vector_index",
)
