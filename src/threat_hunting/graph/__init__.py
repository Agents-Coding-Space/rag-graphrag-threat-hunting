"""Scenario-independent Knowledge Graph contract and read-only loader."""

from .schema import (
    KNOWLEDGE_GRAPH_SCHEMA_VERSION,
    KnowledgeGraphValidationError,
    load_knowledge_graph,
    validate_knowledge_graph,
)

__all__ = (
    "KNOWLEDGE_GRAPH_SCHEMA_VERSION",
    "KnowledgeGraphValidationError",
    "load_knowledge_graph",
    "validate_knowledge_graph",
)
