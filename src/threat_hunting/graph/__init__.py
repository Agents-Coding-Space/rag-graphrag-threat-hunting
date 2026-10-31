"""Scenario-independent Knowledge Graph contract, builder, and read-only loader."""

from .builder import KnowledgeGraphBuildError, build_knowledge_graph

from .schema import (
    KNOWLEDGE_GRAPH_SCHEMA_VERSION,
    KnowledgeGraphValidationError,
    load_knowledge_graph,
    validate_knowledge_graph,
)
from .traversal import KnowledgeGraphTraversalError, traverse_knowledge_graph

__all__ = (
    "KNOWLEDGE_GRAPH_SCHEMA_VERSION",
    "KnowledgeGraphBuildError",
    "KnowledgeGraphValidationError",
    "KnowledgeGraphTraversalError",
    "build_knowledge_graph",
    "load_knowledge_graph",
    "validate_knowledge_graph",
    "traverse_knowledge_graph",
)
