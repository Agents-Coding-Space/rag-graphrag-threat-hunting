"""Extract returned-context signals without assessing relevance or answer truth.

The two signal groups describe returned retrieval hits and the returned graph
neighborhood only. Counts do not establish sufficient evidence, and retrieval
scores are not probabilities. This module neither makes a gate decision nor
recomputes source scores, authenticates raw references, or accesses artifacts.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..retrieval.lexical import tokenize_retrieval_text
from ..retrieval.schema import (
    CHUNK_SOURCE_OBJECT_TYPES,
    CHUNK_STATUSES,
    _scan_contract_guards,
)
from .relevance import _json_bytes, _validated_context_and_signals


GRAPHRAG_GATE_SIGNALS_SCHEMA_VERSION = "graphrag-gate-signals/v1"


class GraphRAGGateSignalError(ValueError):
    """Raised when a context cannot safely supply deterministic gate signals."""


def _opaque_contract_guards(root: Mapping[str, Any]) -> None:
    """Reuse source guards on opaque maps; structural fields are validated once.

    Scanning the whole hybrid envelope would reject its legitimate vector
    component. Source statuses are already checked by the shared context validator.
    """
    for index, hit in enumerate(root["retrieval"]["hits"]):
        _scan_contract_guards(
            hit["chunk"]["metadata"],
            f"context.retrieval.hits[{index}].chunk.metadata",
        )
    if root["traversal"] is not None:
        for collection in ("nodes", "edges"):
            for index, item in enumerate(root["traversal"][collection]):
                _scan_contract_guards(
                    item["attributes"],
                    f"context.traversal.{collection}[{index}].attributes",
                )


def _topical_signals(
    root: Mapping[str, Any], legacy: Mapping[str, Any],
) -> dict[str, object]:
    hits = root["retrieval"]["hits"]
    rrf_scores = [hit["score"] for hit in hits]
    bm25_scores = [
        hit["components"]["lexical"]["score"]
        for hit in hits if hit["components"]["lexical"] is not None
    ]
    query_tokens = set(tokenize_retrieval_text(root["query"]["text"]))
    returned_tokens: set[str] = set()
    for hit in hits:
        returned_tokens.update(tokenize_retrieval_text(hit["chunk"]["title"]))
        returned_tokens.update(tokenize_retrieval_text(hit["chunk"]["content"]))
    matched = len(query_tokens & returned_tokens)
    return {
        "retrieval_hit_count": legacy["retrieval_hit_count"],
        "lexical_hit_count": legacy["lexical_hit_count"],
        "vector_hit_count": legacy["vector_hit_count"],
        "joint_lexical_vector_hit_count": legacy["joint_lexical_vector_hit_count"],
        "returned_top_rrf_score": max(rrf_scores) if rrf_scores else None,
        "returned_top_bm25_score": max(bm25_scores) if bm25_scores else None,
        "returned_top_cosine_score": legacy["top_cosine_score"],
        "query_token_count": len(query_tokens),
        "matched_query_token_count": matched,
        "query_token_coverage": round(matched / len(query_tokens), 8) if query_tokens else 0.0,
    }


def _answerability_signals(
    root: Mapping[str, Any], legacy: Mapping[str, Any],
) -> dict[str, object]:
    type_counts = dict.fromkeys(CHUNK_SOURCE_OBJECT_TYPES, 0)
    status_counts = dict.fromkeys(sorted(CHUNK_STATUSES), 0)
    evidence_hits = reference_hits = 0
    references: set[bytes] = set()
    for hit in root["retrieval"]["hits"]:
        chunk = hit["chunk"]
        type_counts[chunk["chunk_type"]] += 1
        status_counts[chunk["status"]] += 1
        evidence_hits += bool(chunk["evidence_ids"])
        reference_hits += bool(chunk["source_references"])
        references.update(_json_bytes(reference) for reference in chunk["source_references"])
    traversal = root["traversal"]
    nodes = [] if traversal is None else traversal["nodes"]
    edges = [] if traversal is None else traversal["edges"]
    return {
        "chunk_type_counts": type_counts,
        "status_counts": status_counts,
        "hits_with_evidence_ids": evidence_hits,
        "hits_with_source_references": reference_hits,
        "unique_source_reference_count": len(references),
        "mapped_hit_count": legacy["mapped_hit_count"],
        "seed_node_count": legacy["seed_node_count"],
        "traversal_performed": legacy["traversal_performed"],
        "traversal_node_count": legacy["traversal_node_count"],
        "traversal_edge_count": legacy["traversal_edge_count"],
        "traversal_path_count": legacy["traversal_path_count"],
        "traversed_evidence_node_count": sum(node["node_type"] == "evidence" for node in nodes),
        "traversed_limitation_node_count": sum(node["node_type"] == "limitation" for node in nodes),
        "support_edge_count": sum(
            edge["edge_type"] in {"supports", "supports_assessment"} for edge in edges
        ),
    }


def _source_warnings(root: Mapping[str, Any]) -> list[str]:
    stages = [root, root["retrieval"], root["seed_mapping"]]
    if root["traversal"] is not None:
        stages.append(root["traversal"])
    return list(dict.fromkeys(warning for stage in stages for warning in stage["warnings"]))


def extract_graphrag_gate_signals(context: Mapping[str, object]) -> dict[str, object]:
    """Return detached finite signals from one validated in-memory context.

    Query tokens are unique tokenizer outputs, matched exactly against the union
    of returned title/content tokens. Coverage is rounded to eight decimal places.
    Raw-reference uniqueness uses canonical JSON, independent of object key order.
    Mapped-hit counts require nonempty matched node IDs. Null traversal has zero
    traversal counts. Source warnings retain their first occurrence in stage order.

    No labels, expected answers, or opaque metadata values supply signals.
    Source files are not read. Opaque maps also pass the source contract's
    recursive status and content guards.
    All technical input failures raise GraphRAGGateSignalError.
    """
    try:
        root, legacy = _validated_context_and_signals(context)
        _opaque_contract_guards(root)
        topical = _topical_signals(root, legacy)
        answerability = _answerability_signals(root, legacy)
        result = {
            "schema_version": GRAPHRAG_GATE_SIGNALS_SCHEMA_VERSION,
            "corpus_id": root["corpus_id"],
            "graph_id": root["graph_id"],
            "scenario_id": root["scenario_id"],
            "source_ground_truth": root["source_ground_truth"],
            "query": root["query"],
            "topical_relevance": topical,
            "evidence_answerability": answerability,
            "warnings": _source_warnings(root),
            "metadata": {
                "decision_made": False,
                "score_interpretations": {
                    "rrf": "reciprocal_rank_fusion_not_probability",
                    "bm25": "bm25_relevance_not_probability",
                    "cosine": "cosine_similarity_not_probability",
                },
                "topical_signal_count": len(topical),
                "answerability_signal_count": len(answerability),
            },
        }
        _json_bytes(result)
        return result
    except Exception as exc:
        raise GraphRAGGateSignalError(f"Invalid GraphRAG gate signal input: {exc}") from exc


__all__ = (
    "GRAPHRAG_GATE_SIGNALS_SCHEMA_VERSION", "GraphRAGGateSignalError",
    "extract_graphrag_gate_signals",
)
