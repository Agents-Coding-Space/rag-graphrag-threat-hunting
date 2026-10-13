"""Extract returned-context signals without assessing relevance or answer truth.

The two signal groups describe returned retrieval hits and the returned graph
neighborhood only. Counts do not establish sufficient evidence, and retrieval
scores are not probabilities. This module neither makes a gate decision nor
recomputes source scores, authenticates raw references, or accesses artifacts.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
from typing import Any, cast

from ..retrieval.lexical import tokenize_retrieval_text
from ..retrieval.schema import (
    CHUNK_SOURCE_OBJECT_TYPES,
    CHUNK_STATUSES,
    _scan_contract_guards,
)
from .relevance import (
    _boolean, _integer, _json_bytes, _object, _provenance, _query, _require,
    _snapshot, _strings, _text, _validated_context_and_signals,
)


GRAPHRAG_GATE_SIGNALS_SCHEMA_VERSION = "graphrag-gate-signals/v1"


class GraphRAGGateSignalError(ValueError):
    """Raised when a context cannot safely supply deterministic gate signals."""


_GATE_FIELDS = (
    "schema_version", "corpus_id", "graph_id", "scenario_id", "source_ground_truth",
    "query", "topical_relevance", "evidence_answerability", "warnings", "metadata",
)
_TOPICAL_FIELDS = (
    "retrieval_hit_count", "lexical_hit_count", "vector_hit_count",
    "joint_lexical_vector_hit_count", "returned_top_rrf_score",
    "returned_top_bm25_score", "returned_top_cosine_score", "query_token_count",
    "matched_query_token_count", "query_token_coverage",
)
_ANSWERABILITY_FIELDS = (
    "chunk_type_counts", "status_counts", "hits_with_evidence_ids",
    "hits_with_source_references", "unique_source_reference_count", "mapped_hit_count",
    "seed_node_count", "traversal_performed", "traversal_node_count",
    "traversal_edge_count", "traversal_path_count", "traversed_evidence_node_count",
    "traversed_limitation_node_count", "support_edge_count",
)
_TRAVERSAL_COUNT_FIELDS = (
    "traversal_node_count", "traversal_edge_count", "traversal_path_count",
    "traversed_evidence_node_count", "traversed_limitation_node_count", "support_edge_count",
)
_SCORE_INTERPRETATIONS = {
    "rrf": "reciprocal_rank_fusion_not_probability",
    "bm25": "bm25_relevance_not_probability",
    "cosine": "cosine_similarity_not_probability",
}


def _signal_number(
    value: object, path: str, minimum: int | float, maximum: int | float | None = None,
) -> int | float:
    _require(type(value) in (int, float), f"{path} must be numeric, excluding bool")
    number = cast(int | float, value)
    try:
        finite = math.isfinite(number)
    except OverflowError:
        finite = False
    _require(finite, f"{path} must be finite")
    _require(number >= minimum and (maximum is None or number <= maximum), f"{path} is out of range")
    return number


def _validated_gate_signals(document: object) -> dict[str, Any]:
    """Detach and validate aggregate signals without authenticating source files.

    Per-hit counters are bounded by returned hits. Distinct raw references and
    seed nodes can exceed hits because a chunk may have multiple references or
    map relationship endpoints. Missing scores remain observable with nonzero
    membership counts, so an explicit policy can report a missing-score reason.
    """
    root = _object(
        json.loads(_json_bytes(_snapshot(document, "signals", set()))),
        "signals", _GATE_FIELDS,
    )
    _scan_contract_guards(root, "signals")
    _require(root["schema_version"] == GRAPHRAG_GATE_SIGNALS_SCHEMA_VERSION, "signals.schema_version is unsupported")
    for name in ("corpus_id", "graph_id", "scenario_id"):
        _text(root[name], f"signals.{name}")
    _provenance(root["source_ground_truth"], root["scenario_id"], "signals.source_ground_truth")
    query = _query(root["query"], "signals.query")
    _strings(root["warnings"], "signals.warnings")

    topical = _object(root["topical_relevance"], "signals.topical_relevance", _TOPICAL_FIELDS)
    for name in _TOPICAL_FIELDS:
        if name.endswith("_count"):
            _integer(topical[name], f"signals.topical_relevance.{name}")
    hits = topical["retrieval_hit_count"]
    lexical, vector, joint = (topical[name] for name in (
        "lexical_hit_count", "vector_hit_count", "joint_lexical_vector_hit_count",
    ))
    _require(max(lexical, vector) <= hits and joint <= min(lexical, vector), "signals hit memberships exceed returned hits")
    _require(lexical + vector - joint == hits, "signals hit membership union is inconsistent")
    _require(hits <= query["top_k"], "signals returned hits exceed query.top_k")
    for name, count, minimum, maximum in (
        ("returned_top_rrf_score", hits, 0, None),
        ("returned_top_bm25_score", lexical, 0, None),
        ("returned_top_cosine_score", vector, -1, 1),
    ):
        score = topical[name]
        _require(count != 0 or score is None, f"signals.topical_relevance.{name} must be null without hits")
        if score is not None:
            _signal_number(score, f"signals.topical_relevance.{name}", minimum, maximum)
    token_count, matched = topical["query_token_count"], topical["matched_query_token_count"]
    _require(token_count == len(set(tokenize_retrieval_text(query["text"]))), "signals query_token_count disagrees with query.text")
    _require(matched <= token_count and (hits != 0 or matched == 0), "signals matched query token count is inconsistent")
    coverage = _signal_number(topical["query_token_coverage"], "signals.topical_relevance.query_token_coverage", 0, 1)
    expected_coverage = round(matched / token_count, 8) if token_count else 0.0
    _require(coverage == expected_coverage, "signals query_token_coverage disagrees with token counts")

    answerability = _object(root["evidence_answerability"], "signals.evidence_answerability", _ANSWERABILITY_FIELDS)
    for name, vocabulary in (("chunk_type_counts", tuple(CHUNK_SOURCE_OBJECT_TYPES)), ("status_counts", tuple(sorted(CHUNK_STATUSES)))):
        counts = _object(answerability[name], f"signals.evidence_answerability.{name}", vocabulary)
        for kind in vocabulary:
            _integer(counts[kind], f"signals.evidence_answerability.{name}.{kind}")
        _require(sum(counts.values()) == hits, f"signals.evidence_answerability.{name} total disagrees with hits")
    for name in _ANSWERABILITY_FIELDS:
        if name.endswith("_count") or name.startswith("hits_with_"):
            _integer(answerability[name], f"signals.evidence_answerability.{name}")
    for name in ("hits_with_evidence_ids", "hits_with_source_references", "mapped_hit_count"):
        _require(answerability[name] <= hits, f"signals.evidence_answerability.{name} exceeds hits")
    references = answerability["unique_source_reference_count"]
    reference_hits = answerability["hits_with_source_references"]
    _require((references == 0) == (reference_hits == 0), "signals raw-reference counts are inconsistent")
    performed = _boolean(answerability["traversal_performed"], "signals.evidence_answerability.traversal_performed")
    if not performed:
        _require(all(answerability[name] == 0 for name in _TRAVERSAL_COUNT_FIELDS), "signals null traversal must have zero traversal counts")
    node_count = answerability["traversal_node_count"]
    if performed:
        seeds = answerability["seed_node_count"]
        _require(seeds > 0 and node_count >= seeds and answerability["traversal_path_count"] >= seeds, "signals performed traversal omits seeds, nodes or seed paths")
    _require(answerability["traversed_evidence_node_count"] + answerability["traversed_limitation_node_count"] <= node_count, "signals evidence/limitation counts exceed traversal nodes")
    _require(answerability["support_edge_count"] <= answerability["traversal_edge_count"], "signals support edges exceed traversal edges")

    metadata = _object(root["metadata"], "signals.metadata", (
        "decision_made", "score_interpretations", "topical_signal_count", "answerability_signal_count",
    ))
    _require(_boolean(metadata["decision_made"], "signals.metadata.decision_made") is False, "signals.metadata.decision_made must be false")
    interpretations = _object(metadata["score_interpretations"], "signals.metadata.score_interpretations", tuple(_SCORE_INTERPRETATIONS))
    _require(interpretations == _SCORE_INTERPRETATIONS, "signals score interpretations are unsupported")
    for name, count in (("topical_signal_count", len(_TOPICAL_FIELDS)), ("answerability_signal_count", len(_ANSWERABILITY_FIELDS))):
        _require(_integer(metadata[name], f"signals.metadata.{name}") == count, f"signals.metadata.{name} is inconsistent")
    return root


def validate_graphrag_gate_signals(document: Mapping[str, object]) -> None:
    """Validate a strict finite gate signal document, preserving caller input.

    This validates observable aggregate relationships and source provenance
    syntax only. It neither reads artifacts nor establishes answer truth.
    Technical failures raise GraphRAGGateSignalError; process interrupts escape.
    """
    try:
        _validated_gate_signals(document)
    except Exception as exc:
        raise GraphRAGGateSignalError(f"Invalid GraphRAG gate signals: {exc}") from exc


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
    "extract_graphrag_gate_signals", "validate_graphrag_gate_signals",
)
