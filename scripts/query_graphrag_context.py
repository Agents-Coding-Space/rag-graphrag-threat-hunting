#!/usr/bin/env python3
"""Query linked retrieval and graph artifacts with their pinned embedding model."""

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

from threat_hunting.graph import load_knowledge_graph  # noqa: E402
from threat_hunting.graphrag import (  # noqa: E402
    GRAPHRAG_CONTEXT_SCHEMA_VERSION,
    build_graphrag_context,
)
from threat_hunting.graphrag.gate_signals import extract_graphrag_gate_signals  # noqa: E402
from threat_hunting.graphrag.two_stage_gate import assess_graphrag_two_stage_gate  # noqa: E402
from threat_hunting.retrieval import (  # noqa: E402
    SentenceTransformerEmbeddingBackend,
    load_retrieval_corpus,
    load_vector_index,
)


_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")
_REVISION_PATTERN = re.compile(r"[0-9a-fA-F]{40}\Z")


class GraphRAGQueryCliError(ValueError):
    """Raised when a query cannot safely emit a complete GraphRAG context."""


def _expected_hash(value: str, option: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise GraphRAGQueryCliError(
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
        raise GraphRAGQueryCliError(f"cannot hash input {path}: {exc}") from exc
    return digest.hexdigest()


def _assert_input_hashes(
    inputs: tuple[tuple[Path, str], ...], *, phase: str,
) -> None:
    for path, expected in inputs:
        actual = _sha256_file(path)
        if actual != expected:
            raise GraphRAGQueryCliError(
                f"input SHA-256 mismatch {phase} for {path}: "
                f"expected {expected}, got {actual}"
            )


def _preflight(
    corpus: dict[str, Any], index: dict[str, Any], graph: dict[str, Any],
    corpus_sha256: str,
) -> None:
    provenance = index["corpus_provenance"]
    for field in ("corpus_id", "scenario_id"):
        if provenance[field] != corpus[field]:
            raise GraphRAGQueryCliError(
                f"preflight: Vector Index {field} does not match Retrieval Corpus"
            )
    if provenance["sha256"].lower() != corpus_sha256:
        raise GraphRAGQueryCliError(
            "preflight: Vector Index corpus SHA-256 does not match input"
        )
    if corpus["scenario_id"] != graph["scenario_id"]:
        raise GraphRAGQueryCliError(
            "preflight: Retrieval Corpus and Knowledge Graph scenario_id mismatch"
        )
    # Compare complete JSON values, including types, without changing provenance.
    sources = [json.dumps(
        artifact["source_ground_truth"], ensure_ascii=False, sort_keys=True,
        allow_nan=False, separators=(",", ":"),
    ) for artifact in (corpus, graph)]
    if sources[0] != sources[1]:
        raise GraphRAGQueryCliError(
            "preflight: Retrieval Corpus and Knowledge Graph Ground Truth provenance mismatch"
        )


def query_graphrag_context(
    *, corpus_path: Path, vector_index_path: Path, graph_path: Path, query: str,
    expected_corpus_sha256: str, expected_index_sha256: str,
    expected_graph_sha256: str,
    top_k: int = 5, candidate_k: int = 20,
    chunk_types: list[str] | None = None,
    required_dimensions: list[str] | None = None,
    direction: str = "both", max_depth: int = 2,
    allowed_edge_types: list[str] | None = None,
    max_nodes: int = 100, max_edges: int = 200,
    backend_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Load guarded inputs and delegate once to the existing orchestration API.

    The embedding callback alone creates the backend. Retrieval owns prefixes,
    ranking and filtering; orchestration owns exact mapping and traversal.
    Input hashes are checked before loading and after orchestration; main checks
    them once more after serialization, immediately before emitting stdout.
    """
    try:
        inputs = (
            (Path(corpus_path), _expected_hash(
                expected_corpus_sha256, "--expected-corpus-sha256",
            )),
            (Path(vector_index_path), _expected_hash(
                expected_index_sha256, "--expected-index-sha256",
            )),
            (Path(graph_path), _expected_hash(
                expected_graph_sha256, "--expected-graph-sha256",
            )),
        )
        with redirect_stdout(sys.stderr):
            _assert_input_hashes(inputs, phase="before load")
            corpus = load_retrieval_corpus(inputs[0][0])
            index = load_vector_index(inputs[1][0])
            graph = load_knowledge_graph(inputs[2][0])
            _preflight(corpus, index, graph, inputs[0][1])
            embedding = index["embedding"]
            if embedding["provider"] != "sentence-transformers":
                raise GraphRAGQueryCliError(
                    "Vector Index embedding.provider must be 'sentence-transformers'"
                )
            revision = embedding["model_revision"]
            if _REVISION_PATTERN.fullmatch(revision) is None:
                raise GraphRAGQueryCliError(
                    "Vector Index model_revision must be a full 40-character hexadecimal commit SHA"
                )
            backend: Any = None

            def embed_query(texts: list[str]) -> object:
                nonlocal backend
                if backend is None:
                    try:
                        factory = (
                            backend_factory if backend_factory is not None
                            else SentenceTransformerEmbeddingBackend
                        )
                        initialized = factory(
                            model_id=embedding["model_id"], model_revision=revision,
                            dimension=embedding["dimension"], device="cpu",
                            batch_size=1, show_progress_bar=False,
                        )
                        if not callable(getattr(initialized, "embed_documents", None)):
                            raise GraphRAGQueryCliError(
                                "embedding backend must provide embed_documents()"
                            )
                        backend = initialized
                    except Exception as exc:
                        raise GraphRAGQueryCliError(
                            f"embedding backend initialization failed: {exc}"
                        ) from exc
                return backend.embed_documents(texts)

            result = build_graphrag_context(
                corpus, index, graph, query, corpus_sha256=inputs[0][1],
                embed_query=embed_query, top_k=top_k, candidate_k=candidate_k,
                chunk_types=chunk_types, required_dimensions=required_dimensions,
                direction=direction, max_depth=max_depth,
                allowed_edge_types=allowed_edge_types,
                max_nodes=max_nodes, max_edges=max_edges,
            )
            _assert_input_hashes(inputs, phase="after orchestration")
        return result
    except GraphRAGQueryCliError:
        raise
    except Exception as exc:
        raise GraphRAGQueryCliError(f"GraphRAG query failed: {exc}") from exc


def _serialize(result: dict[str, Any]) -> str:
    try:
        if (
            not isinstance(result, dict)
            or result.get("schema_version") != GRAPHRAG_CONTEXT_SCHEMA_VERSION
        ):
            raise ValueError("expected a graphrag-context JSON object")
        output = json.dumps(
            result, ensure_ascii=False, sort_keys=True, allow_nan=False,
            separators=(",", ":"),
        )
        output.encode("utf-8", errors="strict")
        return output
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError) as exc:
        raise GraphRAGQueryCliError(
            f"cannot serialize GraphRAG context as UTF-8 JSON: {exc}"
        ) from exc


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise GraphRAGQueryCliError(message)


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        description=(
            "Retrieve and traverse linked artifacts with a pinned embedding model on CPU. "
            "BM25, cosine and RRF are ranking scores, not probabilities."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--vector-index", type=Path, required=True)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--candidate-k", type=int, default=20)
    parser.add_argument("--chunk-type", action="append", dest="chunk_types")
    parser.add_argument("--required-dimension", action="append", dest="required_dimensions")
    parser.add_argument("--direction", choices=("outgoing", "incoming", "both"), default="both")
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--allowed-edge-type", action="append", dest="allowed_edge_types")
    parser.add_argument("--max-nodes", type=int, default=100)
    parser.add_argument("--max-edges", type=int, default=200)
    parser.add_argument("--expected-corpus-sha256", required=True)
    parser.add_argument("--expected-index-sha256", required=True)
    parser.add_argument("--expected-graph-sha256", required=True)
    parser.add_argument("--gate-policy", type=Path, default=None,
                        help="Path to Two-Stage Gate policy JSON (e.g. configs/gate/two_stage_production_policy.json)")
    parser.add_argument("--enforce-gate", action="store_true", default=False,
                        help="When set, reject questions failing Two-Stage Gate with exit code 1 and explanation")
    parser.add_argument("--format", choices=("context", "gated-context", "decision-only"), default="context",
                        help="Output format: 'context' (raw GraphRAG context), 'gated-context' (wrapped with gate decision), or 'decision-only'")
    return parser


def _configure_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict", newline="\n")


def main(
    argv: list[str] | None = None,
    *, backend_factory: Callable[..., Any] | None = None,
) -> int:
    try:
        _configure_utf8_streams()
        args = _build_parser().parse_args(argv)
        with redirect_stdout(sys.stderr):
            result = query_graphrag_context(
                corpus_path=args.corpus, vector_index_path=args.vector_index,
                graph_path=args.graph, query=args.query,
                expected_corpus_sha256=args.expected_corpus_sha256,
                expected_index_sha256=args.expected_index_sha256,
                expected_graph_sha256=args.expected_graph_sha256,
                top_k=args.top_k, candidate_k=args.candidate_k,
                chunk_types=args.chunk_types, required_dimensions=args.required_dimensions,
                direction=args.direction, max_depth=args.max_depth,
                allowed_edge_types=args.allowed_edge_types,
                max_nodes=args.max_nodes, max_edges=args.max_edges,
                backend_factory=backend_factory,
            )
            
            gate_decision = None
            if args.gate_policy is not None:
                policy_doc = json.loads(args.gate_policy.read_text(encoding="utf-8"))
                # Unwrap policy if wrapped in production policy document
                policy = policy_doc.get("policy", policy_doc)
                if "topical_relevance" in policy_doc and "evidence_answerability" in policy_doc:
                    policy = {
                        "schema_version": policy_doc.get("schema_version", "graphrag-two-stage-gate-policy/v1"),
                        "policy_id": policy_doc.get("policy_id", "prod-policy"),
                        "topical_relevance": policy_doc["topical_relevance"],
                        "evidence_answerability": policy_doc["evidence_answerability"],
                    }
                signals = extract_graphrag_gate_signals(result)
                gate_decision = assess_graphrag_two_stage_gate(signals, policy=policy)

            if args.gate_policy is not None and args.enforce_gate and gate_decision is not None:
                if gate_decision.get("decision") == "abstain":
                    stage = gate_decision.get("abstention_stage", "unknown")
                    reason = "insufficient_evidence" if stage == "evidence_answerability" else "unrelated"
                    reasons = gate_decision.get("reason_codes", [])
                    print(f"error: query rejected by two-stage gate ({reason}): {reasons}", file=sys.stderr)
                    return 1

            if args.format == "decision-only":
                if gate_decision is None:
                    raise GraphRAGQueryCliError("--format decision-only requires --gate-policy")
                output = json.dumps(gate_decision, ensure_ascii=False, indent=2) + "\n"
            elif args.format == "gated-context":
                if gate_decision is None:
                    raise GraphRAGQueryCliError("--format gated-context requires --gate-policy")
                gated_envelope = {
                    "schema_version": "gated-graphrag-context/v1",
                    "status": gate_decision["decision"],
                    "gate_decision": gate_decision,
                    "context": result if gate_decision["decision"] == "proceed" else None,
                }
                output = json.dumps(gated_envelope, ensure_ascii=False, indent=2) + "\n"
            else:
                output = _serialize(result) + "\n"

            _assert_input_hashes((
                (args.corpus, _expected_hash(
                    args.expected_corpus_sha256, "--expected-corpus-sha256",
                )),
                (args.vector_index, _expected_hash(
                    args.expected_index_sha256, "--expected-index-sha256",
                )),
                (args.graph, _expected_hash(
                    args.expected_graph_sha256, "--expected-graph-sha256",
                )),
            ), phase="before stdout after serialization")
        sys.stdout.write(output)
        sys.stdout.flush()
    except Exception as exc:
        message = f"error: {exc}".encode("utf-8", errors="backslashreplace").decode("utf-8")
        print(message, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
