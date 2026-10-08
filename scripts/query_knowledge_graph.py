#!/usr/bin/env python3
"""Query an existing Knowledge Graph with bounded deterministic traversal."""

from __future__ import annotations

import argparse
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

from threat_hunting.graph import (  # noqa: E402
    load_knowledge_graph,
    traverse_knowledge_graph,
)


_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")


class KnowledgeGraphQueryCliError(ValueError):
    """Raised when a graph query cannot safely produce a complete result."""


def _expected_hash(value: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise KnowledgeGraphQueryCliError(
            "--expected-graph-sha256 must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise KnowledgeGraphQueryCliError(f"cannot hash graph {path}: {exc}") from exc
    return digest.hexdigest()


def _assert_graph_hash(path: Path, expected_hash: str, *, phase: str) -> None:
    actual_hash = _sha256_file(path)
    if actual_hash != expected_hash:
        raise KnowledgeGraphQueryCliError(
            f"Knowledge Graph SHA-256 mismatch {phase} for {path}: "
            f"expected {expected_hash}, got {actual_hash}"
        )


def query_knowledge_graph(
    *,
    graph_path: Path,
    expected_graph_sha256: str,
    seed_node_ids: list[str],
    direction: str = "both",
    max_depth: int = 2,
    allowed_edge_types: list[str] | None = None,
    max_nodes: int = 100,
    max_edges: int = 200,
) -> dict[str, Any]:
    """Delegate loading and traversal, retaining every selected source field.

    The graph bytes must match the supplied hash before loading and after
    traversal. The CLI checks again after serialization, before emitting JSON.
    """
    graph_path = Path(graph_path)
    expected_hash = _expected_hash(expected_graph_sha256)
    _assert_graph_hash(graph_path, expected_hash, phase="before load")
    with redirect_stdout(sys.stderr):
        graph = load_knowledge_graph(graph_path)
        result = traverse_knowledge_graph(
            graph,
            seed_node_ids=seed_node_ids,
            direction=direction,
            max_depth=max_depth,
            allowed_edge_types=allowed_edge_types,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )
    _assert_graph_hash(graph_path, expected_hash, phase="after traversal")
    return result


def _serialize(result: dict[str, Any]) -> str:
    try:
        output = json.dumps(
            result, ensure_ascii=False, sort_keys=True, allow_nan=False,
            separators=(",", ":"),
        )
        output.encode("utf-8", errors="strict")
        return output
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError) as exc:
        raise KnowledgeGraphQueryCliError(
            f"cannot serialize traversal result as UTF-8 JSON: {exc}"
        ) from exc


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise KnowledgeGraphQueryCliError(message)


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        description="Traverse an existing Knowledge Graph from explicit seed node IDs.",
        allow_abbrev=False,
    )
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--expected-graph-sha256", required=True)
    parser.add_argument("--seed-node-id", action="append", dest="seed_node_ids", required=True)
    parser.add_argument("--direction", choices=("outgoing", "incoming", "both"), default="both")
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--allowed-edge-type", action="append", dest="allowed_edge_types")
    parser.add_argument("--max-nodes", type=int, default=100)
    parser.add_argument("--max-edges", type=int, default=200)
    return parser


def _configure_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="strict", newline="\n")


def main(argv: list[str] | None = None) -> int:
    try:
        _configure_utf8_streams()
        args = _build_parser().parse_args(argv)
        result = query_knowledge_graph(
            graph_path=args.graph,
            expected_graph_sha256=args.expected_graph_sha256,
            seed_node_ids=args.seed_node_ids,
            direction=args.direction,
            max_depth=args.max_depth,
            allowed_edge_types=args.allowed_edge_types,
            max_nodes=args.max_nodes,
            max_edges=args.max_edges,
        )
        output = _serialize(result) + "\n"
        _assert_graph_hash(
            args.graph, _expected_hash(args.expected_graph_sha256), phase="before stdout",
        )
        sys.stdout.write(output)
        sys.stdout.flush()
    except Exception as exc:
        message = f"error: {exc}".encode("utf-8", errors="backslashreplace").decode("utf-8")
        print(message, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
