"""Tests for Two-Stage Gate integration in query_graphrag_context CLI."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import pytest

import scripts.query_graphrag_context as cli


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs/gate/two_stage_production_policy.json"
V2_CORPUS = ROOT / "outputs/v2/retrieval/mshta-powershell/retrieval_corpus.json"
V2_INDEX = ROOT / "outputs/v2/retrieval/mshta-powershell/vector_index_e5.json"
V2_GRAPH = ROOT / "outputs/v2/graph/mshta-powershell/knowledge_graph.json"


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


@pytest.fixture(scope="module")
def hashes():
    assert V2_CORPUS.is_file(), "v2 corpus must exist"
    assert V2_INDEX.is_file(), "v2 index must exist"
    assert V2_GRAPH.is_file(), "v2 graph must exist"
    assert POLICY_PATH.is_file(), "gate policy must exist"
    return {
        "corpus": digest(V2_CORPUS),
        "index": digest(V2_INDEX),
        "graph": digest(V2_GRAPH),
    }


def test_cli_gate_format_decision_only(hashes, capsys):
    query = "Which process chain led to powershell.exe in the reviewed evidence?"
    argv = [
        "--corpus", str(V2_CORPUS),
        "--vector-index", str(V2_INDEX),
        "--graph", str(V2_GRAPH),
        "--query", query,
        "--expected-corpus-sha256", hashes["corpus"],
        "--expected-index-sha256", hashes["index"],
        "--expected-graph-sha256", hashes["graph"],
        "--gate-policy", str(POLICY_PATH),
        "--format", "decision-only",
    ]
    ret = cli.main(argv)
    assert ret == 0
    captured = capsys.readouterr()
    decision = json.loads(captured.out)
    assert decision["schema_version"] == "graphrag-two-stage-gate-decision/v1"
    assert "decision" in decision
    assert decision["decision"] == "proceed"


def test_cli_gate_format_gated_context_proceed(hashes, capsys):
    query = "Which process chain led to powershell.exe in the reviewed evidence?"
    argv = [
        "--corpus", str(V2_CORPUS),
        "--vector-index", str(V2_INDEX),
        "--graph", str(V2_GRAPH),
        "--query", query,
        "--expected-corpus-sha256", hashes["corpus"],
        "--expected-index-sha256", hashes["index"],
        "--expected-graph-sha256", hashes["graph"],
        "--gate-policy", str(POLICY_PATH),
        "--format", "gated-context",
    ]
    ret = cli.main(argv)
    assert ret == 0
    captured = capsys.readouterr()
    envelope = json.loads(captured.out)
    assert envelope["schema_version"] == "gated-graphrag-context/v1"
    assert envelope["status"] == "proceed"
    assert envelope["context"] is not None
    assert envelope["context"]["schema_version"] == "graphrag-context/v1"


def test_cli_gate_enforce_gate_rejects_unrelated(hashes, capsys):
    query = "Thời tiết ngày mai ở Hà Nội thế nào?"
    argv = [
        "--corpus", str(V2_CORPUS),
        "--vector-index", str(V2_INDEX),
        "--graph", str(V2_GRAPH),
        "--query", query,
        "--expected-corpus-sha256", hashes["corpus"],
        "--expected-index-sha256", hashes["index"],
        "--expected-graph-sha256", hashes["graph"],
        "--gate-policy", str(POLICY_PATH),
        "--enforce-gate",
    ]
    ret = cli.main(argv)
    assert ret == 1
    captured = capsys.readouterr()
    assert "query rejected by two-stage gate" in captured.err
