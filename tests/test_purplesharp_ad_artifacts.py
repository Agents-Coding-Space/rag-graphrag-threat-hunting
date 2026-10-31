"""Unit tests verifying PurpleSharp AD artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest

from threat_hunting.ground_truth.schema import load_ground_truth_document
from threat_hunting.retrieval.schema import load_retrieval_corpus
from threat_hunting.retrieval.vector_schema import load_vector_index
from threat_hunting.graph.schema import load_knowledge_graph


ROOT = Path(__file__).resolve().parents[1]
GT_PATH = ROOT / "outputs/ground_truth/purplesharp-ad/scenario_ground_truth.json"
CORPUS_PATH = ROOT / "outputs/retrieval/purplesharp-ad/retrieval_corpus.json"
GRAPH_PATH = ROOT / "outputs/graph/purplesharp-ad/knowledge_graph.json"
INDEX_PATH = ROOT / "outputs/retrieval/purplesharp-ad/vector_index_e5.json"
ANSWERS_PATH = ROOT / "outputs/ground_truth/purplesharp-ad/reference_answers.json"


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def test_purplesharp_ground_truth_valid():
    assert GT_PATH.is_file(), "PurpleSharp Ground Truth file must exist"
    gt = load_ground_truth_document(GT_PATH)
    assert gt["scenario"]["scenario_id"] == "purplesharp-ad"
    assert len(gt["entities"]) >= 2
    assert len(gt["mitre_assessments"]) == 4
    # Check T1110.003 and T1558.003 presence
    tech_ids = {m["external_id"] for m in gt["mitre_assessments"]}
    assert "T1110.003" in tech_ids
    assert "T1558.003" in tech_ids


def test_purplesharp_retrieval_corpus_valid():
    assert CORPUS_PATH.is_file(), "PurpleSharp Corpus file must exist"
    corpus = load_retrieval_corpus(CORPUS_PATH)
    assert corpus["scenario_id"] == "purplesharp-ad"
    assert len(corpus["chunks"]) == 21
    assert corpus["source_ground_truth"]["sha256"] == digest(GT_PATH)


def test_purplesharp_knowledge_graph_valid():
    assert GRAPH_PATH.is_file(), "PurpleSharp Graph file must exist"
    graph = load_knowledge_graph(GRAPH_PATH)
    assert graph["scenario_id"] == "purplesharp-ad"
    assert len(graph["nodes"]) == 20
    assert len(graph["edges"]) == 22
    assert graph["source_ground_truth"]["sha256"] == digest(GT_PATH)


def test_purplesharp_vector_index_valid():
    assert INDEX_PATH.is_file(), "PurpleSharp Vector Index file must exist"
    index = load_vector_index(INDEX_PATH)
    assert len(index["records"]) == 21
    assert index["embedding"]["dimension"] == 384
    assert index["corpus_provenance"]["sha256"] == digest(CORPUS_PATH)


def test_purplesharp_reference_answers_valid():
    assert ANSWERS_PATH.is_file(), "PurpleSharp Reference Answers file must exist"
    answers = json.loads(ANSWERS_PATH.read_text(encoding="utf-8"))
    assert answers["schema_version"] == "reference-answers/v1"
    assert answers["scenario_id"] == "purplesharp-ad"
    assert len(answers["cases"]) == 25

    counts = answers["metadata"]["decision_counts"]
    assert counts["proceed"] == 12
    assert counts["abstain"] == 13
