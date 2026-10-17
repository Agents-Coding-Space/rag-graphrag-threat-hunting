"""Unit tests verifying Empire Regsvr32 C2 artifacts."""

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
GT_PATH = ROOT / "outputs/ground_truth/regsvr32-c2/scenario_ground_truth.json"
CORPUS_PATH = ROOT / "outputs/retrieval/regsvr32-c2/retrieval_corpus.json"
GRAPH_PATH = ROOT / "outputs/graph/regsvr32-c2/knowledge_graph.json"
INDEX_PATH = ROOT / "outputs/retrieval/regsvr32-c2/vector_index_e5.json"
ANSWERS_PATH = ROOT / "outputs/ground_truth/regsvr32-c2/reference_answers.json"


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def test_regsvr32_ground_truth_valid():
    assert GT_PATH.is_file(), "Regsvr32 Ground Truth file must exist"
    gt = load_ground_truth_document(GT_PATH)
    assert gt["scenario"]["scenario_id"] == "regsvr32-c2"
    assert len(gt["entities"]) == 3
    assert len(gt["mitre_assessments"]) == 3

    tech_ids = {m["external_id"] for m in gt["mitre_assessments"]}
    assert "T1218.010" in tech_ids
    assert "T1071.001" in tech_ids


def test_regsvr32_retrieval_corpus_valid():
    assert CORPUS_PATH.is_file(), "Regsvr32 Corpus file must exist"
    corpus = load_retrieval_corpus(CORPUS_PATH)
    assert corpus["scenario_id"] == "regsvr32-c2"
    assert len(corpus["chunks"]) == 15
    assert corpus["source_ground_truth"]["sha256"] == digest(GT_PATH)


def test_regsvr32_knowledge_graph_valid():
    assert GRAPH_PATH.is_file(), "Regsvr32 Graph file must exist"
    graph = load_knowledge_graph(GRAPH_PATH)
    assert graph["scenario_id"] == "regsvr32-c2"
    assert len(graph["nodes"]) == 14
    assert len(graph["edges"]) == 16
    assert graph["source_ground_truth"]["sha256"] == digest(GT_PATH)


def test_regsvr32_vector_index_valid():
    assert INDEX_PATH.is_file(), "Regsvr32 Vector Index file must exist"
    index = load_vector_index(INDEX_PATH)
    assert len(index["records"]) == 15
    assert index["embedding"]["dimension"] == 384
    assert index["corpus_provenance"]["sha256"] == digest(CORPUS_PATH)


def test_regsvr32_reference_answers_valid():
    assert ANSWERS_PATH.is_file(), "Regsvr32 Reference Answers file must exist"
    answers = json.loads(ANSWERS_PATH.read_text(encoding="utf-8"))
    assert answers["schema_version"] == "reference-answers/v1"
    assert answers["scenario_id"] == "regsvr32-c2"
    assert len(answers["cases"]) == 25

    counts = answers["metadata"]["decision_counts"]
    assert counts["proceed"] == 12
    assert counts["abstain"] == 13
