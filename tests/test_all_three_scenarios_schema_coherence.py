"""Cross-scenario schema coherence and validation test across all 3 threat hunting scenarios."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from threat_hunting.ground_truth.schema import load_ground_truth_document
from threat_hunting.retrieval.schema import load_retrieval_corpus
from threat_hunting.retrieval.vector_schema import load_vector_index
from threat_hunting.graph.schema import load_knowledge_graph


ROOT = Path(__file__).resolve().parents[1]

SCENARIOS = {
    "purplesharp-ad": {
        "name": "PurpleSharp Active Directory (Password Spraying & Kerberoasting)",
        "gt": ROOT / "outputs/ground_truth/purplesharp-ad/scenario_ground_truth.json",
        "corpus": ROOT / "outputs/retrieval/purplesharp-ad/retrieval_corpus.json",
        "graph": ROOT / "outputs/graph/purplesharp-ad/knowledge_graph.json",
        "index": ROOT / "outputs/retrieval/purplesharp-ad/vector_index_e5.json",
        "answers": ROOT / "outputs/ground_truth/purplesharp-ad/reference_answers.json",
        "expected_cases": 25,
        "expected_proceed": 12,
        "expected_abstain": 13,
    },
    "mshta-powershell": {
        "name": "MSHTA Inline VBScript executing PowerShell",
        "gt": ROOT / "outputs/review/mshta-ground-truth/scenario_ground_truth.json",
        "corpus": ROOT / "outputs/v2/retrieval/mshta-powershell/retrieval_corpus.json",
        "graph": ROOT / "outputs/v2/graph/mshta-powershell/knowledge_graph.json",
        "index": ROOT / "outputs/v2/retrieval/mshta-powershell/vector_index_e5.json",
        "answers": ROOT / "outputs/review/mshta-ground-truth/reference_answers.json",
        "expected_cases": 32,
        "expected_proceed": 16,
        "expected_abstain": 16,
    },
    "regsvr32-c2": {
        "name": "Empire Regsvr32 Squiblydoo and C2 Network Connection",
        "gt": ROOT / "outputs/ground_truth/regsvr32-c2/scenario_ground_truth.json",
        "corpus": ROOT / "outputs/retrieval/regsvr32-c2/retrieval_corpus.json",
        "graph": ROOT / "outputs/graph/regsvr32-c2/knowledge_graph.json",
        "index": ROOT / "outputs/retrieval/regsvr32-c2/vector_index_e5.json",
        "answers": ROOT / "outputs/ground_truth/regsvr32-c2/reference_answers.json",
        "expected_cases": 25,
        "expected_proceed": 12,
        "expected_abstain": 13,
    },
}


@pytest.mark.parametrize("scen_id, info", list(SCENARIOS.items()))
def test_scenario_ground_truth_schema(scen_id, info):
    assert info["gt"].is_file(), f"Ground truth missing for {scen_id}"
    doc = load_ground_truth_document(info["gt"])
    assert doc["schema_version"] == "scenario-ground-truth/v2"
    assert doc["scenario"]["scenario_id"] == scen_id


@pytest.mark.parametrize("scen_id, info", list(SCENARIOS.items()))
def test_scenario_retrieval_corpus_schema(scen_id, info):
    assert info["corpus"].is_file(), f"Corpus missing for {scen_id}"
    corpus = load_retrieval_corpus(info["corpus"])
    assert corpus["schema_version"] == "retrieval-corpus/v1"
    assert corpus["scenario_id"] == scen_id
    assert len(corpus["chunks"]) > 0


@pytest.mark.parametrize("scen_id, info", list(SCENARIOS.items()))
def test_scenario_knowledge_graph_schema(scen_id, info):
    assert info["graph"].is_file(), f"Graph missing for {scen_id}"
    graph = load_knowledge_graph(info["graph"])
    assert graph["schema_version"] == "knowledge-graph/v1"
    assert graph["scenario_id"] == scen_id
    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0


@pytest.mark.parametrize("scen_id, info", list(SCENARIOS.items()))
def test_scenario_vector_index_schema(scen_id, info):
    assert info["index"].is_file(), f"Vector index missing for {scen_id}"
    index = load_vector_index(info["index"])
    assert index["schema_version"] == "vector-index/v1"
    assert index["embedding"]["dimension"] == 384
    assert len(index["records"]) > 0


@pytest.mark.parametrize("scen_id, info", list(SCENARIOS.items()))
def test_scenario_reference_answers_counts(scen_id, info):
    assert info["answers"].is_file(), f"Answers missing for {scen_id}"
    answers = json.loads(info["answers"].read_text(encoding="utf-8"))
    assert answers["schema_version"] in ("reference-answers/v1", "mshta-reference-answers/v2")
    assert len(answers["cases"]) == info["expected_cases"]

    counts = answers["metadata"]["decision_counts"]
    assert counts["proceed"] == info["expected_proceed"]
    assert counts["abstain"] == info["expected_abstain"]


def test_total_benchmark_cases_reach_target():
    total_cases = sum(info["expected_cases"] for info in SCENARIOS.values())
    total_proceed = sum(info["expected_proceed"] for info in SCENARIOS.values())
    total_abstain = sum(info["expected_abstain"] for info in SCENARIOS.values())

    assert total_cases == 82
    assert total_proceed == 40
    assert total_abstain == 42
