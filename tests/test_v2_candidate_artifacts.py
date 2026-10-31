"""Unit tests validating candidate v2 artifacts under outputs/v2/."""

from pathlib import Path
import hashlib
import json
import pytest

from threat_hunting.retrieval.schema import load_retrieval_corpus
from threat_hunting.retrieval.vector_schema import load_vector_index
from threat_hunting.graph.schema import load_knowledge_graph


ROOT = Path(__file__).resolve().parents[1]
V2_DIR = ROOT / "outputs/v2"
CORPUS_PATH = V2_DIR / "retrieval/mshta-powershell/retrieval_corpus.json"
GRAPH_PATH = V2_DIR / "graph/mshta-powershell/knowledge_graph.json"
INDEX_PATH = V2_DIR / "retrieval/mshta-powershell/vector_index_e5.json"
MANIFEST_PATH = V2_DIR / "manifest.json"
GT_PATH = ROOT / "outputs/review/mshta-ground-truth/scenario_ground_truth.json"

EXPECTED_GT_SHA256 = "8676d7a1df41058e7f4b1460a0d4bf909fca5d8f20992753e63be7d024268461"


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def test_v2_candidate_ground_truth_integrity():
    assert GT_PATH.is_file(), "Ground truth v2 file must exist"
    actual_hash = digest(GT_PATH)
    assert actual_hash == EXPECTED_GT_SHA256, f"Ground Truth SHA-256 mismatch: {actual_hash}"


def test_v2_candidate_corpus_schema_and_counts():
    assert CORPUS_PATH.is_file(), "Candidate v2 corpus file must exist"
    corpus = load_retrieval_corpus(CORPUS_PATH)
    assert len(corpus["chunks"]) == 22, f"Expected 22 chunks, got {len(corpus['chunks'])}"
    assert corpus["source_ground_truth"]["sha256"] == EXPECTED_GT_SHA256
    assert corpus["source_ground_truth"]["schema_version"] == "scenario-ground-truth/v2"
    assert corpus["review"]["review_status"] == "pending_human_review"


def test_v2_candidate_knowledge_graph_schema_and_counts():
    assert GRAPH_PATH.is_file(), "Candidate v2 graph file must exist"
    graph = load_knowledge_graph(GRAPH_PATH)
    assert len(graph["nodes"]) == 20, f"Expected 20 nodes, got {len(graph['nodes'])}"
    assert len(graph["edges"]) == 21, f"Expected 21 edges, got {len(graph['edges'])}"
    assert graph["source_ground_truth"]["sha256"] == EXPECTED_GT_SHA256
    assert graph["source_ground_truth"]["schema_version"] == "scenario-ground-truth/v2"
    assert graph["review"]["status"] == "pending_human_review"


def test_v2_candidate_vector_index_schema_and_coverage():
    assert INDEX_PATH.is_file(), "Candidate v2 vector index file must exist"
    index = load_vector_index(INDEX_PATH)
    assert len(index["records"]) == 22, f"Expected 22 vector records, got {len(index['records'])}"
    assert index["embedding"]["dimension"] == 384
    assert index["embedding"]["model_id"] == "intfloat/multilingual-e5-small"
    assert index["corpus_provenance"]["sha256"] == digest(CORPUS_PATH)
    assert index["review"]["review_status"] == "pending_human_review"


def test_v2_candidate_manifest_integrity():
    assert MANIFEST_PATH.is_file(), "Candidate v2 manifest must exist"
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "threat-hunting-v2-candidate-manifest/v1"
    assert manifest["status"] == "candidate_review_pending"
    assert manifest["source_ground_truth"]["sha256"] == EXPECTED_GT_SHA256
    assert manifest["artifacts"]["retrieval_corpus.json"]["sha256"] == digest(CORPUS_PATH)
    assert manifest["artifacts"]["knowledge_graph.json"]["sha256"] == digest(GRAPH_PATH)
    assert manifest["artifacts"]["vector_index_e5.json"]["sha256"] == digest(INDEX_PATH)
    assert manifest["verification"]["provenance_chain_verified"] is True
