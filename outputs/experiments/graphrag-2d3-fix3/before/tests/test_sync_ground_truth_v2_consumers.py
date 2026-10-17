"""Synthetic integration for the isolated consumer sync experiment.

The real builders, retriever, traversal and gate run with a two-dimensional
fake embedding backend. Synthetic approval and evaluation sentinels are fixture
data only; no production outputs, model downloads or real approval are used.
"""

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.ground_truth.schema import validate_ground_truth_document
from threat_hunting.graphrag import (
    GraphRAGOrchestrationError,
    assess_graphrag_two_stage_gate,
    build_graphrag_context,
    extract_graphrag_gate_signals,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/ground_truth/scenario_ground_truth_minimal.json"
SCRIPT = ROOT / "scripts/sync_ground_truth_v2_consumers.py"
REVIEWER = "Synthetic Approval Sentinel Person"
# Fixed synthetic fixture time, not an assertion about a real approval event.
APPROVED_AT = "2026-01-02T03:04:05+07:00"
COMMAND = 'launch_fixture.exe --inspect "fixture target Ω"'
PARENT_IMAGE = r"C:\Fixture\parent-fixture.exe"
CHILD_IMAGE = r"C:\Fixture\launch_fixture.exe"

# The fixed development policy is copied as explicit test data, never tuned
# using the synthetic query, expected answers or returned context.
FIXED_POLICY = {
    "schema_version": "graphrag-two-stage-gate-policy/v1",
    "policy_id": "two-stage-dev-5a4b308b106699e0",
    "topical_relevance": {
        "min_retrieval_hit_count": 1, "min_lexical_hit_count": 0,
        "min_vector_hit_count": 0, "min_joint_lexical_vector_hit_count": 0,
        "min_query_token_coverage": 0.18181818,
        "min_returned_top_rrf_score": None, "min_returned_top_bm25_score": None,
        "min_returned_top_cosine_score": 0.84299805,
    },
    "evidence_answerability": {
        "min_hits_with_evidence_ids": 0, "min_hits_with_source_references": 0,
        "min_unique_source_reference_count": 0, "min_mapped_hit_count": 1,
        "min_seed_node_count": 1, "require_traversal": True,
        "min_traversal_node_count": 0, "min_traversal_edge_count": 0,
        "min_traversal_path_count": 0, "min_traversed_evidence_node_count": 0,
        "min_support_edge_count": 0, "max_traversed_limitation_node_count": None,
    },
}


class FakeBackend:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        self.calls.append(list(texts))
        return [[1.0, 0.0] for _ in texts]


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("sync_ground_truth_v2_test_subject", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _approved_ground_truth() -> dict[str, Any]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    document["schema_version"] = "scenario-ground-truth/v2"
    document["review"].update(
        review_status="confirmed", reviewer=REVIEWER, reviewed_at=APPROVED_AT,
    )
    document["facts"][0]["attributes"]["source_observations"] = [{
        "source_file": "synthetic_events.jsonl", "raw_record_ref": "fixture:record:1",
        "original_fields": {
            "CommandLine": COMMAND, "Image": CHILD_IMAGE,
            "ParentImage": PARENT_IMAGE, "ProcessGuid": "fixture-child-guid",
            "ParentProcessGuid": "fixture-parent-guid", "ProcessId": "42",
            "ParentProcessId": "41",
        },
    }]
    document["summary"]["limitations"] = [
        f"Synthetic scope limitation {index}: reviewed records cover this fixture only."
        for index in range(7)
    ]
    validate_ground_truth_document(document)
    return document


@pytest.fixture
def experiment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    module = _module()
    approved = tmp_path / "approved"
    approved.mkdir()
    out = tmp_path / "experiment"
    out.mkdir()
    gt = _approved_ground_truth()
    answers = {"cases": [{
        "case_id": "evaluation-only-case-sentinel-001",
        "query": "Evaluation only query sentinel 002",
        "reference_answer": "Evaluation only answer sentinel 003",
        "expected_decision": "abstain", "category": "unrelated",
    }]}
    for name, document in (
        ("scenario_ground_truth.json", gt), ("reference_answers.json", answers),
        ("review_manifest.json", {"synthetic_fixture": True}),
    ):
        (approved / name).write_bytes(module.encoded(document))
    config = {
        "embedding": {
            "provider": "sentence-transformers", "model_id": "synthetic-fixture-model",
            "model_revision": "a" * 40, "dimension": 2,
            "distance_metric": "cosine", "normalization": "l2",
            "document_prefix": "fixture-document: ", "query_prefix": "fixture-query: ",
        },
        "runtime": {"device": "cpu", "offline": True, "batch_size": 1,
                    "show_progress_bar": False},
    }
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "OUT", out)
    monkeypatch.setattr(module, "APPROVED", approved)
    monkeypatch.setattr(module, "GT_RELATIVE", "approved/scenario_ground_truth.json")
    # Supply the load_inputs contract independently; approval bundle validation
    # has dedicated tests. Real builder validation still runs on this v2 source.
    monkeypatch.setattr(module, "load_inputs", lambda: (gt, answers, config, deepcopy(FIXED_POLICY)))
    backend = FakeBackend()
    before = deepcopy(gt)
    module.build(backend=backend)
    assert gt == before
    return {
        "module": module, "gt": gt, "answers": answers, "config": config,
        "backend": backend, "out": out,
        **{key: module.read(out / name) for key, name in (
            ("corpus", "retrieval_corpus.json"), ("graph", "knowledge_graph.json"),
            ("index", "vector_index.json"), ("manifest", "build_manifest.json"),
        )},
    }


def _context(experiment: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    # Return the small synthetic corpus through real retrieval. Scope nodes
    # intentionally have no invented graph edges and must be retrieved directly.
    chunk_count = len(experiment["corpus"]["chunks"])
    options = {
        "corpus_sha256": experiment["manifest"]["outputs"]["retrieval_corpus.json"],
        "embed_query": experiment["backend"].embed_documents,
        "top_k": chunk_count, "candidate_k": chunk_count, "chunk_types": None,
        "direction": "both", "max_depth": 2, "max_nodes": 100, "max_edges": 200,
    }
    options.update(overrides)
    return build_graphrag_context(
        experiment["corpus"], experiment["index"], experiment["graph"], "inspect", **options,
    )


def test_script_builds_bound_complete_fresh_vectors_without_evaluation_or_approval(experiment):
    corpus, graph, index, manifest = (
        experiment[name] for name in ("corpus", "graph", "index", "manifest")
    )
    source = corpus["source_ground_truth"]
    assert source == graph["source_ground_truth"] == manifest["source_ground_truth"]
    assert source["schema_version"] == "scenario-ground-truth/v2"
    assert source["path"] == "approved/scenario_ground_truth.json"
    assert source["scenario_id"] == experiment["gt"]["scenario"]["scenario_id"]
    assert source["sha256"] == experiment["module"].digest(
        experiment["module"].APPROVED / "scenario_ground_truth.json"
    )
    for name, expected in manifest["outputs"].items():
        assert experiment["module"].digest(experiment["out"] / name) == expected
    assert index["corpus_provenance"]["sha256"] == manifest["outputs"]["retrieval_corpus.json"]
    assert index["corpus_provenance"]["path"] == "experiment/retrieval_corpus.json"
    assert [record["chunk_id"] for record in index["records"]] == sorted(
        chunk["chunk_id"] for chunk in corpus["chunks"]
    )
    assert len({record["chunk_id"] for record in index["records"]}) == len(corpus["chunks"])
    assert all(len(record["vector"]) == 2 for record in index["records"])
    expected_inputs = [
        experiment["config"]["embedding"]["document_prefix"] + chunk["content"]
        for chunk in sorted(corpus["chunks"], key=lambda item: item["chunk_id"])
    ]
    assert experiment["backend"].calls == [expected_inputs]
    assert manifest["embedding_input_sha256"] == [
        hashlib.sha256(text.encode("utf-8")).hexdigest() for text in expected_inputs
    ]
    assert manifest["embedding_cache"] == {
        "old_vector_reuse": False, "document_cache_hits": 0,
        "document_cache_misses": len(expected_inputs),
        "determinism_replay_exact_input_hits": len(expected_inputs),
    }
    runtime = json.dumps((corpus, graph, expected_inputs), ensure_ascii=False)
    for sentinel in (REVIEWER, APPROVED_AT, *(
        experiment["answers"]["cases"][0][field]
        for field in ("case_id", "query", "reference_answer")
    )):
        assert sentinel not in runtime
    for forbidden in ("expected_decision", "reference_answer", "case_id", "human_approved_at"):
        assert forbidden not in runtime


def test_actual_context_returns_original_values_roles_references_and_all_scope_limits(experiment):
    context = _context(experiment)
    fact = next(hit["chunk"] for hit in context["retrieval"]["hits"]
                if hit["chunk"]["source"]["json_pointer"] == "/facts/0")
    expected = experiment["gt"]["facts"][0]
    assert fact["source"]["json_pointer"] == "/facts/0"
    assert fact["metadata"]["attributes"] == expected["attributes"]
    assert fact["source_references"] == expected["source_references"]
    for value in (COMMAND, PARENT_IMAGE, CHILD_IMAGE, "fixture-child-guid", "fixture-parent-guid"):
        assert json.dumps(value, ensure_ascii=False) in fact["content"]
    node = next(item for item in context["traversal"]["nodes"]
                if item["source"]["json_pointer"] == "/facts/0")
    assert node["attributes"]["attributes"] == expected["attributes"]
    assert node["source_references"] == expected["source_references"]
    actual_limits = {item["label"] for item in context["traversal"]["nodes"]
                     if item["node_type"] == "limitation"}
    assert actual_limits == set(experiment["gt"]["summary"]["limitations"])
    signals = extract_graphrag_gate_signals(context)
    decision = assess_graphrag_two_stage_gate(signals, policy=deepcopy(FIXED_POLICY))
    assert decision["decision"] == "proceed"
    assert decision["metadata"]["security_conclusion_made"] is False
    assert signals["evidence_answerability"]["traversed_limitation_node_count"] == 7
    runtime = json.dumps((context, signals, decision))
    assert REVIEWER not in runtime and APPROVED_AT not in runtime
    assert "confirmed" not in signals["evidence_answerability"]["status_counts"]
    assert experiment["backend"].calls[-1] == [
        experiment["config"]["embedding"]["query_prefix"] + "inspect"
    ]


def test_external_command_rubric_uses_only_actual_returned_observations(experiment):
    context = _context(experiment)
    signals = extract_graphrag_gate_signals(context)
    descriptor = {
        "case_id": "synthetic-command-rubric", "category": "relevant_direct",
        "expected_decision": "proceed", "topical_relevant": True,
        "dataset_answerable": True, "minimal_answer_unit_ids": ["launch_value"],
        "raw_reference_requirements": experiment["gt"]["facts"][0]["source_references"],
    }
    units = {"launch_value": {
        "source_ground_truth_pointer": "/facts/0",
        "required_ground_truth_fields": [{
            "pointer": "/facts/0/attributes/source_observations/0/original_fields/CommandLine",
            "value": COMMAND,
        }],
    }}
    before = deepcopy((context, signals, descriptor, units))
    record, diagnostic = experiment["module"].record_for_context(
        context, signals, descriptor, units, experiment["gt"],
    )
    assert record["context_sufficient"] is True
    assert diagnostic["satisfied_answer_units"] == ["launch_value"]
    assert (context, signals, descriptor, units) == before
    # IDs, prose, expected values and raw references cannot replace missing
    # original fields in the actual payload.
    missing = deepcopy(context)
    for hit in missing["retrieval"]["hits"]:
        if hit["chunk"]["source"]["json_pointer"] == "/facts/0":
            hit["chunk"]["metadata"]["attributes"].pop("source_observations")
    for node in missing["traversal"]["nodes"]:
        if node["source"]["json_pointer"] == "/facts/0":
            node["attributes"]["attributes"].pop("source_observations")
    record, diagnostic = experiment["module"].record_for_context(
        missing, signals, descriptor, units, experiment["gt"],
    )
    assert record["context_sufficient"] is False
    assert diagnostic["missing_answer_units"] == ["launch_value"]


def test_fact_only_retrieval_does_not_invent_paths_to_scope_limitations(experiment):
    context = _context(experiment, top_k=1, candidate_k=5, chunk_types=["fact"])
    assert len([chunk for chunk in experiment["corpus"]["chunks"]
                if chunk["chunk_type"] == "limitation"]) == 7
    assert len([node for node in experiment["graph"]["nodes"]
                if node["node_type"] == "limitation"]) == 7
    assert all(node["node_type"] != "limitation" for node in context["traversal"]["nodes"])
    signals = extract_graphrag_gate_signals(context)
    assert signals["evidence_answerability"]["traversed_limitation_node_count"] == 0


@pytest.mark.parametrize("mutation", ["content", "corpus_hash", "graph_source"])
def test_runtime_rejects_stale_content_or_source_bindings(experiment, mutation):
    calls_before = deepcopy(experiment["backend"].calls)
    options = {}
    if mutation == "content":
        experiment["corpus"]["chunks"][0]["content"] += " Additional synthetic text."
        pattern = "content_sha256 mismatch"
    elif mutation == "corpus_hash":
        options["corpus_sha256"] = "f" * 64
        pattern = "corpus.*provenance"
    else:
        experiment["graph"]["source_ground_truth"]["sha256"] = "f" * 64
        pattern = "source_ground_truth mismatch"
    with pytest.raises(GraphRAGOrchestrationError, match=pattern):
        _context(experiment, **options)
    if mutation == "graph_source":
        # Mapping validates the graph after retrieval's one query embedding.
        assert experiment["backend"].calls == calls_before + [[
            experiment["config"]["embedding"]["query_prefix"] + "inspect"
        ]]
    else:
        assert experiment["backend"].calls == calls_before


def test_script_refuses_existing_consumer_outputs_without_overwriting(experiment):
    before = {path.name: path.read_bytes() for path in experiment["out"].iterdir()}
    calls_before = deepcopy(experiment["backend"].calls)
    with pytest.raises(ValueError, match="refusing to overwrite"):
        experiment["module"].build(backend=experiment["backend"])
    assert {path.name: path.read_bytes() for path in experiment["out"].iterdir()} == before
    assert experiment["backend"].calls == calls_before


def test_source_pointer_adapter_reads_escaped_object_keys_and_list_indices():
    assert _module().pointer_value({"a/b": [{"c~d": "fixture-value"}]}, "/a~1b/0/c~0d") == "fixture-value"
