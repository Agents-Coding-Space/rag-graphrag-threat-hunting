"""Development tests for bounded source-backed context enrichment.

Small existing synthetic artifacts and fake query vectors exercise real source
validators and orchestration. These tests never load a model or real dataset.
"""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from threat_hunting.graphrag.orchestrator import build_graphrag_context
from threat_hunting.graphrag.query_context import (
    DEFAULT_CONTEXT_BUDGET, QueryContextError, enrich_query_context,
    validate_query_evidence_context,
)
from threat_hunting.graphrag.query_requirements import analyze_query_requirements


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/retrieval/builder/expected_retrieval_corpus.json"
GRAPH = ROOT / "tests/fixtures/graph/builder/expected_knowledge_graph.json"
INDEX = ROOT / "tests/fixtures/retrieval/vector_builder/expected_vector_index.json"


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


@pytest.fixture
def inputs():
    corpus, graph, index = _read(CORPUS), _read(GRAPH), _read(INDEX)
    query = "List all review limitations."
    context = build_graphrag_context(
        corpus, index, graph, query, corpus_sha256=sha256(CORPUS.read_bytes()).hexdigest(),
        embed_query=lambda texts: [[1.0, 0.0, 0.0] for _ in texts],
        top_k=1, chunk_types=["entity"], max_depth=0,
    )
    return context, corpus, graph, analyze_query_requirements(query)


def _run(inputs, **kwargs):
    return enrich_query_context(*inputs, **kwargs)


def _requirement(inputs, kind, parameters):
    changed = deepcopy(inputs)
    changed[3]["analysis_status"] = "supported"
    changed[3]["requirements"] = [{
        "requirement_id": "r1", "kind": kind, "mandatory": True,
        "parameters": parameters, "analysis_status": "supported",
        "reason_codes": ["synthetic_development_requirement"],
    }]
    return changed


def test_all_limitations_are_returned_with_source_identity_and_no_fake_scores(inputs):
    before = deepcopy(inputs)
    result = _run(inputs)
    assert inputs == before
    assert result["initial_context"] == inputs[0]
    assert result["source_inventory"]["limitation_count"] == 1
    assert result["supplementary_items"]
    assert not result["incomplete_context"]
    expected = {item["chunk_id"]: item for item in inputs[1]["chunks"]}
    for record in result["supplementary_items"]:
        assert record["payload"] == expected[record["item_id"]]
        assert record["origin"] == "supplementary"
        assert record["requirement_ids"] == ["r1"]
        assert record["reason_codes"]
        assert not {"rank", "score", "components"}.intersection(record)
    assert any(record["payload"].get("chunk_type") == "limitation" for record in result["final_items"])
    assert all(record["kind"] != "edge" for record in result["supplementary_items"])
    assert result["budget"]["final_serialized_bytes"] == len(_bytes(result["final_items"]))
    validate_query_evidence_context(result)


def test_deterministic_order_and_cross_representation_dedup(inputs):
    first = _run(inputs)
    shuffled = deepcopy(inputs)
    shuffled[1]["chunks"].reverse()
    shuffled[2]["nodes"].reverse()
    assert _run(shuffled) == first
    keys = [
        (record["payload"]["source"]["object_type"], record["payload"]["source"]["json_pointer"])
        for record in first["supplementary_items"]
    ]
    assert len(keys) == len(set(keys))
    # The graph fallback representation of the same limitation is not added.
    assert all(record["kind"] == "chunk" for record in first["supplementary_items"])
    assert first["selection"]["already_present_item_ids"]


@pytest.mark.parametrize("budget,reason", [
    ({"max_supplementary_items": 0}, "supplementary_item_budget_exhausted"),
    ({"max_final_items": 2}, "final_item_budget_exhausted"),
    ({"max_serialized_bytes": 1}, "baseline_exceeds_budget"),
])
def test_budget_cuts_are_explicit_and_baseline_is_preserved(inputs, budget, reason):
    result = _run(inputs, budget=budget)
    assert result["initial_context"] == inputs[0]
    assert result["incomplete_context"]
    assert not result["supplementary_items"]
    assert any(reason in cut["reason_codes"] for cut in result["selection"]["cut_items"])
    assert len(result["final_items"]) == len(inputs[0]["retrieval"]["hits"]) + len(inputs[0]["traversal"]["nodes"])
    validate_query_evidence_context(result)


def test_utf8_budget_counts_serialized_bytes_and_cuts_whole_items(inputs):
    # Non-ASCII source text remains whole and is measured as UTF-8 bytes.
    limitation = next(item for item in inputs[1]["chunks"] if item["chunk_type"] == "limitation")
    node = next(item for item in inputs[2]["nodes"] if item["node_type"] == "limitation")
    limitation["content"] = node["label"] = "Phạm vi Ω chỉ có dữ liệu tổng hợp."
    complete = _run(inputs)
    limit = complete["budget"]["final_serialized_bytes"] - 1
    cut = _run(inputs, budget={"max_serialized_bytes": limit})
    assert cut["incomplete_context"]
    assert any("serialized_utf8_byte_budget_exhausted" in item["reason_codes"] for item in cut["selection"]["cut_items"])
    assert cut["budget"]["final_serialized_bytes"] <= limit
    for record in cut["supplementary_items"]:
        sources = inputs[1]["chunks"] if record["kind"] == "chunk" else inputs[2]["nodes"]
        assert record["payload"] in sources
    assert complete["budget"]["final_serialized_bytes"] > len(_bytes(complete["final_items"]).decode("utf-8"))


def test_disabled_enrichment_retains_inventory_and_explicit_cuts(inputs):
    result = _run(inputs, enabled=False)
    assert result["initial_context"] == inputs[0]
    assert not result["supplementary_items"]
    assert result["source_inventory"]["limitation_count"] == 1
    assert result["incomplete_context"]
    assert all("enrichment_disabled" in cut["reason_codes"] for cut in result["selection"]["cut_items"])


def test_all_seven_synthetic_limitations_and_partial_budget_are_explicit(inputs):
    corpus, graph = inputs[1:3]
    chunk = next(item for item in corpus["chunks"] if item["chunk_type"] == "limitation")
    node = next(item for item in graph["nodes"] if item["node_type"] == "limitation")
    for index in range(1, 7):
        extra_chunk, extra_node = deepcopy(chunk), deepcopy(node)
        text = f"Synthetic review scope limitation {index}: Ω remains unassessed."
        extra_chunk.update(chunk_id=f"synthetic-limitation-chunk-{index}", content=text)
        extra_node.update(node_id=f"synthetic-limitation-node-{index}", label=text)
        extra_chunk["source"]["json_pointer"] = extra_node["source"]["json_pointer"] = f"/summary/limitations/{index}"
        corpus["chunks"].append(extra_chunk)
        graph["nodes"].append(extra_node)
    corpus["metadata"]["chunk_count"] += 6
    graph["metadata"]["node_count"] += 6
    graph["metadata"]["node_type_counts"]["limitation"] += 6
    complete = _run(inputs)
    assert complete["source_inventory"]["limitation_count"] == 7
    returned = {
        record["payload"]["source"]["json_pointer"] for record in complete["final_items"]
        if record["payload"]["source"]["object_type"] == "limitation"
    }
    assert len(returned) == 7
    assert not complete["incomplete_context"]
    partial = _run(inputs, budget={"max_supplementary_items": 3})
    assert partial["incomplete_context"]
    assert len(partial["supplementary_items"]) == 3
    assert partial["selection"]["cut_items"]
    assert sum(record["payload"]["source"]["object_type"] == "limitation" for record in partial["final_items"]) < 7


def test_unknown_query_does_not_insert_whole_corpus(inputs):
    requirements = inputs[3]
    requirements.update(analysis_status="unsupported", requirements=[], reason_codes=["unsupported_information_request"])
    result = _run(inputs)
    assert result["selection"]["candidate_count"] == 0
    assert not result["supplementary_items"]
    assert len(result["final_items"]) < len(inputs[1]["chunks"])


def test_process_selector_is_data_driven_for_arbitrary_entity_names(inputs):
    entity = next(item for item in inputs[1]["chunks"] if item["chunk_type"] == "entity" and item["title"] == "worker-beta.bin")
    request = _requirement(inputs, "launch_command", {"process": "worker-beta.bin"})
    result = _run(request)
    selected = [record["payload"] for record in result["supplementary_items"]]
    assert any(entity["source"]["object_id"] in item.get("entity_ids", []) for item in selected)
    unrelated = _run(_requirement(inputs, "launch_command", {"process": "unseen-renamed-worker.exe"}))
    assert not unrelated["supplementary_items"]


def test_unrelated_reference_url_is_not_network_evidence(inputs):
    result = _run(_requirement(inputs, "network_url", {
        "actor": None, "action": "download", "field": "url",
    }))
    assert not result["supplementary_items"]


def test_graph_fallback_and_existing_source_object_are_deduplicated(inputs):
    context, corpus, graph, requirements = inputs
    # Request the actual currently returned source object; its node/chunk
    # representation must not be inserted again just because it is a candidate.
    name = context["retrieval"]["hits"][0]["chunk"]["title"]
    result = _run(_requirement(inputs, "evidence_provenance", {"process": name}))
    represented = {
        (item["source"]["object_type"], item["source"]["json_pointer"])
        for item in [context["retrieval"]["hits"][0]["chunk"], *context["traversal"]["nodes"]]
    }
    assert all(
        (record["payload"]["source"]["object_type"], record["payload"]["source"]["json_pointer"]) not in represented
        for record in result["supplementary_items"]
    )


@pytest.mark.parametrize("budget", [{"unknown": 1}, {"max_final_items": True}, {"max_serialized_bytes": -1}, {"max_supplementary_items": 1.5}])
def test_invalid_budget_rejected(inputs, budget):
    with pytest.raises(QueryContextError):
        _run(inputs, budget=budget)


def test_different_source_and_tampered_initial_payload_rejected(inputs):
    changed = deepcopy(inputs)
    changed[2]["source_ground_truth"]["sha256"] = "f" * 64
    with pytest.raises(QueryContextError, match="binding"):
        _run(changed)
    changed = deepcopy(inputs)
    changed[0]["retrieval"]["hits"][0]["chunk"]["metadata"]["synthetic_tamper"] = True
    with pytest.raises(QueryContextError, match="differs from its runtime source"):
        _run(changed)


def test_public_validator_rejects_budget_lie_fabricated_ranking_and_missing_baseline(inputs):
    result = _run(inputs)
    changed = deepcopy(result)
    changed["budget"]["final_serialized_bytes"] -= 1
    with pytest.raises(QueryContextError, match="accounting"):
        validate_query_evidence_context(changed)
    changed = deepcopy(result)
    changed["supplementary_items"][0]["score"] = 0.99
    changed["final_items"][len(changed["final_items"]) - len(changed["supplementary_items"])] = changed["supplementary_items"][0]
    with pytest.raises(QueryContextError, match="fields"):
        validate_query_evidence_context(changed)
    changed = deepcopy(result)
    changed["final_items"].pop(0)
    with pytest.raises(QueryContextError, match="preserve baseline"):
        validate_query_evidence_context(changed)


def test_runtime_does_not_open_files_and_rejects_evaluation_annotations(inputs, monkeypatch):
    import builtins

    def forbidden(*args, **kwargs):
        raise AssertionError("runtime attempted file IO")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    assert _run(inputs)["supplementary_items"]
    inputs[3]["expected_decision"] = "proceed"
    with pytest.raises(QueryContextError):
        _run(inputs)


def test_outputs_and_default_configuration_are_detached(inputs):
    result = _run(inputs)
    again = _run(inputs)
    result["initial_context"]["warnings"].append("changed by caller")
    result["supplementary_items"][0]["payload"]["content"] = "changed by caller"
    assert _run(inputs) == again
    assert DEFAULT_CONTEXT_BUDGET == {
        "max_supplementary_items": 12, "max_final_items": 64, "max_serialized_bytes": 131072,
    }
