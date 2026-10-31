"""Source-bound metadata upgrade and deterministic FIX3 supplementation tests."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from threat_hunting.graphrag.orchestrator import build_graphrag_context
from threat_hunting.graphrag.query_context import QueryContextError, enrich_query_context
from threat_hunting.graphrag.query_context_v2 import enrich_query_context_v2, upgrade_evidence_context, validate_query_evidence_context_v2
from threat_hunting.graphrag.query_requirements import analyze_query_requirements
from threat_hunting.retrieval.vector_builder import build_vector_index


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/retrieval/builder/expected_retrieval_corpus.json"
GRAPH = ROOT / "tests/fixtures/graph/builder/expected_knowledge_graph.json"
INDEX = ROOT / "tests/fixtures/retrieval/vector_builder/expected_vector_index.json"
BUDGET = {"max_supplementary_items": 12, "max_final_items": 64, "max_serialized_bytes": 131072}


@pytest.fixture
def inputs():
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    query = "List all review limitations."
    initial = build_graphrag_context(corpus, index, graph, query,
        corpus_sha256=sha256(CORPUS.read_bytes()).hexdigest(), embed_query=lambda texts: [[1., 0., 0.] for _ in texts],
        top_k=1, chunk_types=["entity"], max_depth=0)
    requirements = analyze_query_requirements(query)
    return initial, corpus, graph, requirements


def test_metadata_upgrade_preserves_exact_final_items_and_old_api(inputs):
    old = enrich_query_context(*inputs)
    before = deepcopy((old, inputs))
    result = upgrade_evidence_context(old, inputs[1], inputs[2])
    assert result["schema_version"] == "query-evidence-context/v2"
    assert result["final_items"] == old["final_items"]
    assert result["initial_context"] == old["initial_context"]
    assert result["source_inventory"]["limitation_sources"][0]["json_pointer"] == "/summary/limitations/0"
    assert (old, inputs) == before
    assert enrich_query_context(*inputs) == old
    assert upgrade_evidence_context(result, inputs[1], inputs[2]) == result
    validate_query_evidence_context_v2(result)


@pytest.mark.parametrize("mutation", ["final_payload", "inventory_pointer", "inventory_duplicate", "inventory_count", "provenance", "version"])
def test_upgrade_rejects_forged_source_or_inventory(inputs, mutation):
    result = upgrade_evidence_context(enrich_query_context(*inputs), inputs[1], inputs[2])
    if mutation == "final_payload":
        result["final_items"][0]["payload"]["content"] += " forged"
    elif mutation == "inventory_pointer":
        result["source_inventory"]["limitation_sources"][0]["json_pointer"] = "/summary/limitations/999"
    elif mutation == "inventory_duplicate":
        result["source_inventory"]["limitation_sources"].append(deepcopy(result["source_inventory"]["limitation_sources"][0]))
    elif mutation == "inventory_count":
        result["source_inventory"]["limitation_count"] += 1
    elif mutation == "provenance":
        result["source_inventory"]["source_ground_truth"]["sha256"] = "0" * 64
    else:
        result["schema_version"] = "query-evidence-context/v999"
    with pytest.raises((ValueError, KeyError)):
        upgrade_evidence_context(result, inputs[1], inputs[2])


def test_v2_limit_enrichment_is_deterministic_detached_and_unranked(inputs):
    before = deepcopy(inputs)
    result = enrich_query_context_v2(*inputs, budget=BUDGET, max_chain_depth=8)
    reversed_inputs = deepcopy(inputs)
    reversed_inputs[1]["chunks"].reverse()
    reversed_inputs[2]["nodes"].reverse()
    reversed_inputs[2]["edges"].reverse()
    assert enrich_query_context_v2(*reversed_inputs, budget=BUDGET, max_chain_depth=8) == result
    assert inputs == before
    assert not result["incomplete_context"]
    assert all(item["kind"] != "edge" and not {"rank", "score", "components", "path"}.intersection(item) for item in result["supplementary_items"])
    assert result["budget"]["final_serialized_bytes"] == len(json.dumps(result["final_items"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


@pytest.mark.parametrize("budget,reason", [({**BUDGET, "max_supplementary_items": 0}, "supplementary_item_budget_exhausted"),
    ({**BUDGET, "max_final_items": 1}, "final_item_budget_exhausted"), ({**BUDGET, "max_serialized_bytes": 1}, "baseline_exceeds_budget")])
def test_budget_cuts_preserve_initial_payloads(inputs, budget, reason):
    result = enrich_query_context_v2(*inputs, budget=budget, max_chain_depth=8)
    assert result["incomplete_context"]
    assert result["initial_context"] == inputs[0]
    assert not result["supplementary_items"]
    assert any(reason in cut["reason_codes"] for cut in result["selection"]["cut_items"])


def _process_sources(inputs):
    _, corpus, graph, _ = deepcopy(inputs)
    names = {"entity-synthetic-alpha": "renamed-launch.exe", "entity-synthetic-beta": "renamed-relay.exe", "entity-synthetic-gamma": "renamed-target.exe"}
    for kind, collection in (("chunk", corpus["chunks"]), ("node", graph["nodes"])):
        for item in collection:
            if item["source"]["object_type"] == "entity":
                identity = item["source"]["object_id"]
                item["title" if kind == "chunk" else "label"] = names[identity]
                attrs = item["metadata" if kind == "chunk" else "attributes"]
                attrs["attributes"].update(process_name=names[identity], host="SYNTHETIC", process_guid=identity)
    endpoints = {"relationship-synthetic-alpha-beta": ("entity-synthetic-alpha", "entity-synthetic-beta"), "relationship-synthetic-beta-gamma": ("entity-synthetic-beta", "entity-synthetic-gamma")}
    for item in corpus["chunks"]:
        if item["chunk_type"] == "relationship":
            parent, child = endpoints[item["source"]["object_id"]]
            item["status"] = "observed"
            item["content"] = f"Relationship {item['source']['object_id']}. Source: {names[parent]} ({parent}). Type: process_spawn. Target: {names[child]} ({child}). Status: observed."
    for edge in graph["edges"]:
        if edge["source"]["object_type"] == "relationship":
            edge["edge_type"], edge["status"] = "process_spawn", "observed"
    graph["metadata"]["edge_type_counts"].pop("initiates", None)
    graph["metadata"]["edge_type_counts"].pop("transitions_to", None)
    graph["metadata"]["edge_type_counts"]["process_spawn"] = 2
    raw = json.dumps(corpus, sort_keys=True).encode()
    index = build_vector_index(corpus, corpus_path="synthetic/corpus.json", corpus_sha256=sha256(raw).hexdigest(),
        embedding=json.loads(INDEX.read_text())["embedding"], embed_documents=lambda texts: [[1., 0., 0.] for _ in texts])
    query = "Which process chain led to renamed-target.exe?"
    initial = build_graphrag_context(corpus, index, graph, query, corpus_sha256=sha256(raw).hexdigest(),
        embed_query=lambda texts: [[1., 0., 0.] for _ in texts], top_k=1, chunk_types=["limitation"], max_depth=0)
    req = analyze_query_requirements("Which process spawned renamed-target.exe?")
    req["query"] = query
    req["analysis_status"] = "supported"
    req["requirements"] = [{"requirement_id": "r1", "kind": "process_relationship", "parameters": {"parent": None, "child": "renamed-target.exe", "chain": True}, "mandatory": True, "analysis_status": "supported", "reason_codes": []}]
    return initial, corpus, graph, req


def test_target_only_supplementation_uses_real_reverse_relationships(inputs):
    data = _process_sources(inputs)
    result = enrich_query_context_v2(*data, budget=BUDGET, max_chain_depth=8)
    pointers = {item["payload"]["source"]["json_pointer"] for item in result["final_items"]}
    assert {"/relationships/0", "/relationships/1", "/entities/0", "/entities/1", "/entities/2"} <= pointers
    assert len(result["source_inventory"]["process_relationships"]) == 2
    assert result["initial_context"] == data[0]
    assert not any(item["kind"] == "edge" for item in result["supplementary_items"])


def test_parser_v2_enrichment_and_support_integrate_without_projection_loss(inputs):
    from threat_hunting.graphrag.query_requirements_v2 import analyze_query_requirements_v2
    from threat_hunting.graphrag.query_support_v2 import assess_evidence_support_v2
    initial, corpus, graph, old_req = _process_sources(inputs)
    req = analyze_query_requirements_v2(old_req["query"])
    assert req["analysis_status"] == "supported"
    result = enrich_query_context_v2(initial, corpus, graph, req, budget=BUDGET, max_chain_depth=8)
    checked = assess_evidence_support_v2(req, result, max_chain_depth=8)
    assert checked["status"] == "supported"
    assert checked["requirements"][0]["completeness"]["status"] == "complete"


@pytest.mark.parametrize("mapped,expected", [(True, True), (False, False)])
def test_creation_fact_only_relationships_are_inventoried_or_coverage_unknown(inputs, mapped, expected):
    from threat_hunting.graphrag.query_context_v2 import _inventory
    _, corpus, graph, _ = _process_sources(inputs)
    # A source creation fact remains real evidence without a materialized
    # relationship. Its original GUIDs must map to source entity instances.
    corpus["chunks"] = [item for item in corpus["chunks"] if item["chunk_type"] != "relationship"]
    graph["edges"] = [item for item in graph["edges"] if item["edge_type"] != "process_spawn"]
    fact = next(item for item in corpus["chunks"] if item["chunk_type"] == "fact")
    fact["status"] = "observed"
    fact["metadata"]["attributes"]["source_observations"] = [{"source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:1", "original_fields": {
        "EventID": 1, "Image": "renamed-relay.exe", "ParentImage": "renamed-launch.exe",
        "ProcessGuid": "entity-synthetic-beta", "ParentProcessGuid": "entity-synthetic-alpha", "Hostname": "SYNTHETIC" if mapped else "UNRESOLVED-HOST"}}]
    inventory = _inventory(corpus, graph)
    assert inventory["process_relationship_inventory_complete"] is expected
    assert bool(inventory["unresolved_process_relationship_sources"]) is not expected
    if mapped:
        assert any(entry["source_identity"]["object_type"] == "fact" for entry in inventory["process_relationships"])


def test_reverse_supplementation_never_invents_unknown_ancestors(inputs):
    data = _process_sources(inputs)
    data[3]["requirements"][0]["parameters"]["child"] = "absent-target.exe"
    result = enrich_query_context_v2(*data, budget=BUDGET, max_chain_depth=8)
    assert not result["supplementary_items"]


@pytest.mark.parametrize("depth", [0, -1, True, None])
def test_context_chain_bound_is_explicit_and_validated(inputs, depth):
    with pytest.raises(ValueError, match="max_chain_depth"):
        enrich_query_context_v2(*inputs, budget=BUDGET, max_chain_depth=depth)
