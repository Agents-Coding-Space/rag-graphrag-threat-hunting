"""Small synthetic source witnesses; no original datasets, models or providers."""
from copy import deepcopy

import pytest

from threat_hunting.evaluation.evidence_contract import (
    assess_source_evidence_gate, evidence_support, groups, project_evidence,
)


def chunk(kind="fact", object_id="fact-one", properties=None, content="Observed source item"):
    return {"chunk_id": "chunk-" + object_id, "chunk_type": kind, "scenario_id": "synthetic",
            "status": "observed", "source": {"object_type": kind, "object_id": object_id, "json_pointer": "/" + kind + "/0"},
            "source_references": [{"source_file": "synthetic.json", "raw_record_ref": "jsonl:line:1"}],
            "content": content, "metadata": properties or {}}


def creation(process="tool.exe", command="tool.exe /t T0000", parent="cmd.exe"):
    return {"attributes": {"source_observations": [{"source_file": "synthetic.json", "raw_record_ref": "jsonl:line:1",
        "canonical_fields": {"event_id": "1", "provider": "Microsoft-Windows-Sysmon", "host": "test-host",
            "process_name": process, "parent_process_name": parent, "command_line": command}}]}}


def context(*items):
    return {"scenario_id": "synthetic", "source_ground_truth": {"scenario_id": "synthetic", "sha256": "a" * 64},
            "retrieval": {"hits": [{"chunk": item} for item in items]}, "traversal": {}}


def legacy(passed=True):
    return {"policy_id": "unchanged-test-policy", "stage_results": {"topical_relevance": {
        "status": "passed" if passed else "failed", "reason_codes": [] if passed else ["returned_top_cosine_score_below_threshold"]}}}


def assess(query, ctx):
    return assess_source_evidence_gate(query, ctx, legacy())[0]


def test_retrieved_fields_are_sufficient_without_graph_or_io():
    ctx = context(chunk(properties=creation()))
    before = deepcopy(ctx)
    gate, projection = assess_source_evidence_gate("Show the launch command for tool.exe", ctx, legacy())
    assert gate["decision"] == "proceed"
    assert ctx == before
    assert ctx["traversal"] == {}
    witness = gate["stage_results"]["evidence_answerability"]["checks"][0]["witnesses"][0]
    assert witness["value"] == "tool.exe /t T0000"
    assert witness["context_pointer"].endswith("/metadata/attributes/source_observations/0/canonical_fields/command_line")
    assert len(projection["units"]) == 1


@pytest.mark.parametrize("mutation", ["refs", "hash", "scenario", "unreferenced_observation"])
def test_missing_provenance_or_cross_scenario_never_grants_support(mutation):
    item = chunk(properties=creation())
    ctx = context(item)
    if mutation == "refs": item["source_references"] = []
    elif mutation == "hash": ctx["source_ground_truth"]["sha256"] = "invalid"
    elif mutation == "scenario": item["scenario_id"] = "other"
    else: item["metadata"]["attributes"]["source_observations"][0]["raw_record_ref"] = "jsonl:line:999"
    assert assess("Show the launch command for tool.exe", ctx)["decision"] == "abstain"


def test_summary_and_unretrieved_reference_are_not_command_fields():
    ctx = context(chunk("scenario", "summary", content='tool.exe was launched with "tool.exe /t T0000"'))
    gate = assess("Show the launch command for tool.exe", ctx)
    assert gate["decision"] == "abstain"
    assert "actor_bound_command_fields_not_returned" in gate["reason_codes"]


def test_graph_adds_only_actual_returned_field_witness():
    fact = chunk(properties=creation())
    ctx = context(chunk("scenario", "summary"))
    assert assess("Show the launch command for tool.exe", ctx)["decision"] == "abstain"
    node = {"node_id": "returned-node", "node_type": "fact", "source": fact["source"], "status": fact["status"],
            "source_references": fact["source_references"], "attributes": fact["metadata"], "label": "source fact"}
    ctx["traversal"] = {"nodes": [node], "edges": []}
    assert assess("Show the launch command for tool.exe", ctx)["decision"] == "proceed"
    assert len(project_evidence(ctx)["units"]) == 2


def test_topical_threshold_is_still_enforced_with_complete_witnesses():
    gate, _ = assess_source_evidence_gate("Show the launch command for tool.exe", context(chunk(properties=creation())), legacy(False))
    assert gate["decision"] == "abstain"
    assert gate["reason_codes"] == ["returned_top_cosine_score_below_threshold"]


def test_strict_relationship_text_supports_parent_without_raw_field_invention():
    relation = chunk("relationship", "relation-one", content="Relationship r1. Source: cmd.exe (p1). Type: process_spawn. Target: tool.exe (p2). Status: observed.")
    ctx = context(relation)
    gate = assess("Which parent process created tool.exe?", ctx)
    assert gate["decision"] == "proceed"
    assert not relation["metadata"]
    other = chunk(properties=creation(parent="other.exe"))
    assert assess("Which parent process created tool.exe?", context(relation, other))["decision"] == "abstain"


@pytest.mark.parametrize("query", ["Write a poem", "Which parent process launched the task?", "Show the launch command"])
def test_unsupported_or_unbound_query_is_not_filled_from_context(query):
    assert assess(query, context(chunk(properties=creation())))["decision"] == "abstain"


def test_process_actor_is_bound_before_command_or_endpoint_support():
    assert assess("Show the launch command for other.exe", context(chunk(properties=creation())))["decision"] == "abstain"
    assert assess("tool.exe connected to which IP and port?", context(chunk(properties=creation())))["decision"] == "abstain"


def test_network_requires_actual_event3_and_actor_endpoint_provider_refs():
    props = creation()
    f = props["attributes"]["source_observations"][0]["canonical_fields"]
    f.update(event_id="3", destination_ip="192.0.2.1", destination_port=8080)
    gate = assess("tool.exe connected to which IP and port?", context(chunk(properties=props)))
    assert gate["decision"] == "proceed"
    f["event_id"] = "1"
    assert assess("tool.exe connected to which IP and port?", context(chunk(properties=props)))["decision"] == "abstain"


def test_negation_applies_to_the_requested_facet_not_another_clause():
    fact = chunk(properties=creation(command="tool.exe query-state"))
    limit = chunk("limitation", "limit-one", content="Completion is established; service state remains unverified.")
    assert assess("tool.exe completion and service state?", context(fact, limit))["decision"] == "abstain"
    limit["content"] = "Process creation does not establish completion or the service state."
    assert assess("tool.exe completion and service state?", context(fact, limit))["decision"] == "proceed"


def test_duplicate_chunk_node_evidence_is_one_group_and_core_needs_boundary():
    ev = chunk("evidence", "e1", content="Evidence e1. Observations: provider=A, event_id=4688; provider=B, event_id=1.")
    ev["source_references"].append({"source_file": "synthetic.json", "raw_record_ref": "jsonl:line:2"})
    ctx = context(ev)
    ctx["traversal"] = {"nodes": [{"node_id": "same-evidence", "node_type": "evidence", "source": ev["source"],
        "status": "observed", "label": "same", "source_references": ev["source_references"],
        "attributes": {"observations": [{"event_id": "1"}, {"event_id": "4688"}]}}]}
    assert len(groups(project_evidence(ctx)["units"])) == 1
    support = evidence_support("How many process creations in the core?", project_evidence(ctx))
    assert support["status"] == "missing"
    assert "core_boundary_not_returned" in support["reason_codes"]


def test_t_argument_and_url_require_the_requested_command_evidence():
    assert assess("Dòng lệnh tool.exe chứa /t nào?", context(chunk(properties=creation(command="tool.exe /x value"))))["decision"] == "abstain"
    assert assess("Lệnh khởi chạy tool.exe dùng giao thức và cổng nào?", context(chunk(properties=creation(command="tool.exe http://192.0.2.1:bad/a"))))["decision"] == "abstain"


def test_compound_request_cannot_ignore_a_missing_second_witness():
    relation = chunk("relationship", "relation-one", content="Relationship r1. Source: cmd.exe (p1). Type: process_spawn. Target: tool.exe (p2). Status: observed.")
    gate = assess("Which parent created tool.exe and show its command line?", context(relation))
    assert gate["decision"] == "abstain"
    assert "actor_bound_command_fields_not_returned" in gate["reason_codes"]
