"""Development tests for support based only on actual returned evidence."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from threat_hunting.graphrag.query_support import (
    QueryEvidenceSupportError,
    assess_evidence_support,
)


def requirement(kind: str, **params: object) -> dict:
    return {"schema_version": "query-requirements/v1", "query": "synthetic request",
            "scope": {"requested_platforms": [], "excluded_platforms": [], "mechanisms": [],
                "comparison": False, "status": "unspecified", "reason_codes": []},
            "entities": [], "reason_codes": [], "limitations": [],
            "analysis_status": "supported", "requirements": [{"requirement_id": "r1",
            "kind": kind, "mandatory": True, "parameters": params,
            "analysis_status": "supported", "reason_codes": []}]}


def wrap(kind: str, payload: dict) -> dict:
    return {"kind": kind, "item_id": payload[f"{kind}_id"], "payload": payload,
            "origin": "supplementary", "requirement_ids": ["r1"], "reason_codes": ["synthetic"]}


def context(*items: dict, count: int = 0) -> dict:
    return {"schema_version": "query-evidence-context/v1", "final_items": list(items),
            "source_inventory": {"limitation_count": count}, "incomplete_context": False}


def fact_observation(child="delta.exe", parent="beta.exe", *, event=1,
                     child_id="guid-delta", parent_id="guid-beta", command="delta --show-status") -> dict:
    return wrap("node", {"node_id": "fact-creation", "node_type": "fact", "status": "observed",
        "source": {"json_pointer": "/facts/0", "object_id": "creation"},
        "attributes": {"subject": "beta", "predicate": "spawned_process", "object": "delta",
            "attributes": {"source_observations": [{"source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:2",
                "original_fields": {"Image": "C:\\Tools\\" + child,
                    "ParentImage": "C:\\Tools\\" + parent, "ProcessGuid": child_id,
                    "ParentProcessGuid": parent_id, "CommandLine": command,
                    "EventID": event, "SourceName": "SyntheticProvider", "Channel": "Synthetic",
                    "TimeCreated": "2026-10-16T08:00:00Z"}}]}},
        "source_references": [{"source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:2"}]})


def entity(name: str, identity: str) -> dict:
    return wrap("node", {"node_id": "node-" + identity, "node_type": "entity", "status": "observed",
        "label": name, "source": {"object_id": identity, "json_pointer": "/entities/" + identity},
        "attributes": {"name": name, "attributes": {"process_name": name, "process_id": identity}}})


def action_fact(actor="delta", action="downloaded_from", url="https://example.test/payload") -> dict:
    return wrap("node", {"node_id": "fact-action", "node_type": "fact", "status": "observed",
        "source": {"object_id": "action", "json_pointer": "/facts/1"},
        "attributes": {"subject": actor, "predicate": action, "object": url,
                       "attributes": {"url": url}},
        "source_references": [{"source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:5"}]})


def limitation(index: int, text: str) -> dict:
    return wrap("chunk", {"chunk_id": f"limit-{index}", "chunk_type": "limitation", "status": "reviewable",
        "content": text, "source": {"json_pointer": f"/summary/limitations/{index}"}, "metadata": {}})


def technique(status="candidate", review_status="needs_review") -> dict:
    return wrap("node", {"node_id": "technique-1", "node_type": "mitre_assessment", "status": status,
        "source": {"json_pointer": "/mitre_assessments/0"},
        "attributes": {"external_id": "T9999.001", "evidence_support": "supported_by_observed_behavior",
                       "review_status": review_status, "rationale": "Synthetic assessment only."}})


@pytest.mark.parametrize("child,parent", [("delta.exe", "beta.exe"), ("renamed-worker.exe", "renamed-launcher.exe")])
def test_explicit_parent_child_observation_supports_arbitrary_names(child, parent):
    result = assess_evidence_support(requirement("process_relationship", parent=parent, child=child, chain=False),
                                     context(fact_observation(child, parent)))
    assert result["status"] == "supported"
    assert result["requirements"][0]["traces"][0]["binding"]["action"] == "process_spawn"


def test_cooccurring_entity_names_do_not_establish_relationship():
    result = assess_evidence_support(requirement("process_relationship", parent="beta.exe", child="delta.exe", chain=False),
                                     context(entity("beta.exe", "beta"), entity("delta.exe", "delta")))
    assert result["status"] == "missing"


@pytest.mark.parametrize("change", ["wrong_direction", "missing_identity", "same_identity", "wrong_event", "no_reference"])
def test_process_roles_identity_event_and_provenance_are_required(change):
    item = fact_observation()
    obs = item["payload"]["attributes"]["attributes"]["source_observations"][0]
    if change == "wrong_direction":
        obs["original_fields"]["Image"], obs["original_fields"]["ParentImage"] = (
            obs["original_fields"]["ParentImage"], obs["original_fields"]["Image"])
    elif change == "missing_identity":
        del obs["original_fields"]["ParentProcessGuid"]
    elif change == "same_identity":
        obs["original_fields"]["ParentProcessGuid"] = obs["original_fields"]["ProcessGuid"]
    elif change == "wrong_event":
        obs["original_fields"]["EventID"] = 3
    else:
        obs["raw_record_ref"] = None
    result = assess_evidence_support(requirement("process_relationship", parent="beta.exe", child="delta.exe", chain=False), context(item))
    assert result["status"] == "missing"


def test_chain_requires_linked_identity_not_same_middle_name():
    first = fact_observation("beta.exe", "alpha.exe", child_id="B", parent_id="A")
    first["item_id"] = first["payload"]["node_id"] = "first"
    second = fact_observation("delta.exe", "beta.exe", child_id="D", parent_id="OTHER-B")
    req = requirement("process_relationship", parent="alpha.exe", child="delta.exe", chain=True)
    assert assess_evidence_support(req, context(first, second))["status"] == "missing"
    second["payload"]["attributes"]["attributes"]["source_observations"][0]["original_fields"]["ParentProcessGuid"] = "B"
    assert assess_evidence_support(req, context(first, second))["status"] == "supported"


@pytest.mark.parametrize("use_pids", [False, True])
def test_cross_host_reused_id_does_not_establish_chain(use_pids):
    first = fact_observation("beta.exe", "alpha.exe", child_id="B", parent_id="A")
    first["item_id"] = first["payload"]["node_id"] = "first"
    second = fact_observation("delta.exe", "beta.exe", child_id="D", parent_id="B")
    for item, host in ((first, "HOST-A"), (second, "HOST-B")):
        fields = item["payload"]["attributes"]["attributes"]["source_observations"][0]["original_fields"]
        fields["Hostname"] = host
        if use_pids:
            fields["ProcessId"] = fields.pop("ProcessGuid")
            fields["ParentProcessId"] = fields.pop("ParentProcessGuid")
    req = requirement("process_relationship", parent="alpha.exe", child="delta.exe", chain=True)
    assert assess_evidence_support(req, context(first, second))["status"] == "missing"


def test_hostless_pid_chain_is_not_established():
    first = fact_observation("beta.exe", "alpha.exe", child_id="2", parent_id="1")
    first["item_id"] = first["payload"]["node_id"] = "first"
    second = fact_observation("delta.exe", "beta.exe", child_id="3", parent_id="2")
    for item in (first, second):
        fields = item["payload"]["attributes"]["attributes"]["source_observations"][0]["original_fields"]
        fields["ProcessId"] = fields.pop("ProcessGuid")
        fields["ParentProcessId"] = fields.pop("ParentProcessGuid")
    assert assess_evidence_support(requirement("process_relationship", parent="alpha.exe", child="delta.exe", chain=True),
        context(first, second))["status"] == "missing"


def test_canonical_relationship_chunk_explicit_roles_and_identity_support_relation():
    item = wrap("chunk", {"chunk_id": "relation", "chunk_type": "relationship", "status": "observed",
        "source": {"json_pointer": "/relationships/0"}, "metadata": {},
        "content": "Relationship rel-1. Source: beta.exe (b-1). Type: process_spawn. Target: delta.exe (d-1). Status: observed.",
        "source_references": [{"source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:1"}]})
    req = requirement("process_relationship", parent="beta.exe", child="delta.exe", chain=False)
    assert assess_evidence_support(req, context(item))["status"] == "supported"


@pytest.mark.parametrize("kind", ["command_completion", "service_state"])
def test_launch_command_cannot_establish_completion_or_service_state(kind):
    data = context(fact_observation(command="delta --query-service running"),
        limitation(0, "Process creation does not establish completion, output, or service state."))
    assert assess_evidence_support(requirement("launch_command", process="delta.exe"), data)["status"] == "supported"
    result = assess_evidence_support(requirement(kind, process="delta.exe"), data)
    assert result["status"] == "missing"
    assert "separate_completion_or_state_observation_not_returned" in result["requirements"][0]["reason_codes"]


def test_parent_command_line_cannot_supply_child_launch_command():
    item = fact_observation()
    fields = item["payload"]["attributes"]["attributes"]["source_observations"][0]["original_fields"]
    fields["ParentCommandLine"] = fields.pop("CommandLine")
    assert assess_evidence_support(requirement("launch_command", process="delta.exe"), context(item))["status"] == "missing"


def test_command_from_another_process_does_not_supply_requested_command():
    assert assess_evidence_support(requirement("launch_command", process="other.exe"), context(fact_observation()))["status"] == "missing"


@pytest.mark.parametrize("actor,action,expected", [("delta", "downloaded_from", "supported"),
    ("other", "downloaded_from", "missing"), ("delta", "connected_to", "missing")])
def test_url_requires_correct_observed_actor_and_action(actor, action, expected):
    data = context(entity("delta.exe", "delta"), entity("other.exe", "other"), action_fact(actor, action))
    req = requirement("network_url", actor="delta.exe", action="download", field="url")
    result = assess_evidence_support(req, data)
    assert result["status"] == expected
    if expected == "supported":
        assert result["requirements"][0]["traces"][0]["binding"]["subject_identity"] == "delta"


def test_url_inside_command_or_summary_does_not_prove_download():
    data = context(fact_observation(command="delta --possible-url https://example.test/payload"),
        limitation(0, "No download proof. See https://example.test/payload for unrelated documentation."))
    assert assess_evidence_support(requirement("network_url", actor="delta.exe", action="download", field="url"), data)["status"] == "missing"


def test_candidate_action_fact_is_not_observed_download_proof():
    item = action_fact()
    item["payload"]["status"] = "candidate"
    assert assess_evidence_support(requirement("network_url", actor="delta.exe", action="download", field="url"),
        context(entity("delta.exe", "delta"), item))["status"] == "missing"


def test_separate_network_connection_is_not_download_proof():
    item = fact_observation(event=3)
    item["payload"]["attributes"]["attributes"]["source_observations"][0]["original_fields"]["DestinationIp"] = "192.0.2.20"
    data = context(item)
    assert assess_evidence_support(requirement("network_url", actor="delta.exe", action="connect", field="endpoint"), data)["status"] == "supported"
    assert assess_evidence_support(requirement("network_url", actor="delta.exe", action="download", field="url"), data)["status"] == "missing"


def test_source_observation_provenance_retains_provider_event_time_and_reference():
    result = assess_evidence_support(requirement("evidence_provenance", process="delta.exe"), context(fact_observation()))
    assert result["status"] == "supported"
    quotes = [trace["quote"] for trace in result["requirements"][0]["traces"]]
    assert "SyntheticProvider" in quotes and "jsonl:line:2" in quotes and "2026-10-16T08:00:00Z" in quotes


def test_unassociated_provenance_reference_is_not_enough():
    item = entity("delta.exe", "delta")
    item["payload"]["source_references"] = [{"source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:2"}]
    assert assess_evidence_support(requirement("evidence_provenance", process="delta.exe"), context(item))["status"] == "missing"


@pytest.mark.parametrize("count,expected", [(1, "supported"), (2, "missing")])
def test_all_limitations_requires_dynamic_inventory_completeness(count, expected):
    data = context(limitation(0, "Only the reviewed core is in scope."), count=count)
    assert assess_evidence_support(requirement("review_limitations", facets=["all"]), data)["status"] == expected


def test_all_limitations_without_inventory_is_unknown():
    data = context(limitation(0, "Only the reviewed core is in scope."))
    del data["source_inventory"]
    assert assess_evidence_support(requirement("review_limitations", facets=["all"]), data)["status"] == "unknown"


def test_duplicate_representations_do_not_fake_limitation_completeness():
    first = limitation(0, "Only the reviewed core is in scope.")
    second = copy.deepcopy(first)
    second["item_id"] = second["payload"]["chunk_id"] = "other-representation"
    assert assess_evidence_support(requirement("review_limitations", facets=["all"]), context(first, second, count=2))["status"] == "missing"


def test_requested_facets_are_mandatory_not_any_limitation():
    req = requirement("review_limitations", facets=["timestamp", "completion"])
    data = context(limitation(0, "Sysmon UtcTime has unresolved timezone."), count=1)
    assert assess_evidence_support(req, data)["status"] == "missing"
    data["final_items"].append(limitation(1, "Process creation does not establish successful cmdlet completion."))
    assert assess_evidence_support(req, data)["status"] == "supported"


def test_candidate_assessment_can_answer_status_but_never_confirmation_proof():
    data = context(technique())
    req = requirement("technique_assessment", technique_id="T9999.001", certainty="assessment")
    assert assess_evidence_support(req, data)["status"] == "supported"
    req["requirements"][0]["parameters"]["certainty"] = "confirmed"
    result = assess_evidence_support(req, data)
    assert result["status"] == "missing"
    assert result["requirements"][0]["reason_codes"] == ["technique_confirmation_not_established"]


def test_technique_label_and_candidate_status_without_assessment_rationale_are_insufficient():
    item = technique()
    del item["payload"]["attributes"]["rationale"]
    assert assess_evidence_support(requirement("technique_assessment", technique_id=None, certainty="assessment"), context(item))["status"] == "missing"


def test_unbound_service_observation_cannot_answer_a_specific_service_question():
    item = action_fact(action="service_state_observed", url="unrelated-service")
    item["payload"]["attributes"]["attributes"] = {"service_name": "unrelated-service", "service_state": "running"}
    req = requirement("service_state", process="delta.exe")
    req["query"] = "What is the Sysmon service state from delta.exe?"
    result = assess_evidence_support(req, context(entity("delta.exe", "delta"), item))
    assert result["status"] == "unknown"
    assert result["requirements"][0]["reason_codes"] == ["service_identity_not_resolved_by_requirement_contract"]


def test_another_command_completion_for_same_process_is_not_requested_cmdlet_proof():
    item = action_fact(action="command_completed", url="Get-UnrelatedStatus")
    item["payload"]["attributes"]["attributes"] = {"exit_code": 0, "command_line": "Get-UnrelatedStatus"}
    req = requirement("command_completion", process="delta.exe")
    req["query"] = "Did Get-Service sysmon complete successfully in delta.exe?"
    result = assess_evidence_support(req, context(entity("delta.exe", "delta"), item))
    assert result["status"] == "unknown"
    assert result["requirements"][0]["reason_codes"] == ["command_identity_not_resolved_by_requirement_contract"]


def test_parent_provenance_trace_exposes_requested_parent_role_and_identity():
    data = context(fact_observation())
    result = assess_evidence_support(requirement("evidence_provenance", process="beta.exe"), data)
    assert result["status"] == "supported"
    traces = result["requirements"][0]["traces"]
    assert any(trace["field"].endswith("/ParentImage") and trace["quote"].endswith("beta.exe") for trace in traces)
    assert any(trace["field"].endswith("/ParentProcessGuid") and trace["quote"] == "guid-beta" for trace in traces)
    for trace in traces:
        actual = data
        for part in trace["context_pointer"].lstrip("/").split("/"):
            actual = actual[int(part)] if isinstance(actual, list) else actual[part]
        assert trace["quote"] == (actual if isinstance(actual, str) else json.dumps(actual, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def test_technique_trace_binds_requested_id_to_actual_assessment_field():
    data = context(technique())
    result = assess_evidence_support(requirement("technique_assessment", technique_id="T9999.001", certainty="assessment"), data)
    traces = result["requirements"][0]["traces"]
    assert traces[0]["field"] == "/attributes/external_id" and traces[0]["quote"] == "T9999.001"
    for trace in traces:
        actual = data
        for part in trace["context_pointer"].lstrip("/").split("/"):
            actual = actual[int(part)] if isinstance(actual, list) else actual[part]
        assert trace["quote"] == actual


def test_different_technique_assessment_does_not_match_requested_id():
    assert assess_evidence_support(requirement("technique_assessment", technique_id="T9998", certainty="assessment"), context(technique()))["status"] == "missing"


@pytest.mark.parametrize("analysis", ["unsupported", "ambiguous"])
def test_unresolved_parser_requirement_is_unknown_not_missing_or_out_of_scope(analysis):
    req = requirement("launch_command", process="delta.exe")
    req["analysis_status"] = analysis
    result = assess_evidence_support(req, context(fact_observation()))
    assert result["status"] == "unknown"
    assert result["requirements"][0]["reason_codes"] == ["query_requirement_analysis_not_supported"]


def test_unsupported_empty_analysis_is_unknown_and_invalid_kind_rejected():
    with pytest.raises(QueryEvidenceSupportError):
        assess_evidence_support(requirement("unimplemented_information"), context())
    req = requirement("launch_command", process="delta.exe")
    req["requirements"] = []
    req["analysis_status"] = "unsupported"
    assert assess_evidence_support(req, context())["status"] == "unknown"


def test_multiple_mandatory_requirements_need_all_support():
    req = requirement("launch_command", process="delta.exe")
    other = requirement("network_url", actor="delta.exe", action="download", field="url")["requirements"][0]
    other["requirement_id"] = "r2"
    req["requirements"].append(other)
    result = assess_evidence_support(req, context(fact_observation()))
    assert result["status"] == "missing"
    assert result["counts"] == {"supported": 1, "missing": 1, "unknown": 0}


def test_every_trace_pointer_resolves_to_actual_returned_value():
    data = context(fact_observation())
    result = assess_evidence_support(requirement("launch_command", process="delta.exe"), data)
    for trace in result["requirements"][0]["traces"]:
        actual = data
        for part in trace["context_pointer"].lstrip("/").split("/"):
            actual = actual[int(part)] if isinstance(actual, list) else actual[part]
        assert trace["quote"] == (actual if isinstance(actual, str) else json.dumps(actual, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        assert trace["item_id"] in {item["item_id"] for item in data["final_items"]}


def test_support_does_not_read_files_or_use_scores_annotations_or_answers(monkeypatch):
    def fail(*_args, **_kwargs):
        raise AssertionError("runtime file read forbidden")
    monkeypatch.setattr(Path, "read_text", fail)
    monkeypatch.setattr(Path, "read_bytes", fail)
    data = context(fact_observation())
    data["expected_label"] = "proceed"
    data["reference_answer"] = "download proved"
    data["score"] = 1e9
    req = requirement("network_url", actor="delta.exe", action="download", field="url")
    before = copy.deepcopy((req, data))
    result = assess_evidence_support(req, data)
    assert result["status"] == "missing"
    assert (req, data) == before
    assert assess_evidence_support(req, data) == result


@pytest.mark.parametrize("change", ["version", "mismatched_id", "duplicate", "nonfinite", "duplicate_requirement"])
def test_malformed_inputs_raise_clear_errors(change):
    req, data = requirement("launch_command", process="delta.exe"), context(fact_observation())
    if change == "version":
        data["schema_version"] = "query-evidence-context/v99"
    elif change == "mismatched_id":
        data["final_items"][0]["item_id"] = "wrong"
    elif change == "duplicate":
        data["final_items"] *= 2
    elif change == "nonfinite":
        data["bad"] = float("nan")
    else:
        req["requirements"] *= 2
    with pytest.raises(QueryEvidenceSupportError):
        assess_evidence_support(req, data)


@pytest.mark.parametrize("query,kind,expected", [
    ("Show the process relationship beta.exe -> delta.exe.", "process_relationship", "supported"),
    ("Chỉ ra quan hệ beta.exe -> delta.exe.", "process_relationship", "supported"),
    ("Which launch command line was recorded for delta.exe?", "launch_command", "supported"),
    ("Lệnh khởi chạy của delta.exe là gì?", "launch_command", "supported"),
    ("Did delta.exe complete successfully?", "command_completion", "missing"),
    ("delta.exe đã hoàn tất thành công?", "command_completion", "missing"),
])
def test_en_vi_new_wordings_flow_from_parser_to_actual_evidence(query, kind, expected):
    from threat_hunting.graphrag.query_requirements import analyze_query_requirements
    req = analyze_query_requirements(query, scope_metadata={"platforms": ["windows"]})
    assert req["analysis_status"] == "supported"
    result = assess_evidence_support(req, context(fact_observation()))
    assert result["status"] == expected
    assert kind in [item["kind"] for item in result["requirements"]]


def test_requirements_for_a_different_query_are_rejected():
    data = context(fact_observation())
    data["initial_context"] = {"query": {"text": "a different user request"}}
    with pytest.raises(QueryEvidenceSupportError, match="disagrees"):
        assess_evidence_support(requirement("launch_command", process="delta.exe"), data)


def test_unresolved_network_object_identity_is_not_a_destination_address():
    item = action_fact(action="connected_to", url="unresolved-entity-123")
    result = assess_evidence_support(requirement("network_url", actor="delta.exe", action="connect", field="endpoint"),
        context(entity("delta.exe", "delta"), item))
    assert result["status"] == "missing"
