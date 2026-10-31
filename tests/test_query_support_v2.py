"""Synthetic development checks for FIX3 identity and completeness boundaries."""
from copy import deepcopy

import pytest

from threat_hunting.graphrag.query_support import assess_evidence_support
from threat_hunting.graphrag.query_support_v2 import assess_evidence_support_v2


def requirement(kind, **params):
    return {"schema_version": "query-requirements/v1", "query": "synthetic request",
        "scope": {"requested_platforms": [], "excluded_platforms": [], "mechanisms": [], "comparison": False, "status": "unspecified", "reason_codes": []},
        "entities": [], "reason_codes": [], "limitations": [], "analysis_status": "supported",
        "requirements": [{"requirement_id": "r1", "kind": kind, "mandatory": True, "parameters": params, "analysis_status": "supported", "reason_codes": []}]}


def wrapper(kind, payload):
    return {"kind": kind, "item_id": payload[f"{kind}_id"], "payload": payload,
            "origin": "supplementary", "requirement_ids": ["r1"], "reason_codes": ["synthetic"]}


def relation(parent, child, parent_id, child_id, number):
    return wrapper("chunk", {"chunk_id": f"relation-{number}", "chunk_type": "relationship", "status": "observed",
        "source": {"object_type": "relationship", "object_id": f"r-{number}", "json_pointer": f"/relationships/{number}"},
        "metadata": {}, "content": f"Relationship r-{number}. Source: {parent} ({parent_id}). Type: process_spawn. Target: {child} ({child_id}). Status: observed.",
        "source_references": [{"source_file": "synthetic.jsonl", "raw_record_ref": f"jsonl:line:{number + 1}"}]})


def limitation(number, text):
    return wrapper("chunk", {"chunk_id": f"limit-{number}", "chunk_type": "limitation", "status": "reviewable",
        "source": {"object_type": "limitation", "object_id": None, "json_pointer": f"/summary/limitations/{number}"}, "metadata": {}, "content": text})


def context(*items, limits=None, relationships=None, v2=True):
    return {"schema_version": "query-evidence-context/v2" if v2 else "query-evidence-context/v1", "final_items": list(items),
        "source_inventory": {"limitation_count": len(limits or []), "limitation_sources": limits or [], "process_relationships": relationships or [],
                             "process_relationship_inventory_complete": True, "unresolved_process_relationship_sources": []}, "incomplete_context": False}


def inventory(*items):
    result = []
    for item in items:
        content = item["payload"]["content"]
        first, last = content.split(". Source: ")[1].split(". Type: process_spawn. Target: ")
        parent = first.rsplit(" (", 1)[1][:-1]
        child = last.split("). Status:")[0].rsplit(" (", 1)[1]
        result.append({"source_identity": deepcopy(item["payload"]["source"]), "parent_identity": parent, "child_identity": child})
    return result


def run(req, ctx, depth=8):
    return assess_evidence_support_v2(req, ctx, max_chain_depth=depth)


@pytest.mark.parametrize("names", [("start.exe", "relay.exe", "end.exe"), ("launch-z.bin", "hop-y.bin", "worker-x.bin")])
def test_target_only_chain_follows_actual_instances_to_source_boundary(names):
    first, second = relation(names[0], names[1], "instance-1", "instance-2", 0), relation(names[1], names[2], "instance-2", "instance-3", 1)
    req = requirement("process_relationship", parent=None, child=names[2], chain=True)
    result = run(req, context(first, second, relationships=inventory(first, second)))
    assert result["status"] == "supported"
    assert result["requirements"][0]["completeness"]["status"] == "complete"
    assert {trace["item_id"] for trace in result["requirements"][0]["traces"]} == {first["item_id"], second["item_id"]}


def test_missing_ancestor_evidence_cannot_be_supplied_by_inventory():
    first, second = relation("a.exe", "b.exe", "a", "b", 0), relation("b.exe", "z.exe", "b", "z", 1)
    result = run(requirement("process_relationship", parent=None, child="z.exe", chain=True), context(second, relationships=inventory(first, second)))
    assert result["status"] == "missing"
    assert result["requirements"][0]["completeness"]["status"] == "incomplete"
    assert all(trace["item_id"] == second["item_id"] for trace in result["requirements"][0]["traces"])


def test_target_only_chain_requires_authenticated_boundary_inventory():
    item = relation("a.exe", "z.exe", "a", "z", 0)
    result = run(requirement("process_relationship", parent=None, child="z.exe", chain=True), context(item, v2=False))
    assert result["status"] == "unknown"


def test_unresolved_source_creation_boundary_stays_unknown():
    item = relation("a.exe", "z.exe", "a", "z", 0)
    ctx = context(item, relationships=inventory(item))
    ctx["source_inventory"]["process_relationship_inventory_complete"] = False
    ctx["source_inventory"]["unresolved_process_relationship_sources"] = [{"object_type": "fact", "object_id": "unresolved", "json_pointer": "/facts/99"}]
    result = run(requirement("process_relationship", parent=None, child="z.exe", chain=True), ctx)
    assert result["status"] == "unknown"
    assert result["requirements"][0]["completeness"]["status"] == "unknown"


@pytest.mark.parametrize("depth,expected", [(1, "unknown"), (2, "supported"), (8, "supported")])
def test_depth_limit_is_explicit_and_does_not_claim_complete_chain(depth, expected):
    first, second = relation("a.exe", "b.exe", "a", "b", 0), relation("b.exe", "z.exe", "b", "z", 1)
    result = run(requirement("process_relationship", parent=None, child="z.exe", chain=True), context(first, second, relationships=inventory(first, second)), depth)
    assert result["status"] == expected
    if depth == 1:
        assert result["requirements"][0]["completeness"]["status"] == "incomplete"


def test_cycle_is_incomplete_and_does_not_loop():
    items = [relation("a.exe", "b.exe", "a", "b", 0), relation("b.exe", "a.exe", "b", "a", 1)]
    result = run(requirement("process_relationship", parent=None, child="b.exe", chain=True), context(*items, relationships=inventory(*items)))
    assert result["status"] == "unknown"
    assert result["requirements"][0]["contradiction"]["status"] == "detected"
    assert result["requirements"][0]["completeness"]["status"] == "incomplete"


def test_same_middle_basename_different_source_instances_do_not_join():
    items = [relation("a.exe", "same.exe", "a", "old-instance", 0), relation("same.exe", "z.exe", "new-instance", "z", 1)]
    result = run(requirement("process_relationship", parent="a.exe", child="z.exe", chain=True), context(*items, relationships=inventory(*items)))
    assert result["status"] == "missing"


def test_multiple_target_instances_remain_unknown():
    items = [relation("a.exe", "z.exe", "a", "z1", 0), relation("b.exe", "z.exe", "b", "z2", 1)]
    assert run(requirement("process_relationship", parent=None, child="z.exe", chain=True), context(*items, relationships=inventory(*items)))["status"] == "unknown"


def observation(number, child, parent, *, pid=False, host="HOST", time="2026-10-17T10:00:00Z"):
    fields = {"Image": child, "ParentImage": parent, "EventID": 1, "Hostname": host, "TimeCreated": time, "CommandLine": child + " --query"}
    fields.update({"ProcessId": str(number + 1), "ParentProcessId": str(number)} if pid else {"ProcessGuid": f"guid-{number + 1}", "ParentProcessGuid": f"guid-{number}"})
    return wrapper("node", {"node_id": f"fact-{number}", "node_type": "fact", "status": "observed", "source": {"object_type": "fact", "object_id": f"fact-{number}", "json_pointer": f"/facts/{number}"},
        "attributes": {"attributes": {"source_observations": [{"source_file": "synthetic.jsonl", "raw_record_ref": f"jsonl:line:{number + 1}", "original_fields": fields}]}},
        "source_references": [{"source_file": "synthetic.jsonl", "raw_record_ref": f"jsonl:line:{number + 1}"}]})


@pytest.mark.parametrize("pid,host,time,expected", [(False, "HOST", "2026-10-17T10:00:01Z", "supported"),
    (False, "OTHER", "2026-10-17T10:00:01Z", "missing"), (True, "HOST", "2026-10-18T10:00:00Z", "missing")])
def test_host_guid_linking_and_reused_pid_lifetime_boundaries(pid, host, time, expected):
    first = observation(1, "b.exe", "a.exe", pid=pid)
    second = observation(2, "z.exe", "b.exe", pid=pid, host=host, time=time)
    result = run(requirement("process_relationship", parent="a.exe", child="z.exe", chain=True), context(first, second))
    assert result["status"] == expected


def test_functional_parent_conflict_is_not_supported():
    items = [relation("a.exe", "z.exe", "a", "z", 0), relation("b.exe", "z.exe", "b", "z", 1)]
    result = run(requirement("process_relationship", parent="a.exe", child="z.exe", chain=False), context(*items))
    assert result["status"] == "unknown"
    assert result["requirements"][0]["contradiction"]["status"] == "detected"


@pytest.mark.parametrize("change,expected", [("none", "supported"), ("wrong_set_same_count", "missing"), ("absent", "missing"), ("unknown_inventory", "unknown")])
def test_all_limitations_compares_exact_identities_not_counts(change, expected):
    items = [limitation(0, "Timestamp timezone is unresolved."), limitation(1, "Reviewed core scope only.")]
    expected_sources = [{**item["payload"]["source"], "facets": ["timestamp"] if index == 0 else ["scope"]} for index, item in enumerate(items)]
    ctx = context(*items, limits=expected_sources)
    if change == "wrong_set_same_count":
        ctx["final_items"][1]["payload"]["source"]["json_pointer"] = "/summary/limitations/77"
    elif change == "absent":
        ctx["final_items"].pop()
    elif change == "unknown_inventory":
        ctx["schema_version"] = "query-evidence-context/v1"
    result = run(requirement("review_limitations", facets=["all"]), ctx)
    assert result["status"] == expected


def test_facet_subset_does_not_require_unrequested_limitations():
    stamp, scope = limitation(0, "Timestamp unresolved."), limitation(1, "Scope limited.")
    sources = [{**stamp["payload"]["source"], "facets": ["timestamp"]}, {**scope["payload"]["source"], "facets": ["scope"]}]
    assert run(requirement("review_limitations", facets=["timestamp"]), context(stamp, limits=sources))["status"] == "supported"
    assert run(requirement("review_limitations", facets=["all"]), context(stamp, limits=sources))["status"] == "missing"


@pytest.mark.parametrize("actual_source_type,expected", [("scenario_summary", "supported"), ("limitation", "missing")])
def test_v2_review_status_requires_actual_scenario_analysis_status(actual_source_type, expected):
    from threat_hunting.graphrag.query_requirements_v2 import analyze_query_requirements_v2
    req = analyze_query_requirements_v2("What is the analysis status of this review?")
    item = wrapper("chunk", {"chunk_id": "scenario", "chunk_type": actual_source_type, "status": "reviewable",
        "source": {"object_type": "scenario", "object_id": "scenario", "json_pointer": "/scenario"},
        "metadata": {"analysis_status": "draft_reviewable"}, "content": "Review status only."})
    result = run(req, context(item))
    assert result["status"] == expected
    if expected == "supported":
        assert result["requirements"][0]["traces"][0]["quote"] == "draft_reviewable"


@pytest.mark.parametrize("kind,parameters", [("command_completion", {"process": "z.exe"}), ("service_state", {"process": "z.exe"}), ("network_url", {"actor": "z.exe", "action": "download", "field": "url"})])
def test_generic_limitation_and_launch_do_not_supply_positive_claims(kind, parameters):
    ctx = context(observation(1, "z.exe", "a.exe"), limitation(0, "Completion, service state and download remain unsupported; https://example.test/doc."))
    assert run(requirement(kind, **parameters), ctx)["status"] == "missing"


@pytest.mark.parametrize("actor,action,expected", [("z", "downloaded_from", "supported"), ("other", "downloaded_from", "missing"), ("z", "connected_to", "missing")])
def test_endpoint_requires_exact_actor_action_binding(actor, action, expected):
    entity = wrapper("node", {"node_id": "entity-z", "node_type": "entity", "status": "observed", "label": "z.exe", "source": {"object_id": "z", "json_pointer": "/entities/0"}, "attributes": {"attributes": {"process_name": "z.exe"}}})
    fact = wrapper("node", {"node_id": "download", "node_type": "fact", "status": "observed", "source": {"object_id": "download", "json_pointer": "/facts/9"},
        "attributes": {"subject": actor, "predicate": action, "object": "https://example.test/file", "attributes": {"url": "https://example.test/file"}},
        "source_references": [{"source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:9"}]})
    result = run(requirement("network_url", actor="z.exe", action="download", field="url"), context(entity, fact))
    assert result["status"] == expected
    if expected == "supported":
        assert result["requirements"][0]["traces"][0]["binding"]["subject_identity"] == "z"


def test_legacy_support_api_and_input_bytes_remain_unchanged():
    req = requirement("launch_command", process="z.exe")
    ctx = context(observation(1, "z.exe", "a.exe"), v2=False)
    before = deepcopy((req, ctx))
    old_result = assess_evidence_support(req, ctx)
    new_result = run(req, ctx)
    assert assess_evidence_support(req, ctx) == old_result
    assert old_result["schema_version"] == "query-evidence-support/v1"
    assert new_result["schema_version"] == "query-evidence-support/v2"
    assert new_result["status"] == old_result["status"] == "supported"
    assert (req, ctx) == before


@pytest.mark.parametrize("same_instance,expected_reason", [(True, "conflicting_original_launch_commands_for_process_instance"), (False, "launch_process_instance_ambiguous")])
def test_launch_requires_nonconflicting_bound_original_command(same_instance, expected_reason):
    first = observation(1, "z.exe", "a.exe")
    second = deepcopy(first)
    second["item_id"] = second["payload"]["node_id"] = "second-view"
    fields = second["payload"]["attributes"]["attributes"]["source_observations"][0]["original_fields"]
    fields["CommandLine"] = "z.exe --different-command"
    if not same_instance:
        fields["ProcessGuid"] = "different-guid"
    result = run(requirement("launch_command", process="z.exe"), context(first, second))
    assert result["status"] == "unknown"
    assert expected_reason in result["requirements"][0]["reason_codes"]


@pytest.mark.parametrize("depth", [0, -1, True, 1.5])
def test_invalid_depth_rejected(depth):
    with pytest.raises(ValueError, match="max_chain_depth"):
        run(requirement("launch_command", process="z.exe"), context(), depth)
