"""FIX3 support with instance-bound chains and exact limitation completeness.

Only final items provide positive support. Source inventory defines boundaries;
missing always describes the checked context, never a system-wide absence.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import query_support as old
from .query_context_v2 import identity_key, source_identity
from .query_requirements import validate_query_requirements_document


QUERY_EVIDENCE_SUPPORT_SCHEMA_VERSION = "query-evidence-support/v2"


def _requirements(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema_version") == "query-requirements/v1":
        return validate_query_requirements_document(value)
    from .query_requirements_v2 import validate_query_requirements_document_v2
    return validate_query_requirements_document_v2(value)


def _state(status: str, *reasons: str) -> dict[str, Any]:
    return {"status": status, "reason_codes": list(reasons)}


def _canonical_relations(records: list[dict[str, Any]], observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    relations = deepcopy(old._relations(records, observations))
    aliases: dict[str, str] = {}
    for record in records:
        if old._type(record) != "entity":
            continue
        nested = old._map(old._attrs(record).get("attributes"))
        identity = old._map(record["payload"].get("source")).get("object_id")
        host, guid = nested.get("host"), nested.get("process_guid")
        if isinstance(identity, str) and host and guid:
            aliases[f"{old._normal(str(host))}:guid:{str(guid).casefold()}"] = "entity:" + identity
    for rel in relations:
        for field in ("parent_chain_id", "child_chain_id"):
            identity = rel[field]
            # A PID plus host is not a process lifetime identity. In particular,
            # two creation records at different times cannot be linked by PID.
            if identity is not None and (":pid:" in identity or identity.startswith("unspecified-host:")):
                identity = None
            rel[field] = aliases.get(identity, identity)
    unique = {}
    for rel in relations:
        key = (rel["parent_chain_id"], rel["child_chain_id"], rel["parent"], rel["child"])
        if key not in unique:
            unique[key] = rel
    return list(unique.values())


def _contradictions(records: list[dict[str, Any]], relations: list[dict[str, Any]], relevant: set[str]) -> dict[str, Any]:
    names: dict[str, set[str]] = {}
    parents: dict[str, set[str]] = {}
    for rel in relations:
        for field, name in (("parent_chain_id", "parent"), ("child_chain_id", "child")):
            if rel[field] is not None:
                names.setdefault(rel[field], set()).add(rel[name])
        if rel["parent_chain_id"] and rel["child_chain_id"]:
            parents.setdefault(rel["child_chain_id"], set()).add(rel["parent_chain_id"])
    conflicts = [identity for identity in relevant if len(names.get(identity, set())) > 1 or len(parents.get(identity, set())) > 1]
    if conflicts:
        return _state("detected", "conflicting_process_instance_names_or_parents")
    return _state("none_detected")


def _chain(params: Mapping[str, Any], context: Mapping[str, Any], records: list[dict[str, Any]], relations: list[dict[str, Any]], max_depth: int) -> tuple[str, str, list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    targets = {rel["child_chain_id"] for rel in relations if old._matches(rel["child"], params.get("child")) and rel["child_chain_id"]}
    if not params.get("child"):
        return "unknown", "chain_target_not_bound", [], _state("unknown", "chain_target_not_bound"), _state("unknown")
    if not targets:
        return "missing", "identity_bound_target_creation_not_returned", [], _state("incomplete", "target_creation_missing"), _state("none_detected")
    if len(targets) != 1:
        return "unknown", "chain_target_instance_ambiguous", [], _state("unknown", "multiple_target_instances"), _state("unknown")
    target = next(iter(targets))
    inventory = old._map(context.get("source_inventory")).get("process_relationships")
    boundaries_known = (context.get("schema_version") == "query-evidence-context/v2" and isinstance(inventory, list)
                        and old._map(context.get("source_inventory")).get("process_relationship_inventory_complete") is True)
    expected = inventory if boundaries_known else []
    traces: list[dict[str, Any]] = []
    visited = {target}
    frontier = {target}
    edges_seen = 0
    reached_parent = False
    def has_cycle(child: str, path: set[str], remaining: int) -> bool:
        if remaining <= 0:
            return False
        for relation in relations:
            parent = relation["parent_chain_id"]
            if relation["child_chain_id"] != child or parent is None:
                continue
            if parent in path or has_cycle(parent, path | {parent}, remaining - 1):
                return True
        return False
    if has_cycle(target, {target}, max_depth):
        cycle_traces = [trace for relation in relations for trace in relation["traces"]]
        return "unknown", "process_chain_cycle_detected", cycle_traces, _state("incomplete", "process_chain_cycle_detected"), _state("detected", "process_chain_cycle_detected")
    for depth in range(max_depth):
        next_frontier: set[str] = set()
        for child_id in sorted(frontier):
            incoming = [rel for rel in relations if rel["child_chain_id"] == child_id and rel["parent_chain_id"]]
            expected_incoming = [entry for entry in expected if "entity:" + entry["child_identity"] == child_id]
            actual_pairs = {(rel["parent_chain_id"], rel["child_chain_id"]) for rel in incoming}
            if any(("entity:" + entry["parent_identity"], child_id) not in actual_pairs for entry in expected_incoming):
                return "missing", "source_ancestor_relationship_not_returned", traces, _state("incomplete", "required_source_relationship_missing"), _contradictions(records, relations, visited)
            if not incoming:
                if params.get("parent") is not None:
                    continue
                if not boundaries_known or not child_id.startswith("entity:"):
                    return "unknown", "chain_source_boundary_unknown", traces, _state("unknown", "chain_source_boundary_unknown"), _contradictions(records, relations, visited)
                continue
            for rel in incoming:
                parent_id = rel["parent_chain_id"]
                traces.extend(rel["traces"])
                edges_seen += 1
                if params.get("parent") is not None and old._matches(rel["parent"], params["parent"]):
                    reached_parent = True
                elif parent_id not in visited:
                    next_frontier.add(parent_id)
                visited.add(parent_id)
        conflict = _contradictions(records, relations, visited)
        if conflict["status"] == "detected":
            return "unknown", "process_instance_conflict", traces, _state("unknown", "process_instance_conflict"), conflict
        if reached_parent:
            return "supported", "identity_linked_process_chain_supported", traces, _state("complete", "requested_endpoints_connected"), conflict
        if not next_frontier:
            if params.get("parent") is not None:
                return "missing", "requested_chain_ancestor_not_returned", traces, _state("incomplete", "requested_ancestor_missing"), conflict
            if edges_seen:
                return "supported", "source_bounded_ancestor_chain_supported", traces, _state("complete", "authenticated_source_boundary_reached"), conflict
            return "missing", "ancestor_relationship_not_returned", traces, _state("incomplete", "ancestor_relationship_missing"), conflict
        frontier = next_frontier
    # At the depth boundary, a known root may terminate without another hop.
    if params.get("parent") is None and boundaries_known and all(identity.startswith("entity:") and not any("entity:" + entry["child_identity"] == identity for entry in expected) for identity in frontier):
        return "supported", "source_bounded_ancestor_chain_supported", traces, _state("complete", "authenticated_source_boundary_reached"), _contradictions(records, relations, visited)
    return "unknown", "process_chain_depth_limit", traces, _state("incomplete", "process_chain_depth_limit"), _contradictions(records, relations, visited)


def _limitations(params: Mapping[str, Any], context: Mapping[str, Any], records: list[dict[str, Any]]) -> tuple[str, str, list[dict[str, Any]], dict[str, Any]]:
    facets = params.get("facets", [])
    limits = [record for record in records if old._type(record) == "limitation"]
    returned = {identity_key(source_identity(record["payload"])): record for record in limits}
    inventory = old._map(context.get("source_inventory")).get("limitation_sources")
    traces: list[dict[str, Any]] = []
    expected: set[str] = set()
    requested_limits = [facet for facet in facets if facet != "review_status"]
    if requested_limits:
        if context.get("schema_version") != "query-evidence-context/v2" or not isinstance(inventory, list):
            return "unknown", "exact_limitation_source_inventory_unavailable", [], _state("unknown", "exact_source_identity_set_unavailable")
        for entry in inventory:
            if "all" in requested_limits or set(requested_limits).intersection(entry.get("facets", [])):
                expected.add(identity_key({field: entry.get(field) for field in ("object_type", "object_id", "json_pointer")}))
        if not expected:
            return "missing", "requested_limitation_sources_not_available_in_context", [], _state("incomplete", "requested_limitation_identity_set_empty")
        for key in sorted(expected.intersection(returned)):
            record = returned[key]
            field = "content" if record["kind"] == "chunk" else "label"
            text = record["payload"].get(field)
            if isinstance(text, str) and text.strip():
                traces.append(old._trace(record, "/" + field, text))
            else:
                return "missing", "limitation_text_not_returned", traces, _state("incomplete", "limitation_text_missing")
        if expected - returned.keys():
            return "missing", "required_limitation_source_identity_set_incomplete", traces, _state("incomplete", "required_limitation_source_identity_missing")
    if "review_status" in facets:
        found = False
        for record in records:
            if old._type(record) not in {"scenario_summary", "scenario"}:
                continue
            attrs = old._attrs(record)
            value = attrs.get("analysis_status")
            if isinstance(value, str) and value:
                traces.append(old._trace(record, old._attr_path(record) + "/analysis_status", value))
                found = True
                break
        if not found:
            return "missing", "scenario_analysis_status_not_returned", traces, _state("incomplete", "scenario_analysis_status_missing")
    if not traces:
        return "missing", "requested_review_metadata_not_returned", [], _state("incomplete", "review_metadata_missing")
    return "supported", "exact_requested_review_source_identities_supported", traces, _state("complete", "requested_source_identity_set_present")


def _launch_guard(params: Mapping[str, Any], observations: list[dict[str, Any]]) -> dict[str, Any]:
    commands: dict[str, set[str]] = {}
    for obs in observations:
        fields = obs["fields"]
        if str(fields.get("EventID")) not in {"1", "4688"} or not old._matches(obs["process"], params.get("process")):
            continue
        guid = fields.get("ProcessGuid")
        host = fields.get("Hostname") or fields.get("Computer") or fields.get("host")
        command = fields.get("CommandLine")
        if guid and host and isinstance(command, str) and command.strip():
            identity = old._normal(str(host)) + ":guid:" + str(guid).casefold()
            commands.setdefault(identity, set()).add(command)
    if any(len(values) > 1 for values in commands.values()):
        return _state("detected", "conflicting_original_launch_commands_for_process_instance")
    if len(commands) > 1:
        return _state("unknown", "launch_process_instance_ambiguous")
    return _state("none_detected")


def assess_evidence_support_v2(requirements: Mapping[str, Any], final_context: Mapping[str, Any], *, max_chain_depth: int) -> dict[str, Any]:
    """Return conservative requirement support with explicit completeness guards."""
    if type(max_chain_depth) is not int or max_chain_depth < 1:
        raise old.QueryEvidenceSupportError("max_chain_depth must be a positive integer")
    reqs, context = _requirements(requirements), old._detach(final_context)
    if context.get("schema_version") not in {"query-evidence-context/v1", "query-evidence-context/v2"}:
        raise old.QueryEvidenceSupportError("unsupported final context version")
    query = old._map(old._map(context.get("initial_context")).get("query")).get("text")
    if query is not None and query != reqs["query"]:
        raise old.QueryEvidenceSupportError("requirements query differs from context")
    records = old._records(context)
    observations = old._observations(records)
    relations = _canonical_relations(records, observations)
    results = []
    for req in reqs["requirements"]:
        kind, params = req["kind"], req["parameters"]
        completeness = _state("not_applicable")
        contradiction = _state("none_detected")
        if reqs["analysis_status"] != "supported" or req["analysis_status"] != "supported":
            status, reason, traces = "unknown", "query_requirement_analysis_not_supported", []
        elif kind == "process_relationship" and params.get("chain"):
            status, reason, traces, completeness, contradiction = _chain(params, context, records, relations, max_chain_depth)
        elif kind == "process_relationship":
            status, reason, traces = old._relationship(params, relations)
            relevant = {rel[field] for rel in relations if old._matches(rel["parent"], params.get("parent")) and old._matches(rel["child"], params.get("child")) for field in ("parent_chain_id", "child_chain_id") if rel[field]}
            contradiction = _contradictions(records, relations, relevant)
            if contradiction["status"] == "detected":
                status, reason = "unknown", "process_instance_conflict"
        elif kind == "review_limitations":
            status, reason, traces, completeness = _limitations(params, context, records)
        elif kind == "launch_command":
            status, reason, traces = old._command(params, observations)
            contradiction = _launch_guard(params, observations)
            if contradiction["status"] != "none_detected":
                status, reason = "unknown", contradiction["reason_codes"][0]
        elif kind in {"command_completion", "service_state"}:
            status, reason, traces = old._completion(kind, params, records)
        elif kind == "network_url":
            status, reason, traces = old._network(params, records, observations)
        elif kind == "evidence_provenance":
            status, reason, traces = old._provenance(params, records, observations)
        elif kind == "technique_assessment":
            status, reason, traces = old._technique(params, records)
        else:
            status, reason, traces = "unknown", "requirement_kind_not_supported_by_verifier", []
        traces = list({old._json(trace): trace for trace in traces}.values())
        results.append({"requirement_id": req["requirement_id"], "kind": kind, "mandatory": req["mandatory"],
            "status": status, "reason_codes": [reason], "traces": traces,
            "completeness": completeness, "contradiction": contradiction})
    statuses = [result["status"] for result in results if result["mandatory"]]
    status = "unknown" if not statuses or "unknown" in statuses else "missing" if "missing" in statuses else "supported"
    return {"schema_version": QUERY_EVIDENCE_SUPPORT_SCHEMA_VERSION, "status": status, "requirements": results,
        "counts": {key: sum(result["status"] == key for result in results) for key in ("supported", "missing", "unknown")},
        "reason_codes": ["all_mandatory_requirements_supported" if status == "supported" else "mandatory_requirement_support_unknown" if status == "unknown" else "mandatory_evidence_missing"],
        "metadata": {"checked_final_item_count": len(records), "file_io_performed": False, "retrieval_scores_used": False,
            "security_conclusion_made": False, "max_chain_depth": max_chain_depth,
            "missing_interpretation": "required_evidence_not_found_in_checked_context_only"}}


__all__ = ("QUERY_EVIDENCE_SUPPORT_SCHEMA_VERSION", "assess_evidence_support_v2")
