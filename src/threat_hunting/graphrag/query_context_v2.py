"""Versioned identity inventory and bounded supplementation for FIX3.

The inventory authenticates source boundaries; it never supplies evidence to a
support verifier. Existing ranked and traversal payloads are copied verbatim.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import json
from typing import Any

from . import query_context as old
from . import query_support as support
from .query_requirements import validate_query_requirements_document


QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION = "query-evidence-context/v2"


def source_identity(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a representation-independent identity within source-GT binding."""
    source = payload.get("source", {})
    return {field: source.get(field) for field in ("object_type", "object_id", "json_pointer")}


def identity_key(identity: Mapping[str, Any]) -> str:
    return old._bytes(dict(identity)).decode("utf-8")


def _requirements(document: Mapping[str, Any]) -> dict[str, Any]:
    if document.get("schema_version") == "query-requirements/v1":
        return validate_query_requirements_document(document)
    from .query_requirements_v2 import validate_query_requirements_document_v2
    return validate_query_requirements_document_v2(document)


def _projection(document: Mapping[str, Any]) -> dict[str, Any]:
    if document.get("schema_version") == "query-requirements/v1":
        return validate_query_requirements_document(document)
    from .query_requirements_v2 import requirements_v1_projection
    return requirements_v1_projection(document)


def _all_source_records(corpus: Mapping[str, Any], graph: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [old._record(kind, item, "supplementary")
            for kind, collection in (("chunk", corpus["chunks"]), ("node", graph["nodes"]), ("edge", graph["edges"]))
            for item in collection]


def _inventory(corpus: Mapping[str, Any], graph: Mapping[str, Any]) -> dict[str, Any]:
    records = _all_source_records(corpus, graph)
    limits: dict[str, dict[str, Any]] = {}
    for record in records:
        if record["kind"] == "edge" or support._type(record) != "limitation":
            continue
        identity = source_identity(record["payload"])
        key = identity_key(identity)
        facets = old._limitation_facets(old._text(record["kind"], record["payload"]))
        if key in limits:
            facets.update(limits[key]["facets"])
        limits[key] = {**identity, "facets": sorted(facets)}
    relationships: dict[str, dict[str, Any]] = {}
    entities = support._entities(records)
    for record in records:
        payload = record["payload"]
        if payload.get("status") != "observed" or not support._refs(record):
            continue
        parent = child = None
        if record["kind"] == "chunk" and support._type(record) == "relationship":
            content = payload.get("content", "")
            if isinstance(content, str) and ". Source:" in content:
                match = support._RELATIONSHIP_TEXT.fullmatch("Source:" + content.split(". Source:", 1)[1])
                if match:
                    _, parent, _, child = match.groups()
        elif record["kind"] == "edge" and support._type(record) == "process_spawn" and payload.get("directed") is True:
            p, c = entities.get(payload.get("source_node_id")), entities.get(payload.get("target_node_id"))
            if p and c:
                parent, child = p["identity"], c["identity"]
        if isinstance(parent, str) and isinstance(child, str) and parent != child:
            identity = source_identity(payload)
            entry = {"source_identity": identity, "parent_identity": parent, "child_identity": child}
            key = identity_key(identity)
            if key in relationships and relationships[key] != entry:
                raise old.QueryContextError("source relationship representations disagree")
            relationships[key] = entry
    # Explicit creation facts can establish a source boundary even when no
    # separately materialized relationship exists. GUID-to-entity mapping uses
    # actual source properties, never process basename or reused PID.
    from .query_support_v2 import _canonical_relations
    inspection_records = support._records({"final_items": records})
    observations = support._observations(inspection_records)
    creation_sources = {identity_key(source_identity(obs["record"]["payload"])): source_identity(obs["record"]["payload"])
                        for obs in observations if str(obs["fields"].get("EventID")) in {"1", "4688"}}
    accounted: set[str] = set()
    by_id = {(record["kind"], record["item_id"]): record for record in records}
    for relation in _canonical_relations(inspection_records, observations):
        parent, child = relation["parent_chain_id"], relation["child_chain_id"]
        if not parent or not child or not parent.startswith("entity:") or not child.startswith("entity:"):
            continue
        for trace in relation["traces"]:
            record = by_id.get((trace["kind"], trace["item_id"]))
            if record is None or support._type(record) != "fact":
                continue
            identity = source_identity(record["payload"])
            key = identity_key(identity)
            entry = {"source_identity": identity, "parent_identity": parent.removeprefix("entity:"), "child_identity": child.removeprefix("entity:")}
            if key in relationships and relationships[key] != entry:
                raise old.QueryContextError("source creation fact contains conflicting instance relationships")
            relationships[key] = entry
            accounted.add(key)
    unresolved = [creation_sources[key] for key in sorted(creation_sources.keys() - accounted)]
    return {
        "source_ground_truth": deepcopy(corpus["source_ground_truth"]),
        "corpus_id": corpus["corpus_id"], "graph_id": graph["graph_id"],
        "limitation_count": len(limits),
        "limitation_sources": [limits[key] for key in sorted(limits)],
        "process_relationships": [relationships[key] for key in sorted(relationships)],
        "process_relationship_inventory_complete": not unresolved,
        "unresolved_process_relationship_sources": unresolved,
    }


def _v1_context(context: Mapping[str, Any]) -> dict[str, Any]:
    projected = deepcopy(dict(context))
    projected["schema_version"] = old.QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION
    projected["source_inventory"] = {key: projected["source_inventory"][key]
        for key in ("source_ground_truth", "corpus_id", "graph_id", "limitation_count")}
    return projected


def validate_query_evidence_context_v2(context: Mapping[str, Any]) -> None:
    """Validate exact versioned fields; source authentication needs source inputs."""
    if context.get("schema_version") != QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION:
        raise old.QueryContextError("expected query-evidence-context/v2")
    old.validate_query_evidence_context(_v1_context(context))
    inventory = context["source_inventory"]
    if set(inventory) != {"source_ground_truth", "corpus_id", "graph_id", "limitation_count", "limitation_sources", "process_relationships", "process_relationship_inventory_complete", "unresolved_process_relationship_sources"}:
        raise old.QueryContextError("v2 source inventory fields are invalid")
    identities = set()
    for entry in inventory["limitation_sources"]:
        if not isinstance(entry, Mapping) or set(entry) != {"object_type", "object_id", "json_pointer", "facets"}:
            raise old.QueryContextError("limitation identity fields are invalid")
        if entry["object_type"] != "limitation" or not isinstance(entry["json_pointer"], str) or not entry["json_pointer"].startswith("/"):
            raise old.QueryContextError("limitation identity is invalid")
        old._strings(entry["facets"], "limitation facets")
        key = identity_key({field: entry[field] for field in ("object_type", "object_id", "json_pointer")})
        if key in identities:
            raise old.QueryContextError("duplicate limitation source identity")
        identities.add(key)
    if len(identities) != inventory["limitation_count"]:
        raise old.QueryContextError("limitation identity inventory disagrees with count")
    identities = set()
    for entry in inventory["process_relationships"]:
        if not isinstance(entry, Mapping) or set(entry) != {"source_identity", "parent_identity", "child_identity"}:
            raise old.QueryContextError("process relationship inventory fields are invalid")
        source = entry["source_identity"]
        if not isinstance(source, Mapping) or set(source) != {"object_type", "object_id", "json_pointer"} or source["object_type"] not in {"relationship", "fact"}:
            raise old.QueryContextError("process relationship source identity is invalid")
        if any(not isinstance(entry[field], str) or not entry[field] for field in ("parent_identity", "child_identity")) or entry["parent_identity"] == entry["child_identity"]:
            raise old.QueryContextError("process relationship endpoints are invalid")
        key = identity_key(source)
        if key in identities:
            raise old.QueryContextError("duplicate process relationship source identity")
        identities.add(key)
    unresolved = inventory["unresolved_process_relationship_sources"]
    if not isinstance(unresolved, list) or any(not isinstance(entry, Mapping) or set(entry) != {"object_type", "object_id", "json_pointer"} or entry["object_type"] != "fact" for entry in unresolved):
        raise old.QueryContextError("unresolved process relationship sources are invalid")
    if len({identity_key(entry) for entry in unresolved}) != len(unresolved):
        raise old.QueryContextError("duplicate unresolved process relationship source")
    if type(inventory["process_relationship_inventory_complete"]) is not bool or inventory["process_relationship_inventory_complete"] != (not unresolved):
        raise old.QueryContextError("process relationship coverage disagrees with unresolved sources")


def upgrade_evidence_context(context: Mapping[str, Any], corpus: Mapping[str, Any], graph: Mapping[str, Any]) -> dict[str, Any]:
    """Authenticate and upgrade metadata only, preserving FIX2 evidence exactly."""
    if context.get("schema_version") not in {old.QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION, QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION}:
        raise old.QueryContextError("unsupported evidence context version")
    projected = _v1_context(context)
    old.validate_query_evidence_context(projected)
    old._validate_bindings(projected["initial_context"], corpus, graph)
    sources = {(record["kind"], record["item_id"]): record["payload"] for record in _all_source_records(corpus, graph)}
    for item in projected["final_items"]:
        if sources.get((item["kind"], item["item_id"])) != item["payload"]:
            raise old.QueryContextError("final evidence differs from runtime source")
    inventory = _inventory(corpus, graph)
    if context.get("schema_version") == QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION and context["source_inventory"] != inventory:
        raise old.QueryContextError("v2 inventory differs from runtime source")
    result = deepcopy(dict(context))
    result["schema_version"] = QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION
    result["source_inventory"] = inventory
    validate_query_evidence_context_v2(result)
    assert result["final_items"] == context["final_items"] and result["initial_context"] == context["initial_context"]
    return result


def _chain_source_keys(records: list[dict[str, Any]], params: Mapping[str, Any], inventory: Mapping[str, Any], depth: int) -> set[str]:
    """Select reverse ancestors from explicit source identities, never filenames."""
    entities = support._entities(records)
    targets = {entry["identity"] for entry in entities.values() if support._matches(entry["name"], params.get("child"))}
    if not params.get("child") or len(targets) != 1:
        return set()
    reached = set(targets)
    source_keys: set[str] = set()
    frontier = set(targets)
    for _ in range(depth):
        incoming = [rel for rel in inventory["process_relationships"] if rel["child_identity"] in frontier]
        next_frontier = set()
        for rel in incoming:
            source_keys.add(identity_key(rel["source_identity"]))
            if rel["parent_identity"] not in reached:
                next_frontier.add(rel["parent_identity"])
                reached.add(rel["parent_identity"])
        frontier = next_frontier
        if not frontier:
            break
    for record in records:
        if record["kind"] == "edge":
            continue
        payload = record["payload"]
        identities = set(payload.get("entity_ids", []))
        identities.add(payload.get("source", {}).get("object_id"))
        attrs = support._attrs(record)
        identities.update(attrs.get(field) for field in ("subject", "object") if isinstance(attrs.get(field), str))
        if support._type(record) in {"entity", "fact", "evidence"} and reached.intersection(identities):
            source_keys.add(identity_key(source_identity(payload)))
    return source_keys


def enrich_query_context_v2(initial_context: Mapping[str, Any], corpus: Mapping[str, Any], graph: Mapping[str, Any], requirements: Mapping[str, Any], *, budget: Mapping[str, object], max_chain_depth: int) -> dict[str, Any]:
    """Recompute only supplementation, with explicit budgets and chain bounds."""
    if type(max_chain_depth) is not int or max_chain_depth < 1:
        raise old.QueryContextError("max_chain_depth must be a positive integer")
    reqs = _requirements(requirements)
    projected = _projection(reqs)
    if reqs["query"] != initial_context["query"]["text"]:
        raise old.QueryContextError("requirements query differs from initial context")
    old._validate_bindings(initial_context, corpus, graph)
    limits = old._budget(budget)
    inventory = _inventory(corpus, graph)
    records = _all_source_records(corpus, graph)
    names = old._entity_names(corpus, graph)
    initial = deepcopy(initial_context)
    items = old._initial_records(initial)
    baseline = deepcopy(items)
    represented = {old._source_key(record["payload"]) for record in items if record["kind"] != "edge"}
    identities = {(record["kind"], record["item_id"]) for record in items}
    chain_keys = {req["requirement_id"]: _chain_source_keys(records, req["parameters"], inventory, max_chain_depth)
                  for req in reqs["requirements"] if req["kind"] == "process_relationship" and req["parameters"].get("chain")}
    candidates = []
    for record in sorted((record for record in records if record["kind"] != "edge"),
                         key=lambda rec: (0 if rec["kind"] == "chunk" else 1, rec["payload"]["source"]["json_pointer"], rec["item_id"])):
        matches = []
        for req in projected["requirements"]:
            if req["analysis_status"] != "supported":
                continue
            rid = req["requirement_id"]
            if rid in chain_keys:
                reason = "identity_bounded_ancestor_evidence" if identity_key(source_identity(record["payload"])) in chain_keys[rid] else None
            else:
                reason = old._candidate_reason(record["kind"], record["payload"], req, names)
            if reason:
                matches.append((rid, reason))
        if matches:
            candidate = deepcopy(record)
            candidate["requirement_ids"] = sorted({rid for rid, _ in matches})
            candidate["reason_codes"] = sorted({reason for _, reason in matches})
            candidates.append(candidate)
    oversized = len(items) > limits["max_final_items"] or len(old._bytes(items)) > limits["max_serialized_bytes"]
    supplements, present, cuts = [], [], []
    for candidate in candidates:
        identity = candidate["kind"], candidate["item_id"]
        source = old._source_key(candidate["payload"])
        if identity in identities or source in represented:
            present.append(candidate["item_id"])
            continue
        reasons = []
        if oversized:
            reasons.append("baseline_exceeds_budget")
        if len(supplements) >= limits["max_supplementary_items"]:
            reasons.append("supplementary_item_budget_exhausted")
        if len(items) + 1 > limits["max_final_items"]:
            reasons.append("final_item_budget_exhausted")
        if len(old._bytes([*items, candidate])) > limits["max_serialized_bytes"]:
            reasons.append("serialized_utf8_byte_budget_exhausted")
        if reasons:
            cuts.append({key: candidate[key] for key in ("kind", "item_id", "requirement_ids") } | {"reason_codes": reasons})
            continue
        items.append(candidate)
        supplements.append(candidate)
        identities.add(identity)
        represented.add(source)
    result = {"schema_version": QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION, "initial_context": initial,
        "final_items": items, "supplementary_items": supplements, "source_inventory": inventory,
        "budget": {**limits, "final_item_count": len(items), "final_serialized_bytes": len(old._bytes(items)),
                   "baseline_exceeds_budget": oversized, "measurement": "canonical_serialized_final_items_utf8_bytes_not_tokens"},
        "selection": {"candidate_count": len(candidates), "already_present_item_ids": sorted(set(present)), "cut_items": cuts},
        "incomplete_context": bool(oversized or cuts), "enrichment_enabled": True}
    result = json.loads(old._bytes(result))
    validate_query_evidence_context_v2(result)
    assert result["final_items"][:len(baseline)] == baseline
    return result


__all__ = ("QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION", "source_identity", "identity_key", "upgrade_evidence_context", "enrich_query_context_v2", "validate_query_evidence_context_v2")
