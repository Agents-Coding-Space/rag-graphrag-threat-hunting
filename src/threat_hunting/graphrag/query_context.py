"""Bounded, source-backed evidence enrichment beside immutable ranked retrieval.

This experimental API never retrieves raw logs or adds ranked hits or graph
paths. It selects existing corpus/graph objects using public query requirements.
The byte budget measures canonical serialized ``final_items``, not tokens.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import json
from typing import Any
import unicodedata

from ..graph.schema import EDGE_FIELDS, NODE_FIELDS, validate_knowledge_graph
from ..retrieval.schema import (
    CHUNK_FIELDS, CHUNK_STATUSES, _scan_contract_guards, validate_retrieval_corpus,
)
from .gate_signals import extract_graphrag_gate_signals
from .query_requirements import validate_query_requirements_document


QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION = "query-evidence-context/v1"
DEFAULT_CONTEXT_BUDGET = {
    "max_supplementary_items": 12,
    "max_final_items": 64,
    "max_serialized_bytes": 131072,
}


class QueryContextError(ValueError):
    """A source, requirements document or enrichment budget is invalid."""


def _bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _strings(value: object, label: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value) or len(set(value)) != len(value):
        raise QueryContextError(f"{label} must contain unique nonempty strings")


def _normal(value: str) -> str:
    text = unicodedata.normalize("NFKD", value.casefold()).replace("đ", "d")
    return " ".join("".join(char for char in text if not unicodedata.combining(char)).split())


def _process_name(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return _normal(value.strip(' \"').replace("\\", "/").rsplit("/", 1)[-1])


def _source_key(item: Mapping[str, Any]) -> tuple[str, str]:
    source = item.get("source", {})
    return str(source.get("object_type", "")), str(source.get("json_pointer", ""))


def _record(kind: str, item: Mapping[str, Any], origin: str) -> dict[str, Any]:
    return {
        "kind": kind, "item_id": item[f"{kind}_id"], "payload": deepcopy(item),
        "origin": origin, "requirement_ids": [], "reason_codes": [],
    }


def _initial_records(context: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = [
        _record("chunk", hit["chunk"], "ranked")
        for hit in context["retrieval"]["hits"]
    ]
    traversal = context["traversal"]
    if traversal is not None:
        result.extend(
            _record(kind, item, "traversal")
            for kind, collection in (("node", "nodes"), ("edge", "edges"))
            for item in traversal[collection]
        )
    # Legacy components already reject duplicate source IDs. This also ensures
    # an unusually repeated representation does not consume final evidence twice.
    seen: set[tuple[str, str]] = set()
    unique = []
    for record in result:
        key = record["kind"], record["item_id"]
        if key not in seen:
            seen.add(key)
            unique.append(record)
    return unique


def _attrs(kind: str, item: Mapping[str, Any]) -> Mapping[str, Any]:
    return item["metadata" if kind == "chunk" else "attributes"]


def _text(kind: str, item: Mapping[str, Any]) -> str:
    return " ".join(
        str(item.get(field, ""))
        for field in (("title", "content") if kind == "chunk" else ("label",))
    )


def _item_type(kind: str, item: Mapping[str, Any]) -> str:
    return item.get("chunk_type" if kind == "chunk" else "node_type", "")


def _entity_names(
    corpus: Mapping[str, Any], graph: Mapping[str, Any],
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for kind, collection in (("chunk", corpus["chunks"]), ("node", graph["nodes"])):
        for item in collection:
            if _item_type(kind, item) != "entity":
                continue
            identifier = item["source"]["object_id"]
            attrs = _attrs(kind, item)
            nested = attrs.get("attributes", {})
            names = result.setdefault(identifier, set())
            names.add(_process_name(item.get("title", item.get("label", ""))))
            if isinstance(nested, Mapping):
                names.update(_process_name(nested.get(field)) for field in ("process_name", "name", "image"))
    return result


def _selector_ids(value: object, names: Mapping[str, set[str]]) -> set[str] | None:
    if value is None:
        return None
    name = _process_name(value)
    return {identifier for identifier, aliases in names.items() if name in aliases}


def _matches_entities(
    item: Mapping[str, Any], requested: set[str] | None,
) -> bool:
    if requested is None:
        return True
    source = item["source"]
    attrs = item.get("metadata", item.get("attributes", {}))
    identities = set(item.get("entity_ids", []))
    identities.update(
        attrs[key] for key in ("subject", "object", "source_entity_id", "target_entity_id")
        if isinstance(attrs.get(key), str)
    )
    return bool(requested.intersection(identities)) or source.get("object_id") in requested


def _limitation_facets(text: str) -> set[str]:
    """Public concepts, independent of limitation indexes or experiment cases."""
    value = _normal(text)
    concepts = {
        "scope": ("scope", "reviewed", "pham vi", "da xem xet"),
        "timestamp": ("timestamp", "utctime", "timecreated", "timezone", "thoi gian", "mui gio"),
        "completion": ("completion", "cmdlet", "service state", "output", "hoan tat", "dich vu", "dau ra"),
        "negative_scan": ("negative scan", "absence", "absent", "am tinh", "vang mat"),
        "candidate_status": ("candidate", "human review", "ung vien", "can duyet"),
        "core_boundaries": ("outside", "core", "clearing", "deletion", "ngoai", "xoa"),
    }
    return {facet for facet, words in concepts.items() if any(word in value for word in words)}


def _structured_network_match(
    kind: str, item: Mapping[str, Any], parameters: Mapping[str, Any],
    requested: set[str] | None,
) -> bool:
    """Select only explicit network data; incidental reference URLs do not count."""
    if not _matches_entities(item, requested):
        return False
    attrs = _attrs(kind, item)
    nested = attrs.get("attributes", {})
    documents = [attrs]
    if isinstance(nested, Mapping):
        documents.append(nested)
        for observation in nested.get("source_observations", []):
            if isinstance(observation, Mapping) and isinstance(observation.get("original_fields"), Mapping):
                documents.append(observation["original_fields"])
    network_fields = {
        "url", "uri", "destination_url", "download_url", "destination_ip",
        "destination_port", "destinationip", "destinationport", "hostname",
    }
    # Hostname alone identifies a source host, not an outbound connection.
    network_fields.remove("hostname")
    return any(
        str(key).casefold() in network_fields and isinstance(value, (str, int))
        for document in documents for key, value in document.items()
    )


def _candidate_reason(
    kind: str, item: Mapping[str, Any], requirement: Mapping[str, Any],
    names: Mapping[str, set[str]],
) -> str | None:
    info = requirement["kind"]
    params = requirement["parameters"]
    item_type = _item_type(kind, item)
    if kind == "edge":
        return None  # Existing graph edges remain in the baseline; never create paths.
    if info == "review_limitations":
        facets = set(params.get("facets", ["all"]))
        if item_type == "limitation" and (
            "all" in facets or facets.intersection(_limitation_facets(_text(kind, item)))
        ):
            return "requested_limitation_facet"
        if item_type == "scenario_summary" and facets.intersection({"all", "scope"}):
            return "requested_review_scope_metadata"
        return None
    if info == "technique_assessment":
        technique_id = params.get("technique_id")
        attrs = _attrs(kind, item)
        matches = technique_id is None or technique_id in item.get("mitre_external_ids", []) or attrs.get("external_id") == technique_id
        if item_type == "mitre_assessment" and matches:
            return "requested_technique_assessment"
        if item_type == "limitation" and "candidate_status" in _limitation_facets(_text(kind, item)):
            return "assessment_certainty_limitation"
        return None
    if info == "process_relationship":
        parents = _selector_ids(params.get("parent"), names)
        children = _selector_ids(params.get("child"), names)
        selectors = [value for value in (parents, children) if value is not None]
        requested = set.union(*selectors) if selectors else None
        if item_type in {"fact", "relationship", "evidence", "entity"} and _matches_entities(item, requested):
            return "requested_process_relationship_evidence"
        return None
    if info in {"launch_command", "command_completion", "service_state", "evidence_provenance"}:
        requested = _selector_ids(params.get("process"), names)
        if item_type in {"fact", "evidence", "entity"} and _matches_entities(item, requested):
            return "requested_process_observation_or_identity"
        if info in {"command_completion", "service_state"} and item_type == "limitation" and "completion" in _limitation_facets(_text(kind, item)):
            return "requested_completion_scope_limitation"
        return None
    if info == "network_url" and item_type in {"fact", "evidence", "entity"}:
        requested = _selector_ids(params.get("actor"), names)
        if _structured_network_match(kind, item, params, requested):
            return "requested_structured_network_observation"
    return None


def _budget(value: Mapping[str, object] | None) -> dict[str, int]:
    if value is None:
        return dict(DEFAULT_CONTEXT_BUDGET)
    if not isinstance(value, Mapping) or set(value) - set(DEFAULT_CONTEXT_BUDGET):
        raise QueryContextError("budget contains unsupported fields")
    result = dict(DEFAULT_CONTEXT_BUDGET)
    for key, number in value.items():
        if type(number) is not int or number < 0:
            raise QueryContextError(f"budget.{key} must be a nonnegative integer")
        result[key] = number
    return result


def _validate_bindings(
    context: Mapping[str, Any], corpus: Mapping[str, Any], graph: Mapping[str, Any],
) -> None:
    extract_graphrag_gate_signals(context)
    validate_retrieval_corpus(corpus)
    validate_knowledge_graph(graph)
    for field in ("scenario_id", "source_ground_truth"):
        if context[field] != corpus[field] or corpus[field] != graph[field]:
            raise QueryContextError(f"{field} differs across source/context bindings")
    if context["corpus_id"] != corpus["corpus_id"] or context["graph_id"] != graph["graph_id"]:
        raise QueryContextError("corpus/graph IDs differ from initial context")
    sources = {
        "chunk": {item["chunk_id"]: item for item in corpus["chunks"]},
        "node": {item["node_id"]: item for item in graph["nodes"]},
        "edge": {item["edge_id"]: item for item in graph["edges"]},
    }
    for record in _initial_records(context):
        original = sources[record["kind"]].get(record["item_id"])
        if original is None or _bytes(original) != _bytes(record["payload"]):
            raise QueryContextError("initial returned item differs from its runtime source")


def validate_query_evidence_context(context: Mapping[str, Any]) -> None:
    """Validate a detached evidence envelope, without reopening source files.

    Source authentication occurs when enrichment is built with corpus and graph.
    This validator checks preserved initial objects, item identities, provenance
    echoes, budget accounting and explicit cuts; it cannot authenticate later
    caller-provided supplementary payloads against unavailable source files.
    """
    try:
        fields = {
            "schema_version", "initial_context", "supplementary_items", "final_items",
            "source_inventory", "budget", "selection", "incomplete_context", "enrichment_enabled",
        }
        if not isinstance(context, Mapping) or set(context) != fields:
            raise QueryContextError("evidence context fields do not match the contract")
        _bytes(context)
        if context["schema_version"] != QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION:
            raise QueryContextError("evidence context schema_version is unsupported")
        extract_graphrag_gate_signals(context["initial_context"])
        baseline = _initial_records(context["initial_context"])
        items, supplements = context["final_items"], context["supplementary_items"]
        if not isinstance(items, list) or not isinstance(supplements, list):
            raise QueryContextError("final and supplementary items must be lists")
        if items[:len(baseline)] != baseline or items[len(baseline):] != supplements:
            raise QueryContextError("final items must preserve baseline then exact supplementary items")
        seen = set()
        represented_sources = {
            _source_key(record["payload"]) for record in baseline if record["kind"] != "edge"
        }
        record_fields = {"kind", "item_id", "payload", "origin", "requirement_ids", "reason_codes"}
        payload_fields = {"chunk": set(CHUNK_FIELDS), "node": set(NODE_FIELDS), "edge": set(EDGE_FIELDS)}
        for index, record in enumerate(items):
            if not isinstance(record, Mapping) or set(record) != record_fields or record["kind"] not in payload_fields:
                raise QueryContextError("evidence item fields or kind are unsupported")
            kind, item = record["kind"], record["payload"]
            if not isinstance(item, Mapping) or set(item) != payload_fields[kind] or item[f"{kind}_id"] != record["item_id"]:
                raise QueryContextError("evidence payload fields or item identity differ")
            if item["status"] not in CHUNK_STATUSES:
                raise QueryContextError("evidence status is unsupported")
            _scan_contract_guards(item["metadata" if kind == "chunk" else "attributes"], "evidence payload")
            identity = kind, record["item_id"]
            if identity in seen:
                raise QueryContextError("duplicate evidence item identity")
            seen.add(identity)
            if index >= len(baseline) and (record["origin"] != "supplementary" or kind == "edge"):
                raise QueryContextError("supplement must be an unranked source chunk/node")
            if index >= len(baseline):
                source = _source_key(item)
                if source in represented_sources:
                    raise QueryContextError("supplement duplicates an already represented source object")
                represented_sources.add(source)
            _strings(record["requirement_ids"], "requirement_ids")
            _strings(record["reason_codes"], "reason_codes")
        inventory = context["source_inventory"]
        if not isinstance(inventory, Mapping) or set(inventory) != {"source_ground_truth", "corpus_id", "graph_id", "limitation_count"}:
            raise QueryContextError("source_inventory fields are unsupported")
        for name in ("source_ground_truth", "corpus_id", "graph_id"):
            if inventory[name] != context["initial_context"][name]:
                raise QueryContextError("source inventory differs from initial context provenance")
        if type(inventory["limitation_count"]) is not int or inventory["limitation_count"] < 0:
            raise QueryContextError("limitation_count must be a nonnegative integer")
        limits = context["budget"]
        budget_fields = set(DEFAULT_CONTEXT_BUDGET) | {"final_item_count", "final_serialized_bytes", "baseline_exceeds_budget", "measurement"}
        if not isinstance(limits, Mapping) or set(limits) != budget_fields:
            raise QueryContextError("budget fields are unsupported")
        _budget({key: limits[key] for key in DEFAULT_CONTEXT_BUDGET})
        oversized = len(baseline) > limits["max_final_items"] or len(_bytes(baseline)) > limits["max_serialized_bytes"]
        if (type(limits["baseline_exceeds_budget"]) is not bool or limits["baseline_exceeds_budget"] != oversized
                or type(limits["final_item_count"]) is not int or limits["final_item_count"] != len(items)
                or type(limits["final_serialized_bytes"]) is not int or limits["final_serialized_bytes"] != len(_bytes(items))
                or limits["measurement"] != "canonical_serialized_final_items_utf8_bytes_not_tokens"):
            raise QueryContextError("budget accounting differs from actual evidence context")
        if len(supplements) > limits["max_supplementary_items"] or (oversized and supplements):
            raise QueryContextError("supplements exceed budget or oversized baseline")
        if not oversized and (len(items) > limits["max_final_items"] or len(_bytes(items)) > limits["max_serialized_bytes"]):
            raise QueryContextError("final context exceeds configured budget")
        selection = context["selection"]
        if not isinstance(selection, Mapping) or set(selection) != {"candidate_count", "already_present_item_ids", "cut_items"}:
            raise QueryContextError("selection fields are unsupported")
        if type(selection["candidate_count"]) is not int or selection["candidate_count"] < 0:
            raise QueryContextError("candidate_count must be a nonnegative integer")
        _strings(selection["already_present_item_ids"], "already_present_item_ids")
        if not isinstance(selection["cut_items"], list):
            raise QueryContextError("cut_items must be a list")
        for cut in selection["cut_items"]:
            if not isinstance(cut, Mapping) or set(cut) != {"kind", "item_id", "requirement_ids", "reason_codes"} or cut["kind"] not in {"chunk", "node"}:
                raise QueryContextError("cut item fields are unsupported")
            _strings(cut["requirement_ids"], "cut.requirement_ids")
            _strings(cut["reason_codes"], "cut.reason_codes")
            if not cut["reason_codes"]:
                raise QueryContextError("cut item must retain a reason")
        if type(context["enrichment_enabled"]) is not bool or (not context["enrichment_enabled"] and supplements):
            raise QueryContextError("disabled enrichment cannot add items")
        if type(context["incomplete_context"]) is not bool or context["incomplete_context"] != bool(oversized or selection["cut_items"]):
            raise QueryContextError("incomplete_context differs from cuts/baseline budget")
    except QueryContextError:
        raise
    except Exception as exc:
        raise QueryContextError(f"Invalid query evidence context: {exc}") from exc


def enrich_query_context(
    initial_context: Mapping[str, Any], corpus: Mapping[str, Any],
    graph: Mapping[str, Any], requirements: Mapping[str, Any], *,
    budget: Mapping[str, object] | None = None, enabled: bool = True,
) -> dict[str, Any]:
    """Return immutable ranked context plus bounded, deterministic evidence items.

    Existing ranked/traversed representations remain untouched. Supplements are
    deduplicated by exact identity and source object already represented in the
    baseline. Whole items are admitted or cut; an oversized baseline is retained
    with explicit incomplete metadata. ``enabled=False`` retains the same public
    source inventory without adding evidence (the gate-only ablation).
    """
    try:
        if type(enabled) is not bool:
            raise QueryContextError("enabled must be boolean")
        limits = _budget(budget)
        validate_query_requirements_document(requirements)
        if requirements["query"] != initial_context["query"]["text"]:
            raise QueryContextError("requirements query differs from initial context")
        _validate_bindings(initial_context, corpus, graph)
        initial = deepcopy(initial_context)
        final_items = _initial_records(initial)
        names = _entity_names(corpus, graph)
        represented = {_source_key(record["payload"]) for record in final_items if record["kind"] != "edge"}
        identities = {(record["kind"], record["item_id"]) for record in final_items}
        inventory = {
            "source_ground_truth": deepcopy(corpus["source_ground_truth"]),
            "corpus_id": corpus["corpus_id"], "graph_id": graph["graph_id"],
            "limitation_count": len({
                _source_key(item) for item in corpus["chunks"] if item["chunk_type"] == "limitation"
            } | {
                _source_key(item) for item in graph["nodes"] if item["node_type"] == "limitation"
            }),
        }
        candidates: list[dict[str, Any]] = []
        # Corpus chunks are the preferred representation; graph nodes provide a
        # fallback for source objects not represented in the corpus.
        for kind, collection in (("chunk", corpus["chunks"]), ("node", graph["nodes"])):
            for item in sorted(collection, key=lambda value: (value["source"]["json_pointer"], value[f"{kind}_id"])):
                matches = [
                    (requirement["requirement_id"], reason)
                    for requirement in requirements["requirements"]
                    if requirement["analysis_status"] == "supported"
                    and (reason := _candidate_reason(kind, item, requirement, names)) is not None
                ]
                if matches:
                    candidate = _record(kind, item, "supplementary")
                    candidate["requirement_ids"] = sorted({identifier for identifier, _ in matches})
                    candidate["reason_codes"] = sorted({reason for _, reason in matches})
                    candidates.append(candidate)
        baseline_bytes = len(_bytes(final_items))
        oversized = len(final_items) > limits["max_final_items"] or baseline_bytes > limits["max_serialized_bytes"]
        supplementary: list[dict[str, Any]] = []
        present: list[str] = []
        cuts: list[dict[str, Any]] = []
        for candidate in candidates:
            identity = candidate["kind"], candidate["item_id"]
            source = _source_key(candidate["payload"])
            if identity in identities or source in represented:
                present.append(candidate["item_id"])
                continue
            reasons = []
            if not enabled:
                reasons.append("enrichment_disabled")
            if oversized:
                reasons.append("baseline_exceeds_budget")
            if len(supplementary) >= limits["max_supplementary_items"]:
                reasons.append("supplementary_item_budget_exhausted")
            if len(final_items) + 1 > limits["max_final_items"]:
                reasons.append("final_item_budget_exhausted")
            if len(_bytes([*final_items, candidate])) > limits["max_serialized_bytes"]:
                reasons.append("serialized_utf8_byte_budget_exhausted")
            if reasons:
                cuts.append({
                    "kind": candidate["kind"], "item_id": candidate["item_id"],
                    "requirement_ids": candidate["requirement_ids"], "reason_codes": reasons,
                })
                continue
            supplementary.append(candidate)
            final_items.append(candidate)
            identities.add(identity)
            represented.add(source)
        result = {
            "schema_version": QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION,
            "initial_context": initial,
            "supplementary_items": supplementary, "final_items": final_items,
            "source_inventory": inventory,
            "budget": {
                **limits, "final_item_count": len(final_items),
                "final_serialized_bytes": len(_bytes(final_items)),
                "baseline_exceeds_budget": oversized,
                "measurement": "canonical_serialized_final_items_utf8_bytes_not_tokens",
            },
            "selection": {
                "candidate_count": len(candidates),
                "already_present_item_ids": sorted(set(present)), "cut_items": cuts,
            },
            "incomplete_context": bool(oversized or cuts),
            "enrichment_enabled": enabled,
        }
        # JSON round trip detaches shared nested records from both caller and
        # other result collections. Scores remain solely in initial_context.
        detached = json.loads(_bytes(result))
        validate_query_evidence_context(detached)
        return detached
    except QueryContextError:
        raise
    except Exception as exc:
        raise QueryContextError(f"Cannot enrich query context: {exc}") from exc


__all__ = (
    "QUERY_EVIDENCE_CONTEXT_SCHEMA_VERSION", "DEFAULT_CONTEXT_BUDGET",
    "QueryContextError", "enrich_query_context", "validate_query_evidence_context",
)
