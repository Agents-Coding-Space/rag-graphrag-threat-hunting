"""Experimental source-bound eligibility beside unchanged legacy/FIX2 APIs.

Runtime source documents authenticate returned objects and source inventories.
They never supply positive evidence absent from ``final_items``. Ranked scores
remain diagnostics, not probabilities; supplementation never receives a score.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
import json
import math
from typing import Any

from ..graph.schema import validate_knowledge_graph
from ..retrieval.schema import validate_retrieval_corpus
from .gate_signals import extract_graphrag_gate_signals
from .query_context import validate_query_evidence_context
from .query_support import assess_evidence_support
from .two_stage_gate import assess_graphrag_two_stage_gate


COMBINED_POLICY_SCHEMA_VERSION = "query-evidence-eligibility-policy/v1"
COMBINED_DECISION_SCHEMA_VERSION = "query-evidence-eligibility-decision/v1"
_MODES = {
    "parser_mode": "supported_with_mandatory_requirements",
    "source_mode": "exact_runtime_source_payloads",
    "scope_mode": "block_mismatch_or_ambiguous_allow_authenticated_bound_unspecified",
    "mandatory_support_mode": "all_supported_with_resolved_nonempty_traces",
    "evidence_mode": "kind_specific_identity_or_source_metadata",
    "completeness_mode": "block_required_identity_set_gap_or_relevant_cuts",
    "contradiction_mode": "block_conflicting_bound_values",
    "legacy_mode": "diagnostic_only",
    "ranking_mode": "diagnostic_only_no_supplement_scores",
}
_QUALITY_FIELDS = {
    "min_ranked_hits", "require_finite_ranked_scores",
    "require_exact_source_bound_ranked_payloads",
}


class CombinedQueryGateError(ValueError):
    """A policy or source-bound runtime input is invalid."""


def _copy(value: object) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise CombinedQueryGateError(f"Expected finite JSON: {exc}") from exc


def _encoded(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def validate_combined_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a complete explicit policy, without filling any default field."""
    value = _copy(policy)
    fields = set(_MODES) | {"schema_version", "policy_id", "retrieval_quality", "max_chain_depth"}
    if not isinstance(value, dict) or set(value) != fields:
        raise CombinedQueryGateError("Combined policy requires exactly all configured fields")
    if value["schema_version"] != COMBINED_POLICY_SCHEMA_VERSION:
        raise CombinedQueryGateError("Unsupported combined policy schema_version")
    if not isinstance(value["policy_id"], str) or not value["policy_id"].strip():
        raise CombinedQueryGateError("Combined policy_id must be nonempty")
    for field, expected in _MODES.items():
        if value[field] != expected:
            raise CombinedQueryGateError(f"Unsupported combined policy {field}")
    quality = value["retrieval_quality"]
    if not isinstance(quality, dict) or set(quality) != _QUALITY_FIELDS:
        raise CombinedQueryGateError("retrieval_quality requires all configured fields")
    if type(quality["min_ranked_hits"]) is not int or quality["min_ranked_hits"] < 1:
        raise CombinedQueryGateError("min_ranked_hits must be a positive integer")
    for field in _QUALITY_FIELDS - {"min_ranked_hits"}:
        if quality[field] is not True:
            raise CombinedQueryGateError(f"retrieval_quality.{field} must be true")
    if type(value["max_chain_depth"]) is not int or not 1 <= value["max_chain_depth"] <= 64:
        raise CombinedQueryGateError("max_chain_depth must be an integer from 1 through 64")
    return value


def _authenticate(context: dict[str, Any], corpus: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    from .query_context_v2 import upgrade_evidence_context, validate_query_evidence_context_v2

    validate_retrieval_corpus(corpus)
    validate_knowledge_graph(graph)
    version = context.get("schema_version")
    if version == "query-evidence-context/v1":
        validate_query_evidence_context(context)
        upgraded = upgrade_evidence_context(context, corpus, graph)
    elif version == "query-evidence-context/v2":
        validate_query_evidence_context_v2(context)
        upgraded = context
    else:
        raise CombinedQueryGateError("Unsupported query evidence context schema_version")
    initial = context["initial_context"]
    for field in ("scenario_id", "source_ground_truth"):
        if initial[field] != corpus[field] or corpus[field] != graph[field]:
            raise CombinedQueryGateError(f"{field} source provenance differs")
    if initial["corpus_id"] != corpus["corpus_id"] or initial["graph_id"] != graph["graph_id"]:
        raise CombinedQueryGateError("Runtime corpus/graph identities differ from context")
    sources = {
        kind: {item[f"{kind}_id"]: item for item in collection}
        for kind, collection in (("chunk", corpus["chunks"]), ("node", graph["nodes"]), ("edge", graph["edges"]))
    }
    for record in context["final_items"]:
        original = sources[record["kind"]].get(record["item_id"])
        if original is None or _encoded(original) != _encoded(record["payload"]):
            raise CombinedQueryGateError("Final evidence payload differs from authenticated runtime source")
    # Even caller-provided v2 inventories must be exactly derivable from these
    # sources; positive support below still reads returned final_items only.
    if version == "query-evidence-context/v2":
        rebuilt = upgrade_evidence_context(context, corpus, graph)
        if upgraded["source_inventory"] != rebuilt["source_inventory"]:
            raise CombinedQueryGateError("Context inventory differs from runtime source inventory")
    return upgraded


def _value(root: object, pointer: str) -> object:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise CombinedQueryGateError("Support trace pointer is not an absolute JSON pointer")
    value = root
    for escaped in pointer.split("/")[1:]:
        part = escaped.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            value = value[int(part)]
        elif isinstance(value, dict):
            value = value[part]
        else:
            raise CombinedQueryGateError("Support trace points outside an evidence field")
    return value


def _trace_records(result: Mapping[str, Any], context: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    traces = result.get("traces")
    if not isinstance(traces, list) or not traces:
        return [], "mandatory_support_trace_empty"
    items = {(item["kind"], item["item_id"]): (index, item) for index, item in enumerate(context["final_items"])}
    records = []
    for trace in traces:
        if not isinstance(trace, dict):
            return [], "mandatory_support_trace_invalid"
        selected = items.get((trace.get("kind"), trace.get("item_id")))
        if selected is None:
            return [], "mandatory_support_trace_not_returned"
        index, item = selected
        field = trace.get("field")
        if not isinstance(field, str) or not field.startswith("/"):
            return [], "mandatory_support_trace_invalid"
        pointer = f"/final_items/{index}/payload" + field
        if trace.get("context_pointer") != pointer:
            return [], "mandatory_support_trace_pointer_mismatch"
        try:
            value = _value(context, pointer)
        except (KeyError, IndexError, ValueError, TypeError, CombinedQueryGateError):
            return [], "mandatory_support_trace_field_missing"
        quote = value if isinstance(value, str) else _encoded(value)
        source = item["payload"].get("source", {})
        if trace.get("quote") != quote or trace.get("source_pointer") != source.get("json_pointer"):
            return [], "mandatory_support_trace_quote_mismatch"
        records.append(item)
    return records, None


def _has_refs(record: Mapping[str, Any]) -> bool:
    return any(isinstance(ref, dict) and isinstance(ref.get("source_file"), str) and ref["source_file"]
               and isinstance(ref.get("raw_record_ref"), str) and ref["raw_record_ref"]
               for ref in record["payload"].get("source_references", []))


def _anchored(requirement: Mapping[str, Any], result: Mapping[str, Any], records: list[dict[str, Any]]) -> bool:
    """Require proof anchors appropriate to what was asked, not topic presence."""
    kind = requirement["kind"]
    traces = result.get("traces", [])
    bindings = [trace["binding"] for trace in traces if isinstance(trace.get("binding"), dict)]
    if kind == "process_relationship":
        return any(binding.get("action") == "process_spawn" and all(
            isinstance(binding.get(field), str) and binding[field]
            for field in ("subject", "object", "subject_identity", "object_identity")
        ) and binding["subject_identity"] != binding["object_identity"] for binding in bindings) and any(_has_refs(item) for item in records)
    if kind in {"launch_command", "network_url", "command_completion", "service_state"}:
        return any(all(isinstance(binding.get(field), str) and binding[field]
                       for field in ("subject", "subject_identity", "action"))
                   and binding.get("object") is not None for binding in bindings) and any(_has_refs(item) for item in records)
    types = {item["payload"].get("source", {}).get("object_type") for item in records}
    if kind == "review_limitations":
        return bool(types) and types <= {"limitation", "scenario"} and all(
            isinstance(item["payload"].get("source", {}).get("json_pointer"), str)
            for item in records)
    if kind == "technique_assessment":
        return "mitre_assessment" in types and any(
            "external_id" in trace.get("field", "") or "mitre_external_ids" in trace.get("field", "")
            for trace in traces)
    if kind == "evidence_provenance":
        # Some traces quote an entire associated observation, others quote its
        # fields. Both are allowed only with authenticated source references.
        text = " ".join(trace.get("field", "") + " " + str(trace.get("quote", "")) for trace in traces)
        return any(_has_refs(item) for item in records) and all(
            any(term in text for term in alternatives)
            for alternatives in (("raw_record_ref",), ("source_file",), ("EventID", "event_id"), ("TimeCreated", "timestamp")))
    return False


def _finite_scores(value: object) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, dict):
        return all(_finite_scores(part) for part in value.values())
    if isinstance(value, list):
        return all(_finite_scores(part) for part in value)
    return True


def assess_combined_query_gate(
    context: Mapping[str, Any], requirements: Mapping[str, Any], *,
    corpus: Mapping[str, Any], graph: Mapping[str, Any], policy: Mapping[str, Any],
    legacy_policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Assess explicit evidence eligibility; reject malformed/authentication input.

    Well-formed inputs with absent/partial/unknown evidence return abstain and
    every blocker. Invalid versions, changed source objects or invalid policies
    raise ``CombinedQueryGateError`` before issuing an eligibility decision.
    """
    try:
        from .query_requirements import validate_query_requirements_document
        from .query_requirements_v2 import validate_query_requirements_document_v2
        from .query_support_v2 import assess_evidence_support_v2

        configured = validate_combined_policy(policy)
        original, requested, source_corpus, source_graph = map(_copy, (context, requirements, corpus, graph))
        upgraded = _authenticate(original, source_corpus, source_graph)
        version = requested.get("schema_version")
        if version == "query-requirements/v1":
            validate_query_requirements_document(requested)
            # FIX2 support output and meaning remain intact for E2/replay.
            old_context = deepcopy(original)
            if old_context["schema_version"] != "query-evidence-context/v1":
                old_context["schema_version"] = "query-evidence-context/v1"
                old_context["source_inventory"] = {
                    field: deepcopy(old_context["source_inventory"][field])
                    for field in ("source_ground_truth", "corpus_id", "graph_id", "limitation_count")
                }
            support = assess_evidence_support(requested, old_context)
        elif version == "query-requirements/v2":
            validate_query_requirements_document_v2(requested)
            support = assess_evidence_support_v2(requested, upgraded, max_chain_depth=configured["max_chain_depth"])
        else:
            raise CombinedQueryGateError("Unsupported query requirements schema_version")
        initial = original["initial_context"]
        if requested["query"] != initial["query"]["text"]:
            raise CombinedQueryGateError("Requirements query differs from ranked context query")
        guards = assess_evidence_support_v2(requested, upgraded, max_chain_depth=configured["max_chain_depth"])
        signals = extract_graphrag_gate_signals(initial)
        legacy = assess_graphrag_two_stage_gate(signals, policy=legacy_policy)
        blockers: list[dict[str, Any]] = []

        def block(stage: str, reason: str, requirement_id: str | None = None) -> None:
            entry = {"stage": stage, "reason_code": reason}
            if requirement_id is not None:
                entry["requirement_id"] = requirement_id
            if entry not in blockers:
                blockers.append(entry)

        scope = requested["scope"]
        if scope["status"] == "mismatch":
            block("scope", "requested_scope_mismatch")
        elif scope["status"] == "ambiguous":
            block("scope", "query_scope_ambiguous")
        mandatory = [item for item in requested["requirements"] if item["mandatory"]]
        if requested["analysis_status"] != "supported":
            block("query_requirements", "query_requirements_" + requested["analysis_status"])
        if not mandatory:
            block("query_requirements", "mandatory_requirements_empty")
        ranked = initial["retrieval"]["hits"]
        if len(ranked) < configured["retrieval_quality"]["min_ranked_hits"]:
            block("retrieval_quality", "source_bound_ranked_hit_count_below_minimum")
        if not _finite_scores(ranked):
            block("retrieval_quality", "ranked_scores_nonfinite")
        if not original["final_items"]:
            block("evidence_answerability", "actual_evidence_context_empty")
        supported = {item["requirement_id"]: item for item in support["requirements"]}
        guarded = {item["requirement_id"]: item for item in guards["requirements"]}
        anchor_diagnostics = []
        for requirement in mandatory:
            rid = requirement["requirement_id"]
            result = supported.get(rid, {})
            guard = guarded.get(rid, {})
            if result.get("status") != "supported":
                block("evidence_answerability", "required_evidence_" + str(result.get("status", "unknown")), rid)
            if guard.get("status") != "supported":
                block("evidence_answerability", "independent_evidence_guard_" + str(guard.get("status", "unknown")), rid)
            records, trace_error = _trace_records(result, original)
            if trace_error:
                block("evidence_answerability", trace_error, rid)
            anchor = not trace_error and _anchored(requirement, result, records)
            anchor_diagnostics.append({"requirement_id": rid, "anchored": anchor,
                                       "scope_unspecified": scope["status"] == "unspecified"})
            if not anchor:
                block("evidence_answerability", "required_evidence_identity_or_source_anchor_missing", rid)
            completeness = guard.get("completeness", {}).get("status", "unknown")
            if completeness not in {"complete", "not_applicable"}:
                block("evidence_completeness", "required_completeness_" + completeness, rid)
            contradiction = guard.get("contradiction", {}).get("status", "unknown")
            if contradiction != "none_detected":
                block("evidence_consistency", "bound_evidence_contradiction_" + contradiction, rid)
        mandatory_ids = {item["requirement_id"] for item in mandatory}
        relevant_cuts = [cut for cut in original["selection"]["cut_items"]
                         if mandatory_ids.intersection(cut["requirement_ids"])]
        # A cut is a blocker only when the required support/completeness remains
        # unestablished; harmless duplicate/extra candidate cuts stay diagnostic.
        incomplete_ids = {item["requirement_id"] for item in guards["requirements"]
                          if item.get("status") != "supported"
                          or item.get("completeness", {}).get("status") not in {"complete", "not_applicable"}}
        if any(incomplete_ids.intersection(cut["requirement_ids"]) for cut in relevant_cuts):
            block("evidence_completeness", "relevant_required_evidence_cut")
        diagnostics = {
            "ranked_retrieval": signals,
            "final_evidence_context": {
                "final_item_count": len(original["final_items"]),
                "supplementary_item_count": len(original["supplementary_items"]),
                "item_kind_counts": dict(sorted(Counter(item["kind"] for item in original["final_items"]).items())),
                "incomplete_context": original["incomplete_context"],
                "relevant_cut_count": len(relevant_cuts),
                "ranking_scores_are_probabilities": False,
                "supplementary_scores_invented": False,
            },
        }
        return _copy({
            "schema_version": COMBINED_DECISION_SCHEMA_VERSION, "configuration": configured,
            "legacy_decision": legacy, "query_requirements": requested,
            "scope_assessment": scope, "support_assessment": support,
            "verification_guards": guards, "signals": diagnostics,
            "authentication": {"mode": configured["source_mode"], "all_final_payloads_authenticated": True,
                               "hidden_source_content_used_as_positive_evidence": False},
            "evidence_anchors": anchor_diagnostics,
            "final_decision": "abstain" if blockers else "proceed",
            "abstention_stage": blockers[0]["stage"] if blockers else None,
            "reason_codes": list(dict.fromkeys(item["reason_code"] for item in blockers)),
            "blockers": blockers, "security_conclusion_made": False,
        })
    except CombinedQueryGateError:
        raise
    except Exception as exc:
        raise CombinedQueryGateError(f"Invalid combined query gate input: {exc}") from exc


__all__ = ("COMBINED_POLICY_SCHEMA_VERSION", "COMBINED_DECISION_SCHEMA_VERSION",
           "CombinedQueryGateError", "validate_combined_policy", "assess_combined_query_gate")
