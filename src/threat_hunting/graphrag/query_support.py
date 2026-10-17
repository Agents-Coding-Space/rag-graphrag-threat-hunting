"""Check bounded query requirements against returned evidence, without IO.

The verifier reads only ``final_items``. It never consults retrieval similarity,
the full corpus, Ground Truth, annotations, or reference answers. Missing means
missing from this context; it is not a real-world absence determination. The
small structured vocabulary below is deliberately narrower than natural language.
"""

from __future__ import annotations

from collections.abc import Mapping
import copy
import ipaddress
import json
import re
from typing import Any
import unicodedata

from .query_requirements import validate_query_requirements_document


QUERY_EVIDENCE_SUPPORT_SCHEMA_VERSION = "query-evidence-support/v1"
_KINDS = {
    "process_relationship", "launch_command", "command_completion", "service_state",
    "network_url", "evidence_provenance", "review_limitations", "technique_assessment",
}
_RELATIONSHIP_TEXT = re.compile(
    r"\ASource:\s*(.*?)\s*\(([^()]+)\)\.\s*Type:\s*process_spawn\.\s*"
    r"Target:\s*(.*?)\s*\(([^()]+)\)\.\s*Status:\s*observed\.\s*\Z",
    re.DOTALL,
)
_FACETS = {
    "scope": ("scope", "reviewed", "core", "pham vi"),
    "timestamp": ("timestamp", "utctime", "timecreated", "timezone", "thoi gian"),
    "completion": ("completion", "output", "service state", "hoan tat", "trang thai dich vu"),
    "negative_scan": ("negative scan", "absence claim", "globally absent", "vang mat"),
    "candidate_status": ("candidate", "human review", "ung vien"),
    "core_boundaries": ("outside", "conhost", "deletion", "event-log", "ngoai"),
}
_NETWORK_PREDICATES = {
    "download": {"downloaded_from", "downloaded_payload_from"},
    "connect": {"connected_to", "network_connection"},
    "network": {"connected_to", "network_connection", "downloaded_from", "downloaded_payload_from"},
}


class QueryEvidenceSupportError(ValueError):
    """The finite in-memory evidence support input is malformed."""


def _normal(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold()).replace("đ", "d")
    return " ".join("".join(c for c in decomposed if not unicodedata.combining(c)).split())


def _name(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return _normal(value.strip().strip('"').replace("\\", "/").rsplit("/", 1)[-1])


def _matches(actual: object, requested: object) -> bool:
    return requested is None or bool(_name(actual)) and _name(actual) == _name(requested)


def _map(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"))


def _detach(value: object) -> dict[str, Any]:
    try:
        result = json.loads(_json(value))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise QueryEvidenceSupportError(f"input must be finite JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise QueryEvidenceSupportError("input must be a JSON object")
    return result


def _records(context: Mapping[str, Any]) -> list[dict[str, Any]]:
    items = context.get("final_items")
    if not isinstance(items, list):
        raise QueryEvidenceSupportError("final_context.final_items must be a list")
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, wrapper in enumerate(items):
        item = _map(wrapper)
        kind, item_id, payload = item.get("kind"), item.get("item_id"), item.get("payload")
        if kind not in {"chunk", "node", "edge"} or not isinstance(item_id, str) or not item_id:
            raise QueryEvidenceSupportError(f"final_items[{index}] requires a kind and item_id")
        if not isinstance(payload, Mapping) or payload.get(f"{kind}_id") != item_id:
            raise QueryEvidenceSupportError(f"final_items[{index}] item_id disagrees with payload")
        if (kind, item_id) in seen:
            raise QueryEvidenceSupportError(f"duplicate final item {(kind, item_id)!r}")
        seen.add((kind, item_id))
        result.append({"kind": kind, "item_id": item_id, "payload": payload,
                       "pointer": f"/final_items/{index}/payload"})
    return result


def _type(record: Mapping[str, Any]) -> object:
    return record["payload"].get(f"{record['kind']}_type")


def _attrs(record: Mapping[str, Any]) -> Mapping[str, Any]:
    return _map(record["payload"].get("metadata" if record["kind"] == "chunk" else "attributes"))


def _attr_path(record: Mapping[str, Any]) -> str:
    return "/metadata" if record["kind"] == "chunk" else "/attributes"


def _refs(record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [ref for ref in _list(record["payload"].get("source_references"))
            if isinstance(ref, Mapping) and isinstance(ref.get("source_file"), str)
            and bool(ref["source_file"]) and isinstance(ref.get("raw_record_ref"), str)
            and bool(ref["raw_record_ref"])]


def _trace(record: Mapping[str, Any], field: str, value: object,
           binding: Mapping[str, Any] | None = None) -> dict[str, Any]:
    trace = {
        "item_id": record["item_id"], "kind": record["kind"], "field": field,
        "context_pointer": record["pointer"] + field,
        "source_pointer": _map(record["payload"].get("source")).get("json_pointer"),
        "quote": value if isinstance(value, str) else _json(value),
    }
    if binding is not None:
        trace["binding"] = dict(binding)
    return trace


def _observations(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for record in records:
        if record["payload"].get("status") != "observed" or _type(record) != "fact":
            continue
        attrs = _attrs(record)
        for index, observation in enumerate(_list(_map(attrs.get("attributes")).get("source_observations"))):
            obs = _map(observation)
            fields = _map(obs.get("original_fields"))
            if not (fields and obs.get("source_file") and obs.get("raw_record_ref")):
                continue
            image_key = "Image" if fields.get("Image") else "NewProcessName"
            parent_key = "ParentImage" if fields.get("ParentImage") else "ParentProcessName"
            is_security = image_key == "NewProcessName"
            child_key = "NewProcessId" if is_security else ("ProcessGuid" if fields.get("ProcessGuid") else "ProcessId")
            parent_id_key = "ProcessId" if is_security else ("ParentProcessGuid" if fields.get("ParentProcessGuid") else "ParentProcessId")
            observations.append({
                "record": record, "fields": fields, "observation": obs,
                "path": _attr_path(record) + f"/attributes/source_observations/{index}",
                "process": fields.get(image_key), "parent": fields.get(parent_key),
                "process_id": fields.get(child_key), "parent_id": fields.get(parent_id_key),
                "image_key": image_key, "parent_key": parent_key,
                "child_id_key": child_key, "parent_id_key": parent_id_key,
            })
    return observations


def _observation_trace(obs: Mapping[str, Any], keys: list[str], binding: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    result = [_trace(obs["record"], obs["path"] + "/original_fields/" + key,
                     obs["fields"][key], binding) for key in keys if key in obs["fields"]]
    result += [_trace(obs["record"], obs["path"] + "/" + key, obs["observation"][key])
               for key in ("source_file", "raw_record_ref")]
    return result


def _entities(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    entities: dict[str, dict[str, Any]] = {}
    for record in records:
        if _type(record) != "entity":
            continue
        payload, attrs = record["payload"], _attrs(record)
        source_id = _map(payload.get("source")).get("object_id")
        identity = _map(attrs.get("attributes"))
        name = identity.get("process_name") or attrs.get("name") or payload.get("title") or payload.get("label")
        name_field = (_attr_path(record) + "/attributes/process_name" if identity.get("process_name")
                      else _attr_path(record) + "/name" if attrs.get("name")
                      else "/title" if payload.get("title") else "/label")
        if isinstance(source_id, str) and isinstance(name, str):
            entity = {"name": name, "identity": source_id, "record": record, "name_field": name_field}
            entities[source_id] = entity
            if record["kind"] == "node":
                entities[record["item_id"]] = entity
    return entities


def _relations(records: list[dict[str, Any]], observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    relations: list[dict[str, Any]] = []
    entities = _entities(records)
    for obs in observations:
        fields = obs["fields"]
        # Only explicit process-creation records establish these roles. A network
        # record containing Image and ParentImage does not establish a creation.
        if str(fields.get("EventID")) not in {"1", "4688"}:
            continue
        if not all(obs[key] for key in ("process", "parent", "process_id", "parent_id")):
            continue
        if str(obs["process_id"]).casefold() == str(obs["parent_id"]).casefold():
            continue
        binding = {"subject": _name(obs["parent"]), "action": "process_spawn", "object": _name(obs["process"]),
                   "subject_identity": str(obs["parent_id"]), "object_identity": str(obs["process_id"])}
        host = fields.get("Hostname") or fields.get("Computer") or fields.get("host")
        # Raw numeric PIDs are host-scoped and reusable. An unscoped PID cannot
        # establish a cross-record process identity. GUID and PID namespaces
        # also cannot accidentally compare equal.
        def chain_identity(key: str, value: object) -> str | None:
            id_kind = "guid" if "Guid" in key else "pid"
            if id_kind == "pid" and not host:
                return None
            return f"{_normal(str(host or 'unspecified-host'))}:{id_kind}:{str(value).casefold()}"
        relations.append({"parent": binding["subject"], "child": binding["object"],
                          "parent_id": binding["subject_identity"], "child_id": binding["object_identity"],
                          "parent_chain_id": chain_identity(obs["parent_id_key"], obs["parent_id"]),
                          "child_chain_id": chain_identity(obs["child_id_key"], obs["process_id"]),
                          "traces": _observation_trace(obs, [obs["parent_key"], obs["image_key"],
                              obs["parent_id_key"], obs["child_id_key"]], binding)})
    for record in records:
        payload = record["payload"]
        if payload.get("status") != "observed" or not _refs(record):
            continue
        if record["kind"] == "edge" and _type(record) == "process_spawn" and payload.get("directed") is True:
            parent, child = entities.get(payload.get("source_node_id")), entities.get(payload.get("target_node_id"))
            if parent is not None and child is not None and parent["identity"] != child["identity"]:
                binding = {"subject": _name(parent["name"]), "action": "process_spawn", "object": _name(child["name"]),
                           "subject_identity": parent["identity"], "object_identity": child["identity"]}
                relations.append({"parent": binding["subject"], "child": binding["object"],
                                  "parent_id": parent["identity"], "child_id": child["identity"],
                                  "parent_chain_id": "entity:" + parent["identity"],
                                  "child_chain_id": "entity:" + child["identity"],
                                  "traces": [_trace(record, "/source_node_id", payload["source_node_id"], binding),
                                             _trace(record, "/target_node_id", payload["target_node_id"], binding),
                                             _trace(parent["record"], "/source/object_id", parent["identity"]),
                                             _trace(child["record"], "/source/object_id", child["identity"]),
                                             _trace(parent["record"], parent["name_field"], parent["name"]),
                                             _trace(child["record"], child["name_field"], child["name"]),
                                             _trace(record, "/source_references", _refs(record))]})
        if record["kind"] == "chunk" and _type(record) == "relationship":
            content = payload.get("content", "")
            if not isinstance(content, str) or ". Source:" not in content:
                continue
            match = _RELATIONSHIP_TEXT.fullmatch("Source:" + content.split(". Source:", 1)[1])
            if match is not None:
                parent, parent_id, child, child_id = match.groups()
                if parent_id == child_id:
                    continue
                binding = {"subject": _name(parent), "action": "process_spawn", "object": _name(child),
                           "subject_identity": parent_id, "object_identity": child_id}
                relations.append({"parent": _name(parent), "child": _name(child), "parent_id": parent_id,
                                  "child_id": child_id, "parent_chain_id": "entity:" + parent_id,
                                  "child_chain_id": "entity:" + child_id,
                                  "traces": [_trace(record, "/content", content, binding)]})
    return relations


def _relationship(params: Mapping[str, Any], relations: list[dict[str, Any]]) -> tuple[str, str, list[dict[str, Any]]]:
    matching = [rel for rel in relations if _matches(rel["parent"], params.get("parent"))
                and _matches(rel["child"], params.get("child"))]
    if not params.get("chain"):
        return ("supported", "directed_process_creation_supported", matching[0]["traces"]) if matching else (
            "missing", "directed_process_creation_not_returned", [])
    for final in relations:
        if not _matches(final["child"], params.get("child")):
            continue
        for first in relations:
            if (first["child_chain_id"] is not None and first["child_chain_id"] == final["parent_chain_id"]
                    and first["parent_chain_id"] != final["child_chain_id"]
                    and first["child"] == final["parent"]
                    and _matches(first["parent"], params.get("parent"))):
                return "supported", "identity_linked_process_chain_supported", first["traces"] + final["traces"]
    return "missing", "identity_linked_process_chain_not_returned", []


def _command(params: Mapping[str, Any], observations: list[dict[str, Any]]) -> tuple[str, str, list[dict[str, Any]]]:
    for obs in observations:
        if (str(obs["fields"].get("EventID")) in {"1", "4688"}
                and _matches(obs["process"], params.get("process")) and obs["process_id"]
                and isinstance(obs["fields"].get("CommandLine"), str) and obs["fields"]["CommandLine"].strip()):
            binding = {"subject": _name(obs["process"]), "action": "launched_with_command_line",
                       "object": obs["fields"]["CommandLine"], "subject_identity": str(obs["process_id"])}
            return "supported", "original_launch_command_supported_only", _observation_trace(
                obs, [obs["image_key"], obs["child_id_key"], "CommandLine"], binding)
    return "missing", "bound_original_launch_command_not_returned", []


def _fact_actor(attrs: Mapping[str, Any], entities: Mapping[str, Any]) -> tuple[str, str] | None:
    subject = attrs.get("subject")
    entity = entities.get(subject) if isinstance(subject, str) else None
    if entity is not None:
        return entity["name"], entity["identity"]
    properties = _map(attrs.get("attributes"))
    process, identity = properties.get("process_name"), properties.get("process_guid") or properties.get("process_id")
    if isinstance(process, str) and identity:
        return process, str(identity)
    return None


def _endpoint(value: object, requested_field: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    if re.fullmatch(r"https?://[^\s]+", value, re.IGNORECASE):
        return True
    if requested_field == "url":
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        # A DNS endpoint must be explicit, rather than treating any unresolved
        # source entity ID as a network destination.
        return bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*", value, re.IGNORECASE))


def _network(params: Mapping[str, Any], records: list[dict[str, Any]], observations: list[dict[str, Any]]) -> tuple[str, str, list[dict[str, Any]]]:
    action, requested_field = params.get("action"), params.get("field")
    if action not in _NETWORK_PREDICATES or requested_field not in {"url", "endpoint"}:
        return "unknown", "network_requirement_not_supported_by_verifier", []
    entities = _entities(records)
    for record in records:
        if _type(record) != "fact" or record["payload"].get("status") != "observed" or not _refs(record):
            continue
        attrs = _attrs(record)
        if attrs.get("predicate") not in _NETWORK_PREDICATES[action]:
            continue
        actor = _fact_actor(attrs, entities)
        if actor is None or not _matches(actor[0], params.get("actor")):
            continue
        properties = _map(attrs.get("attributes"))
        field = "url" if requested_field == "url" else "destination_ip"
        endpoint = properties.get(field)
        path = _attr_path(record) + "/attributes/" + field
        if endpoint is None and isinstance(attrs.get("object"), str):
            endpoint, path = attrs["object"], _attr_path(record) + "/object"
        if not _endpoint(endpoint, requested_field):
            continue
        binding = {"subject": _name(actor[0]), "subject_identity": actor[1], "action": attrs["predicate"], "object": endpoint}
        return "supported", "observed_actor_action_endpoint_supported", [
            _trace(record, _attr_path(record) + "/predicate", attrs["predicate"], binding),
            _trace(record, path, endpoint, binding), _trace(record, "/source_references", _refs(record))]
    if action in {"connect", "network"}:
        for obs in observations:
            if (str(obs["fields"].get("EventID")) != "3" or not obs["process_id"]
                    or not _matches(obs["process"], params.get("actor"))):
                continue
            keys = ["DestinationUrl", "Url"] if requested_field == "url" else ["DestinationIp", "DestinationHostname"]
            for key in keys:
                endpoint = obs["fields"].get(key)
                if not _endpoint(endpoint, requested_field):
                    continue
                binding = {"subject": _name(obs["process"]), "subject_identity": str(obs["process_id"]),
                           "action": "network_connection", "object": endpoint}
                return "supported", "observed_process_network_connection_supported", _observation_trace(
                    obs, [obs["image_key"], obs["child_id_key"], "EventID", key], binding)
    return "missing", "bound_actor_action_endpoint_not_returned", []


def _completion(kind: str, params: Mapping[str, Any], records: list[dict[str, Any]]) -> tuple[str, str, list[dict[str, Any]]]:
    # Explicit completion/state predicates are a distinct evidence contract;
    # command strings and limitation prose never satisfy them.
    predicates = {"command_completed"} if kind == "command_completion" else {"service_state_observed"}
    entities = _entities(records)
    for record in records:
        attrs = _attrs(record)
        if (_type(record) != "fact" or record["payload"].get("status") != "observed"
                or not _refs(record) or attrs.get("predicate") not in predicates):
            continue
        actor = _fact_actor(attrs, entities)
        if actor is None or not _matches(actor[0], params.get("process")):
            continue
        properties = _map(attrs.get("attributes"))
        value = properties.get("exit_code") if kind == "command_completion" else properties.get("service_state")
        if kind == "command_completion" and type(value) is not int:
            continue
        if kind == "service_state" and (not isinstance(value, str) or not value):
            continue
        if kind == "service_state":
            # The v1 query contract identifies a process, not a service. Even a
            # real state observation cannot answer a specifically named service
            # question until the parser/verifier share a service identity field.
            return "unknown", "service_identity_not_resolved_by_requirement_contract", []
        # Likewise, a process can run many command invocations. The v1 contract
        # has no invocation selector, so a completion of another command cannot
        # establish successful completion of the requested one.
        return "unknown", "command_identity_not_resolved_by_requirement_contract", []
    return "missing", "separate_completion_or_state_observation_not_returned", []


def _provenance(params: Mapping[str, Any], records: list[dict[str, Any]], observations: list[dict[str, Any]]) -> tuple[str, str, list[dict[str, Any]]]:
    for obs in observations:
        if _matches(obs["process"], params.get("process")) or (params.get("process") is not None and _matches(obs["parent"], params.get("process"))):
            keys = [key for key in (obs["image_key"], "SourceName", "Channel", "EventID", "TimeCreated") if key in obs["fields"]]
            if params.get("process") is not None and _matches(obs["parent"], params["process"]):
                keys += [key for key in (obs["parent_key"], obs["parent_id_key"]) if key in obs["fields"]]
            if "EventID" in keys and "TimeCreated" in keys:
                return "supported", "associated_original_observation_provenance_supported", _observation_trace(obs, keys)
    if params.get("process") is None:
        for record in records:
            attrs = _attrs(record)
            if _type(record) != "evidence" or record["payload"].get("status") != "observed":
                continue
            for index, obs in enumerate(_list(attrs.get("observations"))):
                if (isinstance(obs, Mapping) and all(obs.get(key) for key in ("source_file", "raw_record_ref", "provider", "event_id", "timestamp"))):
                    return "supported", "associated_evidence_observation_provenance_supported", [
                        _trace(record, _attr_path(record) + f"/observations/{index}", obs)]
    return "missing", "associated_observation_provenance_not_returned", []


def _limitations(params: Mapping[str, Any], context: Mapping[str, Any], records: list[dict[str, Any]]) -> tuple[str, str, list[dict[str, Any]]]:
    facets = params.get("facets")
    if not isinstance(facets, list) or not facets or any(facet not in {*_FACETS, "all"} for facet in facets):
        return "unknown", "limitation_facets_not_supported_by_verifier", []
    limitations = []
    for record in records:
        if _type(record) != "limitation":
            continue
        key = "content" if record["kind"] == "chunk" else "label"
        text = record["payload"].get(key)
        pointer = _map(record["payload"].get("source")).get("json_pointer")
        if isinstance(text, str) and text.strip() and isinstance(pointer, str):
            limitations.append((record, key, text, pointer))
    traces: list[dict[str, Any]] = []
    if "all" in facets:
        count = _map(context.get("source_inventory")).get("limitation_count")
        if type(count) is not int or count < 0:
            return "unknown", "all_limitations_completeness_unknown", []
        unique = {pointer for _, _, _, pointer in limitations}
        traces = [_trace(record, "/" + key, text) for record, key, text, _ in limitations]
        if len(unique) < count:
            return "missing", "all_limitations_context_incomplete", traces
        if count == 0:
            return "missing", "limitation_evidence_not_returned", []
        if len(unique) != count:
            return "unknown", "limitation_inventory_inconsistent", traces
    for facet in facets:
        if facet == "all":
            continue
        matching = [(record, key, text) for record, key, text, _ in limitations
                    if any(term in _normal(text) for term in _FACETS[facet])]
        if not matching:
            return "missing", f"limitation_facet_{facet}_not_returned", traces
        record, key, text = matching[0]
        traces.append(_trace(record, "/" + key, text))
    return "supported", "requested_limitation_evidence_supported", traces


def _technique(params: Mapping[str, Any], records: list[dict[str, Any]]) -> tuple[str, str, list[dict[str, Any]]]:
    requested, certainty = params.get("technique_id"), params.get("certainty")
    if certainty not in {"assessment", "confirmed"}:
        return "unknown", "technique_certainty_not_supported_by_verifier", []
    candidate_traces: list[dict[str, Any]] = []
    for record in records:
        if _type(record) != "mitre_assessment":
            continue
        attrs, payload = _attrs(record), record["payload"]
        external = attrs.get("external_id")
        if record["kind"] == "chunk":
            ids = _list(payload.get("mitre_external_ids"))
            external = ids[0] if len(ids) == 1 else None
        if not isinstance(external, str) or (requested is not None and external != requested):
            continue
        if not all(isinstance(attrs.get(key), str) and attrs[key] for key in ("evidence_support", "review_status")):
            continue
        rationale = attrs.get("rationale")
        rationale_field = _attr_path(record) + "/rationale"
        if record["kind"] == "chunk":
            # Canonical assessment chunks preserve rationale in their text;
            # arbitrary labels or a candidate status alone are insufficient.
            text = payload.get("content")
            if isinstance(text, str) and ". Rationale: " in text and ". Review status: " in text:
                rationale = text.split(". Rationale: ", 1)[1].rsplit(". Review status: ", 1)[0]
                rationale_field = "/content"
        if not isinstance(rationale, str) or not rationale.strip():
            continue
        traces = [_trace(record, "/status", payload.get("status")),
                  _trace(record, _attr_path(record) + "/evidence_support", attrs["evidence_support"]),
                  _trace(record, _attr_path(record) + "/review_status", attrs["review_status"]),
                  _trace(record, rationale_field, payload["content"] if rationale_field == "/content" else rationale)]
        traces.insert(0, _trace(record, "/mitre_external_ids" if record["kind"] == "chunk"
                               else _attr_path(record) + "/external_id",
                               payload["mitre_external_ids"] if record["kind"] == "chunk" else external))
        if certainty == "confirmed" and (payload.get("status") != "confirmed" or attrs["review_status"] != "confirmed"):
            candidate_traces.extend(traces)
            continue
        return "supported", "technique_assessment_status_preserved", traces
    if candidate_traces:
        return "missing", "technique_confirmation_not_established", candidate_traces
    return "missing", "requested_technique_assessment_not_returned", []


def assess_evidence_support(requirements: Mapping[str, object], final_context: Mapping[str, object]) -> dict[str, object]:
    """Return deterministic support traces from mandatory returned requirements.

    The caller supplies the query-requirements and query-evidence-context versioned
    envelopes. Every trace points into the latter's actual ``final_items``. Neither
    approval nor candidate labels establish a positive security conclusion.
    """
    reqs, context = _detach(requirements), _detach(final_context)
    try:
        reqs = validate_query_requirements_document(reqs)
    except ValueError as exc:
        raise QueryEvidenceSupportError(f"invalid query requirements: {exc}") from exc
    if context.get("schema_version") != "query-evidence-context/v1":
        raise QueryEvidenceSupportError("final_context.schema_version is unsupported")
    if not isinstance(reqs.get("requirements"), list):
        raise QueryEvidenceSupportError("requirements.requirements must be a list")
    initial_query = _map(_map(context.get("initial_context")).get("query")).get("text")
    if initial_query is not None and initial_query != reqs["query"]:
        raise QueryEvidenceSupportError("requirements.query disagrees with initial_context.query.text")
    records = _records(context)
    observations = _observations(records)
    relations = _relations(records, observations)
    results: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for requirement in reqs["requirements"]:
        req = _map(requirement)
        rid, kind, params = req.get("requirement_id"), req.get("kind"), _map(req.get("parameters"))
        if not isinstance(rid, str) or not rid or rid in seen_ids or type(req.get("mandatory")) is not bool:
            raise QueryEvidenceSupportError("requirements need unique IDs and a boolean mandatory flag")
        seen_ids.add(rid)
        if req.get("analysis_status") != "supported" or reqs.get("analysis_status") != "supported":
            status, reason, traces = "unknown", "query_requirement_analysis_not_supported", []
        elif kind not in _KINDS:
            status, reason, traces = "unknown", "requirement_kind_not_supported_by_verifier", []
        elif kind == "process_relationship":
            status, reason, traces = _relationship(params, relations)
        elif kind == "launch_command":
            status, reason, traces = _command(params, observations)
        elif kind in {"command_completion", "service_state"}:
            status, reason, traces = _completion(kind, params, records)
        elif kind == "network_url":
            status, reason, traces = _network(params, records, observations)
        elif kind == "evidence_provenance":
            status, reason, traces = _provenance(params, records, observations)
        elif kind == "review_limitations":
            status, reason, traces = _limitations(params, context, records)
        else:
            status, reason, traces = _technique(params, records)
        # The same observation can be returned via a node and a chunk. Traces
        # remain source-backed but identical trace records are emitted once.
        traces = list({_json(trace): trace for trace in traces}.values())
        results.append({"requirement_id": rid, "kind": kind, "mandatory": req["mandatory"],
                        "status": status, "reason_codes": [reason], "traces": traces})
    mandatory = [result["status"] for result in results if result["mandatory"]]
    status = "unknown" if not mandatory or "unknown" in mandatory else "missing" if "missing" in mandatory else "supported"
    output = {
        "schema_version": QUERY_EVIDENCE_SUPPORT_SCHEMA_VERSION,
        "status": status, "requirements": results,
        "counts": {key: sum(result["status"] == key for result in results) for key in ("supported", "missing", "unknown")},
        "reason_codes": ["all_mandatory_requirements_supported"] if status == "supported" else [
            "mandatory_requirement_support_unknown" if status == "unknown" else "mandatory_evidence_missing"],
        "metadata": {"checked_final_item_count": len(records), "file_io_performed": False,
                     "retrieval_scores_used": False, "security_conclusion_made": False,
                     "missing_interpretation": "required_evidence_not_found_in_checked_context_only"},
    }
    return copy.deepcopy(output)


__all__ = ("QUERY_EVIDENCE_SUPPORT_SCHEMA_VERSION", "QueryEvidenceSupportError", "assess_evidence_support")
