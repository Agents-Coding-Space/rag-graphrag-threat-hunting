"""Source-bound experimental eligibility, using only returned context objects.

No IO, graph lookup, benchmark IDs, answers, or label inputs. This is a finite
query subset and an explicit replacement for graph-topology admission, not a
compatibility trick that calls retrieval objects graph nodes or traversals.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Iterator
import unicodedata
from urllib.parse import urlsplit

VERSION = "source-evidence-contract/v1"


def fold(value: str) -> str:
    return " ".join("".join(c for c in unicodedata.normalize("NFKD", value.casefold().replace("đ", "d"))
                            if not unicodedata.combining(c)).split())


def basename(value: Any) -> str:
    return str(value or "").strip('"').replace("\\", "/").rsplit("/", 1)[-1].casefold()


def walk(value: Any, pointer: str = "") -> Iterator[tuple[dict, str]]:
    if isinstance(value, dict):
        yield value, pointer
        for key, item in value.items():
            yield from walk(item, pointer + "/" + key.replace("~", "~0").replace("/", "~1"))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from walk(item, pointer + f"/{i}")


def project_evidence(context: dict[str, Any]) -> dict[str, Any]:
    """Preserve exact source views; no extra objects/fields are fetched or added."""
    provenance = deepcopy(context.get("source_ground_truth", {}))
    valid_binding = bool(re.fullmatch(r"[0-9a-f]{64}", str(provenance.get("sha256", ""))))
    valid_binding &= provenance.get("scenario_id") == context.get("scenario_id")
    entries = [(hit["chunk"], f"/retrieval/hits/{i}/chunk", "chunk")
               for i, hit in enumerate(context.get("retrieval", {}).get("hits", []))]
    for collection, kind in (("nodes", "node"), ("edges", "edge")):
        entries += [(item, f"/traversal/{collection}/{i}", kind)
                    for i, item in enumerate((context.get("traversal") or {}).get(collection, []))]
    units = []
    for payload, pointer, kind in entries:
        source = payload.get("source") or {}
        refs = [deepcopy(r) for r in payload.get("source_references", [])
                if isinstance(r, dict) and r.get("source_file") and r.get("raw_record_ref")]
        bound = valid_binding and isinstance(source.get("json_pointer"), str) and source["json_pointer"].startswith("/")
        if kind == "chunk":
            bound &= payload.get("scenario_id") == context.get("scenario_id")
        units.append({"origin": {"kind": kind, "item_id": payload.get(kind + "_id"), "context_pointer": pointer},
                      "source": deepcopy(source), "status": payload.get("status"),
                      "object_type": source.get("object_type"), "source_bound": bool(bound),
                      "source_references": refs, "text": payload.get("content", payload.get("label", "")),
                      "properties": deepcopy(payload.get("metadata" if kind == "chunk" else "attributes", {}))})
    return {"schema_version": VERSION, "scenario_id": context.get("scenario_id"),
            "source_ground_truth": provenance, "units": units}


def trace(unit: dict, field: str, value: Any) -> dict:
    base = unit["origin"]["context_pointer"]
    if field.startswith("/"):
        pointer = base + ("/metadata" if unit["origin"]["kind"] == "chunk" else "/attributes") + field
    else:
        key = {"text": "content" if unit["origin"]["kind"] == "chunk" else "label",
               "properties": "metadata" if unit["origin"]["kind"] == "chunk" else "attributes"}.get(field, field)
        pointer = base + "/" + key
    return {"origin": unit["origin"], "source": unit["source"], "source_references": unit["source_references"],
            "field": field, "context_pointer": pointer, "value": value}


def observations(units: list[dict]) -> list[dict]:
    result = []
    aliases = {"event_id": ("event_id", "EventID"), "provider": ("provider", "SourceName"),
               "process_name": ("process_name", "Image", "NewProcessName"),
               "parent_process_name": ("parent_process_name", "ParentImage", "ParentProcessName"),
               "command_line": ("command_line", "CommandLine"), "host": ("host", "Hostname"),
               "destination_ip": ("destination_ip", "DestinationIp"), "destination_port": ("destination_port", "DestinationPort")}
    for unit in units:
        if not unit["source_bound"] or unit["status"] != "observed":
            continue
        refs = {(r["source_file"], r["raw_record_ref"]) for r in unit["source_references"]}
        for item, path in walk(unit["properties"]):
            field_type = "canonical_fields" if isinstance(item.get("canonical_fields"), dict) else "original_fields"
            raw = item.get(field_type)
            if not isinstance(raw, dict) or (item.get("source_file"), item.get("raw_record_ref")) not in refs:
                continue
            fields, field_paths = {}, {}
            for target, candidates in aliases.items():
                key = next((k for k in candidates if raw.get(k) is not None), None)
                if key:
                    fields[target], field_paths[target] = raw[key], path + "/" + field_type + "/" + key
            result.append({"unit": unit, "fields": fields, "field_paths": field_paths,
                           "source_file": item["source_file"], "raw_record_ref": item["raw_record_ref"]})
    return result


def groups(units: list[dict]) -> list[dict]:
    """Deduplicate evidence identities, never count chunk/node copies as creations."""
    result = {}
    for unit in units:
        if not (unit["source_bound"] and unit["status"] == "observed" and unit["object_type"] == "evidence" and unit["source_references"]):
            continue
        props = unit["properties"]
        event_ids = {str(o.get("event_id")) for o in props.get("observations", []) if isinstance(o, dict)}
        event_ids.update(re.findall(r"event_id=(\d+)", unit["text"]))
        providers = {str(o["provider"]) for o in props.get("observations", []) if isinstance(o, dict) and o.get("provider")}
        providers.update(re.findall(r"provider=([^,;]+),\s*event_id=\d+", unit["text"]))
        # Source object identity ignores representation-only artifact_type.
        identity = (unit["source"].get("object_id"), unit["source"].get("json_pointer"))
        result.setdefault(identity, {"unit": unit, "event_ids": event_ids, "providers": providers,
                                     "refs": {(r["source_file"], r["raw_record_ref"]) for r in unit["source_references"]}})
    return list(result.values())


def requirements(query: str) -> dict:
    """Declared literal EN/VI subset; unrecognized requests fail closed."""
    text = fold(query)
    processes = list(dict.fromkeys(re.findall(r"[\w.-]+\.exe\b", text)))
    checks = []
    outcomes = []
    if "crack" in text or "cracking" in text:
        outcomes = ["cracking"] + (["account"] if "tai khoan" in text or "account" in text else [])
    elif any(word in text for word in ("exfiltration", "danh cap", "stolen data", "data theft")):
        outcomes = ["exfiltration"] + (["bytes"] if any(w in text for w in ("dung luong", "bytes", "volume")) else [])
    elif any(word in text for word in ("hoan tat", "completion", "output", "trang thai dich vu", "service state", "thanh cong")):
        outcomes = [key for key, words in {
            "completion": ("hoan tat", "completion", "thanh cong"), "output": ("output", "dau ra"),
            "service_state": ("trang thai dich vu", "service state")}.items() if any(w in text for w in words)]
    if outcomes:
        checks.append("outcome_limits")
    elif any(w in text for w in ("bao nhieu", "how many")) and any(w in text for w in ("tao tien trinh", "process creation")):
        checks.append("creation_groups")
    elif any(w in text for w in ("provider", "event id")) and any(w in text for w in ("hai quan sat", "two observations", "hai lan", "two launches")):
        checks.append("provider_groups")
    elif any(w in text for w in ("parent", " la cha", "parent process")) or re.search(r"tien trinh nao.*khoi chay", text):
        checks.append("parent")
    elif any(w in text for w in ("dong lenh", "lenh khoi chay", "command line", "commandline", "launch command", "co che script")):
        checks.append("command")
    elif any(w in text for w in ("ket noi", "network_connection", "connected", "connection")):
        checks.append("connection")
    # Preserve additional explicit requests instead of accepting just the first
    # recognized intent. Background "from a connection" in a limits question
    # does not by itself request endpoint enumeration.
    if any(w in text for w in ("command line", "commandline", "dong lenh", "launch command")) and "command" not in checks:
        checks.append("command")
    if ("parent" in text or " la cha" in text) and not any(c in checks for c in ("parent", "creation_groups")):
        checks.append("parent")
    if any(w in text for w in ("which ip", "which endpoint", "ip va cong nao")) and "connection" not in checks:
        checks.append("connection")
    return {"query": query, "checks": checks, "processes": processes, "outcome_facets": outcomes,
            "requires_core_boundary": "core" in text and "creation_groups" in checks,
            "requires_t_argument": "/t" in text and "command" in checks,
            "requires_url": any(w in text for w in ("scriptlet", "giao thuc", "protocol")) and "command" in checks}


def evidence_support(query: str, projection: dict) -> dict:
    """Require field/source witnesses for every recognized information request."""
    request = requirements(query)
    units, checks = projection["units"], []
    obs, evidence_groups = observations(units), groups(units)
    requested_process = request["processes"][0] if len(request["processes"]) == 1 else None
    if "command" in request["checks"] and request["processes"]:
        requested_process = request["processes"][0]
    relevant = [o for o in obs if not requested_process or basename(o["fields"].get("process_name")) == requested_process]

    def add(name: str, witnesses: list[dict], reason: str) -> None:
        checks.append({"requirement": name, "status": "supported" if witnesses else "missing",
                       "reason_code": "source_witness_present" if witnesses else reason, "witnesses": witnesses})

    for kind in request["checks"]:
        witnesses = []
        if kind == "parent":
            for o in relevant if requested_process else []:
                f = o["fields"]
                if str(f.get("event_id")) in {"1", "4688"} and f.get("parent_process_name") and f.get("process_name"):
                    witnesses.append(trace(o["unit"], o["field_paths"]["parent_process_name"], {"parent": f["parent_process_name"], "child": f["process_name"]}))
            # Exact renderer of a returned relationship is a source-level claim,
            # not invented raw fields and not a fabricated traversal.
            for unit in units:
                if unit["source_bound"] and unit["object_type"] == "relationship" and unit["status"] == "observed" and unit["source_references"]:
                    match = re.fullmatch(r"Relationship [^.]+\. Source: (.*?) \(([^()]+)\)\. Type: process_spawn\. Target: (.*?) \(([^()]+)\)\. Status: observed\.", unit["text"])
                    if match and requested_process and basename(match[3]) == requested_process:
                        witnesses.append(trace(unit, "text", {"parent": match[1], "child": match[3]}))
            if len({basename(w["value"]["parent"]) for w in witnesses}) > 1:
                witnesses = []
            add(kind, witnesses, "requested_parent_not_bound_or_conflicting")
        elif kind == "command":
            for o in relevant if requested_process else []:
                command = o["fields"].get("command_line")
                if str(o["fields"].get("event_id")) not in {"1", "4688"} or not isinstance(command, str) or not command:
                    continue
                if request["requires_t_argument"] and not re.search(r"(?:^|\s)/t(?:\s|:)", command, re.I):
                    continue
                if request["requires_url"]:
                    urls = re.findall(r"https?://[^\s\"']+", command, re.I)
                    try:
                        valid_url = any(urlsplit(url).hostname and urlsplit(url).port for url in urls)
                    except ValueError:
                        valid_url = False
                    if not valid_url:
                        continue
                witnesses.append(trace(o["unit"], o["field_paths"]["command_line"], command))
            add(kind, witnesses, "actor_bound_command_fields_not_returned")
        elif kind == "connection":
            for o in relevant if requested_process else []:
                f = o["fields"]
                if str(f.get("event_id")) == "3" and f.get("process_name") and f.get("destination_ip") and f.get("destination_port") is not None and f.get("provider"):
                    witnesses.append(trace(o["unit"], o["field_paths"]["destination_ip"], {**f, "source_file": o["source_file"], "raw_record_ref": o["raw_record_ref"]}))
            add(kind, witnesses, "actor_endpoint_event_provider_fields_not_returned")
        elif kind in {"creation_groups", "provider_groups"}:
            related_refs = {(o["source_file"], o["raw_record_ref"]) for o in relevant}
            selected = [g for g in evidence_groups if g["event_ids"] == {"1", "4688"} and len(g["refs"]) == 2 and len(g["providers"]) >= 2
                        and (not requested_process or requested_process in fold(g["unit"]["text"]) or g["refs"].intersection(related_refs))]
            witnesses = [trace(g["unit"], "source_references", sorted(g["refs"])) for g in selected]
            add(kind, witnesses, "paired_creation_evidence_groups_not_returned")
            if kind == "creation_groups":
                text = fold(query)
                expected_four = bool(re.search(r"\b(?:bon|four|4)\s+(?:quan sat|observations)", text))
                add("complete_requested_observations", witnesses if not expected_four or len(selected) == 2 else [], "four_observation_request_not_complete")
                if request["requires_core_boundary"]:
                    boundaries = [trace(u, "text", u["text"]) for u in units if u["source_bound"] and u["object_type"] == "limitation"
                                  and "core" in fold(u["text"]) and any(w in fold(u["text"]) for w in ("outside", "ngoai", "limited to", "only", "excludes", "chi gom"))]
                    add("core_boundary", boundaries, "core_boundary_not_returned")
        elif kind == "outcome_limits":
            actor_obs = relevant
            if not requested_process:
                text = fold(query)
                actor_obs = [o for o in obs if (basename(o["fields"].get("process_name")).removesuffix(".exe") in text
                             and basename(o["fields"].get("process_name"))) or
                             ("get-service" in text and "get-service" in fold(str(o["fields"].get("command_line", ""))))]
            add("observed_anchor", [trace(o["unit"], "properties", o["fields"]) for o in actor_obs], "relevant_observed_anchor_not_returned")
            facet_words = {"completion": ("completion", "hoan tat"), "output": ("output", "dau ra"),
                           "service_state": ("service state", "trang thai dich vu"), "cracking": ("crack",),
                           "account": ("account", "tai khoan"), "exfiltration": ("exfiltration", "data theft", "transferred content"),
                           "bytes": ("bytes", "volume", "dung luong")}
            for facet in request["outcome_facets"]:
                limits = []
                for u in units:
                    if not u["source_bound"] or u["object_type"] not in {"limitation", "evidence"}:
                        continue
                    text = fold(u["text"])
                    clauses = re.split(r"[.;]\s+", text)
                    if any(any(w in clause for w in ("does not", "do not", "unverified", "not established", "not prove", "khong", "chua"))
                           and any(w in clause for w in facet_words[facet]) for clause in clauses):
                        limits.append(trace(u, "text", u["text"]))
                add("limit_" + facet, limits, "explicit_requested_limit_not_returned")
    if not request["checks"]:
        add("recognized_query", [], "unsupported_query_contract")
    # Require provenance-bearing evidence independently from cosine or prose.
    bound_hits = [u for u in units if u["origin"]["kind"] == "chunk" and u["source_bound"] and u["source_references"]]
    add("bound_retrieved_hit", [trace(u, "source", u["source"]) for u in bound_hits], "source_bound_retrieved_hit_missing")
    return {"schema_version": VERSION, "requirements": request, "checks": checks,
            "status": "supported" if all(c["status"] == "supported" for c in checks) else "missing",
            "reason_codes": list(dict.fromkeys(c["reason_code"] for c in checks if c["status"] != "supported"))}


def assess_source_evidence_gate(query: str, context: dict, legacy: dict) -> tuple[dict, dict]:
    """Keep topical policy verbatim; replace topology admission for both branches."""
    projection = project_evidence(context)
    support = evidence_support(query, projection)
    topical = legacy["stage_results"]["topical_relevance"]
    topical_failed = topical["status"] != "passed"
    reasons = topical["reason_codes"] if topical_failed else support["reason_codes"]
    decision = {"schema_version": "source-evidence-gate-decision/v1", "contract": VERSION,
                "decision": "abstain" if reasons else "proceed",
                "abstention_stage": "topical_relevance" if topical_failed else "evidence_answerability" if reasons else None,
                "reason_codes": reasons, "stage_results": {"topical_relevance": deepcopy(topical), "evidence_answerability": support},
                "legacy_policy_id": legacy["policy_id"], "human_review_required": True,
                "interpretation": "Experimental query/source eligibility, not verified answer truth or production qualification."}
    return decision, projection
