"""Full-file process/network correlation with explicit ambiguity and PID lifetimes."""
from __future__ import annotations

from collections import Counter
from itertools import zip_longest
from pathlib import Path
from typing import Any

from .authentication import time_value, stable_id
from .slice_provenance import digest
from threat_hunting.mordor.format_detection import detect_format
from threat_hunting.mordor.parser import iter_records, iter_jsonl
from threat_hunting.normalizer import normalize_record


def basename(value: Any) -> str:
    return str(value or "").replace("\\", "/").rsplit("/", 1)[-1].casefold()


def pid(value: Any) -> int | None:
    try:
        text = str(value)
        return int(text, 16 if text.casefold().startswith("0x") else 10)
    except (TypeError, ValueError):
        return None


def read_aligned(raw: Path, canonical: Path, raw_sha256: str, canonical_sha256: str) -> tuple[list[dict], dict]:
    """Stream every input; keep only process creation/exit and network observations."""
    if digest(raw) != raw_sha256 or digest(canonical) != canonical_sha256:
        raise ValueError(f"Raw/canonical hash mismatch: {raw.name}")
    rows, counts = [], Counter()
    for source, normalized in zip_longest(iter_records(raw, detect_format(raw).source_format), iter_jsonl(canonical)):
        if source is None or normalized is None:
            raise ValueError(f"Raw/canonical count mismatch: {raw.name}")
        event = normalized.data
        if normalize_record(source.data, raw_record_ref=source.raw_record_ref, source_file=raw.name).event != event:
            raise ValueError(f"Raw/canonical alignment mismatch: {raw.name}:{source.raw_record_ref}")
        counts[str(event["event_id"])] += 1
        if (event["provider"], str(event["event_id"])) not in {
            ("Microsoft-Windows-Sysmon", "1"), ("Microsoft-Windows-Sysmon", "3"), ("Microsoft-Windows-Sysmon", "5"),
            ("Microsoft-Windows-Security-Auditing", "4688"), ("Microsoft-Windows-Security-Auditing", "4689"),
            ("Microsoft-Windows-Security-Auditing", "5156")}:
            continue
        # Preserve original fields needed for Sigma and evidence; no Message boilerplate.
        keep = ("EventID", "SourceName", "Hostname", "TimeCreated", "@timestamp", "UtcTime", "Image", "NewProcessName",
                "ProcessGuid", "ProcessId", "NewProcessId", "ParentImage", "ParentProcessName", "ParentProcessGuid", "ParentProcessId",
                "CommandLine", "ParentCommandLine", "OriginalFileName", "SourceIp", "SourcePort", "DestinationIp", "DestinationPort", "Initiated")
        rows.append({"source_file": raw.name, "raw_record_ref": source.raw_record_ref, "canonical_fields": event,
                     "original_fields": {key: source.data[key] for key in keep if key in source.data}})
    if digest(raw) != raw_sha256 or digest(canonical) != canonical_sha256:
        raise ValueError(f"Input changed: {raw.name}")
    return rows, {"raw_records": sum(counts.values()), "canonical_records": sum(counts.values()), "equal_records": sum(counts.values()),
                  "dropped_records": 0, "event_ids": dict(sorted(counts.items())), "raw_sha256": raw_sha256, "canonical_sha256": canonical_sha256}


def correlate_process_network(rows: list[dict], *, root_image: str = "regsvr32.exe", dedup_seconds: float = 2.0,
                              pid_max_seconds: float = 120.0) -> dict:
    """Exact host/GUID first. PID fallback requires creation, bounded lifetime and image.

    Never join by basename/PID alone or choose arbitrarily among candidates.
    Background networks and unpaired Security views are retained separately.
    """
    creates = [r for r in rows if str(r["canonical_fields"]["event_id"]) in {"1", "4688"}]
    sysmon = [r for r in creates if str(r["canonical_fields"]["event_id"]) == "1"]
    groups, ambiguous, unpaired = [], [], []
    for item in sysmon:
        f = item["canonical_fields"]
        identity = [item["source_file"], f["host"] or "", f.get("process_guid") or item["raw_record_ref"]]
        groups.append({"process_key": stable_id("process", identity), "creation": f, "observations": [item], "status": "observed"})
    candidates = {}
    for item in (r for r in creates if str(r["canonical_fields"]["event_id"]) == "4688"):
        f = item["canonical_fields"]
        matches = []
        for group in groups:
            g = group["creation"]
            a, b = time_value(f.get("timestamp")), time_value(g.get("timestamp"))
            if (f.get("host") and f["host"] == g["host"] and pid(f.get("process_id")) is not None
                    and pid(f["process_id"]) == pid(g["process_id"]) and pid(f.get("parent_process_id")) == pid(g.get("parent_process_id"))
                    and basename(f.get("process_name")) == basename(g.get("process_name"))
                    and f.get("command_line") == g.get("command_line") and a and b and abs((a-b).total_seconds()) <= dedup_seconds):
                matches.append(group["process_key"])
        candidates[item["raw_record_ref"]] = (item, matches)
    for item, matches in candidates.values():
        if len(matches) == 1 and sum(matches[0] in links for _, links in candidates.values()) == 1:
            group = next(g for g in groups if g["process_key"] == matches[0])
            group["observations"].append(item)
            group["correlation_status"] = "inferred"
        elif matches:
            ambiguous.append({"kind": "creation_dedup", "observation": item, "candidate_process_keys": matches})
        else:
            unpaired.append(item)
    # Security-only views are processes with bounded PID identity, not dropped.
    for item in unpaired:
        groups.append({"process_key": stable_id("process", [item["source_file"], item["raw_record_ref"]]),
                       "creation": item["canonical_fields"], "observations": [item], "status": "observed", "correlation_status": "single_view"})

    def within_lifetime(f: dict, group: dict, *, fallback: bool) -> bool:
        g = group["creation"]
        t, start = time_value(f.get("timestamp")), time_value(g.get("timestamp"))
        if t is None or start is None or t < start:
            return False
        if fallback and (t-start).total_seconds() > pid_max_seconds:
            return False
        # Next creation on same host/PID ends this lifetime even if name differs.
        later = [time_value(x["creation"].get("timestamp")) for x in groups if x is not group
                 and x["creation"].get("host") == g.get("host") and pid(g.get("process_id")) is not None
                 and pid(x["creation"].get("process_id")) == pid(g.get("process_id"))]
        if any(v and start < v <= t for v in later):
            return False
        for row in rows:
            exit = row["canonical_fields"]
            end = time_value(exit.get("timestamp"))
            if str(exit["event_id"]) not in {"5", "4689"} or not end or not (start <= end < t) or exit.get("host") != g.get("host"):
                continue
            if ((g.get("process_guid") and exit.get("process_guid") == g["process_guid"])
                    or (not exit.get("process_guid") and pid(exit.get("process_id")) is not None and pid(exit.get("process_id")) == pid(g.get("process_id")))):
                return False
        return True

    def resolve(f: dict, *, parent: bool = False) -> tuple[list[dict], str]:
        guid = f.get("parent_process_guid" if parent else "process_guid")
        process_id = f.get("parent_process_id" if parent else "process_id")
        image = f.get("parent_process_name" if parent else "process_name")
        matches = []
        for group in groups:
            g = group["creation"]
            if not f.get("host") or f["host"] != g.get("host"):
                continue
            if guid:
                if g.get("process_guid") != guid:
                    continue
            elif pid(process_id) is None or pid(process_id) != pid(g.get("process_id")):
                continue
            if image and basename(image) != basename(g.get("process_name")):
                continue
            if not within_lifetime(f, group, fallback=not bool(guid)):
                continue
            matches.append(group)
        return matches, "host_guid_lifetime" if guid else "host_pid_image_bounded_lifetime"

    links = []
    for group in groups:
        matches, basis = resolve(group["creation"], parent=True)
        matches = [m for m in matches if m is not group]
        if len(matches) == 1:
            links.append({"source_process_key": matches[0]["process_key"], "target_process_key": group["process_key"],
                          "basis": basis, "status": "inferred", "source_references": refs(group["observations"])})
        elif matches:
            ambiguous.append({"kind": "parent", "process_key": group["process_key"], "candidate_process_keys": [m["process_key"] for m in matches]})
    selected = {g["process_key"] for g in groups if basename(g["creation"].get("process_name")) == root_image.casefold()}
    while True:
        expanded = selected | {link["target_process_key"] for link in links if link["source_process_key"] in selected}
        if expanded == selected:
            break
        selected = expanded
    connections, background, unresolved = [], [], []
    for row in rows:
        f = row["canonical_fields"]
        if str(f["event_id"]) != "3":
            continue
        matches, basis = resolve(f)
        if len(matches) == 1:
            item = {"process_key": matches[0]["process_key"], "observation": row, "status": "inferred", "basis": basis}
            (connections if item["process_key"] in selected else background).append(item)
        elif len(matches) > 1:
            ambiguous.append({"kind": "network", "observation": row, "candidate_process_keys": [m["process_key"] for m in matches]})
        else:
            unresolved.append({"observation": row, "reason": "No unique observed creation within identity/lifetime; process may predate capture."})
    return {"schema_version": "process-network-correlation/v1", "review_status": "pending_human_review",
            "processes": groups, "selected_process_keys": sorted(selected), "parent_child_links": links,
            "connections": connections, "background_connections": background, "unresolved_connections": unresolved,
            "ambiguous_links": ambiguous, "creation_observation_count": len(creates), "sysmon_network_observation_count": sum(str(r['canonical_fields']['event_id']) == '3' for r in rows),
            "policy": {"creation_view_tolerance_seconds": dedup_seconds, "pid_fallback_max_seconds": pid_max_seconds,
                       "guid_with_conflicting_image_or_lifetime": "reject", "pid_reuse": "stop_at_next_creation_or_exit", "ambiguous": "retain_separately"}}


def refs(rows: list[dict]) -> list[dict]:
    return [{key: row[key] for key in ("source_file", "raw_record_ref")} for row in rows]
