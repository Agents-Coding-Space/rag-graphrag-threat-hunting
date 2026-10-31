"""Offline authentication survey and conservative, reviewable correlations.

Canonical v2 lacks outcome/workstation/ticket fields. Hydrate only from the
hash-verified raw source, checking the complete raw/canonical alignment first.
No benchmark IDs, launch arguments, external CTI, or reference answers are input.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from itertools import zip_longest
from pathlib import Path
from typing import Any
import hashlib
import json

from threat_hunting.mordor.format_detection import detect_format
from threat_hunting.mordor.parser import iter_jsonl, iter_records
from threat_hunting.normalizer import normalize_record
from .slice_provenance import digest

SECURITY = "Microsoft-Windows-Security-Auditing"
AUTH_IDS = {"4624", "4625", "4627", "4634", "4648", "4672", "4740", "4768", "4769", "4771", "4776", "4778", "4779"}
RAW_FIELDS = (
    "EventID", "Hostname", "SourceName", "Channel", "@timestamp", "TimeCreated", "EventTime", "EventReceivedTime",
    "TargetUserName", "TargetDomainName", "SubjectUserName", "SubjectDomainName", "TargetUserSid", "SubjectUserSid",
    "WorkstationName", "Workstation", "IpAddress", "IpPort", "Status", "SubStatus", "FailureReason", "EventType",
    "LogonType", "LogonProcessName", "AuthenticationPackageName", "PackageName", "ProcessName", "ProcessId",
    "TargetLogonId", "SubjectLogonId", "LogonGuid", "ServiceName", "ServiceSid", "TicketOptions", "TicketEncryptionType",
)


def scalar(value: Any) -> str | None:
    """Keep missing, placeholder and multivalued source fields out of joins."""
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return None
    value = str(value).strip()
    return None if value in {"", "-"} else value


def time_value(value: Any) -> datetime | None:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result if result.tzinfo is not None else None
    except ValueError:
        return None


def stable_id(kind: str, refs: list[str]) -> str:
    return kind + "-" + hashlib.sha256("\n".join(sorted(refs)).encode()).hexdigest()[:16]


def outcome(event_id: str, raw: dict) -> str:
    if event_id in {"4625", "4771"}:
        return "failure"
    if event_id == "4624":
        return "success"
    if event_id in {"4768", "4769", "4776"}:
        status = scalar(raw.get("Status"))
        if status is not None:
            try:
                return "success" if int(status, 16) == 0 else "failure"
            except ValueError:
                pass
    return "context_only"


def survey_authentication(raw_path: Path, canonical_path: Path, *, expected_raw_sha256: str,
                          expected_canonical_sha256: str) -> dict[str, Any]:
    """Read every raw/canonical record; retain relevant observations with fields."""
    before = {str(p): digest(p) for p in (raw_path, canonical_path)}
    if before[str(raw_path)] != expected_raw_sha256 or before[str(canonical_path)] != expected_canonical_sha256:
        raise ValueError(f"Input provenance mismatch: {raw_path.name} / {canonical_path.name}")
    fmt = detect_format(raw_path)
    counts: Counter = Counter()
    providers: Counter = Counter()
    missing: dict[str, Counter] = defaultdict(Counter)
    multivalued: dict[str, Counter] = defaultdict(Counter)
    observations = []
    launches = []
    timestamp_min = timestamp_max = None
    count = 0
    conflicts = 0
    for raw_record, canonical_record in zip_longest(iter_records(raw_path, fmt.source_format), iter_jsonl(canonical_path)):
        if raw_record is None or canonical_record is None:
            raise ValueError(f"Record count mismatch: {raw_path.name} / {canonical_path.name}")
        raw, event = raw_record.data, canonical_record.data
        reference = raw_record.raw_record_ref
        # Full normalized equality also checks source file, stable refs and order.
        if normalize_record(raw, raw_record_ref=reference, source_file=raw_path.name).event != event:
            raise ValueError(f"Raw/canonical mismatch: {raw_path.name}:{reference}")
        count += 1
        eid = str(event.get("event_id"))
        counts[eid] += 1
        providers[str(event.get("provider"))] += 1
        if time_value(event.get("timestamp")) is not None:
            timestamp_min = min(timestamp_min, event["timestamp"]) if timestamp_min else event["timestamp"]
            timestamp_max = max(timestamp_max, event["timestamp"]) if timestamp_max else event["timestamp"]
        if "purplesharp" in str(event.get("process_name", "")).casefold() and eid in {"1", "4688"}:
            launches.append({"source_file": raw_path.name, "raw_record_ref": reference, "canonical_fields": event,
                             "status": "observed", "interpretation": "Launch arguments express requested simulation; not proof of technique execution or success."})
        if event.get("provider") != SECURITY or eid not in AUTH_IDS:
            continue
        for field in RAW_FIELDS:
            if scalar(raw.get(field)) is None:
                missing[eid][field] += 1
            if isinstance(raw.get(field), (list, dict)):
                multivalued[eid][field] += 1
        original = {k: raw[k] for k in RAW_FIELDS if k in raw}
        event_time = scalar(raw.get("EventTime"))
        if event_time and event.get("timestamp") and event_time[:19].replace(" ", "T") != event["timestamp"][:19]:
            conflicts += 1
        observations.append({"observation_id": stable_id("auth", [raw_path.name, reference]), "source_file": raw_path.name,
                             "raw_record_ref": reference, "timestamp": event.get("timestamp"), "event_id": eid,
                             "host": event.get("host"), "target_account": scalar(raw.get("TargetUserName")),
                             "target_domain": scalar(raw.get("TargetDomainName")),
                             "source_workstation": scalar(raw.get("WorkstationName")) or scalar(raw.get("Workstation")),
                             "source_ip": scalar(raw.get("IpAddress")), "outcome": outcome(eid, raw),
                             "original_fields": original, "canonical_fields": event, "status": "observed"})
    if any(digest(p) != before[str(p)] for p in (raw_path, canonical_path)):
        raise ValueError(f"Input changed during authentication survey: {raw_path.name}")
    profiles = {}
    for eid in sorted(AUTH_IDS):
        rows = [o for o in observations if o["event_id"] == eid]
        profiles[eid] = {
            "count": len(rows),
            "start": min((o["timestamp"] for o in rows if o["timestamp"]), default=None),
            "end": max((o["timestamp"] for o in rows if o["timestamp"]), default=None),
            "distributions": {field: dict(sorted(Counter(str(o.get(field)) for o in rows).items()))
                              for field in ("host", "target_account", "target_domain", "source_workstation", "source_ip", "outcome")},
            "original_field_distributions": {field: dict(sorted(Counter(str(o["original_fields"].get(field)) for o in rows).items()))
                                             for field in ("SubjectUserName", "Status", "SubStatus", "LogonType", "AuthenticationPackageName", "ServiceName", "TicketOptions", "TicketEncryptionType")}}
    return {"schema_version": "authentication-survey/v1", "review_status": "pending_human_review",
            "input_provenance": [{"path": str(p.resolve()), "sha256": before[str(p)]} for p in (raw_path, canonical_path)],
            "source_file": raw_path.name, "raw_records_read": count, "canonical_records_read": count,
            "raw_canonical_equal_records": count, "dropped_records": 0, "format": fmt.source_format, "encoding": fmt.encoding,
            "event_ids": dict(sorted(counts.items())), "providers": dict(sorted(providers.items())),
            "time_window": {"start": timestamp_min, "end": timestamp_max},
            "auth_event_ids": {eid: sum(o["event_id"] == eid for o in observations) for eid in sorted(AUTH_IDS)},
            "authentication_profiles": profiles,
            "missing_fields_by_event": {k: dict(v) for k, v in sorted(missing.items())},
            "multivalued_fields_by_event": {k: dict(v) for k, v in sorted(multivalued.items())},
            "auth_eventtime_vs_canonical_conflicts": conflicts, "observations": observations, "launch_intent": launches,
            "timestamp_policy": "Use existing canonical timestamp unchanged. Preserve timezone-naive EventTime and @timestamp differences; no timezone correction.",
            "mapping": {"target_account": "raw.TargetUserName", "target_domain": "raw.TargetDomainName",
                        "source_workstation": "raw.WorkstationName or raw.Workstation", "source_ip": "raw.IpAddress (dash -> null)",
                        "destination_host": "canonical.host from raw.Hostname; collection host is not the destination",
                        "status/sub_status/logon_type/tickets": "raw original fields; canonical v2 does not represent these"}}


def _failure_code(item: dict) -> str | None:
    raw = item["original_fields"]
    return scalar(raw.get("SubStatus")) or scalar(raw.get("Status"))


def _compatible(left: dict, right: dict, tolerance: float) -> bool:
    if left["source_file"] != right["source_file"] or left["outcome"] != "failure" or right["outcome"] != "failure":
        return False
    for field in ("target_account", "source_workstation"):
        a, b = scalar(left.get(field)), scalar(right.get(field))
        if a is None or b is None or a.casefold() != b.casefold():
            return False
    for field in ("target_domain", "source_ip"):
        a, b = scalar(left.get(field)), scalar(right.get(field))
        if a is not None and b is not None and a.casefold() != b.casefold():
            return False
    a, b = _failure_code(left), _failure_code(right)
    if a is None or b is None or a.casefold() != b.casefold():
        return False
    a, b = time_value(left.get("timestamp")), time_value(right.get("timestamp"))
    return a is not None and b is not None and abs((a - b).total_seconds()) <= tolerance


def correlate_failures(observations: list[dict], *, tolerance_seconds: float = 1.0) -> dict[str, Any]:
    """Pair only mutually unique endpoint/DC views; retain ambiguous candidates.

    Same account name in another domain/IP is never silently merged. A missing
    domain in 4776 is a recorded weakness. Ambiguous components are excluded from
    threshold decisions rather than inflating counts or inventing a unique match.
    """
    if tolerance_seconds < 0:
        raise ValueError("tolerance_seconds must be nonnegative")
    failures = [o for o in observations if o["event_id"] in {"4625", "4776"} and o["outcome"] == "failure"]
    candidates: dict[str, list[str]] = defaultdict(list)
    by_id = {o["observation_id"]: o for o in failures}
    for left in failures:
        if left["event_id"] != "4625":
            continue
        for right in failures:
            if right["event_id"] == "4776" and _compatible(left, right, tolerance_seconds):
                candidates[left["observation_id"]].append(right["observation_id"])
                candidates[right["observation_id"]].append(left["observation_id"])
    used: set[str] = set()
    attempts = []
    ambiguous = []
    for item in failures:
        oid = item["observation_id"]
        if oid in used:
            continue
        links = candidates[oid]
        if links and (len(links) != 1 or len(candidates[links[0]]) != 1):
            ambiguous.append({"observation_id": oid, "candidate_observation_ids": sorted(links), "status": "unresolved"})
            continue
        group = [item] + ([by_id[links[0]]] if links else [])
        # Anchor to endpoint timestamp when present; retain both original times.
        group.sort(key=lambda o: (o["event_id"], o["raw_record_ref"]))
        primary = group[0]
        used.update(o["observation_id"] for o in group)
        source = primary.get("source_workstation") or primary.get("source_ip")
        source_kind = "workstation" if primary.get("source_workstation") else "ip" if primary.get("source_ip") else None
        endpoint = next((o for o in group if o["event_id"] == "4625"), None)
        context = {"kind": source_kind, "value": source, "domain": primary.get("target_domain"),
                   "endpoint_host": endpoint.get("host") if endpoint else None,
                   "caller_process": endpoint["original_fields"].get("ProcessName") if endpoint else None,
                   "caller_pid": endpoint["original_fields"].get("ProcessId") if endpoint else None}
        attempts.append({"attempt_id": stable_id("attempt", [o["observation_id"] for o in group]),
                         "timestamp": primary["timestamp"], "source_context": context,
                         "target_account": primary["target_account"], "target_domain": primary.get("target_domain"),
                         "observation_ids": [o["observation_id"] for o in group],
                         "raw_record_refs": [o["raw_record_ref"] for o in group],
                         "status": "inferred" if len(group) == 2 else "observed",
                         "correlation_basis": "mutually_unique_account_workstation_failure_code_within_tolerance" if len(group) == 2 else "single_view",
                         "limitations": ["4776 target domain absent; pairing is inferred, not a shared attempt ID"] if len(group) == 2 and any(o.get("target_domain") is None for o in group) else []})
    return {"schema_version": "authentication-correlation/v1", "review_status": "pending_human_review",
            "tolerance_seconds": tolerance_seconds, "failure_observations": len(failures),
            "paired_attempts": sum(len(a["observation_ids"]) == 2 for a in attempts),
            "countable_attempts": len(attempts), "ambiguous_observations": ambiguous,
            "attempts": sorted(attempts, key=lambda a: (a["timestamp"] or "", a["attempt_id"]))}


def detect_spraying(attempts: list[dict], *, window_seconds: float = 60, min_accounts: int = 5) -> list[dict]:
    """Sliding distinct-account windows over deduplicated, source-bound attempts."""
    if window_seconds <= 0 or min_accounts < 2:
        raise ValueError("Positive window and at least two accounts required")
    groups: dict[str, list[dict]] = defaultdict(list)
    for attempt in attempts:
        if attempt.get("target_account") and attempt["source_context"].get("value") and time_value(attempt["timestamp"]):
            groups[json.dumps(attempt["source_context"], sort_keys=True)].append(attempt)
    findings = []
    for key, items in sorted(groups.items()):
        items.sort(key=lambda a: (a["timestamp"], a["attempt_id"]))
        windows: list[list[dict]] = []
        for index, start in enumerate(items):
            window = [a for a in items[index:] if (time_value(a["timestamp"]) - time_value(start["timestamp"])).total_seconds() <= window_seconds]
            if len({a["target_account"].casefold() for a in window}) >= min_accounts:
                ids = {a["attempt_id"] for a in window}
                if not any(ids <= {a["attempt_id"] for a in previous} for previous in windows):
                    windows.append(window)
        for window in windows:
            refs = [a["attempt_id"] for a in window]
            findings.append({"finding_id": stable_id("spray-candidate", refs), "status": "candidate",
                             "source_context": json.loads(key), "window_seconds": window_seconds, "min_distinct_accounts": min_accounts,
                             "start": window[0]["timestamp"], "end": window[-1]["timestamp"],
                             "duration_seconds": (time_value(window[-1]["timestamp"]) - time_value(window[0]["timestamp"])).total_seconds(),
                             "attempt_ids": refs, "distinct_accounts": sorted({a["target_account"] for a in window}),
                             "assessment": "Concentrated failures across accounts support suspected spraying; password sameness and successful compromise are unobserved."})
    return findings


def assess_logons(observations: list[dict], attempts: list[dict], *, window_seconds: float = 60) -> dict:
    """Investigate success around failures without calling a same-name link compromise."""
    successes = [o for o in observations if o["event_id"] == "4624" and o["outcome"] == "success"]
    links = []
    for attempt in attempts:
        for success in successes:
            user = scalar(success.get("target_account"))
            if not user or user.casefold() != str(attempt.get("target_account")).casefold():
                continue
            failed_time, success_time = time_value(attempt["timestamp"]), time_value(success["timestamp"])
            if failed_time is None or success_time is None:
                continue
            delta = (success_time - failed_time).total_seconds()
            if abs(delta) <= window_seconds:
                links.append({"attempt_id": attempt["attempt_id"], "success_observation_id": success["observation_id"],
                              "success_ref": success["raw_record_ref"], "delta_seconds": delta,
                              "direction": "after_failure" if delta >= 0 else "before_failure",
                              "status": "candidate", "basis": "same_account_name_and_time_only",
                              "limitation": "Domain, source, target, logon type/session may differ; not proof a failed password later succeeded or an account was compromised."})
    privileged_links = []
    privileges = [o for o in observations if o["event_id"] == "4672"]
    for success in successes:
        session = scalar(success["original_fields"].get("TargetLogonId"))
        if session is None or session == "0x0":
            continue
        for context in privileges:
            subject_session = scalar(context["original_fields"].get("SubjectLogonId"))
            subject = scalar(context["original_fields"].get("SubjectUserName"))
            success_time, context_time = time_value(success["timestamp"]), time_value(context["timestamp"])
            if (subject_session and subject and success_time and context_time
                    and subject_session.casefold() == session.casefold()
                    and context["host"] == success["host"] and context["host"] is not None
                    and subject.casefold() == str(success["target_account"]).casefold()
                    and abs((context_time - success_time).total_seconds()) <= 1):
                privileged_links.append({"success_observation_id": success["observation_id"],
                                         "privilege_observation_id": context["observation_id"],
                                         "raw_record_refs": [success["raw_record_ref"], context["raw_record_ref"]],
                                         "status": "inferred", "basis": "same_host_account_logon_id_within_one_second",
                                         "limitation": "Special privileges are session context, not proof of unusual or malicious logon."})
    return {"schema_version": "logon-investigation/v1", "review_status": "pending_human_review",
            "success_count": len(successes), "successes_by_account": dict(Counter(o.get("target_account") for o in successes)),
            "successes_by_host": dict(Counter(o.get("host") for o in successes)),
            "successes_by_logon_type": dict(Counter(str(o["original_fields"].get("LogonType")) for o in successes)),
            "successes_by_source_ip": dict(Counter(str(o.get("source_ip")) for o in successes)),
            "same_name_temporal_candidates": links, "abnormal_login_verdict": "not_established_without_baseline",
            "privileged_logon_context_links": privileged_links,
            "missing_context": ["Historical per-account source/time/device baseline", "Shared failed/successful authentication attempt identifier", "Business context / approved activity"],
            "brute_force_per_account": "Repeated guessing against one account is not established by a single failed observation per account in the correlated group."}
