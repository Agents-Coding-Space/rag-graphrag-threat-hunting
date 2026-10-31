"""Classify, group, and build MSHTA-to-PowerShell process artifacts.

The helpers in this module operate entirely in memory and do not read production
datasets.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from numbers import Real
from pathlib import PureWindowsPath
from typing import Literal, TypeAlias

from threat_hunting.schemas.canonical_mapping import (
    SECURITY_PROVIDER,
    SYSMON_PROVIDER,
)

from .schema import (
    EvidenceItem,
    EvidenceObservation,
    ObservedEntity,
    Relationship,
    ScenarioEvidenceDocument,
    _parse_iso8601_timestamp,
    create_evidence_item,
    create_process_entity,
    create_relationship,
    equivalent_process_id,
)


ProcessCreationKind: TypeAlias = Literal[
    "cmd_to_mshta",
    "mshta_to_powershell",
]


@dataclass(frozen=True)
class ProcessCreationGroup:
    """One classified process creation and its retained telemetry views."""

    kind: ProcessCreationKind
    observations: tuple[Mapping[str, object], ...]
    correlation_status: Literal["inferred"] | None
    correlation_tolerance_seconds: float = 1.0


@dataclass(frozen=True)
class _ClassifiedObservation:
    kind: ProcessCreationKind
    observation: Mapping[str, object]
    provenance: tuple[str, str]
    context: tuple[str, str]


@dataclass(frozen=True)
class _ProcessEntityCandidate:
    entity: ObservedEntity
    pid_rank: tuple[int, str]


_SECURITY_PROCESS_CREATION_CONTEXT = (SECURITY_PROVIDER.casefold(), "4688")
_SYSMON_PROCESS_CREATION_CONTEXT = (SYSMON_PROVIDER.casefold(), "1")
_PROCESS_CREATION_CONTEXTS = frozenset(
    {_SECURITY_PROCESS_CREATION_CONTEXT, _SYSMON_PROCESS_CREATION_CONTEXT}
)
_PROCESS_CREATION_KINDS: dict[tuple[str, str], ProcessCreationKind] = {
    ("cmd.exe", "mshta.exe"): "cmd_to_mshta",
    ("mshta.exe", "powershell.exe"): "mshta_to_powershell",
}
_SUPPORTED_PROCESS_NAMES = frozenset(
    process_name
    for process_pair in _PROCESS_CREATION_KINDS
    for process_name in process_pair
)
_PROCESS_CREATION_SUMMARIES: dict[ProcessCreationKind, str] = {
    "cmd_to_mshta": "cmd.exe spawned mshta.exe",
    "mshta_to_powershell": "mshta.exe spawned powershell.exe",
}
_EVIDENCE_CANONICAL_FIELDS = (
    "host",
    "user",
    "process_name",
    "process_id",
    "parent_process_name",
    "parent_process_id",
    "command_line",
    "process_guid",
    "parent_process_guid",
)
_DOCUMENT_REVIEW_NOTES = (
    "When present, Security 4688 and Sysmon 1 observations are grouped using "
    "inferred telemetry correlation.",
    "Evidence remains draft_reviewable and requires human review; this is not "
    "a confirmed attack conclusion.",
    "Sigma and MITRE ATT&CK mappings are not applied in this milestone.",
)


def normalize_process_name(value: object) -> str | None:
    """Return a comparison-only supported Windows executable basename.

    Original values are never changed. Non-strings, empty values, and strings
    that look like command lines rather than executable paths are rejected.
    """

    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    starts_quoted = candidate.startswith('"')
    ends_quoted = candidate.endswith('"')
    if starts_quoted or ends_quoted:
        if not (starts_quoted and ends_quoted and len(candidate) >= 2):
            return None
        candidate = candidate[1:-1]
        if not candidate or candidate != candidate.strip():
            return None
    if '"' in candidate or candidate.endswith(("\\", "/")):
        return None

    path = PureWindowsPath(candidate)
    basename = path.name
    normalized_basename = basename.casefold()
    if (
        not basename
        or any(part != part.strip() for part in path.parts)
        or any(character.isspace() for character in basename)
        or normalized_basename not in _SUPPORTED_PROCESS_NAMES
    ):
        return None
    return normalized_basename


def _normalize_event_id(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value >= 0 else None
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate if candidate else None


def _process_creation_context(
    event: Mapping[str, object],
) -> tuple[str, str] | None:
    if not isinstance(event, Mapping):
        return None
    provider = event.get("provider")
    if not isinstance(provider, str) or not provider.strip():
        return None
    event_id = _normalize_event_id(event.get("event_id"))
    if event_id is None:
        return None
    context = (provider.strip().casefold(), event_id)
    return context if context in _PROCESS_CREATION_CONTEXTS else None


def classify_process_creation(
    event: Mapping[str, object],
) -> ProcessCreationKind | None:
    """Classify one supported Security 4688 or Sysmon 1 canonical event."""

    if _process_creation_context(event) is None:
        return None

    parent_process = normalize_process_name(event.get("parent_process_name"))
    process = normalize_process_name(event.get("process_name"))
    if parent_process is None or process is None:
        return None
    return _PROCESS_CREATION_KINDS.get((parent_process, process))


def _normalize_host(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().casefold()


def _validated_tolerance_seconds(value: object) -> float:
    message = "tolerance_seconds must be a finite, non-negative number"
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(message)
    try:
        tolerance = float(value)
    except (OverflowError, TypeError, ValueError) as error:
        raise ValueError(message) from error
    if not math.isfinite(tolerance) or tolerance < 0:
        raise ValueError(message)
    return tolerance


def same_process_creation(
    left: Mapping[str, object],
    right: Mapping[str, object],
    *,
    tolerance_seconds: float = 1.0,
) -> bool:
    """Return whether Security 4688 and Sysmon 1 describe one creation.

    This comparison is symmetric and reads canonical fields only. Naive
    timestamps are compared only with naive timestamps; aware timestamps are
    converted to UTC before comparison.
    """

    tolerance = _validated_tolerance_seconds(tolerance_seconds)
    left_context = _process_creation_context(left)
    right_context = _process_creation_context(right)
    if frozenset((left_context, right_context)) != _PROCESS_CREATION_CONTEXTS:
        return False

    left_kind = classify_process_creation(left)
    right_kind = classify_process_creation(right)
    if left_kind is None or left_kind != right_kind:
        return False

    left_host = _normalize_host(left.get("host"))
    right_host = _normalize_host(right.get("host"))
    if left_host is None or left_host != right_host:
        return False
    if not equivalent_process_id(left.get("process_id"), right.get("process_id")):
        return False
    if not equivalent_process_id(
        left.get("parent_process_id"), right.get("parent_process_id")
    ):
        return False

    left_timestamp = _parse_iso8601_timestamp(left.get("timestamp"))
    right_timestamp = _parse_iso8601_timestamp(right.get("timestamp"))
    if left_timestamp is None or right_timestamp is None:
        return False
    left_aware = (
        left_timestamp.tzinfo is not None
        and left_timestamp.utcoffset() is not None
    )
    right_aware = (
        right_timestamp.tzinfo is not None and right_timestamp.utcoffset() is not None
    )
    if left_aware != right_aware:
        return False
    if left_aware:
        left_timestamp = left_timestamp.astimezone(timezone.utc)
        right_timestamp = right_timestamp.astimezone(timezone.utc)
    difference = abs((left_timestamp - right_timestamp).total_seconds())
    return difference <= tolerance


def _required_provenance(event: Mapping[str, object]) -> tuple[str, str]:
    values: list[str] = []
    for field_name in ("source_file", "raw_record_ref"):
        value = event.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                "classified process-creation event requires non-empty "
                f"{field_name}"
            )
        values.append(value)
    return values[0], values[1]


def _group_sort_key(
    group: ProcessCreationGroup,
) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    timestamps = tuple(
        str(observation.get("timestamp") or "")
        for observation in group.observations
    )
    provenance = tuple(
        _required_provenance(observation) for observation in group.observations
    )
    return group.kind, min(timestamps), provenance


def group_process_creations(
    events: Iterable[Mapping[str, object]],
    *,
    tolerance_seconds: float = 1.0,
) -> tuple[ProcessCreationGroup, ...]:
    """Group unambiguous Security/Sysmon views without creating evidence."""

    tolerance = _validated_tolerance_seconds(tolerance_seconds)
    candidates_by_provenance: dict[
        tuple[str, str], _ClassifiedObservation
    ] = {}
    for event in events:
        kind = classify_process_creation(event)
        if kind is None:
            continue
        provenance = _required_provenance(event)
        existing = candidates_by_provenance.get(provenance)
        if existing is not None:
            if dict(existing.observation) != dict(event):
                raise ValueError(
                    "conflicting process-creation events share provenance: "
                    f"source_file={provenance[0]!r}, "
                    f"raw_record_ref={provenance[1]!r}"
                )
            continue
        context = _process_creation_context(event)
        if context is None:  # Defensive: classification already requires a context.
            continue
        candidates_by_provenance[provenance] = _ClassifiedObservation(
            kind=kind,
            observation=event,
            provenance=provenance,
            context=context,
        )

    candidates = tuple(candidates_by_provenance.values())
    security_candidates = tuple(
        candidate
        for candidate in candidates
        if candidate.context == _SECURITY_PROCESS_CREATION_CONTEXT
    )
    sysmon_candidates = tuple(
        candidate
        for candidate in candidates
        if candidate.context == _SYSMON_PROCESS_CREATION_CONTEXT
    )
    sysmon_matches_by_security: dict[tuple[str, str], set[tuple[str, str]]] = {
        candidate.provenance: set() for candidate in security_candidates
    }
    security_matches_by_sysmon: dict[tuple[str, str], set[tuple[str, str]]] = {
        candidate.provenance: set() for candidate in sysmon_candidates
    }
    for security in security_candidates:
        for sysmon in sysmon_candidates:
            if same_process_creation(
                security.observation,
                sysmon.observation,
                tolerance_seconds=tolerance,
            ):
                sysmon_matches_by_security[security.provenance].add(
                    sysmon.provenance
                )
                security_matches_by_sysmon[sysmon.provenance].add(
                    security.provenance
                )

    paired_provenance: set[tuple[str, str]] = set()
    groups: list[ProcessCreationGroup] = []
    for security in security_candidates:
        sysmon_matches = sysmon_matches_by_security[security.provenance]
        if len(sysmon_matches) != 1:
            continue
        sysmon_provenance = next(iter(sysmon_matches))
        if len(security_matches_by_sysmon[sysmon_provenance]) != 1:
            continue
        sysmon = candidates_by_provenance[sysmon_provenance]
        groups.append(
            ProcessCreationGroup(
                kind=security.kind,
                observations=(security.observation, sysmon.observation),
                correlation_status="inferred",
                correlation_tolerance_seconds=tolerance,
            )
        )
        paired_provenance.update((security.provenance, sysmon.provenance))

    for candidate in candidates:
        if candidate.provenance in paired_provenance:
            continue
        groups.append(
            ProcessCreationGroup(
                kind=candidate.kind,
                observations=(candidate.observation,),
                correlation_status=None,
                correlation_tolerance_seconds=tolerance,
            )
        )
    return tuple(sorted(groups, key=_group_sort_key))


def _validated_evidence_group(
    group: ProcessCreationGroup,
) -> tuple[Mapping[str, object], ...]:
    if not isinstance(group, ProcessCreationGroup):
        raise ValueError("group must be a ProcessCreationGroup")
    if group.kind not in _PROCESS_CREATION_SUMMARIES:
        raise ValueError(f"unsupported process-creation group kind: {group.kind!r}")
    tolerance = _validated_tolerance_seconds(
        group.correlation_tolerance_seconds
    )
    observations = group.observations
    if len(observations) not in (1, 2):
        raise ValueError("process-creation group must contain one or two observations")

    for observation in observations:
        if not isinstance(observation, Mapping):
            raise ValueError("group observations must be mappings")
        _required_provenance(observation)
        if classify_process_creation(observation) != group.kind:
            raise ValueError("group kind does not match every observation")

    if len(observations) == 1:
        if group.correlation_status is not None:
            raise ValueError("singleton group correlation_status must be None")
        return observations

    if group.correlation_status != "inferred":
        raise ValueError("paired group correlation_status must be inferred")
    contexts = tuple(_process_creation_context(item) for item in observations)
    expected_contexts = (
        _SECURITY_PROCESS_CREATION_CONTEXT,
        _SYSMON_PROCESS_CREATION_CONTEXT,
    )
    if contexts != expected_contexts:
        raise ValueError(
            "paired group must contain Security 4688 first and Sysmon 1 second"
        )
    if not same_process_creation(
        observations[0],
        observations[1],
        tolerance_seconds=tolerance,
    ):
        raise ValueError("paired observations do not describe the same process creation")
    return observations


def _evidence_observation(event: Mapping[str, object]) -> EvidenceObservation:
    source_file, raw_record_ref = _required_provenance(event)
    raw_fields = event.get("raw_fields", {})
    if not isinstance(raw_fields, Mapping):
        raise ValueError("raw_fields must be a mapping when provided")
    canonical_fields = {
        field_name: event[field_name]
        for field_name in _EVIDENCE_CANONICAL_FIELDS
        if field_name in event and event[field_name] is not None
    }
    return EvidenceObservation(
        source_file=source_file,
        raw_record_ref=raw_record_ref,
        provider=(
            str(event["provider"]) if event.get("provider") is not None else None
        ),
        event_id=(
            str(event["event_id"]) if event.get("event_id") is not None else None
        ),
        timestamp=(
            str(event["timestamp"]) if event.get("timestamp") is not None else None
        ),
        canonical_fields=canonical_fields,
        raw_fields=raw_fields,
    )


def build_process_creation_evidence(
    group: ProcessCreationGroup,
) -> dict[str, object]:
    """Build one reviewable observed evidence item from a validated group."""

    group_observations = _validated_evidence_group(group)
    observations = tuple(
        _evidence_observation(event) for event in group_observations
    )
    paired = len(observations) == 2
    reason = (
        "Parent and child process fields are observed directly in both telemetry "
        "events. The Security and Sysmon observations are inferred to describe "
        "the same process creation."
        if paired
        else "Parent and child process fields are observed directly in one "
        "telemetry event."
    )
    evidence = create_evidence_item(
        evidence_type="process_creation",
        status="observed",
        summary=_PROCESS_CREATION_SUMMARIES[group.kind],
        observations=observations,
        reason=reason,
        review_status="needs_review",
    )
    result = evidence.to_dict()
    result["observations"] = [
        observation.to_dict() for observation in observations
    ]
    return result


def _normalized_process_guid(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().casefold()


def _pid_preference(
    event: Mapping[str, object],
    process_id: object,
) -> tuple[int, str]:
    if isinstance(process_id, int) and not isinstance(process_id, bool):
        decimal = True
    elif isinstance(process_id, str):
        candidate = process_id.strip()
        decimal = candidate.isascii() and candidate.isdecimal()
    else:
        decimal = False
    sysmon = _process_creation_context(event) == _SYSMON_PROCESS_CREATION_CONTEXT
    if sysmon and decimal:
        priority = 0
    elif sysmon:
        priority = 1
    elif decimal:
        priority = 2
    else:
        priority = 3
    return priority, f"{type(process_id).__name__}:{process_id!s}"


def _process_endpoint_candidate(
    observations: tuple[Mapping[str, object], ...],
    *,
    parent: bool,
) -> _ProcessEntityCandidate:
    endpoint_name = "source" if parent else "target"
    name_field = "parent_process_name" if parent else "process_name"
    pid_field = "parent_process_id" if parent else "process_id"
    guid_field = "parent_process_guid" if parent else "process_guid"

    hosts: list[str] = []
    process_names: list[str] = []
    process_guids: set[str] = set()
    pid_options: list[
        tuple[tuple[int, str], Mapping[str, object], object]
    ] = []
    for observation in observations:
        host = observation.get("host")
        if not isinstance(host, str) or not host.strip():
            raise ValueError(
                f"{endpoint_name} process endpoint requires a non-empty host"
            )
        hosts.append(host.strip())

        process_name = normalize_process_name(observation.get(name_field))
        if process_name is None:
            raise ValueError(
                f"{endpoint_name} process endpoint requires a valid {name_field}"
            )
        process_names.append(process_name)

        process_guid = _normalized_process_guid(observation.get(guid_field))
        if process_guid is not None:
            process_guids.add(process_guid)

        process_id = observation.get(pid_field)
        if equivalent_process_id(process_id, process_id):
            pid_options.append(
                (_pid_preference(observation, process_id), observation, process_id)
            )

    if len({host.casefold() for host in hosts}) != 1:
        raise ValueError(f"conflicting hosts in {endpoint_name} process endpoint")
    if len(set(process_names)) != 1:
        raise ValueError(
            f"conflicting process names in {endpoint_name} process endpoint"
        )
    if len(process_guids) > 1:
        raise ValueError(
            f"conflicting process GUIDs in {endpoint_name} process endpoint"
        )
    if pid_options:
        first_pid = pid_options[0][2]
        if any(
            not equivalent_process_id(first_pid, option[2])
            for option in pid_options[1:]
        ):
            raise ValueError(
                f"conflicting process IDs in {endpoint_name} process endpoint"
            )

    host = min(hosts, key=lambda value: (value.casefold(), value))
    process_name = process_names[0]
    process_guid = next(iter(process_guids), None)
    ordered_pid_options = sorted(pid_options, key=lambda option: option[0])
    if process_guid is not None:
        if ordered_pid_options:
            pid_rank, representative, process_id = ordered_pid_options[0]
        else:
            pid_rank = (4, "")
            representative = observations[0]
            process_id = None
        timestamp = representative.get("timestamp")
        entity = create_process_entity(
            host=host,
            process_name=process_name,
            process_id=process_id,
            process_guid=process_guid,
            timestamp=timestamp if isinstance(timestamp, str) else "",
        )
        return _ProcessEntityCandidate(entity=entity, pid_rank=pid_rank)

    for pid_rank, representative, process_id in ordered_pid_options:
        timestamp = representative.get("timestamp")
        if not isinstance(timestamp, str):
            continue
        try:
            entity = create_process_entity(
                host=host,
                process_name=process_name,
                process_id=process_id,
                process_guid=None,
                timestamp=timestamp,
            )
        except ValueError:
            continue
        return _ProcessEntityCandidate(entity=entity, pid_rank=pid_rank)

    raise ValueError(
        f"{endpoint_name} process endpoint requires ProcessGuid or valid "
        "host + process_id + timestamp identity"
    )


def _merge_process_entity_candidates(
    left: _ProcessEntityCandidate,
    right: _ProcessEntityCandidate,
) -> _ProcessEntityCandidate:
    if left.entity.entity_id != right.entity.entity_id:
        raise ValueError("cannot merge process entities with different identities")
    left_attributes = left.entity.attributes
    right_attributes = right.entity.attributes
    left_host = str(left_attributes["host"])
    right_host = str(right_attributes["host"])
    if left_host.casefold() != right_host.casefold():
        raise ValueError("conflicting hosts for the same process entity identity")
    left_name = str(left_attributes["process_name"])
    right_name = str(right_attributes["process_name"])
    if left_name != right_name:
        raise ValueError("conflicting process names for the same entity identity")

    left_guid = _normalized_process_guid(left_attributes.get("process_guid"))
    right_guid = _normalized_process_guid(right_attributes.get("process_guid"))
    if left_guid != right_guid:
        raise ValueError("conflicting process GUIDs for the same entity identity")
    left_pid = left_attributes.get("process_id")
    right_pid = right_attributes.get("process_id")
    left_pid_valid = equivalent_process_id(left_pid, left_pid)
    right_pid_valid = equivalent_process_id(right_pid, right_pid)
    if (
        left_pid_valid
        and right_pid_valid
        and not equivalent_process_id(left_pid, right_pid)
    ):
        raise ValueError("conflicting process IDs for the same entity identity")

    representative = min((left, right), key=lambda item: item.pid_rank)
    process_id = representative.entity.attributes.get("process_id")
    if not equivalent_process_id(process_id, process_id):
        if left_pid_valid:
            representative = left
            process_id = left_pid
        elif right_pid_valid:
            representative = right
            process_id = right_pid
    host = min((left_host, right_host), key=lambda value: (value.casefold(), value))
    if left_guid is None:
        left_timestamp = left_attributes.get("identity_timestamp")
        right_timestamp = right_attributes.get("identity_timestamp")
        if left_timestamp != right_timestamp or not isinstance(left_timestamp, str):
            raise ValueError(
                "conflicting identity timestamps for the same process entity identity"
            )
        timestamp = left_timestamp
    else:
        timestamp = ""
    entity = create_process_entity(
        host=host,
        process_name=left_name,
        process_id=process_id,
        process_guid=left_guid,
        timestamp=timestamp,
    )
    if entity.entity_id != left.entity.entity_id:
        raise ValueError("merged process entity changed deterministic identity")
    return _ProcessEntityCandidate(entity=entity, pid_rank=representative.pid_rank)


def build_process_entities(
    groups: Iterable[ProcessCreationGroup],
) -> tuple[dict[str, object], ...]:
    """Build deterministic, deduplicated source and target process entities."""

    entities_by_id: dict[str, _ProcessEntityCandidate] = {}
    for group in groups:
        observations = _validated_evidence_group(group)
        for parent in (True, False):
            candidate = _process_endpoint_candidate(observations, parent=parent)
            entity_id = candidate.entity.entity_id
            existing = entities_by_id.get(entity_id)
            if existing is not None:
                candidate = _merge_process_entity_candidates(existing, candidate)
            entities_by_id[entity_id] = candidate
    return tuple(
        entities_by_id[entity_id].entity.to_dict()
        for entity_id in sorted(entities_by_id)
    )


def _required_artifact_id(
    artifact: Mapping[str, object],
    field_name: str,
    artifact_name: str,
) -> str:
    value = artifact.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{artifact_name} must contain a non-empty {field_name}"
        )
    return value


def build_process_spawn_relationships(
    groups: Iterable[ProcessCreationGroup],
) -> tuple[dict[str, object], ...]:
    """Build observed process-spawn relationships with valid references."""

    materialized_groups = tuple(groups)
    if not materialized_groups:
        return ()

    entities = build_process_entities(materialized_groups)
    entity_ids = {
        _required_artifact_id(entity, "entity_id", "process entity")
        for entity in entities
    }
    if len(entity_ids) != len(entities):
        raise ValueError("process entity IDs must be unique")

    evidence_ids: set[str] = set()
    relationship_support: dict[tuple[str, str, str], set[str]] = {}
    for group in materialized_groups:
        observations = _validated_evidence_group(group)
        evidence = build_process_creation_evidence(group)
        evidence_id = _required_artifact_id(
            evidence,
            "evidence_id",
            "process-creation evidence",
        )
        evidence_ids.add(evidence_id)

        source_entity_id = _process_endpoint_candidate(
            observations,
            parent=True,
        ).entity.entity_id
        target_entity_id = _process_endpoint_candidate(
            observations,
            parent=False,
        ).entity.entity_id
        if source_entity_id not in entity_ids:
            raise ValueError(
                "process-spawn source endpoint does not resolve to an entity"
            )
        if target_entity_id not in entity_ids:
            raise ValueError(
                "process-spawn target endpoint does not resolve to an entity"
            )
        key = ("process_spawn", source_entity_id, target_entity_id)
        relationship_support.setdefault(key, set()).add(evidence_id)

    relationships = []
    for (relationship_type, source_entity_id, target_entity_id), supported_by in (
        sorted(relationship_support.items())
    ):
        missing_evidence = supported_by - evidence_ids
        if missing_evidence:
            raise ValueError(
                "process-spawn relationship references missing evidence: "
                f"{sorted(missing_evidence)}"
            )
        relationship = create_relationship(
            relationship_type=relationship_type,
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            status="observed",
            supported_by=supported_by,
            review_status="needs_review",
        )
        if relationship.source_entity_id not in entity_ids:
            raise ValueError("relationship source entity does not exist")
        if relationship.target_entity_id not in entity_ids:
            raise ValueError("relationship target entity does not exist")
        if set(relationship.supported_by) - evidence_ids:
            raise ValueError("relationship evidence reference does not exist")
        relationships.append(relationship)
    return tuple(
        relationship.to_dict()
        for relationship in sorted(
            relationships,
            key=lambda item: item.relationship_id,
        )
    )


def _document_sources_and_time_window(
    groups: tuple[ProcessCreationGroup, ...],
) -> tuple[tuple[str, ...], dict[str, object]]:
    source_files: set[str] = set()
    timestamp_candidates: list[tuple[datetime, str, str, str]] = []
    timestamp_awareness: bool | None = None
    for group in groups:
        for observation in _validated_evidence_group(group):
            source_file, raw_record_ref = _required_provenance(observation)
            source_files.add(source_file)
            timestamp = observation.get("timestamp")
            parsed = _parse_iso8601_timestamp(timestamp)
            if parsed is None or not isinstance(timestamp, str):
                raise ValueError(
                    "process-creation observation requires a valid canonical "
                    "timestamp"
                )
            aware = parsed.tzinfo is not None and parsed.utcoffset() is not None
            if timestamp_awareness is None:
                timestamp_awareness = aware
            elif timestamp_awareness != aware:
                raise ValueError(
                    "cannot mix naive and aware canonical timestamps in a "
                    "scenario evidence document"
                )
            comparison_timestamp = (
                parsed.astimezone(timezone.utc) if aware else parsed
            )
            timestamp_candidates.append(
                (
                    comparison_timestamp,
                    timestamp,
                    source_file,
                    raw_record_ref,
                )
            )

    if not timestamp_candidates:
        return (), {"start": None, "end": None}
    sort_key = lambda item: (item[0], item[1], item[2], item[3])
    return tuple(sorted(source_files)), {
        "start": min(timestamp_candidates, key=sort_key)[1],
        "end": max(timestamp_candidates, key=sort_key)[1],
    }


def _document_entity(artifact: Mapping[str, object]) -> ObservedEntity:
    attributes = artifact.get("attributes")
    if not isinstance(attributes, Mapping):
        raise ValueError("process entity attributes must be a mapping")
    return ObservedEntity(
        entity_id=_required_artifact_id(
            artifact,
            "entity_id",
            "process entity",
        ),
        entity_type=_required_artifact_id(
            artifact,
            "entity_type",
            "process entity",
        ),
        attributes=attributes,
    )


def _document_observation(
    artifact: Mapping[str, object],
) -> EvidenceObservation:
    canonical_fields = artifact.get("canonical_fields")
    raw_fields = artifact.get("raw_fields")
    if not isinstance(canonical_fields, Mapping):
        raise ValueError("evidence observation canonical_fields must be a mapping")
    if not isinstance(raw_fields, Mapping):
        raise ValueError("evidence observation raw_fields must be a mapping")
    provider = artifact.get("provider")
    event_id = artifact.get("event_id")
    timestamp = artifact.get("timestamp")
    return EvidenceObservation(
        source_file=_required_artifact_id(
            artifact,
            "source_file",
            "evidence observation",
        ),
        raw_record_ref=_required_artifact_id(
            artifact,
            "raw_record_ref",
            "evidence observation",
        ),
        provider=provider if isinstance(provider, str) else None,
        event_id=event_id if isinstance(event_id, str) else None,
        timestamp=timestamp if isinstance(timestamp, str) else None,
        canonical_fields=canonical_fields,
        raw_fields=raw_fields,
    )


def _document_evidence(artifact: Mapping[str, object]) -> EvidenceItem:
    observation_artifacts = artifact.get("observations")
    if not isinstance(observation_artifacts, list) or any(
        not isinstance(item, Mapping) for item in observation_artifacts
    ):
        raise ValueError("evidence observations must be a list of mappings")
    return EvidenceItem(
        evidence_id=_required_artifact_id(
            artifact,
            "evidence_id",
            "process-creation evidence",
        ),
        evidence_type=_required_artifact_id(
            artifact,
            "evidence_type",
            "process-creation evidence",
        ),
        status=_required_artifact_id(
            artifact,
            "status",
            "process-creation evidence",
        ),
        summary=_required_artifact_id(
            artifact,
            "summary",
            "process-creation evidence",
        ),
        observations=tuple(
            _document_observation(item) for item in observation_artifacts
        ),
        reason=_required_artifact_id(
            artifact,
            "reason",
            "process-creation evidence",
        ),
        review_status=_required_artifact_id(
            artifact,
            "review_status",
            "process-creation evidence",
        ),
    )


def _document_relationship(artifact: Mapping[str, object]) -> Relationship:
    supported_by = artifact.get("supported_by")
    if not isinstance(supported_by, list) or any(
        not isinstance(item, str) for item in supported_by
    ):
        raise ValueError("relationship supported_by must be a list of strings")
    return Relationship(
        relationship_id=_required_artifact_id(
            artifact,
            "relationship_id",
            "process-spawn relationship",
        ),
        relationship_type=_required_artifact_id(
            artifact,
            "relationship_type",
            "process-spawn relationship",
        ),
        source_entity_id=_required_artifact_id(
            artifact,
            "source_entity_id",
            "process-spawn relationship",
        ),
        target_entity_id=_required_artifact_id(
            artifact,
            "target_entity_id",
            "process-spawn relationship",
        ),
        status=_required_artifact_id(
            artifact,
            "status",
            "process-spawn relationship",
        ),
        supported_by=tuple(supported_by),
        review_status=_required_artifact_id(
            artifact,
            "review_status",
            "process-spawn relationship",
        ),
    )


def build_mshta_powershell_evidence_document(
    groups: Iterable[ProcessCreationGroup],
) -> dict[str, object]:
    """Assemble validated process groups into scenario-evidence/v1."""

    materialized_groups = tuple(groups)
    source_files, time_window = _document_sources_and_time_window(
        materialized_groups
    )
    entity_artifacts = build_process_entities(materialized_groups)

    evidence_by_id: dict[str, dict[str, object]] = {}
    for group in materialized_groups:
        artifact = build_process_creation_evidence(group)
        evidence_id = _required_artifact_id(
            artifact,
            "evidence_id",
            "process-creation evidence",
        )
        existing = evidence_by_id.get(evidence_id)
        if existing is not None and existing != artifact:
            raise ValueError(
                "conflicting process-creation evidence shares an evidence_id"
            )
        evidence_by_id[evidence_id] = artifact

    relationship_artifacts = build_process_spawn_relationships(
        materialized_groups
    )
    document = ScenarioEvidenceDocument(
        scenario_id="mshta-powershell",
        scenario_name="MSHTA spawning PowerShell",
        source_files=source_files,
        time_window=time_window,
        observed_entities=tuple(
            _document_entity(artifact) for artifact in entity_artifacts
        ),
        evidence=tuple(
            _document_evidence(evidence_by_id[evidence_id])
            for evidence_id in sorted(evidence_by_id)
        ),
        relationships=tuple(
            _document_relationship(artifact)
            for artifact in sorted(
                relationship_artifacts,
                key=lambda item: str(item.get("relationship_id") or ""),
            )
        ),
        sigma_rules=(),
        mitre_techniques=(),
        review_notes=_DOCUMENT_REVIEW_NOTES,
    )
    return document.to_dict()


def extract_mshta_powershell_evidence(
    events: Iterable[Mapping[str, object]],
    *,
    correlation_tolerance_seconds: float = 1.0,
) -> dict[str, object]:
    """Extract one in-memory scenario-evidence document from canonical events."""

    groups = group_process_creations(
        events,
        tolerance_seconds=correlation_tolerance_seconds,
    )
    return build_mshta_powershell_evidence_document(groups)


__all__ = (
    "ProcessCreationKind",
    "ProcessCreationGroup",
    "build_mshta_powershell_evidence_document",
    "build_process_creation_evidence",
    "build_process_entities",
    "build_process_spawn_relationships",
    "classify_process_creation",
    "extract_mshta_powershell_evidence",
    "group_process_creations",
    "normalize_process_name",
    "same_process_creation",
)
