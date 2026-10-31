"""Versioned, reviewable scenario-evidence data contract.

This module does not read datasets, execute Sigma, or assign ATT&CK techniques.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence


SCENARIO_EVIDENCE_SCHEMA_VERSION = "scenario-evidence/v1"
ANALYSIS_STATUS_DRAFT_REVIEWABLE = "draft_reviewable"
EVIDENCE_STATUSES = ("observed", "inferred", "candidate", "confirmed")
AUTOMATIC_EVIDENCE_STATUSES = ("observed", "inferred", "candidate")
REVIEW_STATUSES = ("needs_review", "reviewed", "rejected")

SCENARIO_EVIDENCE_FIELDS = (
    "schema_version",
    "scenario_id",
    "scenario_name",
    "source_files",
    "analysis_status",
    "time_window",
    "observed_entities",
    "evidence",
    "relationships",
    "sigma_rules",
    "mitre_techniques",
    "review_notes",
)

def _require_nonempty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _copied_sorted_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    copied = {str(key): copy.deepcopy(item) for key, item in value.items()}
    return MappingProxyType(dict(sorted(copied.items())))


def _plain_mapping(value: Mapping[str, object]) -> dict[str, object]:
    return {key: copy.deepcopy(item) for key, item in value.items()}


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _deterministic_id(prefix: str, identity: object) -> str:
    digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:20]}"


def _parse_process_id(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parsed = int(candidate, 16 if candidate.lower().startswith("0x") else 10)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def equivalent_process_id(left: object, right: object) -> bool:
    """Compare valid decimal/hexadecimal PIDs without changing stored values."""

    parsed_left = _parse_process_id(left)
    parsed_right = _parse_process_id(right)
    return parsed_left is not None and parsed_right is not None and parsed_left == parsed_right


def _parse_iso8601_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith(("Z", "z")):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _parse_timestamp(value: object) -> datetime | None:
    if isinstance(value, str) and value.strip().endswith("z"):
        return None
    parsed = _parse_iso8601_timestamp(value)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _validated_time_window(
    value: object,
    *,
    empty_document: bool,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("time_window must be a mapping")
    if len(value) != 2 or set(value) != {"start", "end"}:
        raise ValueError("time_window must contain exactly start and end")

    start = value["start"]
    end = value["end"]
    if start is None and end is None:
        return _copied_sorted_mapping(value)
    if start is None or end is None:
        raise ValueError(
            "time_window start and end must both be null or both be timestamps"
        )
    if empty_document:
        raise ValueError("empty scenario evidence requires a null time_window")

    parsed_start = _parse_iso8601_timestamp(start)
    parsed_end = _parse_iso8601_timestamp(end)
    if parsed_start is None or parsed_end is None:
        raise ValueError(
            "time_window start and end must be valid ISO 8601 strings"
        )
    start_aware = (
        parsed_start.tzinfo is not None
        and parsed_start.utcoffset() is not None
    )
    end_aware = parsed_end.tzinfo is not None and parsed_end.utcoffset() is not None
    if start_aware != end_aware:
        raise ValueError(
            "time_window start and end must both be aware or both be naive"
        )
    if parsed_start > parsed_end:
        raise ValueError("time_window start must not be after end")
    return _copied_sorted_mapping(value)


@dataclass(frozen=True)
class EvidenceObservation:
    source_file: str
    raw_record_ref: str
    provider: str | None
    event_id: str | None
    timestamp: str | None
    canonical_fields: Mapping[str, object]
    raw_fields: Mapping[str, object]

    def __post_init__(self) -> None:
        _require_nonempty_string(self.source_file, "source_file")
        _require_nonempty_string(self.raw_record_ref, "raw_record_ref")
        object.__setattr__(self, "canonical_fields", _copied_sorted_mapping(self.canonical_fields))
        object.__setattr__(self, "raw_fields", _copied_sorted_mapping(self.raw_fields))

    def to_dict(self) -> dict[str, object]:
        return {
            "source_file": self.source_file,
            "raw_record_ref": self.raw_record_ref,
            "provider": self.provider,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "canonical_fields": _plain_mapping(self.canonical_fields),
            "raw_fields": _plain_mapping(self.raw_fields),
        }


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    evidence_type: str
    status: str
    summary: str
    observations: tuple[EvidenceObservation, ...]
    reason: str
    review_status: str = "needs_review"

    def __post_init__(self) -> None:
        _require_nonempty_string(self.evidence_id, "evidence_id")
        _require_nonempty_string(self.evidence_type, "evidence_type")
        _require_nonempty_string(self.summary, "summary")
        _require_nonempty_string(self.reason, "reason")
        if self.status not in EVIDENCE_STATUSES:
            raise ValueError(f"unsupported evidence status: {self.status}")
        if self.review_status not in REVIEW_STATUSES:
            raise ValueError(f"unsupported review status: {self.review_status}")
        if not self.observations:
            raise ValueError("evidence must contain at least one observation")

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "status": self.status,
            "summary": self.summary,
            "observations": [observation.to_dict() for observation in self.observations],
            "reason": self.reason,
            "review_status": self.review_status,
        }


@dataclass(frozen=True)
class ObservedEntity:
    entity_id: str
    entity_type: str
    attributes: Mapping[str, object]

    def __post_init__(self) -> None:
        _require_nonempty_string(self.entity_id, "entity_id")
        _require_nonempty_string(self.entity_type, "entity_type")
        object.__setattr__(self, "attributes", _copied_sorted_mapping(self.attributes))
        if self.entity_type == "process":
            _require_nonempty_string(self.attributes.get("host"), "attributes.host")
            _require_nonempty_string(
                self.attributes.get("process_name"), "attributes.process_name"
            )
            guid = self.attributes.get("process_guid")
            if not _require_optional_nonempty(guid):
                if _parse_process_id(self.attributes.get("process_id")) is None:
                    raise ValueError("process identity fallback requires a valid process_id")
                if _parse_timestamp(self.attributes.get("identity_timestamp")) is None:
                    raise ValueError(
                        "process identity fallback requires an identity_timestamp"
                    )

    def to_dict(self) -> dict[str, object]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "attributes": _plain_mapping(self.attributes),
        }


@dataclass(frozen=True)
class Relationship:
    relationship_id: str
    relationship_type: str
    source_entity_id: str
    target_entity_id: str
    status: str
    supported_by: tuple[str, ...]
    review_status: str = "needs_review"

    def __post_init__(self) -> None:
        _require_nonempty_string(self.relationship_id, "relationship_id")
        _require_nonempty_string(self.relationship_type, "relationship_type")
        _require_nonempty_string(self.source_entity_id, "source_entity_id")
        _require_nonempty_string(self.target_entity_id, "target_entity_id")
        if self.status not in EVIDENCE_STATUSES:
            raise ValueError(f"unsupported relationship status: {self.status}")
        if self.review_status not in REVIEW_STATUSES:
            raise ValueError(f"unsupported review status: {self.review_status}")
        if not self.supported_by or any(not item.strip() for item in self.supported_by):
            raise ValueError("supported_by must contain non-empty evidence IDs")

    def to_dict(self) -> dict[str, object]:
        return {
            "relationship_id": self.relationship_id,
            "relationship_type": self.relationship_type,
            "source_entity_id": self.source_entity_id,
            "target_entity_id": self.target_entity_id,
            "status": self.status,
            "supported_by": list(self.supported_by),
            "review_status": self.review_status,
        }


@dataclass(frozen=True)
class ScenarioEvidenceDocument:
    scenario_id: str
    scenario_name: str
    source_files: tuple[str, ...]
    time_window: Mapping[str, object]
    observed_entities: tuple[ObservedEntity, ...]
    evidence: tuple[EvidenceItem, ...]
    relationships: tuple[Relationship, ...]
    sigma_rules: tuple[object, ...] = ()
    mitre_techniques: tuple[object, ...] = ()
    review_notes: tuple[str, ...] = ()
    schema_version: str = SCENARIO_EVIDENCE_SCHEMA_VERSION
    analysis_status: str = ANALYSIS_STATUS_DRAFT_REVIEWABLE

    def __post_init__(self) -> None:
        _require_nonempty_string(self.scenario_id, "scenario_id")
        _require_nonempty_string(self.scenario_name, "scenario_name")
        if self.schema_version != SCENARIO_EVIDENCE_SCHEMA_VERSION:
            raise ValueError(f"unsupported schema version: {self.schema_version}")
        if self.analysis_status != ANALYSIS_STATUS_DRAFT_REVIEWABLE:
            raise ValueError("new scenario evidence must remain draft_reviewable")
        if any(not item.strip() for item in self.source_files):
            raise ValueError("source_files must contain non-empty filenames")
        if not self.source_files and (
            self.observed_entities or self.evidence or self.relationships
        ):
            raise ValueError("non-empty scenario evidence requires source_files")
        validated_time_window = _validated_time_window(
            self.time_window,
            empty_document=not (
                self.source_files
                or self.observed_entities
                or self.evidence
                or self.relationships
            ),
        )
        evidence_ids = {item.evidence_id for item in self.evidence}
        if len(evidence_ids) != len(self.evidence):
            raise ValueError("evidence_id values must be unique")
        entity_ids = {item.entity_id for item in self.observed_entities}
        if len(entity_ids) != len(self.observed_entities):
            raise ValueError("entity_id values must be unique")
        relationship_ids = {
            item.relationship_id for item in self.relationships
        }
        if len(relationship_ids) != len(self.relationships):
            raise ValueError("relationship_id values must be unique")
        for relationship in self.relationships:
            missing = set(relationship.supported_by) - evidence_ids
            if missing:
                raise ValueError(f"relationship references missing evidence: {sorted(missing)}")
            if relationship.source_entity_id not in entity_ids:
                raise ValueError("relationship source entity does not exist")
            if relationship.target_entity_id not in entity_ids:
                raise ValueError("relationship target entity does not exist")
        object.__setattr__(self, "time_window", validated_time_window)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "source_files": list(self.source_files),
            "analysis_status": self.analysis_status,
            "time_window": _plain_mapping(self.time_window),
            "observed_entities": [entity.to_dict() for entity in self.observed_entities],
            "evidence": [item.to_dict() for item in self.evidence],
            "relationships": [item.to_dict() for item in self.relationships],
            "sigma_rules": copy.deepcopy(list(self.sigma_rules)),
            "mitre_techniques": copy.deepcopy(list(self.mitre_techniques)),
            "review_notes": list(self.review_notes),
        }


def create_evidence_item(
    *,
    evidence_type: str,
    status: str,
    summary: str,
    observations: Sequence[EvidenceObservation],
    reason: str,
    review_status: str = "needs_review",
) -> EvidenceItem:
    """Create evidence with a stable ID; automatic confirmed status is forbidden."""

    if status not in AUTOMATIC_EVIDENCE_STATUSES:
        raise ValueError("automatic evidence status must be observed, inferred, or candidate")
    ordered = tuple(
        sorted(
            observations,
            key=lambda item: (item.timestamp or "", item.source_file, item.raw_record_ref),
        )
    )
    identity = {
        "evidence_type": evidence_type,
        "observations": [
            [item.source_file, item.raw_record_ref] for item in ordered
        ],
    }
    return EvidenceItem(
        evidence_id=_deterministic_id("evidence", identity),
        evidence_type=evidence_type,
        status=status,
        summary=summary,
        observations=ordered,
        reason=reason,
        review_status=review_status,
    )


def create_relationship(
    *,
    relationship_type: str,
    source_entity_id: str,
    target_entity_id: str,
    status: str,
    supported_by: Iterable[str],
    review_status: str = "needs_review",
) -> Relationship:
    """Create a relationship with stable ordering and no automatic confirmation."""

    if status not in AUTOMATIC_EVIDENCE_STATUSES:
        raise ValueError("automatic relationship status must be observed, inferred, or candidate")
    ordered_support = tuple(sorted(set(supported_by)))
    identity = {
        "relationship_type": relationship_type,
        "source_entity_id": source_entity_id,
        "target_entity_id": target_entity_id,
        "supported_by": ordered_support,
    }
    return Relationship(
        relationship_id=_deterministic_id("relationship", identity),
        relationship_type=relationship_type,
        source_entity_id=source_entity_id,
        target_entity_id=target_entity_id,
        status=status,
        supported_by=ordered_support,
        review_status=review_status,
    )


def create_process_entity(
    *,
    host: str,
    process_name: str,
    process_id: object,
    timestamp: str,
    process_guid: object = None,
) -> ObservedEntity:
    """Create a deterministic process identity without treating a PID as global."""

    _require_nonempty_string(host, "host")
    _require_nonempty_string(process_name, "process_name")
    guid = process_guid if _require_optional_nonempty(process_guid) else None
    if guid is not None:
        identity = {"host": host.casefold(), "process_guid": str(guid).casefold()}
    else:
        parsed_pid = _parse_process_id(process_id)
        if parsed_pid is None:
            raise ValueError("process identity fallback requires a valid process_id")
        if _parse_timestamp(timestamp) is None:
            raise ValueError("process identity fallback requires an identity_timestamp")
        identity = {
            "host": host.casefold(),
            "process_id": parsed_pid,
            "timestamp": timestamp,
        }
    attributes: dict[str, object] = {
        "host": host,
        "process_name": process_name,
        "process_id": copy.deepcopy(process_id),
        "process_guid": copy.deepcopy(guid),
    }
    if guid is None:
        attributes["identity_timestamp"] = timestamp
    return ObservedEntity(
        entity_id=_deterministic_id("process", identity),
        entity_type="process",
        attributes=attributes,
    )


def _require_optional_nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def scenario_evidence_schema_document() -> dict[str, object]:
    """Return a machine-readable description of the evidence contract."""

    return {
        "schema_version": SCENARIO_EVIDENCE_SCHEMA_VERSION,
        "analysis_status": ANALYSIS_STATUS_DRAFT_REVIEWABLE,
        "top_level_fields": list(SCENARIO_EVIDENCE_FIELDS),
        "evidence_statuses": list(EVIDENCE_STATUSES),
        "automatic_evidence_statuses": list(AUTOMATIC_EVIDENCE_STATUSES),
        "review_statuses": list(REVIEW_STATUSES),
    }


def serialize_scenario_evidence(document: ScenarioEvidenceDocument) -> str:
    """Serialize a document to deterministic UTF-8-compatible JSON text."""

    return json.dumps(
        document.to_dict(),
        ensure_ascii=False,
        separators=(",", ":"),
    ) + "\n"
