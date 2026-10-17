from __future__ import annotations

import json
from dataclasses import replace

import pytest

from threat_hunting.evidence import (
    EVIDENCE_STATUSES,
    REVIEW_STATUSES,
    EvidenceItem,
    EvidenceObservation,
    ObservedEntity,
    ScenarioEvidenceDocument,
    create_evidence_item,
    create_process_entity,
    create_relationship,
    scenario_evidence_schema_document,
    serialize_scenario_evidence,
)


def _observation(ref: str = "jsonl:line:1") -> EvidenceObservation:
    return EvidenceObservation(
        source_file="fixture.json",
        raw_record_ref=ref,
        provider="Microsoft-Windows-Sysmon",
        event_id="1",
        timestamp="2020-10-22T02:57:59.857000Z",
        canonical_fields={"process_id": "10980", "process_name": "mshta.exe"},
        raw_fields={"ProcessId": "10980", "Image": "mshta.exe"},
    )


def _document() -> ScenarioEvidenceDocument:
    observation = _observation()
    evidence = create_evidence_item(
        evidence_type="process_creation",
        status="observed",
        summary="cmd.exe spawned mshta.exe",
        observations=(observation,),
        reason="Parent and child fields are present.",
    )
    source = create_process_entity(
        host="WORKSTATION5",
        process_name="cmd.exe",
        process_id="5888",
        timestamp="2020-10-22T02:57:59.857000Z",
    )
    target = create_process_entity(
        host="WORKSTATION5",
        process_name="mshta.exe",
        process_id="10980",
        process_guid="{PROCESS-GUID}",
        timestamp="2020-10-22T02:57:59.857000Z",
    )
    relationship = create_relationship(
        relationship_type="process_spawn",
        source_entity_id=source.entity_id,
        target_entity_id=target.entity_id,
        status="observed",
        supported_by=(evidence.evidence_id,),
    )
    return ScenarioEvidenceDocument(
        scenario_id="mshta-powershell",
        scenario_name="Suspicious PowerShell execution through MSHTA",
        source_files=("fixture.json",),
        time_window={
            "start": "2020-10-22T02:57:59.857000Z",
            "end": "2020-10-22T02:57:59.857000Z",
        },
        observed_entities=(source, target),
        evidence=(evidence,),
        relationships=(relationship,),
        review_notes=("Fixture-only draft.",),
    )


def _empty_document() -> ScenarioEvidenceDocument:
    return ScenarioEvidenceDocument(
        scenario_id="empty-scenario",
        scenario_name="Empty scenario evidence",
        source_files=(),
        time_window={"start": None, "end": None},
        observed_entities=(),
        evidence=(),
        relationships=(),
    )


def test_schema_version_required_fields_and_status_enums() -> None:
    schema = scenario_evidence_schema_document()
    assert schema["schema_version"] == "scenario-evidence/v1"
    assert schema["analysis_status"] == "draft_reviewable"
    assert schema["top_level_fields"] == [
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
    ]
    assert tuple(schema["evidence_statuses"]) == EVIDENCE_STATUSES
    assert tuple(schema["review_statuses"]) == REVIEW_STATUSES
    assert schema["automatic_evidence_statuses"] == [
        "observed",
        "inferred",
        "candidate",
    ]


def test_automatic_factories_reject_confirmed_and_invalid_statuses() -> None:
    with pytest.raises(ValueError, match="automatic evidence status"):
        create_evidence_item(
            evidence_type="process_creation",
            status="confirmed",
            summary="not allowed",
            observations=(_observation(),),
            reason="not reviewed",
        )
    with pytest.raises(ValueError, match="automatic relationship status"):
        create_relationship(
            relationship_type="process_spawn",
            source_entity_id="a",
            target_entity_id="b",
            status="confirmed",
            supported_by=("evidence-1",),
        )
    with pytest.raises(ValueError, match="unsupported evidence status"):
        EvidenceItem(
            evidence_id="evidence-1",
            evidence_type="process_creation",
            status="invalid",
            summary="invalid",
            observations=(_observation(),),
            reason="invalid",
        )


@pytest.mark.parametrize("field", ["source_file", "raw_record_ref"])
def test_observation_requires_provenance(field: str) -> None:
    values = {
        "source_file": "fixture.json",
        "raw_record_ref": "jsonl:line:1",
    }
    values[field] = ""
    with pytest.raises(ValueError, match=field):
        EvidenceObservation(
            **values,
            provider="provider",
            event_id="1",
            timestamp="2020-01-01T00:00:00Z",
            canonical_fields={},
            raw_fields={},
        )


def test_evidence_id_is_deterministic_and_raw_fields_are_exact_copies() -> None:
    raw_fields = {"Image": "C:\\Windows\\System32\\mshta.exe", "ProcessId": "10980"}
    observation = EvidenceObservation(
        source_file="fixture.json",
        raw_record_ref="jsonl:line:1",
        provider="provider",
        event_id="1",
        timestamp="2020-01-01T00:00:00Z",
        canonical_fields={"process_name": "mshta.exe"},
        raw_fields=raw_fields,
    )
    first = create_evidence_item(
        evidence_type="process_creation",
        status="observed",
        summary="summary one",
        observations=(observation,),
        reason="reason one",
    )
    second = create_evidence_item(
        evidence_type="process_creation",
        status="observed",
        summary="different prose",
        observations=(observation,),
        reason="different prose",
    )
    raw_fields["ProcessId"] = "changed-after-construction"
    assert first.evidence_id == second.evidence_id
    assert first.observations[0].to_dict()["raw_fields"]["ProcessId"] == "10980"


def test_process_entity_id_is_deterministic_and_pid_alone_is_not_identity() -> None:
    first = create_process_entity(
        host="WORKSTATION5",
        process_name="mshta.exe",
        process_id="0x2ae4",
        timestamp="2020-10-22T02:57:59.856000Z",
    )
    second = create_process_entity(
        host="WORKSTATION5",
        process_name="mshta.exe",
        process_id="10980",
        timestamp="2020-10-22T02:57:59.856000Z",
    )
    later = create_process_entity(
        host="WORKSTATION5",
        process_name="mshta.exe",
        process_id="10980",
        timestamp="2020-10-22T03:57:59.856000Z",
    )
    assert first.entity_id == second.entity_id
    assert first.entity_id != later.entity_id
    with pytest.raises(ValueError, match="identity_timestamp"):
        ObservedEntity(
            entity_id="pid-only",
            entity_type="process",
            attributes={
                "host": "WORKSTATION5",
                "process_name": "mshta.exe",
                "process_id": "10980",
                "process_guid": None,
            },
        )


def test_relationship_must_reference_existing_evidence_and_entities() -> None:
    document = _document()
    bad_relationship = create_relationship(
        relationship_type="process_spawn",
        source_entity_id=document.observed_entities[0].entity_id,
        target_entity_id=document.observed_entities[1].entity_id,
        status="observed",
        supported_by=("evidence-missing",),
    )
    with pytest.raises(ValueError, match="missing evidence"):
        ScenarioEvidenceDocument(
            scenario_id=document.scenario_id,
            scenario_name=document.scenario_name,
            source_files=document.source_files,
            time_window=document.time_window,
            observed_entities=document.observed_entities,
            evidence=document.evidence,
            relationships=(bad_relationship,),
        )


def test_serialization_is_deterministic_and_readback_has_exact_field_order() -> None:
    document = _document()
    first = serialize_scenario_evidence(document)
    second = serialize_scenario_evidence(document)
    parsed = json.loads(first)
    assert first == second
    assert tuple(parsed) == tuple(scenario_evidence_schema_document()["top_level_fields"])
    assert parsed["schema_version"] == "scenario-evidence/v1"
    assert parsed["analysis_status"] == "draft_reviewable"
    assert first.endswith("\n")


def test_new_document_cannot_be_promoted_automatically() -> None:
    document = _document()
    with pytest.raises(ValueError, match="draft_reviewable"):
        ScenarioEvidenceDocument(
            scenario_id=document.scenario_id,
            scenario_name=document.scenario_name,
            source_files=document.source_files,
            time_window=document.time_window,
            observed_entities=document.observed_entities,
            evidence=document.evidence,
            relationships=document.relationships,
            analysis_status="confirmed",
        )


def test_document_requires_unique_relationship_ids() -> None:
    document = _document()
    relationship = document.relationships[0]
    with pytest.raises(ValueError, match="relationship_id values must be unique"):
        ScenarioEvidenceDocument(
            scenario_id=document.scenario_id,
            scenario_name=document.scenario_name,
            source_files=document.source_files,
            time_window=document.time_window,
            observed_entities=document.observed_entities,
            evidence=document.evidence,
            relationships=(relationship, relationship),
        )


def test_time_window_accepts_empty_document_with_null_bounds() -> None:
    document = _empty_document()
    assert document.to_dict()["time_window"] == {"start": None, "end": None}
    assert json.loads(serialize_scenario_evidence(document))["time_window"] == {
        "start": None,
        "end": None,
    }


def test_time_window_accepts_aware_bounds_and_preserves_original_strings() -> None:
    time_window = {
        "start": "2020-10-22T09:00:00+07:00",
        "end": "2020-10-22T03:00:00Z",
    }
    document = replace(_document(), time_window=time_window)
    assert document.to_dict()["time_window"] == time_window
    serialized = serialize_scenario_evidence(document)
    assert json.loads(serialized)["time_window"] == time_window
    assert "2020-10-22T09:00:00+07:00" in serialized
    assert "2020-10-22T03:00:00Z" in serialized


def test_time_window_accepts_naive_bounds_without_assigning_timezone() -> None:
    time_window = {
        "start": "2020-10-22T02:57:59.857000",
        "end": "2020-10-22T02:58:00.489000",
    }
    document = replace(_document(), time_window=time_window)
    assert document.to_dict()["time_window"] == time_window


def test_time_window_accepts_equal_bounds() -> None:
    timestamp = "2020-10-22T02:57:59.857000Z"
    document = replace(
        _document(),
        time_window={"start": timestamp, "end": timestamp},
    )
    assert document.to_dict()["time_window"] == {
        "start": timestamp,
        "end": timestamp,
    }


@pytest.mark.parametrize(
    "time_window",
    (
        {"start": "2020-10-22T02:57:59Z"},
        {"end": "2020-10-22T02:58:00Z"},
        {
            "start": "2020-10-22T02:57:59Z",
            "end": "2020-10-22T02:58:00Z",
            "extra": "not allowed",
        },
    ),
)
def test_time_window_rejects_missing_or_extra_keys(
    time_window: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="exactly start and end"):
        replace(_document(), time_window=time_window)


@pytest.mark.parametrize("time_window", (None, [], "not-a-mapping"))
def test_time_window_rejects_non_mapping(time_window: object) -> None:
    with pytest.raises(ValueError, match="time_window must be a mapping"):
        replace(
            _document(),
            time_window=time_window,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "time_window",
    (
        {"start": None, "end": "2020-10-22T02:58:00Z"},
        {"start": "2020-10-22T02:57:59Z", "end": None},
    ),
)
def test_time_window_rejects_only_one_null_bound(
    time_window: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="both be null or both be timestamps"):
        replace(_document(), time_window=time_window)


@pytest.mark.parametrize(
    "time_window",
    (
        {"start": "not-a-timestamp", "end": "2020-10-22T02:58:00Z"},
        {"start": "2020-10-22T02:57:59Z", "end": ""},
        {"start": 1, "end": "2020-10-22T02:58:00Z"},
    ),
)
def test_time_window_rejects_invalid_iso8601_bounds(
    time_window: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="valid ISO 8601 strings"):
        replace(_document(), time_window=time_window)


def test_time_window_rejects_mixed_aware_and_naive_bounds() -> None:
    with pytest.raises(ValueError, match="both be aware or both be naive"):
        replace(
            _document(),
            time_window={
                "start": "2020-10-22T02:57:59Z",
                "end": "2020-10-22T02:58:00",
            },
        )


@pytest.mark.parametrize(
    "time_window",
    (
        {
            "start": "2020-10-22T10:00:00+07:00",
            "end": "2020-10-22T02:30:00Z",
        },
        {
            "start": "2020-10-22T02:58:00",
            "end": "2020-10-22T02:57:59",
        },
    ),
)
def test_time_window_rejects_start_after_end(
    time_window: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="start must not be after end"):
        replace(_document(), time_window=time_window)


def test_empty_document_rejects_timestamp_time_window() -> None:
    with pytest.raises(ValueError, match="empty scenario evidence requires"):
        replace(
            _empty_document(),
            time_window={
                "start": "2020-10-22T02:57:59Z",
                "end": "2020-10-22T02:58:00Z",
            },
        )
