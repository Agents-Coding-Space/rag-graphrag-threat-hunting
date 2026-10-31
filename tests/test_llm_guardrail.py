"""Unit tests for HallucinationGuardrail."""

from __future__ import annotations

import pytest

from threat_hunting.llm.guardrail import HallucinationGuardrail, extract_context_anchors
from threat_hunting.llm.schema import AttackStep, MitreTechniqueMatch, ThreatHuntingReport


@pytest.fixture
def sample_context():
    return {
        "retrieval": {
            "hits": [
                {
                    "chunk": {
                        "chunk_type": "evidence",
                        "content": "cmd.exe spawned mshta.exe with vbscript inline. Associated with T1218.005",
                        "source": {"json_pointer": "/facts/0"},
                        "evidence_ids": ["evidence-b07a5ff4763e629715e6"],
                        "metadata": {
                            "attributes": {
                                "source_observations": [
                                    {
                                        "source_file": "fixture.json",
                                        "raw_record_ref": "jsonl:line:275",
                                        "original_fields": {
                                            "EventID": 1,
                                            "TimeCreated": "2020-10-22T02:57:59.857Z",
                                            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                                            "Image": "C:\\Windows\\System32\\mshta.exe",
                                        },
                                    }
                                ]
                            }
                        },
                    }
                }
            ]
        },
        "traversal": {
            "nodes": [
                {"node_id": "evidence-b07a5ff4763e629715e6", "label": "process creation", "node_type": "evidence"},
                {"node_id": "fixture-assessment", "node_type": "mitre_assessment", "status": "candidate",
                 "attributes": {"external_id": "T1218.005", "name": "Mshta", "stix_id": "attack-pattern--11111111-1111-4111-8111-111111111111", "evidence_support": "supported_by_observed_behavior", "review_status": "needs_review"}}
            ],
            "edges": [],
        },
    }


def test_extract_context_anchors(sample_context):
    anchors = extract_context_anchors(sample_context)
    assert "evidence-b07a5ff4763e629715e6" in anchors["evidence_refs"]
    assert "jsonl:line:275" in anchors["evidence_refs"]
    assert "/facts/0" in anchors["evidence_refs"]
    assert "T1218.005" in anchors["techniques"]
    assert "cmd.exe" in anchors["process_names"]
    assert "mshta.exe" in anchors["process_names"]


def test_guardrail_valid_report(sample_context):
    report = ThreatHuntingReport(
        verdict="MALICIOUS",
        executive_summary="cmd.exe spawned mshta.exe",
        technical_analysis="Analysis",
        attack_chain=[
            AttackStep(
                step_number=1,
                source_entity="cmd.exe",
                action="process_spawn",
                target_entity="mshta.exe",
                evidence_ref="evidence-b07a5ff4763e629715e6",
            )
        ],
        mitre_mappings=[
            MitreTechniqueMatch(
                technique_id="T1218.005",
                technique_name="Mshta",
                confidence="supported_by_observed_behavior",
                rationale="Matches T1218.005",
            )
        ],
        evidence_refs=["evidence-b07a5ff4763e629715e6"],
    )

    guardrail = HallucinationGuardrail(strict=True)
    res = guardrail.validate(report, sample_context)
    assert res.is_valid is True
    assert len(res.hallucinated_entities) == 0
    assert len(res.unsupported_evidence_refs) == 0
    assert len(res.unsupported_techniques) == 0


def test_guardrail_catches_hallucinations(sample_context):
    # Report contains fabricated entities (mimikatz.exe), fake technique (T9999), and fake evidence ref
    report = ThreatHuntingReport(
        verdict="MALICIOUS",
        executive_summary="Attacker ran mimikatz",
        technical_analysis="Analysis",
        attack_chain=[
            AttackStep(
                step_number=1,
                source_entity="cmd.exe",
                action="process_spawn",
                target_entity="mimikatz.exe",
                evidence_ref="evidence-fabricated-ref",
            )
        ],
        mitre_mappings=[
            MitreTechniqueMatch(
                technique_id="T9999",
                technique_name="Unknown",
                confidence="candidate",
                rationale="Fabricated technique",
            )
        ],
        evidence_refs=["evidence-fabricated-ref"],
    )

    guardrail = HallucinationGuardrail(strict=True)
    res = guardrail.validate(report, sample_context)
    assert res.is_valid is False
    assert "mimikatz.exe" in res.hallucinated_entities
    assert "T9999" in res.unsupported_techniques
    assert "evidence-fabricated-ref" in res.unsupported_evidence_refs
    assert res.sanitized_report is not None
    assert res.sanitized_report.verdict == "INSUFFICIENT_EVIDENCE"
    assert len(res.sanitized_report.unverified_claims) >= 3


def report_with_step(**updates):
    step = dict(step_number=1, source_entity="cmd.exe", action="spawned_process", target_entity="mshta.exe", evidence_ref="evidence-b07a5ff4763e629715e6")
    step.update(updates)
    return ThreatHuntingReport(verdict="SUSPICIOUS", executive_summary="Draft", technical_analysis="Draft", attack_chain=[AttackStep(**step)], evidence_refs=[step["evidence_ref"]])


@pytest.mark.parametrize("change", [
    {"evidence_ref": "Chunk #1"}, {"target_entity": "powershell.exe"},
    {"timestamp": "2020-10-22T02:58:00.462Z"}, {"source_entity": "cmd.exe PID 99999"},
])
def test_invalid_or_semantically_wrong_citation_is_not_retained_as_checked_step(sample_context, change):
    result = HallucinationGuardrail().validate(report_with_step(**change), sample_context)
    assert result.validation_status == "validation_failed"
    assert result.sanitized_report.attack_chain == []
    assert "Chunk #1" not in result.sanitized_report.evidence_refs
    assert result.human_review_required
    assert "direct_answer" in result.unverified_fields


def test_text_mention_does_not_authorize_citation_or_technique(sample_context):
    sample_context["retrieval"]["hits"][0]["chunk"]["content"] += " invented-ref T9999"
    report = report_with_step(evidence_ref="invented-ref")
    report.mitre_mappings = [MitreTechniqueMatch(technique_id="T9999", technique_name="Invented", confidence="candidate", rationale="Mentioned")]
    result = HallucinationGuardrail().validate(report, sample_context)
    assert not result.is_valid
    assert result.sanitized_report.evidence_refs == []
    assert result.sanitized_report.mitre_mappings == []


@pytest.mark.parametrize("source_support", ["not_supported_by_observed_command", "not_assessed"])
def test_mitre_source_assessment_is_preserved_instead_of_promoted(sample_context, source_support):
    node = sample_context["traversal"]["nodes"][1]
    node["attributes"].update(external_id="T1059.007", name="JavaScript", evidence_support=source_support)
    report = report_with_step()
    report.mitre_mappings = [MitreTechniqueMatch(technique_id="T1059.007", technique_name="JavaScript", confidence="supported_by_observed_behavior", rationale="vbscript:Execute")]
    result = HallucinationGuardrail().validate(report, sample_context)
    mapping = result.sanitized_report.mitre_mappings[0]
    assert not result.is_valid
    assert mapping.confidence == "candidate"
    assert mapping.evidence_support == source_support
    assert mapping.assessment_status == "candidate"


def test_unresolved_stix_cannot_support_positive_mapping(sample_context):
    sample_context["traversal"]["nodes"][1]["attributes"]["stix_id"] = None
    report = report_with_step()
    report.mitre_mappings = [MitreTechniqueMatch(technique_id="T1218.005", technique_name="Mshta", confidence="confirmed", rationale="Claim")]
    result = HallucinationGuardrail().validate(report, sample_context)
    assert result.sanitized_report.mitre_mappings[0].confidence == "candidate"
    assert not result.is_valid


def test_canonical_network_fields_support_endpoint_but_not_process_creation(sample_context):
    chunk = sample_context["retrieval"]["hits"][0]["chunk"]
    chunk["metadata"]["attributes"]["source_observations"] = [{"source_file":"fixture.json", "raw_record_ref":"jsonl:line:275", "field_origin":"canonical-event/v2", "canonical_fields":{"event_id":"3", "process_name":"kestrel.exe", "destination_ip":"192.0.2.7", "destination_port":8444, "timestamp":"2020-10-22T03:00:00Z"}}]
    report = report_with_step(source_entity="kestrel.exe", action="network_connection", target_entity="192.0.2.7:8444", timestamp="2020-10-22T03:00:00Z")
    assert HallucinationGuardrail().validate(report, sample_context).is_valid
    report.attack_chain[0].target_entity = "192.0.2.7:80"
    assert not HallucinationGuardrail().validate(report, sample_context).is_valid


@pytest.mark.parametrize("confidence,support,expected_valid", [
    ("candidate", "not_assessed", True),
    ("supported_by_observed_behavior", "not_assessed", False),
    ("candidate", "supported_by_observed_behavior", False),
    ("confirmed", "not_assessed", False),
])
def test_unresolved_runtime_assessments_accept_preserved_status_and_reject_promotion(confidence, support, expected_valid):
    """RG04 state shape, synthetic inputs: do not infer its lost raw values."""
    identifiers = ("T1218.010", "T1071.001")
    context = {"retrieval": {"hits": []}, "traversal": {"edges": [], "nodes": [
        {"node_id": "fixture-assessment-" + technique, "node_type": "mitre_assessment", "status": "candidate",
         "attributes": {"external_id": technique, "name": technique + " (ATT&CK object unresolved)",
            "stix_id": None, "evidence_support": "not_assessed", "review_status": "needs_review"}}
        for technique in identifiers
    ]}}
    report = ThreatHuntingReport(verdict="INSUFFICIENT_EVIDENCE", executive_summary="Draft",
        technical_analysis="Narrative remains unverified even if structured checks pass.",
        mitre_mappings=[MitreTechniqueMatch(technique_id=technique, technique_name="Unverified draft name",
            confidence=confidence, evidence_support=support, rationale="Draft") for technique in identifiers])
    result = HallucinationGuardrail().validate(report, context)
    assert result.is_valid is expected_valid
    assert {issue["code"] for issue in result.issues} == (set() if expected_valid else {"assessment_promotion"})
    assert all(m.confidence == "candidate" and m.evidence_support == "not_assessed"
        for m in result.sanitized_report.mitre_mappings)
    assert "technical_analysis" in result.unverified_fields
    assert result.human_review_required


@pytest.mark.parametrize("action", ["http_completed", "exfiltrated_data", "download_completed", "scriptlet_executed"])
def test_connection_cannot_support_a_completion_or_exfiltration_step(sample_context, action):
    chunk = sample_context["retrieval"]["hits"][0]["chunk"]
    chunk["metadata"]["attributes"]["source_observations"] = [{"source_file": "fixture.json", "raw_record_ref": "jsonl:line:275",
        "canonical_fields": {"event_id": "3", "process_name": "kestrel.exe", "destination_ip": "192.0.2.7", "destination_port": 8444}}]
    result = HallucinationGuardrail().validate(report_with_step(source_entity="kestrel.exe", action=action,
        target_entity="192.0.2.7:8444"), sample_context)
    assert not result.is_valid
    assert result.sanitized_report.attack_chain == []
    assert any(issue["code"] == "unsupported_step" for issue in result.issues)
