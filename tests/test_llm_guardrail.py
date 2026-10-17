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
                        "metadata": {
                            "attributes": {
                                "source_observations": [
                                    {
                                        "raw_record_ref": "jsonl:line:275",
                                        "original_fields": {
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
                {"node_id": "evidence-b07a5ff4763e629715e6", "label": "T1218.005 Mshta", "node_type": "evidence"}
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
