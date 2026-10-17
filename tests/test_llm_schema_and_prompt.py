"""Unit tests for ThreatHuntingReport schema and ThreatHuntingPromptBuilder."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from threat_hunting.llm.prompt import ThreatHuntingPromptBuilder, format_context_for_prompt
from threat_hunting.llm.schema import AttackStep, MitreTechniqueMatch, ThreatHuntingReport


def test_threat_hunting_report_valid():
    step = AttackStep(
        step_number=1,
        source_entity="cmd.exe PID 5440",
        action="spawned_process",
        target_entity="mshta.exe PID 3624",
        evidence_ref="evidence-b07a5ff4763e629715e6",
        timestamp="2020-10-22T02:57:59.856000Z",
    )
    mitre = MitreTechniqueMatch(
        technique_id="T1218.005",
        technique_name="Mshta",
        confidence="supported_by_observed_behavior",
        rationale="Command line contains mshta inline vbscript",
    )
    report = ThreatHuntingReport(
        verdict="MALICIOUS",
        executive_summary="Phát hiện tiến trình mshta thực thi mã độc.",
        technical_analysis="Chi tiết chuỗi tiến trình cmd.exe gọi mshta.exe.",
        attack_chain=[step],
        mitre_mappings=[mitre],
        sigma_matches=["proc_creation_win_mshta_susp_execution"],
        containment_recommendations=["Kill PID 3624"],
        unverified_claims=["Chưa rõ cmdlet output"],
        evidence_refs=["evidence-b07a5ff4763e629715e6"],
    )
    assert report.verdict == "MALICIOUS"
    assert report.schema_version == "threat-hunting-report/v1"
    assert len(report.attack_chain) == 1
    assert report.attack_chain[0].target_entity == "mshta.exe PID 3624"


def test_threat_hunting_report_validation_errors():
    # Missing required field
    with pytest.raises(ValidationError):
        ThreatHuntingReport(verdict="MALICIOUS")  # type: ignore[call-arg]

    # Invalid verdict choice
    with pytest.raises(ValidationError):
        ThreatHuntingReport(
            verdict="INVALID_VERDICT",  # type: ignore[arg-type]
            executive_summary="test",
            technical_analysis="test",
        )


def test_format_context_for_prompt():
    dummy_context = {
        "retrieval": {
            "hits": [
                {
                    "chunk": {
                        "chunk_type": "entity",
                        "content": "Process cmd.exe",
                        "source": {"json_pointer": "/entities/0"},
                    }
                }
            ]
        },
        "traversal": {
            "nodes": [
                {"node_id": "proc-1", "node_type": "process", "label": "cmd.exe", "status": "observed"}
            ],
            "edges": [
                {"source": "proc-1", "target": "proc-2", "edge_type": "process_spawn"}
            ],
        },
    }
    formatted = format_context_for_prompt(dummy_context)
    assert "=== CONTEXT PHÁP Y & TRI THỨC AN TOÀN THÔNG TIN ===" in formatted
    assert "Chunk #1 [entity] (Source: /entities/0):" in formatted
    assert "Process cmd.exe" in formatted
    assert "Node (process) ID: proc-1 | Label: cmd.exe" in formatted
    assert "proc-1 --[process_spawn]--> proc-2" in formatted


def test_prompt_builder_messages():
    builder = ThreatHuntingPromptBuilder()
    query = "Which process chain led to powershell.exe?"
    dummy_context = {"retrieval": {"hits": []}, "traversal": {"nodes": [], "edges": []}}

    messages = builder.build_messages(query, dummy_context)
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert "ZERO-ASSUMPTION" in messages[0]["content"]
    assert "EVIDENCE CITATION" in messages[0]["content"]

    assert messages[1]["role"] == "user"
    assert query in messages[1]["content"]
    assert "threat-hunting-report/v1" in messages[1]["content"]
