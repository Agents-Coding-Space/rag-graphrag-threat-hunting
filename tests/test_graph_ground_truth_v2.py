"""Versioned graph provenance and evidence preservation with synthetic inputs.

The legacy fixtures remain byte-for-byte unchanged. Source observations below
are synthetic and exercise original field values and process-role differences;
they are not additional evidence for the production scenario.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.graph import (
    KnowledgeGraphBuildError,
    KnowledgeGraphValidationError,
    build_knowledge_graph,
    traverse_knowledge_graph,
    validate_knowledge_graph,
)
from threat_hunting.ground_truth.schema import (
    SUPPORTED_GROUND_TRUTH_SCHEMA_VERSIONS,
    validate_ground_truth_document,
)


ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH_PATH = "tests/fixtures/ground_truth/builder/expected_ground_truth.json"
EXPECTED_GRAPH_PATH = "tests/fixtures/graph/builder/expected_knowledge_graph.json"
SOURCE_PATH = "synthetic/approved_ground_truth.json"
REVIEWER = "Synthetic reviewer excluded from graph content"
REVIEWED_AT = "2024-01-02T15:04:05+07:00"
REVIEW_ONLY_MARKERS = (
    "synthetic-review-case-not-evidence",
    "synthetic-review-rubric-not-content",
    "synthetic-review-note-not-content",
)
ADDED_LIMITATIONS = (
    "Synthetic process creation establishes the launch command, not cmdlet completion or service state.",
    "Synthetic observations outside the reviewed core remain outside this graph's behavior claims.",
    "Synthetic timestamp candidates disagree; no timezone correction or causal relationship is inferred.",
)


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _legacy_ground_truth() -> dict[str, Any]:
    return json.loads((ROOT / GROUND_TRUTH_PATH).read_text(encoding="utf-8"))


def _v2_ground_truth(*, approved: bool = True) -> dict[str, Any]:
    document = _legacy_ground_truth()
    document["schema_version"] = "scenario-ground-truth/v2"
    document["review"].update({
        "review_status": "confirmed" if approved else "pending_human_review",
        "reviewer": REVIEWER if approved else None,
        "reviewed_at": REVIEWED_AT if approved else None,
        "decisions": [{
            "case_id": REVIEW_ONLY_MARKERS[0],
            "expected_decision": "abstain",
            "rubric": REVIEW_ONLY_MARKERS[1],
        }],
        "notes": [REVIEW_ONLY_MARKERS[2]],
    })
    # Security 4688 uses NewProcessId for the child and ProcessId for its
    # parent; Sysmon 1 uses ProcessId for the child and ParentProcessId for
    # its parent. The graph must keep the original names and values intact.
    for index, fact in enumerate(document["facts"]):
        references = fact["source_references"]
        child_id = 1200 + index
        parent_id = 1100 + index
        original_fields = {
            "CommandLine": f'"C:\\synthetic\\child-{index}.exe" --inspect "dịch vụ"',
            "TimeCreated": f"2024-01-01T00:00:0{index}Z",
            "Hostname": "synthetic-host",
            "SubjectUserName": "synthetic-user",
        }
        if index == 0:
            original_fields.update({
                "EventID": 4688,
                "NewProcessName": f"C:\\synthetic\\child-{index}.exe",
                "NewProcessId": hex(child_id),
                "ParentProcessName": f"C:\\synthetic\\parent-{index}.exe",
                "ProcessId": hex(parent_id),
            })
        else:
            original_fields.update({
                "EventID": 1,
                "Image": f"C:\\synthetic\\child-{index}.exe",
                "ProcessId": str(child_id),
                "ProcessGuid": "{synthetic-child-guid}",
                "ParentImage": f"C:\\synthetic\\parent-{index}.exe",
                "ParentProcessId": str(parent_id),
                "ParentProcessGuid": "{synthetic-parent-guid}",
                "ParentCommandLine": '"C:\\synthetic\\parent-1.exe" --launch-child',
                "UtcTime": "2024-01-01 04:00:01.000",
            })
        fact["attributes"]["source_observations"] = [{
            **references[0], "original_fields": original_fields,
        }]
    document["summary"]["limitations"].extend(ADDED_LIMITATIONS)
    validate_ground_truth_document(document)
    return document


def _build(document: dict[str, Any]) -> dict[str, Any]:
    return build_knowledge_graph(
        document, ground_truth_path=SOURCE_PATH,
        ground_truth_sha256=sha256(_json_bytes(document)).hexdigest(),
    )


def _source_nodes(graph: dict[str, Any], object_type: str) -> dict[str, Any]:
    return {
        node["source"]["object_id"]: node
        for node in graph["nodes"] if node["node_type"] == object_type
    }


def _assert_references(graph: dict[str, Any], document: dict[str, Any]) -> None:
    nodes = {node["node_id"]: node for node in graph["nodes"]}
    evidence_ids = {item["evidence_id"] for item in document["evidence"]}
    for item in [*graph["nodes"], *graph["edges"]]:
        value: Any = document
        for token in item["source"]["json_pointer"].split("/")[1:]:
            token = token.replace("~1", "/").replace("~0", "~")
            value = value[int(token)] if isinstance(value, list) else value[token]
        assert value is not None
        assert set(item["evidence_ids"]).issubset(evidence_ids)
    for edge in graph["edges"]:
        assert edge["source_node_id"] in nodes
        assert edge["target_node_id"] in nodes
        assert set(edge["supporting_node_ids"]).issubset(nodes)


def test_v1_output_still_matches_untouched_golden_fixture() -> None:
    source = ROOT / GROUND_TRUTH_PATH
    expected = ROOT / EXPECTED_GRAPH_PATH
    before = {path: path.read_bytes() for path in (source, expected)}
    graph = build_knowledge_graph(
        _legacy_ground_truth(), ground_truth_path=GROUND_TRUTH_PATH,
        ground_truth_sha256=sha256(source.read_bytes()).hexdigest(),
    )
    assert graph == json.loads(expected.read_text(encoding="utf-8"))
    assert {path: path.read_bytes() for path in (source, expected)} == before


@pytest.mark.parametrize("approved", (False, True), ids=("pending", "approved"))
def test_v2_preserves_actual_source_provenance_and_deterministic_output(approved: bool) -> None:
    document = _v2_ground_truth(approved=approved)
    before = deepcopy(document)
    first, second = _build(document), _build(document)
    assert first["schema_version"] == "knowledge-graph/v1"
    assert first["source_ground_truth"] == {
        "path": SOURCE_PATH,
        "schema_version": document["schema_version"],
        "sha256": sha256(_json_bytes(document)).hexdigest(),
        "scenario_id": document["scenario"]["scenario_id"],
    }
    assert _json_bytes(first) == _json_bytes(second)
    assert document == before
    assert validate_knowledge_graph(first) is None
    _assert_references(first, document)


@pytest.mark.parametrize("schema_version", sorted(SUPPORTED_GROUND_TRUTH_SCHEMA_VERSIONS))
def test_graph_schema_accepts_only_ground_truths_exported_supported_versions(schema_version: str) -> None:
    graph = _build(_legacy_ground_truth())
    graph["source_ground_truth"]["schema_version"] = schema_version
    assert validate_knowledge_graph(graph) is None


@pytest.mark.parametrize("schema_version", (
    "scenario-ground-truth/v0", "scenario-ground-truth/v3",
    "scenario-ground-truth/v2-extra", "other/v2", "", None, [], {}, 2,
))
def test_unsupported_source_versions_rejected_by_builder_and_graph_schema(schema_version: object) -> None:
    document = _v2_ground_truth(approved=False)
    document["schema_version"] = schema_version
    before = deepcopy(document)
    with pytest.raises(KnowledgeGraphBuildError, match="schema_version"):
        _build(document)
    assert document == before
    graph = _build(_legacy_ground_truth())
    graph["source_ground_truth"]["schema_version"] = schema_version
    with pytest.raises(KnowledgeGraphValidationError, match="schema_version"):
        validate_knowledge_graph(graph)


def test_document_approval_and_evaluation_only_review_metadata_do_not_become_graph_content() -> None:
    approved, pending = _v2_ground_truth(), _v2_ground_truth(approved=False)
    approved_graph, pending_graph = _build(approved), _build(pending)
    assert approved_graph["nodes"] == pending_graph["nodes"]
    assert approved_graph["edges"] == pending_graph["edges"]
    assert approved_graph["graph_id"] != pending_graph["graph_id"]  # Source hash changed.
    assert approved_graph["review"] == {
        "status": "pending_human_review", "reviewer": None, "reviewed_at": None,
    }
    serialized = _json_bytes(approved_graph).decode("utf-8")
    for marker in (REVIEWER, REVIEWED_AT, *REVIEW_ONLY_MARKERS, '"confirmed"', '"expected_decision"', '"case_id"', '"rubric"'):
        assert marker not in serialized
    for collection in ("entities", "facts", "evidence", "sigma_findings", "mitre_assessments"):
        object_type = {
            "entities": "entity", "facts": "fact", "sigma_findings": "sigma_finding",
            "mitre_assessments": "mitre_assessment", "evidence": "evidence",
        }[collection]
        id_field = {
            "entities": "entity_id", "facts": "fact_id", "evidence": "evidence_id",
            "sigma_findings": "finding_id", "mitre_assessments": "assessment_id",
        }[collection]
        nodes = _source_nodes(approved_graph, object_type)
        assert {item[id_field]: item["status"] for item in approved[collection]} == {
            source_id: node["status"] for source_id, node in nodes.items()
        }


@pytest.mark.parametrize("location", ("status", "nested_status", "nested_value"))
def test_v2_keeps_existing_confirmed_guards_for_security_content(location: str) -> None:
    document = _v2_ground_truth()
    if location == "status":
        document["facts"][0]["status"] = "confirmed"
    else:
        key = "status" if location == "nested_status" else "label"
        document["facts"][0]["attributes"]["extension"] = {key: "confirmed"}
    with pytest.raises(KnowledgeGraphBuildError, match="confirmed"):
        _build(document)
    graph = _build(_v2_ground_truth())
    graph["nodes"][0]["attributes"]["extension"] = {"label": "confirmed"}
    with pytest.raises(KnowledgeGraphValidationError, match="confirmed"):
        validate_knowledge_graph(graph)


@pytest.mark.parametrize("field", ("question", "expected_answer", "reference_answer", "evaluation_questions"))
def test_v2_keeps_existing_benchmark_guards_for_mapped_content(field: str) -> None:
    document = _v2_ground_truth()
    document["facts"][0]["attributes"]["extension"] = {field: "synthetic evaluation text"}
    with pytest.raises(KnowledgeGraphBuildError, match="forbidden"):
        _build(document)


def test_all_original_values_process_roles_and_references_survive_graph_and_traversal() -> None:
    document = _v2_ground_truth()
    graph = _build(document)
    facts = _source_nodes(graph, "fact")
    for fact in document["facts"]:
        node = facts[fact["fact_id"]]
        assert node["attributes"]["attributes"] == fact["attributes"]
        assert node["attributes"]["subject"] == fact["subject"]
        assert node["attributes"]["object"] == fact["object"]
        assert node["source_references"] == sorted(
            fact["source_references"], key=lambda item: (item["source_file"], item["raw_record_ref"]),
        )
        result = traverse_knowledge_graph(graph, seed_node_ids=[node["node_id"]])
        returned = _source_nodes(result, "fact")[fact["fact_id"]]
        assert returned == node
        # This comparison includes CommandLine values, all original process
        # role/identity fields, and source references, not just field names.
        assert returned["attributes"]["attributes"]["source_observations"] == fact["attributes"]["source_observations"]
    relationship_edges = [edge for edge in graph["edges"] if edge["source"]["object_type"] == "relationship"]
    assert len(relationship_edges) == len(document["relationships"])
    assert {edge["edge_type"] for edge in relationship_edges} == {
        relationship["relationship_type"] for relationship in document["relationships"]
    }


def test_every_approved_limitation_has_its_own_source_pointer_and_traverses_unchanged() -> None:
    document = _v2_ground_truth()
    graph = _build(document)
    limitations = {node["source"]["json_pointer"]: node for node in graph["nodes"] if node["node_type"] == "limitation"}
    assert len(limitations) == len(document["summary"]["limitations"])
    for index, text in enumerate(document["summary"]["limitations"]):
        node = limitations[f"/summary/limitations/{index}"]
        assert node["label"] == text
        assert node["status"] == "reviewable"
        assert node["evidence_ids"] == []
        result = traverse_knowledge_graph(graph, seed_node_ids=[node["node_id"]])
        assert result["nodes"] == [node]
        assert result["edges"] == []  # No inferred causal links to limitations.
