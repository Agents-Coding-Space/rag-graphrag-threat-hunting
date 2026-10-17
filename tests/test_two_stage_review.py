"""Approved evaluation sources and semantic support stay outside runtime gates."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.evaluation.two_stage_review import (
    TwoStageReviewError, audit_returned_context, load_approved_evaluation_bundle,
)
from threat_hunting.ground_truth.approval_update import serialize_review_document

# Reuse the small synthetic approval-contract constructors, not local outputs.
from test_ground_truth_approval import _approve, _manifest, _reference_answers


@pytest.fixture
def bundle(tmp_path: Path) -> tuple[dict[str, Any], ...]:
    fixture = Path(__file__).parent / "fixtures/ground_truth/scenario_ground_truth_minimal.json"
    gt = json.loads(fixture.read_text(encoding="utf-8"))
    answers = _reference_answers(gt)
    approved = _approve((gt, answers, _manifest(gt, answers)))
    for name, document in zip(
        ("scenario_ground_truth.json", "reference_answers.json", "review_manifest.json"),
        approved, strict=True,
    ):
        (tmp_path / name).write_bytes(serialize_review_document(document))
    return approved


def test_load_approved_v2_validates_actual_bytes_without_rewriting(
    tmp_path: Path, bundle: tuple[dict[str, Any], ...],
) -> None:
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert load_approved_evaluation_bundle(tmp_path) == bundle
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


@pytest.mark.parametrize("name", ["scenario_ground_truth.json", "reference_answers.json"])
def test_byte_change_invalidates_approval_dependency_hash(
    tmp_path: Path, bundle: tuple[dict[str, Any], ...], name: str,
) -> None:
    path = tmp_path / name
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(TwoStageReviewError, match=name):
        load_approved_evaluation_bundle(tmp_path)


@pytest.mark.parametrize("payload", [b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b'{'])
def test_load_errors_name_the_actual_file(
    tmp_path: Path, bundle: tuple[dict[str, Any], ...], payload: bytes,
) -> None:
    (tmp_path / "reference_answers.json").write_bytes(payload)
    with pytest.raises(TwoStageReviewError, match="reference_answers.json"):
        load_approved_evaluation_bundle(tmp_path)


def test_pending_v1_is_not_silently_downversioned_or_approved(tmp_path: Path) -> None:
    path = Path(__file__).parent / "fixtures/ground_truth/scenario_ground_truth_minimal.json"
    (tmp_path / "scenario_ground_truth.json").write_bytes(path.read_bytes())
    with pytest.raises(TwoStageReviewError, match="scenario_ground_truth.json.*v2"):
        load_approved_evaluation_bundle(tmp_path)


def test_valid_pending_v2_bundle_is_not_accepted_as_approved(
    tmp_path: Path, bundle: tuple[dict[str, Any], ...],
) -> None:
    gt, answers, manifest = copy.deepcopy(bundle)
    gt["review"].update(review_status="pending_human_review", reviewer=None, reviewed_at=None)
    answers["review"].update(
        review_status="ai_review_completed_pending_human_approval",
        human_reviewer=None, human_approved_at=None,
    )
    manifest.update(human_review_status="pending_human_review", human_reviewer=None, human_approved_at=None)
    gt_bytes = serialize_review_document(gt)
    answers["sources"]["ground_truth"]["sha256"] = hashlib.sha256(gt_bytes).hexdigest()
    answer_bytes = serialize_review_document(answers)
    manifest["artifacts"]["scenario_ground_truth.json"] = hashlib.sha256(gt_bytes).hexdigest()
    manifest["artifacts"]["reference_answers.json"] = hashlib.sha256(answer_bytes).hexdigest()
    for name, payload in (
        ("scenario_ground_truth.json", gt_bytes), ("reference_answers.json", answer_bytes),
        ("review_manifest.json", serialize_review_document(manifest)),
    ):
        (tmp_path / name).write_bytes(payload)
    with pytest.raises(TwoStageReviewError, match="approval is required"):
        load_approved_evaluation_bundle(tmp_path)


def _context(*, nodes: list[dict[str, Any]] | None = None,
             edges: list[dict[str, Any]] | None = None,
             chunks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"retrieval": {"hits": [{"chunk": chunk} for chunk in chunks or []]},
            "traversal": {"nodes": nodes or [], "edges": edges or []}}


def _case(*units: str, category: str = "relevant_direct") -> dict[str, Any]:
    return {"category": category, "minimal_answer_unit_ids": list(units),
            "expected_evidence_ids": ["ev-one"]}


def _unit(pointer: str, fields: dict[str, Any]) -> dict[str, Any]:
    return {"source_ground_truth_pointer": pointer,
            "required_ground_truth_fields": [
                {"pointer": pointer + relative, "value": value}
                for relative, value in fields.items()
            ]}


def _entity(node_id: str, source_id: str) -> dict[str, Any]:
    return {"node_id": node_id, "node_type": "entity",
            "source": {"object_type": "entity", "object_id": source_id}}


@pytest.fixture
def relation() -> tuple[dict[str, Any], dict[str, Any]]:
    units = {"spawn": _unit("/relationships/0", {
        "/source_entity_id": "process-parent", "/target_entity_id": "process-child",
        "/relationship_type": "process_spawn", "/status": "observed",
    })}
    edge = {"edge_type": "process_spawn", "directed": True, "status": "observed",
            "source_node_id": "n-parent", "target_node_id": "n-child",
            "source": {"json_pointer": "/relationships/0", "object_type": "relationship"},
            "evidence_ids": ["ev-one"]}
    return units, _context(
        nodes=[_entity("n-parent", "process-parent"), _entity("n-child", "process-child")],
        edges=[edge],
    )


def test_directed_graph_relation_requires_both_resolved_endpoints(
    relation: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    units, context = relation
    assert audit_returned_context(context, _case("spawn"), units)["context_sufficient"] is True
    context["traversal"]["nodes"].pop()
    assert audit_returned_context(context, _case("spawn"), units)["context_sufficient"] is False


@pytest.mark.parametrize("change", ["reverse", "undirected", "wrong-status"])
def test_wrong_relation_direction_or_status_is_not_support(
    relation: tuple[dict[str, Any], dict[str, Any]], change: str,
) -> None:
    units, context = relation
    edge = context["traversal"]["edges"][0]
    if change == "reverse":
        edge["source_node_id"], edge["target_node_id"] = edge["target_node_id"], edge["source_node_id"]
    elif change == "undirected":
        edge["directed"] = False
    else:
        edge["status"] = "candidate"
    assert audit_returned_context(context, _case("spawn"), units)["context_sufficient"] is False


def test_fact_can_support_relation_only_with_correct_roles_and_returned_entities(
    relation: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    units, context = relation
    context["traversal"]["edges"] = []
    fact = {"node_type": "fact", "status": "observed", "source": {"object_type": "fact"},
            "attributes": {"subject": "process-parent", "predicate": "spawned_process",
                           "object": "process-child"}}
    context["traversal"]["nodes"].append(fact)
    assert audit_returned_context(context, _case("spawn"), units)["context_sufficient"] is True
    fact["attributes"]["subject"], fact["attributes"]["object"] = "process-child", "process-parent"
    assert audit_returned_context(context, _case("spawn"), units)["context_sufficient"] is False


def test_relationship_chunk_roles_are_checked_instead_of_bag_of_ids(
    relation: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    units, _ = relation
    chunk = {"chunk_type": "relationship", "status": "observed",
             "source": {"json_pointer": "/relationships/0"},
             "content": "Source: parent.exe (process-parent). Type: process_spawn. Target: child.exe (process-child)."}
    assert audit_returned_context(_context(chunks=[chunk]), _case("spawn"), units)["context_sufficient"] is True
    chunk["content"] = "Source: child.exe (process-child). Type: process_spawn. Target: parent.exe (process-parent)."
    assert audit_returned_context(_context(chunks=[chunk]), _case("spawn"), units)["context_sufficient"] is False


def test_launch_summary_and_raw_ref_do_not_supply_missing_original_command() -> None:
    command = '"C:\\Windows\\shell.exe" -command Get-Service example'
    units = {"command": _unit("/facts/0", {
        "/attributes/source_observations/0/original_fields/CommandLine": command,
    })}
    fact = {"source": {"json_pointer": "/facts/0", "object_type": "fact"},
            "attributes": {"attributes": {}}, "evidence_ids": ["ev-one"]}
    summary = {"source": {"json_pointer": "/scenario"}, "content": command + " successfully ran"}
    context = _context(nodes=[fact], chunks=[summary])
    assert audit_returned_context(context, _case("command"), units)["context_sufficient"] is False
    fact["attributes"]["attributes"]["source_observations"] = [{
        "source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:1",
        "original_fields": {"CommandLine": command},
    }]
    assert audit_returned_context(context, _case("command"), units)["context_sufficient"] is True
    descriptor = _case("command")
    descriptor["raw_reference_requirements"] = [{"source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:9"}]
    assert audit_returned_context(context, descriptor, units)["context_sufficient"] is False


def test_original_observations_require_provider_event_raw_reference_associations() -> None:
    observations = [{"source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:1",
                     "provider": "provider-A", "event_id": "1", "timestamp": "2020-01-01T00:00:00Z"}]
    refs = [{"source_file": "synthetic.jsonl", "raw_record_ref": "jsonl:line:1"}]
    units = {"obs": _unit("/evidence/0", {"/observations": observations, "/source_references": refs})}
    node = {"source": {"json_pointer": "/evidence/0"}, "attributes": {"observations": copy.deepcopy(observations)},
            "source_references": refs, "evidence_ids": ["ev-one"]}
    assert audit_returned_context(_context(nodes=[node]), _case("obs"), units)["context_sufficient"] is True
    node["attributes"]["observations"][0]["raw_record_ref"] = "jsonl:line:2"
    assert audit_returned_context(_context(nodes=[node]), _case("obs"), units)["context_sufficient"] is False


def test_assessment_requires_its_own_candidate_support_and_review_fields() -> None:
    fields = {"/external_id": "T1234", "/status": "candidate",
              "/evidence_support": "not_assessed", "/review_status": "needs_review",
              "/rationale": "Only the source tag was resolved."}
    units = {"assessment": _unit("/mitre_assessments/0", fields)}
    node = {"source": {"json_pointer": "/mitre_assessments/0"}, "status": "candidate",
            "attributes": {key[1:]: value for key, value in fields.items() if key != "/status"}}
    context = _context(nodes=[node])
    assert audit_returned_context(context, _case("assessment"), units)["context_sufficient"] is True
    node["attributes"]["review_status"] = "wrong"
    node["label"] = "needs_review candidate not_assessed"  # stray words cannot override fields
    assert audit_returned_context(context, _case("assessment"), units)["context_sufficient"] is False


def test_prose_mismatch_is_unknown_until_external_audit_establishes_absence() -> None:
    unit = _unit("/summary/limitations/4", {"": "Process creation does not establish successful completion."})
    units = {"limit": unit}
    chunk = {"source": {"json_pointer": "/summary/limitations/4", "object_type": "limitation"},
             "content": "A launch record is not proof of completion."}
    context = _context(chunks=[chunk])
    assert audit_returned_context(context, _case("limit"), units)["context_sufficient"] is None
    unit["acceptable_semantic_equivalents"] = [chunk["content"]]
    assert audit_returned_context(context, _case("limit"), units)["context_sufficient"] is True
    unit.pop("acceptable_semantic_equivalents")
    unit["known_absent_from_frozen_consumers"] = True
    assert audit_returned_context(context, _case("limit"), units)["context_sufficient"] is False


@pytest.mark.parametrize("category,expected", [("insufficient_evidence", False), ("unrelated", None)])
def test_abstention_categories_do_not_become_the_same_layer_label(category: str, expected: bool | None) -> None:
    result = audit_returned_context(_context(), _case(category=category), {})
    assert result["context_sufficient"] is expected


def test_labels_answers_and_provenance_addresses_never_supply_runtime_evidence(
    relation: tuple[dict[str, Any], dict[str, Any]], monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threat_hunting.graphrag.gate_signals as gate_signals

    def unexpected(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("external context audit must not call or construct gate inputs")

    monkeypatch.setattr(gate_signals, "extract_graphrag_gate_signals", unexpected)
    units, context = relation
    context["traversal"]["edges"] = []
    descriptor = _case("spawn")
    descriptor.update(expected_decision="proceed", reference_answer="gold-answer", query="gold-question")
    context["retrieval"]["hits"] = [{"chunk": {
        "source": {"json_pointer": "/relationships/0"},
        "metadata": {"expected_answer": "Source: parent.exe (process-parent). Type: process_spawn. Target: child.exe (process-child).",
                     "review_status": "confirmed"},
    }}]
    before = copy.deepcopy((context, descriptor, units))
    result = audit_returned_context(context, descriptor, units)
    assert result["context_sufficient"] is False
    assert (context, descriptor, units) == before
    assert "gold-answer" not in json.dumps(result)
    assert "gold-question" not in json.dumps(result)
    assert result["expected_evidence_ids"] == ["ev-one"]
    assert result["returned_evidence_ids"] == []


@pytest.mark.parametrize("ids", [["missing"], ["x", "x"], "x"])
def test_bad_external_rubric_fails_explicitly(ids: Any) -> None:
    with pytest.raises(TwoStageReviewError):
        audit_returned_context(_context(), {"category": "relevant_direct", "minimal_answer_unit_ids": ids}, {})
