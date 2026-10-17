from __future__ import annotations

import ast
import builtins
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import random
import socket
import sys
import time
from typing import Any
import uuid

import pytest

from threat_hunting.graph import (
    KnowledgeGraphBuildError,
    KnowledgeGraphValidationError,
    build_knowledge_graph,
    validate_knowledge_graph,
)
from threat_hunting.graph import builder as graph_builder
from threat_hunting.ground_truth import validate_ground_truth_document


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH_PATH = "tests/fixtures/ground_truth/builder/expected_ground_truth.json"
EXPECTED_GRAPH_PATH = "tests/fixtures/graph/builder/expected_knowledge_graph.json"
BUILDER_PATH = REPOSITORY_ROOT / "src/threat_hunting/graph/builder.py"
SOURCE_COLLECTIONS = (
    ("entities", "entity", "entity_id"),
    ("facts", "fact", "fact_id"),
    ("evidence", "evidence", "evidence_id"),
    ("sigma_findings", "sigma_finding", "finding_id"),
    ("mitre_assessments", "mitre_assessment", "assessment_id"),
)
FORBIDDEN_FIELDS = {
    "question", "questions", "expected_answer", "expected_answers",
    "reference_answer", "reference_answers", "gold_answer", "gold_answers",
    "evaluation_questions", "question_id", "question_text", "answer_id",
}


def _ground_truth() -> dict[str, Any]:
    return json.loads((REPOSITORY_ROOT / GROUND_TRUTH_PATH).read_text(encoding="utf-8"))


def _source_hash() -> str:
    return sha256((REPOSITORY_ROOT / GROUND_TRUTH_PATH).read_bytes()).hexdigest()


def _build(document: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
    arguments = {
        "ground_truth_path": GROUND_TRUTH_PATH,
        "ground_truth_sha256": _source_hash(),
        **kwargs,
    }
    return build_knowledge_graph(_ground_truth() if document is None else document, **arguments)


def _nodes(graph: dict[str, Any]) -> dict[tuple[str, str | None], dict[str, Any]]:
    return {
        (node["source"]["object_type"], node["source"]["object_id"]): node
        for node in graph["nodes"]
    }


def _resolve_pointer(document: Any, pointer: str) -> Any:
    value = document
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def _serialized(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _walk(value: object):
    yield value
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested)


def _node_id_map(graph: dict[str, Any]) -> dict[tuple[str, str | None], str]:
    return {key: node["node_id"] for key, node in _nodes(graph).items()}


def _edge_id_map(graph: dict[str, Any]) -> dict[tuple[str, str, str, str | None], str]:
    return {
        (edge["edge_type"], edge["source_node_id"], edge["target_node_id"],
         edge["source"]["object_id"]): edge["edge_id"]
        for edge in graph["edges"]
    }


def test_build_matches_complete_expected_graph() -> None:
    expected = json.loads((REPOSITORY_ROOT / EXPECTED_GRAPH_PATH).read_text(encoding="utf-8"))
    assert _build() == expected


def test_output_passes_graph1_validation_and_counts_are_computed() -> None:
    graph = _build()
    assert validate_knowledge_graph(graph) is None
    assert len(graph["nodes"]) == 13
    assert len(graph["edges"]) == 17
    assert graph["metadata"]["node_count"] == len(graph["nodes"])
    assert graph["metadata"]["edge_count"] == len(graph["edges"])
    assert graph["metadata"]["node_type_counts"] == dict(Counter(node["node_type"] for node in graph["nodes"]))
    assert graph["metadata"]["edge_type_counts"] == {
        "initiates": 1, "transitions_to": 1, "fact_subject": 2,
        "fact_object": 2, "supports": 9, "supports_assessment": 2,
    }
    assert graph["metadata"]["mapping_version"] == "ground-truth-to-knowledge-graph/v1"


def test_input_and_output_validators_are_called_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    document = _ground_truth()
    calls: list[str] = []

    def validate_input(value: object) -> None:
        assert value is document
        calls.append("ground_truth")
        validate_ground_truth_document(value)

    def validate_output(value: object) -> None:
        assert calls == ["ground_truth"]
        calls.append("knowledge_graph")
        validate_knowledge_graph(value)

    monkeypatch.setattr(graph_builder, "validate_ground_truth_document", validate_input)
    monkeypatch.setattr(graph_builder, "validate_knowledge_graph", validate_output)
    _build(document)
    assert calls == ["ground_truth", "knowledge_graph"]


def test_invalid_ground_truth_is_rejected_before_path_conversion() -> None:
    document = _ground_truth()
    document["schema_version"] = "wrong/v1"

    class UnusablePath:
        def __fspath__(self) -> str:
            pytest.fail("Path was inspected before Ground Truth validation")

    with pytest.raises(KnowledgeGraphBuildError, match="schema_version"):
        _build(document, ground_truth_path=UnusablePath())


def test_input_is_not_mutated_and_fixture_bytes_are_unchanged() -> None:
    path = REPOSITORY_ROOT / GROUND_TRUTH_PATH
    initial_bytes = path.read_bytes()
    document = _ground_truth()
    before = deepcopy(document)
    _build(document)
    assert document == before
    assert path.read_bytes() == initial_bytes


def test_deep_copies_do_not_alias_input_or_independent_builds() -> None:
    document = _ground_truth()
    document["entities"][0]["attributes"]["nested"] = {"values": ["Dữ liệu giả lập", None]}
    document["relationships"][0]["attributes"]["nested"] = {"values": [1, 2]}
    first = _build(document)
    second = _build(document)
    before = deepcopy(document)
    source_nodes = _nodes(first)
    source_nodes[("entity", document["entities"][0]["entity_id"])]["attributes"]["attributes"]["nested"]["values"].append("changed")
    source_nodes[("evidence", document["evidence"][0]["evidence_id"])]["attributes"]["observations"][0]["provider"] = "changed"
    next(edge for edge in first["edges"] if edge["source"]["object_type"] == "relationship" and edge["source"]["object_id"] == document["relationships"][0]["relationship_id"])["attributes"]["nested"]["values"].append(3)
    first["review"]["reviewer"] = "changed"
    assert document == before
    assert second == _build(document)
    assert first != second


def test_repeat_builds_serialize_to_identical_bytes() -> None:
    document = _ground_truth()
    assert _serialized(_build(document)) == _serialized(_build(document))


def test_source_collection_order_changes_pointers_but_not_ids() -> None:
    original = _ground_truth()
    reordered = deepcopy(original)
    for collection, _, _ in SOURCE_COLLECTIONS:
        reordered[collection].reverse()
    reordered["relationships"].reverse()
    reordered["queryable_dimensions"].reverse()
    reordered["warnings"].reverse()
    before = _build(original)
    after = _build(reordered)
    assert before["graph_id"] == after["graph_id"]
    assert _node_id_map(before) == _node_id_map(after)
    assert _edge_id_map(before) == _edge_id_map(after)
    assert _nodes(before)[("entity", original["entities"][0]["entity_id"])]["source"]["json_pointer"] != _nodes(after)[("entity", original["entities"][0]["entity_id"])]["source"]["json_pointer"]
    for node in after["nodes"]:
        source = _resolve_pointer(reordered, node["source"]["json_pointer"])
        if node["source"]["object_id"] is not None:
            assert node["source"]["object_id"] in source.values()


def test_nodes_edges_ids_dimensions_references_and_warnings_are_stably_sorted() -> None:
    document = _ground_truth()
    baseline = _build(document)
    for collection, _, _ in SOURCE_COLLECTIONS:
        for item in document[collection]:
            for field in ("evidence_ids", "supporting_evidence_ids", "supporting_sigma_rule_ids", "observation_match_ids", "behavior_match_ids"):
                if field in item:
                    item[field] = list(reversed(item[field])) + item[field][:1]
            if "source_references" in item:
                item["source_references"] = list(reversed(item["source_references"])) + item["source_references"][:1]
    graph = _build(document)
    assert _node_id_map(graph) == _node_id_map(baseline)
    assert _edge_id_map(graph) == _edge_id_map(baseline)
    for collection, id_field in (("nodes", "node_id"), ("edges", "edge_id")):
        assert [item[id_field] for item in graph[collection]] == sorted(item[id_field] for item in graph[collection])
        for item in graph[collection]:
            for field in ("evidence_ids", "supporting_node_ids", "dimensions"):
                if field in item:
                    assert item[field] == sorted(set(item[field]))
            pairs = [(ref["source_file"], ref["raw_record_ref"]) for ref in item["source_references"]]
            assert pairs == sorted(set(pairs))
    assert graph["queryable_dimensions"] == sorted(set(document["queryable_dimensions"]))
    assert graph["warnings"] == sorted(document["warnings"])
    assert Counter(edge["edge_type"] for edge in graph["edges"])["supports"] == 9
    for node in graph["nodes"]:
        for field in ("observation_match_ids", "behavior_match_ids", "supporting_sigma_rule_ids"):
            if field in node["attributes"]:
                assert node["attributes"][field] == sorted(set(node["attributes"][field]))


def test_graph_identity_uses_scenario_hash_and_mapping_version() -> None:
    graph = _build()
    assert graph["graph_id"].startswith("knowledge-graph--")
    assert len(graph["graph_id"].split("--", 1)[1]) == 64
    assert graph["graph_id"] == _build()["graph_id"]
    assert graph["graph_id"] != _build(ground_truth_sha256="f" * 64)["graph_id"]
    renamed = _ground_truth()
    renamed["scenario"]["scenario_id"] = "scenario-other-synthetic"
    for provenance in renamed["input_provenance"]:
        provenance["scenario_id"] = renamed["scenario"]["scenario_id"]
    assert graph["graph_id"] != _build(renamed)["graph_id"]
    assert graph["source_ground_truth"] == {
        "path": GROUND_TRUTH_PATH,
        "schema_version": "scenario-ground-truth/v1",
        "sha256": _source_hash(),
        "scenario_id": _ground_truth()["scenario"]["scenario_id"],
    }


def test_graph_hash_identity_includes_both_versions_scenario_and_supplied_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _ground_truth()
    digest = _source_hash()
    payloads: dict[str, bytes] = {}

    def capture(payload: bytes):
        result = sha256(payload)
        payloads[result.hexdigest()] = payload
        return result

    monkeypatch.setattr(graph_builder.hashlib, "sha256", capture)
    graph = build_knowledge_graph(
        document, ground_truth_path=GROUND_TRUTH_PATH, ground_truth_sha256=digest,
    )
    identity = payloads[graph["graph_id"].split("--", 1)[1]].decode("utf-8")
    for component in (
        "knowledge-graph/v1", "ground-truth-to-knowledge-graph/v1",
        document["scenario"]["scenario_id"], digest,
    ):
        assert component in identity


def test_object_identities_do_not_depend_on_labels_or_source_hash() -> None:
    document = _ground_truth()
    baseline = _build(document)
    document["scenario"]["scenario_name"] = "Another synthetic narrative"
    document["entities"][0]["name"] = "Another synthetic entity"
    document["facts"][0]["attributes"]["additional"] = {"values": ["synthetic"]}
    changed = _build(document, ground_truth_sha256="1" * 64)
    assert _node_id_map(baseline) == _node_id_map(changed)
    assert _edge_id_map(baseline) == _edge_id_map(changed)
    for node in baseline["nodes"]:
        assert node["node_id"].startswith("graph-node--")
    for edge in baseline["edges"]:
        assert edge["edge_id"].startswith("graph-edge--")


def test_source_json_pointers_resolve_original_objects_and_edge_terms() -> None:
    document = _ground_truth()
    graph = _build(document)
    node_lookup = _nodes(graph)
    for collection, object_type, id_field in SOURCE_COLLECTIONS:
        for index, item in enumerate(document[collection]):
            node = node_lookup[(object_type, item[id_field])]
            assert node["source"] == {
                "object_type": object_type,
                "object_id": item[id_field],
                "json_pointer": f"/{collection}/{index}",
            }
            assert _resolve_pointer(document, node["source"]["json_pointer"]) is item
    for edge in graph["edges"]:
        pointed = _resolve_pointer(document, edge["source"]["json_pointer"])
        assert pointed is not None
        if edge["edge_type"] in {"initiates", "transitions_to"}:
            assert pointed["relationship_id"] == edge["source"]["object_id"]


def test_derived_edge_pointers_identify_original_terms_and_id_list_entries() -> None:
    document = _ground_truth()
    for collection, _, _ in SOURCE_COLLECTIONS:
        document[collection].reverse()
        for item in document[collection]:
            for field in ("evidence_ids", "supporting_evidence_ids", "supporting_sigma_rule_ids"):
                if field in item:
                    item[field] = list(reversed(item[field])) + item[field][:1]
    graph = _build(document)
    by_node_id = {node["node_id"]: node for node in graph["nodes"]}
    for edge in graph["edges"]:
        source = edge["source"]
        term = _resolve_pointer(document, source["json_pointer"])
        if edge["edge_type"] in {"fact_subject", "fact_object"}:
            field = "subject" if edge["edge_type"] == "fact_subject" else "object"
            index = next(index for index, fact in enumerate(document["facts"]) if fact["fact_id"] == source["object_id"])
            assert source["json_pointer"] == f"/facts/{index}/{field}"
            assert term == document["facts"][index][field]
        elif edge["edge_type"] == "supports":
            source_node = by_node_id[edge["source_node_id"]]
            target_node = by_node_id[edge["target_node_id"]]
            owner_pointer = target_node["source"]["json_pointer"]
            owner = _resolve_pointer(document, owner_pointer)
            field = "supporting_evidence_ids" if target_node["node_type"] == "mitre_assessment" else "evidence_ids"
            evidence_id = source_node["source"]["object_id"]
            assert source["json_pointer"] == f"{owner_pointer}/{field}/{owner[field].index(evidence_id)}"
            assert term == evidence_id
        elif edge["edge_type"] == "supports_assessment":
            finding = by_node_id[edge["source_node_id"]]
            assessment = by_node_id[edge["target_node_id"]]
            owner_pointer = assessment["source"]["json_pointer"]
            owner = _resolve_pointer(document, owner_pointer)
            rule_id = finding["attributes"]["rule_id"]
            assert source["json_pointer"] == f"{owner_pointer}/supporting_sigma_rule_ids/{owner['supporting_sigma_rule_ids'].index(rule_id)}"
            assert term == rule_id


def test_scenario_source_uses_pointer_identity_and_preserves_scenario_id() -> None:
    document = _ground_truth()
    graph = _build(document)
    scenario_nodes = [node for node in graph["nodes"] if node["node_type"] == "scenario"]
    assert len(scenario_nodes) == 1
    source = scenario_nodes[0]["source"]
    assert source["object_type"] == "scenario"
    assert source["object_id"] is None
    assert source["json_pointer"] == "/scenario"
    assert _resolve_pointer(document, source["json_pointer"]) is document["scenario"]
    assert graph["scenario_id"] == document["scenario"]["scenario_id"]
    assert graph["source_ground_truth"]["scenario_id"] == document["scenario"]["scenario_id"]


def test_scenario_node_preserves_reviewable_metadata() -> None:
    document = _ground_truth()
    graph = _build(document)
    nodes = [node for node in graph["nodes"] if node["node_type"] == "scenario"]
    assert len(nodes) == 1
    node = nodes[0]
    assert node["label"] == document["scenario"]["scenario_name"]
    assert node["status"] == "reviewable"
    assert node["source"]["json_pointer"] == "/scenario"
    assert node["attributes"] == {
        "description": document["scenario"]["description"],
        "analysis_status": "draft_reviewable",
        "time_window": document["scenario"]["time_window"],
    }
    assert node["evidence_ids"] == []
    assert node["source_references"] == []


@pytest.mark.parametrize("collection,object_type,id_field", SOURCE_COLLECTIONS)
def test_each_source_object_maps_without_losing_attributes_status_or_provenance(
    collection: str, object_type: str, id_field: str,
) -> None:
    document = _ground_truth()
    nodes = _nodes(_build(document))
    for item in document[collection]:
        node = nodes[(object_type, item[id_field])]
        assert node["node_type"] == object_type
        assert node["status"] == item["status"]
        excluded = {id_field, "status", "evidence_ids", "supporting_evidence_ids", "source_references"}
        assert node["attributes"] == {key: value for key, value in item.items() if key not in excluded}
        evidence_ids = item.get("evidence_ids", item.get("supporting_evidence_ids", []))
        if object_type == "evidence":
            evidence_ids = [item[id_field]]
        assert node["evidence_ids"] == sorted(set(evidence_ids))
        assert node["source_references"] == item.get("source_references", [])
        if object_type == "entity":
            assert node["label"] == item["name"]
            assert node["attributes"]["attributes"] == item["attributes"]
        elif object_type == "fact":
            assert node["label"] == item["predicate"]
        elif object_type == "evidence":
            assert node["label"] == item["summary"]
            assert node["attributes"]["observations"] == item["observations"]
        elif object_type == "sigma_finding":
            assert node["label"] == item["rule_title"]
        else:
            assert item["external_id"] in node["label"]
            assert item["name"] in node["label"]


def test_limitations_are_reviewable_nodes_with_original_pointer_and_no_fake_edges() -> None:
    document = _ground_truth()
    document["summary"]["limitations"].append("Một giới hạn synthetic khác.")
    graph = _build(document)
    limitations = [node for node in graph["nodes"] if node["node_type"] == "limitation"]
    assert len(limitations) == 2
    for node in limitations:
        index = int(node["source"]["json_pointer"].rsplit("/", 1)[1])
        assert node["source"] == {"object_type": "limitation", "object_id": None, "json_pointer": f"/summary/limitations/{index}"}
        assert node["label"] == document["summary"]["limitations"][index]
        assert node["status"] == "reviewable"
        assert node["attributes"] == {}
        assert node["evidence_ids"] == []
        assert node["source_references"] == []
        assert all(node["node_id"] not in (edge["source_node_id"], edge["target_node_id"]) for edge in graph["edges"])


def test_idless_limitation_identity_uses_pointer_and_preserves_repeated_text() -> None:
    document = _ground_truth()
    document["summary"]["limitations"] *= 2
    graph = _build(document)
    nodes = [node for node in graph["nodes"] if node["node_type"] == "limitation"]
    assert len(nodes) == 2
    assert len({node["node_id"] for node in nodes}) == 2
    assert len({node["label"] for node in nodes}) == 1
    document["summary"]["limitations"][0] = "Another synthetic limitation."
    changed = _build(document)
    assert {node["source"]["json_pointer"]: node["node_id"] for node in nodes} == {
        node["source"]["json_pointer"]: node["node_id"]
        for node in changed["nodes"] if node["node_type"] == "limitation"
    }


def test_direct_relationships_keep_direction_status_attributes_and_evidence_nodes() -> None:
    document = _ground_truth()
    document["relationships"][0]["attributes"] = {"detail": {"synthetic": [1, None]}}
    graph = _build(document)
    nodes = _nodes(graph)
    for item in document["relationships"]:
        matching = [edge for edge in graph["edges"] if edge["source"]["object_type"] == "relationship" and edge["source"]["object_id"] == item["relationship_id"]]
        assert len(matching) == 1
        edge = matching[0]
        assert edge["source_node_id"] == nodes[("entity", item["source_entity_id"])]["node_id"]
        assert edge["target_node_id"] == nodes[("entity", item["target_entity_id"])]["node_id"]
        assert edge["edge_type"] == item["relationship_type"]
        assert edge["directed"] is True
        assert edge["status"] == item["status"]
        assert edge["attributes"] == item["attributes"]
        assert edge["evidence_ids"] == item["evidence_ids"]
        assert edge["source_references"] == item["source_references"]
        assert edge["supporting_node_ids"] == sorted(nodes[("evidence", identifier)]["node_id"] for identifier in item["evidence_ids"])
    assert not any(node["node_type"] == "relationship" for node in graph["nodes"])


def test_direct_and_derived_edges_with_same_type_have_distinct_identities() -> None:
    document = _ground_truth()
    document["relationships"][0]["relationship_type"] = "supports"
    graph = _build(document)
    supports = [edge for edge in graph["edges"] if edge["edge_type"] == "supports"]
    assert len(supports) == 10
    assert len({edge["edge_id"] for edge in supports}) == 10
    assert sum(edge["source"]["object_type"] == "relationship" for edge in supports) == 1


def test_source_id_uniqueness_is_scoped_to_object_type() -> None:
    document = _ground_truth()
    document["facts"][0]["fact_id"] = document["entities"][0]["entity_id"]
    graph = _build(document)
    nodes = _nodes(graph)
    shared = document["entities"][0]["entity_id"]
    assert nodes[("entity", shared)]["node_id"] != nodes[("fact", shared)]["node_id"]
    assert graph["metadata"]["node_count"] == 13


def test_canonical_identity_encoding_distinguishes_embedded_separators() -> None:
    def document_with_identity(scenario_id: str, entity_id: str) -> dict[str, Any]:
        document = _ground_truth()
        previous_id = document["entities"][0]["entity_id"]
        document["scenario"]["scenario_id"] = scenario_id
        for provenance in document["input_provenance"]:
            provenance["scenario_id"] = scenario_id
        document["entities"][0]["entity_id"] = entity_id
        for fact in document["facts"]:
            for field in ("subject", "object"):
                if fact[field] == previous_id:
                    fact[field] = entity_id
        for relationship in document["relationships"]:
            for field in ("source_entity_id", "target_entity_id"):
                if relationship[field] == previous_id:
                    relationship[field] = entity_id
        document["summary"]["key_entities"] = [
            entity_id if item == previous_id else item
            for item in document["summary"]["key_entities"]
        ]
        return document

    first_id = "synthetic-separated-id"
    second_id = "entity\x00" + first_id
    first = _build(document_with_identity("scenario-separated\x00entity", first_id))
    second = _build(document_with_identity("scenario-separated", second_id))
    assert _nodes(first)[("entity", first_id)]["node_id"] != _nodes(second)[("entity", second_id)]["node_id"]


def test_fact_edges_preserve_all_owner_evidence_attributes_and_source_references() -> None:
    document = _ground_truth()
    document["facts"][0]["attributes"] = {"synthetic": {"nested": [None, 1]}}
    graph = _build(document)
    nodes = _nodes(graph)
    for fact in document["facts"]:
        edges = [edge for edge in graph["edges"] if edge["edge_type"] in {"fact_subject", "fact_object"} and edge["source"]["object_id"] == fact["fact_id"]]
        assert len(edges) == 2
        for edge in edges:
            assert edge["attributes"] == fact["attributes"]
            assert edge["evidence_ids"] == fact["evidence_ids"]
            assert edge["source_references"] == fact["source_references"]
            assert edge["supporting_node_ids"] == sorted(nodes[("evidence", evidence_id)]["node_id"] for evidence_id in fact["evidence_ids"])


def test_facts_have_exact_entity_connections_and_keep_their_status() -> None:
    document = _ground_truth()
    graph = _build(document)
    nodes = _nodes(graph)
    expected: set[tuple[str, str, str, str]] = set()
    for fact in document["facts"]:
        fact_node_id = nodes[("fact", fact["fact_id"])]["node_id"]
        expected.add(("fact_subject", nodes[("entity", fact["subject"])]["node_id"], fact_node_id, fact["status"]))
        expected.add(("fact_object", fact_node_id, nodes[("entity", fact["object"])]["node_id"], fact["status"]))
    actual = {(edge["edge_type"], edge["source_node_id"], edge["target_node_id"], edge["status"]) for edge in graph["edges"] if edge["edge_type"] in {"fact_subject", "fact_object"}}
    assert actual == expected


@pytest.mark.parametrize("term", (
    "Alpha display override", "ENTITY-SYNTHETIC-ALPHA", "entity-synthetic-alpha ",
    "entity-unknown", "unknown literal", 17, True, {"entity_id": "entity-synthetic-alpha"},
    ["entity-synthetic-alpha"],
))
@pytest.mark.parametrize("field,edge_type", (("subject", "fact_subject"), ("object", "fact_object")))
def test_nonmatching_fact_terms_are_preserved_without_guessed_entity_edges(
    term: object, field: str, edge_type: str,
) -> None:
    document = _ground_truth()
    fact = document["facts"][0]
    fact[field] = deepcopy(term)
    graph = _build(document)
    node = _nodes(graph)[("fact", fact["fact_id"])]
    assert node["attributes"][field] == term
    assert len([node for node in graph["nodes"] if node["node_type"] == "entity"]) == 3
    assert all(not (edge["edge_type"] == edge_type and node["node_id"] in (edge["source_node_id"], edge["target_node_id"])) for edge in graph["edges"])


def test_evidence_support_edges_have_only_declared_targets_and_target_status() -> None:
    document = _ground_truth()
    graph = _build(document)
    nodes = _nodes(graph)
    expected = set()
    for collection, object_type, id_field in SOURCE_COLLECTIONS:
        if object_type == "evidence":
            continue
        for item in document[collection]:
            evidence_ids = item.get("evidence_ids", item.get("supporting_evidence_ids", []))
            for evidence_id in evidence_ids:
                expected.add((nodes[("evidence", evidence_id)]["node_id"], nodes[(object_type, item[id_field])]["node_id"], item["status"]))
    edges = [edge for edge in graph["edges"] if edge["edge_type"] == "supports"]
    actual = {(edge["source_node_id"], edge["target_node_id"], edge["status"]) for edge in edges}
    assert len(edges) == len(actual) == 9
    assert actual == expected
    assert all(edge["directed"] is True for edge in edges)


def test_support_edges_preserve_owner_provenance_without_inherited_references() -> None:
    graph = _build()
    nodes = {node["node_id"]: node for node in graph["nodes"]}
    for edge in graph["edges"]:
        if edge["edge_type"] == "supports":
            target = nodes[edge["target_node_id"]]
            evidence = nodes[edge["source_node_id"]]
            assert edge["evidence_ids"] == [evidence["source"]["object_id"]]
            assert edge["source_references"] == target["source_references"]
            assert edge["attributes"] == {}
        elif edge["edge_type"] == "supports_assessment":
            target = nodes[edge["target_node_id"]]
            assert edge["evidence_ids"] == target["evidence_ids"]
            assert edge["source_references"] == []
            assert edge["attributes"] == {}
            evidence_nodes = sorted(
                node["node_id"] for node in graph["nodes"]
                if node["node_type"] == "evidence" and node["source"]["object_id"] in target["evidence_ids"]
            )
            assert edge["supporting_node_ids"] == evidence_nodes


def test_sigma_mitre_links_use_exact_rule_ids_and_all_matching_findings() -> None:
    document = _ground_truth()
    duplicate_rule = deepcopy(document["sigma_findings"][0])
    duplicate_rule["finding_id"] = "finding-synthetic-another-observation"
    document["sigma_findings"].append(duplicate_rule)
    graph = _build(document)
    nodes = _nodes(graph)
    expected = set()
    for assessment in document["mitre_assessments"]:
        for finding in document["sigma_findings"]:
            if finding["rule_id"] in assessment["supporting_sigma_rule_ids"]:
                expected.add((nodes[("sigma_finding", finding["finding_id"])]["node_id"], nodes[("mitre_assessment", assessment["assessment_id"])]["node_id"]))
    links = [edge for edge in graph["edges"] if edge["edge_type"] == "supports_assessment"]
    assert {(edge["source_node_id"], edge["target_node_id"]) for edge in links} == expected
    assert len(links) == 3
    assert all(edge["status"] == "candidate" and edge["directed"] is True for edge in links)


@pytest.mark.parametrize("collection", ("entities", "facts", "evidence", "relationships"))
@pytest.mark.parametrize("status", ("observed", "inferred", "candidate"))
def test_core_statuses_are_preserved_without_promotion(collection: str, status: str) -> None:
    document = _ground_truth()
    document[collection][0]["status"] = status
    graph = _build(document)
    if collection == "relationships":
        item = document[collection][0]
        edge = next(edge for edge in graph["edges"] if edge["source"]["object_id"] == item["relationship_id"])
        assert edge["status"] == status
    else:
        object_type = {"entities": "entity", "facts": "fact", "evidence": "evidence"}[collection]
        id_field = {"entities": "entity_id", "facts": "fact_id", "evidence": "evidence_id"}[collection]
        assert _nodes(graph)[(object_type, document[collection][0][id_field])]["status"] == status


def test_dimensions_use_only_declared_generic_concepts_and_fact_predicates() -> None:
    document = _ground_truth()
    declared = ["entity", "sigma_rule", "mitre_technique", "initiates_activity", "has_reviewable_transition"]
    document["queryable_dimensions"] += declared
    graph = _build(document)
    assert graph["queryable_dimensions"] == sorted(document["queryable_dimensions"])
    expected = {
        "scenario": {"provenance"}, "limitation": {"provenance"},
        "entity": {"entity", "provenance"}, "evidence": {"evidence", "provenance"},
        "sigma_finding": {"sigma_rule", "evidence", "provenance"},
        "mitre_assessment": {"mitre_technique", "evidence", "provenance"},
    }
    for node in graph["nodes"]:
        if node["node_type"] == "fact":
            assert set(node["dimensions"]) == {node["attributes"]["predicate"], "evidence", "provenance"}
        else:
            assert set(node["dimensions"]) == expected[node["node_type"]]
    for edge in graph["edges"]:
        assert set(edge["dimensions"]).issubset(document["queryable_dimensions"])
    document["queryable_dimensions"] = []
    empty = _build(document)
    assert empty["queryable_dimensions"] == []
    assert all(item["dimensions"] == [] for item in empty["nodes"] + empty["edges"])


@pytest.mark.parametrize("dimensions", (["evidence", "evidence"], [True], "evidence"))
def test_invalid_input_dimensions_are_rejected_before_any_deduplication(dimensions: object) -> None:
    document = _ground_truth()
    document["queryable_dimensions"] = dimensions
    before = deepcopy(document)
    with pytest.raises(KnowledgeGraphBuildError, match="queryable_dimensions"):
        _build(document)
    assert document == before


@pytest.mark.parametrize("failure", ("source_entity", "target_entity", "entity_evidence", "fact_evidence", "relationship_evidence", "sigma_evidence", "mitre_evidence", "sigma_rule", "fuzzy_sigma_rule"))
def test_missing_references_fail_closed_without_changing_input(failure: str) -> None:
    document = _ground_truth()
    if failure in {"source_entity", "target_entity"}:
        document["relationships"][0][failure + "_id"] = "entity-not-present"
    else:
        collection, field = {
            "entity_evidence": ("entities", "evidence_ids"),
            "fact_evidence": ("facts", "evidence_ids"),
            "relationship_evidence": ("relationships", "evidence_ids"),
            "sigma_evidence": ("sigma_findings", "evidence_ids"),
            "mitre_evidence": ("mitre_assessments", "supporting_evidence_ids"),
            "sigma_rule": ("mitre_assessments", "supporting_sigma_rule_ids"),
            "fuzzy_sigma_rule": ("mitre_assessments", "supporting_sigma_rule_ids"),
        }[failure]
        document[collection][0][field] = ["rule-synthetic-alpha " if failure == "fuzzy_sigma_rule" else "missing-synthetic-reference"]
    before = deepcopy(document)
    with pytest.raises(KnowledgeGraphBuildError):
        _build(document)
    assert document == before


@pytest.mark.parametrize("collection", tuple(item[0] for item in SOURCE_COLLECTIONS) + ("relationships", "input_provenance"))
def test_duplicate_source_object_ids_fail_closed(collection: str) -> None:
    document = _ground_truth()
    document[collection].append(deepcopy(document[collection][0]))
    before = deepcopy(document)
    with pytest.raises(KnowledgeGraphBuildError, match="[Dd]uplicate"):
        _build(document)
    assert document == before


@pytest.mark.parametrize("collection,id_field", (("nodes", "node_id"), ("edges", "edge_id")))
def test_digest_collisions_fail_closed_for_distinct_nodes_and_edges(
    collection: str, id_field: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Inject the external digest dependency; no real hash collision is needed.
    document = _ground_truth()
    arguments = {"ground_truth_path": GROUND_TRUTH_PATH, "ground_truth_sha256": _source_hash()}
    payloads: dict[str, bytes] = {}

    def capture_digest(payload: bytes):
        digest = sha256(payload)
        payloads[digest.hexdigest()] = payload
        return digest

    monkeypatch.setattr(graph_builder.hashlib, "sha256", capture_digest)
    graph = build_knowledge_graph(document, **arguments)
    hashes = [item[id_field].rsplit("--", 1)[1] for item in graph[collection][:2]]
    colliding_payloads = {payloads[digest] for digest in hashes}
    assert len(colliding_payloads) == 2

    class ForcedDigest:
        def hexdigest(self) -> str:
            return "c" * 64

    def collide_digest(payload: bytes):
        return ForcedDigest() if payload in colliding_payloads else sha256(payload)

    monkeypatch.setattr(graph_builder.hashlib, "sha256", collide_digest)
    before = deepcopy(document)
    with pytest.raises(KnowledgeGraphBuildError, match="[Cc]ollision"):
        build_knowledge_graph(document, **arguments)
    assert document == before


@pytest.mark.parametrize("failure", ("schema", "scenario_missing", "scenario_empty", "scenario_inconsistent"))
def test_invalid_schema_or_scenario_fails_closed(failure: str) -> None:
    document = _ground_truth()
    if failure == "schema":
        document["schema_version"] = "wrong/v0"
    elif failure == "scenario_missing":
        del document["scenario"]["scenario_id"]
    elif failure == "scenario_empty":
        document["scenario"]["scenario_id"] = " "
    else:
        document["input_provenance"][0]["scenario_id"] = "different-scenario"
    with pytest.raises(KnowledgeGraphBuildError):
        _build(document)


@pytest.mark.parametrize("value", (None, [], "ground truth", True))
def test_ground_truth_must_be_a_document_object(value: object) -> None:
    with pytest.raises(KnowledgeGraphBuildError):
        build_knowledge_graph(
            value, ground_truth_path=GROUND_TRUTH_PATH, ground_truth_sha256=_source_hash(),
        )


@pytest.mark.parametrize("field", ("subject", "object"))
@pytest.mark.parametrize("term", (None, "", " \t"))
def test_invalid_fact_terms_fail_closed(field: str, term: object) -> None:
    document = _ground_truth()
    document["facts"][0][field] = term
    with pytest.raises(KnowledgeGraphBuildError):
        _build(document)


@pytest.mark.parametrize("digest", (None, 1, b"a" * 64, "", "a" * 63, "a" * 65, "g" * 64, "a" * 64 + "\n"))
def test_invalid_source_hash_fails_closed(digest: object) -> None:
    with pytest.raises(KnowledgeGraphBuildError, match="sha256|SHA-256"):
        _build(ground_truth_sha256=digest)


@pytest.mark.parametrize("source_path", (None, 1, b"synthetic.json", "", " \t\n", "synthetic\x00.json"))
def test_invalid_source_path_fails_closed(source_path: object) -> None:
    with pytest.raises(KnowledgeGraphBuildError, match="path"):
        _build(ground_truth_path=source_path)


@pytest.mark.parametrize("source_path", ("unopened/synthetic.json", Path("unopened/synthetic.json")))
def test_supplied_path_and_hash_are_preserved_without_resolution(source_path: object) -> None:
    graph = _build(ground_truth_path=source_path, ground_truth_sha256="Ab" * 32)
    assert graph["source_ground_truth"]["path"] == os.fspath(source_path)
    assert graph["source_ground_truth"]["sha256"] == "Ab" * 32


def test_custom_pathlike_is_accepted_without_opening_its_file() -> None:
    class SyntheticPath:
        def __fspath__(self) -> str:
            return "never-created/synthetic.json"

    assert _build(ground_truth_path=SyntheticPath())["source_ground_truth"]["path"] == "never-created/synthetic.json"


@pytest.mark.parametrize("operation", ("validate_ground_truth_document", "validate_knowledge_graph", "sha256"))
@pytest.mark.parametrize("error_type", (RuntimeError, TypeError, OSError, RecursionError))
def test_dependency_errors_are_wrapped_with_their_original_cause(
    operation: str, error_type: type[Exception], monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = error_type("synthetic injected failure")

    def fail(*args: Any, **kwargs: Any) -> None:
        raise failure

    dependency = graph_builder.hashlib if operation == "sha256" else graph_builder
    monkeypatch.setattr(dependency, operation, fail)
    with pytest.raises(KnowledgeGraphBuildError) as error:
        _build()
    assert error.value.__cause__ is failure


def test_path_conversion_errors_are_wrapped() -> None:
    failure = RuntimeError("synthetic path conversion failure")

    class BrokenPath:
        def __fspath__(self) -> str:
            raise failure

    with pytest.raises(KnowledgeGraphBuildError) as error:
        _build(ground_truth_path=BrokenPath())
    assert error.value.__cause__ is failure


def test_graph_output_validation_failure_is_not_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = KnowledgeGraphValidationError("synthetic output contract rejection")

    def reject(graph: dict[str, Any]) -> None:
        assert graph["metadata"]["node_count"] == len(graph["nodes"])
        raise failure

    monkeypatch.setattr(graph_builder, "validate_knowledge_graph", reject)
    with pytest.raises(KnowledgeGraphBuildError) as error:
        _build()
    assert error.value.__cause__ is failure


def test_output_remains_pending_review_without_confirmed_or_question_contracts() -> None:
    graph = _build()
    assert graph["review"] == {"status": "pending_human_review", "reviewer": None, "reviewed_at": None}
    values = list(_walk(graph))
    assert not any(isinstance(value, str) and value.strip().casefold() == "confirmed" for value in values)
    assert not any(isinstance(value, str) and value.strip().casefold().replace("-", "_").replace(" ", "_") in FORBIDDEN_FIELDS for value in values)


@pytest.mark.parametrize("field", ("question", "expected_answer", "evaluation_questions"))
def test_question_fields_are_rejected_even_in_nested_attributes(field: str) -> None:
    document = _ground_truth()
    document["entities"][0]["attributes"]["extension"] = {field: "synthetic content"}
    with pytest.raises(KnowledgeGraphBuildError):
        _build(document)


@pytest.mark.parametrize("location", ("status", "nested_attribute"))
def test_confirmed_values_are_rejected_without_correcting_input(location: str) -> None:
    document = _ground_truth()
    if location == "status":
        document["entities"][0]["status"] = "confirmed"
    else:
        document["facts"][0]["attributes"]["nested"] = {"review": "confirmed"}
    before = deepcopy(document)
    with pytest.raises(KnowledgeGraphBuildError):
        _build(document)
    assert document == before


def test_scenario_independence_with_arbitrary_synthetic_entities_rules_and_techniques() -> None:
    original = _ground_truth()
    replacements = {
        original["scenario"]["scenario_id"]: "scenario-inventory-review",
        **{item["entity_id"]: f"asset-{index}" for index, item in enumerate(original["entities"])},
        **{item["evidence_id"]: f"observation-{index}" for index, item in enumerate(original["evidence"])},
        **{item["rule_id"]: f"catalog-rule-{index}" for index, item in enumerate(original["sigma_findings"])},
    }

    def rename(value: object) -> object:
        if isinstance(value, str):
            return replacements.get(value, value)
        if isinstance(value, list):
            return [rename(item) for item in value]
        if isinstance(value, dict):
            return {key: rename(item) for key, item in value.items()}
        return value

    document = rename(original)
    assert isinstance(document, dict)
    document["scenario"]["scenario_name"] = "Synthetic inventory review"
    for index, entity in enumerate(document["entities"]):
        entity["name"] = f"inventory-value-{index}"
        entity["entity_type"] = "inventory_asset"
        entity["attributes"] = {"inventory_tag": f"item-{index}"}
    for index, assessment in enumerate(document["mitre_assessments"]):
        assessment["external_id"] = f"CUSTOM-{index}"
        assessment["stix_id"] = f"pattern--inventory-{index}"
        assessment["name"] = f"Inventory Pattern {index}"
    graph = _build(document)
    assert graph["scenario_id"] == "scenario-inventory-review"
    assert graph["metadata"]["node_count"] == 13
    assert graph["metadata"]["edge_count"] == 17
    nodes = _nodes(graph)
    assert {node["label"] for node in graph["nodes"] if node["node_type"] == "entity"} == {f"inventory-value-{index}" for index in range(3)}
    assert all(("entity", f"asset-{index}") in nodes for index in range(3))
    assert all(("evidence", f"observation-{index}") in nodes for index in range(2))
    for forbidden in ("mshta", "powershell", "cmd.exe", "t1218.005", "proc_creation_win_", "jsonl:line:275", "jsonl:line:398"):
        assert forbidden not in _serialized(graph).decode("utf-8").casefold()
        assert forbidden not in BUILDER_PATH.read_text(encoding="utf-8").casefold()


def test_builder_performs_no_file_io_network_or_nondeterministic_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    document = _ground_truth()
    arguments = {"ground_truth_path": "never-opened/synthetic.json", "ground_truth_sha256": _source_hash()}
    expected = build_knowledge_graph(document, **arguments)

    def forbidden(*args: Any, **kwargs: Any):
        raise AssertionError("Builder attempted an external or nondeterministic operation")

    with monkeypatch.context() as patch:
        for owner, names in (
            (builtins, ("open",)), (io, ("open",)),
            (Path, ("open", "read_text", "read_bytes", "write_text", "write_bytes", "exists", "resolve")),
            (os, ("open", "stat", "listdir")),
            (socket, ("socket", "create_connection", "getaddrinfo")),
            (time, ("time", "time_ns", "monotonic", "perf_counter")),
            (random, ("random", "randint", "randrange", "choice", "choices", "shuffle", "getrandbits")),
            (uuid, ("uuid1", "uuid4")),
        ):
            for name in names:
                patch.setattr(owner, name, forbidden)
        result = build_knowledge_graph(document, **arguments)
    assert result == expected


def test_builder_imports_only_standard_library_and_internal_contracts() -> None:
    tree = ast.parse(BUILDER_PATH.read_text(encoding="utf-8"))
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    assert imported_roots <= sys.stdlib_module_names | {"threat_hunting", "__future__"}
    assert imported_roots.isdisjoint({"time", "datetime", "random", "uuid", "socket", "urllib", "http", "requests", "networkx", "neo4j"})


def test_empty_optional_collections_create_only_the_scenario_node() -> None:
    document = _ground_truth()
    for collection, _, _ in SOURCE_COLLECTIONS:
        document[collection] = []
    document["relationships"] = []
    for field in document["summary"]:
        document["summary"][field] = []
    graph = _build(document)
    assert graph["metadata"]["node_count"] == 1
    assert graph["metadata"]["edge_count"] == 0
    assert graph["metadata"]["node_type_counts"] == {"scenario": 1}
    assert graph["metadata"]["edge_type_counts"] == {}
    assert graph["nodes"][0]["node_type"] == "scenario"
