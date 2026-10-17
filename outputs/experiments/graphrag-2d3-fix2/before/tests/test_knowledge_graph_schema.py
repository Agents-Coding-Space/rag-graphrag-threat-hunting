"""Knowledge Graph contracts exercised with synthetic data and read-only loading."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.graph import (
    KNOWLEDGE_GRAPH_SCHEMA_VERSION,
    KnowledgeGraphValidationError,
    load_knowledge_graph,
    validate_knowledge_graph,
)


FIXTURE_PATH = Path(__file__).parent / "fixtures/graph/knowledge_graph_minimal.json"
SCHEMA_PATH = Path(__file__).parents[1] / "src/threat_hunting/graph/schema.py"
TOP_LEVEL_FIELDS = (
    "schema_version", "graph_id", "scenario_id", "source_ground_truth", "nodes",
    "edges", "queryable_dimensions", "review", "warnings", "metadata",
)
NODE_FIELDS = (
    "node_id", "node_type", "label", "status", "source", "attributes",
    "evidence_ids", "source_references", "dimensions",
)
EDGE_FIELDS = (
    "edge_id", "edge_type", "source_node_id", "target_node_id", "directed",
    "status", "source", "supporting_node_ids", "evidence_ids",
    "source_references", "attributes", "dimensions",
)
SOURCE_FIELDS = ("object_type", "object_id", "json_pointer")
GROUND_TRUTH_FIELDS = ("path", "schema_version", "sha256", "scenario_id")
REVIEW_FIELDS = ("status", "reviewer", "reviewed_at")
REFERENCE_FIELDS = ("source_file", "raw_record_ref")
COUNT_FIELDS = ("node_count", "edge_count", "node_type_counts", "edge_type_counts")
FORBIDDEN_FIELDS = (
    "question", "questions", "expected_answer", "expected_answers",
    "reference_answer", "gold_answer", "evaluation_questions", "question_id",
    "question_text", "answer_id", "reference_answers", "gold_answers",
)


def _document() -> dict[str, Any]:
    document = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _write(path: Path, document: object) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _counts(document: dict[str, Any]) -> None:
    document["metadata"].update(
        node_count=len(document["nodes"]),
        edge_count=len(document["edges"]),
        node_type_counts=dict(Counter(node["node_type"] for node in document["nodes"])),
        edge_type_counts=dict(Counter(edge["edge_type"] for edge in document["edges"])),
    )


def _subject(document: dict[str, Any], kind: str) -> dict[str, Any]:
    return document["nodes" if kind == "node" else "edges"][0]


def _references(document: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    items = document["nodes" if kind == "node" else "edges"]
    return next(item["source_references"] for item in items if item["source_references"])


def _object_at(document: dict[str, Any], location: str) -> dict[str, Any]:
    if location == "root":
        return document
    if location in {"node", "edge"}:
        return _subject(document, location)
    if location in {"node_source", "edge_source"}:
        return _subject(document, location.split("_")[0])["source"]
    if location == "reference":
        return _references(document, "node")[0]
    return document[location]


def _walk_keys(value: object):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _walk_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_keys(nested)


def test_public_schema_export_and_validation_convention() -> None:
    assert KNOWLEDGE_GRAPH_SCHEMA_VERSION == "knowledge-graph/v1"
    assert validate_knowledge_graph(_document()) is None


def test_fixture_has_required_generic_nodes_edges_and_provenance() -> None:
    document = _document()
    counts = Counter(node["node_type"] for node in document["nodes"])

    assert set(document) == set(TOP_LEVEL_FIELDS)
    assert counts == {
        "scenario": 1, "entity": 2, "evidence": 1, "mitre_assessment": 1, "limitation": 1,
    }
    assert len(document["edges"]) >= 2
    assert all(edge["directed"] is True for edge in document["edges"])
    assert any(edge["supporting_node_ids"] for edge in document["edges"])
    assert any(node["source_references"] for node in document["nodes"])
    assert next(node for node in document["nodes"] if node["node_type"] == "mitre_assessment")["status"] == "candidate"
    assert next(node for node in document["nodes"] if node["node_type"] == "limitation")["status"] == "reviewable"
    assert document["review"] == {
        "status": "pending_human_review", "reviewer": None, "reviewed_at": None,
    }
    assert document["metadata"]["node_count"] == len(document["nodes"])
    assert document["metadata"]["edge_count"] == len(document["edges"])
    assert document["metadata"]["node_type_counts"] == dict(counts)
    assert document["metadata"]["edge_type_counts"] == dict(Counter(
        edge["edge_type"] for edge in document["edges"]
    ))


def test_loader_reads_fixture_and_preserves_source_bytes() -> None:
    before = FIXTURE_PATH.read_bytes()
    loaded = load_knowledge_graph(FIXTURE_PATH)
    assert loaded == _document()
    assert FIXTURE_PATH.read_bytes() == before


def test_validator_does_not_mutate_valid_document() -> None:
    document = _document()
    before = deepcopy(document)
    validate_knowledge_graph(document)
    assert document == before


@pytest.mark.parametrize("failure", ("duplicate_node", "dangling_edge", "metadata", "confirmed"))
def test_validator_does_not_mutate_rejected_document(failure: str) -> None:
    document = _document()
    if failure == "duplicate_node":
        document["nodes"][1]["node_id"] = document["nodes"][0]["node_id"]
    elif failure == "dangling_edge":
        document["edges"][0]["target_node_id"] = "missing-node"
    elif failure == "metadata":
        document["metadata"]["node_count"] = 0
    else:
        document["nodes"][0]["attributes"]["nested"] = ["ConFiRmEd"]
    before = deepcopy(document)
    with pytest.raises(KnowledgeGraphValidationError):
        validate_knowledge_graph(document)
    assert document == before


@pytest.mark.parametrize("document", (None, [], 12, True, "{}"))
def test_root_must_be_a_json_object(document: object) -> None:
    with pytest.raises(KnowledgeGraphValidationError):
        validate_knowledge_graph(document)


@pytest.mark.parametrize(
    ("location", "field"),
    [
        *(("root", field) for field in TOP_LEVEL_FIELDS),
        *(("node", field) for field in NODE_FIELDS),
        *(("edge", field) for field in EDGE_FIELDS),
        *(("node_source", field) for field in SOURCE_FIELDS),
        *(("edge_source", field) for field in SOURCE_FIELDS),
        *(("source_ground_truth", field) for field in GROUND_TRUTH_FIELDS),
        *(("review", field) for field in REVIEW_FIELDS),
        *(("reference", field) for field in REFERENCE_FIELDS),
        *(("metadata", field) for field in COUNT_FIELDS),
    ],
)
def test_required_contract_fields_cannot_be_missing(location: str, field: str) -> None:
    document = _document()
    del _object_at(document, location)[field]
    with pytest.raises(KnowledgeGraphValidationError, match=field):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("location", ("root", "node", "edge", "node_source", "edge_source", "source_ground_truth", "review", "reference"))
def test_strict_contract_objects_reject_extra_fields(location: str) -> None:
    document = _document()
    _object_at(document, location)["undeclared"] = "synthetic extension"
    with pytest.raises(KnowledgeGraphValidationError, match="unexpected|extra"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("field", ("schema_version", "source_schema"))
def test_schema_versions_are_fixed(field: str) -> None:
    document = _document()
    if field == "schema_version":
        document["schema_version"] = "knowledge-graph/v999"
    else:
        document["source_ground_truth"]["schema_version"] = "other-source/v1"
    with pytest.raises(KnowledgeGraphValidationError, match="schema_version"):
        validate_knowledge_graph(document)


def test_source_ground_truth_scenario_must_match_graph() -> None:
    document = _document()
    document["source_ground_truth"]["scenario_id"] = "synthetic-other-scenario"
    with pytest.raises(KnowledgeGraphValidationError, match="scenario_id"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("digest", ("a" * 63, "a" * 65, "g" * 64, "a" * 64 + "\n", "", True, None))
def test_source_sha256_requires_exact_hexadecimal_string(digest: object) -> None:
    document = _document()
    document["source_ground_truth"]["sha256"] = digest
    with pytest.raises(KnowledgeGraphValidationError, match="sha256"):
        validate_knowledge_graph(document)


def test_uppercase_hex_source_hash_is_accepted_without_normalization() -> None:
    document = _document()
    document["source_ground_truth"]["sha256"] = "ABCDEF12" * 8
    before = deepcopy(document)
    validate_knowledge_graph(document)
    assert document == before


@pytest.mark.parametrize("kind", ("node", "edge"))
def test_duplicate_identifiers_are_rejected(kind: str) -> None:
    document = _document()
    items = document["nodes" if kind == "node" else "edges"]
    items[1][kind + "_id"] = items[0][kind + "_id"]
    with pytest.raises(KnowledgeGraphValidationError, match="[Dd]uplicate.*" + kind + "_id"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("field", ("source_node_id", "target_node_id"))
def test_edge_endpoints_must_exist(field: str) -> None:
    document = _document()
    document["edges"][0][field] = "synthetic-missing-node"
    with pytest.raises(KnowledgeGraphValidationError, match=field):
        validate_knowledge_graph(document)


def test_supporting_nodes_must_exist() -> None:
    document = _document()
    document["edges"][0]["supporting_node_ids"] = ["synthetic-missing-node"]
    with pytest.raises(KnowledgeGraphValidationError, match="supporting_node_ids"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize(("kind", "field"), (("node", "evidence_ids"), ("edge", "evidence_ids"), ("edge", "supporting_node_ids")))
def test_reference_id_lists_must_be_unique(kind: str, field: str) -> None:
    document = _document()
    value = document["nodes"][0]["node_id"] if field == "supporting_node_ids" else "evidence-synthetic-external"
    _subject(document, kind)[field] = [value, value]
    with pytest.raises(KnowledgeGraphValidationError, match="duplicate"):
        validate_knowledge_graph(document)


def test_evidence_ids_are_external_ground_truth_provenance() -> None:
    document = _document()
    value = "evidence-external-ground-truth-only"
    assert value not in {node["node_id"] for node in document["nodes"]}
    document["nodes"][0]["evidence_ids"] = [value]
    document["edges"][0]["evidence_ids"] = [value]
    validate_knowledge_graph(document)


@pytest.mark.parametrize("kind", ("node", "edge"))
@pytest.mark.parametrize("value", ("Uppercase", "has-hyphen", "has.dot", "has space", "1start", "", True, None))
def test_types_require_normalized_identifiers(kind: str, value: object) -> None:
    document = _document()
    _subject(document, kind)[kind + "_type"] = value
    with pytest.raises(KnowledgeGraphValidationError, match=kind + "_type"):
        validate_knowledge_graph(document)


def test_types_and_source_object_types_are_open_vocabularies() -> None:
    document = _document()
    document["nodes"][0]["node_type"] = "future_artifact_v2"
    document["edges"][0]["edge_type"] = "future_support_v2"
    document["nodes"][0]["source"]["object_type"] = "future-source-object"
    document["edges"][0]["source"]["object_type"] = "another_source"
    _counts(document)
    validate_knowledge_graph(document)


@pytest.mark.parametrize("kind", ("node", "edge"))
@pytest.mark.parametrize("status", ("observed", "inferred", "candidate", "reviewable"))
def test_all_conservative_statuses_are_accepted(kind: str, status: str) -> None:
    document = _document()
    _subject(document, kind)["status"] = status
    validate_knowledge_graph(document)


@pytest.mark.parametrize("kind", ("node", "edge"))
@pytest.mark.parametrize("status", ("approved", "not_assessed", "Observed", "", None))
def test_invalid_statuses_are_rejected(kind: str, status: object) -> None:
    document = _document()
    _subject(document, kind)["status"] = status
    with pytest.raises(KnowledgeGraphValidationError, match="status"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("value", ("confirmed", "CONFIRMED", " ConFiRmEd \t"))
@pytest.mark.parametrize("location", ("status", "attributes", "metadata", "review"))
def test_confirmed_is_rejected_recursively_and_case_insensitively(value: str, location: str) -> None:
    document = _document()
    if location == "status":
        document["edges"][0]["status"] = value
    elif location == "attributes":
        document["nodes"][0]["attributes"]["nested"] = [{"opaque": [value]}]
    elif location == "metadata":
        document["metadata"]["nested"] = {"other": [{"review_status": value}]}
    else:
        document["review"]["reviewer"] = {"nested": [value]}
    with pytest.raises(KnowledgeGraphValidationError, match="confirmed"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("field", FORBIDDEN_FIELDS)
def test_question_and_answer_fields_are_rejected_inside_nested_extensions(field: str) -> None:
    document = _document()
    document["nodes"][0]["attributes"]["nested"] = [{"details": {field: "forbidden"}}]
    with pytest.raises(KnowledgeGraphValidationError, match="forbidden"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("field", (
    "QUESTION", "Expected-Answer", "REFERENCE-ANSWERS", "Gold-Answer",
    " question ", " expected answer ",
))
def test_question_guard_normalizes_case_and_hyphens(field: str) -> None:
    document = _document()
    document["metadata"]["nested"] = [{field: []}]
    with pytest.raises(KnowledgeGraphValidationError, match="forbidden"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("label", (
    "Which entity participated?", "Question: identify the entity",
    "Expected answer: synthetic alpha", "Reference answer: synthetic alpha",
    "Gold_answer: synthetic alpha",
))
def test_labels_are_narrative_and_do_not_embed_questions_or_answers(label: str) -> None:
    document = _document()
    document["nodes"][0]["label"] = label
    with pytest.raises(KnowledgeGraphValidationError, match="label"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("location", ("graph", "node", "edge"))
@pytest.mark.parametrize("failure", ("duplicate", "unknown", "nonstring"))
def test_dimensions_are_declared_unique_string_lists(location: str, failure: str) -> None:
    document = _document()
    owner = document if location == "graph" else _subject(document, location)
    field = "queryable_dimensions" if location == "graph" else "dimensions"
    if failure == "duplicate":
        owner[field] = [document["queryable_dimensions"][0]] * 2
    elif failure == "unknown":
        if location == "graph":
            owner[field] = []
        else:
            owner[field] = ["undeclared_dimension"]
    else:
        owner[field] = [True]
    with pytest.raises(KnowledgeGraphValidationError, match="dimension"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("kind", ("node", "edge"))
def test_duplicate_source_reference_pairs_are_rejected(kind: str) -> None:
    document = _document()
    references = _references(document, kind)
    references.append(deepcopy(references[0]))
    with pytest.raises(KnowledgeGraphValidationError, match="duplicate source reference"):
        validate_knowledge_graph(document)


def test_source_reference_uniqueness_is_scoped_to_the_pair_and_owner() -> None:
    document = _document()
    references = _references(document, "node")
    original = deepcopy(references[0])
    references[:] = [
        original,
        {"source_file": original["source_file"], "raw_record_ref": original["raw_record_ref"] + ":other"},
        {"source_file": "another_synthetic.jsonl", "raw_record_ref": original["raw_record_ref"]},
    ]
    document["edges"][0]["source_references"] = [deepcopy(original)]
    validate_knowledge_graph(document)


@pytest.mark.parametrize("field", COUNT_FIELDS)
def test_metadata_counts_must_match_graph_exactly(field: str) -> None:
    document = _document()
    if field.endswith("type_counts"):
        key = next(iter(document["metadata"][field]))
        document["metadata"][field][key] += 1
    else:
        document["metadata"][field] += 1
    with pytest.raises(KnowledgeGraphValidationError, match=field):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("field", ("node_type_counts", "edge_type_counts"))
@pytest.mark.parametrize("mode", ("missing_type", "extra_zero_type", "wrong_type"))
def test_type_count_tables_have_exact_type_keys(field: str, mode: str) -> None:
    document = _document()
    counts = document["metadata"][field]
    key = next(iter(counts))
    if mode == "missing_type":
        del counts[key]
    elif mode == "extra_zero_type":
        counts["extra_synthetic_type"] = 0
    else:
        counts["wrong_synthetic_type"] = counts.pop(key)
    with pytest.raises(KnowledgeGraphValidationError, match=field):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("field", COUNT_FIELDS)
@pytest.mark.parametrize("value", (True, False, -1, 1.0, "1", None))
def test_metadata_counts_are_nonnegative_integers_excluding_bool(field: str, value: object) -> None:
    document = _document()
    if field.endswith("type_counts"):
        key = next(iter(document["metadata"][field]))
        document["metadata"][field][key] = value
    else:
        document["metadata"][field] = value
    with pytest.raises(KnowledgeGraphValidationError, match=field):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("directed", (0, 1, "true", None))
def test_directed_requires_a_real_boolean(directed: object) -> None:
    document = _document()
    document["edges"][0]["directed"] = directed
    with pytest.raises(KnowledgeGraphValidationError, match="directed"):
        validate_knowledge_graph(document)


def test_undirected_edges_are_supported_without_changing_endpoints() -> None:
    document = _document()
    document["edges"][0]["directed"] = False
    before = deepcopy(document)
    validate_knowledge_graph(document)
    assert document == before


@pytest.mark.parametrize("kind", ("node", "edge"))
@pytest.mark.parametrize("pointer", ("", "entities/0", "#/entities/0", "/bad~", "/bad~2", "/bad~01~3", None))
def test_source_json_pointer_is_absolute_with_valid_escapes(kind: str, pointer: object) -> None:
    document = _document()
    _subject(document, kind)["source"]["json_pointer"] = pointer
    with pytest.raises(KnowledgeGraphValidationError, match="json_pointer"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("pointer", ("/", "/entities/0", "/a~0b/~1nested", "/đường dẫn/π"))
def test_valid_json_pointer_syntax_is_preserved(pointer: str) -> None:
    document = _document()
    document["nodes"][0]["source"]["json_pointer"] = pointer
    before = deepcopy(document)
    validate_knowledge_graph(document)
    assert document == before


@pytest.mark.parametrize("kind", ("node", "edge"))
@pytest.mark.parametrize("object_id", (None, "synthetic-external-object"))
def test_source_object_id_is_nullable_or_a_nonempty_string(kind: str, object_id: object) -> None:
    document = _document()
    _subject(document, kind)["source"]["object_id"] = object_id
    validate_knowledge_graph(document)


@pytest.mark.parametrize("location", ("root", "node", "edge", "node_source", "source_ground_truth", "reference"))
@pytest.mark.parametrize("value", ("", " \t\n ", None, False))
def test_required_strings_cannot_be_empty_or_other_types(location: str, value: object) -> None:
    document = _document()
    field = {
        "root": "graph_id", "node": "label", "edge": "edge_id",
        "node_source": "object_type", "source_ground_truth": "path", "reference": "raw_record_ref",
    }[location]
    _object_at(document, location)[field] = value
    with pytest.raises(KnowledgeGraphValidationError, match=field):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("field", ("reviewer", "reviewed_at"))
def test_review_identity_and_time_must_remain_null(field: str) -> None:
    document = _document()
    document["review"][field] = "synthetic reviewer or time"
    with pytest.raises(KnowledgeGraphValidationError, match=field):
        validate_knowledge_graph(document)


def test_review_status_must_remain_pending_human_review() -> None:
    document = _document()
    document["review"]["status"] = "approved"
    with pytest.raises(KnowledgeGraphValidationError, match="status"):
        validate_knowledge_graph(document)


def test_attributes_and_metadata_are_generic_json_extensions() -> None:
    document = _document()
    extension = {
        "labels": ["Dữ liệu tổng quát", "synthetic"], "score": 1.25,
        "count": 2, "enabled": True, "optional": None, "nested": [{"payload": []}],
    }
    document["nodes"][0]["attributes"] = deepcopy(extension)
    document["edges"][0]["attributes"] = deepcopy(extension)
    document["metadata"]["extension"] = deepcopy(extension)
    before = deepcopy(document)
    validate_knowledge_graph(document)
    assert document == before


@pytest.mark.parametrize("location", ("node", "edge"))
def test_attributes_must_be_an_object(location: str) -> None:
    document = _document()
    _subject(document, location)["attributes"] = []
    with pytest.raises(KnowledgeGraphValidationError, match="attributes"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("value", (math.nan, math.inf, -math.inf))
@pytest.mark.parametrize("location", ("attributes", "metadata"))
def test_nonfinite_numbers_are_rejected_recursively(location: str, value: float) -> None:
    document = _document()
    owner = document["metadata"] if location == "metadata" else document["edges"][0]["attributes"]
    owner["nested"] = [{"value": value}]
    with pytest.raises(KnowledgeGraphValidationError, match="finite"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("value", (("not", "json"), {1, 2}, b"not json", object()))
def test_extension_values_must_be_json_compatible(value: object) -> None:
    document = _document()
    document["nodes"][0]["attributes"]["nested"] = [value]
    with pytest.raises(KnowledgeGraphValidationError, match="JSON"):
        validate_knowledge_graph(document)


def test_extension_object_keys_must_be_strings() -> None:
    document = _document()
    document["metadata"]["extension"] = {1: "invalid key"}
    with pytest.raises(KnowledgeGraphValidationError, match="non-string"):
        validate_knowledge_graph(document)


def test_empty_graph_and_empty_reference_lists_are_valid() -> None:
    document = _document()
    document["nodes"] = []
    document["edges"] = []
    document["queryable_dimensions"] = []
    _counts(document)
    validate_knowledge_graph(document)
    assert document["metadata"]["node_type_counts"] == {}
    assert document["metadata"]["edge_type_counts"] == {}


def test_aggregate_nodes_can_have_empty_provenance_and_dimensions() -> None:
    document = _document()
    for node in document["nodes"]:
        node["source_references"] = []
        node["evidence_ids"] = []
        node["dimensions"] = []
    for edge in document["edges"]:
        edge["supporting_node_ids"] = []
        edge["source_references"] = []
        edge["evidence_ids"] = []
        edge["dimensions"] = []
    validate_knowledge_graph(document)


def test_duplicate_warning_text_is_allowed_by_repository_convention() -> None:
    document = _document()
    document["warnings"] = ["Synthetic warning", "Synthetic warning"]
    validate_knowledge_graph(document)


@pytest.mark.parametrize("warnings", ("warning", [""], [None], [True]))
def test_warnings_are_nonempty_string_lists(warnings: object) -> None:
    document = _document()
    document["warnings"] = warnings
    with pytest.raises(KnowledgeGraphValidationError, match="warnings"):
        validate_knowledge_graph(document)


def test_loader_preserves_unicode_and_does_not_write_or_create_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _document()
    document["nodes"][0]["label"] = "Dữ liệu tổng quát cần được xem xét."
    document["metadata"]["unicode"] = "Hành vi tổng hợp — π"
    path = tmp_path / "đồ thị.json"
    _write(path, document)
    before = path.read_bytes()
    before_names = sorted(item.name for item in tmp_path.iterdir())
    modes = []
    original_open = Path.open

    def read_only_open(path: Path, mode: str = "r", *args: Any, **kwargs: Any):
        modes.append(mode)
        assert not any(character in mode for character in "wax+")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", read_only_open)
    loaded = load_knowledge_graph(path)

    assert loaded == document
    assert loaded["nodes"][0]["label"] == "Dữ liệu tổng quát cần được xem xét."
    assert modes and path.read_bytes() == before
    assert sorted(item.name for item in tmp_path.iterdir()) == before_names


@pytest.mark.parametrize("location", ("root", "nested"))
def test_loader_rejects_duplicate_json_keys_with_filename(tmp_path: Path, location: str) -> None:
    path = tmp_path / "duplicate.json"
    if location == "root":
        text = '{"schema_version":"knowledge-graph/v1","schema_version":"knowledge-graph/v1"}'
    else:
        document = _document()
        document["metadata"]["nested"] = {"duplicate_marker": 1}
        text = json.dumps(document, ensure_ascii=False)
        text = text.replace('"duplicate_marker": 1', '"duplicate_marker":1,"duplicate_marker":2', 1)
    path.write_text(text, encoding="utf-8")
    before = path.read_bytes()

    with pytest.raises(KnowledgeGraphValidationError) as error:
        load_knowledge_graph(path)
    assert "duplicate JSON" in str(error.value)
    assert str(path) in str(error.value)
    assert path.read_bytes() == before


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity", "1e999"))
def test_loader_rejects_nonfinite_json_numbers_with_filename(tmp_path: Path, constant: str) -> None:
    document = _document()
    document["metadata"]["numeric_marker"] = "replacement_marker"
    text = json.dumps(document).replace('"replacement_marker"', constant)
    path = tmp_path / "nonfinite.json"
    path.write_text(text, encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(KnowledgeGraphValidationError) as error:
        load_knowledge_graph(path)
    assert str(path) in str(error.value)
    assert path.read_bytes() == before


@pytest.mark.parametrize("payload", (b"\xff\xfe", b'{"value":"\xc3("}', b'{"value":"\xed\xa0\x80"}'))
def test_loader_rejects_invalid_utf8_with_filename(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "invalid_utf8.json"
    path.write_bytes(payload)
    with pytest.raises(KnowledgeGraphValidationError) as error:
        load_knowledge_graph(path)
    assert str(path) in str(error.value)
    assert path.read_bytes() == payload


@pytest.mark.parametrize("failure", ("malformed", "array", "schema"))
def test_loader_parse_and_validation_errors_include_filename(tmp_path: Path, failure: str) -> None:
    path = tmp_path / "invalid_graph.json"
    if failure == "malformed":
        path.write_text('{"schema_version":', encoding="utf-8")
    elif failure == "array":
        _write(path, [])
    else:
        document = _document()
        document["schema_version"] = "invalid/v0"
        _write(path, document)
    before = path.read_bytes()
    with pytest.raises(KnowledgeGraphValidationError) as error:
        load_knowledge_graph(path)
    assert str(path) in str(error.value)
    assert path.read_bytes() == before


def test_loader_missing_file_errors_include_requested_path(tmp_path: Path) -> None:
    path = tmp_path / "missing_graph.json"
    with pytest.raises(KnowledgeGraphValidationError) as error:
        load_knowledge_graph(path)
    assert str(path) in str(error.value)
    assert not path.exists()


def test_fixture_and_schema_are_scenario_independent() -> None:
    fixture = FIXTURE_PATH.read_text(encoding="utf-8").casefold()
    source = SCHEMA_PATH.read_text(encoding="utf-8").casefold()
    for forbidden in (
        "mshta", "powershell", "cmd.exe", "t1059.007", "t1140", "t1218.005",
        "proc_creation_win_", "jsonl:line:275", "jsonl:line:398",
    ):
        assert forbidden not in fixture
        assert forbidden not in source
    assert "synthetic" in fixture
    assert "jsonl:line:" not in fixture
    keys = {key.casefold().replace("-", "_") for key in _walk_keys(_document())}
    assert set(FORBIDDEN_FIELDS).isdisjoint(keys)
    assert '"confirmed"' not in fixture


def test_loading_does_not_change_fixture_hash() -> None:
    before = hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()
    load_knowledge_graph(FIXTURE_PATH)
    after = hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()
    assert before == after


@pytest.mark.parametrize("location", ("key", "value"))
def test_validator_rejects_invalid_unicode_inside_extensions(location: str) -> None:
    document = _document()
    document["metadata"]["extension"] = {
        "\ud800" if location == "key" else "label": "synthetic" if location == "key" else "\ud800"
    }
    with pytest.raises(KnowledgeGraphValidationError, match="UTF-8"):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("location", ("key", "value"))
def test_loader_rejects_escaped_unicode_surrogates_with_filename(tmp_path: Path, location: str) -> None:
    document = _document()
    document["metadata"]["extension"] = {
        "\ud800" if location == "key" else "label": "synthetic" if location == "key" else "\ud800"
    }
    path = tmp_path / "escaped_unicode.json"
    path.write_text(json.dumps(document, ensure_ascii=True), encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(KnowledgeGraphValidationError) as error:
        load_knowledge_graph(path)
    assert "UTF-8" in str(error.value)
    assert str(path) in str(error.value)
    assert path.read_bytes() == before


@pytest.mark.parametrize("container_kind", ("list", "object"))
def test_cyclic_python_extensions_fail_closed(container_kind: str) -> None:
    document = _document()
    container: Any = [] if container_kind == "list" else {}
    if container_kind == "list":
        container.append(container)
    else:
        container["self"] = container
    document["nodes"][0]["attributes"]["cycle"] = container
    with pytest.raises(KnowledgeGraphValidationError, match="circular|cycle"):
        validate_knowledge_graph(document)
    assert document["nodes"][0]["attributes"]["cycle"] is container


def test_shared_acyclic_extension_containers_remain_valid() -> None:
    document = _document()
    shared = {"values": ["synthetic", 1, None]}
    document["nodes"][0]["attributes"]["shared"] = shared
    document["edges"][0]["attributes"]["shared"] = shared
    before = deepcopy(document)
    validate_knowledge_graph(document)
    assert document == before
    assert document["nodes"][0]["attributes"]["shared"] is shared
    assert document["edges"][0]["attributes"]["shared"] is shared


def test_deep_acyclic_json_extension_does_not_require_python_recursion() -> None:
    document = _document()
    nested = {"terminal": "synthetic"}
    for _ in range(1500):
        nested = {"level": nested}
    document["nodes"][0]["attributes"]["deep"] = nested

    assert validate_knowledge_graph(document) is None

    assert document["nodes"][0]["attributes"]["deep"] is nested
    leaf = nested
    for _ in range(1500):
        leaf = leaf["level"]
    assert leaf == {"terminal": "synthetic"}


@pytest.mark.parametrize("location", ("node_source", "edge_source", "source_ground_truth", "review", "metadata", "reference"))
def test_nested_contract_objects_reject_nonobjects(location: str) -> None:
    document = _document()
    if location in {"node_source", "edge_source"}:
        _subject(document, location.split("_")[0])["source"] = []
    elif location == "reference":
        _references(document, "node")[0] = []
    else:
        document[location] = []
    with pytest.raises(KnowledgeGraphValidationError):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("field", ("nodes", "edges", "queryable_dimensions", "warnings"))
def test_top_level_lists_reject_other_container_types(field: str) -> None:
    document = _document()
    document[field] = {}
    with pytest.raises(KnowledgeGraphValidationError, match=field):
        validate_knowledge_graph(document)


@pytest.mark.parametrize("kind", ("node", "edge"))
@pytest.mark.parametrize("field", ("evidence_ids", "dimensions", "source_references"))
def test_item_provenance_collections_must_be_lists(kind: str, field: str) -> None:
    document = _document()
    _subject(document, kind)[field] = "synthetic"
    with pytest.raises(KnowledgeGraphValidationError, match=field):
        validate_knowledge_graph(document)
