from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

import pytest

from threat_hunting.ground_truth import validate_ground_truth_document
from threat_hunting.retrieval import (
    RetrievalCorpusBuildError,
    build_retrieval_corpus,
    validate_retrieval_corpus,
)
from threat_hunting.retrieval import builder as retrieval_builder


GROUND_TRUTH_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "ground_truth"
    / "builder"
    / "expected_ground_truth.json"
)
EXPECTED_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "retrieval"
    / "builder"
    / "expected_retrieval_corpus.json"
)
SOURCE_PATH = GROUND_TRUTH_PATH.relative_to(Path(__file__).parents[1]).as_posix()
SOURCE_SHA256 = sha256(GROUND_TRUTH_PATH.read_bytes()).hexdigest()
CHUNK_COUNTS = {
    "scenario_summary": 1,
    "entity": 3,
    "fact": 2,
    "relationship": 2,
    "evidence": 2,
    "sigma_finding": 2,
    "mitre_assessment": 2,
    "limitation": 1,
}
FORBIDDEN_FIELDS = {
    "questions",
    "evaluation_questions",
    "expected_answers",
    "question_id",
    "question_text",
    "expected_answer",
    "answer_id",
    "embedding",
    "embedding_model",
    "vector",
    "llm_response",
}


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _ground_truth() -> dict[str, Any]:
    return _json(GROUND_TRUTH_PATH)


def _expected() -> dict[str, Any]:
    return _json(EXPECTED_PATH)


def _build(ground_truth: object | None = None) -> dict[str, object]:
    return build_retrieval_corpus(
        _ground_truth() if ground_truth is None else ground_truth,
        source_ground_truth_path=SOURCE_PATH,
        source_ground_truth_sha256=SOURCE_SHA256,
    )


def _chunk(
    corpus: dict[str, object], chunk_type: str, object_id: str | None = None
) -> dict[str, Any]:
    chunks = corpus["chunks"]
    assert isinstance(chunks, list)
    candidates = [item for item in chunks if item["chunk_type"] == chunk_type]
    if object_id is not None:
        candidates = [
            item for item in candidates if item["source"]["object_id"] == object_id
        ]
    assert len(candidates) == 1
    return candidates[0]


def _walk(value: object) -> list[object]:
    values = [value]
    if isinstance(value, dict):
        for key, nested in value.items():
            values.extend((key, *_walk(nested)))
    elif isinstance(value, list):
        for nested in value:
            values.extend(_walk(nested))
    return values


def _without_pointers(corpus: dict[str, object]) -> dict[str, object]:
    normalized = deepcopy(corpus)
    for chunk in normalized["chunks"]:
        chunk["source"]["json_pointer"] = "<current-input-index>"
    return normalized


def test_build_matches_complete_expected_fixture() -> None:
    assert _build() == _expected()


def test_built_corpus_passes_retrieval_validator() -> None:
    validate_retrieval_corpus(_build())


def test_source_ground_truth_fixture_passes_ground_truth_validator() -> None:
    validate_ground_truth_document(_ground_truth())


def test_builder_does_not_mutate_ground_truth() -> None:
    ground_truth = _ground_truth()
    before = deepcopy(ground_truth)

    _build(ground_truth)

    assert ground_truth == before


def test_two_builds_are_equal_and_byte_equivalent() -> None:
    first = _build()
    second = _build()

    assert first == second
    assert json.dumps(first, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        second, ensure_ascii=False, separators=(",", ":")
    )


def test_corpus_id_is_deterministic() -> None:
    assert _build()["corpus_id"] == (
        "retrieval-corpus--a8d7adca8c70e4ec669cc6848aec6159133dcc30c7ae6fb8b59db4c9dfb5006e"
    )


def test_chunk_ids_are_deterministic_and_unique() -> None:
    first_ids = [item["chunk_id"] for item in _build()["chunks"]]
    second_ids = [item["chunk_id"] for item in _build()["chunks"]]

    assert first_ids == second_ids
    assert len(first_ids) == len(set(first_ids))
    assert all(item.startswith("retrieval-chunk--") for item in first_ids)


def test_every_ground_truth_object_has_exactly_one_chunk() -> None:
    ground_truth = _ground_truth()
    corpus = _build(ground_truth)
    counts = {
        chunk_type: sum(
            item["chunk_type"] == chunk_type for item in corpus["chunks"]
        )
        for chunk_type in CHUNK_COUNTS
    }

    assert counts == CHUNK_COUNTS
    assert len(corpus["chunks"]) == 15
    assert counts["entity"] == len(ground_truth["entities"])
    assert counts["fact"] == len(ground_truth["facts"])
    assert counts["relationship"] == len(ground_truth["relationships"])
    assert counts["evidence"] == len(ground_truth["evidence"])
    assert counts["sigma_finding"] == len(ground_truth["sigma_findings"])
    assert counts["mitre_assessment"] == len(ground_truth["mitre_assessments"])


def test_each_limitation_has_exactly_one_chunk() -> None:
    ground_truth = _ground_truth()
    limitations = [
        item for item in _build()["chunks"] if item["chunk_type"] == "limitation"
    ]

    assert len(limitations) == len(ground_truth["summary"]["limitations"])
    assert [item["content"] for item in limitations] == ground_truth["summary"][
        "limitations"
    ]


def test_status_mapping_preserves_source_semantics() -> None:
    ground_truth = _ground_truth()
    corpus = _build(ground_truth)

    assert _chunk(corpus, "scenario_summary")["status"] == "reviewable"
    assert _chunk(corpus, "limitation")["status"] == "reviewable"
    for collection, chunk_type, identifier in (
        ("entities", "entity", "entity_id"),
        ("facts", "fact", "fact_id"),
        ("relationships", "relationship", "relationship_id"),
        ("evidence", "evidence", "evidence_id"),
        ("sigma_findings", "sigma_finding", "finding_id"),
        ("mitre_assessments", "mitre_assessment", "assessment_id"),
    ):
        for source in ground_truth[collection]:
            assert _chunk(corpus, chunk_type, source[identifier])["status"] == source[
                "status"
            ]


def test_json_pointers_match_current_ground_truth_indexes() -> None:
    ground_truth = _ground_truth()
    corpus = _build(ground_truth)

    assert _chunk(corpus, "scenario_summary")["source"]["json_pointer"] == "/scenario"
    for collection, chunk_type, identifier in (
        ("entities", "entity", "entity_id"),
        ("facts", "fact", "fact_id"),
        ("relationships", "relationship", "relationship_id"),
        ("evidence", "evidence", "evidence_id"),
        ("sigma_findings", "sigma_finding", "finding_id"),
        ("mitre_assessments", "mitre_assessment", "assessment_id"),
    ):
        for index, source in enumerate(ground_truth[collection]):
            assert _chunk(corpus, chunk_type, source[identifier])["source"][
                "json_pointer"
            ] == f"/{collection}/{index}"
    assert _chunk(corpus, "limitation")["source"]["json_pointer"] == (
        "/summary/limitations/0"
    )


def test_object_ids_use_ground_truth_ids_and_aggregates_use_null() -> None:
    corpus = _build()
    expected_ids = {
        "entity": "entity_id",
        "fact": "fact_id",
        "relationship": "relationship_id",
        "evidence": "evidence_id",
        "sigma_finding": "finding_id",
        "mitre_assessment": "assessment_id",
    }
    ground_truth = _ground_truth()
    collections = {
        "entity": "entities",
        "fact": "facts",
        "relationship": "relationships",
        "evidence": "evidence",
        "sigma_finding": "sigma_findings",
        "mitre_assessment": "mitre_assessments",
    }

    for chunk_type, identifier in expected_ids.items():
        expected = {
            item[identifier] for item in ground_truth[collections[chunk_type]]
        }
        actual = {
            item["source"]["object_id"]
            for item in corpus["chunks"]
            if item["chunk_type"] == chunk_type
        }
        assert actual == expected
    assert _chunk(corpus, "scenario_summary")["source"]["object_id"] is None
    assert _chunk(corpus, "limitation")["source"]["object_id"] is None


def test_entity_chunk_has_evidence_fact_relationship_and_provenance_enrichment() -> None:
    chunk = _chunk(_build(), "entity", "entity-synthetic-beta")

    assert chunk["evidence_ids"] == ["evidence-synthetic-1", "evidence-synthetic-2"]
    assert chunk["fact_ids"] == [
        "fact-synthetic-alpha-activity",
        "fact-synthetic-beta-transition",
    ]
    assert chunk["relationship_ids"] == [
        "relationship-synthetic-alpha-beta",
        "relationship-synthetic-beta-gamma",
    ]
    assert len(chunk["source_references"]) == 4


def test_fact_chunk_preserves_references_and_exact_entity_terms() -> None:
    chunk = _chunk(_build(), "fact", "fact-synthetic-alpha-activity")

    assert chunk["entity_ids"] == [
        "entity-synthetic-alpha",
        "entity-synthetic-beta",
    ]
    assert chunk["fact_ids"] == ["fact-synthetic-alpha-activity"]
    assert chunk["evidence_ids"] == ["evidence-synthetic-1"]
    assert chunk["source_references"] == [
        {
            "source_file": "synthetic_events.jsonl",
            "raw_record_ref": "fixture:record:1",
        }
    ]


def test_fact_relationship_attribute_links_only_to_existing_relationship() -> None:
    ground_truth = _ground_truth()
    ground_truth["facts"][0]["attributes"]["relationship_id"] = (
        "relationship-synthetic-alpha-beta"
    )

    chunk = _chunk(
        _build(ground_truth), "fact", "fact-synthetic-alpha-activity"
    )

    assert chunk["relationship_ids"] == ["relationship-synthetic-alpha-beta"]


def test_relationship_chunk_preserves_endpoints_evidence_and_references() -> None:
    chunk = _chunk(
        _build(), "relationship", "relationship-synthetic-beta-gamma"
    )

    assert chunk["entity_ids"] == [
        "entity-synthetic-beta",
        "entity-synthetic-gamma",
    ]
    assert chunk["relationship_ids"] == ["relationship-synthetic-beta-gamma"]
    assert chunk["evidence_ids"] == ["evidence-synthetic-2"]
    assert [item["raw_record_ref"] for item in chunk["source_references"]] == [
        "fixture:record:3",
        "fixture:record:4",
    ]


def test_evidence_chunk_has_complete_reverse_references() -> None:
    chunk = _chunk(_build(), "evidence", "evidence-synthetic-1")

    assert chunk["entity_ids"] == [
        "entity-synthetic-alpha",
        "entity-synthetic-beta",
    ]
    assert chunk["fact_ids"] == ["fact-synthetic-alpha-activity"]
    assert chunk["relationship_ids"] == ["relationship-synthetic-alpha-beta"]
    assert chunk["sigma_rule_ids"] == ["rule-synthetic-alpha"]
    assert chunk["mitre_external_ids"] == ["SYN-1001"]


def test_sigma_chunk_links_only_existing_mitre_supporting_rule() -> None:
    alpha = next(
        item
        for item in _build()["chunks"]
        if item["chunk_type"] == "sigma_finding"
        and item["sigma_rule_ids"] == ["rule-synthetic-alpha"]
    )

    assert alpha["evidence_ids"] == ["evidence-synthetic-1"]
    assert alpha["mitre_external_ids"] == ["SYN-1001"]


def test_mitre_chunk_preserves_support_and_aggregates_evidence_references() -> None:
    supported = next(
        item
        for item in _build()["chunks"]
        if item["chunk_type"] == "mitre_assessment"
        and item["mitre_external_ids"] == ["SYN-1001"]
    )
    not_assessed = next(
        item
        for item in _build()["chunks"]
        if item["chunk_type"] == "mitre_assessment"
        and item["mitre_external_ids"] == ["SYN-1002"]
    )

    assert supported["evidence_ids"] == ["evidence-synthetic-1"]
    assert supported["sigma_rule_ids"] == ["rule-synthetic-alpha"]
    assert len(supported["source_references"]) == 2
    assert supported["metadata"]["evidence_support"] == (
        "supported_by_observed_behavior"
    )
    assert not_assessed["evidence_ids"] == []
    assert not_assessed["source_references"] == []
    assert not_assessed["metadata"]["evidence_support"] == "not_assessed"


def test_source_references_are_deduplicated_and_stably_sorted() -> None:
    ground_truth = _ground_truth()
    references = ground_truth["evidence"][0]["source_references"]
    references.insert(0, deepcopy(references[1]))
    references.append(deepcopy(references[0]))

    chunk = _chunk(_build(ground_truth), "evidence", "evidence-synthetic-1")
    pairs = [
        (item["source_file"], item["raw_record_ref"])
        for item in chunk["source_references"]
    ]

    assert pairs == sorted(set(pairs))
    assert len(pairs) == 2


def test_corpus_dimensions_are_union_unique_and_deterministic() -> None:
    ground_truth = _ground_truth()
    dimensions = _build()["queryable_dimensions"]
    expected = sorted(
        set(ground_truth["queryable_dimensions"])
        | retrieval_builder.GENERAL_QUERYABLE_DIMENSIONS
    )

    assert dimensions == expected
    assert len(dimensions) == len(set(dimensions))
    for chunk in _build()["chunks"]:
        assert set(chunk["queryable_dimensions"]) <= set(dimensions)


def test_builder_never_emits_confirmed() -> None:
    assert all(
        not (isinstance(value, str) and value.casefold() == "confirmed")
        for value in _walk(_build())
    )


def test_builder_never_emits_question_or_expected_answer_fields() -> None:
    string_values = {value for value in _walk(_build()) if isinstance(value, str)}

    assert FORBIDDEN_FIELDS.isdisjoint(string_values)


def test_builder_never_emits_embedding_vector_or_llm_fields() -> None:
    string_values = {value for value in _walk(_build()) if isinstance(value, str)}

    assert {"embedding", "embedding_model", "vector", "llm_response"}.isdisjoint(
        string_values
    )


def test_builder_source_has_no_production_scenario_or_knowledge_ids() -> None:
    source = Path(retrieval_builder.__file__).read_text(encoding="utf-8").casefold()

    for forbidden in (
        "mshta",
        "powershell",
        "cmd.exe",
        "t1059.007",
        "t1140",
        "t1218.005",
        "jsonl:line:",
    ):
        assert forbidden not in source


def test_builder_source_has_no_file_io_clock_random_or_uuid_logic() -> None:
    source = Path(retrieval_builder.__file__).read_text(encoding="utf-8").casefold()

    for forbidden in (
        ".open(",
        ".read_text(",
        ".write_text(",
        "json.load(",
        "datetime.now",
        "time.time",
        "import random",
        "import uuid",
        "uuid4",
    ):
        assert forbidden not in source


def test_expected_fixture_and_source_ground_truth_are_fully_synthetic() -> None:
    text = (
        GROUND_TRUTH_PATH.read_text(encoding="utf-8")
        + EXPECTED_PATH.read_text(encoding="utf-8")
    ).casefold()

    for forbidden in (
        "mshta",
        "powershell",
        "cmd.exe",
        "t1059.007",
        "t1140",
        "t1218.005",
        "jsonl:line:",
    ):
        assert forbidden not in text


def test_invalid_ground_truth_is_wrapped_as_build_error() -> None:
    ground_truth = _ground_truth()
    del ground_truth["scenario"]

    with pytest.raises(RetrievalCorpusBuildError, match="Invalid Ground Truth Core"):
        _build(ground_truth)


@pytest.mark.parametrize("path", ("", "   ", None, 42))
def test_invalid_source_path_is_rejected(path: object) -> None:
    with pytest.raises(RetrievalCorpusBuildError, match="source_ground_truth_path"):
        build_retrieval_corpus(
            _ground_truth(),
            source_ground_truth_path=path,  # type: ignore[arg-type]
            source_ground_truth_sha256=SOURCE_SHA256,
        )


@pytest.mark.parametrize("digest", ("", "a" * 63, "a" * 65, "g" * 64, None))
def test_invalid_source_hash_is_rejected(digest: object) -> None:
    with pytest.raises(RetrievalCorpusBuildError, match="source_ground_truth_sha256"):
        build_retrieval_corpus(
            _ground_truth(),
            source_ground_truth_path=SOURCE_PATH,
            source_ground_truth_sha256=digest,  # type: ignore[arg-type]
        )


def test_literal_fact_terms_are_not_misclassified_as_entities() -> None:
    ground_truth = _ground_truth()
    ground_truth["facts"].append(
        {
            "fact_id": "fact-synthetic-literal",
            "subject": "literal subject",
            "predicate": "describes",
            "object": {"literal": "object"},
            "attributes": {},
            "status": "inferred",
            "evidence_ids": [],
            "source_references": [],
        }
    )

    chunk = _chunk(_build(ground_truth), "fact", "fact-synthetic-literal")

    assert chunk["entity_ids"] == []
    assert "literal subject" in chunk["content"]
    assert '{"literal":"object"}' in chunk["content"]


def test_reordering_id_based_source_collections_preserves_ids_and_semantics() -> None:
    original = _build()
    reordered_ground_truth = _ground_truth()
    for field in (
        "entities",
        "facts",
        "relationships",
        "evidence",
        "sigma_findings",
        "mitre_assessments",
    ):
        reordered_ground_truth[field].reverse()

    reordered = _build(reordered_ground_truth)

    assert reordered["corpus_id"] == original["corpus_id"]
    assert {item["chunk_id"] for item in reordered["chunks"]} == {
        item["chunk_id"] for item in original["chunks"]
    }
    assert _without_pointers(reordered) == _without_pointers(original)


def test_warning_and_review_policy_is_deterministic() -> None:
    ground_truth = _ground_truth()
    ground_truth["warnings"].append(ground_truth["warnings"][0])

    corpus = _build(ground_truth)

    assert corpus["warnings"] == sorted(set(ground_truth["warnings"]))
    assert corpus["review"] == {
        "review_status": "pending_human_review",
        "reviewer": None,
        "reviewed_at": None,
        "notes": [
            "This corpus was generated automatically from a validated Ground Truth Core document.",
            "The generated corpus has not been reviewed by a human.",
        ],
    }


def test_source_path_and_hash_are_preserved_without_file_access() -> None:
    corpus = build_retrieval_corpus(
        _ground_truth(),
        source_ground_truth_path=Path("logical") / "ground_truth.json",
        source_ground_truth_sha256=SOURCE_SHA256.upper(),
    )

    assert corpus["source_ground_truth"]["path"] == "logical/ground_truth.json"
    assert corpus["source_ground_truth"]["sha256"] == SOURCE_SHA256


def test_chunk_content_contains_required_source_semantics() -> None:
    corpus = _build()

    assert "Type: synthetic_agent" in _chunk(
        corpus, "entity", "entity-synthetic-alpha"
    )["content"]
    assert "Predicate: initiates_activity" in _chunk(
        corpus, "fact", "fact-synthetic-alpha-activity"
    )["content"]
    assert "Source: Alpha display override" in _chunk(
        corpus, "relationship", "relationship-synthetic-alpha-beta"
    )["content"]
    assert "provider=Synthetic-Provider" in _chunk(
        corpus, "evidence", "evidence-synthetic-1"
    )["content"]
    assert "Caveats: known_unmapped_field: SyntheticField" in next(
        item
        for item in corpus["chunks"]
        if item["chunk_type"] == "sigma_finding"
        and item["sigma_rule_ids"] == ["rule-synthetic-beta"]
    )["content"]
    assert "Evidence support: not_assessed" in next(
        item
        for item in corpus["chunks"]
        if item["chunk_type"] == "mitre_assessment"
        and item["mitre_external_ids"] == ["SYN-1002"]
    )["content"]


def test_chunk_order_uses_fixed_type_then_source_identity() -> None:
    chunks = _build()["chunks"]
    keys = []
    for chunk in chunks:
        source = chunk["source"]
        identity = source["object_id"] or source["json_pointer"]
        keys.append(
            (
                retrieval_builder.CHUNK_TYPE_RANK[chunk["chunk_type"]],
                identity,
            )
        )

    assert keys == sorted(keys)


def test_retrieval_validation_failures_are_wrapped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(_: object) -> None:
        raise retrieval_builder.RetrievalCorpusValidationError("synthetic rejection")

    monkeypatch.setattr(retrieval_builder, "validate_retrieval_corpus", reject)

    with pytest.raises(RetrievalCorpusBuildError, match="synthetic rejection"):
        _build()
