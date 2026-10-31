"""Contract, loader, Unicode deduplication and benchmark curation checks."""

from __future__ import annotations

import ast
import builtins
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
import json
from pathlib import Path
import re
import socket
from types import MappingProxyType
import unicodedata

import pytest

from threat_hunting.evaluation import (
    RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION,
    RelevanceCalibrationDatasetValidationError,
    load_relevance_calibration_dataset,
    validate_relevance_calibration_dataset,
)
from threat_hunting.evaluation import relevance_dataset


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "tests/fixtures/evaluation/relevance_calibration_minimal.json"
BENCHMARK_PATH = ROOT / "benchmarks/graphrag/mshta_relevance_calibration.json"
IMPLEMENTATION_PATH = ROOT / "src/threat_hunting/evaluation/relevance_dataset.py"
CATEGORIES = {
    "relevant_direct": "proceed", "relevant_paraphrase": "proceed",
    "insufficient_evidence": "abstain", "unrelated": "abstain",
}

# This curation profile records reviewed source availability, not LLM answers.
# Actual source bytes and all anchor resolutions are verified operationally and
# recorded in the review inventory; ordinary pytest needs only tracked files.
CURATION_PROFILE = {
    "ground_truth_sha256": "b2e3aa48c2c20e6a49479e765db0a1d660121fdb70472ca36f308b1094ddbc41",
    "scenario_id": "mshta-powershell",
    "section_counts": {"entities": 3, "facts": 2, "relationships": 2, "evidence": 2, "mitre_assessments": 3},
    "allowed_anchor_paths": frozenset({
        "/facts", "/relationships", "/facts/1", "/relationships/0", "/facts/0",
        "/relationships/1", "/evidence/0", "/evidence/1", "/mitre_assessments/2",
        "/mitre_assessments/0", "/summary/limitations", "/review/notes",
        "/facts/0/source_references", "/evidence/0/observations", "/entities",
        "/mitre_assessments/0/rationale", "/summary/observed_behavior",
        "/evidence/1/observations", "/evidence", "/review", "/mitre_assessments/1",
        "/mitre_assessments/1/rationale", "/mitre_assessments/1/evidence_support",
        "/scenario/description",
    }),
    "known_processes": frozenset({"cmd.exe", "mshta.exe", "powershell.exe"}),
    "known_raw_refs": frozenset({"jsonl:line:4", "jsonl:line:30", "jsonl:line:275", "jsonl:line:398"}),
    "technique_availability": {
        "T1218.005": ("candidate", "supported_by_observed_behavior", "needs_review"),
        "T1059.007": ("candidate", "not_supported_by_observed_command", "needs_review"),
        "T1140": ("candidate", "not_assessed", "needs_review"),
    },
    "reviewed_scope": "two reviewed behavior/evidence groups",
    "full_dataset_negative_scan_performed": False,
    "review_status": "pending_human_review",
}

# Each tuple contains acceptable independently reviewed anchor bundles for a
# topic. The two spawn topics share a tag but retain their distinct source sets.
CURATED_TOPIC_ANCHORS = {
    "process_chain": ({"/facts", "/relationships"},),
    "process_parent": ({"/facts/1", "/relationships/0"},),
    "process_spawn_evidence": (
        {"/facts/0", "/relationships/1", "/evidence/0"},
        {"/facts/1", "/relationships/0", "/evidence/1"},
    ),
    "technique_assessment": ({"/mitre_assessments/2"},),
    "technique_support_status": ({"/mitre_assessments/0"},),
    "scope_limitations": ({"/summary/limitations", "/review/notes"},),
    "relation_provenance": ({"/facts/0/source_references", "/evidence/0/observations"},),
    "process_chain_paraphrase": ({"/entities", "/relationships"}, {"/facts", "/relationships"}),
    "process_parent_paraphrase": ({"/facts/1", "/evidence/1"},),
    "technique_review_paraphrase": ({"/mitre_assessments/2", "/review/notes"},),
    "technique_support_paraphrase": ({"/mitre_assessments/0/rationale", "/summary/observed_behavior"},),
    "evidence_provenance_paraphrase": ({"/evidence/0/observations", "/evidence/1/observations"},),
    "human_review_paraphrase": ({"/summary/limitations", "/review/notes"},),
    "observed_action_paraphrase": ({"/summary/observed_behavior"},),
    "missing_download_evidence": ({"/evidence", "/summary/observed_behavior", "/summary/limitations"},),
    "missing_c2_evidence": ({"/evidence", "/summary/limitations"},),
    "missing_attribution_evidence": ({"/entities", "/evidence", "/summary/limitations", "/review"},),
    "missing_credential_theft_evidence": ({"/evidence", "/summary/observed_behavior", "/summary/limitations"},),
    "missing_destructive_evidence": ({"/evidence", "/summary/observed_behavior", "/summary/limitations"},),
    "missing_decoded_content": ({"/evidence", "/mitre_assessments/1", "/summary/limitations"},),
    "missing_decoding_evidence": ({"/mitre_assessments/1/rationale", "/mitre_assessments/1/evidence_support"},),
    "missing_final_determination": ({"/review/notes", "/summary/limitations"},),
    **{name: ({"/scenario/description"},) for name in (
        "out_of_scope_weather", "out_of_scope_pricing", "out_of_scope_linux_scheduling",
        "out_of_scope_sql_injection", "out_of_scope_ransomware", "out_of_scope_kubernetes",
        "out_of_scope_learning", "out_of_scope_opaque_token",
    )},
}


def _document() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _counts(document: dict) -> None:
    cases = document["cases"]
    document["metadata"] = {
        "case_count": len(cases),
        "category_counts": {name: sum(case["category"] == name for case in cases) for name in CATEGORIES},
        "language_counts": {name: sum(case["language"] == name for case in cases) for name in ("en", "vi")},
        "decision_counts": {name: sum(case["expected_decision"] == name for case in cases) for name in ("proceed", "abstain")},
    }


def _at(document: dict, path: tuple) -> object:
    result = document
    for field in path:
        result = result[field]
    return result


def _walk(value: object):
    yield value
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":")).encode("utf-8")


def test_valid_generic_fixture_and_public_exports() -> None:
    document = _document()
    assert validate_relevance_calibration_dataset(document) is None
    assert document["schema_version"] == RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION
    assert RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION == "graphrag-relevance-calibration-dataset/v1"
    assert RelevanceCalibrationDatasetValidationError is relevance_dataset.RelevanceCalibrationDatasetValidationError
    assert issubclass(RelevanceCalibrationDatasetValidationError, ValueError)
    assert validate_relevance_calibration_dataset is relevance_dataset.validate_relevance_calibration_dataset
    assert load_relevance_calibration_dataset is relevance_dataset.load_relevance_calibration_dataset


def test_valid_loader_preserves_unicode_bytes_and_returns_independent_documents() -> None:
    original = FIXTURE_PATH.read_bytes()
    expected = json.loads(original)
    first = load_relevance_calibration_dataset(FIXTURE_PATH)
    second = load_relevance_calibration_dataset(FIXTURE_PATH)
    assert first == second == expected
    assert first is not second
    assert first["cases"] is not second["cases"]
    first["cases"][1]["query"] = "Output edit"
    first["metadata"]["case_count"] = 99
    assert second == expected
    assert FIXTURE_PATH.read_bytes() == original


def test_generic_validator_accepts_small_unbalanced_arbitrary_scenario() -> None:
    document = _document()
    document["dataset_id"], document["scenario_id"] = "another-dataset", "another-synthetic-scenario"
    document["cases"] = document["cases"][:1]
    document["cases"][0]["tags"] = []
    _counts(document)
    assert validate_relevance_calibration_dataset(document) is None
    assert validate_relevance_calibration_dataset(MappingProxyType(document)) is None


@pytest.mark.parametrize("field", ["schema_version", "dataset_id", "scenario_id", "purpose", "cases", "metadata"])
@pytest.mark.parametrize("operation", ["missing", "unknown"])
def test_exact_top_level_fields(field: str, operation: str) -> None:
    document = _document()
    if operation == "missing":
        del document[field]
    else:
        document[field + "_unexpected"] = document[field]
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        validate_relevance_calibration_dataset(document)
    assert "$" in str(error.value)


@pytest.mark.parametrize("field", ["case_id", "category", "language", "query", "expected_decision", "rationale", "tags"])
@pytest.mark.parametrize("operation", ["missing", "unknown"])
def test_exact_case_fields(field: str, operation: str) -> None:
    document = _document()
    case = document["cases"][0]
    if operation == "missing":
        del case[field]
    else:
        case[field + "_unexpected"] = case[field]
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        validate_relevance_calibration_dataset(document)
    assert "$.cases[0]" in str(error.value)


@pytest.mark.parametrize("field,value", [
    ("schema_version", "unknown/v1"), ("purpose", "production_policy"),
    ("dataset_id", ""), ("dataset_id", " \t"), ("dataset_id", 1),
    ("scenario_id", ""), ("scenario_id", None), ("cases", []), ("cases", {}), ("metadata", []),
])
def test_invalid_root_values(field: str, value: object) -> None:
    document = _document()
    document[field] = value
    with pytest.raises(RelevanceCalibrationDatasetValidationError):
        validate_relevance_calibration_dataset(document)


@pytest.mark.parametrize("field,value", [
    ("case_id", ""), ("case_id", "  "), ("case_id", 1),
    ("category", "other"), ("category", None), ("language", "fr"), ("language", "EN"),
    ("expected_decision", "confirmed"), ("expected_decision", "abstain"),
    ("query", ""), ("query", " \n\t"), ("query", False),
    ("rationale", ""), ("rationale", " \n"), ("rationale", []),
    ("tags", "one"), ("tags", [""]), ("tags", [" "]), ("tags", [1]), ("tags", ["same", "same"]),
])
def test_invalid_case_values(field: str, value: object) -> None:
    document = _document()
    document["cases"][0][field] = value
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        validate_relevance_calibration_dataset(document)
    assert "$.cases[0]" in str(error.value)


@pytest.mark.parametrize("category,decision", [(name, "abstain" if expected == "proceed" else "proceed") for name, expected in CATEGORIES.items()])
def test_category_decision_mapping_is_mandatory(category: str, decision: str) -> None:
    document = _document()
    document["cases"][0].update(category=category, expected_decision=decision)
    _counts(document)
    with pytest.raises(RelevanceCalibrationDatasetValidationError):
        validate_relevance_calibration_dataset(document)


def test_duplicate_case_id_fails_with_case_path() -> None:
    document = _document()
    document["cases"][1]["case_id"] = document["cases"][0]["case_id"]
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        validate_relevance_calibration_dataset(document)
    assert "$.cases[1].case_id" in str(error.value)


@pytest.mark.parametrize("first,second", [
    ("Same question", "Same question"),
    ("Same QUESTION", "same question"),
    ("ＡＢＣ question", "abc question"),
    ("same\t question\n here", "  same question here  "),
    ("Straße", "STRASSE"),
    ("câu hỏi", unicodedata.normalize("NFD", "CÂU HỎI")),
    ("ＱＵＥＲＹ\u00a0ＴＥＸＴ", "query\n text"),
])
def test_queries_deduplicate_after_nfkc_casefold_and_whitespace(first: str, second: str) -> None:
    document = _document()
    document["cases"][0]["query"] = first
    document["cases"][1]["query"] = second
    before = deepcopy(document)
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        validate_relevance_calibration_dataset(document)
    assert "$.cases[1].query" in str(error.value)
    assert document == before


def test_query_normalization_only_checks_duplicates_without_rewriting_text() -> None:
    document = _document()
    document["cases"][0]["query"] = "  ＦＯＯ\tStraße\n tín hiệu Ω  "
    before = deepcopy(document)
    assert validate_relevance_calibration_dataset(document) is None
    assert document == before


COUNTER_PATHS = [
    ("metadata", "case_count"),
    *[("metadata", "category_counts", name) for name in CATEGORIES],
    *[("metadata", "language_counts", name) for name in ("en", "vi")],
    *[("metadata", "decision_counts", name) for name in ("proceed", "abstain")],
]


@pytest.mark.parametrize("path", COUNTER_PATHS)
@pytest.mark.parametrize("value", [True, -1, 1.0, "1", None, 999])
def test_metadata_counters_are_exact_nonnegative_integers_matching_cases(path: tuple, value: object) -> None:
    document = _document()
    _at(document, path[:-1])[path[-1]] = value
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        validate_relevance_calibration_dataset(document)
    assert "$.metadata" in str(error.value)


@pytest.mark.parametrize("path", [("metadata",), ("metadata", "category_counts"), ("metadata", "language_counts"), ("metadata", "decision_counts")])
@pytest.mark.parametrize("operation", ["missing", "unknown", "malformed"])
def test_metadata_requires_all_and_only_declared_counter_fields(path: tuple, operation: str) -> None:
    document = _document()
    target = _at(document, path)
    if operation == "missing":
        del target[next(iter(target))]
    elif operation == "unknown":
        target["other"] = 0
    else:
        _at(document, path[:-1])[path[-1]] = []
    with pytest.raises(RelevanceCalibrationDatasetValidationError):
        validate_relevance_calibration_dataset(document)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
@pytest.mark.parametrize("path", [("metadata", "case_count"), ("cases", 0, "query"), ("cases", 0, "tags")])
def test_nonfinite_numbers_fail_in_memory_anywhere(path: tuple, value: object) -> None:
    document = _document()
    _at(document, path[:-1])[path[-1]] = value
    with pytest.raises(RelevanceCalibrationDatasetValidationError):
        validate_relevance_calibration_dataset(document)


@pytest.mark.parametrize("field", ["expected_answer", "reference_answer", "gold_answer", "generated_answer", "ＥＸＰＥＣＴＥＤ＿ＡＮＳＷＥＲ", "Reference-Answer"])
def test_recursive_answer_guard_is_checked_before_nested_shape(field: str) -> None:
    document = _document()
    document["cases"][0]["tags"] = [{"nested": [{field: "forbidden synthetic answer"}]}]
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        validate_relevance_calibration_dataset(document)
    assert field in str(error.value) or json.dumps(field, ensure_ascii=True) in str(error.value)
    assert "$.cases[0].tags[0].nested[0]" in str(error.value)


@pytest.mark.parametrize("field", ["status", "analysis_status", "review_status", "Review-Status"])
@pytest.mark.parametrize("value", ["confirmed", " CONFIRMED ", ["candidate", "confirmed"], {"nested": ["confirmed"]}])
def test_recursive_confirmed_guard_checks_nested_status_like_values(field: str, value: object) -> None:
    document = _document()
    document["cases"][0]["tags"] = [{field: value}]
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        validate_relevance_calibration_dataset(document)
    assert "confirmed" in str(error.value).casefold()
    assert "$.cases[0].tags[0]" in str(error.value)


def test_confirmed_word_in_question_does_not_become_a_status() -> None:
    document = _document()
    document["cases"][0]["query"] = "What does the word confirmed mean in this synthetic note?"
    assert validate_relevance_calibration_dataset(document) is None


@pytest.mark.parametrize("field", ["threshold", "cosine_threshold", "production_threshold", "production_policy", "relevance_policy", "policy"])
def test_thresholds_and_production_policy_are_forbidden_recursively(field: str) -> None:
    document = _document()
    document["cases"][0]["tags"] = [{"nested": {field: 0.5}}]
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        validate_relevance_calibration_dataset(document)
    assert field in str(error.value)


@pytest.mark.parametrize("value", [(1, 2), {1: "value"}, "\ud800", object()])
def test_non_json_or_invalid_utf8_values_fail_closed(value: object) -> None:
    document = _document()
    document["cases"][0]["tags"] = [value]
    with pytest.raises(RelevanceCalibrationDatasetValidationError):
        validate_relevance_calibration_dataset(document)


def test_cycles_fail_closed_and_leave_input_intact() -> None:
    document = _document()
    document["cases"][0]["tags"] = [document]
    with pytest.raises(RelevanceCalibrationDatasetValidationError):
        validate_relevance_calibration_dataset(document)
    assert document["cases"][0]["tags"][0] is document


@pytest.mark.parametrize("document", [None, [], "dataset", 1, {}])
def test_malformed_root_fails_closed(document: object) -> None:
    with pytest.raises(RelevanceCalibrationDatasetValidationError):
        validate_relevance_calibration_dataset(document)


@pytest.mark.parametrize("location", ["root", "case", "counts"])
def test_loader_rejects_duplicate_json_keys_with_filename_and_path(tmp_path: Path, location: str) -> None:
    document = _document()
    text = json.dumps(document, ensure_ascii=False)
    if location == "root":
        token = '"dataset_id": ' + json.dumps(document["dataset_id"])
        expected_path = "$.dataset_id"
    elif location == "case":
        token = '"query": ' + json.dumps(document["cases"][0]["query"], ensure_ascii=False)
        expected_path = "$.cases[0].query"
    else:
        token = '"relevant_direct": 1'
        expected_path = "$.metadata.category_counts.relevant_direct"
    text = text.replace(token, token + ", " + token, 1)
    path = tmp_path / "duplicate.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        load_relevance_calibration_dataset(path)
    assert str(path) in str(error.value)
    assert expected_path in str(error.value)


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity"])
def test_loader_rejects_nonstandard_json_numbers_with_path(tmp_path: Path, value: str) -> None:
    text = json.dumps(_document(), ensure_ascii=False).replace('"case_count": 4', '"case_count": ' + value)
    path = tmp_path / "nonfinite.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        load_relevance_calibration_dataset(path)
    assert str(path) in str(error.value)
    assert "$.metadata.case_count" in str(error.value)


@pytest.mark.parametrize("payload", [b"\xff", b"{", b"[]", b"{}", b"null"])
def test_loader_invalid_encoding_json_or_root_includes_filename_and_json_path(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(payload)
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        load_relevance_calibration_dataset(path)
    assert str(path) in str(error.value)
    assert "$" in str(error.value)
    assert path.read_bytes() == payload


def test_loader_missing_file_reports_failed_filename_and_root_path(tmp_path: Path) -> None:
    path = tmp_path / "missing.json"
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        load_relevance_calibration_dataset(path)
    assert str(path) in str(error.value)
    assert "$" in str(error.value)


def test_loader_structural_error_includes_precise_case_path(tmp_path: Path) -> None:
    document = _document()
    document["cases"][2]["query"] = " "
    path = tmp_path / "case_error.json"
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        load_relevance_calibration_dataset(path)
    assert str(path) in str(error.value)
    assert "$.cases[2].query" in str(error.value)


def test_success_and_rejection_do_not_mutate_documents() -> None:
    valid = _document()
    invalid = deepcopy(valid)
    invalid["metadata"]["case_count"] = 99
    snapshots = deepcopy((valid, invalid))
    for _ in range(2):
        validate_relevance_calibration_dataset(valid)
        with pytest.raises(RelevanceCalibrationDatasetValidationError):
            validate_relevance_calibration_dataset(invalid)
    assert (valid, invalid) == snapshots
    assert _canonical(valid) == _canonical(snapshots[0])


def test_validator_has_no_io_network_or_embedding_dependency(monkeypatch) -> None:
    document = _document()

    def forbidden(*args, **kwargs):
        pytest.fail("In-memory dataset validation attempted an external operation")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert validate_relevance_calibration_dataset(document) is None


def test_generic_implementation_is_separate_from_production_algorithms_and_questions() -> None:
    source = IMPLEMENTATION_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
    assert not any(name and any(part in name for part in ("graphrag", "retrieval", "sentence_transformers", "embedding_backend", "requests", "socket")) for name in imports)
    for forbidden in ("mshta.exe", "powershell.exe", "t1218.005", "mshta-powershell", "benchmarks/", "outputs/"):
        assert forbidden not in source.casefold()
    numeric_literals = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and type(node.value) is int}
    assert 32 not in numeric_literals
    benchmark = json.loads(BENCHMARK_PATH.read_text(encoding="utf-8"))
    assert all(case["query"] not in source for case in benchmark["cases"])


def test_production_dataset_distribution_and_labels() -> None:
    document = load_relevance_calibration_dataset(BENCHMARK_PATH)
    cases = document["cases"]
    assert len(cases) == 32
    assert Counter(case["category"] for case in cases) == {name: 8 for name in CATEGORIES}
    assert Counter(case["language"] for case in cases) == {"en": 16, "vi": 16}
    assert Counter(case["expected_decision"] for case in cases) == {"proceed": 16, "abstain": 16}
    for category, expected in CATEGORIES.items():
        selected = [case for case in cases if case["category"] == category]
        assert Counter(case["language"] for case in selected) == {"en": 4, "vi": 4}
        assert all(case["expected_decision"] == expected for case in selected)


def test_production_dataset_has_no_answers_thresholds_or_confirmed_statuses() -> None:
    document = load_relevance_calibration_dataset(BENCHMARK_PATH)
    answer_fields = {"expected_answer", "reference_answer", "gold_answer", "generated_answer"}
    for item in _walk(document):
        if isinstance(item, dict):
            for key, value in item.items():
                normalized = unicodedata.normalize("NFKC", key).casefold().replace("-", "_")
                assert normalized not in answer_fields
                assert "threshold" not in normalized
                assert normalized not in {"policy", "production_policy", "relevance_policy"}
                if "status" in normalized or "review" in normalized:
                    assert all(not isinstance(nested, str) or nested.strip().casefold() != "confirmed" for nested in _walk(value))


def test_benchmark_rationale_anchors_match_reviewed_curation_profile_and_add_no_iocs() -> None:
    benchmark = load_relevance_calibration_dataset(BENCHMARK_PATH)
    assert benchmark["scenario_id"] == CURATION_PROFILE["scenario_id"]
    for case in benchmark["cases"]:
        anchors = {tag.removeprefix("ground_truth:") for tag in case["tags"] if tag.startswith("ground_truth:")}
        topics = {tag for tag in case["tags"] if not tag.startswith("ground_truth:")}
        assert anchors and anchors.issubset(CURATION_PROFILE["allowed_anchor_paths"]), case["case_id"]
        assert len(topics) == 1, case["case_id"]
        topic = topics.pop()
        assert topic in CURATED_TOPIC_ANCHORS
        assert any(bundle.issubset(anchors) for bundle in CURATED_TOPIC_ANCHORS[topic]), case["case_id"]
        if topic.startswith("missing_"):
            assert case["category"] == "insufficient_evidence" and case["expected_decision"] == "abstain"
        elif topic.startswith("out_of_scope_"):
            assert case["category"] == "unrelated" and case["expected_decision"] == "abstain"
        else:
            assert case["category"] in {"relevant_direct", "relevant_paraphrase"}
            assert case["expected_decision"] == "proceed"
        rationale = case["rationale"]
        assert set(re.findall(r"\b[a-z][a-z0-9_]*\.exe\b", rationale.casefold())).issubset(CURATION_PROFILE["known_processes"])
        assert set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", rationale)).issubset(CURATION_PROFILE["technique_availability"])
        assert set(re.findall(r"jsonl:line:\d+", rationale)).issubset(CURATION_PROFILE["known_raw_refs"])
        assert re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", rationale) is None
        assert re.search(r"https?://", rationale, re.IGNORECASE) is None


def test_production_validation_preserves_fixture_and_benchmark_bytes() -> None:
    before = {path: path.read_bytes() for path in (FIXTURE_PATH, BENCHMARK_PATH)}
    first = load_relevance_calibration_dataset(BENCHMARK_PATH)
    second = load_relevance_calibration_dataset(BENCHMARK_PATH)
    assert _canonical(first) == _canonical(second)
    assert before == {path: path.read_bytes() for path in before}


def test_clean_clone_validation_needs_no_ignored_outputs(monkeypatch) -> None:
    def guard(operation):
        def checked(path, *args, **kwargs):
            assert "outputs" not in {part.casefold() for part in path.parts}, "Tests must not depend on ignored production artifacts"
            return operation(path, *args, **kwargs)
        return checked

    for name in ("open", "read_bytes", "read_text"):
        monkeypatch.setattr(Path, name, guard(getattr(Path, name)))
    fixture = load_relevance_calibration_dataset(FIXTURE_PATH)
    benchmark = load_relevance_calibration_dataset(BENCHMARK_PATH)
    assert validate_relevance_calibration_dataset(fixture) is None
    assert validate_relevance_calibration_dataset(benchmark) is None
    test_benchmark_rationale_anchors_match_reviewed_curation_profile_and_add_no_iocs()
    test_production_validation_preserves_fixture_and_benchmark_bytes()


def test_loader_json_numeric_overflow_reports_domain_error_and_field_path(tmp_path: Path) -> None:
    text = json.dumps(_document(), ensure_ascii=False).replace('"case_count": 4', '"case_count": 1e999')
    path = tmp_path / "overflow.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        load_relevance_calibration_dataset(path)
    assert str(path) in str(error.value)
    assert "$.metadata.case_count" in str(error.value)


def test_very_large_mismatched_counter_raises_domain_error_without_formatting_value() -> None:
    document = _document()
    document["metadata"]["case_count"] = 10 ** 5000
    with pytest.raises(RelevanceCalibrationDatasetValidationError) as error:
        validate_relevance_calibration_dataset(document)
    assert "$.metadata.case_count" in str(error.value)
