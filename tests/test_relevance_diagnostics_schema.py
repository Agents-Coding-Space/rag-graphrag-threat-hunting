"""Diagnostic read-back recalculates signals, statistics, findings and metadata."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from threat_hunting.evaluation import (
    RelevanceDiagnosticsError, analyze_relevance_separability,
    load_relevance_diagnostics, validate_relevance_diagnostics,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/evaluation/diagnostics"


def diagnostics_document():
    dataset_path = FIXTURES / "dataset.json"
    report_path = FIXTURES / "calibration_report.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return analyze_relevance_separability(
        dataset, report,
        dataset_path=dataset_path.relative_to(ROOT).as_posix(),
        dataset_sha256=sha256(dataset_path.read_bytes()).hexdigest(),
        report_path=report_path.relative_to(ROOT).as_posix(),
        report_sha256=sha256(report_path.read_bytes()).hexdigest(),
    )


@pytest.fixture
def diagnostics():
    return diagnostics_document()


def _target(document, location):
    result = document
    for name in location:
        result = result[name]
    return result


def _refresh_id(document):
    body = {key: value for key, value in document.items() if key != "analysis_id"}
    encoded = json.dumps(body, ensure_ascii=False, sort_keys=True, allow_nan=False,
                         separators=(",", ":")).encode("utf-8")
    document["analysis_id"] = "relevance-diagnostics-" + sha256(encoded).hexdigest()


def test_minimal_diagnostics_valid_detached_and_deterministic(diagnostics):
    before = deepcopy(diagnostics)
    assert validate_relevance_diagnostics(diagnostics) is None
    assert diagnostics == before
    again = diagnostics_document()
    assert json.dumps(again, ensure_ascii=False, sort_keys=True, separators=(",", ":")) == json.dumps(
        diagnostics, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert diagnostics["review"] == {"status": "pending_human_review", "reviewer": None, "reviewed_at": None}
    assert diagnostics["audit"]["signal_snapshot_scope"] == "per_case"
    assert diagnostics["audit"]["diagnostic_verification"] == "policy_outcome_replay_from_canonical_case_signals"
    assert all("policy_results" not in case for case in diagnostics["cases"])


def test_readback_matches_bytes_and_avoids_gate_or_backend(tmp_path, diagnostics, monkeypatch):
    from threat_hunting.graphrag import relevance
    from threat_hunting.retrieval import embedding_backend
    def forbidden(*args, **kwargs):
        pytest.fail("diagnostic read-back must not execute gate or model")
    monkeypatch.setattr(relevance, "assess_graphrag_relevance", forbidden)
    monkeypatch.setattr(embedding_backend, "SentenceTransformerEmbeddingBackend", forbidden)
    path = tmp_path / "diagnostics.json"
    path.write_text(json.dumps(diagnostics, ensure_ascii=False, sort_keys=True, allow_nan=False), encoding="utf-8")
    assert load_relevance_diagnostics(path) == diagnostics
    assert path.read_text(encoding="utf-8").endswith("}")


@pytest.mark.parametrize("location", [
    (), ("provenance",), ("provenance", "dataset"), ("provenance", "calibration_report"),
    ("audit",), ("cases", 0), ("cases", 0, "signals"), ("policies", 0),
    ("selection_constraints",), ("analysis",), ("metadata",), ("review",),
])
@pytest.mark.parametrize("operation", ["missing", "extra"])
def test_every_structural_object_requires_exact_fields(diagnostics, location, operation):
    value = _target(diagnostics, location)
    if operation == "missing":
        del value[next(iter(value))]
    else:
        value["unknown_field"] = 0
    with pytest.raises(RelevanceDiagnosticsError, match=r"\$"):
        validate_relevance_diagnostics(diagnostics)


@pytest.mark.parametrize("location,value", [
    (("schema_version",), "other/v1"), (("analysis_id",), "wrong-id"),
    (("scenario_id",), " "),
    (("provenance", "dataset", "sha256"), "x" * 64),
    (("provenance", "calibration_report", "sha256"), "a" * 63),
    (("provenance", "dataset", "sha256"), "A" * 64),
    (("provenance", "dataset", "dataset_id"), None),
    (("provenance", "calibration_report", "calibration_id"), ""),
    (("provenance", "dataset", "schema_version"), "different"),
    (("provenance", "calibration_report", "schema_version"), "different"),
    (("audit", "signal_snapshot_scope"), "per_policy"),
    (("audit", "historical_invariance_assurance"), "independently_verified"),
    (("audit", "replayed_outcome_count"), True),
    (("audit", "replayed_outcome_count"), -1),
    (("cases", 0, "case_id"), ""), (("cases", 0, "category"), None),
    (("cases", 0, "language"), True), (("cases", 0, "expected_decision"), "confirmed"),
    (("cases", 0, "warnings"), ["z", "a"]),
    (("cases", 0, "warnings"), ["duplicate", "duplicate"]),
    (("cases", 0, "signals", "retrieval_hit_count"), True),
    (("cases", 0, "signals", "retrieval_hit_count"), -1),
    (("cases", 0, "signals", "traversal_performed"), 1),
    (("cases", 0, "signals", "top_cosine_score"), 2),
    (("cases", 0, "signals", "top_cosine_score"), float("nan")),
    (("cases", 0, "signals", "top_cosine_score"), float("inf")),
    (("cases", 0, "signals", "lexical_hit_count"), 999),
    (("cases", 0, "signals", "mapped_hit_count"), 999),
    (("cases", 0, "signals", "joint_lexical_vector_hit_count"), 999),
    (("policies", 0, "min_hits"), True), (("policies", 0, "min_seed_nodes"), -1),
    (("policies", 0, "require_lexical_support"), 1),
    (("policies", 0, "min_cosine_score"), -2),
    (("selection_constraints", "min_f1"), True),
    (("review", "status"), "confirmed"), (("review", "reviewer"), "unexpected"),
    (("review", "reviewed_at"), "2026-01-01"),
])
def test_invalid_values_fail_closed_with_json_path(diagnostics, location, value):
    parent = _target(diagnostics, location[:-1])
    parent[location[-1]] = value
    with pytest.raises(RelevanceDiagnosticsError, match=r"\$"):
        validate_relevance_diagnostics(diagnostics)


@pytest.mark.parametrize("collection", ["cases", "policies"])
@pytest.mark.parametrize("operation", ["duplicate", "reverse", "empty", "wrong-type"])
def test_id_collections_must_be_nonempty_unique_and_sorted(diagnostics, collection, operation):
    if operation == "duplicate":
        diagnostics[collection][1] = deepcopy(diagnostics[collection][0])
    elif operation == "reverse":
        diagnostics[collection].reverse()
    elif operation == "empty":
        diagnostics[collection] = []
    else:
        diagnostics[collection] = {}
    with pytest.raises(RelevanceDiagnosticsError):
        validate_relevance_diagnostics(diagnostics)


def test_duplicate_policy_body_with_distinct_id_is_rejected(diagnostics):
    duplicate = deepcopy(diagnostics["policies"][0])
    duplicate["policy_id"] = "unique-policy-name"
    diagnostics["policies"].append(duplicate)
    diagnostics["policies"].sort(key=lambda policy: policy["policy_id"])
    with pytest.raises(RelevanceDiagnosticsError, match="duplicate policy body"):
        validate_relevance_diagnostics(diagnostics)


@pytest.mark.parametrize("section", ["analysis", "metadata", "warnings"])
def test_forged_derived_sections_fail_even_with_rehashed_id(diagnostics, section):
    if isinstance(diagnostics[section], dict):
        diagnostics[section]["forged"] = 0
    else:
        diagnostics[section].append("forged")
    _refresh_id(diagnostics)
    with pytest.raises(RelevanceDiagnosticsError, match=rf"\$\.{section}"):
        validate_relevance_diagnostics(diagnostics)


@pytest.mark.parametrize("location", [
    ("analysis", "distributions"),
    ("analysis", "statistics"),
    ("analysis", "statistics", "by_expected_decision", "proceed", "retrieval_hit_count"),
    ("analysis", "numeric_ranges", 0),
    ("analysis", "collisions", 0),
    ("analysis", "dominance"),
    ("analysis", "dominance", "conflicts", 0),
    ("analysis", "policy_failures"),
    ("analysis", "policy_failures", "highest_metrics"),
    ("analysis", "policy_failures", "candidate_results", 0),
    ("analysis", "policy_failures", "candidate_results", 0, "metrics"),
    ("analysis", "trade_off_frontier", 0),
    ("analysis", "findings", 0),
    ("analysis", "findings", 0, "evidence"),
])
@pytest.mark.parametrize("operation", ["missing", "extra"])
def test_nested_analysis_contracts_are_strict(diagnostics, location, operation):
    target = _target(diagnostics, location)
    if operation == "missing":
        del target[next(iter(target))]
    else:
        target["unknown"] = None
    _refresh_id(diagnostics)
    with pytest.raises(RelevanceDiagnosticsError, match=r"\$\.analysis"):
        validate_relevance_diagnostics(diagnostics)


@pytest.mark.parametrize("location,value", [
    (("analysis", "collisions", 0, "case_ids"), ["unknown-case"]),
    (("analysis", "dominance", "conflicts", 0, "proceed_case_id"), "unknown-case"),
    (("analysis", "dominance", "conflicts", 0, "abstain_case_id"), "unknown-case"),
    (("analysis", "policy_failures", "candidate_results", 0, "policy_id"), "unknown-policy"),
    (("analysis", "trade_off_frontier", 0, "representative_policy_id"), "unknown-policy"),
    (("analysis", "trade_off_frontier", 0, "equivalent_policy_ids"), ["unknown-policy"]),
    (("analysis", "findings", 0, "evidence", "case_ids"), ["unknown-case"]),
    (("analysis", "findings", 0, "status"), "confirmed"),
    (("analysis", "policy_failures", "highest_metrics", "f1"), 1.0),
    (("analysis", "statistics", "by_expected_decision", "proceed", "retrieval_hit_count", "mean"), 999),
    (("metadata", "collision_count"), 999),
    (("metadata", "dominance_conflict_count"), 999),
])
def test_references_statistics_findings_and_counts_are_verified(diagnostics, location, value):
    parent = _target(diagnostics, location[:-1])
    parent[location[-1]] = value
    _refresh_id(diagnostics)
    with pytest.raises(RelevanceDiagnosticsError):
        validate_relevance_diagnostics(diagnostics)


def _first_numeric(container, path=()):
    if isinstance(container, dict):
        for key in sorted(container):
            result = _first_numeric(container[key], (*path, key))
            if result is not None:
                return result
    elif isinstance(container, list):
        for index, item in enumerate(container):
            result = _first_numeric(item, (*path, index))
            if result is not None:
                return result
    elif type(container) in (float, int):
        return path
    return None


@pytest.mark.parametrize("section", ["analysis", "metadata"])
def test_derived_numeric_types_exclude_booleans(diagnostics, section):
    location = _first_numeric(diagnostics[section])
    assert location is not None
    parent = _target(diagnostics[section], location[:-1])
    parent[location[-1]] = True
    _refresh_id(diagnostics)
    with pytest.raises(RelevanceDiagnosticsError):
        validate_relevance_diagnostics(diagnostics)


def test_loaded_semantic_failure_retains_filename_and_nested_json_path(tmp_path, diagnostics):
    diagnostics["cases"][0]["signals"]["retrieval_hit_count"] = -1
    path = tmp_path / "invalid-signals.json"
    path.write_text(json.dumps(diagnostics), encoding="utf-8")
    with pytest.raises(RelevanceDiagnosticsError, match=r"invalid-signals\.json.*\$\.cases\[0\]\.signals"):
        load_relevance_diagnostics(path)


@pytest.mark.parametrize("raw", [
    b'{"schema_version":1,"schema_version":2}',
    b'{"nested":{"x":1,"x":2}}',
    b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
    b'{"value":1e999}', b'\xff', b'{', b'[]', b'null',
])
def test_strict_loader_rejects_duplicate_nonfinite_encoding_and_shape(tmp_path, raw):
    path = tmp_path / "bad-diagnostics.json"
    path.write_bytes(raw)
    with pytest.raises(RelevanceDiagnosticsError, match=r"bad-diagnostics\.json.*\$"):
        load_relevance_diagnostics(path)


def test_loader_missing_file_has_filename_and_path(tmp_path):
    with pytest.raises(RelevanceDiagnosticsError, match=r"missing\.json.*\$"):
        load_relevance_diagnostics(tmp_path / "missing.json")


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), object(), {1: "value"}])
def test_invalid_native_json_uses_diagnostics_exception(invalid):
    with pytest.raises(RelevanceDiagnosticsError):
        validate_relevance_diagnostics(invalid)


def test_cyclic_json_rejected_without_mutation():
    document = {}
    document["cycle"] = document
    with pytest.raises(RelevanceDiagnosticsError, match="cyclic"):
        validate_relevance_diagnostics(document)
    assert document["cycle"] is document
