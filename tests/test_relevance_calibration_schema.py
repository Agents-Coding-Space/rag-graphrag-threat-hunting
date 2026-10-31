"""Report read-back verifies complete compact outcomes without embedding or gate IO."""

from copy import deepcopy
import json

import pytest

from threat_hunting.evaluation import (
    CalibrationReportValidationError, build_calibration_report,
    calibrate_relevance_policies, load_calibration_report, validate_calibration_report,
)
from threat_hunting.evaluation import relevance_calibration as engine
from test_relevance_calibration import calibration_inputs


def report_document():
    dataset, contexts, policies, config = calibration_inputs()
    result = calibrate_relevance_policies(dataset, contexts, candidate_policies=policies,
                                         selection_constraints=config["selection_constraints"])
    scenario = dataset["scenario_id"]
    fields = {
        "dataset": ("graphrag-relevance-calibration-dataset/v1", {"dataset_id": dataset["dataset_id"], "scenario_id": scenario}),
        "config": (config["schema_version"], {"calibration_id": config["calibration_id"]}),
        "corpus": ("retrieval-corpus/v1", {"corpus_id": "synthetic-corpus", "scenario_id": scenario}),
        "vector_index": ("vector-index/v1", {"index_id": "synthetic-index", "corpus_id": "synthetic-corpus", "scenario_id": scenario}),
        "graph": ("knowledge-graph/v1", {"graph_id": "synthetic-graph", "scenario_id": scenario}),
        "ground_truth": ("scenario-ground-truth/v1", {"scenario_id": scenario}),
    }
    provenance = {name: {"path": name + ".json", "sha256": "1" * 64, "schema_version": schema, **identity}
                  for name, (schema, identity) in fields.items()}
    provenance["embedding"] = {"provider": "sentence-transformers", "model_id": "synthetic-model", "model_revision": "a" * 40,
                               "dimension": 3, "distance_metric": "cosine", "normalization": "l2", "document_prefix": "", "query_prefix": ""}
    report = build_calibration_report(result, calibration_id=config["calibration_id"], provenance=provenance,
                                      candidate_search_space=config["candidate_search_space"],
                                      execution={"graphrag_context_count": 4, "embedding_backend_count": 1,
                                                 **{name: config[name] for name in ("retrieval", "traversal", "embedding_runtime")}})
    return report


@pytest.fixture
def report():
    return report_document()


def test_report_detached_inputs_and_no_full_context(report):
    before = deepcopy(report)
    built = build_calibration_report(report["calibration"], calibration_id=report["calibration_id"],
                                     provenance=report["provenance"], candidate_search_space=report["candidate_search_space"],
                                     execution=report["execution"])
    assert built == before
    built["calibration"]["cases"][0]["signals"]["retrieval_hit_count"] = 999
    built["provenance"]["corpus"]["corpus_id"] = "changed"
    assert report == before
    assert "hits" not in report["calibration"]["cases"][0]
    assert report["review"] == {"status": "pending_human_review", "reviewer": None, "reviewed_at": None}


def test_strict_readback_no_gate_or_model(tmp_path, report, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("report validation must not rerun the relevance gate")
    monkeypatch.setattr(engine, "assess_graphrag_relevance", forbidden)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, allow_nan=False), encoding="utf-8")
    assert load_calibration_report(path) == report


def test_builder_invalid_nonfinite_input_uses_report_error(report):
    report["provenance"]["embedding"]["dimension"] = float("inf")
    with pytest.raises(CalibrationReportValidationError):
        build_calibration_report(report["calibration"], calibration_id=report["calibration_id"],
                                 provenance=report["provenance"], candidate_search_space=report["candidate_search_space"],
                                 execution=report["execution"])


@pytest.mark.parametrize("location", [
    (), ("provenance",), ("provenance", "dataset"), ("provenance", "embedding"),
    ("execution",), ("review",), ("calibration",), ("calibration", "cases", 0),
    ("calibration", "cases", 0, "signals"), ("calibration", "cases", 0, "policy_results", 0),
    ("calibration", "candidate_results", 0), ("calibration", "candidate_results", 0, "metrics"),
])
@pytest.mark.parametrize("operation", ["missing", "extra"])
def test_report_exact_keys(report, location, operation):
    target = report
    for name in location:
        target = target[name]
    if operation == "extra":
        target["extra"] = 0
    else:
        del target[next(iter(target))]
    with pytest.raises(CalibrationReportValidationError):
        validate_calibration_report(report)


@pytest.mark.parametrize("location,value", [
    (("schema_version",), "bad"), (("calibration_id",), "different"),
    (("review", "status"), "confirmed"), (("review", "reviewer"), "unexpected"),
    (("provenance", "corpus", "sha256"), "z" * 64),
    (("provenance", "dataset", "scenario_id"), "different"),
    (("provenance", "vector_index", "corpus_id"), "different"),
    (("provenance", "embedding", "provider"), "other"),
    (("provenance", "embedding", "model_revision"), "main"),
    (("provenance", "embedding", "dimension"), True),
    (("execution", "graphrag_context_count"), 3), (("execution", "embedding_backend_count"), 2),
    (("calibration", "candidate_count"), 1), (("calibration", "case_count"), True),
    (("calibration", "selection_status"), "no_eligible_policy"),
    (("calibration", "selected_policy"), None), (("calibration", "selected_policy_metrics"), None),
    (("calibration", "selected_policy_metrics", "accuracy"), True),
    (("calibration", "candidate_results", 0, "metrics", "accuracy"), 0.5),
    (("calibration", "candidate_results", 0, "confusion_matrix", "tp"), 99),
    (("calibration", "candidate_results", 0, "eligible"), False),
    (("calibration", "candidate_results", 0, "false_positive_case_ids"), ["invented"]),
    (("calibration", "cases", 0, "actual_decision"), "confirmed"),
    (("calibration", "cases", 0, "signals", "top_cosine_score"), float("nan")),
    (("calibration", "cases", 0, "signals", "lexical_hit_count"), 999),
    (("calibration", "cases", 0, "policy_results", 0, "actual_decision"), "confirmed"),
    (("calibration", "cases", 0, "policy_results", 0, "reason_codes"), ["invented"]),
])
def test_report_consistency_and_forbidden_states(report, location, value):
    target = report
    for name in location[:-1]:
        target = target[name]
    target[location[-1]] = value
    with pytest.raises(CalibrationReportValidationError):
        validate_calibration_report(report)


@pytest.mark.parametrize("collection", ["cases", "candidate_results"])
def test_duplicate_and_unordered_results_rejected(report, collection):
    report["calibration"][collection][1] = deepcopy(report["calibration"][collection][0])
    with pytest.raises(CalibrationReportValidationError):
        validate_calibration_report(report)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'\xff', b'{'])
def test_report_duplicate_nonfinite_encoding_loader_errors(tmp_path, raw):
    path = tmp_path / "bad-report.json"
    path.write_bytes(raw)
    with pytest.raises(CalibrationReportValidationError, match="bad-report.json"):
        load_calibration_report(path)
