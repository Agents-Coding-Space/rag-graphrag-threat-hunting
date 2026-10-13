"""Synthetic selection CLI checks, strict input and transactional publication."""

from __future__ import annotations

import ast
import builtins
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
from typing import Any
import urllib.request

import pytest

from threat_hunting.evaluation import validate_embedding_model_selection
from threat_hunting.evaluation.embedding_retrieval_comparison import _complete_report


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/select_embedding_model.py"
FIXTURE = Path(__file__).parent / "fixtures/evaluation/embedding_model_selection/input_comparison.json"
SPEC = importlib.util.spec_from_file_location("testable_embedding_model_selection_cli", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)

SUMMARY_FIELDS = {
    "output_path", "output_size_bytes", "output_sha256", "evaluation_id",
    "baseline_candidate_id", "eligible_candidate_count", "decision",
    "recommended_candidate_id", "review_status",
}


def _bytes(document: object) -> bytes:
    return json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8") + b"\n"


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    root = tmp_path / "repository"
    root.mkdir()
    wrapper = json.loads(FIXTURE.read_text(encoding="utf-8"))
    report, policy = wrapper["comparison_report"], wrapper["policy"]
    policy["tie_break_policy"] = "human_review"
    report_path = root / "inputs/synthetic_comparison.json"
    policy_path = root / "configs/evaluation/synthetic_selection_policy.json"
    report_path.parent.mkdir(parents=True)
    policy_path.parent.mkdir(parents=True)
    report_path.write_bytes(_bytes(report))
    policy_path.write_bytes(_bytes(policy))
    monkeypatch.setattr(cli, "REPOSITORY_ROOT", root)
    return SimpleNamespace(
        root=root, report=report, policy=policy, report_path=report_path,
        report_sha256=sha256(report_path.read_bytes()).hexdigest(),
        policy_path=policy_path, output=root / "outputs/evaluation/synthetic/selection.json",
    )


def _save_report(workspace: SimpleNamespace) -> None:
    workspace.report_path.write_bytes(_bytes(workspace.report))
    workspace.report_sha256 = sha256(workspace.report_path.read_bytes()).hexdigest()


def _save_policy(workspace: SimpleNamespace) -> None:
    workspace.policy_path.write_bytes(_bytes(workspace.policy))


def _args(workspace: SimpleNamespace, *, overwrite: bool = False, relative: bool = False) -> list[str]:
    def label(path: Path) -> str:
        return path.relative_to(workspace.root).as_posix() if relative else str(path)

    arguments = [
        "--comparison-report", label(workspace.report_path),
        "--comparison-report-sha256", workspace.report_sha256,
        "--policy", label(workspace.policy_path), "--output", label(workspace.output),
    ]
    if overwrite:
        arguments.append("--overwrite")
    return arguments


def _run(workspace: SimpleNamespace, *, overwrite: bool = False) -> dict[str, Any]:
    return cli.run_selection_cli(
        comparison_report_path=workspace.report_path,
        comparison_report_sha256=workspace.report_sha256,
        policy_path=workspace.policy_path, output_path=workspace.output,
        overwrite=overwrite,
    )


def _assert_no_temporary_files(workspace: SimpleNamespace) -> None:
    allowed = {path for path in (workspace.report_path, workspace.policy_path, workspace.output) if path.is_file()}
    assert {path for path in workspace.root.rglob("*") if path.is_file()} == allowed


def _failure(workspace: SimpleNamespace, capsys: Any, *, overwrite: bool = False) -> str:
    assert cli.main(_args(workspace, overwrite=overwrite)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error:") and captured.err.endswith("\n")
    _assert_no_temporary_files(workspace)
    return captured.err


def _old_output(workspace: SimpleNamespace, existing: bool) -> bytes:
    old = b"previous reviewed output bytes\r\n"
    if existing:
        workspace.output.parent.mkdir(parents=True)
        workspace.output.write_bytes(old)
    return old


def _assert_output_preserved(workspace: SimpleNamespace, existing: bool, old: bytes) -> None:
    if existing:
        assert workspace.output.read_bytes() == old
    else:
        assert not workspace.output.exists()
    _assert_no_temporary_files(workspace)


def _spy_core(monkeypatch: pytest.MonkeyPatch) -> list[tuple[dict, dict]]:
    real = cli.evaluate_embedding_model_candidates
    calls: list[tuple[dict, dict]] = []

    def evaluate(report: dict, *, policy: dict) -> dict:
        calls.append(deepcopy((report, policy)))
        return real(report, policy=policy)

    monkeypatch.setattr(cli, "evaluate_embedding_model_candidates", evaluate)
    return calls


def test_success_calls_existing_core_once_and_validates_read_back(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
) -> None:
    calls = _spy_core(monkeypatch)
    validations: list[tuple[dict, dict, dict]] = []
    validate = cli.validate_embedding_model_selection

    def validate_output(selection: dict, *, comparison_report: dict, policy: dict) -> None:
        validations.append(deepcopy((selection, comparison_report, policy)))
        validate(selection, comparison_report=comparison_report, policy=policy)

    monkeypatch.setattr(cli, "validate_embedding_model_selection", validate_output)
    original_report = workspace.report_path.read_bytes()
    original_policy = workspace.policy_path.read_bytes()
    before_documents = deepcopy((workspace.report, workspace.policy))
    assert cli.main(_args(workspace)) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and captured.out.count("\n") == 1
    summary = json.loads(captured.out)
    assert set(summary) == SUMMARY_FIELDS
    assert captured.out == _bytes(summary).decode("utf-8")
    assert len(calls) == 1 and calls[0] == before_documents
    assert calls[0][1]["tie_break_policy"] == "human_review"
    assert len(validations) == 2
    assert all(context_report == workspace.report and context_policy == workspace.policy
               for _, context_report, context_policy in validations)
    payload = workspace.output.read_bytes()
    selection = json.loads(payload.decode("utf-8"))
    assert payload == _bytes(selection)
    assert payload.endswith(b"\n") and not payload.endswith(b"\n\n") and b"\r" not in payload
    assert summary["output_path"] == "outputs/evaluation/synthetic/selection.json"
    assert summary["output_size_bytes"] == len(payload)
    assert summary["output_sha256"] == sha256(payload).hexdigest()
    assert summary["evaluation_id"] == selection["evaluation_id"]
    assert summary["baseline_candidate_id"] == "baseline"
    assert summary["eligible_candidate_count"] == 1
    assert summary["decision"] == "provisional_recommendation"
    assert summary["recommended_candidate_id"] == "candidate-eligible"
    assert summary["review_status"] == "pending_human_review"
    assert selection["review"] == {"review_status": "pending_human_review", "reviewer": None, "reviewed_at": None}
    validate_embedding_model_selection(selection, comparison_report=workspace.report, policy=workspace.policy)
    assert any("does not automatically change" in warning for warning in selection["warnings"])
    assert workspace.report_path.read_bytes() == original_report
    assert workspace.policy_path.read_bytes() == original_policy
    assert (workspace.report, workspace.policy) == before_documents
    _assert_no_temporary_files(workspace)


def test_report_and_policy_are_validated_before_exactly_one_evaluation(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    stages: list[str] = []
    report_validator = cli.validate_embedding_retrieval_comparison_report
    policy_validator = cli.validate_embedding_model_selection_policy
    evaluate = cli.evaluate_embedding_model_candidates

    def report_check(report: dict) -> None:
        stages.append("report")
        report_validator(report)

    def policy_check(policy: dict, *, comparison_report: dict) -> None:
        stages.append("policy")
        policy_validator(policy, comparison_report=comparison_report)

    def core(report: dict, *, policy: dict) -> dict:
        stages.append("evaluation")
        return evaluate(report, policy=policy)

    monkeypatch.setattr(cli, "validate_embedding_retrieval_comparison_report", report_check)
    monkeypatch.setattr(cli, "validate_embedding_model_selection_policy", policy_check)
    monkeypatch.setattr(cli, "evaluate_embedding_model_candidates", core)
    _run(workspace)
    assert stages == ["report", "policy", "evaluation"]


def test_two_runs_with_overwrite_return_identical_bytes_and_detached_summaries(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _spy_core(monkeypatch)
    first = _run(workspace)
    payload = workspace.output.read_bytes()
    second = _run(workspace, overwrite=True)
    assert first == second and workspace.output.read_bytes() == payload
    assert len(calls) == 2
    first["decision"] = "changed locally"
    assert second["decision"] == "provisional_recommendation"
    _assert_no_temporary_files(workspace)


def test_relative_repository_paths_work(workspace: SimpleNamespace, capsys: Any) -> None:
    assert cli.main(_args(workspace, relative=True)) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and json.loads(captured.out)["output_path"].endswith("/selection.json")
    _assert_no_temporary_files(workspace)


def test_unicode_candidate_ids_are_written_as_utf8_without_ascii_escaping(workspace: SimpleNamespace) -> None:
    renamed = "candidate-éligible"
    for descriptor in workspace.report["candidates"]:
        if descriptor["candidate_id"] == "candidate-eligible":
            descriptor["candidate_id"] = renamed
    workspace.report["candidates"].sort(key=lambda item: item["candidate_id"])
    for case in workspace.report["cases"]:
        for ranking in case["rankings"]:
            if ranking["candidate_id"] == "candidate-eligible":
                ranking["candidate_id"] = renamed
        case["rankings"].sort(key=lambda item: item["candidate_id"])
    workspace.report = _complete_report(workspace.report)
    _save_report(workspace)
    summary = _run(workspace)
    payload = workspace.output.read_bytes()
    assert summary["recommended_candidate_id"] == renamed
    assert renamed.encode("utf-8") in payload and b"\\u00e9" not in payload
    assert payload == _bytes(json.loads(payload.decode("utf-8")))


def test_human_review_tie_is_preserved_without_a_recommendation(workspace: SimpleNamespace) -> None:
    for case in workspace.report["cases"]:
        donor = next(row for row in case["rankings"] if row["candidate_id"] == "candidate-eligible")
        recipient = next(row for row in case["rankings"] if row["candidate_id"] == "candidate-priority-miss")
        recipient["hits"] = deepcopy(donor["hits"])
    workspace.report = _complete_report(workspace.report)
    _save_report(workspace)
    summary = _run(workspace)
    assert summary["decision"] == "needs_human_review"
    assert summary["eligible_candidate_count"] == 2 and summary["recommended_candidate_id"] is None
    assert workspace.policy["tie_break_policy"] == "human_review"


def test_no_eligible_candidate_reports_retain_baseline_without_promotion(workspace: SimpleNamespace) -> None:
    workspace.policy["min_priority_language_delta"] = 1.0
    _save_policy(workspace)
    summary = _run(workspace)
    assert summary["decision"] == "retain_baseline"
    assert summary["eligible_candidate_count"] == 0 and summary["recommended_candidate_id"] is None
    assert summary["review_status"] == "pending_human_review"


@pytest.mark.parametrize("missing", ["report_path", "policy_path"])
def test_missing_input_file_fails_before_core(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, missing: str,
) -> None:
    calls = _spy_core(monkeypatch)
    path = getattr(workspace, missing)
    path.unlink()
    assert path.name in _failure(workspace, capsys)
    assert calls == [] and not workspace.output.exists()


@pytest.mark.parametrize("target", ["report", "policy"])
@pytest.mark.parametrize("payload", [
    b"{", b"{} trailing", b'{"same":1,"same":2}',
    b'{"outer":{"same":1,"same":2}}', b'{"value":NaN}',
    b'{"value":Infinity}', b'{"value":-Infinity}', b'{"value":1e999}',
    b"\xff", b'{"value":"\\ud800"}', b'{"\\ud800":"value"}',
    b"[]", b"null", b"true", b'"string"', b"0",
])
def test_all_json_inputs_are_strict_before_core(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
    target: str, payload: bytes,
) -> None:
    calls = _spy_core(monkeypatch)
    path = workspace.report_path if target == "report" else workspace.policy_path
    path.write_bytes(payload)
    if target == "report":
        workspace.report_sha256 = sha256(payload).hexdigest()
    assert path.name in _failure(workspace, capsys)
    assert calls == [] and not workspace.output.exists()


@pytest.mark.parametrize("payload", [
    b"{", b'{"a":1,"a":2}', b'{"x":{"a":1,"a":2}}',
    b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
    b'{"value":1e999}', b"\xff", b'{"value":"\\udfff"}', b"[]", b"null",
])
def test_strict_parser_errors_identify_source_without_loose_json(payload: bytes) -> None:
    with pytest.raises(cli.EmbeddingModelSelectionCliError, match="synthetic.json"):
        cli._parse_json_bytes(payload, source_path="synthetic.json")


@pytest.mark.parametrize("digest", [
    "", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "0x" + "a" * 64,
    " " + "a" * 64, "a" * 64 + "\n",
])
def test_hash_format_is_lowercase_full_sha256_before_core(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, digest: str,
) -> None:
    calls = _spy_core(monkeypatch)
    workspace.report_sha256 = digest
    assert "SHA-256" in _failure(workspace, capsys)
    assert calls == [] and not workspace.output.exists()


def test_wrong_report_hash_is_checked_before_any_json_parse(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
) -> None:
    workspace.report_path.write_bytes(b"malformed bytes with mismatched hash")

    def forbidden_parse(*args: object, **kwargs: object) -> None:
        raise AssertionError("must verify report hash before parsing any JSON")

    monkeypatch.setattr(cli, "_parse_json_bytes", forbidden_parse)
    assert "SHA-256 does not match" in _failure(workspace, capsys)
    assert not workspace.output.exists()


@pytest.mark.parametrize("mutation", ["schema", "baseline", "duplicate_candidate", "aggregate", "delta"])
def test_report_or_candidate_tampering_fails_before_core(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, mutation: str,
) -> None:
    calls = _spy_core(monkeypatch)
    if mutation == "schema":
        workspace.report["schema_version"] = "wrong/v1"
    elif mutation == "baseline":
        workspace.report["baseline_candidate_id"] = "unknown"
    elif mutation == "duplicate_candidate":
        workspace.report["candidates"][1]["candidate_id"] = workspace.report["candidates"][0]["candidate_id"]
    elif mutation == "aggregate":
        workspace.report["aggregates"][0]["metrics"][0]["mrr_at_k"] = 0.123
    else:
        workspace.report["comparisons"][0]["deltas"][0]["metrics"][1]["mrr_at_k"] = 0.123
    _save_report(workspace)
    _failure(workspace, capsys)
    assert calls == [] and not workspace.output.exists()


@pytest.mark.parametrize("mutation", [
    "missing_tie", "invalid_tie", "boolean_tie", "null_tie", "missing_field",
    "extra_field", "missing_cutoff", "missing_language", "confirmed", "forbidden",
])
def test_policy_contract_failures_precede_core(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, mutation: str,
) -> None:
    calls = _spy_core(monkeypatch)
    if mutation == "missing_tie":
        del workspace.policy["tie_break_policy"]
    elif mutation in {"invalid_tie", "boolean_tie", "null_tie"}:
        workspace.policy["tie_break_policy"] = {"invalid_tie": "random", "boolean_tie": True, "null_tie": None}[mutation]
    elif mutation == "missing_field":
        del workspace.policy["primary_metric"]
    elif mutation == "extra_field":
        workspace.policy["unexpected"] = None
    elif mutation == "missing_cutoff":
        workspace.policy["primary_cutoff"] = 7
    elif mutation == "missing_language":
        workspace.policy["priority_language"] = "zz"
    elif mutation == "confirmed":
        workspace.policy["review"]["review_status"] = "CONFIRMED"
    else:
        workspace.policy["review"]["unexpected"] = {"generated_answer": "injected"}
    _save_policy(workspace)
    _failure(workspace, capsys)
    assert calls == [] and not workspace.output.exists()


def test_existing_output_without_overwrite_is_untouched_before_core(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
) -> None:
    old = _old_output(workspace, True)
    calls = _spy_core(monkeypatch)
    assert "--overwrite" in _failure(workspace, capsys)
    assert calls == [] and workspace.output.read_bytes() == old


@pytest.mark.parametrize("kind", ["report", "policy", "outside_repository", "outside_evaluation", "directory"])
def test_unsafe_output_paths_fail_before_core_and_preserve_inputs(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, kind: str,
) -> None:
    calls = _spy_core(monkeypatch)
    before = (workspace.report_path.read_bytes(), workspace.policy_path.read_bytes())
    if kind == "report":
        workspace.output = workspace.report_path
    elif kind == "policy":
        workspace.output = workspace.policy_path
    elif kind == "outside_repository":
        workspace.output = workspace.root.parent / "outside_selection.json"
    elif kind == "outside_evaluation":
        workspace.output = workspace.root / "configs/selection.json"
    else:
        workspace.output.mkdir(parents=True)
    _failure(workspace, capsys, overwrite=True)
    assert calls == []
    assert (workspace.report_path.read_bytes(), workspace.policy_path.read_bytes()) == before


def test_symlink_output_is_rejected_before_core(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
) -> None:
    calls = _spy_core(monkeypatch)
    is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == workspace.output or is_symlink(path))
    assert "symlink" in _failure(workspace, capsys)
    assert calls == [] and not workspace.output.exists()


@pytest.mark.parametrize("overlap", ["same_path", "hardlinked_inputs", "hardlinked_output"])
def test_path_and_inode_aliases_cannot_overwrite_read_only_inputs(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, overlap: str,
) -> None:
    calls = _spy_core(monkeypatch)
    if overlap == "same_path":
        workspace.policy_path.unlink()
        workspace.policy_path = workspace.report_path
    elif overlap == "hardlinked_inputs":
        workspace.policy_path.unlink()
        os.link(workspace.report_path, workspace.policy_path)
    else:
        workspace.output.parent.mkdir(parents=True)
        os.link(workspace.report_path, workspace.output)
    before = workspace.report_path.read_bytes()
    assert "overlap" in _failure(workspace, capsys, overwrite=True)
    assert calls == [] and workspace.report_path.read_bytes() == before


@pytest.mark.parametrize("required", ["--comparison-report", "--comparison-report-sha256", "--policy", "--output"])
def test_missing_cli_arguments_use_error_prefix_and_code_two(
    workspace: SimpleNamespace, capsys: Any, required: str,
) -> None:
    arguments = _args(workspace)
    index = arguments.index(required)
    del arguments[index:index + 2]
    assert cli.main(arguments) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err.startswith("error:")
    assert not workspace.output.exists()


def test_unknown_argument_uses_error_prefix_and_code_two(workspace: SimpleNamespace, capsys: Any) -> None:
    assert cli.main([*_args(workspace), "--unsupported"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err.startswith("error:")
    assert not workspace.output.exists()


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("phase", ["evaluation", "serialization"])
def test_computation_or_serialization_failure_does_not_publish_partial_output(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
    existing: bool, phase: str,
) -> None:
    old = _old_output(workspace, existing)

    def fail(*args: object, **kwargs: object) -> None:
        raise ValueError("synthetic failure before publication")

    name = "evaluate_embedding_model_candidates" if phase == "evaluation" else "_serialize_selection"
    monkeypatch.setattr(cli, name, fail)
    _failure(workspace, capsys, overwrite=existing)
    _assert_output_preserved(workspace, existing, old)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("payload", [b"{}", b"{", b"\xff", b'{"value":NaN}'])
def test_invalid_serialized_output_fails_read_back_and_rolls_back(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
    existing: bool, payload: bytes,
) -> None:
    old = _old_output(workspace, existing)
    monkeypatch.setattr(cli, "_serialize_selection", lambda selection: payload)
    _failure(workspace, capsys, overwrite=existing)
    _assert_output_preserved(workspace, existing, old)


@pytest.mark.parametrize("existing", [False, True])
def test_atomic_os_operation_failure_keeps_old_output_and_removes_temporary_file(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, existing: bool,
) -> None:
    old = _old_output(workspace, existing)
    calls: list[tuple[Path, Path]] = []

    def fail(source: object, destination: object) -> None:
        source_path, destination_path = Path(source), Path(destination)
        calls.append((source_path, destination_path))
        assert source_path.parent == destination_path.parent == workspace.output.parent
        assert source_path.read_bytes().endswith(b"\n")
        raise OSError("synthetic atomic publication failure")

    monkeypatch.setattr(cli.os, "replace" if existing else "link", fail)
    _failure(workspace, capsys, overwrite=existing)
    assert len(calls) == 1
    _assert_output_preserved(workspace, existing, old)


@pytest.mark.parametrize("existing", [False, True])
def test_temporary_cleanup_error_after_publication_retries_and_rolls_back(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, existing: bool,
) -> None:
    old = _old_output(workspace, existing)
    unlink = Path.unlink
    failed = False

    def transient_unlink(path: Path, *args: object, **kwargs: object) -> None:
        nonlocal failed
        if path.suffix == ".tmp" and not failed:
            failed = True
            raise OSError("synthetic transient temporary cleanup failure")
        unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", transient_unlink)
    _failure(workspace, capsys, overwrite=existing)
    assert failed
    _assert_output_preserved(workspace, existing, old)


@pytest.mark.parametrize("existing", [False, True])
def test_temp_file_flush_failure_does_not_publish_or_leave_temporary_files(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, existing: bool,
) -> None:
    old = _old_output(workspace, existing)

    def flush_error(descriptor: int) -> None:
        raise OSError("synthetic fsync failure before publication")

    monkeypatch.setattr(cli.os, "fsync", flush_error)
    _failure(workspace, capsys, overwrite=existing)
    _assert_output_preserved(workspace, existing, old)


def test_new_output_rollback_retries_a_transient_unlink_failure(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
) -> None:
    unlink = Path.unlink
    failed = False

    def transient_unlink(path: Path, *args: object, **kwargs: object) -> None:
        nonlocal failed
        if path == workspace.output and not failed:
            failed = True
            raise OSError("synthetic transient output rollback failure")
        unlink(path, *args, **kwargs)

    def read_back_error(*args: object, **kwargs: object) -> None:
        raise ValueError("synthetic read-back failure")

    monkeypatch.setattr(Path, "unlink", transient_unlink)
    monkeypatch.setattr(cli, "_read_back_selection", read_back_error)
    assert "read-back failure" in _failure(workspace, capsys)
    assert failed and not workspace.output.exists()
    _assert_no_temporary_files(workspace)


def test_old_output_rollback_retries_a_transient_restore_failure(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
) -> None:
    old = _old_output(workspace, True)
    replace = cli._replace_bytes
    failed = False

    def transient_restore(output: Path, payload: bytes, **options: object) -> None:
        nonlocal failed
        if payload == old and not failed:
            failed = True
            raise OSError("synthetic transient old-output restore failure")
        replace(output, payload, **options)

    def read_back_error(*args: object, **kwargs: object) -> None:
        raise ValueError("synthetic read-back failure")

    monkeypatch.setattr(cli, "_replace_bytes", transient_restore)
    monkeypatch.setattr(cli, "_read_back_selection", read_back_error)
    assert "read-back failure" in _failure(workspace, capsys, overwrite=True)
    assert failed
    _assert_output_preserved(workspace, True, old)


@pytest.mark.parametrize("existing", [False, True])
def test_invalid_core_output_cannot_bypass_output_validator(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, existing: bool,
) -> None:
    old = _old_output(workspace, existing)
    evaluate = cli.evaluate_embedding_model_candidates

    def forged_output(report: dict, *, policy: dict) -> dict:
        selection = evaluate(report, policy=policy)
        selection["metadata"]["eligible_candidate_count"] = 999
        return selection

    monkeypatch.setattr(cli, "evaluate_embedding_model_candidates", forged_output)
    _failure(workspace, capsys, overwrite=existing)
    _assert_output_preserved(workspace, existing, old)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("failure", ["read_error", "corruption", "interrupt", "system_exit"])
def test_read_back_failures_restore_bytes_without_reading_failed_output(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
    existing: bool, failure: str,
) -> None:
    old = _old_output(workspace, existing)
    blocked = False
    read_bytes = Path.read_bytes

    def read(path: Path) -> bytes:
        if blocked and path == workspace.output:
            raise OSError("persistent read failure after publication")
        return read_bytes(path)

    def fail_readback(path: Path, payload: bytes, **context: object) -> None:
        nonlocal blocked
        if failure == "read_error":
            blocked = True
            path.read_bytes()
        elif failure == "corruption":
            path.write_bytes(b"corrupted published selection")
            raise ValueError("synthetic read-back mismatch")
        elif failure == "interrupt":
            raise KeyboardInterrupt("synthetic interruption")
        else:
            raise SystemExit(7)

    monkeypatch.setattr(Path, "read_bytes", read)
    monkeypatch.setattr(cli, "_read_back_selection", fail_readback)
    expected = KeyboardInterrupt if failure == "interrupt" else SystemExit if failure == "system_exit" else cli.EmbeddingModelSelectionCliError
    with pytest.raises(expected):
        _run(workspace, overwrite=existing)
    blocked = False
    _assert_output_preserved(workspace, existing, old)


@pytest.mark.parametrize("existing", [False, True])
def test_read_back_bytes_mismatch_even_with_valid_json_rolls_back(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any, existing: bool,
) -> None:
    old = _old_output(workspace, existing)
    read_back = cli._read_back_selection

    def rewrite(path: Path, payload: bytes, **context: object) -> None:
        document = json.loads(path.read_bytes())
        path.write_bytes(json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8"))
        read_back(path, payload, **context)

    monkeypatch.setattr(cli, "_read_back_selection", rewrite)
    assert "read-back bytes differ" in _failure(workspace, capsys, overwrite=existing)
    _assert_output_preserved(workspace, existing, old)


@pytest.mark.parametrize("target", ["report_path", "policy_path"])
@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("phase", ["parse", "evaluation", "serialization", "before_publication", "after_readback"])
def test_input_hash_drift_at_every_publication_checkpoint_rolls_back(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
    target: str, existing: bool, phase: str,
) -> None:
    old = _old_output(workspace, existing)
    path = getattr(workspace, target)
    changed = False

    def mutate_once() -> None:
        nonlocal changed
        if not changed:
            path.write_bytes(path.read_bytes() + b" ")
            changed = True

    if phase == "parse":
        parse = cli._parse_json_bytes

        def parsing(payload: bytes, *, source_path: str) -> dict:
            document = parse(payload, source_path=source_path)
            mutate_once()
            return document

        monkeypatch.setattr(cli, "_parse_json_bytes", parsing)
    elif phase == "evaluation":
        evaluate = cli.evaluate_embedding_model_candidates

        def evaluation(report: dict, *, policy: dict) -> dict:
            selection = evaluate(report, policy=policy)
            mutate_once()
            return selection

        monkeypatch.setattr(cli, "evaluate_embedding_model_candidates", evaluation)
    elif phase == "serialization":
        serialize = cli._serialize_selection

        def serialization(selection: dict) -> bytes:
            payload = serialize(selection)
            mutate_once()
            return payload

        monkeypatch.setattr(cli, "_serialize_selection", serialization)
    elif phase == "before_publication":
        replace = cli._replace_bytes

        def replacing(output: Path, payload: bytes, **options: object) -> None:
            mutate_once()
            replace(output, payload, **options)

        monkeypatch.setattr(cli, "_replace_bytes", replacing)
    else:
        read_back = cli._read_back_selection

        def readback(output: Path, payload: bytes, **context: object) -> None:
            read_back(output, payload, **context)
            mutate_once()

        monkeypatch.setattr(cli, "_read_back_selection", readback)
    assert "SHA-256" in _failure(workspace, capsys, overwrite=existing)
    assert changed
    _assert_output_preserved(workspace, existing, old)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("phase", ["evaluation", "serialization", "after_write_check"])
def test_control_flow_interrupts_propagate_with_rollback_and_cleanup(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
    existing: bool, error: type[BaseException], phase: str,
) -> None:
    old = _old_output(workspace, existing)

    def interrupt(*args: object, **kwargs: object) -> None:
        raise error("synthetic control-flow exception")

    if phase == "evaluation":
        monkeypatch.setattr(cli, "evaluate_embedding_model_candidates", interrupt)
    elif phase == "serialization":
        monkeypatch.setattr(cli, "_serialize_selection", interrupt)
    else:
        check = cli._assert_input_hashes

        def check_after_write(expected: dict[Path, str]) -> None:
            if workspace.output.exists() and workspace.output.read_bytes() != old:
                interrupt()
            check(expected)

        monkeypatch.setattr(cli, "_assert_input_hashes", check_after_write)
    with pytest.raises(error):
        cli.main(_args(workspace, overwrite=existing))
    _assert_output_preserved(workspace, existing, old)


def test_no_overwrite_race_preserves_competing_writer(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
) -> None:
    link = cli.os.link
    concurrent = b"concurrent writer bytes"

    def compete(source: object, destination: object) -> None:
        Path(destination).write_bytes(concurrent)
        link(source, destination)

    monkeypatch.setattr(cli.os, "link", compete)
    _failure(workspace, capsys)
    assert workspace.output.read_bytes() == concurrent
    _assert_no_temporary_files(workspace)


def test_overwrite_detects_competing_writer_before_publication_without_restoring_stale_bytes(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any,
) -> None:
    _old_output(workspace, True)
    replace = cli._replace_bytes
    concurrent = b"concurrent replacement of original output"

    def compete(output: Path, payload: bytes, **options: object) -> None:
        output.write_bytes(concurrent)
        replace(output, payload, **options)

    monkeypatch.setattr(cli, "_replace_bytes", compete)
    assert "output changed before publication" in _failure(workspace, capsys, overwrite=True)
    assert workspace.output.read_bytes() == concurrent
    _assert_no_temporary_files(workspace)


def test_interrupt_immediately_after_atomic_publication_uses_publication_flag_for_rollback(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = _old_output(workspace, True)
    replace = cli._replace_bytes

    def interrupt_after_publish(output: Path, payload: bytes, **options: object) -> None:
        replace(output, payload, **options)
        if "on_publish" in options:
            raise KeyboardInterrupt("published but not complete")

    monkeypatch.setattr(cli, "_replace_bytes", interrupt_after_publish)
    with pytest.raises(KeyboardInterrupt):
        _run(workspace, overwrite=True)
    _assert_output_preserved(workspace, True, old)


def test_input_hash_checks_bind_exact_report_and_policy_bytes(workspace: SimpleNamespace) -> None:
    expected = {
        workspace.report_path: workspace.report_sha256,
        workspace.policy_path: sha256(workspace.policy_path.read_bytes()).hexdigest(),
    }
    assert cli._assert_input_hashes(expected) is None
    workspace.policy_path.write_bytes(workspace.policy_path.read_bytes() + b"\n")
    with pytest.raises(cli.EmbeddingModelSelectionCliError, match="SHA-256"):
        cli._assert_input_hashes(expected)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_serializer_never_writes_nonfinite_json_numbers(value: float) -> None:
    with pytest.raises(ValueError):
        cli._serialize_selection({"value": value})


def test_cli_uses_core_without_model_backend_or_network(
    workspace: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    imports: list[str] = []
    original_import = builtins.__import__
    forbidden = (
        "sentence_transformers", "torch", "transformers", "huggingface_hub",
        "requests", "httpx", "threat_hunting.retrieval.embedding_backend",
        "threat_hunting.retrieval.vector_retriever", "threat_hunting.graphrag",
    )

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden):
            imports.append(name)
            raise AssertionError(f"forbidden runtime import: {name}")
        return original_import(name, *args, **kwargs)

    def network(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(socket, "create_connection", network)
    monkeypatch.setattr(urllib.request, "urlopen", network)
    _run(workspace)
    assert imports == []
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    direct_imports = [
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    ] + [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any(name == prefix or name.startswith(prefix + ".")
                   for name in direct_imports for prefix in forbidden)
    _assert_no_temporary_files(workspace)
