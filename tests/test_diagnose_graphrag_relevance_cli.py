"""Diagnostics CLI input integrity, local-only execution, and atomic rollback."""

from __future__ import annotations

import ast
import builtins
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/diagnose_graphrag_relevance.py"
FIXTURES = ROOT / "tests/fixtures/evaluation/diagnostics"
INPUT_NAMES = ("dataset", "report")
HASH_OPTIONS = {"dataset": "--dataset-sha256", "report": "--calibration-report-sha256"}

SPEC = importlib.util.spec_from_file_location("testable_relevance_diagnostics_cli", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)


def _hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _arguments(paths: dict[str, Path], *, overwrite: bool = False) -> list[str]:
    args = [
        "--dataset", str(paths["dataset"]), "--dataset-sha256", _hash(paths["dataset"]),
        "--calibration-report", str(paths["report"]),
        "--calibration-report-sha256", _hash(paths["report"]),
        "--output", str(paths["output"]),
    ]
    return args + (["--overwrite"] if overwrite else [])


def _kwargs(paths: dict[str, Path], *, overwrite: bool = False) -> dict[str, Any]:
    return {
        "dataset_path": paths["dataset"], "calibration_report_path": paths["report"],
        "dataset_sha256": _hash(paths["dataset"]),
        "calibration_report_sha256": _hash(paths["report"]),
        "output_path": paths["output"], "overwrite": overwrite,
    }


def _main(paths, capsys, *, argv=None, overwrite=False):
    code = cli.main(_arguments(paths, overwrite=overwrite) if argv is None else argv)
    capture = capsys.readouterr()
    return code, capture.out, capture.err


def _assert_failure(result):
    code, stdout, stderr = result
    assert code == 2
    assert stdout == ""
    assert any(line.startswith("error:") for line in stderr.splitlines())
    assert "Traceback" not in stderr


def _assert_previous_and_clean(paths, previous):
    if previous is None:
        assert not paths["output"].exists()
    else:
        assert paths["output"].read_bytes() == previous
    assert not list(paths["output"].parent.glob("*.tmp"))


@pytest.fixture
def paths(tmp_path):
    result = {
        "dataset": tmp_path / "dataset.json", "report": tmp_path / "calibration.json",
        "output": tmp_path / "reports" / "diagnostics.json",
    }
    result["output"].parent.mkdir()
    result["dataset"].write_bytes((FIXTURES / "dataset.json").read_bytes())
    report = _read(FIXTURES / "calibration_report.json")
    report["provenance"]["dataset"].update(
        path=result["dataset"].as_posix(), sha256=_hash(result["dataset"]),
    )
    result["report"].write_bytes(cli._serialize(report))
    return result


def test_parser_accepts_every_requested_option(paths):
    args = cli._build_parser().parse_args(_arguments(paths, overwrite=True))
    assert args.dataset == paths["dataset"]
    assert args.calibration_report == paths["report"]
    assert args.dataset_sha256 == _hash(paths["dataset"])
    assert args.calibration_report_sha256 == _hash(paths["report"])
    assert args.output == paths["output"]
    assert args.overwrite is True


@pytest.mark.parametrize("extra", [
    ["--dat", "other.json"], ["--calibration-report-sha", "a" * 64],
    ["--out", "other.json"], ["--threshold", "0.2"], ["--query", "not supported"],
])
def test_parser_rejects_abbreviations_and_runtime_query_policy_options(paths, capsys, extra):
    _assert_failure(_main(paths, capsys, argv=_arguments(paths) + extra))


@pytest.mark.parametrize("option", [
    "--dataset", "--dataset-sha256", "--calibration-report",
    "--calibration-report-sha256", "--output",
])
def test_every_input_output_and_hash_option_is_required(paths, capsys, option):
    args = _arguments(paths)
    index = args.index(option)
    del args[index:index + 2]
    _assert_failure(_main(paths, capsys, argv=args))


@pytest.mark.parametrize("name", INPUT_NAMES)
@pytest.mark.parametrize("invalid", ["", "a" * 63, "a" * 65, "g" * 64, "a" * 64 + "\n"])
def test_hash_format_fails_before_loaders_or_analyzer(paths, capsys, monkeypatch, name, invalid):
    def forbidden(*args, **kwargs):
        pytest.fail("malformed hashes must fail before loaders and analysis")
    monkeypatch.setattr(cli, "load_relevance_calibration_dataset", forbidden)
    monkeypatch.setattr(cli, "load_calibration_report", forbidden)
    monkeypatch.setattr(cli, "analyze_relevance_separability", forbidden)
    args = _arguments(paths)
    args[args.index(HASH_OPTIONS[name]) + 1] = invalid
    _assert_failure(_main(paths, capsys, argv=args))
    assert not paths["output"].exists()


@pytest.mark.parametrize("name", INPUT_NAMES)
def test_each_input_hash_mismatch_is_preload_failure(paths, capsys, monkeypatch, name):
    def forbidden(*args, **kwargs):
        pytest.fail("all hashes must match before the first loader")
    monkeypatch.setattr(cli, "load_relevance_calibration_dataset", forbidden)
    args = _arguments(paths)
    args[args.index(HASH_OPTIONS[name]) + 1] = "0" * 64
    result = _main(paths, capsys, argv=args)
    _assert_failure(result)
    assert str(paths[name]) in result[2]
    assert not paths["output"].exists()


@pytest.mark.parametrize("name", INPUT_NAMES)
def test_missing_input_names_failed_file(paths, capsys, name):
    args = _arguments(paths)
    paths[name].unlink()
    result = _main(paths, capsys, argv=args)
    _assert_failure(result)
    assert str(paths[name]) in result[2]


@pytest.mark.parametrize("name", INPUT_NAMES)
@pytest.mark.parametrize("invalid", [
    b'{"duplicate":1,"duplicate":2}', b'{"bad":NaN}', b'{"bad":Infinity}',
    b'{"bad":-Infinity}', b'{', b'\xff',
])
def test_strict_input_json_errors_include_filename(paths, capsys, monkeypatch, name, invalid):
    paths[name].write_bytes(invalid)
    def forbidden(*args, **kwargs):
        pytest.fail("invalid inputs cannot reach diagnostics")
    monkeypatch.setattr(cli, "analyze_relevance_separability", forbidden)
    result = _main(paths, capsys)
    _assert_failure(result)
    assert str(paths[name]) in result[2]
    assert not paths["output"].exists()


def test_uppercase_hashes_are_normalized_without_input_mutation(paths, capsys):
    before = {name: paths[name].read_bytes() for name in INPUT_NAMES}
    args = _arguments(paths)
    for option in HASH_OPTIONS.values():
        args[args.index(option) + 1] = args[args.index(option) + 1].upper()
    assert _main(paths, capsys, argv=args)[0] == 0
    assert before == {name: paths[name].read_bytes() for name in INPUT_NAMES}


@pytest.mark.parametrize("name", INPUT_NAMES)
def test_output_cannot_replace_input_even_with_overwrite(paths, capsys, name):
    before = paths[name].read_bytes()
    args = _arguments(paths, overwrite=True)
    args[args.index("--output") + 1] = str(paths[name].parent / "." / paths[name].name)
    _assert_failure(_main(paths, capsys, argv=args))
    assert paths[name].read_bytes() == before


@pytest.mark.parametrize("name", INPUT_NAMES)
def test_output_hardlink_alias_cannot_overwrite_input(paths, capsys, name):
    before = paths[name].read_bytes()
    cli.os.link(paths[name], paths["output"])
    _assert_failure(_main(paths, capsys, overwrite=True))
    assert paths[name].read_bytes() == before
    assert paths["output"].read_bytes() == before


def test_output_symlink_is_rejected_before_any_analysis(paths, capsys, monkeypatch):
    real = Path.is_symlink
    def is_symlink(path):
        return True if path == paths["output"] else real(path)
    monkeypatch.setattr(Path, "is_symlink", is_symlink)
    def forbidden(*args, **kwargs):
        pytest.fail("symlink output must fail before loading")
    monkeypatch.setattr(cli, "load_relevance_calibration_dataset", forbidden)
    _assert_failure(_main(paths, capsys, overwrite=True))
    assert not paths["output"].exists()


def test_existing_output_requires_overwrite_before_loading(paths, capsys, monkeypatch):
    previous = b"previous reviewed output\n"
    paths["output"].write_bytes(previous)
    def forbidden(*args, **kwargs):
        pytest.fail("existing output protection must precede loaders")
    monkeypatch.setattr(cli, "load_relevance_calibration_dataset", forbidden)
    _assert_failure(_main(paths, capsys))
    _assert_previous_and_clean(paths, previous)


def test_real_loaders_analyzer_and_validated_readback_are_reused_once(paths, capsys, monkeypatch):
    loader_calls, analyze_calls, readback_paths = [], [], []
    original_dataset = cli.load_relevance_calibration_dataset
    original_report = cli.load_calibration_report
    original_analyze = cli.analyze_relevance_separability
    original_readback = cli.load_relevance_diagnostics
    def dataset_loader(path):
        loader_calls.append(("dataset", path))
        print("synthetic dataset loader message")
        return original_dataset(path)
    def report_loader(path):
        loader_calls.append(("report", path))
        print("synthetic calibration loader message")
        return original_report(path)
    def analyze(dataset, report, **kwargs):
        before = deepcopy((dataset, report))
        analyze_calls.append((dataset, report, kwargs))
        print("synthetic analyzer message")
        result = original_analyze(dataset, report, **kwargs)
        assert (dataset, report) == before
        return result
    def readback(path):
        readback_paths.append(Path(path))
        print("synthetic read-back loader message")
        return original_readback(path)
    monkeypatch.setattr(cli, "load_relevance_calibration_dataset", dataset_loader)
    monkeypatch.setattr(cli, "load_calibration_report", report_loader)
    monkeypatch.setattr(cli, "analyze_relevance_separability", analyze)
    monkeypatch.setattr(cli, "load_relevance_diagnostics", readback)
    code, stdout, stderr = _main(paths, capsys)
    assert code == 0
    assert loader_calls == [("dataset", paths["dataset"]), ("report", paths["report"])]
    assert len(analyze_calls) == 1
    assert analyze_calls[0][2] == {
        "dataset_path": paths["dataset"].as_posix(), "dataset_sha256": _hash(paths["dataset"]),
        "report_path": paths["report"].as_posix(), "report_sha256": _hash(paths["report"]),
    }
    assert len(readback_paths) == 2
    assert all(path.parent == paths["output"].parent for path in readback_paths)
    assert readback_paths[-1] == paths["output"]
    assert "synthetic" in stderr and "synthetic" not in stdout
    summary = json.loads(stdout)
    assert summary == {"output": paths["output"].as_posix(), "sha256": _hash(paths["output"])}
    assert stdout.count("\n") == 1 and stdout.endswith("\n")


def test_success_deterministic_compact_utf8_detached_and_no_other_files(paths):
    before = {name: paths[name].read_bytes() for name in INPUT_NAMES}
    first = cli.run_diagnostics(**_kwargs(paths))
    first_bytes = paths["output"].read_bytes()
    assert _read(paths["output"]) == first
    assert first_bytes == cli._serialize(first)
    assert first_bytes.endswith(b"\n") and first_bytes.count(b"\n") == 1
    first["review"]["status"] = "altered-only-in-returned-document"
    assert _read(paths["output"])["review"]["status"] == "pending_human_review"
    second = cli.run_diagnostics(**_kwargs(paths, overwrite=True))
    assert paths["output"].read_bytes() == first_bytes
    assert second == _read(paths["output"])
    assert before == {name: paths[name].read_bytes() for name in INPUT_NAMES}
    assert {path.name for path in paths["output"].parent.iterdir()} == {paths["output"].name}
    assert not _contains_confirmed(second)


def _contains_confirmed(value):
    if isinstance(value, str):
        return value == "confirmed"
    if isinstance(value, dict):
        return any(_contains_confirmed(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_confirmed(item) for item in value)
    return False


@pytest.mark.parametrize("name", INPUT_NAMES)
@pytest.mark.parametrize("phase", ["load", "build", "serialization", "temporary", "installed"])
def test_input_changes_at_each_phase_abort_and_restore_previous(paths, capsys, monkeypatch, name, phase):
    previous = b"reviewed report before execution\n"
    paths["output"].write_bytes(previous)
    args = _arguments(paths, overwrite=True)
    def mutate():
        paths[name].write_bytes(paths[name].read_bytes() + b" ")
    if phase == "load":
        original = cli.load_calibration_report
        def loader(path):
            result = original(path)
            mutate()
            return result
        monkeypatch.setattr(cli, "load_calibration_report", loader)
    elif phase == "build":
        original = cli.analyze_relevance_separability
        def analyze(*args, **kwargs):
            result = original(*args, **kwargs)
            mutate()
            return result
        monkeypatch.setattr(cli, "analyze_relevance_separability", analyze)
    elif phase == "serialization":
        original = cli._serialize
        def serialize(document):
            result = original(document)
            if document.get("schema_version") == "graphrag-relevance-diagnostics/v1":
                mutate()
            return result
        monkeypatch.setattr(cli, "_serialize", serialize)
    else:
        original = cli.load_relevance_diagnostics
        def readback(path):
            result = original(path)
            installed = Path(path) == paths["output"]
            if installed == (phase == "installed"):
                mutate()
            return result
        monkeypatch.setattr(cli, "load_relevance_diagnostics", readback)
    result = _main(paths, capsys, argv=args)
    _assert_failure(result)
    assert str(paths[name]) in result[2]
    _assert_previous_and_clean(paths, previous)


@pytest.mark.parametrize("overwrite", [False, True])
@pytest.mark.parametrize("phase", ["temporary", "installed"])
def test_readback_validation_failure_removes_new_output_or_restores_old(paths, capsys, monkeypatch, overwrite, phase):
    previous = b"previous untouched report\n" if overwrite else None
    if previous is not None:
        paths["output"].write_bytes(previous)
    original = cli.load_relevance_diagnostics
    def readback(path):
        if (Path(path) == paths["output"]) == (phase == "installed"):
            raise cli.RelevanceDiagnosticsError("synthetic read-back schema failure at $")
        return original(path)
    monkeypatch.setattr(cli, "load_relevance_diagnostics", readback)
    _assert_failure(_main(paths, capsys, overwrite=overwrite))
    _assert_previous_and_clean(paths, previous)


def test_temporary_bytes_change_is_detected_before_install(paths, capsys, monkeypatch):
    original = cli.load_relevance_diagnostics
    def readback(path):
        result = original(path)
        if Path(path) != paths["output"]:
            Path(path).write_bytes(Path(path).read_bytes() + b" ")
        return result
    monkeypatch.setattr(cli, "load_relevance_diagnostics", readback)
    result = _main(paths, capsys)
    _assert_failure(result)
    assert "temporary diagnostics bytes changed" in result[2]
    _assert_previous_and_clean(paths, None)


def test_analyzer_failure_preserves_existing_output(paths, capsys, monkeypatch):
    previous = b"old diagnostics"
    paths["output"].write_bytes(previous)
    def analyze(*args, **kwargs):
        raise cli.RelevanceDiagnosticsError("synthetic independent outcome replay failed")
    monkeypatch.setattr(cli, "analyze_relevance_separability", analyze)
    result = _main(paths, capsys, overwrite=True)
    _assert_failure(result)
    assert "replay failed" in result[2]
    _assert_previous_and_clean(paths, previous)


def test_output_validation_runs_before_serialization_and_install(paths, capsys, monkeypatch):
    def validate(document):
        raise cli.RelevanceDiagnosticsError("synthetic output validation failure at $.metadata")
    monkeypatch.setattr(cli, "validate_relevance_diagnostics", validate)
    _assert_failure(_main(paths, capsys))
    _assert_previous_and_clean(paths, None)


def test_nonfinite_output_cannot_be_serialized(paths, capsys, monkeypatch):
    monkeypatch.setattr(cli, "analyze_relevance_separability", lambda *args, **kwargs: {"bad": float("nan")})
    monkeypatch.setattr(cli, "validate_relevance_diagnostics", lambda document: None)
    _assert_failure(_main(paths, capsys))
    _assert_previous_and_clean(paths, None)


def test_write_failure_cleans_temporary_and_preserves_old(paths, capsys, monkeypatch):
    previous = b"previous output"
    paths["output"].write_bytes(previous)
    def replace(source, destination):
        raise PermissionError("synthetic atomic replacement denied")
    monkeypatch.setattr(cli.os, "replace", replace)
    _assert_failure(_main(paths, capsys, overwrite=True))
    _assert_previous_and_clean(paths, previous)


def test_concurrent_creation_is_never_replaced(paths, capsys, monkeypatch):
    original = cli.os.link
    def link(source, destination):
        Path(destination).write_bytes(b"another writer")
        return original(source, destination)
    monkeypatch.setattr(cli.os, "link", link)
    _assert_failure(_main(paths, capsys))
    _assert_previous_and_clean(paths, b"another writer")


def test_concurrent_overwrite_is_never_replaced(paths, capsys, monkeypatch):
    paths["output"].write_bytes(b"previous bytes")
    original = cli.load_relevance_diagnostics
    def readback(path):
        result = original(path)
        if Path(path) != paths["output"]:
            paths["output"].write_bytes(b"another writer")
        return result
    monkeypatch.setattr(cli, "load_relevance_diagnostics", readback)
    _assert_failure(_main(paths, capsys, overwrite=True))
    _assert_previous_and_clean(paths, b"another writer")


def test_rollback_refuses_to_replace_a_changed_installed_output(paths, capsys, monkeypatch):
    paths["output"].write_bytes(b"previous bytes")
    original = cli.load_relevance_diagnostics
    def readback(path):
        result = original(path)
        if Path(path) == paths["output"]:
            paths["output"].write_bytes(b"another writer")
            raise ValueError("read-back failed after concurrent output change")
        return result
    monkeypatch.setattr(cli, "load_relevance_diagnostics", readback)
    result = _main(paths, capsys, overwrite=True)
    _assert_failure(result)
    assert "refusing to roll back another writer" in result[2]
    _assert_previous_and_clean(paths, b"another writer")


def test_execution_never_imports_models_or_opens_network(paths, monkeypatch):
    original_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        if name.split(".")[0] in {"sentence_transformers", "torch", "transformers", "huggingface_hub"}:
            pytest.fail("diagnostics cannot import model or embedding packages")
        return original_import(name, *args, **kwargs)
    def forbidden(*args, **kwargs):
        pytest.fail("diagnostics cannot access network")
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    cli.run_diagnostics(**_kwargs(paths))


def test_cli_source_delegates_once_without_hardcoded_production_data():
    source = SCRIPT.read_text(encoding="utf-8")
    calls = [node.func.id for node in ast.walk(ast.parse(source))
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("analyze_relevance_separability") == 1
    forbidden_calls = {
        "build_graphrag_context", "assess_graphrag_relevance", "calibrate_relevance_policies",
        "SentenceTransformerEmbeddingBackend", "SentenceTransformer",
    }
    assert not forbidden_calls.intersection(calls)
    for forbidden in ("mshta", "powershell", "T1218.005", "all-MiniLM-L6-v2", "672", "32 cases"):
        assert forbidden.casefold() not in source.casefold()


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_interrupts_are_not_converted_to_error_exit(paths, monkeypatch, interruption):
    def analyze(*args, **kwargs):
        raise interruption()
    monkeypatch.setattr(cli, "analyze_relevance_separability", analyze)
    with pytest.raises(interruption):
        cli.main(_arguments(paths))
    _assert_previous_and_clean(paths, None)


def test_subprocess_help_and_bad_arguments_require_no_model():
    help_result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--help"], capture_output=True, check=False)
    assert help_result.returncode == 0 and help_result.stderr == b""
    for option in (b"--dataset-sha256", b"--calibration-report-sha256", b"--overwrite"):
        assert option in help_result.stdout
    bad = subprocess.run([sys.executable, "-B", str(SCRIPT), "--not-an-option"], capture_output=True, check=False)
    assert bad.returncode == 2 and bad.stdout == b"" and bad.stderr.startswith(b"error:")


def test_subprocess_unicode_paths_are_valid_utf8_and_stable(paths):
    unicode_directory = paths["output"].parent / "kiểm-tra"
    paths["output"] = unicode_directory / "chẩn-đoán.json"
    command = [sys.executable, "-B", str(SCRIPT), *_arguments(paths, overwrite=True)]
    first = subprocess.run(command, capture_output=True, check=False)
    assert first.returncode == 0, first.stderr.decode("utf-8")
    first_bytes = paths["output"].read_bytes()
    second = subprocess.run(command, capture_output=True, check=False)
    assert second.returncode == 0, second.stderr.decode("utf-8")
    assert first.stdout == second.stdout
    assert paths["output"].read_bytes() == first_bytes
    assert first.stdout.decode("utf-8").count("\n") == 1
    assert json.loads(first.stdout)["output"] == paths["output"].as_posix()
