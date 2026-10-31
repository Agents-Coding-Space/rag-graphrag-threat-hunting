from __future__ import annotations

import ast
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import ModuleType
from typing import Any

import pytest

from threat_hunting.graph import (
    KnowledgeGraphBuildError,
    KnowledgeGraphValidationError,
    build_knowledge_graph,
    load_knowledge_graph,
    validate_knowledge_graph,
)
from threat_hunting.ground_truth import load_ground_truth_document


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts/build_knowledge_graph.py"
GROUND_TRUTH_FIXTURE = (
    REPOSITORY_ROOT / "tests/fixtures/ground_truth/builder/expected_ground_truth.json"
)
EXPECTED_GRAPH_FIXTURE = (
    REPOSITORY_ROOT / "tests/fixtures/graph/builder/expected_knowledge_graph.json"
)
SCENARIO_ID = "scenario-synthetic-builder"


def _sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _copy_input(tmp_path: Path) -> Path:
    path = tmp_path / "ground_truth.json"
    shutil.copyfile(GROUND_TRUTH_FIXTURE, path)
    return path


def _arguments(
    input_path: Path,
    output_path: Path,
    *,
    expected_hash: str | None = None,
    scenario_id: str = SCENARIO_ID,
    overwrite: bool = False,
) -> list[str]:
    arguments = [
        "--ground-truth", str(input_path),
        "--ground-truth-sha256", _sha256(input_path) if expected_hash is None else expected_hash,
        "--expected-scenario-id", scenario_id,
        "--output", str(output_path),
    ]
    if overwrite:
        arguments.append("--overwrite")
    return arguments


def _run(input_path: Path, output_path: Path, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *_arguments(input_path, output_path, **kwargs)],
        cwd=REPOSITORY_ROOT, capture_output=True, text=True, encoding="utf-8", check=False,
    )


def _assert_clean(tmp_path: Path, output_path: Path, previous: bytes | None) -> None:
    if previous is None:
        assert not output_path.exists()
    else:
        assert output_path.read_bytes() == previous
    assert not list(tmp_path.rglob("*.tmp"))


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    name = "knowledge_graph_cli_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def test_cli_build_success_reports_only_valid_stats_and_local_graph(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    input_bytes = input_path.read_bytes()
    output_path = tmp_path / "knowledge_graph.json"
    result = _run(input_path, output_path)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert len(result.stdout.splitlines()) == 1
    graph = load_knowledge_graph(output_path)
    validate_knowledge_graph(graph)
    assert json.loads(result.stdout) == {
        "schema_version": "knowledge-graph/v1",
        "graph_id": graph["graph_id"],
        "scenario_id": SCENARIO_ID,
        "review_status": "pending_human_review",
        "node_count": len(graph["nodes"]),
        "edge_count": len(graph["edges"]),
        "node_type_counts": dict(Counter(node["node_type"] for node in graph["nodes"])),
        "edge_type_counts": dict(Counter(edge["edge_type"] for edge in graph["edges"])),
        "input_path": input_path.name,
        "input_sha256": _sha256(input_path),
        "output_path": output_path.name,
        "output_sha256": _sha256(output_path),
    }
    assert input_path.read_bytes() == input_bytes
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "ground_truth.json", "knowledge_graph.json",
    ]


def test_cli_matches_reviewed_expected_graph_fixture(tmp_path: Path) -> None:
    output_path = tmp_path / "knowledge_graph.json"
    before = GROUND_TRUTH_FIXTURE.read_bytes()
    result = _run(GROUND_TRUTH_FIXTURE, output_path)
    assert result.returncode == 0, result.stderr
    expected = json.loads(EXPECTED_GRAPH_FIXTURE.read_text(encoding="utf-8"))
    assert load_knowledge_graph(output_path) == expected
    assert GROUND_TRUTH_FIXTURE.read_bytes() == before


def test_cli_repeat_runs_are_byte_identical_and_preserve_input(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"
    before = input_path.read_bytes()
    first = _run(input_path, output_path, overwrite=True)
    assert first.returncode == 0, first.stderr
    first_bytes = output_path.read_bytes()
    second = _run(input_path, output_path, overwrite=True)
    assert second.returncode == 0, second.stderr
    assert output_path.read_bytes() == first_bytes
    assert json.loads(first.stdout) == json.loads(second.stdout)
    assert input_path.read_bytes() == before
    assert not list(tmp_path.glob("*.tmp"))


def test_build_delegates_to_existing_builder_without_mutating_loaded_document(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = _copy_input(tmp_path)
    document = load_ground_truth_document(input_path)
    initial = deepcopy(document)
    calls: list[dict[str, Any]] = []

    def build(value: object, **kwargs: Any) -> dict[str, Any]:
        assert value is document
        calls.append(kwargs)
        return build_knowledge_graph(value, **kwargs)

    monkeypatch.setattr(cli, "load_ground_truth_document", lambda path: document)
    monkeypatch.setattr(cli, "build_knowledge_graph", build)
    output_path = tmp_path / "knowledge_graph.json"
    assert cli.main(_arguments(input_path, output_path)) == 0
    assert document == initial
    assert calls == [{"ground_truth_path": input_path.name, "ground_truth_sha256": _sha256(input_path)}]
    assert load_knowledge_graph(output_path) == build_knowledge_graph(document, **calls[0])


@pytest.mark.parametrize("missing_flag", [
    "--ground-truth", "--ground-truth-sha256", "--expected-scenario-id", "--output",
])
def test_cli_requires_all_input_arguments(tmp_path: Path, missing_flag: str) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"
    arguments = _arguments(input_path, output_path)
    position = arguments.index(missing_flag)
    del arguments[position:position + 2]
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *arguments],
        capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert result.returncode != 0
    assert missing_flag in result.stderr
    assert result.stdout == ""
    assert not output_path.exists()


def test_cli_missing_input_returns_stderr_and_nonzero_exit(tmp_path: Path) -> None:
    input_path = tmp_path / "missing.json"
    output_path = tmp_path / "knowledge_graph.json"
    result = _run(input_path, output_path, expected_hash="0" * 64)
    assert result.returncode == 2
    assert "missing.json" in result.stderr
    assert result.stdout == ""
    _assert_clean(tmp_path, output_path, None)


@pytest.mark.parametrize("payload, message", [
    (b'{"schema_version":', "Cannot read"),
    (b'{"key": 1, "key": 2}', "duplicate"),
    (b'{"nested": {"key": 1, "key": 2}}', "duplicate"),
    (b'{"value": NaN}', "non-standard"),
    (b'{"value": Infinity}', "non-standard"),
    (b'{"value": -Infinity}', "non-standard"),
    (b'{}', "fields"),
    (b'[]', "object"),
    (b'\xff', "Cannot read"),
])
def test_cli_rejects_invalid_ground_truth_without_touching_old_output(
    tmp_path: Path, payload: bytes, message: str,
) -> None:
    input_path = tmp_path / "ground_truth.json"
    input_path.write_bytes(payload)
    output_path = tmp_path / "knowledge_graph.json"
    previous = b"existing graph stays unchanged\n"
    output_path.write_bytes(previous)
    result = _run(input_path, output_path, overwrite=True)
    assert result.returncode == 2
    assert message.casefold() in result.stderr.casefold()
    assert "ground_truth.json" in result.stderr
    assert result.stdout == ""
    assert input_path.read_bytes() == payload
    _assert_clean(tmp_path, output_path, previous)


@pytest.mark.parametrize("expected_hash", ["", "abc", "g" * 64, "a" * 63, "a" * 65, "a" * 64 + "\n"])
def test_cli_rejects_malformed_sha256(tmp_path: Path, expected_hash: str) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"
    result = _run(input_path, output_path, expected_hash=expected_hash)
    assert result.returncode == 2
    assert "64 hexadecimal" in result.stderr
    assert result.stdout == ""
    _assert_clean(tmp_path, output_path, None)


def test_hash_is_checked_before_ground_truth_is_loaded(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"

    def unexpected_load(path: Path) -> None:
        pytest.fail("Ground Truth loaded before verifying its SHA-256")

    monkeypatch.setattr(cli, "load_ground_truth_document", unexpected_load)
    assert cli.main(_arguments(input_path, output_path, expected_hash="0" * 64)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "SHA-256 mismatch" in captured.err
    _assert_clean(tmp_path, output_path, None)


def test_uppercase_expected_sha256_is_normalized(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"
    result = _run(input_path, output_path, expected_hash=_sha256(input_path).upper())
    assert result.returncode == 0, result.stderr
    assert load_knowledge_graph(output_path)["source_ground_truth"]["sha256"] == _sha256(input_path)


@pytest.mark.parametrize("scenario_id", ["another-scenario", "", "   "])
def test_cli_rejects_scenario_id_mismatch_or_empty_value(tmp_path: Path, scenario_id: str) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"
    result = _run(input_path, output_path, scenario_id=scenario_id)
    assert result.returncode == 2
    assert "scenario" in result.stderr
    assert result.stdout == ""
    _assert_clean(tmp_path, output_path, None)


def test_cli_refuses_existing_output_without_overwrite(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"
    previous = b"existing output\n"
    output_path.write_bytes(previous)
    result = _run(input_path, output_path)
    assert result.returncode == 2
    assert "--overwrite" in result.stderr
    assert result.stdout == ""
    _assert_clean(tmp_path, output_path, previous)


def test_cli_overwrites_existing_output_successfully(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"
    output_path.write_bytes(b"old output\n")
    result = _run(input_path, output_path, overwrite=True)
    assert result.returncode == 0, result.stderr
    assert load_knowledge_graph(output_path)["scenario_id"] == SCENARIO_ID
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("failure", ["builder", "validator", "temporary_readback", "final_readback"])
def test_failures_preserve_output_and_remove_owned_temporary_files(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], existing: bool, failure: str,
) -> None:
    input_path = _copy_input(tmp_path)
    input_bytes = input_path.read_bytes()
    output_path = tmp_path / "knowledge_graph.json"
    previous = b"previous output, preserved byte for byte\n" if existing else None
    if previous is not None:
        output_path.write_bytes(previous)

    if failure == "builder":
        def fail_build(*args: Any, **kwargs: Any) -> None:
            raise KnowledgeGraphBuildError("injected builder failure")
        monkeypatch.setattr(cli, "build_knowledge_graph", fail_build)
    elif failure == "validator":
        monkeypatch.setattr(cli, "build_knowledge_graph", lambda *args, **kwargs: {})
    else:
        original_load = cli.load_knowledge_graph

        def fail_load(path: Path) -> dict[str, Any]:
            is_final = path == output_path
            if (failure == "final_readback") == is_final:
                raise KnowledgeGraphValidationError("injected read-back validation failure")
            return original_load(path)

        monkeypatch.setattr(cli, "load_knowledge_graph", fail_load)

    assert cli.main(_arguments(input_path, output_path, overwrite=True)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err
    assert input_path.read_bytes() == input_bytes
    _assert_clean(tmp_path, output_path, previous)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("phase", ["builder", "temporary_write", "after_replace"])
def test_input_changes_are_detected_and_output_is_restored(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], existing: bool, phase: str,
) -> None:
    input_path = _copy_input(tmp_path)
    original_hash = _sha256(input_path)
    output_path = tmp_path / "knowledge_graph.json"
    previous = b"old output\n" if existing else None
    if previous is not None:
        output_path.write_bytes(previous)

    def mutate_input() -> None:
        input_path.write_bytes(input_path.read_bytes() + b"\n")

    if phase == "builder":
        original_build = cli.build_knowledge_graph

        def mutating_build(*args: Any, **kwargs: Any) -> dict[str, Any]:
            graph = original_build(*args, **kwargs)
            mutate_input()
            return graph

        monkeypatch.setattr(cli, "build_knowledge_graph", mutating_build)
    elif phase == "temporary_write":
        original_load = cli.load_knowledge_graph
        changed = False

        def mutating_load(path: Path) -> dict[str, Any]:
            nonlocal changed
            graph = original_load(path)
            if path != output_path and not changed:
                mutate_input()
                changed = True
            return graph

        monkeypatch.setattr(cli, "load_knowledge_graph", mutating_load)
    else:
        original_replace = cli.os.replace
        changed = False

        def mutating_replace(source: Path, target: Path) -> None:
            nonlocal changed
            original_replace(source, target)
            if Path(target) == output_path and not changed:
                mutate_input()
                changed = True

        monkeypatch.setattr(cli.os, "replace", mutating_replace)

    assert cli.main(_arguments(input_path, output_path, expected_hash=original_hash, overwrite=True)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "SHA-256" in captured.err
    assert _sha256(input_path) != original_hash
    _assert_clean(tmp_path, output_path, previous)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("failure", ["write", "fsync", "replace"])
def test_filesystem_failures_leave_original_output_intact(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], existing: bool, failure: str,
) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"
    previous = b"old output\n" if existing else None
    if previous is not None:
        output_path.write_bytes(previous)
    if failure == "write":
        original_open = Path.open

        def fail_open(path: Path, *args: Any, **kwargs: Any) -> Any:
            if path.name.endswith(".tmp") and args and args[0] == "xb":
                raise OSError("injected temporary creation failure")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", fail_open)
    elif failure == "fsync":
        def fail_fsync(descriptor: int) -> None:
            raise OSError("injected fsync failure")
        monkeypatch.setattr(cli.os, "fsync", fail_fsync)
    else:
        def fail_replace(source: Path, target: Path) -> None:
            raise OSError("injected replace failure")
        monkeypatch.setattr(cli.os, "replace", fail_replace)
    assert cli.main(_arguments(input_path, output_path, overwrite=True)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "injected" in captured.err
    _assert_clean(tmp_path, output_path, previous)


@pytest.mark.parametrize("target_name", [".knowledge_graph.json.tmp", ".knowledge_graph.json.backup.tmp"])
def test_preexisting_temporary_file_is_preserved(
    cli: ModuleType, tmp_path: Path, target_name: str,
) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"
    output_path.write_bytes(b"old output\n")
    occupied = tmp_path / target_name
    occupied.write_bytes(b"unrelated temporary file\n")
    assert cli.main(_arguments(input_path, output_path, overwrite=True)) == 2
    assert occupied.read_bytes() == b"unrelated temporary file\n"
    assert output_path.read_bytes() == b"old output\n"
    assert {path.name for path in tmp_path.glob("*.tmp")} == {target_name}


def test_cli_creates_parent_directory_when_needed(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "nested/graph/knowledge_graph.json"
    result = _run(input_path, output_path)
    assert result.returncode == 0, result.stderr
    assert load_knowledge_graph(output_path)["scenario_id"] == SCENARIO_ID
    assert not list(tmp_path.rglob("*.tmp"))


def test_cli_refuses_to_overwrite_its_ground_truth(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    before = input_path.read_bytes()
    result = _run(input_path, input_path, overwrite=True)
    assert result.returncode == 2
    assert input_path.read_bytes() == before
    assert result.stdout == ""
    assert not list(tmp_path.glob("*.tmp"))


def test_cli_refuses_hardlink_alias_of_ground_truth(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    output_path = tmp_path / "knowledge_graph.json"
    output_path.hardlink_to(input_path)
    before = input_path.read_bytes()
    result = _run(input_path, output_path, overwrite=True)
    assert result.returncode == 2
    assert result.stdout == ""
    assert output_path.samefile(input_path)
    assert input_path.read_bytes() == output_path.read_bytes() == before
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("phase", ["temporary", "final"])
@pytest.mark.parametrize("mismatch", ["semantic", "bytes"])
def test_readback_mismatch_preserves_output_and_cleans_temporary_files(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], existing: bool, phase: str, mismatch: str,
) -> None:
    input_path = _copy_input(tmp_path)
    before = input_path.read_bytes()
    output_path = tmp_path / "knowledge_graph.json"
    previous = b"old output\n" if existing else None
    if previous is not None:
        output_path.write_bytes(previous)
    original_load = cli.load_knowledge_graph

    def mismatching_load(path: Path) -> dict[str, Any]:
        graph = original_load(path)
        if (phase == "final") == (path == output_path):
            if mismatch == "semantic":
                graph["nodes"][0]["label"] += " changed"
            else:
                path.write_bytes(path.read_bytes() + b"\n")
        return graph

    monkeypatch.setattr(cli, "load_knowledge_graph", mismatching_load)
    assert cli.main(_arguments(input_path, output_path, overwrite=True)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "read-back" in captured.err
    assert input_path.read_bytes() == before
    _assert_clean(tmp_path, output_path, previous)


@pytest.mark.parametrize("name", [".knowledge_graph.json.tmp", ".knowledge_graph.json.backup.tmp"])
def test_cli_refuses_input_using_transaction_temporary_path(tmp_path: Path, name: str) -> None:
    input_path = tmp_path / name
    input_path.write_bytes(GROUND_TRUTH_FIXTURE.read_bytes())
    before = input_path.read_bytes()
    output_path = tmp_path / "knowledge_graph.json"
    result = _run(input_path, output_path, overwrite=True)
    assert result.returncode == 2
    assert input_path.read_bytes() == before
    assert not output_path.exists()


def test_serialization_preserves_unicode_and_has_one_final_newline(tmp_path: Path) -> None:
    input_path = _copy_input(tmp_path)
    document = load_ground_truth_document(input_path)
    document["entities"][0]["attributes"]["note"] = "Dữ liệu thử nghiệm"
    input_path.write_bytes((json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    output_path = tmp_path / "knowledge_graph.json"
    result = _run(input_path, output_path)
    assert result.returncode == 0, result.stderr
    payload = output_path.read_bytes()
    assert "Dữ liệu thử nghiệm".encode("utf-8") in payload
    assert payload.endswith(b"\n") and not payload.endswith(b"\n\n")
    assert b"\r\n" not in payload
    assert not payload.startswith(b"\xef\xbb\xbf")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_serializer_rejects_nonfinite_values(cli: ModuleType, value: float) -> None:
    with pytest.raises(cli.KnowledgeGraphCliError, match="serialize"):
        cli._serialize({"invalid": value})


def test_cli_has_no_network_model_clock_random_uuid_or_traversal_dependencies() -> None:
    tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    forbidden = {
        "socket", "requests", "urllib", "http", "time", "datetime", "random",
        "uuid", "tempfile", "sentence_transformers", "transformers", "torch",
        "openai", "threat_hunting.retrieval",
    }
    assert not {module for module in imports if any(
        module == name or module.startswith(name + ".") for name in forbidden
    )}
    assert not {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)} & {
        "uuid4", "mkstemp", "time", "now", "utcnow", "random", "traverse", "embed_documents",
    }
