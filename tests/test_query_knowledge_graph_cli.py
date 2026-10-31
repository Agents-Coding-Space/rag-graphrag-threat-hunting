"""Read-only production traversal CLI contracts using existing synthetic fixtures."""

from __future__ import annotations

import ast
import builtins
from collections import Counter
from collections.abc import Iterator
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
from types import ModuleType
from typing import Any

import pytest

from threat_hunting.graph import (
    KnowledgeGraphTraversalError,
    KnowledgeGraphValidationError,
    load_knowledge_graph,
    traverse_knowledge_graph,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts/query_knowledge_graph.py"
MINIMAL_FIXTURE = ROOT / "tests/fixtures/graph/knowledge_graph_minimal.json"
BUILDER_FIXTURE = ROOT / "tests/fixtures/graph/builder/expected_knowledge_graph.json"
ACTOR_ID = "node-synthetic-actor"
RESOURCE_ID = "node-synthetic-resource"


def _hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _copy_graph(tmp_path: Path, fixture: Path = MINIMAL_FIXTURE) -> Path:
    path = tmp_path / "knowledge_graph.json"
    shutil.copyfile(fixture, path)
    return path


def _arguments(
    path: Path,
    *,
    seeds: list[str] | None = None,
    expected_hash: str | None = None,
    **options: Any,
) -> list[str]:
    args = [
        "--graph", str(path),
        "--expected-graph-sha256", _hash(path) if expected_hash is None else expected_hash,
    ]
    for seed in [ACTOR_ID] if seeds is None else seeds:
        args.extend(("--seed-node-id", seed))
    for name, value in options.items():
        if name == "allowed_edge_types":
            for edge_type in value or []:
                args.extend(("--allowed-edge-type", edge_type))
        else:
            args.extend(("--" + name.replace("_", "-"), str(value)))
    return args


def _run(path: Path, **options: Any) -> subprocess.CompletedProcess[bytes]:
    return _run_arguments(_arguments(path, **options), cwd=path.parent)


def _run_arguments(
    args: list[str], *, cwd: Path = ROOT,
) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args], cwd=cwd,
        capture_output=True, check=False, env=environment,
    )


def _success(result: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    assert result.returncode == 0, result.stderr.decode("utf-8")
    assert result.stderr == b""
    output = result.stdout.decode("utf-8")
    document = json.loads(output)
    assert isinstance(document, dict)
    assert document["schema_version"] == "graph-traversal-result/v1"
    expected = json.dumps(
        document, ensure_ascii=False, sort_keys=True, allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    assert result.stdout == expected
    assert result.stdout.count(b"\n") == 1
    assert not result.stdout.startswith(b"\xef\xbb\xbf")
    assert b"\r\n" not in result.stdout
    return document


def _failure(result: subprocess.CompletedProcess[bytes], message: str = "") -> None:
    assert result.returncode == 2
    assert result.stdout == b""
    stderr = result.stderr.decode("utf-8")
    assert stderr.startswith("error:")
    assert message in stderr
    assert "Traceback" not in stderr


def _query(cli: ModuleType, path: Path, **options: Any) -> dict[str, Any]:
    args = {
        "graph_path": path, "expected_graph_sha256": _hash(path),
        "seed_node_ids": [ACTOR_ID],
    }
    args.update(options)
    return cli.query_knowledge_graph(**args)


def _main_failure(
    cli: ModuleType, args: list[str], capsys: pytest.CaptureFixture[str],
    *, message: str = "",
) -> None:
    assert cli.main(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err
    assert message in captured.err
    assert "Traceback" not in captured.err


def _busy_seed(graph: dict[str, Any]) -> str:
    degrees: Counter[str] = Counter()
    for edge in graph["edges"]:
        degrees.update((edge["source_node_id"], edge["target_node_id"]))
    return sorted(degrees, key=lambda node_id: (-degrees[node_id], node_id))[0]


def _walk(value: object) -> Iterator[object]:
    yield value
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    name = "query_knowledge_graph_cli_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def test_single_seed_success_uses_documented_defaults(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path)
    output = _success(_run(path))
    assert output == traverse_knowledge_graph(load_knowledge_graph(path), seed_node_ids=[ACTOR_ID])
    assert output["request"] == {
        "seed_node_ids": [ACTOR_ID], "direction": "both", "max_depth": 2,
        "allowed_edge_types": None, "max_nodes": 100, "max_edges": 200,
    }


def test_multiple_seed_success_preserves_every_seed(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path)
    seeds = [RESOURCE_ID, ACTOR_ID, "node-synthetic-assessment"]
    output = _success(_run(path, seeds=seeds))
    assert output["seed_node_ids"] == sorted(seeds)
    assert set(seeds).issubset(node["node_id"] for node in output["nodes"])
    assert output == traverse_knowledge_graph(load_knowledge_graph(path), seed_node_ids=seeds)


@pytest.mark.parametrize("direction", ("outgoing", "incoming", "both"))
@pytest.mark.parametrize("max_depth", (0, 1, 2))
def test_direction_and_depth_match_existing_traversal(
    tmp_path: Path, direction: str, max_depth: int,
) -> None:
    path = _copy_graph(tmp_path, BUILDER_FIXTURE)
    graph = load_knowledge_graph(path)
    seed = _busy_seed(graph)
    output = _success(_run(path, seeds=[seed], direction=direction, max_depth=max_depth))
    assert output == traverse_knowledge_graph(
        graph, seed_node_ids=[seed], direction=direction, max_depth=max_depth,
    )
    assert output["metadata"]["max_reached_depth"] <= max_depth
    if max_depth == 0:
        assert [node["node_id"] for node in output["nodes"]] == [seed]
        assert output["edges"] == []


@pytest.mark.parametrize("filters", (["supports"], ["supports", "fact_subject"], ["unseen_edge_type"]))
def test_repeatable_edge_filters_are_delegated(tmp_path: Path, filters: list[str]) -> None:
    path = _copy_graph(tmp_path, BUILDER_FIXTURE)
    graph = load_knowledge_graph(path)
    seed = _busy_seed(graph)
    output = _success(_run(path, seeds=[seed], allowed_edge_types=filters))
    assert output == traverse_knowledge_graph(graph, seed_node_ids=[seed], allowed_edge_types=filters)
    assert output["request"]["allowed_edge_types"] == sorted(filters)
    assert {edge["edge_type"] for edge in output["edges"]}.issubset(filters)


@pytest.mark.parametrize(
    ("max_nodes", "max_edges", "limit"), ((1, 200, "max_nodes"), (100, 1, "max_edges"), (2, 1, "max_nodes")),
)
def test_limits_preserve_truncation_metadata_and_warnings(
    tmp_path: Path, max_nodes: int, max_edges: int, limit: str,
) -> None:
    path = _copy_graph(tmp_path, BUILDER_FIXTURE)
    graph = load_knowledge_graph(path)
    seed = _busy_seed(graph)
    output = _success(_run(path, seeds=[seed], max_nodes=max_nodes, max_edges=max_edges))
    assert output == traverse_knowledge_graph(
        graph, seed_node_ids=[seed], max_nodes=max_nodes, max_edges=max_edges,
    )
    assert len(output["nodes"]) <= max_nodes
    assert len(output["edges"]) <= max_edges
    assert output["metadata"]["truncated"] is True
    assert limit in output["metadata"]["applied_limits"]
    assert set(graph["warnings"]).issubset(output["warnings"])
    assert f"Traversal result truncated by {limit}={output['request'][limit]}." in output["warnings"]


def test_seed_and_filter_order_do_not_change_stdout_bytes(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path, BUILDER_FIXTURE)
    graph = load_knowledge_graph(path)
    seeds = [node["node_id"] for node in graph["nodes"] if node["node_type"] == "entity"]
    filters = ["supports", "fact_subject"]
    first = _run(path, seeds=seeds, allowed_edge_types=filters)
    second = _run(path, seeds=list(reversed(seeds)), allowed_edge_types=list(reversed(filters)))
    _success(first)
    _success(second)
    assert first.stdout == second.stdout


def test_repeated_runs_are_deterministic_byte_for_byte(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path)
    original_bytes = path.read_bytes()
    digest = _hash(path)
    first, second = _run(path, expected_hash=digest), _run(path, expected_hash=digest)
    _success(first)
    _success(second)
    assert first.stdout == second.stdout
    assert path.read_bytes() == original_bytes
    assert _hash(path) == digest


def test_unicode_stdout_is_utf8_unescaped_and_one_json_object(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path)
    output = _run(path, seeds=["node-synthetic-limitation"])
    _success(output)
    assert "Dữ liệu giả lập dùng để kiểm tra contract.".encode("utf-8") in output.stdout
    decoder = json.JSONDecoder()
    value, offset = decoder.raw_decode(output.stdout.decode("utf-8"))
    assert isinstance(value, dict)
    assert output.stdout.decode("utf-8")[offset:] == "\n"


def test_all_selected_nodes_and_edges_keep_full_provenance(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path, BUILDER_FIXTURE)
    graph = load_knowledge_graph(path)
    seeds = [node["node_id"] for node in graph["nodes"]]
    output = _success(_run(path, seeds=seeds, max_depth=1))
    assert output["nodes"] == sorted(graph["nodes"], key=lambda node: node["node_id"])
    assert output["edges"] == sorted(graph["edges"], key=lambda edge: edge["edge_id"])
    assert any(node["source_references"] for node in output["nodes"])
    assert any(edge["source_references"] for edge in output["edges"])
    assert any(edge["supporting_node_ids"] for edge in output["edges"])


def test_incoming_paths_retain_original_edge_direction(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path)
    graph = load_knowledge_graph(path)
    output = _success(_run(path, seeds=[RESOURCE_ID], direction="incoming", max_depth=1))
    original_edge = next(edge for edge in graph["edges"] if edge["edge_type"] == "synthetic_interaction")
    assert output["edges"] == [original_edge]
    assert original_edge["source_node_id"] == ACTOR_ID
    assert original_edge["target_node_id"] == RESOURCE_ID
    path_to_actor = next(item for item in output["paths"] if item["target_node_id"] == ACTOR_ID)
    assert path_to_actor["node_ids"] == [RESOURCE_ID, ACTOR_ID]


@pytest.mark.parametrize("invalid", ("", "bad", "a" * 63, "a" * 65, "g" * 64, " " + "a" * 64, "a" * 64 + "\n"))
def test_invalid_sha256_format_returns_two_without_json(tmp_path: Path, invalid: str) -> None:
    path = _copy_graph(tmp_path)
    _failure(_run(path, expected_hash=invalid), "64 hexadecimal")


def test_uppercase_sha256_is_accepted(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path)
    _success(_run(path, expected_hash=_hash(path).upper()))


def test_hash_mismatch_prevents_loader_and_traversal(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _copy_graph(tmp_path)

    def forbidden_call(*args: Any, **kwargs: Any) -> None:
        pytest.fail("hash mismatch must stop before loader/traversal")

    monkeypatch.setattr(cli, "load_knowledge_graph", forbidden_call)
    monkeypatch.setattr(cli, "traverse_knowledge_graph", forbidden_call)
    _main_failure(cli, _arguments(path, expected_hash="0" * 64), capsys, message="SHA-256 mismatch before load")


def test_missing_graph_reports_path_and_no_json(tmp_path: Path) -> None:
    missing = tmp_path / "missing_graph.json"
    _failure(_run(missing, expected_hash="0" * 64), "missing_graph.json")


@pytest.mark.parametrize(
    "failure", ("malformed", "array", "duplicate_root", "duplicate_nested", "schema", "nan", "invalid_utf8", "confirmed"),
)
def test_invalid_graph_inputs_are_rejected(tmp_path: Path, failure: str) -> None:
    path = _copy_graph(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    if failure == "malformed":
        payload = b'{"schema_version":'
    elif failure == "array":
        payload = b"[]"
    elif failure == "duplicate_root":
        payload = b'{"schema_version":"knowledge-graph/v1","schema_version":"knowledge-graph/v1"}'
    elif failure == "duplicate_nested":
        document["nodes"][0]["attributes"] = {"unique_token": 1}
        payload = json.dumps(document).replace('"unique_token": 1', '"unique_token": 1,"unique_token": 2').encode("utf-8")
    elif failure == "invalid_utf8":
        payload = b'{"label":"\xff"}'
    else:
        if failure == "schema":
            document["metadata"]["node_count"] += 1
        elif failure == "nan":
            document["nodes"][0]["attributes"]["invalid"] = float("nan")
        else:
            document["nodes"][0]["status"] = "confirmed"
        payload = json.dumps(document).encode("utf-8")
    path.write_bytes(payload)
    _failure(_run(path), "knowledge graph")
    assert path.read_bytes() == payload


@pytest.mark.parametrize("flag", ("--graph", "--expected-graph-sha256", "--seed-node-id"))
def test_required_arguments_missing_return_two(tmp_path: Path, flag: str) -> None:
    path = _copy_graph(tmp_path)
    args = _arguments(path)
    offset = args.index(flag)
    del args[offset:offset + 2]
    _failure(_run_arguments(args, cwd=tmp_path), flag)


@pytest.mark.parametrize("seeds", ([ACTOR_ID, ACTOR_ID], ["unknown-fixture-node"], [""], ["   "]))
def test_invalid_seeds_return_two_without_json(tmp_path: Path, seeds: list[str]) -> None:
    path = _copy_graph(tmp_path)
    _failure(_run(path, seeds=seeds))


@pytest.mark.parametrize("direction", ("sideways", "Incoming", "", "outgoing,incoming"))
def test_invalid_direction_returns_two(tmp_path: Path, direction: str) -> None:
    path = _copy_graph(tmp_path)
    _failure(_run(path, direction=direction), "--direction")


@pytest.mark.parametrize("depth", ("1.5", "true", -1, 65))
def test_invalid_depth_returns_two(tmp_path: Path, depth: object) -> None:
    path = _copy_graph(tmp_path)
    _failure(_run(path, max_depth=depth))


@pytest.mark.parametrize("limit", ("max_nodes", "max_edges"))
@pytest.mark.parametrize("value", (0, -1, "1.5", "false"))
def test_invalid_limits_return_two(tmp_path: Path, limit: str, value: object) -> None:
    path = _copy_graph(tmp_path)
    _failure(_run(path, **{limit: value}))


def test_node_limit_must_accommodate_all_seeds(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path)
    _failure(_run(path, seeds=[ACTOR_ID, RESOURCE_ID], max_nodes=1), "every seed")


@pytest.mark.parametrize("filters", (["supports", "supports"], ["bad-type"], ["Supports"], [""]))
def test_duplicate_or_invalid_edge_filters_return_two(tmp_path: Path, filters: list[str]) -> None:
    path = _copy_graph(tmp_path)
    _failure(_run(path, allowed_edge_types=filters))


@pytest.mark.parametrize("args", (["--unknown-option"], ["--output", "forbidden.json"], ["--gra", "graph.json"]))
def test_unknown_or_abbreviated_arguments_do_not_create_output(tmp_path: Path, args: list[str]) -> None:
    path = _copy_graph(tmp_path)
    before = {item.name: item.read_bytes() for item in tmp_path.iterdir()}
    _failure(_run_arguments([*_arguments(path), *args], cwd=tmp_path))
    assert {item.name: item.read_bytes() for item in tmp_path.iterdir()} == before


def test_cli_directly_delegates_loader_and_all_traversal_options(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _copy_graph(tmp_path)
    graph = load_knowledge_graph(path)
    seeds = [RESOURCE_ID, ACTOR_ID]
    filters = ["synthetic_interaction"]
    calls: list[tuple[str, object]] = []
    expected = traverse_knowledge_graph(
        graph, seed_node_ids=seeds, direction="incoming", max_depth=1,
        allowed_edge_types=filters, max_nodes=3, max_edges=7,
    )

    def load(source: Path) -> dict[str, Any]:
        calls.append(("load", source))
        return graph

    def traverse(source: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        assert source is graph
        calls.append(("traverse", kwargs))
        assert kwargs["seed_node_ids"] is seeds
        assert kwargs["allowed_edge_types"] is filters
        return expected

    monkeypatch.setattr(cli, "load_knowledge_graph", load)
    monkeypatch.setattr(cli, "traverse_knowledge_graph", traverse)
    actual = _query(
        cli, path, seed_node_ids=seeds, direction="incoming", max_depth=1,
        allowed_edge_types=filters, max_nodes=3, max_edges=7,
    )
    assert actual is expected
    assert calls == [("load", path), ("traverse", {
        "seed_node_ids": seeds, "direction": "incoming", "max_depth": 1,
        "allowed_edge_types": filters, "max_nodes": 3, "max_edges": 7,
    })]
    assert seeds == [RESOURCE_ID, ACTOR_ID]
    assert filters == ["synthetic_interaction"]


@pytest.mark.parametrize("stage", ("load_knowledge_graph", "traverse_knowledge_graph"))
@pytest.mark.parametrize("error_class", (RuntimeError, KnowledgeGraphTraversalError, KnowledgeGraphValidationError))
def test_delegated_errors_are_stderr_only_without_partial_json(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], stage: str, error_class: type[Exception],
) -> None:
    path = _copy_graph(tmp_path)

    def fail(*args: Any, **kwargs: Any) -> None:
        print("synthetic diagnostic from delegated operation")
        raise error_class("injected operation failure")

    monkeypatch.setattr(cli, stage, fail)
    _main_failure(cli, _arguments(path), capsys, message="injected operation failure")


@pytest.mark.parametrize("stage", ("loader", "traversal", "serialization"))
def test_graph_change_at_each_execution_boundary_prevents_stdout(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], stage: str,
) -> None:
    path = _copy_graph(tmp_path)
    digest = _hash(path)
    attribute = {
        "loader": "load_knowledge_graph", "traversal": "traverse_knowledge_graph",
        "serialization": "_serialize",
    }[stage]
    original = getattr(cli, attribute)

    def mutate(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        path.write_bytes(path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(cli, attribute, mutate)
    phase = "before stdout" if stage == "serialization" else "after traversal"
    _main_failure(cli, _arguments(path, expected_hash=digest), capsys, message=f"SHA-256 mismatch {phase}")
    assert _hash(path) != digest


def test_graph_removed_during_traversal_is_stderr_only(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _copy_graph(tmp_path)
    original = cli.traverse_knowledge_graph

    def remove(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = original(*args, **kwargs)
        path.unlink()
        return result

    monkeypatch.setattr(cli, "traverse_knowledge_graph", remove)
    _main_failure(cli, _arguments(path), capsys, message="cannot hash graph")


@pytest.mark.parametrize(
    "result", ({"bad": float("nan")}, {"bad": float("inf")}, {"bad": float("-inf")}, {"bad": {1, 2}}, {"bad": "\ud800"}),
)
def test_serialization_failure_never_emits_partial_json(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], result: dict[str, Any],
) -> None:
    path = _copy_graph(tmp_path)
    monkeypatch.setattr(cli, "traverse_knowledge_graph", lambda *args, **kwargs: result)
    _main_failure(cli, _arguments(path), capsys, message="cannot serialize")


def test_serialize_is_completed_before_final_hash_check_and_stdout(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _copy_graph(tmp_path)
    phases: list[str] = []
    original_assert = cli._assert_graph_hash
    original_serialize = cli._serialize

    def check(source: Path, digest: str, *, phase: str) -> None:
        phases.append(phase)
        assert capsys.readouterr().out == ""
        original_assert(source, digest, phase=phase)

    def serialize(result: dict[str, Any]) -> str:
        phases.append("serialization")
        return original_serialize(result)

    monkeypatch.setattr(cli, "_assert_graph_hash", check)
    monkeypatch.setattr(cli, "_serialize", serialize)
    assert cli.main(_arguments(path)) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["schema_version"] == "graph-traversal-result/v1"
    assert captured.err == ""
    assert phases == ["before load", "after traversal", "serialization", "before stdout"]


def test_query_does_not_modify_graph_or_create_files(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path)
    before = {item.name: item.read_bytes() for item in tmp_path.iterdir()}
    _success(_run(path))
    assert {item.name: item.read_bytes() for item in tmp_path.iterdir()} == before


def test_runtime_query_uses_read_only_file_modes_and_no_network(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _copy_graph(tmp_path)
    expected = _hash(path)
    modes: list[str] = []
    original_path_open, original_open = Path.open, builtins.open

    def guard_path_open(source: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        modes.append(mode)
        assert not set(mode) & set("wax+")
        return original_path_open(source, mode, *args, **kwargs)

    def guard_open(source: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        modes.append(mode)
        assert not set(mode) & set("wax+")
        return original_open(source, mode, *args, **kwargs)

    def forbidden_network(*args: Any, **kwargs: Any) -> None:
        pytest.fail("traversal query must not contact the network")

    monkeypatch.setattr(Path, "open", guard_path_open)
    monkeypatch.setattr(builtins, "open", guard_open)
    monkeypatch.setattr(socket, "socket", forbidden_network)
    monkeypatch.setattr(socket, "create_connection", forbidden_network)
    result = _query(cli, path, expected_graph_sha256=expected)
    assert result["nodes"]
    assert modes and set(modes).issubset({"rb", "r"})
    assert _hash(path) == expected


def test_positive_and_negative_mitre_assessments_remain_reviewable(tmp_path: Path) -> None:
    path = _copy_graph(tmp_path, BUILDER_FIXTURE)
    graph = load_knowledge_graph(path)
    assessments = [node for node in graph["nodes"] if node["node_type"] == "mitre_assessment"]
    assert len(assessments) == 2
    cases = (
        ("T1059.007", "not_supported_by_observed_command", "Synthetic negative assessment: observed command does not demonstrate this behavior."),
        ("T1218.005", "supported_by_observed_behavior", "Synthetic positive assessment: supplied evidence supports the candidate behavior."),
    )
    for node, (external_id, support, rationale) in zip(assessments, cases, strict=True):
        node["attributes"].update(
            external_id=external_id, evidence_support=support,
            rationale=rationale, review_status="needs_review",
        )
        assert node["status"] == "candidate"
    path.write_text(json.dumps(graph, ensure_ascii=False), encoding="utf-8")
    original_bytes = path.read_bytes()
    output = _success(_run(
        path, seeds=[node["node_id"] for node in assessments], direction="incoming", max_depth=2,
    ))
    selected = {node["node_id"]: node for node in output["nodes"]}
    for original, (_, support, _) in zip(assessments, cases, strict=True):
        assert selected[original["node_id"]] == original
        assert selected[original["node_id"]]["attributes"]["evidence_support"] == support
        assert selected[original["node_id"]]["attributes"]["rationale"]
        assert selected[original["node_id"]]["attributes"]["review_status"] == "needs_review"
        assert selected[original["node_id"]]["status"] == "candidate"
    assert any(edge["edge_type"] == "supports" for edge in output["edges"])
    forbidden = {"technique_confirmed", "technique_supported", "security_conclusion", "confirmed"}
    assert all(value not in forbidden for value in _walk(output) if isinstance(value, str))
    assert b"confirmed" not in json.dumps(output).encode("utf-8").lower()
    assert path.read_bytes() == original_bytes


def test_fixture_files_remain_unchanged_after_cli_runs(tmp_path: Path) -> None:
    snapshots = {fixture: fixture.read_bytes() for fixture in (MINIMAL_FIXTURE, BUILDER_FIXTURE)}
    path = _copy_graph(tmp_path)
    _success(_run(path))
    assert all(fixture.read_bytes() == payload for fixture, payload in snapshots.items())


def test_help_describes_cli_options_without_file_output_option() -> None:
    result = _run_arguments(["--help"])
    assert result.returncode == 0 and result.stderr == b""
    help_text = result.stdout.decode("utf-8")
    for flag in (
        "--graph", "--expected-graph-sha256", "--seed-node-id", "--direction",
        "--max-depth", "--allowed-edge-type", "--max-nodes", "--max-edges",
    ):
        assert flag in help_text
    assert "--output" not in help_text


def test_cli_source_is_generic_and_has_no_model_network_clock_or_file_writes() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    for forbidden in (
        "mshta", "powershell.exe", "cmd.exe", "regsvr32", "t1059.007", "t1218.005",
        "jsonl:line:", "node-synthetic", "graph-node--", "technique_confirmed",
        "technique_supported", "security_conclusion", "confirmed",
    ):
        assert forbidden not in source.casefold()
    tree = ast.parse(source)
    imports = {
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    forbidden_modules = {
        "socket", "requests", "urllib", "http", "time", "datetime", "random", "uuid",
        "tempfile", "sentence_transformers", "transformers", "torch", "openai",
        "threat_hunting.retrieval", "threat_hunting.ground_truth",
    }
    assert not {name for name in imports if any(
        name == forbidden or name.startswith(forbidden + ".") for forbidden in forbidden_modules
    )}
    attrs = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not attrs & {"write_text", "write_bytes", "mkdir", "mkstemp", "replace", "unlink", "uuid4", "now", "random"}
    graph_imports = {
        alias.name for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "threat_hunting.graph"
        for alias in node.names
    }
    assert graph_imports == {"load_knowledge_graph", "traverse_knowledge_graph"}
