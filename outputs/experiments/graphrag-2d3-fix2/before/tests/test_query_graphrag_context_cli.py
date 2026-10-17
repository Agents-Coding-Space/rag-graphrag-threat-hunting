"""Production GraphRAG CLI contracts using synthetic inputs and fake embeddings."""

from __future__ import annotations

import ast
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from threat_hunting.graph import load_knowledge_graph
from threat_hunting.graphrag import build_graphrag_context
from threat_hunting.retrieval import load_retrieval_corpus, load_vector_index


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/query_graphrag_context.py"
FIXTURES = (
    ROOT / "tests/fixtures/retrieval/builder/expected_retrieval_corpus.json",
    ROOT / "tests/fixtures/retrieval/vector_builder/expected_vector_index.json",
    ROOT / "tests/fixtures/graph/builder/expected_knowledge_graph.json",
)
REVISION = "a" * 40
QUERY = "Những thực thể synthetic nào cần được xem xét?"
HASH_OPTIONS = (
    "--expected-corpus-sha256", "--expected-index-sha256", "--expected-graph-sha256",
)
LOADERS = ("load_retrieval_corpus", "load_vector_index", "load_knowledge_graph")
Paths = tuple[Path, Path, Path]

SPEC = importlib.util.spec_from_file_location("testable_graphrag_query_cli", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)


def _hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")


@pytest.fixture
def paths(tmp_path: Path) -> Paths:
    destinations = tuple(tmp_path / name for name in ("corpus.json", "index.json", "graph.json"))
    for source, destination in zip(FIXTURES, destinations, strict=True):
        shutil.copyfile(source, destination)
    index = load_vector_index(destinations[1])
    index["corpus_provenance"]["sha256"] = _hash(destinations[0])
    index["embedding"]["provider"] = "sentence-transformers"
    index["embedding"]["model_revision"] = REVISION
    _write(destinations[1], index)
    return destinations


class Factory:
    """The resulting backend supplies only the required embedding method."""

    def __init__(self, *, on_embed=None, init_error=None, embed_error=None, noisy=False):
        self.calls: list[dict[str, Any]] = []
        self.batches: list[list[str]] = []
        self.on_embed = on_embed
        self.init_error = init_error
        self.embed_error = embed_error
        self.noisy = noisy

    def __call__(self, **settings):
        self.calls.append(settings)
        if self.noisy:
            print("synthetic model initialization")
        if self.init_error is not None:
            raise self.init_error

        def embed_documents(texts):
            self.batches.append(list(texts))
            if self.noisy:
                print("synthetic model inference")
            if self.on_embed is not None:
                self.on_embed()
            if self.embed_error is not None:
                raise self.embed_error
            return [[1.0, *([0.0] * (settings["dimension"] - 1))] for _ in texts]

        return SimpleNamespace(embed_documents=embed_documents)


def _kwargs(paths: Paths, factory=None, **options) -> dict[str, Any]:
    return {
        "corpus_path": paths[0], "vector_index_path": paths[1], "graph_path": paths[2],
        "query": QUERY, "expected_corpus_sha256": _hash(paths[0]),
        "expected_index_sha256": _hash(paths[1]), "expected_graph_sha256": _hash(paths[2]),
        "backend_factory": Factory() if factory is None else factory, **options,
    }


def _arguments(paths: Paths, query: str = QUERY) -> list[str]:
    args = ["--corpus", str(paths[0]), "--vector-index", str(paths[1]),
            "--graph", str(paths[2]), "--query", query]
    for option, path in zip(HASH_OPTIONS, paths, strict=True):
        args.extend((option, _hash(path)))
    return args


def _main(paths, capsys, *, factory=None, argv=None):
    code = cli.main(
        _arguments(paths) if argv is None else argv,
        backend_factory=Factory() if factory is None else factory,
    )
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _assert_failure(result):
    code, stdout, stderr = result
    assert code == 2
    assert stdout == ""
    assert any(line.startswith("error:") for line in stderr.splitlines())
    assert "Traceback" not in stderr


def _change(paths: Paths, number: int, change) -> None:
    document = json.loads(paths[number].read_text(encoding="utf-8"))
    change(document)
    _write(paths[number], document)


def _walk(value):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def test_parser_accepts_every_option_and_repeated_filters(paths):
    args = cli._build_parser().parse_args(_arguments(paths) + [
        "--top-k", "3", "--candidate-k", "9",
        "--chunk-type", "entity", "--chunk-type", "relationship",
        "--required-dimension", "evidence", "--required-dimension", "provenance",
        "--direction", "incoming", "--max-depth", "1",
        "--allowed-edge-type", "supports", "--allowed-edge-type", "spawned",
        "--max-nodes", "77", "--max-edges", "88",
    ])
    assert (args.corpus, args.vector_index, args.graph) == paths
    assert args.query == QUERY
    assert (args.top_k, args.candidate_k, args.direction, args.max_depth) == (3, 9, "incoming", 1)
    assert args.chunk_types == ["entity", "relationship"]
    assert args.required_dimensions == ["evidence", "provenance"]
    assert args.allowed_edge_types == ["supports", "spawned"]
    assert (args.max_nodes, args.max_edges) == (77, 88)
    assert (args.expected_corpus_sha256, args.expected_index_sha256,
            args.expected_graph_sha256) == tuple(_hash(path) for path in paths)


@pytest.mark.parametrize("extra", [
    ["--dir", "both"], ["--quer", "anything"], ["--expected-graph-sha", "a" * 64],
    ["--direction", "sideways"], ["--top-k", "fraction"], ["--output", "unwanted.json"],
])
def test_parser_rejects_abbreviation_invalid_choices_and_unknown_options(paths, capsys, extra):
    _assert_failure(_main(paths, capsys, argv=_arguments(paths) + extra))


@pytest.mark.parametrize("direction", ["outgoing", "incoming", "both"])
def test_parser_valid_directions_and_defaults(paths, direction):
    args = cli._build_parser().parse_args(_arguments(paths) + ["--direction", direction])
    assert args.direction == direction
    assert (args.top_k, args.candidate_k, args.max_depth, args.max_nodes, args.max_edges) == (
        5, 20, 2, 100, 200,
    )
    assert args.chunk_types is args.required_dimensions is args.allowed_edge_types is None


@pytest.mark.parametrize("option", HASH_OPTIONS)
@pytest.mark.parametrize("invalid", ["", "a" * 63, "a" * 65, "g" * 64, " a" * 32, "a" * 64 + "\n"])
def test_hash_format_fails_before_any_loader_or_model(paths, capsys, monkeypatch, option, invalid):
    def forbidden(*args, **kwargs):
        pytest.fail("loader/model must not run after invalid expected hash")
    for name in LOADERS:
        monkeypatch.setattr(cli, name, forbidden)
    args = _arguments(paths)
    args[args.index(option) + 1] = invalid
    _assert_failure(_main(paths, capsys, factory=forbidden, argv=args))


@pytest.mark.parametrize("invalid", [None, 1, True, [], {}])
def test_hash_requires_a_string(invalid):
    with pytest.raises(cli.GraphRAGQueryCliError, match="64 hexadecimal"):
        cli._expected_hash(invalid, "--expected-corpus-sha256")


@pytest.mark.parametrize("number", range(3))
def test_each_input_hash_mismatch_prevents_load_and_model(paths, capsys, monkeypatch, number):
    def forbidden(*args, **kwargs):
        pytest.fail("no loader/model may run before matching input hashes")
    for name in LOADERS:
        monkeypatch.setattr(cli, name, forbidden)
    args = _arguments(paths)
    args[args.index(HASH_OPTIONS[number]) + 1] = "0" * 64
    result = _main(paths, capsys, factory=forbidden, argv=args)
    _assert_failure(result)
    assert str(paths[number]) in result[2]


@pytest.mark.parametrize("number", range(3))
def test_missing_input_reports_filename_without_model(paths, capsys, number):
    args = _arguments(paths)
    paths[number].unlink()
    factory = Factory()
    result = _main(paths, capsys, factory=factory, argv=args)
    _assert_failure(result)
    assert str(paths[number]) in result[2]
    assert factory.calls == []


@pytest.mark.parametrize("number", range(3))
@pytest.mark.parametrize("invalid", [b'{"duplicate":1,"duplicate":2}', b'{"bad":NaN}', b'{', b'\xff'])
def test_reused_loaders_reject_bad_json_schema_and_encoding(paths, capsys, number, invalid):
    paths[number].write_bytes(invalid)
    factory = Factory()
    result = _main(paths, capsys, factory=factory)
    _assert_failure(result)
    assert str(paths[number]) in result[2]
    assert factory.calls == []


def test_all_three_loaders_and_single_orchestrator_are_reused(paths, monkeypatch):
    sequence = []
    objects = []
    for name in LOADERS:
        original = getattr(cli, name)
        def load(path, _name=name, _original=original):
            sequence.append(_name)
            result = _original(path)
            objects.append(result)
            return result
        monkeypatch.setattr(cli, name, load)
    original = cli.build_graphrag_context
    results = []
    def orchestrate(*args, **kwargs):
        sequence.append("orchestration")
        assert args[:3] == tuple(objects)
        assert all(actual is expected for actual, expected in zip(args[:3], objects, strict=True))
        result = original(*args, **kwargs)
        results.append(result)
        return result
    monkeypatch.setattr(cli, "build_graphrag_context", orchestrate)
    result = cli.query_graphrag_context(**_kwargs(paths))
    assert sequence == [*LOADERS, "orchestration"]
    assert len(results) == 1 and result is results[0]


@pytest.mark.parametrize("field,value", [
    ("corpus_id", "different-corpus"), ("scenario_id", "different-scenario"),
    ("sha256", "0" * 64),
])
def test_index_corpus_preflight_fails_before_backend(paths, capsys, field, value):
    _change(paths, 1, lambda document: document["corpus_provenance"].__setitem__(field, value))
    factory = Factory()
    result = _main(paths, capsys, factory=factory)
    _assert_failure(result)
    assert "preflight" in result[2]
    assert factory.calls == []


def test_graph_scenario_preflight_fails_before_backend(paths, capsys, monkeypatch):
    graph = load_knowledge_graph(paths[2])
    graph["scenario_id"] = "different-scenario"
    monkeypatch.setattr(cli, "load_knowledge_graph", lambda path: graph)
    factory = Factory()
    result = _main(paths, capsys, factory=factory)
    _assert_failure(result)
    assert "scenario_id mismatch" in result[2]
    assert factory.calls == []


@pytest.mark.parametrize("field,value", [("path", "different-ground-truth.json"), ("sha256", "0" * 64)])
def test_entire_ground_truth_provenance_checked_before_backend(paths, capsys, field, value):
    _change(paths, 2, lambda document: document["source_ground_truth"].__setitem__(field, value))
    factory = Factory()
    result = _main(paths, capsys, factory=factory)
    _assert_failure(result)
    assert "Ground Truth provenance mismatch" in result[2]
    assert factory.calls == []


@pytest.mark.parametrize("provider", ["synthetic-provider", "Sentence-Transformers"])
def test_unsupported_provider_prevents_backend(paths, capsys, provider):
    _change(paths, 1, lambda document: document["embedding"].__setitem__("provider", provider))
    factory = Factory()
    result = _main(paths, capsys, factory=factory)
    _assert_failure(result)
    assert "provider" in result[2] and factory.calls == []


@pytest.mark.parametrize("revision", ["main", "v1.0", "a" * 39, "a" * 41, "g" * 40, "a" * 40 + "\n"])
def test_unpinned_revision_prevents_backend(paths, capsys, revision):
    _change(paths, 1, lambda document: document["embedding"].__setitem__("model_revision", revision))
    factory = Factory()
    result = _main(paths, capsys, factory=factory)
    _assert_failure(result)
    assert "40-character" in result[2] and factory.calls == []


def test_uppercase_hashes_remain_compatible_without_mutating_provenance(paths, capsys):
    _change(paths, 1, lambda document: document["corpus_provenance"].__setitem__(
        "sha256", document["corpus_provenance"]["sha256"].upper(),
    ))
    before = [path.read_bytes() for path in paths]
    args = _arguments(paths)
    for option in HASH_OPTIONS:
        args[args.index(option) + 1] = args[args.index(option) + 1].upper()
    code, stdout, stderr = _main(paths, capsys, argv=args)
    assert code == 0 and stderr == "" and json.loads(stdout)["retrieval"]["hits"]
    assert [path.read_bytes() for path in paths] == before


def test_lazy_default_backend_descriptor_unicode_prefix_and_callback_contract(paths, monkeypatch):
    factory = Factory()
    monkeypatch.setattr(cli, "SentenceTransformerEmbeddingBackend", factory)
    arguments = _kwargs(paths)
    arguments.pop("backend_factory")
    result = cli.query_graphrag_context(**arguments)
    embedding = load_vector_index(paths[1])["embedding"]
    assert factory.calls == [{
        "model_id": embedding["model_id"], "model_revision": REVISION,
        "dimension": embedding["dimension"], "device": "cpu",
        "batch_size": 1, "show_progress_bar": False,
    }]
    assert factory.batches == [[embedding["query_prefix"] + QUERY]]
    assert result["query"]["text"] == QUERY


def test_no_eligible_hits_retain_embedding_contract_and_skip_traversal(paths):
    factory = Factory()
    dimensions = load_retrieval_corpus(paths[0])["queryable_dimensions"]
    result = cli.query_graphrag_context(**_kwargs(paths, factory, required_dimensions=dimensions))
    assert result["retrieval"]["hits"] == []
    assert result["seed_mapping"]["seed_node_ids"] == []
    assert result["traversal"] is None
    assert result["metadata"]["traversal_performed"] is False
    # The current vector retriever embeds once before checking eligible chunks.
    assert result["warnings"] and len(factory.calls) == 1
    assert len(factory.batches) == 1


def test_orchestration_without_callback_never_initializes_backend(paths, monkeypatch):
    context = {"schema_version": "graphrag-context/v1"}
    factory = Factory()
    monkeypatch.setattr(cli, "build_graphrag_context", lambda *args, **kwargs: context)
    assert cli.query_graphrag_context(**_kwargs(paths, factory)) is context
    assert factory.calls == []


def test_backend_initialized_once_even_for_repeated_callback_calls(paths, monkeypatch):
    factory = Factory()
    def orchestrate(*args, **kwargs):
        assert kwargs["embed_query"](["first"]) == [[1.0, 0.0, 0.0]]
        assert kwargs["embed_query"](["second"]) == [[1.0, 0.0, 0.0]]
        return {"schema_version": "graphrag-context/v1"}
    monkeypatch.setattr(cli, "build_graphrag_context", orchestrate)
    cli.query_graphrag_context(**_kwargs(paths, factory))
    assert len(factory.calls) == 1 and factory.batches == [["first"], ["second"]]


@pytest.mark.parametrize("backend", [object(), SimpleNamespace(embed_documents=None)])
def test_backend_missing_required_embedding_method(paths, capsys, backend):
    result = _main(paths, capsys, factory=lambda **settings: backend)
    _assert_failure(result)
    assert "embed_documents" in result[2]


@pytest.mark.parametrize("stage", ["initialization", "embedding"])
def test_backend_failures_emit_only_error(paths, capsys, stage):
    factory = Factory(**({"init_error": RuntimeError("cannot initialize")} if stage == "initialization"
                         else {"embed_error": RuntimeError("cannot embed")}))
    _assert_failure(_main(paths, capsys, factory=factory))


def test_options_forwarded_unchanged_to_one_orchestration_call(paths, monkeypatch):
    calls = []
    options = {
        "top_k": 3, "candidate_k": 9, "chunk_types": ["entity", "relationship"],
        "required_dimensions": ["provenance"], "direction": "incoming", "max_depth": 1,
        "allowed_edge_types": ["supports", "spawned"], "max_nodes": 77, "max_edges": 88,
    }
    def orchestrate(*args, **kwargs):
        calls.append((args, kwargs))
        return {"schema_version": "graphrag-context/v1"}
    monkeypatch.setattr(cli, "build_graphrag_context", orchestrate)
    cli.query_graphrag_context(**_kwargs(paths, **options))
    assert len(calls) == 1 and calls[0][0][3] == QUERY
    assert calls[0][1]["corpus_sha256"] == _hash(paths[0])
    for name, value in options.items():
        assert calls[0][1][name] == value
        if isinstance(value, list):
            assert calls[0][1][name] is value


def test_full_context_status_and_provenance_match_existing_api(paths):
    corpus, index, graph = (loader(path) for loader, path in zip(
        (load_retrieval_corpus, load_vector_index, load_knowledge_graph), paths, strict=True,
    ))
    expected = build_graphrag_context(
        corpus, index, graph, QUERY, corpus_sha256=_hash(paths[0]),
        embed_query=lambda texts: [[1.0, 0.0, 0.0]],
    )
    actual = cli.query_graphrag_context(**_kwargs(paths))
    assert actual == expected
    assert actual["source_ground_truth"] == corpus["source_ground_truth"]
    forbidden = {"answer", "confidence", "security_verdict", "evaluation_question", "expected_answer"}
    for value in _walk(actual):
        if isinstance(value, dict):
            assert forbidden.isdisjoint(value)
        elif isinstance(value, str):
            assert value != "confirmed"
    assessment = next(node for node in actual["traversal"]["nodes"] if node["node_type"] == "mitre_assessment")
    assert assessment["status"] == "candidate"


def test_loaded_objects_and_input_files_remain_unchanged_and_no_file_is_written(paths, monkeypatch):
    objects = []
    snapshots = []
    for name in LOADERS:
        original = getattr(cli, name)
        def load(path, _original=original):
            value = _original(path)
            objects.append(value)
            snapshots.append(deepcopy(value))
            return value
        monkeypatch.setattr(cli, name, load)
    before = {path.name: path.read_bytes() for path in paths[0].parent.iterdir()}
    def no_write(*args, **kwargs):
        pytest.fail("query must not write files")
    monkeypatch.setattr(Path, "write_bytes", no_write)
    monkeypatch.setattr(Path, "write_text", no_write)
    cli.query_graphrag_context(**_kwargs(paths))
    assert objects == snapshots
    assert {path.name: path.read_bytes() for path in paths[0].parent.iterdir()} == before


def test_stdout_compact_sorted_utf8_one_newline_and_byte_deterministic(paths, capsys):
    first = _main(paths, capsys)
    second = _main(paths, capsys)
    assert first == second
    code, stdout, stderr = first
    assert code == 0 and stderr == ""
    result = json.loads(stdout)
    assert result["schema_version"] == "graphrag-context/v1"
    assert QUERY in stdout
    assert stdout.count("\n") == 1 and stdout.endswith("\n")
    assert stdout.encode("utf-8") == (json.dumps(
        result, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("utf-8")


def test_noisy_loaders_backend_and_orchestration_are_redirected(paths, capsys, monkeypatch):
    for name in LOADERS:
        original = getattr(cli, name)
        def noisy(path, _name=name, _original=original):
            print(_name)
            return _original(path)
        monkeypatch.setattr(cli, name, noisy)
    original = cli.build_graphrag_context
    def orchestrate(*args, **kwargs):
        print("synthetic orchestration message")
        return original(*args, **kwargs)
    monkeypatch.setattr(cli, "build_graphrag_context", orchestrate)
    code, stdout, stderr = _main(paths, capsys, factory=Factory(noisy=True))
    assert code == 0 and json.loads(stdout)["schema_version"] == "graphrag-context/v1"
    for message in (*LOADERS, "synthetic orchestration message", "synthetic model initialization",
                    "synthetic model inference"):
        assert message in stderr and message not in stdout


@pytest.mark.parametrize("number", range(3))
@pytest.mark.parametrize("stage", ["embedding", "orchestration", "serialization"])
def test_each_hash_gate_detects_input_change_without_partial_stdout(paths, capsys, monkeypatch, number, stage):
    def mutate():
        paths[number].write_bytes(paths[number].read_bytes() + b" ")
    factory = Factory(on_embed=mutate) if stage == "embedding" else Factory()
    if stage == "orchestration":
        original = cli.build_graphrag_context
        def orchestrate(*args, **kwargs):
            result = original(*args, **kwargs)
            mutate()
            return result
        monkeypatch.setattr(cli, "build_graphrag_context", orchestrate)
    if stage == "serialization":
        original = cli._serialize
        def serialize(result):
            output = original(result)
            mutate()
            return output
        monkeypatch.setattr(cli, "_serialize", serialize)
    args = _arguments(paths)
    result = _main(paths, capsys, factory=factory, argv=args)
    _assert_failure(result)
    assert str(paths[number]) in result[2]
    assert ("after serialization" if stage == "serialization" else "after orchestration") in result[2]


def test_hash_checks_for_all_inputs_follow_required_order(paths, capsys, monkeypatch):
    sequence = []
    original_hash = cli._sha256_file
    def check(path):
        sequence.append(path)
        return original_hash(path)
    original = cli._serialize
    def serialize(result):
        sequence.append("serialization")
        return original(result)
    monkeypatch.setattr(cli, "_sha256_file", check)
    monkeypatch.setattr(cli, "_serialize", serialize)
    assert _main(paths, capsys)[0] == 0
    assert sequence == [*paths, *paths, "serialization", *paths]


@pytest.mark.parametrize("invalid", [
    {"schema_version": "wrong"}, [],
    {"schema_version": "graphrag-context/v1", "invalid": float("nan")},
    {"schema_version": "graphrag-context/v1", "invalid": float("inf")},
    {"schema_version": "graphrag-context/v1", "invalid": {"set"}},
    {"schema_version": "graphrag-context/v1", "invalid": "\ud800"},
])
def test_serialization_failures_leave_stdout_empty(paths, capsys, monkeypatch, invalid):
    monkeypatch.setattr(cli, "build_graphrag_context", lambda *args, **kwargs: invalid)
    _assert_failure(_main(paths, capsys))


@pytest.mark.parametrize("stage", [*LOADERS, "build_graphrag_context", "_serialize", "_sha256_file"])
def test_component_failures_emit_error_exit_two(paths, capsys, monkeypatch, stage):
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic component failure")
    monkeypatch.setattr(cli, stage, fail)
    _assert_failure(_main(paths, capsys))


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("stage", ["loader", "initialization", "embedding", "orchestration", "serialization"])
def test_process_control_exceptions_are_never_caught(paths, monkeypatch, exception, stage):
    def fail(*args, **kwargs):
        raise exception()
    factory = Factory()
    if stage == "initialization":
        factory.init_error = exception()
    elif stage == "embedding":
        factory.embed_error = exception()
    else:
        name = {"loader": LOADERS[0], "orchestration": "build_graphrag_context",
                "serialization": "_serialize"}[stage]
        monkeypatch.setattr(cli, name, fail)
    with pytest.raises(exception):
        cli.main(_arguments(paths), backend_factory=factory)


def test_subprocess_help_and_parser_errors_do_not_load_model():
    help_result = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--help"], capture_output=True, check=False,
    )
    assert help_result.returncode == 0 and help_result.stderr == b""
    assert b"--allowed-edge-type" in help_result.stdout
    bad = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--direction", "sideways"],
        capture_output=True, check=False,
    )
    assert bad.returncode == 2 and bad.stdout == b"" and bad.stderr.startswith(b"error:")


def test_implementation_generic_and_delegates_only_to_orchestration():
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("build_graphrag_context") == 1
    assert not {"retrieve_hybrid", "retrieve_vector", "map_hybrid_hits_to_graph_seeds",
                "traverse_knowledge_graph"}.intersection(calls)
    for forbidden in ("mshta", "powershell", "T1218.005", "all-MiniLM-L6-v2", "outputs/retrieval",
                      "graph-node--", "retrieval-chunk--", "token="):
        assert forbidden.casefold() not in source.casefold()
