"""Calibration runner guards and atomic output with local synthetic embeddings."""

from __future__ import annotations

import ast
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
import math
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/calibrate_graphrag_relevance.py"
FIXTURE_ROOT = ROOT / "tests/fixtures"
REVISION = "a" * 40
INPUT_NAMES = ("dataset", "config", "corpus", "index", "graph", "ground_truth")
HASH_OPTIONS = {name: "--expected-" + name.replace("_", "-") + "-sha256"
                for name in INPUT_NAMES}
PATH_OPTIONS = {
    "dataset": "--dataset", "config": "--config", "corpus": "--corpus",
    "index": "--vector-index", "graph": "--graph", "ground_truth": "--ground-truth",
}
PATH_KEYWORDS = {
    "dataset": "dataset_path", "config": "config_path", "corpus": "corpus_path",
    "index": "vector_index_path", "graph": "graph_path", "ground_truth": "ground_truth_path",
}


SPEC = importlib.util.spec_from_file_location("testable_graphrag_calibration_cli", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)


def _hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")


class Factory:
    """No model or network: one backend provides the embedding callback contract."""

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
            print("synthetic initialization message")
        if self.init_error is not None:
            raise self.init_error

        def embed_documents(texts):
            self.batches.append(list(texts))
            if self.noisy:
                print("synthetic embedding message")
            if self.on_embed is not None:
                self.on_embed()
            if self.embed_error is not None:
                raise self.embed_error
            return [[1.0, *([0.0] * (settings["dimension"] - 1))] for _ in texts]

        return SimpleNamespace(embed_documents=embed_documents)


def _arguments(paths: dict[str, Path], **options) -> list[str]:
    args = []
    for name in INPUT_NAMES:
        args.extend((PATH_OPTIONS[name], str(paths[name]), HASH_OPTIONS[name], _hash(paths[name])))
    args.extend(("--output", str(paths["output"]), "--cache-dir", str(paths["cache"])))
    if options.get("overwrite"):
        args.append("--overwrite")
    return args


def _kwargs(paths: dict[str, Path], factory=None, **options) -> dict[str, Any]:
    args = {PATH_KEYWORDS[name]: paths[name] for name in INPUT_NAMES}
    args.update({"expected_" + name + "_sha256": _hash(paths[name]) for name in INPUT_NAMES})
    args.update(output_path=paths["output"], cache_dir=paths["cache"],
                backend_factory=Factory() if factory is None else factory)
    args.update(options)
    return args


def _main(paths, capsys, *, factory=None, argv=None, overwrite=False):
    code = cli.main(
        _arguments(paths, overwrite=overwrite) if argv is None else argv,
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


def _change(paths, name, change):
    document = _read(paths[name])
    change(document)
    _write(paths[name], document)


def _snapshot_files(directory: Path):
    return {path.relative_to(directory).as_posix(): path.read_bytes()
            for path in directory.rglob("*") if path.is_file()}


def _walk(value):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


@pytest.fixture
def paths(tmp_path):
    result = {name: tmp_path / (name + ".json") for name in INPUT_NAMES}
    result["output"] = tmp_path / "reports" / "calibration.json"
    result["cache"] = tmp_path / "external-cache"
    result["output"].parent.mkdir()
    result["cache"].mkdir()
    source = {
        "dataset": "evaluation/relevance_calibration_minimal.json",
        "corpus": "retrieval/builder/expected_retrieval_corpus.json",
        "index": "retrieval/vector_builder/expected_vector_index.json",
        "graph": "graph/builder/expected_knowledge_graph.json",
        "ground_truth": "ground_truth/builder/expected_ground_truth.json",
    }
    documents = {name: _read(FIXTURE_ROOT / fixture) for name, fixture in source.items()}
    documents["dataset"]["scenario_id"] = documents["corpus"]["scenario_id"]
    _write(result["ground_truth"], documents["ground_truth"])
    for name in ("corpus", "graph"):
        documents[name]["source_ground_truth"].update(
            path=result["ground_truth"].as_posix(), sha256=_hash(result["ground_truth"]),
        )
        _write(result[name], documents[name])
    index = documents["index"]
    index["corpus_provenance"].update(path=result["corpus"].as_posix(), sha256=_hash(result["corpus"]))
    index["embedding"].update(provider="sentence-transformers", model_revision=REVISION, normalization="l2")
    for record in index["records"]:
        norm = math.sqrt(sum(value * value for value in record["vector"]))
        record["vector"] = [value / norm for value in record["vector"]]
    _write(result["index"], index)
    _write(result["dataset"], documents["dataset"])
    config = _read(ROOT / "configs/evaluation/mshta_relevance_calibration.json")
    config["calibration_id"] = "synthetic-calibration"
    config["expected_case_count"] = 4
    for field in config["candidate_search_space"]:
        config["candidate_search_space"][field] = config["candidate_search_space"][field][:1]
    config["candidate_search_space"]["min_hits"] = [1, 5]
    _write(result["config"], config)
    return result


def test_parser_all_input_hashes_output_cache_and_overwrite(paths):
    args = cli._build_parser().parse_args(_arguments(paths, overwrite=True))
    for name in INPUT_NAMES:
        attribute = "vector_index" if name == "index" else name
        assert getattr(args, attribute) == paths[name]
        assert getattr(args, "expected_" + name + "_sha256") == _hash(paths[name])
    assert args.output == paths["output"]
    assert args.cache_dir == paths["cache"]
    assert args.overwrite is True


@pytest.mark.parametrize("extra", [
    ["--dat", "unwanted.json"], ["--expected-corpus-sha", "a" * 64],
    ["--cache", "unwanted"], ["--query", "do not add queries at runtime"],
    ["--threshold", "0.2"],
])
def test_parser_rejects_abbreviation_and_query_policy_overrides(paths, capsys, extra):
    _assert_failure(_main(paths, capsys, argv=_arguments(paths) + extra))


@pytest.mark.parametrize("name", INPUT_NAMES)
@pytest.mark.parametrize("invalid", ["", "a" * 63, "a" * 65, "g" * 64, "a" * 64 + "\n"])
def test_expected_hash_format_before_any_loader_or_model(paths, capsys, monkeypatch, name, invalid):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid hashes must fail before loaders or backend")
    monkeypatch.setattr(cli, "load_retrieval_corpus", forbidden)
    args = _arguments(paths)
    args[args.index(HASH_OPTIONS[name]) + 1] = invalid
    _assert_failure(_main(paths, capsys, factory=forbidden, argv=args))
    assert not paths["output"].exists()


@pytest.mark.parametrize("name", INPUT_NAMES)
def test_each_input_hash_mismatch_before_load_and_model(paths, capsys, monkeypatch, name):
    def forbidden(*args, **kwargs):
        pytest.fail("all hashes must match before loading")
    monkeypatch.setattr(cli, "load_retrieval_corpus", forbidden)
    args = _arguments(paths)
    args[args.index(HASH_OPTIONS[name]) + 1] = "0" * 64
    result = _main(paths, capsys, factory=forbidden, argv=args)
    _assert_failure(result)
    assert str(paths[name]) in result[2]
    assert not paths["output"].exists()


@pytest.mark.parametrize("name", INPUT_NAMES)
def test_missing_input_has_filename_and_no_backend(paths, capsys, name):
    args = _arguments(paths)
    paths[name].unlink()
    factory = Factory()
    result = _main(paths, capsys, factory=factory, argv=args)
    _assert_failure(result)
    assert str(paths[name]) in result[2]
    assert not factory.calls


@pytest.mark.parametrize("name", INPUT_NAMES)
@pytest.mark.parametrize("invalid", [
    b'{"duplicate":1,"duplicate":2}', b'{"bad":NaN}', b'{"bad":Infinity}', b'{', b'\xff',
])
def test_strict_json_duplicate_nonfinite_invalid_json_encoding_before_model(paths, capsys, name, invalid):
    paths[name].write_bytes(invalid)
    factory = Factory()
    result = _main(paths, capsys, factory=factory)
    _assert_failure(result)
    assert str(paths[name]) in result[2]
    assert not factory.calls
    assert not paths["output"].exists()


def test_uppercase_expected_hashes_are_accepted(paths, capsys):
    args = _arguments(paths)
    for option in HASH_OPTIONS.values():
        args[args.index(option) + 1] = args[args.index(option) + 1].upper()
    assert _main(paths, capsys, argv=args)[0] == 0


@pytest.mark.parametrize("field,value", [
    ("corpus_id", "different-corpus"), ("scenario_id", "different-scenario"),
    ("sha256", "0" * 64),
])
def test_index_preflight_mismatch_is_lazy(paths, capsys, field, value):
    _change(paths, "index", lambda document: document["corpus_provenance"].__setitem__(field, value))
    factory = Factory()
    result = _main(paths, capsys, factory=factory)
    _assert_failure(result)
    assert not factory.calls


def test_dataset_scenario_mismatch_before_backend(paths, capsys):
    _change(paths, "dataset", lambda document: document.__setitem__("scenario_id", "different-scenario"))
    factory = Factory()
    _assert_failure(_main(paths, capsys, factory=factory))
    assert not factory.calls


def test_dataset_case_count_contract_before_backend(paths, capsys):
    _change(paths, "dataset", lambda document: document["metadata"].__setitem__("case_count", 99))
    factory = Factory()
    _assert_failure(_main(paths, capsys, factory=factory))
    assert not factory.calls


@pytest.mark.parametrize("name", ["corpus", "graph"])
@pytest.mark.parametrize("field,value", [
    ("path", "different-ground-truth.json"), ("sha256", "0" * 64),
    ("schema_version", "scenario-ground-truth/v999"),
])
def test_full_ground_truth_provenance_links_before_backend(paths, capsys, name, field, value):
    _change(paths, name, lambda document: document["source_ground_truth"].__setitem__(field, value))
    if name == "corpus":
        _change(paths, "index", lambda document: document["corpus_provenance"].__setitem__(
            "sha256", _hash(paths["corpus"]),
        ))
    factory = Factory()
    _assert_failure(_main(paths, capsys, factory=factory))
    assert not factory.calls


@pytest.mark.parametrize("provider", ["synthetic-provider", "Sentence-Transformers"])
def test_unsupported_provider_before_backend(paths, capsys, provider):
    _change(paths, "index", lambda document: document["embedding"].__setitem__("provider", provider))
    factory = Factory()
    _assert_failure(_main(paths, capsys, factory=factory))
    assert not factory.calls


@pytest.mark.parametrize("revision", ["main", "a" * 39, "a" * 41, "g" * 40, "a" * 40 + "\n"])
def test_revision_must_be_full_commit_before_backend(paths, capsys, revision):
    _change(paths, "index", lambda document: document["embedding"].__setitem__("model_revision", revision))
    factory = Factory()
    _assert_failure(_main(paths, capsys, factory=factory))
    assert not factory.calls


def test_cache_inside_repository_is_rejected_before_backend(paths, capsys):
    args = _arguments(paths)
    args[args.index("--cache-dir") + 1] = str(ROOT / "outputs/model-cache-forbidden")
    factory = Factory()
    _assert_failure(_main(paths, capsys, factory=factory, argv=args))
    assert not factory.calls
    assert not (ROOT / "outputs/model-cache-forbidden").exists()


@pytest.mark.parametrize("name", INPUT_NAMES)
def test_output_cannot_overwrite_any_input(paths, capsys, name):
    before = paths[name].read_bytes()
    args = _arguments(paths, overwrite=True)
    args[args.index("--output") + 1] = str(paths[name])
    factory = Factory()
    _assert_failure(_main(paths, capsys, factory=factory, argv=args))
    assert not factory.calls
    assert paths[name].read_bytes() == before


def test_existing_output_needs_explicit_overwrite_before_backend(paths, capsys):
    paths["output"].write_bytes(b"previous review output\n")
    factory = Factory()
    _assert_failure(_main(paths, capsys, factory=factory))
    assert not factory.calls
    assert paths["output"].read_bytes() == b"previous review output\n"


@pytest.mark.parametrize("stage", ["initialization", "embedding"])
def test_backend_failure_does_not_install_output(paths, capsys, stage):
    options = {"init_error" if stage == "initialization" else "embed_error":
               RuntimeError("synthetic backend failure")}
    _assert_failure(_main(paths, capsys, factory=Factory(**options)))
    assert not paths["output"].exists()


@pytest.mark.parametrize("backend", [object(), SimpleNamespace(embed_documents=None)])
def test_backend_requires_embed_documents_contract(paths, capsys, backend):
    result = _main(paths, capsys, factory=lambda **kwargs: backend)
    _assert_failure(result)
    assert "embed_documents" in result[2]
    assert not paths["output"].exists()


def test_report_stdout_utf8_json_one_newline_and_no_model_noise(paths, capsys):
    factory = Factory(noisy=True)
    code, stdout, stderr = _main(paths, capsys, factory=factory)
    assert code == 0
    summary = json.loads(stdout)
    assert isinstance(summary, dict)
    assert stdout.endswith("\n") and stdout.count("\n") == 1
    assert stdout.encode("utf-8") == (json.dumps(
        summary, ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("utf-8")
    assert "synthetic initialization message" in stderr
    assert "synthetic embedding message" in stderr
    assert "synthetic" not in stdout or "synthetic initialization message" not in stdout


def test_deterministic_overwrite_and_readback_preserve_all_inputs(paths):
    before = {name: paths[name].read_bytes() for name in INPUT_NAMES}
    first = cli.run_calibration(**_kwargs(paths))
    first_bytes = paths["output"].read_bytes()
    assert _read(paths["output"]) == first
    second = cli.run_calibration(**_kwargs(paths, overwrite=True))
    assert second == first
    assert paths["output"].read_bytes() == first_bytes
    assert first_bytes.endswith(b"\n") and first_bytes.count(b"\n") == 1
    assert before == {name: paths[name].read_bytes() for name in INPUT_NAMES}
    assert {path.name for path in paths["output"].parent.iterdir()} == {paths["output"].name}
    assert all(value != "confirmed" for value in _walk(first) if isinstance(value, str))


@pytest.mark.parametrize("name", INPUT_NAMES)
def test_input_changes_during_embedding_abort_and_keep_existing_output(paths, capsys, name):
    paths["output"].write_bytes(b"old report\n")
    args = _arguments(paths, overwrite=True)
    def mutate():
        paths[name].write_bytes(paths[name].read_bytes() + b" ")
    factory = Factory(on_embed=mutate)
    result = _main(paths, capsys, factory=factory, argv=args)
    _assert_failure(result)
    assert str(paths[name]) in result[2]
    assert paths["output"].read_bytes() == b"old report\n"
    assert {path.name for path in paths["output"].parent.iterdir()} == {paths["output"].name}


def test_subprocess_help_and_parser_failure_need_no_backend():
    help_result = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--help"], capture_output=True, check=False,
    )
    assert help_result.returncode == 0 and help_result.stderr == b""
    assert b"--cache-dir" in help_result.stdout and b"--overwrite" in help_result.stdout
    invalid = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--not-an-option"], capture_output=True, check=False,
    )
    assert invalid.returncode == 2 and invalid.stdout == b""
    assert invalid.stderr.startswith(b"error:")


def test_runner_delegates_to_existing_orchestrator_and_keeps_generic_source():
    source = SCRIPT.read_text(encoding="utf-8")
    calls = [node.func.id for node in ast.walk(ast.parse(source))
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.count("build_graphrag_context") == 1
    assert calls.count("calibrate_relevance_policies") == 1
    assert not {"retrieve_hybrid", "retrieve_vector", "map_hybrid_hits_to_graph_seeds",
                "traverse_knowledge_graph"}.intersection(calls)
    for forbidden in ("mshta", "powershell", "T1218.005", "all-MiniLM-L6-v2",
                      "outputs/retrieval", "graph-node--", "retrieval-chunk--"):
        assert forbidden.casefold() not in source.casefold()


def test_one_context_per_case_shared_callback_backend_and_no_policy_embedding(paths, monkeypatch):
    from threat_hunting.evaluation import relevance_calibration as engine
    real_build, real_gate = cli.build_graphrag_context, engine.assess_graphrag_relevance
    build_calls, gate_calls = [], []
    def build(*args, **kwargs):
        build_calls.append((args, kwargs))
        return real_build(*args, **kwargs)
    def gate(context, *, policy):
        gate_calls.append((id(context), policy["policy_id"]))
        return real_gate(context, policy=policy)
    monkeypatch.setattr(cli, "build_graphrag_context", build)
    monkeypatch.setattr(engine, "assess_graphrag_relevance", gate)
    factory = Factory()
    report = cli.run_calibration(**_kwargs(paths, factory))
    dataset, config = _read(paths["dataset"]), _read(paths["config"])
    assert len(build_calls) == len(dataset["cases"]) == 4
    assert [args[3] for args, kwargs in build_calls] == [case["query"] for case in dataset["cases"]]
    assert len({id(kwargs["embed_query"]) for args, kwargs in build_calls}) == 1
    for args, kwargs in build_calls:
        assert {name: kwargs[name] for name in config["retrieval"]} == config["retrieval"]
        assert {name: kwargs[name] for name in config["traversal"]} == config["traversal"]
        assert kwargs["corpus_sha256"] == _hash(paths["corpus"])
    assert len(factory.calls) == 1 and len(factory.batches) == 4
    assert len(gate_calls) == 8 and len({context for context, policy in gate_calls}) == 4
    assert report["execution"]["embedding_backend_count"] == 1
    settings = factory.calls[0]
    index = _read(paths["index"])
    assert settings["model_id"] == index["embedding"]["model_id"]
    assert settings["model_revision"] == REVISION
    assert settings["dimension"] == index["embedding"]["dimension"]
    assert settings["device"] == "cpu" and settings["batch_size"] == 1
    assert settings["show_progress_bar"] is False


def test_offline_model_factory_explicit_no_token_or_network(paths, monkeypatch):
    calls = []
    settings = ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY",
                "HF_HUB_DISABLE_IMPLICIT_TOKEN", "HF_HUB_DISABLE_PROGRESS_BARS", "DO_NOT_TRACK")
    for setting in settings:
        monkeypatch.setenv(setting, "0")
    def constructor(*args, **kwargs):
        calls.append((args, kwargs))
        return object()
    monkeypatch.setitem(sys.modules, "sentence_transformers", SimpleNamespace(SentenceTransformer=constructor))
    cli._offline_model_factory(paths["cache"])("synthetic-model", revision=REVISION, device="cpu")
    assert calls == [(("synthetic-model",), {"revision": REVISION, "device": "cpu", "cache_folder": str(paths["cache"]),
                                           "local_files_only": True, "token": False, "trust_remote_code": False})]
    assert all(cli.os.environ[setting] == "1" for setting in settings)


def test_loaders_reused_and_messages_redirected(paths, capsys, monkeypatch):
    names = ["load_relevance_calibration_dataset", "load_calibration_config", "load_retrieval_corpus",
             "load_vector_index", "load_knowledge_graph", "load_ground_truth_document"]
    seen = []
    for name in names:
        real = getattr(cli, name)
        def loader(path, *, real=real, name=name):
            seen.append(name)
            print("loader message " + name)
            return real(path)
        monkeypatch.setattr(cli, name, loader)
    code, stdout, stderr = _main(paths, capsys)
    assert code == 0 and seen == names
    assert "loader message" in stderr and "loader message" not in stdout


@pytest.mark.parametrize("overwrite", [False, True])
def test_hash_change_after_serialization_preserves_prior_output(paths, capsys, monkeypatch, overwrite):
    if overwrite:
        paths["output"].write_bytes(b"old review report")
    real = cli._serialize
    def serialize(document):
        result = real(document)
        if document.get("schema_version") == "graphrag-relevance-calibration/v1":
            paths["graph"].write_bytes(paths["graph"].read_bytes() + b" ")
        return result
    monkeypatch.setattr(cli, "_serialize", serialize)
    _assert_failure(_main(paths, capsys, overwrite=overwrite))
    assert paths["output"].read_bytes() == b"old review report" if overwrite else not paths["output"].exists()
    assert not list(paths["output"].parent.glob("*.tmp"))


@pytest.mark.parametrize("overwrite", [False, True])
def test_hash_change_after_installed_readback_rolls_back_atomically(paths, capsys, monkeypatch, overwrite):
    if overwrite:
        paths["output"].write_bytes(b"old review report")
    real = cli.load_calibration_report
    def readback(path):
        document = real(path)
        if Path(path) == paths["output"]:
            paths["corpus"].write_bytes(paths["corpus"].read_bytes() + b" ")
        return document
    monkeypatch.setattr(cli, "load_calibration_report", readback)
    _assert_failure(_main(paths, capsys, overwrite=overwrite))
    assert paths["output"].read_bytes() == b"old review report" if overwrite else not paths["output"].exists()
    assert not list(paths["output"].parent.glob("*.tmp"))


@pytest.mark.parametrize("phase", ["temporary", "installed"])
def test_readback_validation_failure_rolls_back_and_cleans(paths, capsys, monkeypatch, phase):
    paths["output"].write_bytes(b"old review report")
    real = cli.load_calibration_report
    def readback(path):
        if (Path(path) == paths["output"]) == (phase == "installed"):
            raise ValueError("synthetic read-back validation failure")
        return real(path)
    monkeypatch.setattr(cli, "load_calibration_report", readback)
    _assert_failure(_main(paths, capsys, overwrite=True))
    assert paths["output"].read_bytes() == b"old review report"
    assert not list(paths["output"].parent.glob("*.tmp"))


def test_concurrent_creation_cannot_be_overwritten(paths, capsys, monkeypatch):
    real = cli.os.link
    def racing_link(source, destination):
        Path(destination).write_bytes(b"other writer")
        return real(source, destination)
    monkeypatch.setattr(cli.os, "link", racing_link)
    _assert_failure(_main(paths, capsys))
    assert paths["output"].read_bytes() == b"other writer"
    assert not list(paths["output"].parent.glob("*.tmp"))


def test_backend_stays_lazy_until_orchestrator_invokes_callback(paths, monkeypatch):
    _change(paths, "config", lambda document: document["retrieval"].__setitem__("chunk_types", []))
    real = cli.build_graphrag_context
    def cached_context(*args, **kwargs):
        kwargs["embed_query"] = lambda texts: [[1.0, 0.0, 0.0] for _ in texts]
        return real(*args, **kwargs)
    monkeypatch.setattr(cli, "build_graphrag_context", cached_context)
    def forbidden(**kwargs):
        pytest.fail("backend must only be created by the embedding callback")
    report = cli.run_calibration(**_kwargs(paths, forbidden))
    assert report["execution"]["embedding_backend_count"] == 0
    assert report["calibration"]["selection_status"] == "no_eligible_policy"


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_process_interrupts_are_not_caught(paths, interruption):
    with pytest.raises(interruption):
        cli.main(_arguments(paths), backend_factory=lambda **kwargs: (_ for _ in ()).throw(interruption()))
    assert not paths["output"].exists()
