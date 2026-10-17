"""Offline evaluation CLI preflight, synthetic backends and atomic output."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from test_embedding_retrieval_runner import (
    SOURCE_CORPUS_PATH,
    SOURCE_DATASET_PATH,
    SOURCE_JUDGMENTS_PATH,
    _bytes,
    _candidate_documents,
    _refresh,
    _synthetic_inputs,
)
from threat_hunting.evaluation import validate_embedding_retrieval_comparison_report


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/compare_embedding_retrieval_models.py"
SPEC = importlib.util.spec_from_file_location("testable_embedding_retrieval_models_cli", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)
REAL_SNAPSHOT_RESOLVER = cli._resolve_offline_snapshot

SUMMARY_FIELDS = {
    "output_path", "output_sha256", "evaluation_id", "baseline_candidate_id",
    "candidate_ids", "case_count", "ranking_limit", "pareto_result", "review_status",
}
INPUT_PATHS = (
    SOURCE_DATASET_PATH, SOURCE_JUDGMENTS_PATH, SOURCE_CORPUS_PATH,
    "fixtures/baseline_build_config.json", "fixtures/baseline_vector_index.json",
    "fixtures/candidate_build_config.json", "fixtures/candidate_vector_index.json",
)


class _Backend(SimpleNamespace):
    def __call__(self, texts):
        return self.embed_documents(texts)


class Factory:
    """Record reuse and errors without importing or executing an embedding model."""

    def __init__(self, *, init_error=None, embed_error=None, on_embed=None, noisy=False,
                 vector=None):
        self.calls: list[dict[str, Any]] = []
        self.backends: list[SimpleNamespace] = []
        self.init_error = init_error
        self.embed_error = embed_error
        self.on_embed = on_embed
        self.noisy = noisy
        self.vector = vector

    def __call__(self, **settings):
        self.calls.append(dict(settings))
        if self.noisy:
            print("synthetic initialization stdout")
            print("synthetic initialization stderr", file=sys.stderr)
        if self.init_error is not None:
            raise self.init_error
        batches: list[list[str]] = []

        def embed_documents(texts):
            batches.append(list(texts))
            if self.noisy:
                print("synthetic embedding stdout")
                print("synthetic embedding stderr", file=sys.stderr)
            if self.on_embed is not None:
                self.on_embed()
            if self.embed_error is not None:
                raise self.embed_error
            vector = self.vector
            if vector is None:
                vector = [3.0, 4.0, *([0.0] * (settings["dimension"] - 2))]
            return [deepcopy(vector) for _ in texts]

        backend = _Backend(embed_documents=embed_documents, batches=batches)
        self.backends.append(backend)
        return backend


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    root.mkdir()
    cache = tmp_path / "external_model_cache"
    cache.mkdir()
    config, documents, source_bytes = _synthetic_inputs()
    for relative, payload in source_bytes.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    config_path = root / "configs/evaluation/synthetic_run.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_bytes(_bytes(config))
    output = root / "outputs/evaluation/synthetic_comparison.json"
    monkeypatch.setattr(cli, "REPOSITORY_ROOT", root)
    snapshot_calls = []

    def snapshot(embedding):
        snapshot_calls.append(deepcopy(embedding))
        return cache

    monkeypatch.setattr(cli, "_resolve_offline_snapshot", snapshot)
    return SimpleNamespace(
        root=root, cache=cache, config=config, documents=documents,
        source_bytes=source_bytes, config_path=config_path, output=output,
        snapshot_calls=snapshot_calls,
    )


def _save(workspace):
    for relative, payload in workspace.source_bytes.items():
        (workspace.root / relative).write_bytes(payload)
    workspace.config_path.write_bytes(_bytes(workspace.config))


def _args(workspace, *, overwrite=False, offline=True):
    args = ["--config", str(workspace.config_path), "--output", str(workspace.output)]
    if offline:
        args.append("--offline")
    if overwrite:
        args.append("--overwrite")
    return args


def _files(workspace):
    return {
        p.relative_to(workspace.root).as_posix(): p.read_bytes()
        for p in workspace.root.rglob("*") if p.is_file()
    }


def _assert_no_temporary_files(workspace):
    allowed = {workspace.config_path, *(workspace.root / p for p in INPUT_PATHS)}
    if workspace.output.exists():
        allowed.add(workspace.output)
    actual = {p for p in workspace.root.rglob("*") if p.is_file()}
    assert actual == allowed


def _failure(workspace, capsys, factory, *, overwrite=False):
    assert cli.main(_args(workspace, overwrite=overwrite), backend_factory=factory) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error:")
    assert captured.err.endswith("\n")
    _assert_no_temporary_files(workspace)
    return captured.err


def _bind_file_pin(config, relative, payload):
    digest = sha256(payload).hexdigest()
    for source in config["sources"].values():
        if source["path"] == relative:
            source["sha256"] = digest
    for candidate in config["candidates"]:
        for path_field, hash_field in (
            ("build_config_path", "build_config_sha256"),
            ("vector_index_path", "vector_index_sha256"),
        ):
            if candidate[path_field] == relative:
                candidate[hash_field] = digest


def test_success_compact_summary_two_backends_and_query_prefix_once(workspace, capsys):
    factory = Factory()
    before = _files(workspace)
    assert cli.main(_args(workspace), backend_factory=factory) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.endswith("\n") and captured.out.count("\n") == 1
    summary = json.loads(captured.out)
    assert set(summary) == SUMMARY_FIELDS
    assert captured.out.strip() == json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
    assert summary["candidate_ids"] == ["baseline", "candidate"]
    assert summary["baseline_candidate_id"] == "baseline"
    assert summary["case_count"] == 8 and summary["ranking_limit"] == 10
    assert summary["review_status"] == "pending_human_review"
    assert summary["output_sha256"] == sha256(workspace.output.read_bytes()).hexdigest()
    report = json.loads(workspace.output.read_text(encoding="utf-8"))
    validate_embedding_retrieval_comparison_report(report)
    assert summary["evaluation_id"] == report["evaluation_id"]
    assert summary["pareto_result"] == {
        row["candidate_id"]: row["pareto"]["result"] for row in report["comparisons"]
    }
    assert report["metadata"]["ranking_count"] == 16
    assert len(factory.calls) == len(factory.backends) == 2
    assert len(workspace.snapshot_calls) == 2
    queries = [case["query"] for case in workspace.documents[SOURCE_DATASET_PATH]["cases"]]
    for settings, backend, candidate in zip(factory.calls, factory.backends, workspace.config["candidates"]):
        descriptor = _candidate_documents(workspace.config, workspace.documents, candidate["candidate_id"])[0]["embedding"]
        assert settings["model_id"] == descriptor["model_id"]
        assert settings["model_revision"] == descriptor["model_revision"]
        assert settings["dimension"] == descriptor["dimension"]
        assert settings["device"] == "cpu" and settings["batch_size"] == 1
        assert settings["show_progress_bar"] is False
        assert callable(settings["model_factory"])
        assert len(backend.batches) == 8 and all(len(batch) == 1 for batch in backend.batches)
        assert Counter(batch[0] for batch in backend.batches) == Counter(descriptor["query_prefix"] + query for query in queries)
    for relative, payload in before.items():
        assert (workspace.root / relative).read_bytes() == payload
    _assert_no_temporary_files(workspace)


def test_noisy_third_party_output_is_captured(workspace, capsys):
    assert cli.main(_args(workspace), backend_factory=Factory(noisy=True)) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and captured.out.count("\n") == 1
    assert set(json.loads(captured.out)) == SUMMARY_FIELDS
    assert "synthetic initialization" not in captured.out
    assert "synthetic embedding" not in captured.out


def test_run_api_returns_only_detached_summary_and_repeated_bytes(workspace):
    factory = Factory()
    first = cli.run_comparison_cli(
        config_path=workspace.config_path, output_path=workspace.output,
        offline=True, overwrite=False, backend_factory=factory,
    )
    payload = workspace.output.read_bytes()
    second = cli.run_comparison_cli(
        config_path=workspace.config_path, output_path=workspace.output,
        offline=True, overwrite=True, backend_factory=factory,
    )
    assert first == second and workspace.output.read_bytes() == payload
    first["candidate_ids"].clear()
    assert second["candidate_ids"] == ["baseline", "candidate"]
    assert len(factory.calls) == 4
    _assert_no_temporary_files(workspace)


@pytest.mark.parametrize("relative", INPUT_PATHS)
def test_every_input_hash_mismatch_fails_before_backend_creation(workspace, capsys, relative):
    path = workspace.root / relative
    path.write_bytes(path.read_bytes() + b" ")
    factory = Factory()
    _failure(workspace, capsys, factory)
    assert factory.calls == [] and not workspace.output.exists()


@pytest.mark.parametrize("relative", INPUT_PATHS)
@pytest.mark.parametrize("payload", [b'{"same":1,"same":2}', b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}', b'\xff'])
def test_all_json_inputs_are_loaded_strictly_before_backend(workspace, capsys, relative, payload):
    (workspace.root / relative).write_bytes(payload)
    _bind_file_pin(workspace.config, relative, payload)
    workspace.config_path.write_bytes(_bytes(workspace.config))
    factory = Factory()
    _failure(workspace, capsys, factory)
    assert factory.calls == [] and not workspace.output.exists()


@pytest.mark.parametrize("payload", [b'{"same":1,"same":2}', b'{"ranking_limit":NaN}', b'{"ranking_limit":Infinity}', b'\xff'])
def test_run_config_strict_json_failure_precedes_backend(workspace, capsys, payload):
    workspace.config_path.write_bytes(payload)
    factory = Factory()
    _failure(workspace, capsys, factory)
    assert factory.calls == []


def test_descriptor_mismatch_precedes_backend(workspace, capsys):
    _, index = _candidate_documents(workspace.config, workspace.documents)
    index["embedding"]["query_prefix"] = "incorrect: "
    _refresh(workspace.config, workspace.documents, workspace.source_bytes)
    _save(workspace)
    factory = Factory()
    _failure(workspace, capsys, factory)
    assert factory.calls == []


def test_all_offline_snapshots_are_preflighted_before_any_backend(workspace, capsys, monkeypatch):
    calls = []

    def snapshot(embedding):
        calls.append(embedding["model_id"])
        if len(calls) == 2:
            raise ValueError("missing offline snapshot for synthetic candidate")
        return workspace.cache

    monkeypatch.setattr(cli, "_resolve_offline_snapshot", snapshot)
    factory = Factory()
    _failure(workspace, capsys, factory)
    assert len(calls) == 2 and factory.calls == []


def test_existing_output_without_overwrite_is_preserved_before_backend(workspace, capsys):
    workspace.output.parent.mkdir(parents=True)
    workspace.output.write_bytes(b"previous reviewed output\n")
    factory = Factory()
    _failure(workspace, capsys, factory)
    assert workspace.output.read_bytes() == b"previous reviewed output\n"
    assert factory.calls == []


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("phase", ["construction", "embedding"])
def test_backend_failures_keep_old_output_and_no_partial_report(workspace, capsys, existing, phase):
    if existing:
        workspace.output.parent.mkdir(parents=True)
        workspace.output.write_bytes(b"original output\n")
    factory = Factory(**{("init_error" if phase == "construction" else "embed_error"): RuntimeError("synthetic model error")}, noisy=True)
    _failure(workspace, capsys, factory, overwrite=existing)
    assert workspace.output.read_bytes() == b"original output\n" if existing else not workspace.output.exists()


@pytest.mark.parametrize("vector", [[float("nan")] * 6, [float("inf")] * 6, [1.0], [0.0] * 6])
def test_invalid_query_vectors_do_not_publish_report(workspace, capsys, vector):
    _failure(workspace, capsys, Factory(vector=vector))
    assert not workspace.output.exists()


@pytest.mark.parametrize("stage", ["retrieval", "serialization", "after_write"])
@pytest.mark.parametrize("existing", [False, True])
def test_hash_change_at_each_required_checkpoint_rolls_back(workspace, capsys, monkeypatch, stage, existing):
    old = b"old stable output\n"
    if existing:
        workspace.output.parent.mkdir(parents=True)
        workspace.output.write_bytes(old)
    source = workspace.root / SOURCE_DATASET_PATH
    changed = False

    def mutate_once():
        nonlocal changed
        if not changed:
            source.write_bytes(source.read_bytes() + b" ")
            changed = True

    factory = Factory(on_embed=mutate_once if stage == "retrieval" else None)
    if stage == "serialization":
        original = cli._serialize_report

        def serialize(report):
            payload = original(report)
            mutate_once()
            return payload

        monkeypatch.setattr(cli, "_serialize_report", serialize)
    if stage == "after_write":
        original = cli._assert_input_hashes

        def check(expected):
            if workspace.output.exists() and workspace.output.read_bytes() != old:
                mutate_once()
            return original(expected)

        monkeypatch.setattr(cli, "_assert_input_hashes", check)
    _failure(workspace, capsys, factory, overwrite=existing)
    assert changed
    assert workspace.output.read_bytes() == old if existing else not workspace.output.exists()


@pytest.mark.parametrize("existing", [False, True])
def test_invalid_serialized_readback_rolls_back_output(workspace, capsys, monkeypatch, existing):
    old = b"earlier output bytes\n"
    if existing:
        workspace.output.parent.mkdir(parents=True)
        workspace.output.write_bytes(old)
    monkeypatch.setattr(cli, "_serialize_report", lambda report: b"{}")
    _failure(workspace, capsys, Factory(), overwrite=existing)
    assert workspace.output.read_bytes() == old if existing else not workspace.output.exists()


def test_atomic_replace_failure_preserves_old_output(workspace, capsys, monkeypatch):
    workspace.output.parent.mkdir(parents=True)
    old = b"output before replacement\n"
    workspace.output.write_bytes(old)
    replace = cli.os.replace
    calls = []

    def fail_once(source, destination):
        calls.append((Path(source), Path(destination)))
        assert Path(source).parent == Path(destination).parent
        if len(calls) == 1:
            raise OSError("synthetic atomic replacement failure")
        return replace(source, destination)

    monkeypatch.setattr(cli.os, "replace", fail_once)
    _failure(workspace, capsys, Factory(), overwrite=True)
    assert calls and workspace.output.read_bytes() == old


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(7)])
@pytest.mark.parametrize("phase", ["construction", "embedding"])
def test_control_flow_interrupts_are_not_wrapped(workspace, error, phase):
    factory = Factory(**{("init_error" if phase == "construction" else "embed_error"): error})
    with pytest.raises(type(error)):
        cli.main(_args(workspace), backend_factory=factory)
    assert not workspace.output.exists()
    _assert_no_temporary_files(workspace)


@pytest.mark.parametrize("kind", ["input", "outside_repository"])
def test_unsafe_output_target_is_rejected_before_backend(workspace, capsys, kind):
    workspace.output = workspace.root / SOURCE_DATASET_PATH if kind == "input" else workspace.root.parent / "outside_report.json"
    factory = Factory()
    before = {p: (workspace.root / p).read_bytes() for p in INPUT_PATHS}
    assert cli.main(_args(workspace, overwrite=True), backend_factory=factory) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err.startswith("error:")
    assert factory.calls == []
    assert all((workspace.root / p).read_bytes() == payload for p, payload in before.items())


def _cached_snapshot(workspace, monkeypatch):
    for key in ("HF_HUB_CACHE", "HUGGINGFACE_HUB_CACHE", "HF_HOME", "XDG_CACHE_HOME"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HF_HUB_CACHE", str(workspace.cache))
    descriptor = workspace.documents["fixtures/baseline_build_config.json"]["embedding"]
    snapshot = workspace.cache / ("models--" + descriptor["model_id"].replace("/", "--")) / "snapshots" / descriptor["model_revision"]
    snapshot.mkdir(parents=True)
    for name in ("config.json", "tokenizer.json", "tokenizer_config.json"):
        (snapshot / name).write_bytes(b"{}")
    (snapshot / "model.safetensors").write_bytes(b"synthetic weights; never loaded")
    modules = [
        {"idx": 0, "name": "0", "path": "", "type": "sentence_transformers.models.Transformer"},
        {"idx": 1, "name": "1", "path": "1_Pooling", "type": "sentence_transformers.models.Pooling"},
        {"idx": 2, "name": "2", "path": "2_Normalize", "type": "sentence_transformers.models.Normalize"},
    ]
    (snapshot / "modules.json").write_bytes(_bytes(modules))
    (snapshot / "1_Pooling").mkdir()
    (snapshot / "1_Pooling/config.json").write_bytes(b"{}")
    return descriptor, snapshot, modules


def test_real_resolver_requires_exact_revision_in_external_cache(workspace, monkeypatch):
    descriptor, snapshot, _ = _cached_snapshot(workspace, monkeypatch)
    assert not (snapshot / "2_Normalize").exists()
    assert REAL_SNAPSHOT_RESOLVER(descriptor) == snapshot
    wrong = {**descriptor, "model_revision": "f" * 40}
    with pytest.raises(cli.EmbeddingRetrievalCliError, match="missing offline snapshot"):
        REAL_SNAPSHOT_RESOLVER(wrong)
    monkeypatch.setenv("HF_HUB_CACHE", str(workspace.root / "model_cache"))
    with pytest.raises(cli.EmbeddingRetrievalCliError, match="outside the repository"):
        REAL_SNAPSHOT_RESOLVER(descriptor)


@pytest.mark.parametrize("mutation", ["weights", "pooling", "duplicate", "nonfinite", "trailing", "remote_module", "unsafe_module_path"])
def test_real_resolver_rejects_incomplete_or_unsafe_cache(workspace, monkeypatch, mutation):
    descriptor, snapshot, modules = _cached_snapshot(workspace, monkeypatch)
    if mutation == "weights":
        (snapshot / "model.safetensors").unlink()
    elif mutation == "pooling":
        (snapshot / "1_Pooling/config.json").unlink()
    elif mutation == "duplicate":
        (snapshot / "modules.json").write_bytes(b'[{"type":"one","type":"two"}]')
    elif mutation == "nonfinite":
        (snapshot / "modules.json").write_bytes(b'[{"idx":NaN}]')
    elif mutation == "trailing":
        (snapshot / "modules.json").write_bytes(_bytes(modules) + b',"extra":1')
    else:
        modules[0]["type" if mutation == "remote_module" else "path"] = "remote.module" if mutation == "remote_module" else "../escape"
        (snapshot / "modules.json").write_bytes(_bytes(modules))
    with pytest.raises(ValueError):
        REAL_SNAPSHOT_RESOLVER(descriptor)


def test_pooling_config_cannot_resolve_outside_cache(workspace, monkeypatch):
    descriptor, snapshot, _ = _cached_snapshot(workspace, monkeypatch)
    outside = workspace.root.parent / "escaped_config.json"
    outside.write_bytes(b"{}")
    resolve = Path.resolve

    def redirected(path, *args, **kwargs):
        if path == snapshot / "1_Pooling/config.json":
            return outside
        return resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", redirected)
    with pytest.raises(cli.EmbeddingRetrievalCliError, match="escapes"):
        REAL_SNAPSHOT_RESOLVER(descriptor)


def test_default_factory_uses_only_local_cpu_snapshot_without_token(workspace, monkeypatch):
    descriptor, snapshot, _ = _cached_snapshot(workspace, monkeypatch)
    torch_calls = []
    model_calls = []
    sentinel = object()

    def constructor(*args, **kwargs):
        model_calls.append((args, kwargs))
        return sentinel

    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(
        set_num_threads=lambda count: torch_calls.append(("threads", count)),
        use_deterministic_algorithms=lambda value: torch_calls.append(("deterministic", value)),
    ))
    monkeypatch.setitem(sys.modules, "sentence_transformers", SimpleNamespace(SentenceTransformer=constructor))
    monkeypatch.setenv("HF_HUB_OFFLINE", "previous")
    with cli._offline_environment():
        assert all(cli.os.environ[key] == value for key, value in cli._OFFLINE_ENV.items())
        result = cli._offline_model_factory(snapshot)(
            descriptor["model_id"], revision=descriptor["model_revision"], device="cpu",
        )
    assert cli.os.environ["HF_HUB_OFFLINE"] == "previous"
    assert result is sentinel
    assert torch_calls == [("threads", 1), ("deterministic", True)]
    assert model_calls == [((str(snapshot),), {
        "revision": descriptor["model_revision"], "device": "cpu",
        "cache_folder": str(snapshot.parents[2]), "local_files_only": True,
        "trust_remote_code": False, "token": False,
    })]


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("failure", ["persistent_read_error", "corruption", "interrupt", "system_exit"])
def test_readback_failures_restore_output_without_reading_failed_file(workspace, monkeypatch, existing, failure):
    old = b"old exact output bytes\r\n"
    workspace.output.parent.mkdir(parents=True)
    if existing:
        workspace.output.write_bytes(old)
    read_bytes = Path.read_bytes
    blocked = False

    def read(path):
        if blocked and path == workspace.output:
            raise OSError("persistent read failure after publication")
        return read_bytes(path)

    def fail_readback(path, payload):
        nonlocal blocked
        if failure == "persistent_read_error":
            blocked = True
            path.read_bytes()
        elif failure == "corruption":
            path.write_bytes(b"corrupted installed report")
            raise ValueError("read-back mismatch")
        elif failure == "interrupt":
            raise KeyboardInterrupt()
        else:
            raise SystemExit(7)

    monkeypatch.setattr(Path, "read_bytes", read)
    monkeypatch.setattr(cli, "_read_back_report", fail_readback)
    expected = KeyboardInterrupt if failure == "interrupt" else SystemExit if failure == "system_exit" else cli.EmbeddingRetrievalCliError
    with pytest.raises(expected):
        cli.run_comparison_cli(config_path=workspace.config_path, output_path=workspace.output,
                               offline=True, overwrite=existing, backend_factory=Factory())
    blocked = False
    assert workspace.output.read_bytes() == old if existing else not workspace.output.exists()
    _assert_no_temporary_files(workspace)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_interrupt_after_write_hash_check_restores_old_output(workspace, monkeypatch, existing, error):
    old = b"previous report"
    workspace.output.parent.mkdir(parents=True)
    if existing:
        workspace.output.write_bytes(old)
    check = cli._assert_input_hashes

    def interrupt(expected):
        if workspace.output.exists() and workspace.output.read_bytes() != old:
            raise error()
        check(expected)

    monkeypatch.setattr(cli, "_assert_input_hashes", interrupt)
    with pytest.raises(error):
        cli.main(_args(workspace, overwrite=existing), backend_factory=Factory())
    assert workspace.output.read_bytes() == old if existing else not workspace.output.exists()
    _assert_no_temporary_files(workspace)


def test_no_overwrite_race_preserves_competing_writer(workspace, capsys, monkeypatch):
    link = cli.os.link
    concurrent = b"concurrent report bytes"

    def compete(source, destination):
        Path(destination).write_bytes(concurrent)
        link(source, destination)

    monkeypatch.setattr(cli.os, "link", compete)
    assert cli.main(_args(workspace), backend_factory=Factory()) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err.startswith("error:")
    assert workspace.output.read_bytes() == concurrent
    _assert_no_temporary_files(workspace)


def test_symlink_output_is_rejected_before_backend(workspace, capsys, monkeypatch):
    is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == workspace.output or is_symlink(path))
    factory = Factory()
    _failure(workspace, capsys, factory)
    assert factory.calls == []
