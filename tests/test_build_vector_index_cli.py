from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import shutil
import sys
from typing import Any

import pytest

from threat_hunting.retrieval import (
    EmbeddingBackendError,
    VectorIndexValidationError,
    load_retrieval_corpus,
    load_vector_index,
    validate_vector_index,
)


REPOSITORY_ROOT = Path(__file__).parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "build_vector_index.py"
CORPUS_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "retrieval"
    / "builder"
    / "expected_retrieval_corpus.json"
)
PRODUCTION_CONFIG = (
    REPOSITORY_ROOT / "configs" / "retrieval" / "mshta_vector_index.json"
)
REVISION = "b" * 40

SPEC = importlib.util.spec_from_file_location(
    "testable_build_vector_index_cli", SCRIPT_PATH
)
assert SPEC is not None and SPEC.loader is not None
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)


class FakeBackend:
    def __init__(
        self,
        *,
        dimension: int,
        actual_dimension: int | None = None,
        load_error: Exception | None = None,
        embed_error: Exception | None = None,
    ) -> None:
        self.dimension = dimension
        self.actual_dimension = (
            dimension if actual_dimension is None else actual_dimension
        )
        self.load_error = load_error
        self.embed_error = embed_error
        self.load_calls = 0
        self.text_calls: list[list[str]] = []

    def load(self) -> None:
        self.load_calls += 1
        if self.load_error is not None:
            raise self.load_error

    @property
    def embedding_dimension(self) -> int:
        return self.actual_dimension

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        self.text_calls.append(list(texts))
        if self.embed_error is not None:
            raise self.embed_error
        return [
            [float(index + offset + 1) for offset in range(self.dimension)]
            for index, _ in enumerate(texts)
        ]


class RecordingFactory:
    def __init__(
        self,
        *,
        actual_dimension: int | None = None,
        load_error: Exception | None = None,
        embed_error: Exception | None = None,
    ) -> None:
        self.actual_dimension = actual_dimension
        self.load_error = load_error
        self.embed_error = embed_error
        self.calls: list[dict[str, object]] = []
        self.backends: list[FakeBackend] = []

    def __call__(self, **kwargs: object) -> FakeBackend:
        self.calls.append(dict(kwargs))
        backend = FakeBackend(
            dimension=int(kwargs["dimension"]),
            actual_dimension=self.actual_dimension,
            load_error=self.load_error,
            embed_error=self.embed_error,
        )
        self.backends.append(backend)
        return backend


def _sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _portable_expected(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return path.name


def _copy_corpus(tmp_path: Path) -> Path:
    path = tmp_path / "retrieval_corpus.json"
    shutil.copyfile(CORPUS_FIXTURE, path)
    return path


def _config_document(**embedding_updates: object) -> dict[str, object]:
    embedding: dict[str, object] = {
        "provider": "sentence-transformers",
        "model_id": "organization/generic-test-model",
        "model_revision": REVISION,
        "dimension": 3,
        "distance_metric": "cosine",
        "normalization": "l2",
        "document_prefix": "document: ",
        "query_prefix": "query: ",
    }
    embedding.update(embedding_updates)
    return {
        "schema_version": "vector-index-build-config/v1",
        "embedding": embedding,
        "runtime": {
            "device": "cpu",
            "batch_size": 4,
            "show_progress_bar": False,
        },
    }


def _write_config(
    tmp_path: Path, **embedding_updates: object
) -> Path:
    path = tmp_path / "vector_config.json"
    path.write_text(
        json.dumps(_config_document(**embedding_updates), ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def _arguments(
    corpus_path: Path,
    config_path: Path,
    output_path: Path,
    *,
    expected_hash: str | None = None,
    overwrite: bool = False,
) -> list[str]:
    result = [
        "--corpus",
        str(corpus_path),
        "--config",
        str(config_path),
        "--output",
        str(output_path),
        "--expected-corpus-sha256",
        expected_hash or _sha256(corpus_path),
    ]
    if overwrite:
        result.append("--overwrite")
    return result


def _run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    corpus_path: Path,
    config_path: Path,
    output_path: Path,
    *,
    factory: RecordingFactory | None = None,
    expected_hash: str | None = None,
    overwrite: bool = False,
) -> tuple[int, str, str, RecordingFactory]:
    selected_factory = factory or RecordingFactory()
    monkeypatch.setattr(
        cli, "_sentence_transformers_version", lambda: "6.1.0"
    )
    result = cli.main(
        _arguments(
            corpus_path,
            config_path,
            output_path,
            expected_hash=expected_hash,
            overwrite=overwrite,
        ),
        backend_factory=selected_factory,
    )
    captured = capsys.readouterr()
    return result, captured.out, captured.err, selected_factory


def _successful_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[Path, Path, Path, dict[str, Any], RecordingFactory]:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    output_path = tmp_path / "vector_index.json"
    code, stdout, stderr, factory = _run(
        monkeypatch, capsys, corpus_path, config_path, output_path
    )
    assert code == 0, stderr
    assert stderr == ""
    stats = json.loads(stdout)
    assert isinstance(stats, dict)
    return corpus_path, config_path, output_path, stats, factory


def test_cli_happy_path_builds_valid_index_and_complete_stats(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path, _, output_path, stats, factory = _successful_build(
        tmp_path, monkeypatch, capsys
    )
    document = load_vector_index(output_path)
    validate_vector_index(document)

    assert stats == {
        "corpus_id": document["corpus_provenance"]["corpus_id"],
        "index_id": document["index_id"],
        "input_path": _portable_expected(corpus_path),
        "input_sha256": _sha256(corpus_path),
        "model_id": "organization/generic-test-model",
        "model_revision": REVISION,
        "output_path": _portable_expected(output_path),
        "output_sha256": _sha256(output_path),
        "provider": "sentence-transformers",
        "record_count": 15,
        "review_status": "pending_human_review",
        "scenario_id": "scenario-synthetic-builder",
        "schema_version": "vector-index/v1",
        "sentence_transformers_version": "6.1.0",
        "vector_dimension": 3,
    }
    assert factory.calls == [
        {
            "model_id": "organization/generic-test-model",
            "model_revision": REVISION,
            "dimension": 3,
            "device": "cpu",
            "batch_size": 4,
            "show_progress_bar": False,
        }
    ]
    assert factory.backends[0].load_calls == 1
    assert len(factory.backends[0].text_calls[0]) == 15


def test_cli_does_not_mutate_retrieval_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    original = corpus_path.read_bytes()
    config_path = _write_config(tmp_path)

    code, _, stderr, _ = _run(
        monkeypatch,
        capsys,
        corpus_path,
        config_path,
        tmp_path / "vector_index.json",
    )

    assert code == 0, stderr
    assert corpus_path.read_bytes() == original


@pytest.mark.parametrize("target", ["corpus", "config"])
def test_cli_rejects_malformed_json_without_partial_stdout(
    target: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    selected = corpus_path if target == "corpus" else config_path
    selected.write_text('{"schema_version":', encoding="utf-8")
    output_path = tmp_path / "vector_index.json"

    code, stdout, stderr, factory = _run(
        monkeypatch, capsys, corpus_path, config_path, output_path
    )

    assert code == 2
    assert stdout == ""
    assert "error:" in stderr
    assert not output_path.exists()
    assert factory.calls == []


@pytest.mark.parametrize("target", ["corpus", "config"])
def test_cli_rejects_duplicate_json_keys_without_output(
    target: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    selected = corpus_path if target == "corpus" else config_path
    text = selected.read_text(encoding="utf-8")
    text = text.replace(
        '"schema_version":',
        '"schema_version": "duplicate", "schema_version":',
        1,
    )
    selected.write_text(text, encoding="utf-8")
    output_path = tmp_path / "vector_index.json"

    code, stdout, stderr, factory = _run(
        monkeypatch, capsys, corpus_path, config_path, output_path
    )

    assert code == 2
    assert stdout == ""
    assert "duplicate JSON object key" in stderr
    assert not output_path.exists()
    assert factory.calls == []


def test_cli_rejects_corpus_hash_mismatch_before_model_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    output_path = tmp_path / "vector_index.json"

    code, stdout, stderr, factory = _run(
        monkeypatch,
        capsys,
        corpus_path,
        config_path,
        output_path,
        expected_hash="0" * 64,
    )

    assert code == 2
    assert stdout == ""
    assert "before model loading" in stderr
    assert not output_path.exists()
    assert factory.calls == []


def test_cli_detects_hash_change_after_write_and_removes_new_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    output_path = tmp_path / "vector_index.json"
    real_hash = _sha256(corpus_path)
    hashes = iter((real_hash, real_hash, "0" * 64))
    monkeypatch.setattr(cli, "_sha256_file", lambda path: next(hashes))

    code, stdout, stderr, _ = _run(
        monkeypatch, capsys, corpus_path, config_path, output_path
    )

    assert code == 2
    assert stdout == ""
    assert "after write" in stderr
    assert not output_path.exists()
    assert list(tmp_path.glob(".*.tmp")) == []


@pytest.mark.parametrize("revision", [None, "main", "latest", "a" * 39])
def test_cli_rejects_missing_or_floating_model_revision(
    revision: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config = _config_document()
    embedding = config["embedding"]
    assert isinstance(embedding, dict)
    if revision is None:
        del embedding["model_revision"]
    else:
        embedding["model_revision"] = revision
    config_path = tmp_path / "vector_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    code, stdout, stderr, factory = _run(
        monkeypatch,
        capsys,
        corpus_path,
        config_path,
        tmp_path / "vector_index.json",
    )

    assert code == 2
    assert stdout == ""
    assert "model_revision" in stderr
    assert factory.calls == []


def test_cli_rejects_model_dimension_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    output_path = tmp_path / "vector_index.json"

    code, stdout, stderr, _ = _run(
        monkeypatch,
        capsys,
        corpus_path,
        config_path,
        output_path,
        factory=RecordingFactory(actual_dimension=4),
    )

    assert code == 2
    assert stdout == ""
    assert "dimension mismatch" in stderr
    assert not output_path.exists()


@pytest.mark.parametrize("phase", ["load", "embed"])
def test_cli_reports_backend_error_without_output_or_partial_json(
    phase: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    output_path = tmp_path / "vector_index.json"
    error = EmbeddingBackendError(f"synthetic {phase} failure")
    factory = RecordingFactory(
        load_error=error if phase == "load" else None,
        embed_error=error if phase == "embed" else None,
    )

    code, stdout, stderr, _ = _run(
        monkeypatch,
        capsys,
        corpus_path,
        config_path,
        output_path,
        factory=factory,
    )

    assert code == 2
    assert stdout == ""
    assert f"synthetic {phase} failure" in stderr
    assert not output_path.exists()


def test_cli_refuses_existing_output_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    output_path = tmp_path / "vector_index.json"
    original = b"existing-output-must-survive"
    output_path.write_bytes(original)

    code, stdout, stderr, factory = _run(
        monkeypatch, capsys, corpus_path, config_path, output_path
    )

    assert code == 2
    assert stdout == ""
    assert "--overwrite" in stderr
    assert output_path.read_bytes() == original
    assert factory.calls == []


def test_cli_overwrite_is_atomic_and_leaves_no_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    output_path = tmp_path / "vector_index.json"
    output_path.write_bytes(b"old")

    code, _, stderr, _ = _run(
        monkeypatch,
        capsys,
        corpus_path,
        config_path,
        output_path,
        overwrite=True,
    )

    assert code == 0, stderr
    validate_vector_index(load_vector_index(output_path))
    assert output_path.read_bytes() != b"old"
    assert list(tmp_path.glob(".*.tmp")) == []


def test_post_write_validation_failure_restores_previous_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    output_path = tmp_path / "vector_index.json"
    original = b"valid-prior-output-placeholder"
    output_path.write_bytes(original)
    real_loader = cli.load_vector_index
    calls = 0

    def fail_final_readback(path: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise VectorIndexValidationError("synthetic read-back failure")
        return real_loader(path)

    monkeypatch.setattr(cli, "load_vector_index", fail_final_readback)

    code, stdout, stderr, _ = _run(
        monkeypatch,
        capsys,
        corpus_path,
        config_path,
        output_path,
        overwrite=True,
    )

    assert code == 2
    assert stdout == ""
    assert "synthetic read-back failure" in stderr
    assert output_path.read_bytes() == original
    assert list(tmp_path.glob(".*.tmp")) == []


def test_two_overwrite_runs_are_byte_for_byte_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    config_path = _write_config(tmp_path)
    output_path = tmp_path / "vector_index.json"

    first_code, first_stdout, first_stderr, _ = _run(
        monkeypatch, capsys, corpus_path, config_path, output_path
    )
    first_bytes = output_path.read_bytes()
    second_code, second_stdout, second_stderr, _ = _run(
        monkeypatch,
        capsys,
        corpus_path,
        config_path,
        output_path,
        overwrite=True,
    )

    assert first_code == second_code == 0
    assert first_stderr == second_stderr == ""
    assert output_path.read_bytes() == first_bytes
    assert json.loads(first_stdout)["index_id"] == json.loads(second_stdout)[
        "index_id"
    ]


def test_production_config_is_strict_pinned_cpu_l2_and_has_no_answers() -> None:
    document = cli.load_build_config(PRODUCTION_CONFIG)

    assert document == {
        "schema_version": "vector-index-build-config/v1",
        "embedding": {
            "provider": "sentence-transformers",
            "model_id": "sentence-transformers/all-MiniLM-L6-v2",
            "model_revision": "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
            "dimension": 384,
            "distance_metric": "cosine",
            "normalization": "l2",
            "document_prefix": "",
            "query_prefix": "",
        },
        "runtime": {
            "device": "cpu",
            "batch_size": 32,
            "show_progress_bar": False,
        },
    }
    lowered = PRODUCTION_CONFIG.read_text(encoding="utf-8").casefold()
    for forbidden in ("credential", "token", "question", "expected_answer"):
        assert forbidden not in lowered


def test_cli_source_has_no_production_scenario_or_path_hardcodes() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "mshta-powershell",
        "retrieval_corpus.json",
        "outputs/retrieval",
        "all-minilm-l6-v2",
    ):
        assert forbidden not in source


def test_input_loader_still_accepts_unchanged_fixture() -> None:
    before = CORPUS_FIXTURE.read_bytes()
    corpus = load_retrieval_corpus(CORPUS_FIXTURE)

    assert corpus["metadata"]["chunk_count"] == 15
    assert CORPUS_FIXTURE.read_bytes() == before
