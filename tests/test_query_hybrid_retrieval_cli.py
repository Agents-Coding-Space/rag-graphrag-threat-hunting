"""Production hybrid query CLI contracts using fake local embeddings only."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import pytest

from threat_hunting.retrieval import (
    HybridRetrievalError,
    load_retrieval_corpus,
    load_vector_index,
    retrieve_hybrid,
)


REPOSITORY_ROOT = Path(__file__).parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "query_hybrid_retrieval.py"
FIXTURES = Path(__file__).parent / "fixtures" / "retrieval"
CORPUS_FIXTURE = FIXTURES / "builder" / "expected_retrieval_corpus.json"
INDEX_FIXTURE = FIXTURES / "vector_builder" / "expected_vector_index.json"
REVISION = "a" * 40

SPEC = importlib.util.spec_from_file_location(
    "testable_query_hybrid_retrieval_cli", SCRIPT_PATH
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
        vectors: object | None = None,
        inference_error: Exception | None = None,
        on_embed: Callable[[], None] | None = None,
        noisy: bool = False,
    ) -> None:
        self.dimension = dimension
        self.vectors = vectors
        self.inference_error = inference_error
        self.on_embed = on_embed
        self.noisy = noisy
        self.calls: list[list[str]] = []

    def embed_documents(self, texts: list[str]) -> object:
        self.calls.append(list(texts))
        if self.noisy:
            print("synthetic inference message")
        if self.on_embed is not None:
            self.on_embed()
        if self.inference_error is not None:
            raise self.inference_error
        if self.vectors is not None:
            return self.vectors
        return [[1.0, *([0.0] * (self.dimension - 1))]]


class RecordingFactory:
    def __init__(
        self,
        *,
        vectors: object | None = None,
        initialization_error: Exception | None = None,
        inference_error: Exception | None = None,
        on_embed: Callable[[], None] | None = None,
        noisy: bool = False,
    ) -> None:
        self.vectors = vectors
        self.initialization_error = initialization_error
        self.inference_error = inference_error
        self.on_embed = on_embed
        self.noisy = noisy
        self.calls: list[dict[str, object]] = []
        self.backends: list[FakeBackend] = []

    def __call__(self, **kwargs: Any) -> FakeBackend:
        self.calls.append(dict(kwargs))
        if self.noisy:
            print("synthetic initialization message")
        if self.initialization_error is not None:
            raise self.initialization_error
        backend = FakeBackend(
            dimension=kwargs["dimension"],
            vectors=self.vectors,
            inference_error=self.inference_error,
            on_embed=self.on_embed,
            noisy=self.noisy,
        )
        self.backends.append(backend)
        return backend


def _hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def paths(tmp_path: Path) -> tuple[Path, Path]:
    corpus_path = tmp_path / "retrieval_corpus.json"
    index_path = tmp_path / "vector_index.json"
    shutil.copyfile(CORPUS_FIXTURE, corpus_path)
    index = load_vector_index(INDEX_FIXTURE)
    index["corpus_provenance"]["sha256"] = _hash(corpus_path)
    index["embedding"]["provider"] = "sentence-transformers"
    index["embedding"]["model_revision"] = REVISION
    index_path.write_text(json.dumps(index, ensure_ascii=False), encoding="utf-8")
    return corpus_path, index_path


def _query(
    paths: tuple[Path, Path],
    *,
    factory: object | None = None,
    **updates: Any,
) -> dict[str, Any]:
    corpus_path, index_path = paths
    kwargs: dict[str, Any] = {
        "corpus_path": corpus_path,
        "vector_index_path": index_path,
        "query": "Thực thể synthetic nào cần xem xét?",
        "top_k": 5,
        "candidate_k": 20,
        "chunk_types": None,
        "required_dimensions": None,
        "expected_corpus_sha256": (
            updates["expected_corpus_sha256"]
            if "expected_corpus_sha256" in updates else _hash(corpus_path)
        ),
        "expected_index_sha256": (
            updates["expected_index_sha256"]
            if "expected_index_sha256" in updates else _hash(index_path)
        ),
        "backend_factory": factory if factory is not None else RecordingFactory(),
    }
    kwargs.update(updates)
    return cli.query_hybrid_retrieval(**kwargs)


def _arguments(paths: tuple[Path, Path], *, query: str = "synthetic activity?") -> list[str]:
    corpus_path, index_path = paths
    return [
        "--corpus", str(corpus_path),
        "--vector-index", str(index_path),
        "--query", query,
        "--top-k", "5",
        "--candidate-k", "20",
        "--expected-corpus-sha256", _hash(corpus_path),
        "--expected-index-sha256", _hash(index_path),
    ]


def _main(
    paths: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
    *,
    factory: object | None = None,
    argv: list[str] | None = None,
) -> tuple[int, str, str]:
    code = cli.main(
        _arguments(paths) if argv is None else argv,
        backend_factory=factory if factory is not None else RecordingFactory(),
    )
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _change_index(paths: tuple[Path, Path], change: Callable[[dict[str, Any]], None]) -> None:
    index_path = paths[1]
    index = json.loads(index_path.read_text(encoding="utf-8"))
    change(index)
    index_path.write_text(json.dumps(index, ensure_ascii=False), encoding="utf-8")


def test_success_matches_direct_hybrid_retriever(paths: tuple[Path, Path]) -> None:
    factory = RecordingFactory()
    result = _query(paths, factory=factory)
    corpus = load_retrieval_corpus(paths[0])
    index = load_vector_index(paths[1])
    expected = retrieve_hybrid(
        corpus, index, "Thực thể synthetic nào cần xem xét?",
        corpus_sha256=_hash(paths[0]),
        embed_query=lambda texts: [[1.0, 0.0, 0.0]],
        top_k=5,
        candidate_k=20,
    )

    assert result == expected
    assert result["schema_version"] == "retrieval-result/v1"
    assert result["retrieval_method"] == "hybrid-rrf/v1"
    assert result["metadata"]["score_interpretation"] == "reciprocal_rank_fusion_not_probability"
    assert result["metadata"]["rrf_k"] == 60
    assert result["metadata"]["score_precision"] == 12
    assert result["metadata"]["component_methods"] == {
        "lexical": "bm25/v1", "vector": "vector-cosine/v1",
    }
    assert len(result["hits"]) == 5


def test_backend_receives_only_index_descriptor_and_explicit_cpu_settings(
    paths: tuple[Path, Path],
) -> None:
    factory = RecordingFactory()
    _query(paths, factory=factory)
    embedding = load_vector_index(paths[1])["embedding"]

    assert factory.calls == [{
        "model_id": embedding["model_id"],
        "model_revision": embedding["model_revision"],
        "dimension": embedding["dimension"],
        "device": "cpu",
        "batch_size": 1,
        "show_progress_bar": False,
    }]


def test_query_is_embedded_once_with_prefix_once_and_original_text_preserved(
    paths: tuple[Path, Path],
) -> None:
    factory = RecordingFactory()
    query = "  câu hỏi tự do?  "
    result = _query(paths, factory=factory, query=query)
    prefix = load_vector_index(paths[1])["embedding"]["query_prefix"]

    assert len(factory.backends) == 1
    assert factory.backends[0].calls == [[prefix + query]]
    assert result["query"]["text"] == query


def test_query_filters_limits_hash_and_callback_are_forwarded_without_mutation(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    types = ["relationship", "evidence"]
    dimensions = ["provenance"]
    query = "  Thực thể synthetic nào?  "
    seen: list[dict[str, Any]] = []
    query_arguments: list[tuple[object, ...]] = []
    original_retrieve = cli.retrieve_hybrid

    def recording_retrieve(*args: object, **kwargs: Any) -> dict[str, Any]:
        seen.append(kwargs)
        query_arguments.append(args)
        return original_retrieve(*args, **kwargs)

    monkeypatch.setattr(cli, "retrieve_hybrid", recording_retrieve)
    result = _query(
        paths, query=query, chunk_types=types, required_dimensions=dimensions,
        top_k=1, candidate_k=7,
    )

    assert seen[0]["chunk_types"] is types
    assert seen[0]["required_dimensions"] is dimensions
    assert seen[0]["top_k"] == 1
    assert seen[0]["candidate_k"] == 7
    assert seen[0]["corpus_sha256"] == _hash(paths[0])
    assert callable(seen[0]["embed_query"])
    assert query_arguments[0][2] == query
    assert types == ["relationship", "evidence"]
    assert dimensions == ["provenance"]
    assert result["query"]["filters"] == {
        "chunk_types": sorted(types), "required_dimensions": dimensions,
    }
    assert len(result["hits"]) <= 1


def test_hits_preserve_complete_chunk_provenance_and_status(paths: tuple[Path, Path]) -> None:
    corpus = load_retrieval_corpus(paths[0])
    result = _query(paths, top_k=100, candidate_k=100)
    by_id = {chunk["chunk_id"]: chunk for chunk in corpus["chunks"]}

    assert len(result["hits"]) == len(corpus["chunks"])
    for hit in result["hits"]:
        chunk = hit["chunk"]
        assert chunk == by_id[chunk["chunk_id"]]
        assert "status" in chunk
        assert "source_references" in chunk
        assert "json_pointer" in chunk["source"]


def test_main_returns_utf8_compact_deterministic_json_with_exact_newline(
    paths: tuple[Path, Path], capsys: pytest.CaptureFixture[str],
) -> None:
    query = "Thực thể synthetic nào cần xem xét?"
    argv = _arguments(paths, query=query)
    first = _main(paths, capsys, argv=argv)
    second = _main(paths, capsys, argv=argv)

    assert first == second
    code, stdout, stderr = first
    assert code == 0 and stderr == ""
    result = json.loads(stdout)
    assert stdout == json.dumps(
        result, ensure_ascii=False, sort_keys=True, allow_nan=False,
        separators=(",", ":"),
    ) + "\n"
    assert stdout.count("\n") == 1
    assert query in stdout
    assert "\\u1ef1" not in stdout
    assert stdout.encode("utf-8").decode("utf-8") == stdout


@pytest.mark.parametrize("field", ("expected_corpus_sha256", "expected_index_sha256"))
def test_wrong_hash_fails_before_backend_creation(
    paths: tuple[Path, Path], field: str,
) -> None:
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError, match="SHA-256 mismatch"):
        _query(paths, factory=factory, **{field: "0" * 64})
    assert factory.calls == []


@pytest.mark.parametrize("field", ("expected_corpus_sha256", "expected_index_sha256"))
@pytest.mark.parametrize("value", (None, 1, True, "", "f" * 63, "g" * 64, "f" * 65, "f" * 64 + "\n"))
def test_invalid_hash_format_or_type_fails_before_backend_creation(
    paths: tuple[Path, Path], field: str, value: object,
) -> None:
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError, match="64 hexadecimal"):
        _query(paths, factory=factory, **{field: value})
    assert factory.calls == []


def test_uppercase_expected_hashes_are_accepted(paths: tuple[Path, Path]) -> None:
    result = _query(
        paths,
        expected_corpus_sha256=_hash(paths[0]).upper(),
        expected_index_sha256=_hash(paths[1]).upper(),
    )
    assert result["hits"]


@pytest.mark.parametrize("position", (0, 1))
def test_changed_input_during_embedding_fails_closed(
    paths: tuple[Path, Path], position: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    changed_path = paths[position]
    before = changed_path.read_bytes()
    factory = RecordingFactory(on_embed=lambda: changed_path.write_bytes(before + b"\n"))
    code, stdout, stderr = _main(paths, capsys, factory=factory)

    assert code == 2 and stdout == ""
    assert "changed during query" in stderr
    assert len(factory.backends[0].calls) == 1
    assert changed_path.read_bytes() == before + b"\n"


@pytest.mark.parametrize("position", (0, 1))
@pytest.mark.parametrize("failure", ("json", "schema", "duplicate", "nonfinite", "encoding"))
def test_invalid_json_and_schema_inputs_fail_before_backend_creation(
    paths: tuple[Path, Path], position: int, failure: str,
) -> None:
    path = paths[position]
    if failure == "json":
        path.write_text('{"schema_version":', encoding="utf-8")
    elif failure == "schema":
        value = json.loads(path.read_text(encoding="utf-8"))
        value["schema_version"] = "unsupported/v0"
        path.write_text(json.dumps(value), encoding="utf-8")
    elif failure == "duplicate":
        path.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
    elif failure == "nonfinite":
        path.write_text('{"value":NaN}', encoding="utf-8")
    else:
        path.write_bytes(b"\xff\xfe")
    factory = RecordingFactory()
    before = [item.read_bytes() for item in paths]

    with pytest.raises(cli.HybridQueryCliError):
        _query(paths, factory=factory)
    assert factory.calls == []
    assert [item.read_bytes() for item in paths] == before


def test_other_provider_is_rejected_before_backend_creation(paths: tuple[Path, Path]) -> None:
    _change_index(paths, lambda index: index["embedding"].update(provider="synthetic-provider"))
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError, match="provider"):
        _query(paths, factory=factory)
    assert factory.calls == []


@pytest.mark.parametrize("revision", ("main", "revision-001", "a" * 39, "g" * 40, "a" * 41))
def test_unpinned_model_revision_is_rejected_before_backend_creation(
    paths: tuple[Path, Path], revision: str,
) -> None:
    _change_index(paths, lambda index: index["embedding"].update(model_revision=revision))
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError, match="revision"):
        _query(paths, factory=factory)
    assert factory.calls == []


@pytest.mark.parametrize("failure", ("provenance_hash", "corpus_id", "scenario_id", "missing_chunk", "chunk_type", "content_hash", "coverage"))
def test_linkage_errors_are_checked_by_retriever_before_backend_creation(
    paths: tuple[Path, Path], failure: str,
) -> None:
    def change(index: dict[str, Any]) -> None:
        if failure == "provenance_hash":
            index["corpus_provenance"]["sha256"] = "0" * 64
        elif failure in {"corpus_id", "scenario_id"}:
            index["corpus_provenance"][failure] = "synthetic-wrong-id"
        elif failure == "missing_chunk":
            index["records"][0]["chunk_id"] = "synthetic-missing-chunk"
        elif failure == "chunk_type":
            current = index["records"][0]["chunk_type"]
            index["records"][0]["chunk_type"] = "entity" if current != "entity" else "evidence"
        elif failure == "content_hash":
            index["records"][0]["content_sha256"] = "0" * 64
        else:
            index["records"].pop()
            index["metadata"]["record_count"] = len(index["records"])
            index["metadata"]["complete_corpus_coverage"] = True

    _change_index(paths, change)
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError):
        _query(paths, factory=factory)
    assert factory.calls == []


@pytest.mark.parametrize("phase", ("initialization", "inference"))
def test_backend_exceptions_are_wrapped_without_partial_json(
    paths: tuple[Path, Path], phase: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    factory = RecordingFactory(**{f"{phase}_error": RuntimeError(f"synthetic {phase} failure")})
    code, stdout, stderr = _main(paths, capsys, factory=factory)

    assert code == 2 and stdout == ""
    assert f"synthetic {phase} failure" in stderr
    assert "Traceback" not in stderr


def test_direct_backend_exception_has_cli_exception_type(paths: tuple[Path, Path]) -> None:
    factory = RecordingFactory(initialization_error=RuntimeError("synthetic factory failure"))
    with pytest.raises(cli.HybridQueryCliError, match="synthetic factory failure"):
        _query(paths, factory=factory)


@pytest.mark.parametrize("backend", (object(), {"embed_documents": "not callable"}))
def test_backend_without_embedding_method_is_rejected(
    paths: tuple[Path, Path], backend: object,
) -> None:
    with pytest.raises(cli.HybridQueryCliError):
        _query(paths, factory=lambda **kwargs: backend)


@pytest.mark.parametrize("vectors", (
    [], [[1, 0, 0], [1, 0, 0]], [[1, 0]], [[1, 0, 0, 0]], "invalid",
    [[0, 0, 0]], [[float("nan"), 0, 0]], [[float("inf"), 0, 0]],
    [[-float("inf"), 0, 0]], [[True, 0, 0]], [["1", 0, 0]], [None],
))
def test_invalid_embedding_count_dimension_and_numbers_are_rejected(
    paths: tuple[Path, Path], vectors: object,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, stdout, stderr = _main(paths, capsys, factory=RecordingFactory(vectors=vectors))
    assert code == 2 and stdout == ""
    assert "error:" in stderr
    assert "Traceback" not in stderr


@pytest.mark.parametrize("query", ("", " \t\n ", "?! … —", None, 42, False))
def test_invalid_query_is_rejected_before_backend_creation(
    paths: tuple[Path, Path], query: object,
) -> None:
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError, match="query"):
        _query(paths, factory=factory, query=query)
    assert factory.calls == []


@pytest.mark.parametrize("top_k", (0, -1, True, False, 1.5, "5", None))
@pytest.mark.parametrize("limit", ("top_k", "candidate_k"))
def test_invalid_limits_are_rejected_before_backend_creation(
    paths: tuple[Path, Path], top_k: object, limit: str,
) -> None:
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError, match=limit):
        _query(paths, factory=factory, **{limit: top_k})
    assert factory.calls == []


@pytest.mark.parametrize("field", ("chunk_types", "required_dimensions"))
@pytest.mark.parametrize("value", (["unknown-value"], ["entity", "entity"], "entity", 3, [None], {"entity": True}))
def test_invalid_or_duplicate_filters_are_rejected_before_backend_creation(
    paths: tuple[Path, Path], field: str, value: object,
) -> None:
    factory = RecordingFactory()
    duplicate_case = value == ["entity", "entity"]
    if duplicate_case and field == "required_dimensions":
        value = ["provenance", "provenance"]
    with pytest.raises(cli.HybridQueryCliError, match=field + (".*duplicate" if duplicate_case else "")):
        _query(paths, factory=factory, **{field: value})
    assert factory.calls == []


def test_empty_filter_preserves_retriever_semantics_and_still_embeds_once(
    paths: tuple[Path, Path],
) -> None:
    factory = RecordingFactory()
    result = _query(paths, factory=factory, chunk_types=[])
    assert result["hits"] == []
    assert result["query"]["filters"]["chunk_types"] == []
    assert len(factory.backends[0].calls) == 1


def test_arbitrary_question_does_not_force_empty_semantic_hits(paths: tuple[Path, Path]) -> None:
    result = _query(paths, query="unmatched_synthetic_token_987654321")
    assert result["hits"]


def test_success_preserves_input_bytes_objects_and_directory_contents(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    before_bytes = [path.read_bytes() for path in paths]
    before_names = sorted(path.name for path in paths[0].parent.iterdir())
    before_hashes = [_hash(path) for path in paths]
    loaded: list[tuple[dict[str, Any], dict[str, Any]]] = []
    original_retrieve = cli.retrieve_hybrid

    def checking_retrieve(corpus: dict[str, Any], index: dict[str, Any], *args: object, **kwargs: Any) -> dict[str, Any]:
        before = deepcopy((corpus, index))
        result = original_retrieve(corpus, index, *args, **kwargs)
        assert (corpus, index) == before
        loaded.append(before)
        return result

    monkeypatch.setattr(cli, "retrieve_hybrid", checking_retrieve)
    _query(paths)

    assert loaded
    assert [path.read_bytes() for path in paths] == before_bytes
    assert [_hash(path) for path in paths] == before_hashes
    assert sorted(path.name for path in paths[0].parent.iterdir()) == before_names


def test_cli_never_opens_paths_for_writing(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_hashes = [_hash(path) for path in paths]
    modes: list[str] = []
    original_open = Path.open

    def read_only_open(path: Path, mode: str = "r", *args: Any, **kwargs: Any):
        modes.append(mode)
        assert not any(character in mode for character in "wax+")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", read_only_open)
    _query(paths, expected_corpus_sha256=expected_hashes[0], expected_index_sha256=expected_hashes[1])
    assert modes


def test_output_does_not_add_answer_confidence_or_confirmed(paths: tuple[Path, Path]) -> None:
    result = _query(paths, top_k=100, candidate_k=100)
    forbidden = {"answer", "confidence", "security_confidence", "confirmed", "llm_output", "hybrid_score"}

    def inspect(value: object) -> None:
        if isinstance(value, dict):
            assert forbidden.isdisjoint(value)
            for child in value.values():
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)
        elif isinstance(value, str):
            assert value.casefold() != "confirmed"

    inspect(result)


@pytest.mark.parametrize("invalid_result", (
    {"score": float("nan")}, {"score": float("inf")}, {"score": -float("inf")},
    {"unsupported": {1, 2}}, {"invalid_unicode": "\ud800"},
))
def test_serialization_errors_fail_without_partial_stdout(
    paths: tuple[Path, Path], invalid_result: object,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "retrieve_hybrid", lambda *args, **kwargs: invalid_result)
    code, stdout, stderr = _main(paths, capsys)

    assert code == 2 and stdout == ""
    assert "error:" in stderr
    assert "Traceback" not in stderr


@pytest.mark.parametrize("position", (0, 1))
def test_hash_file_io_error_is_wrapped_without_backend_creation(
    paths: tuple[Path, Path], position: int,
) -> None:
    changed = list(paths)
    changed[position] = paths[position].parent / "missing.json"
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError):
        _query(
            tuple(changed), factory=factory,
            expected_corpus_sha256=_hash(paths[0]),
            expected_index_sha256=_hash(paths[1]),
        )
    assert factory.calls == []


@pytest.mark.parametrize("position", (0, 1))
def test_input_disappearing_during_query_is_wrapped_and_has_no_partial_stdout(
    paths: tuple[Path, Path], position: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    factory = RecordingFactory(on_embed=lambda: paths[position].unlink())
    code, stdout, stderr = _main(paths, capsys, factory=factory)
    assert code == 2 and stdout == ""
    assert "error:" in stderr


def test_noisy_backend_messages_are_redirected_away_from_json_stdout(
    paths: tuple[Path, Path], capsys: pytest.CaptureFixture[str],
) -> None:
    code, stdout, stderr = _main(paths, capsys, factory=RecordingFactory(noisy=True))
    assert code == 0
    assert json.loads(stdout)["hits"]
    assert stdout.count("\n") == 1
    assert "synthetic initialization message" in stderr
    assert "synthetic inference message" in stderr
    assert "synthetic initialization message" not in stdout


def test_noisy_backend_failure_keeps_stdout_empty(
    paths: tuple[Path, Path], capsys: pytest.CaptureFixture[str],
) -> None:
    factory = RecordingFactory(noisy=True, initialization_error=RuntimeError("synthetic failure"))
    code, stdout, stderr = _main(paths, capsys, factory=factory)
    assert code == 2 and stdout == ""
    assert "synthetic failure" in stderr


@pytest.mark.parametrize("loader_name", ("load_retrieval_corpus", "load_vector_index"))
def test_noisy_loader_messages_cannot_contaminate_json_stdout(
    paths: tuple[Path, Path], loader_name: str,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    original = getattr(cli, loader_name)

    def noisy_loader(path: Path) -> dict[str, Any]:
        print("synthetic loader message")
        return original(path)

    monkeypatch.setattr(cli, loader_name, noisy_loader)
    code, stdout, stderr = _main(paths, capsys)
    assert code == 0 and json.loads(stdout)["hits"]
    assert "synthetic loader message" in stderr
    assert "synthetic loader message" not in stdout


def test_main_repeatable_filters_and_top_k(
    paths: tuple[Path, Path], capsys: pytest.CaptureFixture[str],
) -> None:
    argv = _arguments(paths)
    argv[argv.index("--top-k") + 1] = "1"
    argv.extend((
        "--chunk-type", "evidence", "--chunk-type", "relationship",
        "--required-dimension", "provenance", "--required-dimension", "evidence",
    ))
    code, stdout, stderr = _main(paths, capsys, argv=argv)
    assert code == 0 and stderr == ""
    result = json.loads(stdout)
    assert result["query"]["top_k"] == 1
    assert result["query"]["filters"] == {
        "chunk_types": ["evidence", "relationship"],
        "required_dimensions": ["evidence", "provenance"],
    }


@pytest.mark.parametrize("failure", (
    "missing_corpus", "missing_index", "missing_query", "missing_corpus_hash",
    "missing_index_hash", "invalid_top_k", "invalid_candidate_k", "unknown_output",
    "unknown_option",
))
def test_main_parser_errors_return_two_and_only_stderr(
    paths: tuple[Path, Path], failure: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    argv = _arguments(paths)
    if failure.startswith("missing_"):
        flag = {
            "missing_corpus": "--corpus", "missing_index": "--vector-index",
            "missing_query": "--query", "missing_corpus_hash": "--expected-corpus-sha256",
            "missing_index_hash": "--expected-index-sha256",
        }[failure]
        offset = argv.index(flag)
        del argv[offset:offset + 2]
    elif failure == "invalid_top_k":
        argv[argv.index("--top-k") + 1] = "1.5"
    elif failure == "invalid_candidate_k":
        argv[argv.index("--candidate-k") + 1] = "1.5"
    elif failure == "unknown_output":
        argv.extend(("--output", str(paths[0].parent / "forbidden.json")))
    else:
        argv.append("--unknown-option")
    factory = RecordingFactory()
    code, stdout, stderr = _main(paths, capsys, factory=factory, argv=argv)
    assert code == 2 and stdout == ""
    assert "error:" in stderr
    assert "Traceback" not in stderr
    assert factory.calls == []
    assert not (paths[0].parent / "forbidden.json").exists()


def test_main_invalid_expected_hash_is_stderr_only(
    paths: tuple[Path, Path], capsys: pytest.CaptureFixture[str],
) -> None:
    argv = _arguments(paths)
    argv[argv.index("--expected-index-sha256") + 1] = "not-a-hash"
    code, stdout, stderr = _main(paths, capsys, argv=argv)
    assert code == 2 and stdout == ""
    assert "64 hexadecimal" in stderr


def test_subprocess_error_exit_and_utf8_stderr_do_not_load_a_model(paths: tuple[Path, Path]) -> None:
    argv = _arguments(paths)
    argv[argv.index("--expected-corpus-sha256") + 1] = "0" * 64
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *argv],
        cwd=REPOSITORY_ROOT, capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "SHA-256 mismatch" in result.stderr
    assert "Traceback" not in result.stderr


def test_subprocess_help_has_no_output_file_option_or_model_loading() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        cwd=REPOSITORY_ROOT, capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert result.returncode == 0 and result.stderr == ""
    assert "--vector-index" in result.stdout
    assert "--expected-index-sha256" in result.stdout
    assert "--candidate-k" in result.stdout
    assert "--output" not in result.stdout


def test_cli_source_is_scenario_independent_and_has_no_generation_or_file_writes() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8").casefold()
    for forbidden in (
        "all-minilm", "mshta-powershell", "t1218.005", "powershell.exe", "mshta.exe",
        "retrieval-chunk--", "scenario-mshta", "scenario-synthetic-builder",
        "expected_answer", "llm_output", "hybrid_score", "security_confidence",
        "trust_remote_code=true", "write_text(", "write_bytes(", "mkdir(", "mkstemp(",
        "53abc9e44c03c46aaf024cdb79b61ad3381d50feb82689f27074151381b9d0f3",
        "94705156295740dfbf835a867c031213975481ec0bee68275c886be9d8cf2116",
    ):
        assert forbidden not in source


def test_backend_construction_is_lazy_until_hybrid_embedding_callback(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = RecordingFactory()
    original_retrieve = cli.retrieve_hybrid
    entry_calls = []

    def checking_retrieve(*args: object, **kwargs: Any) -> dict[str, Any]:
        assert factory.calls == []
        assert callable(kwargs["embed_query"])
        entry_calls.append(True)
        result = original_retrieve(*args, **kwargs)
        assert len(factory.calls) == 1
        return result

    monkeypatch.setattr(cli, "retrieve_hybrid", checking_retrieve)
    _query(paths, factory=factory)

    assert entry_calls == [True]
    assert len(factory.backends[0].calls) == 1


def test_hybrid_results_are_returned_without_rescoring_or_changing_components(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = _query(paths, top_k=15, candidate_k=15)
    before = deepcopy(expected)
    monkeypatch.setattr(cli, "retrieve_hybrid", lambda *args, **kwargs: expected)
    factory = RecordingFactory()

    result = _query(paths, factory=factory)
    code, stdout, stderr = _main(paths, capsys, factory=factory)

    assert result is expected
    assert json.loads(stdout) == expected == before
    assert code == 0 and stderr == ""
    assert factory.calls == []
    assert any(hit["components"]["lexical"] is not None for hit in expected["hits"])
    assert any(hit["components"]["vector"] is not None for hit in expected["hits"])


@pytest.mark.parametrize(("top_k", "candidate_k"), ((1, 1), (2, 4), (5, 20), (20, 100)))
def test_valid_candidate_and_final_limits_match_direct_hybrid(
    paths: tuple[Path, Path], top_k: int, candidate_k: int,
) -> None:
    result = _query(paths, top_k=top_k, candidate_k=candidate_k)
    expected = retrieve_hybrid(
        load_retrieval_corpus(paths[0]), load_vector_index(paths[1]),
        "Thực thể synthetic nào cần xem xét?", corpus_sha256=_hash(paths[0]),
        embed_query=lambda texts: [[1, 0, 0]], top_k=top_k, candidate_k=candidate_k,
    )

    assert result == expected
    assert result["query"]["top_k"] == top_k
    assert result["query"]["candidate_k"] == candidate_k
    assert len(result["hits"]) <= top_k
    assert result["metadata"]["lexical_candidate_count"] <= candidate_k
    assert result["metadata"]["vector_candidate_count"] <= candidate_k


def test_candidate_k_smaller_than_top_k_fails_before_backend_creation(
    paths: tuple[Path, Path], capsys: pytest.CaptureFixture[str],
) -> None:
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError, match="candidate_k"):
        _query(paths, factory=factory, top_k=5, candidate_k=4)
    argv = _arguments(paths)
    argv[argv.index("--candidate-k") + 1] = "4"
    code, stdout, stderr = _main(paths, capsys, factory=factory, argv=argv)

    assert code == 2 and stdout == ""
    assert "candidate_k" in stderr
    assert factory.calls == []


def test_main_default_limits_are_five_and_twenty(
    paths: tuple[Path, Path], capsys: pytest.CaptureFixture[str],
) -> None:
    argv = _arguments(paths)
    for option in ("--top-k", "--candidate-k"):
        offset = argv.index(option)
        del argv[offset:offset + 2]
    code, stdout, stderr = _main(paths, capsys, argv=argv)

    assert code == 0 and stderr == ""
    result = json.loads(stdout)
    assert result["query"]["top_k"] == 5
    assert result["query"]["candidate_k"] == 20
    assert len(result["hits"]) == 5


@pytest.mark.parametrize("error_type", (HybridRetrievalError, RuntimeError))
def test_hybrid_retriever_errors_are_wrapped_without_partial_stdout(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], error_type: type[Exception],
) -> None:
    def failing_retrieve(*args: object, **kwargs: Any) -> dict[str, Any]:
        raise error_type("synthetic hybrid failure")

    monkeypatch.setattr(cli, "retrieve_hybrid", failing_retrieve)
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError, match="synthetic hybrid failure"):
        _query(paths, factory=factory)
    code, stdout, stderr = _main(paths, capsys, factory=factory)

    assert code == 2 and stdout == ""
    assert "synthetic hybrid failure" in stderr
    assert "Traceback" not in stderr
    assert factory.calls == []


@pytest.mark.parametrize("loader_name", ("load_retrieval_corpus", "load_vector_index"))
def test_loader_errors_have_cli_error_context_and_no_backend_or_output(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], loader_name: str,
) -> None:
    def failing_loader(path: Path) -> dict[str, Any]:
        raise OSError("synthetic loader failure")

    monkeypatch.setattr(cli, loader_name, failing_loader)
    factory = RecordingFactory()
    with pytest.raises(cli.HybridQueryCliError, match="synthetic loader failure"):
        _query(paths, factory=factory)
    code, stdout, stderr = _main(paths, capsys, factory=factory)

    assert code == 2 and stdout == ""
    assert "synthetic loader failure" in stderr
    assert "Traceback" not in stderr
    assert factory.calls == []


def test_error_message_with_invalid_unicode_is_escaped_for_utf8_stderr(
    paths: tuple[Path, Path], capsys: pytest.CaptureFixture[str],
) -> None:
    factory = RecordingFactory(initialization_error=RuntimeError("synthetic \ud800 failure"))
    code, stdout, stderr = _main(paths, capsys, factory=factory)

    assert code == 2 and stdout == ""
    assert "\\ud800" in stderr
    assert stderr.encode("utf-8", errors="strict")
    assert "Traceback" not in stderr


def test_utf8_stream_configuration_uses_strict_encoding_and_single_newline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    class ConfigurableStream:
        def reconfigure(self, **kwargs: Any) -> None:
            calls.append(kwargs)

    monkeypatch.setattr(cli.sys, "stdout", ConfigurableStream())
    monkeypatch.setattr(cli.sys, "stderr", ConfigurableStream())
    cli._configure_utf8_streams()

    assert calls == [{"encoding": "utf-8", "errors": "strict", "newline": "\n"}] * 2


def test_utf8_stream_configuration_failure_returns_two_and_stderr_only(
    paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def failing_configuration() -> None:
        raise OSError("synthetic stream configuration failure")

    monkeypatch.setattr(cli, "_configure_utf8_streams", failing_configuration)
    factory = RecordingFactory()
    code, stdout, stderr = _main(paths, capsys, factory=factory)

    assert code == 2 and stdout == ""
    assert "synthetic stream configuration failure" in stderr
    assert "Traceback" not in stderr
    assert factory.calls == []


def test_generator_filters_and_empty_dimensions_keep_retriever_semantics(
    paths: tuple[Path, Path],
) -> None:
    with_generators = _query(
        paths, chunk_types=iter(["relationship", "evidence"]),
        required_dimensions=iter(["provenance"]),
    )
    with_lists = _query(
        paths, chunk_types=["relationship", "evidence"], required_dimensions=["provenance"],
    )
    assert with_generators == with_lists
    unfiltered = _query(paths)
    empty_dimensions = _query(paths, required_dimensions=[])
    assert unfiltered["hits"] == empty_dimensions["hits"]
    assert unfiltered["metadata"] == empty_dimensions["metadata"]


def test_failure_does_not_write_or_leave_temporary_files(
    paths: tuple[Path, Path], capsys: pytest.CaptureFixture[str],
) -> None:
    before_bytes = [path.read_bytes() for path in paths]
    before_contents = sorted(path.relative_to(paths[0].parent) for path in paths[0].parent.rglob("*"))
    factory = RecordingFactory(inference_error=RuntimeError("synthetic failure"))
    code, stdout, stderr = _main(paths, capsys, factory=factory)

    assert code == 2 and stdout == "" and "synthetic failure" in stderr
    assert [path.read_bytes() for path in paths] == before_bytes
    assert sorted(path.relative_to(paths[0].parent) for path in paths[0].parent.rglob("*")) == before_contents
