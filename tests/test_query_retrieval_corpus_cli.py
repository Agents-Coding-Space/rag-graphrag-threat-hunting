from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import pytest

from threat_hunting.retrieval import load_retrieval_corpus, retrieve_lexical


REPOSITORY_ROOT = Path(__file__).parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "query_retrieval_corpus.py"
CORPUS_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "retrieval"
    / "retrieval_corpus_minimal.json"
)


def _sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _copy_corpus(tmp_path: Path) -> Path:
    corpus_path = tmp_path / "retrieval_corpus.json"
    shutil.copyfile(CORPUS_FIXTURE, corpus_path)
    return corpus_path


def _run(
    corpus_path: Path,
    query: str,
    *,
    top_k: object = 5,
    chunk_types: list[str] | None = None,
    required_dimensions: list[str] | None = None,
    expected_hash: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(SCRIPT_PATH),
        "--corpus",
        str(corpus_path),
        "--query",
        query,
        "--top-k",
        str(top_k),
    ]
    for chunk_type in chunk_types or []:
        command.extend(("--chunk-type", chunk_type))
    for dimension in required_dimensions or []:
        command.extend(("--required-dimension", dimension))
    if expected_hash is not None:
        command.extend(("--expected-corpus-sha256", expected_hash))
    return subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _stdout_json(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    value = json.loads(result.stdout)
    assert isinstance(value, dict)
    return value


def test_unicode_runtime_question_with_question_mark_is_accepted(
    tmp_path: Path,
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    query = "Thực thể synthetic nào cần xem xét?"

    result = _run(corpus_path, query)

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    document = _stdout_json(result)
    assert document["schema_version"] == "retrieval-result/v1"
    assert document["query"]["text"] == query
    assert document["hits"]


def test_stdout_matches_direct_retriever_result(tmp_path: Path) -> None:
    corpus_path = _copy_corpus(tmp_path)
    query = "synthetic activity"

    result = _run(corpus_path, query)
    expected = retrieve_lexical(
        load_retrieval_corpus(corpus_path),
        query,
        top_k=5,
        chunk_types=None,
        required_dimensions=None,
    )

    assert result.returncode == 0, result.stderr
    assert _stdout_json(result) == expected


def test_top_k_and_repeatable_filters_are_forwarded(tmp_path: Path) -> None:
    corpus_path = _copy_corpus(tmp_path)
    query = "synthetic origin entity"
    chunk_types = ["entity", "relationship"]
    required_dimensions = ["entity", "provenance"]

    result = _run(
        corpus_path,
        query,
        top_k=1,
        chunk_types=chunk_types,
        required_dimensions=required_dimensions,
    )
    expected = retrieve_lexical(
        load_retrieval_corpus(corpus_path),
        query,
        top_k=1,
        chunk_types=chunk_types,
        required_dimensions=required_dimensions,
    )

    assert result.returncode == 0, result.stderr
    assert _stdout_json(result) == expected
    assert len(expected["hits"]) == 1
    assert expected["query"]["filters"] == {
        "chunk_types": ["entity", "relationship"],
        "required_dimensions": ["entity", "provenance"],
    }


def test_hits_preserve_complete_chunk_status_and_provenance(tmp_path: Path) -> None:
    corpus_path = _copy_corpus(tmp_path)
    corpus = load_retrieval_corpus(corpus_path)

    result = _run(corpus_path, "fixture records transition", top_k=20)
    output = _stdout_json(result)

    assert result.returncode == 0, result.stderr
    chunks_by_id = {chunk["chunk_id"]: chunk for chunk in corpus["chunks"]}
    assert output["hits"]
    for hit in output["hits"]:
        chunk = hit["chunk"]
        assert chunk == chunks_by_id[chunk["chunk_id"]]
        assert "status" in chunk
        assert "source_references" in chunk
        assert "json_pointer" in chunk["source"]


def test_no_match_succeeds_with_empty_hits_and_retriever_warning(
    tmp_path: Path,
) -> None:
    corpus_path = _copy_corpus(tmp_path)

    result = _run(corpus_path, "unmatched_token_987654321")
    output = _stdout_json(result)

    assert result.returncode == 0, result.stderr
    assert output["hits"] == []
    assert output["warnings"] == [
        "No eligible chunks matched the normalized lexical query terms."
    ]


@pytest.mark.parametrize("failure", ("schema", "json", "duplicate"))
def test_invalid_corpus_inputs_are_rejected_without_partial_json(
    tmp_path: Path,
    failure: str,
) -> None:
    corpus_path = _copy_corpus(tmp_path)
    if failure == "schema":
        document = json.loads(corpus_path.read_text(encoding="utf-8"))
        document["schema_version"] = "retrieval-corpus/v0"
        corpus_path.write_text(json.dumps(document), encoding="utf-8")
    elif failure == "json":
        corpus_path.write_text('{"schema_version":', encoding="utf-8")
    else:
        text = corpus_path.read_text(encoding="utf-8")
        text = text.replace(
            '"schema_version": "retrieval-corpus/v1",',
            '"schema_version": "retrieval-corpus/v1",\n'
            '  "schema_version": "retrieval-corpus/v1",',
            1,
        )
        corpus_path.write_text(text, encoding="utf-8")

    result = _run(corpus_path, "synthetic")

    assert result.returncode != 0
    assert result.stdout == ""
    assert "error:" in result.stderr


def test_wrong_expected_sha256_is_rejected_without_result(tmp_path: Path) -> None:
    corpus_path = _copy_corpus(tmp_path)

    result = _run(corpus_path, "synthetic", expected_hash="0" * 64)

    assert result.returncode != 0
    assert result.stdout == ""
    assert "SHA-256 mismatch before query" in result.stderr


@pytest.mark.parametrize(
    ("top_k", "chunk_types", "required_dimensions", "message"),
    (
        (0, None, None, "positive integer"),
        (-1, None, None, "positive integer"),
        (5, ["not-a-chunk-type"], None, "unsupported value"),
        (5, None, ["not-a-dimension"], "unsupported value"),
        (5, ["entity", "entity"], None, "duplicate"),
        (5, None, ["entity", "entity"], "duplicate"),
    ),
)
def test_invalid_top_k_and_filters_are_rejected(
    tmp_path: Path,
    top_k: object,
    chunk_types: list[str] | None,
    required_dimensions: list[str] | None,
    message: str,
) -> None:
    corpus_path = _copy_corpus(tmp_path)

    result = _run(
        corpus_path,
        "synthetic",
        top_k=top_k,
        chunk_types=chunk_types,
        required_dimensions=required_dimensions,
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert message in result.stderr


def test_two_identical_runs_have_byte_identical_stdout(tmp_path: Path) -> None:
    corpus_path = _copy_corpus(tmp_path)
    digest = _sha256(corpus_path)

    first = _run(
        corpus_path,
        "synthetic transition?",
        top_k=7,
        expected_hash=digest,
    )
    second = _run(
        corpus_path,
        "synthetic transition?",
        top_k=7,
        expected_hash=digest,
    )

    assert first.returncode == second.returncode == 0
    assert first.stdout.encode("utf-8") == second.stdout.encode("utf-8")


def test_query_does_not_change_corpus_bytes_or_sha256(tmp_path: Path) -> None:
    corpus_path = _copy_corpus(tmp_path)
    bytes_before = corpus_path.read_bytes()
    hash_before = _sha256(corpus_path)

    result = _run(
        corpus_path,
        "synthetic evidence",
        expected_hash=hash_before,
    )

    assert result.returncode == 0, result.stderr
    assert corpus_path.read_bytes() == bytes_before
    assert _sha256(corpus_path) == hash_before


def test_invalid_expected_hash_format_is_rejected(tmp_path: Path) -> None:
    corpus_path = _copy_corpus(tmp_path)

    result = _run(corpus_path, "synthetic", expected_hash="not-a-hash")

    assert result.returncode != 0
    assert result.stdout == ""
    assert "64 hexadecimal" in result.stderr


def test_cli_source_has_no_scenario_specific_queries_answers_ids_or_hashes() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "tiến trình nào đã khởi chạy powershell.exe",
        "expected_answer",
        "expected_answers",
        "mshta-powershell",
        "mshta.exe",
        "powershell.exe",
        "t1218.005",
        "53abc9e44c03c46aaf024cdb79b61ad3381d50feb82689f27074151381b9d0f3",
    ):
        assert forbidden not in source
