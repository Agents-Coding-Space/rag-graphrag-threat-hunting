#!/usr/bin/env python3
"""Build a validated Vector Index from one Retrieval Corpus document."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
import hashlib
from importlib import metadata as importlib_metadata
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, NoReturn


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPOSITORY_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from threat_hunting.retrieval import (  # noqa: E402
    EmbeddingBackendError,
    RetrievalCorpusValidationError,
    SentenceTransformerEmbeddingBackend,
    VectorIndexBuildError,
    VectorIndexValidationError,
    build_vector_index,
    load_retrieval_corpus,
    load_vector_index,
    validate_vector_index,
)
from threat_hunting.retrieval.vector_schema import (  # noqa: E402
    EMBEDDING_FIELDS,
    SUPPORTED_DISTANCE_METRICS,
    SUPPORTED_NORMALIZATIONS,
)


CONFIG_SCHEMA_VERSION = "vector-index-build-config/v1"
CONFIG_FIELDS = ("schema_version", "embedding", "runtime")
RUNTIME_FIELDS = ("device", "batch_size", "show_progress_bar")
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
MODEL_REVISION_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class VectorIndexCliError(ValueError):
    """Raised when CLI inputs cannot safely produce a Vector Index."""


@dataclass(frozen=True)
class BuildStats:
    schema_version: str
    index_id: str
    corpus_id: str
    scenario_id: str
    review_status: str
    record_count: int
    vector_dimension: int
    provider: str
    model_id: str
    model_revision: str
    sentence_transformers_version: str
    input_path: str
    input_sha256: str
    output_path: str
    output_sha256: str


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_json_number(value: str) -> NoReturn:
    raise ValueError(f"non-standard JSON number {value!r}")


def _require_object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VectorIndexCliError(f"{path} must be a JSON object")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected_fields: tuple[str, ...], path: str
) -> None:
    expected = set(expected_fields)
    actual = set(value)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    details: list[str] = []
    if missing:
        details.append(f"missing {missing!r}")
    if unexpected:
        details.append(f"unexpected {unexpected!r}")
    if details:
        raise VectorIndexCliError(
            f"{path} fields do not match the contract: {'; '.join(details)}"
        )


def _require_nonempty_string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VectorIndexCliError(f"{path} must be a non-empty string")
    return value


def _require_string(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise VectorIndexCliError(f"{path} must be a string")
    return value


def _require_positive_integer(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise VectorIndexCliError(f"{path} must be a positive integer")
    return value


def _validate_json_value(value: object, path: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise VectorIndexCliError(f"{path} must contain finite JSON numbers")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise VectorIndexCliError(
                    f"{path} contains a non-string object key"
                )
            _validate_json_value(item, f"{path}.{key}")
        return
    raise VectorIndexCliError(
        f"{path} contains a value that cannot be represented in JSON"
    )


def _validate_build_config(document: object) -> dict[str, object]:
    root = _require_object(document, "$config")
    _validate_json_value(root, "$config")
    _require_exact_fields(root, CONFIG_FIELDS, "$config")
    schema_version = _require_nonempty_string(
        root["schema_version"], "$config.schema_version"
    )
    if schema_version != CONFIG_SCHEMA_VERSION:
        raise VectorIndexCliError(
            f"$config.schema_version must be {CONFIG_SCHEMA_VERSION!r}"
        )

    raw_embedding = _require_object(root["embedding"], "$config.embedding")
    _require_exact_fields(raw_embedding, EMBEDDING_FIELDS, "$config.embedding")
    embedding = {field: raw_embedding[field] for field in EMBEDDING_FIELDS}
    provider = _require_nonempty_string(
        embedding["provider"], "$config.embedding.provider"
    )
    if provider != "sentence-transformers":
        raise VectorIndexCliError(
            "$config.embedding.provider must be 'sentence-transformers'"
        )
    _require_nonempty_string(embedding["model_id"], "$config.embedding.model_id")
    revision = _require_nonempty_string(
        embedding["model_revision"], "$config.embedding.model_revision"
    )
    if MODEL_REVISION_PATTERN.fullmatch(revision) is None:
        raise VectorIndexCliError(
            "$config.embedding.model_revision must be a full 40-character "
            "hexadecimal commit SHA"
        )
    embedding["model_revision"] = revision.lower()
    _require_positive_integer(
        embedding["dimension"], "$config.embedding.dimension"
    )
    metric = _require_nonempty_string(
        embedding["distance_metric"], "$config.embedding.distance_metric"
    )
    if metric not in SUPPORTED_DISTANCE_METRICS:
        raise VectorIndexCliError(
            "$config.embedding.distance_metric has unsupported value "
            f"{metric!r}"
        )
    normalization = _require_nonempty_string(
        embedding["normalization"], "$config.embedding.normalization"
    )
    if normalization not in SUPPORTED_NORMALIZATIONS:
        raise VectorIndexCliError(
            "$config.embedding.normalization has unsupported value "
            f"{normalization!r}"
        )
    _require_string(
        embedding["document_prefix"], "$config.embedding.document_prefix"
    )
    _require_string(embedding["query_prefix"], "$config.embedding.query_prefix")

    raw_runtime = _require_object(root["runtime"], "$config.runtime")
    _require_exact_fields(raw_runtime, RUNTIME_FIELDS, "$config.runtime")
    runtime: dict[str, object] = {
        "device": _require_nonempty_string(
            raw_runtime["device"], "$config.runtime.device"
        ),
        "batch_size": _require_positive_integer(
            raw_runtime["batch_size"], "$config.runtime.batch_size"
        ),
        "show_progress_bar": raw_runtime["show_progress_bar"],
    }
    if runtime["device"] != "cpu":
        raise VectorIndexCliError("$config.runtime.device must be 'cpu'")
    if runtime["show_progress_bar"] is not False:
        raise VectorIndexCliError(
            "$config.runtime.show_progress_bar must be false"
        )
    return {
        "schema_version": schema_version,
        "embedding": embedding,
        "runtime": runtime,
    }


def load_build_config(path: Path) -> dict[str, object]:
    """Strict-load one UTF-8 Vector Index build configuration."""

    source_path = Path(path)
    try:
        with source_path.open("r", encoding="utf-8") as handle:
            document = json.load(
                handle,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_number,
            )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise VectorIndexCliError(
            f"cannot read vector index build config {source_path}: {exc}"
        ) from exc
    try:
        return _validate_build_config(document)
    except VectorIndexCliError as exc:
        raise VectorIndexCliError(
            f"invalid vector index build config {source_path}: {exc}"
        ) from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise VectorIndexCliError(f"cannot hash corpus {path}: {exc}") from exc
    return digest.hexdigest()


def _expected_hash(value: str) -> str:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise VectorIndexCliError(
            "--expected-corpus-sha256 must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _assert_corpus_hash(path: Path, expected_hash: str, *, phase: str) -> None:
    actual_hash = _sha256_file(path)
    if actual_hash != expected_hash:
        raise VectorIndexCliError(
            f"corpus SHA-256 mismatch {phase} for {path}: "
            f"expected {expected_hash}, got {actual_hash}"
        )


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return path.name


def _serialize(document: dict[str, object]) -> bytes:
    try:
        text = json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        return (text + "\n").encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise VectorIndexCliError(
            f"cannot serialize Vector Index as UTF-8 JSON: {exc}"
        ) from exc


def _write_temporary_payload(output_path: Path, payload: bytes) -> Path:
    try:
        descriptor, raw_path = tempfile.mkstemp(
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(raw_path)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        if "temporary_path" in locals():
            temporary_path.unlink(missing_ok=True)
        raise VectorIndexCliError(
            f"cannot write temporary output beside {output_path}: {exc}"
        ) from exc
    return temporary_path


def _restore_output(output_path: Path, previous_bytes: bytes | None) -> None:
    if previous_bytes is None:
        output_path.unlink(missing_ok=True)
        return
    restore_path = _write_temporary_payload(output_path, previous_bytes)
    try:
        os.replace(restore_path, output_path)
    finally:
        restore_path.unlink(missing_ok=True)


def _write_atomic(
    output_path: Path,
    payload: bytes,
    *,
    expected_document: dict[str, object],
    overwrite: bool,
) -> bytes | None:
    if output_path.exists() and not overwrite:
        raise VectorIndexCliError(
            f"output already exists (pass --overwrite to replace it): {output_path}"
        )

    previous_bytes = output_path.read_bytes() if output_path.exists() else None
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        temporary_path = _write_temporary_payload(output_path, payload)
        temporary_document = load_vector_index(temporary_path)
        if temporary_document != expected_document:
            raise VectorIndexCliError(
                f"temporary output failed semantic read-back: {temporary_path}"
            )
        if temporary_path.read_bytes() != payload:
            raise VectorIndexCliError(
                f"temporary output failed byte read-back: {temporary_path}"
            )
        os.replace(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return previous_bytes


def _sentence_transformers_version() -> str:
    try:
        return importlib_metadata.version("sentence-transformers")
    except importlib_metadata.PackageNotFoundError as exc:
        raise VectorIndexCliError(
            "cannot determine installed sentence-transformers version"
        ) from exc


def build_document(
    *,
    corpus_path: Path,
    config_path: Path,
    output_path: Path,
    expected_corpus_sha256: str,
    overwrite: bool,
    backend_factory: Callable[..., object] = SentenceTransformerEmbeddingBackend,
) -> BuildStats:
    """Load, embed, atomically write, and read back one Vector Index."""

    resolved_output = output_path.resolve()
    if resolved_output in {corpus_path.resolve(), config_path.resolve()}:
        raise VectorIndexCliError(
            "--output must resolve to a different path than --corpus and --config"
        )
    if output_path.exists() and not overwrite:
        raise VectorIndexCliError(
            f"output already exists (pass --overwrite to replace it): {output_path}"
        )

    expected_hash = _expected_hash(expected_corpus_sha256)
    config = load_build_config(config_path)
    corpus = load_retrieval_corpus(corpus_path)
    _assert_corpus_hash(corpus_path, expected_hash, phase="before model loading")
    embedding = config["embedding"]
    runtime = config["runtime"]
    assert isinstance(embedding, Mapping)
    assert isinstance(runtime, Mapping)

    try:
        backend = backend_factory(
            model_id=embedding["model_id"],
            model_revision=embedding["model_revision"],
            dimension=embedding["dimension"],
            device=runtime["device"],
            batch_size=runtime["batch_size"],
            show_progress_bar=runtime["show_progress_bar"],
        )
        load = getattr(backend, "load", None)
        if not callable(load):
            raise VectorIndexCliError(
                "embedding backend does not provide load()"
            )
        load()
        actual_dimension = getattr(backend, "embedding_dimension", None)
    except (EmbeddingBackendError, VectorIndexCliError):
        raise
    except Exception as exc:
        raise VectorIndexCliError(
            f"embedding backend initialization failed: {exc}"
        ) from exc
    if actual_dimension != embedding["dimension"]:
        raise VectorIndexCliError(
            "model embedding dimension mismatch: "
            f"expected {embedding['dimension']}, got {actual_dimension}"
        )
    embed_documents = getattr(backend, "embed_documents", None)
    if not callable(embed_documents):
        raise VectorIndexCliError(
            "embedding backend does not provide embed_documents()"
        )

    document = build_vector_index(
        corpus,
        corpus_path=_portable_path(corpus_path),
        corpus_sha256=expected_hash,
        embedding=embedding,
        embed_documents=embed_documents,
    )
    validate_vector_index(document)
    payload = _serialize(document)
    sentence_transformers_version = _sentence_transformers_version()
    _assert_corpus_hash(corpus_path, expected_hash, phase="before write")
    previous_bytes = _write_atomic(
        output_path,
        payload,
        expected_document=document,
        overwrite=overwrite,
    )
    try:
        written = load_vector_index(output_path)
        if written != document or output_path.read_bytes() != payload:
            raise VectorIndexCliError(
                f"generated output failed deterministic read-back: {output_path}"
            )
        _assert_corpus_hash(corpus_path, expected_hash, phase="after write")
    except Exception:
        _restore_output(output_path, previous_bytes)
        raise

    return BuildStats(
        schema_version=str(document["schema_version"]),
        index_id=str(document["index_id"]),
        corpus_id=str(document["corpus_provenance"]["corpus_id"]),
        scenario_id=str(document["corpus_provenance"]["scenario_id"]),
        review_status=str(document["review"]["review_status"]),
        record_count=len(document["records"]),
        vector_dimension=int(document["embedding"]["dimension"]),
        provider=str(document["embedding"]["provider"]),
        model_id=str(document["embedding"]["model_id"]),
        model_revision=str(document["embedding"]["model_revision"]),
        sentence_transformers_version=sentence_transformers_version,
        input_path=_portable_path(corpus_path),
        input_sha256=expected_hash,
        output_path=_portable_path(output_path),
        output_sha256=hashlib.sha256(payload).hexdigest(),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a local Sentence Transformers Vector Index."
    )
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-corpus-sha256", required=True)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing output file atomically.",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    backend_factory: Callable[..., object] = SentenceTransformerEmbeddingBackend,
) -> int:
    args = _build_parser().parse_args(argv)
    try:
        stats = build_document(
            corpus_path=args.corpus,
            config_path=args.config,
            output_path=args.output,
            expected_corpus_sha256=args.expected_corpus_sha256,
            overwrite=args.overwrite,
            backend_factory=backend_factory,
        )
    except (
        EmbeddingBackendError,
        RetrievalCorpusValidationError,
        VectorIndexBuildError,
        VectorIndexCliError,
        VectorIndexValidationError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            asdict(stats),
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
