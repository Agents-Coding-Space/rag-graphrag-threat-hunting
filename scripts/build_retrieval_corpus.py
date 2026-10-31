#!/usr/bin/env python3
"""Build a validated Retrieval Corpus from one Ground Truth Core document."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPOSITORY_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from threat_hunting.ground_truth import (  # noqa: E402
    GroundTruthValidationError,
    load_ground_truth_document,
)
from threat_hunting.retrieval import (  # noqa: E402
    RetrievalCorpusBuildError,
    RetrievalCorpusValidationError,
    build_retrieval_corpus,
    load_retrieval_corpus,
    validate_retrieval_corpus,
)


_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")


class RetrievalCorpusCliError(ValueError):
    """Raised when CLI inputs cannot safely produce a Retrieval Corpus."""


@dataclass(frozen=True)
class BuildStats:
    scenario_id: str
    schema_version: str
    corpus_id: str
    review_status: str
    total_chunks: int
    chunk_counts: dict[str, int]
    input_path: str
    input_sha256: str
    output_path: str
    output_sha256: str


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise RetrievalCorpusCliError(f"cannot hash input {path}: {exc}") from exc
    return digest.hexdigest()


def _expected_hash(value: str) -> str:
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise RetrievalCorpusCliError(
            "--expected-input-sha256 must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _expected_scenario(value: str) -> str:
    if not value.strip():
        raise RetrievalCorpusCliError("--expected-scenario-id must not be empty")
    return value


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return path.name


def _serialize(document: dict[str, object]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _assert_input_hash(path: Path, expected_hash: str, *, phase: str) -> None:
    actual_hash = _sha256_file(path)
    if actual_hash != expected_hash:
        raise RetrievalCorpusCliError(
            f"input SHA-256 mismatch {phase} for {path}: "
            f"expected {expected_hash}, got {actual_hash}"
        )


def _write_atomic(
    output_path: Path,
    payload: bytes,
    *,
    expected_document: dict[str, object],
    overwrite: bool,
) -> None:
    if output_path.exists() and not overwrite:
        raise RetrievalCorpusCliError(
            f"output already exists (pass --overwrite to replace it): {output_path}"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    created = False
    try:
        with temporary_path.open("xb") as handle:
            created = True
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_document = load_retrieval_corpus(temporary_path)
        if temporary_document != expected_document or temporary_path.read_bytes() != payload:
            raise RetrievalCorpusCliError(
                f"temporary output failed deterministic read-back: {temporary_path}"
            )
        os.replace(temporary_path, output_path)
        created = False
    except Exception:
        if created:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def build_document(
    *,
    input_path: Path,
    output_path: Path,
    expected_input_sha256: str,
    expected_scenario_id: str,
    overwrite: bool,
) -> BuildStats:
    """Load, build, atomically write, and read back one Retrieval Corpus."""

    if input_path.resolve() == output_path.resolve():
        raise RetrievalCorpusCliError("--input and --output must resolve to different paths")
    if output_path.exists() and not overwrite:
        raise RetrievalCorpusCliError(
            f"output already exists (pass --overwrite to replace it): {output_path}"
        )

    expected_hash = _expected_hash(expected_input_sha256)
    scenario_id = _expected_scenario(expected_scenario_id)
    _assert_input_hash(input_path, expected_hash, phase="before build")
    ground_truth = load_ground_truth_document(input_path)
    actual_scenario_id = ground_truth["scenario"]["scenario_id"]
    if actual_scenario_id != scenario_id:
        raise RetrievalCorpusCliError(
            f"scenario_id mismatch for {input_path}: "
            f"expected {scenario_id!r}, got {actual_scenario_id!r}"
        )

    document = build_retrieval_corpus(
        ground_truth,
        source_ground_truth_path=_portable_path(input_path),
        source_ground_truth_sha256=expected_hash,
    )
    validate_retrieval_corpus(document)
    payload = _serialize(document)
    _assert_input_hash(input_path, expected_hash, phase="before write")
    _write_atomic(
        output_path,
        payload,
        expected_document=document,
        overwrite=overwrite,
    )

    written = load_retrieval_corpus(output_path)
    if written != document or output_path.read_bytes() != payload:
        raise RetrievalCorpusCliError(
            f"generated output failed deterministic read-back: {output_path}"
        )
    _assert_input_hash(input_path, expected_hash, phase="after write")

    chunk_counts: dict[str, int] = {}
    for chunk in document["chunks"]:
        chunk_type = str(chunk["chunk_type"])
        chunk_counts[chunk_type] = chunk_counts.get(chunk_type, 0) + 1
    return BuildStats(
        scenario_id=str(document["scenario_id"]),
        schema_version=str(document["schema_version"]),
        corpus_id=str(document["corpus_id"]),
        review_status=str(document["review"]["review_status"]),
        total_chunks=len(document["chunks"]),
        chunk_counts=dict(sorted(chunk_counts.items())),
        input_path=_portable_path(input_path),
        input_sha256=expected_hash,
        output_path=_portable_path(output_path),
        output_sha256=hashlib.sha256(payload).hexdigest(),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a validated Retrieval Corpus from Ground Truth Core."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-input-sha256", required=True)
    parser.add_argument("--expected-scenario-id", required=True)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing output file atomically.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        stats = build_document(
            input_path=args.input,
            output_path=args.output,
            expected_input_sha256=args.expected_input_sha256,
            expected_scenario_id=args.expected_scenario_id,
            overwrite=args.overwrite,
        )
    except (
        RetrievalCorpusCliError,
        GroundTruthValidationError,
        RetrievalCorpusBuildError,
        RetrievalCorpusValidationError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(asdict(stats), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
