#!/usr/bin/env python3
"""Build a validated, reviewable Knowledge Graph from Ground Truth Core."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPOSITORY_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from threat_hunting.ground_truth import load_ground_truth_document  # noqa: E402
from threat_hunting.graph import (  # noqa: E402
    build_knowledge_graph,
    load_knowledge_graph,
    validate_knowledge_graph,
)


_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")


class KnowledgeGraphCliError(ValueError):
    """Raised when CLI inputs cannot safely produce a Knowledge Graph."""


@dataclass(frozen=True)
class BuildStats:
    schema_version: str
    graph_id: str
    scenario_id: str
    review_status: str
    node_count: int
    edge_count: int
    node_type_counts: dict[str, int]
    edge_type_counts: dict[str, int]
    input_path: str
    input_sha256: str
    output_path: str
    output_sha256: str


def _expected_hash(value: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise KnowledgeGraphCliError(
            "--ground-truth-sha256 must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _expected_scenario(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise KnowledgeGraphCliError("--expected-scenario-id must not be empty")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise KnowledgeGraphCliError(f"cannot hash Ground Truth {path}: {exc}") from exc
    return digest.hexdigest()


def _assert_input_hash(path: Path, expected_hash: str, *, phase: str) -> None:
    actual_hash = _sha256_file(path)
    if actual_hash != expected_hash:
        raise KnowledgeGraphCliError(
            f"Ground Truth SHA-256 mismatch {phase} for {path}: "
            f"expected {expected_hash}, got {actual_hash}"
        )


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return path.name


def _temporary_paths(output_path: Path) -> tuple[Path, Path]:
    return (
        output_path.with_name(f".{output_path.name}.tmp"),
        output_path.with_name(f".{output_path.name}.backup.tmp"),
    )


def _paths_alias(left: Path, right: Path) -> bool:
    if left.resolve() == right.resolve():
        return True
    return left.exists() and right.exists() and left.samefile(right)


def _validate_paths(ground_truth_path: Path, output_path: Path) -> None:
    temporary_path, backup_path = _temporary_paths(output_path)
    if any(
        _paths_alias(ground_truth_path, target)
        for target in (output_path, temporary_path, backup_path)
    ):
        raise KnowledgeGraphCliError(
            f"--output and its temporary paths must differ from Ground Truth: "
            f"{output_path}; input {ground_truth_path}"
        )
    if output_path.is_symlink():
        raise KnowledgeGraphCliError(
            f"--output must not be a symbolic link: {output_path}"
        )
    if output_path.exists() and not output_path.is_file():
        raise KnowledgeGraphCliError(f"--output must be a file: {output_path}")


def _serialize(document: dict[str, Any]) -> bytes:
    try:
        text = json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False)
        return (text + "\n").encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError) as exc:
        raise KnowledgeGraphCliError(
            f"cannot serialize Knowledge Graph as UTF-8 JSON: {exc}"
        ) from exc


def _write_temporary_payload(path: Path, payload: bytes) -> None:
    """Create an owned file exclusively; leave an existing file untouched."""
    created = False
    try:
        with path.open("xb") as handle:
            created = True
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception as exc:
        if created:
            try:
                path.unlink(missing_ok=True)
            except OSError as cleanup_exc:
                raise KnowledgeGraphCliError(
                    f"cannot clean temporary output {path}: {cleanup_exc}; "
                    f"original write failure: {exc}"
                ) from exc
        raise KnowledgeGraphCliError(
            f"cannot write temporary output {path}: {exc}"
        ) from exc


def _write_atomic(
    output_path: Path,
    payload: bytes,
    *,
    expected_document: dict[str, Any],
    overwrite: bool,
    ground_truth_path: Path,
    expected_hash: str,
) -> None:
    """Keep the previous output until final read-back and input checks pass."""
    _validate_paths(ground_truth_path, output_path)
    if output_path.exists() and not overwrite:
        raise KnowledgeGraphCliError(
            f"output already exists (pass --overwrite to replace it): {output_path}"
        )
    temporary_path, backup_path = _temporary_paths(output_path)
    for reserved_path in (temporary_path, backup_path):
        if reserved_path.exists() or reserved_path.is_symlink():
            raise KnowledgeGraphCliError(
                f"temporary path already exists; leaving it unchanged: {reserved_path}"
            )

    previous_bytes = output_path.read_bytes() if output_path.exists() else None
    owned_paths: set[Path] = set()
    installed = False
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if previous_bytes is not None:
            _write_temporary_payload(backup_path, previous_bytes)
            owned_paths.add(backup_path)
        _write_temporary_payload(temporary_path, payload)
        owned_paths.add(temporary_path)
        temporary_document = load_knowledge_graph(temporary_path)
        if (
            temporary_document != expected_document
            or temporary_path.read_bytes() != payload
        ):
            raise KnowledgeGraphCliError(
                f"temporary output failed deterministic read-back: {temporary_path}"
            )
        if output_path.exists() and not overwrite:
            raise KnowledgeGraphCliError(
                f"output already exists (pass --overwrite to replace it): {output_path}"
            )
        os.replace(temporary_path, output_path)
        owned_paths.remove(temporary_path)
        installed = True
        written = load_knowledge_graph(output_path)
        if written != expected_document or output_path.read_bytes() != payload:
            raise KnowledgeGraphCliError(
                f"generated output failed deterministic read-back: {output_path}"
            )
        _assert_input_hash(ground_truth_path, expected_hash, phase="after write")
        if backup_path in owned_paths:
            backup_path.unlink()
            owned_paths.remove(backup_path)
    except Exception as exc:
        if installed:
            try:
                if previous_bytes is None:
                    output_path.unlink(missing_ok=True)
                else:
                    os.replace(backup_path, output_path)
                    owned_paths.remove(backup_path)
            except OSError as rollback_exc:
                # Retain the backup when restoration is impossible, for recovery.
                owned_paths.discard(backup_path)
                raise KnowledgeGraphCliError(
                    f"cannot restore previous output {output_path}: {rollback_exc}; "
                    f"original failure: {exc}; backup: {backup_path}"
                ) from exc
        raise
    finally:
        for owned_path in owned_paths:
            owned_path.unlink(missing_ok=True)


def build_document(
    *,
    ground_truth_path: Path,
    ground_truth_sha256: str,
    expected_scenario_id: str,
    output_path: Path,
    overwrite: bool,
) -> BuildStats:
    """Load, build, validate, atomically write, and read back one graph."""
    expected_hash = _expected_hash(ground_truth_sha256)
    scenario_id = _expected_scenario(expected_scenario_id)
    _validate_paths(ground_truth_path, output_path)
    if output_path.exists() and not overwrite:
        raise KnowledgeGraphCliError(
            f"output already exists (pass --overwrite to replace it): {output_path}"
        )
    _assert_input_hash(ground_truth_path, expected_hash, phase="before read")
    ground_truth = load_ground_truth_document(ground_truth_path)
    actual_scenario_id = ground_truth["scenario"]["scenario_id"]
    if actual_scenario_id != scenario_id:
        raise KnowledgeGraphCliError(
            f"scenario_id mismatch for {ground_truth_path}: "
            f"expected {scenario_id!r}, got {actual_scenario_id!r}"
        )
    document = build_knowledge_graph(
        ground_truth,
        ground_truth_path=_portable_path(ground_truth_path),
        ground_truth_sha256=expected_hash,
    )
    validate_knowledge_graph(document)
    payload = _serialize(document)
    stats = BuildStats(
        schema_version=document["schema_version"],
        graph_id=document["graph_id"],
        scenario_id=document["scenario_id"],
        review_status=document["review"]["status"],
        node_count=len(document["nodes"]),
        edge_count=len(document["edges"]),
        node_type_counts=dict(sorted(Counter(
            node["node_type"] for node in document["nodes"]
        ).items())),
        edge_type_counts=dict(sorted(Counter(
            edge["edge_type"] for edge in document["edges"]
        ).items())),
        input_path=_portable_path(ground_truth_path),
        input_sha256=expected_hash,
        output_path=_portable_path(output_path),
        output_sha256=hashlib.sha256(payload).hexdigest(),
    )
    _assert_input_hash(ground_truth_path, expected_hash, phase="before write")
    _write_atomic(
        output_path,
        payload,
        expected_document=document,
        overwrite=overwrite,
        ground_truth_path=ground_truth_path,
        expected_hash=expected_hash,
    )
    return stats


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a validated Knowledge Graph from Ground Truth Core."
    )
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--ground-truth-sha256", required=True)
    parser.add_argument("--expected-scenario-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--overwrite", action="store_true",
        help="Replace an existing output file atomically.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        stats = build_document(
            ground_truth_path=args.ground_truth,
            ground_truth_sha256=args.ground_truth_sha256,
            expected_scenario_id=args.expected_scenario_id,
            output_path=args.output,
            overwrite=args.overwrite,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(
        asdict(stats), ensure_ascii=False, sort_keys=True, allow_nan=False,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
