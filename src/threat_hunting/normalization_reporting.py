"""Preflight, execute, and report deterministic normalization runs."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import uuid

from threat_hunting.discovery import DiscoveredInput, discover_inputs
from threat_hunting.mordor.format_detection import FormatDetection, detect_format
from threat_hunting.normalization_writer import (
    CANONICAL_EVENTS_FILENAME,
    NORMALIZATION_ISSUES_FILENAME,
    NormalizationWriteStats,
    write_normalized_file,
)
from threat_hunting.reporting import assign_output_directories
from threat_hunting.run_spec import RunSpec
from threat_hunting.schemas.canonical_event import (
    CANONICAL_SCHEMA_VERSION,
    canonical_schema_document,
)


NORMALIZATION_RUN_SCHEMA_VERSION = "normalization-run/v1"
CANONICAL_SCHEMA_FILENAME = "canonical_schema.json"
NORMALIZATION_MANIFEST_FILENAME = "manifest.json"
NORMALIZATION_SUMMARY_FILENAME = "summary.md"


class NormalizationRunError(RuntimeError):
    """Raised when a normalization run cannot complete safely."""


@dataclass(frozen=True)
class PreparedNormalizationInput:
    """One fully inspected source and all deterministic output paths."""

    source: DiscoveredInput
    detection: FormatDetection
    source_size_bytes: int
    source_sha256: str
    output_directory: Path
    canonical_events_relative_path: str
    normalization_issues_relative_path: str


@dataclass(frozen=True)
class NormalizationPreflight:
    """A complete run plan produced before any output is written."""

    experiment_id: str
    output_directory: Path
    inputs: tuple[PreparedNormalizationInput, ...]


def _file_sha256(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise NormalizationRunError(f"Cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _relative_to_run(path: Path, output_directory: Path) -> str:
    return path.relative_to(output_directory).as_posix()


def preflight_normalization_run(
    run_spec: RunSpec,
    search_root: Path,
    output_directory: Path,
    *,
    overwrite: bool = False,
) -> NormalizationPreflight:
    """Resolve and validate every source and output before writing anything."""

    resolved_output = output_directory.resolve()
    sources = discover_inputs(run_spec.inputs, search_root)

    detected: list[tuple[DiscoveredInput, FormatDetection, int, str]] = []
    for source in sources:
        detection = detect_format(source.path)
        detected.append(
            (
                source,
                detection,
                source.path.stat().st_size,
                _file_sha256(source.path),
            )
        )

    missing_baselines = sorted(
        source.requested_value
        for source, _, _, _ in detected
        if source.expected_record_count is None
    )
    if missing_baselines:
        raise NormalizationRunError(
            "Normalization requires expected_record_count for every input: "
            + ", ".join(missing_baselines)
        )

    assignment_inputs = [
        {
            "source": {
                "filename": source.path.name,
                "repository_relative_path": source.repository_relative_path,
                "sha256": source_sha256,
            }
        }
        for source, _, _, source_sha256 in detected
    ]
    assignments = assign_output_directories(assignment_inputs)

    prepared: list[PreparedNormalizationInput] = []
    output_paths: list[Path] = [
        resolved_output / CANONICAL_SCHEMA_FILENAME,
        resolved_output / NORMALIZATION_SUMMARY_FILENAME,
        resolved_output / NORMALIZATION_MANIFEST_FILENAME,
    ]
    for source, detection, source_size, source_sha256 in sorted(
        detected,
        key=lambda item: item[0].repository_relative_path.casefold(),
    ):
        directory_name = assignments[source.repository_relative_path]
        per_file_directory = resolved_output / "files" / directory_name
        canonical_path = per_file_directory / CANONICAL_EVENTS_FILENAME
        issues_path = per_file_directory / NORMALIZATION_ISSUES_FILENAME
        output_paths.extend((canonical_path, issues_path))
        prepared.append(
            PreparedNormalizationInput(
                source=source,
                detection=detection,
                source_size_bytes=source_size,
                source_sha256=source_sha256,
                output_directory=per_file_directory,
                canonical_events_relative_path=_relative_to_run(
                    canonical_path, resolved_output
                ),
                normalization_issues_relative_path=_relative_to_run(
                    issues_path, resolved_output
                ),
            )
        )

    if len(output_paths) != len(set(output_paths)):
        raise NormalizationRunError("Normalization output paths collide")
    if not overwrite:
        existing = sorted(
            (path for path in output_paths if path.exists()),
            key=lambda path: path.as_posix().casefold(),
        )
        if existing:
            raise NormalizationRunError(
                "Output already exists; use --overwrite: "
                + ", ".join(str(path) for path in existing)
            )

    return NormalizationPreflight(
        experiment_id=run_spec.experiment_id,
        output_directory=resolved_output,
        inputs=tuple(prepared),
    )


def _output_metadata(path: Path) -> tuple[int, str]:
    try:
        return path.stat().st_size, _file_sha256(path)
    except OSError as exc:
        raise NormalizationRunError(
            f"Cannot inspect normalized output {path}: {exc}"
        ) from exc


def _file_manifest_entry(
    prepared: PreparedNormalizationInput,
    stats: NormalizationWriteStats,
) -> dict[str, object]:
    expected = prepared.source.expected_record_count
    baseline_matches = expected == stats.input_record_count
    canonical_size, canonical_sha256 = _output_metadata(
        stats.canonical_events_path
    )
    issues_size, issues_sha256 = _output_metadata(
        stats.normalization_issues_path
    )
    return {
        "input": prepared.source.requested_value,
        "repository_relative_path": prepared.source.repository_relative_path,
        "source_filename": prepared.source.path.name,
        "source_size_bytes": prepared.source_size_bytes,
        "source_sha256": prepared.source_sha256,
        "source_format": prepared.detection.source_format,
        "status": "completed" if baseline_matches else "baseline_mismatch",
        "expected_record_count": expected,
        "input_record_count": stats.input_record_count,
        "output_event_count": stats.output_event_count,
        "dropped_record_count": stats.dropped_record_count,
        "event_with_issues_count": stats.event_with_issues_count,
        "issue_count": stats.issue_count,
        "issue_counts": dict(sorted(stats.issue_counts.items())),
        "timestamp_null_count": stats.timestamp_null_count,
        "canonical_events": prepared.canonical_events_relative_path,
        "canonical_events_size_bytes": canonical_size,
        "canonical_events_sha256": canonical_sha256,
        "normalization_issues": prepared.normalization_issues_relative_path,
        "normalization_issues_size_bytes": issues_size,
        "normalization_issues_sha256": issues_sha256,
    }


def build_normalization_manifest(
    experiment_id: str,
    file_entries: list[dict[str, object]],
) -> dict[str, object]:
    """Build a deterministic run manifest from validated per-file statistics."""

    ordered = sorted(
        (dict(entry) for entry in file_entries),
        key=lambda entry: str(entry["repository_relative_path"]).casefold(),
    )
    for entry in ordered:
        entry["issue_counts"] = dict(sorted(dict(entry["issue_counts"]).items()))
    successful_count = sum(entry["status"] == "completed" for entry in ordered)
    failed_count = len(ordered) - successful_count
    total_input = sum(int(entry["input_record_count"]) for entry in ordered)
    total_output = sum(int(entry["output_event_count"]) for entry in ordered)
    total_dropped = sum(int(entry["dropped_record_count"]) for entry in ordered)
    status = (
        "completed"
        if failed_count == 0 and total_input == total_output and total_dropped == 0
        else "completed_with_errors"
    )
    return {
        "schema_version": NORMALIZATION_RUN_SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "status": status,
        "canonical_schema_version": CANONICAL_SCHEMA_VERSION,
        "canonical_schema": CANONICAL_SCHEMA_FILENAME,
        "summary": NORMALIZATION_SUMMARY_FILENAME,
        "input_count": len(ordered),
        "successful_count": successful_count,
        "failed_count": failed_count,
        "total_input_records": total_input,
        "total_output_events": total_output,
        "total_dropped_records": total_dropped,
        "total_issue_count": sum(int(entry["issue_count"]) for entry in ordered),
        "total_events_with_issues": sum(
            int(entry["event_with_issues_count"]) for entry in ordered
        ),
        "files": ordered,
    }


def normalization_summary_markdown(manifest: dict[str, object]) -> str:
    """Render a short deterministic Vietnamese summary from manifest data."""

    lines = [
        f"# Báo cáo normalization: {manifest['experiment_id']}",
        "",
        "> Đây là kết quả normalization, chưa phải phát hiện hoặc kết luận tấn công.",
        "",
        "| Dataset | Input records | Canonical events | Dropped | Events có issue | Total issues | Timestamp null | Status |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    files = list(manifest["files"])
    for raw_entry in files:
        entry = dict(raw_entry)
        lines.append(
            "| "
            + " | ".join(
                str(value)
                for value in (
                    entry["source_filename"],
                    entry["input_record_count"],
                    entry["output_event_count"],
                    entry["dropped_record_count"],
                    entry["event_with_issues_count"],
                    entry["issue_count"],
                    entry["timestamp_null_count"],
                    entry["status"],
                )
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Tổng cộng",
            "",
            f"- Input records: {manifest['total_input_records']}",
            f"- Canonical events: {manifest['total_output_events']}",
            f"- Dropped records: {manifest['total_dropped_records']}",
            f"- Events có issue: {manifest['total_events_with_issues']}",
            f"- Total issues: {manifest['total_issue_count']}",
            "",
            "## Issues và integrity theo dataset",
            "",
        ]
    )
    for raw_entry in files:
        entry = dict(raw_entry)
        issue_counts = dict(entry["issue_counts"])
        rendered_issues = (
            ", ".join(
                f"`{code}`: {issue_counts[code]}" for code in sorted(issue_counts)
            )
            if issue_counts
            else "không có issue"
        )
        lines.extend(
            [
                f"### {entry['source_filename']}",
                "",
                f"- Issue counts: {rendered_issues}",
                f"- Raw SHA-256: `{entry['source_sha256']}`",
                f"- Canonical events: [{entry['canonical_events']}]({entry['canonical_events']})",
                f"- Normalization issues: [{entry['normalization_issues']}]({entry['normalization_issues']})",
                "",
            ]
        )

    lines.extend(
        [
            "`timestamp_conflict` là review warning khi các timestamp candidates lệch quá policy threshold; không làm record bị loại.",
            "",
            "`unsupported_context` nghĩa là provider/Event ID chưa có mapping chuyên biệt; base fields vẫn được giữ khi hợp lệ.",
            "",
            "Pipeline không filtering hoặc deduplication. Event có issue vẫn được ghi theo contract 1:1.",
            "",
        ]
    )
    return "\n".join(lines)


def _temporary_path(final_path: Path, suffix: str) -> Path:
    return final_path.with_name(
        f".{final_path.name}.{uuid.uuid4().hex}.{suffix}"
    )


def _stage_bytes(final_path: Path, payload: bytes) -> Path:
    temporary = _temporary_path(final_path, "tmp")
    with temporary.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return temporary


def _publish_reports(
    staged: tuple[tuple[Path, Path], ...],
    *,
    overwrite: bool,
) -> None:
    backups: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        if overwrite:
            for _, final_path in staged:
                if final_path.exists():
                    backup = _temporary_path(final_path, "bak")
                    os.replace(final_path, backup)
                    backups.append((final_path, backup))
        else:
            existing = [final for _, final in staged if final.exists()]
            if existing:
                raise NormalizationRunError(
                    "Report output already exists; use --overwrite: "
                    + ", ".join(str(path) for path in existing)
                )
        for temporary, final_path in staged:
            os.replace(temporary, final_path)
            published.append(final_path)
    except Exception:
        for final_path in reversed(published):
            if final_path.exists():
                final_path.unlink()
        for final_path, backup in reversed(backups):
            if backup.exists():
                os.replace(backup, final_path)
        raise
    else:
        for _, backup in backups:
            if backup.exists():
                backup.unlink()


def write_normalization_reports(
    output_directory: Path,
    manifest: dict[str, object],
    *,
    overwrite: bool = False,
) -> None:
    """Atomically publish schema, summary, and manifest, with manifest last."""

    output_directory.mkdir(parents=True, exist_ok=True)
    schema_path = output_directory / CANONICAL_SCHEMA_FILENAME
    summary_path = output_directory / NORMALIZATION_SUMMARY_FILENAME
    manifest_path = output_directory / NORMALIZATION_MANIFEST_FILENAME
    final_paths = (schema_path, summary_path, manifest_path)
    if not overwrite:
        existing = [path for path in final_paths if path.exists()]
        if existing:
            raise NormalizationRunError(
                "Report output already exists; use --overwrite: "
                + ", ".join(str(path) for path in existing)
            )

    schema_bytes = (
        json.dumps(
            canonical_schema_document(),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    ).encode("utf-8")
    summary_bytes = normalization_summary_markdown(manifest).encode("utf-8")
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    ).encode("utf-8")
    json.loads(schema_bytes)
    json.loads(manifest_bytes)

    staged_paths: list[Path] = []
    try:
        staged_list: list[tuple[Path, Path]] = []
        for final_path, payload in (
            (schema_path, schema_bytes),
            (summary_path, summary_bytes),
            (manifest_path, manifest_bytes),
        ):
            temporary = _stage_bytes(final_path, payload)
            staged_paths.append(temporary)
            staged_list.append((temporary, final_path))
        _publish_reports(tuple(staged_list), overwrite=overwrite)
    finally:
        for temporary in staged_paths:
            if temporary.exists():
                temporary.unlink()


def run_normalization(
    run_spec: RunSpec,
    search_root: Path,
    output_directory: Path,
    *,
    overwrite: bool = False,
) -> dict[str, object]:
    """Execute one preflighted streaming normalization run."""

    preflight = preflight_normalization_run(
        run_spec,
        search_root,
        output_directory,
        overwrite=overwrite,
    )
    entries: list[dict[str, object]] = []
    for prepared in preflight.inputs:
        try:
            stats = write_normalized_file(
                prepared.source.path,
                prepared.detection.source_format,
                prepared.output_directory,
                overwrite=overwrite,
            )
        except Exception as exc:
            raise NormalizationRunError(
                "Normalization writer failed for "
                f"{prepared.source.repository_relative_path}: {exc}"
            ) from exc
        source_sha256_after = _file_sha256(prepared.source.path)
        if source_sha256_after != prepared.source_sha256:
            raise NormalizationRunError(
                "Source SHA-256 changed during normalization for "
                f"{prepared.source.repository_relative_path}: "
                f"before={prepared.source_sha256}, after={source_sha256_after}"
            )
        entries.append(_file_manifest_entry(prepared, stats))

    manifest = build_normalization_manifest(preflight.experiment_id, entries)
    try:
        write_normalization_reports(
            preflight.output_directory,
            manifest,
            overwrite=overwrite,
        )
    except Exception as exc:
        raise NormalizationRunError(
            f"Normalization report generation failed: {exc}"
        ) from exc
    return manifest
