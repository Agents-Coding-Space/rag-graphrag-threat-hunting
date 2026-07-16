"""Deterministic, collision-safe JSON reporting."""

from __future__ import annotations

from collections import defaultdict
import json
import os
from pathlib import Path
import re
import uuid
from typing import Iterable

from .schemas.canonical_event import canonical_schema_document


class ReportingError(ValueError):
    """Raised when reports cannot be written safely."""


def _safe_stem(filename: str) -> str:
    stem = Path(filename).stem.casefold()
    safe = re.sub(r"[^a-z0-9]+", "_", stem).strip("_")
    return safe or "input"


def assign_output_directories(
    reports: Iterable[dict[str, object]],
) -> dict[str, str]:
    """Assign unique deterministic directory names to source reports."""

    report_list = list(reports)
    bases: dict[str, list[dict[str, object]]] = defaultdict(list)
    for report in report_list:
        source = dict(report["source"])
        base = f"{_safe_stem(str(source['filename']))}--{str(source['sha256'])[:12]}"
        bases[base].append(report)

    assigned: dict[str, str] = {}
    for base in sorted(bases):
        group = sorted(
            bases[base],
            key=lambda report: str(dict(report["source"])["repository_relative_path"]).casefold(),
        )
        for index, report in enumerate(group, start=1):
            source_path = str(dict(report["source"])["repository_relative_path"])
            assigned[source_path] = base if len(group) == 1 else f"{base}--{index:02d}"
    return assigned


def _write_json_atomic(path: Path, payload: object, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise ReportingError(f"Output already exists (use --overwrite): {path}")

    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_reports(
    output_directory: Path,
    experiment_id: str,
    reports: Iterable[dict[str, object]],
    overwrite: bool = False,
) -> dict[str, object]:
    """Write one inspection file per source plus shared schema and manifest."""

    report_list = list(reports)
    assignments = assign_output_directories(report_list)
    output_directory.mkdir(parents=True, exist_ok=True)

    canonical_path = output_directory / "canonical_schema.json"
    _write_json_atomic(canonical_path, canonical_schema_document(), overwrite)

    file_entries: list[dict[str, object]] = []
    for report in sorted(
        report_list,
        key=lambda item: str(dict(item["source"])["repository_relative_path"]).casefold(),
    ):
        source = dict(report["source"])
        relative_source = str(source["repository_relative_path"])
        directory_name = assignments[relative_source]
        relative_report = Path("files") / directory_name / "inspection.json"
        _write_json_atomic(output_directory / relative_report, report, overwrite)
        file_entries.append(
            {
                "input": relative_source,
                "status": report["status"],
                "record_count_check": report["record_count_check"],
                "report": relative_report.as_posix(),
            }
        )

    failed_count = sum(entry["status"] != "completed" for entry in file_entries)
    manifest: dict[str, object] = {
        "schema_version": "mordor-inspection-run/v1",
        "experiment_id": experiment_id,
        "status": "completed" if failed_count == 0 else "completed_with_errors",
        "input_count": len(file_entries),
        "successful_count": len(file_entries) - failed_count,
        "failed_count": failed_count,
        "canonical_schema": canonical_path.name,
        "files": file_entries,
    }
    _write_json_atomic(output_directory / "manifest.json", manifest, overwrite)
    return manifest

