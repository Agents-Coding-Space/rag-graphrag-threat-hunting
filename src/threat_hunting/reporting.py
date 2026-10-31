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


SUMMARY_CANONICAL_FIELDS = (
    "timestamp",
    "host",
    "user",
    "subject_user",
    "target_user",
    "process_name",
    "parent_process_name",
    "process_id",
    "parent_process_id",
    "process_guid",
    "parent_process_guid",
    "command_line",
    "parent_command_line",
    "source_ip",
    "destination_ip",
    "destination_port",
)


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


def _write_text_atomic(path: Path, text: str, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise ReportingError(f"Output already exists (use --overwrite): {path}")

    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _distribution_summary(values: object, limit: int = 5) -> str:
    if not isinstance(values, list) or not values:
        return "Không quan sát thấy"
    rendered = []
    for item in values[:limit]:
        entry = dict(item)
        rendered.append(f"`{entry['value']}` ({entry['count']})")
    return ", ".join(rendered)


def _mapping_summary(proposal: object) -> tuple[str, str]:
    document = dict(proposal)
    status = str(document.get("status", "unavailable"))
    candidates = list(document.get("candidates", []))
    if not candidates:
        return status, "—"
    rendered = []
    for candidate in candidates[:3]:
        item = dict(candidate)
        coverage = float(item.get("context_coverage", 0.0)) * 100
        context = f"{item.get('provider', '—')} / Event ID {item.get('event_id', '—')}"
        rendered.append(
            f"`{item['source_path']}` [{context}] ({coverage:.1f}% context coverage)"
        )
    return status, ", ".join(rendered)


def _summary_markdown(
    experiment_id: str,
    reports: list[dict[str, object]],
    assignments: dict[str, str],
) -> str:
    ordered = sorted(
        reports,
        key=lambda item: str(
            dict(item["source"])["repository_relative_path"]
        ).casefold(),
    )
    lines = [
        f"# Structural inspection summary: {experiment_id}",
        "",
        "> Đây mới là structural inspection, chưa phải phát hiện tấn công, "
        "evidence extraction hoặc ground truth.",
        "",
        "## Inputs",
        "",
        "| Input | Format | Expected | Actual | Baseline | SHA-256 | "
        "Time range based on @timestamp | Distinct field paths |",
        "| --- | --- | ---: | ---: | --- | --- | --- | ---: |",
    ]
    for report in ordered:
        source = dict(report["source"])
        detection = dict(report["format_detection"])
        count_check = dict(report["record_count_check"])
        time_range = dict(report["time_range"])
        schema = dict(report["observed_schema"])
        minimum = time_range.get("minimum") or time_range.get("minimum_utc") or "—"
        maximum = time_range.get("maximum") or time_range.get("maximum_utc") or "—"
        rendered_range = minimum if minimum == maximum else f"{minimum} → {maximum}"
        row = (
            source["filename"],
            detection["format"],
            (
                count_check.get("expected")
                if count_check.get("expected") is not None
                else "—"
            ),
            count_check["actual"],
            count_check["status"],
            source["sha256"],
            rendered_range,
            schema["distinct_field_path_count"],
        )
        lines.append("| " + " | ".join(_markdown_cell(value) for value in row) + " |")

    lines.extend(
        [
            "",
            "Coverage trong bảng input được tính trên toàn file. Coverage thấp "
            "của `CommandLine`, `ParentImage` hoặc field theo Event ID không có "
            "nghĩa field đó không hữu ích trong đúng structural context.",
            "",
            "Event ID dưới đây chỉ là context để hiểu schema; không phải kết luận "
            "event hoặc dataset là tấn công.",
            "",
            "Timestamp conflict là cảnh báo về các timestamp candidates không nhất "
            "quán; không đồng nghĩa record hoặc dataset invalid.",
            "",
            "## Per-input highlights",
            "",
        ]
    )
    for report in ordered:
        source = dict(report["source"])
        relative_source = str(source["repository_relative_path"])
        distributions = dict(report["distributions"])
        mappings = dict(report["canonical_mapping_proposals"])
        warnings = list(report.get("warnings", []))
        structural_contexts = list(
            report.get("security_relevant_structural_contexts", [])
        )
        report_path = (
            Path("files") / assignments[relative_source] / "inspection.json"
        ).as_posix()
        lines.extend(
            [
                f"### {source['filename']}",
                "",
                f"- Chi tiết đầy đủ: `{report_path}`",
                "- Event ID phổ biến: "
                f"{_distribution_summary(distributions.get('event_id'))}",
                "- Provider phổ biến: "
                f"{_distribution_summary(distributions.get('provider'))}",
                "- Security-relevant structural contexts: "
                + (
                    ", ".join(
                        f"{dict(context)['label']} ({dict(context)['count']})"
                        for context in structural_contexts
                    )
                    if structural_contexts
                    else "Không quan sát thấy"
                ),
                "",
                "| Candidate canonical field | Status | "
                "Source candidates (context coverage) |",
                "| --- | --- | --- |",
            ]
        )
        for field_name in SUMMARY_CANONICAL_FIELDS:
            status, candidates = _mapping_summary(mappings.get(field_name, {}))
            lines.append(
                f"| `{field_name}` | {_markdown_cell(status)} | {candidates} |"
            )
        context_unmapped = dict(
            mappings.get("context_specific_unmapped", {"candidates": []})
        )
        unmapped = list(context_unmapped.get("candidates", []))
        if unmapped:
            rendered = ", ".join(
                f"`{dict(item)['source_path']}` ({dict(item)['source_role']})"
                for item in unmapped
            )
            lines.extend(
                [
                    "",
                    "Context-specific/unmapped process roles: " + rendered + ".",
                ]
            )
        lines.extend(["", "Warnings:"])
        if warnings:
            lines.extend(f"- {_markdown_cell(warning)}" for warning in warnings)
        else:
            lines.append("- Không có warning từ structural inspection.")
        lines.append("")

    lines.extend(
        [
            "Danh sách field đầy đủ và toàn bộ thống kê vẫn nằm trong "
            "`inspection.json` của từng file.",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(
    output_directory: Path,
    experiment_id: str,
    reports: Iterable[dict[str, object]],
    overwrite: bool = False,
) -> dict[str, object]:
    """Write per-source JSON, shared schema, manifest, and one Markdown summary."""

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

    summary_path = output_directory / "summary.md"
    _write_text_atomic(
        summary_path,
        _summary_markdown(experiment_id, report_list, assignments),
        overwrite,
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
        "summary": summary_path.name,
        "files": file_entries,
    }
    _write_json_atomic(output_directory / "manifest.json", manifest, overwrite)
    return manifest
