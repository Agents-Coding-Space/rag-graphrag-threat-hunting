from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

import threat_hunting.normalization_writer as writer_module
from threat_hunting.mordor.parser import MordorParseError
from threat_hunting.normalizer import NormalizationResult, normalize_record
from threat_hunting.normalization_writer import (
    CANONICAL_EVENTS_FILENAME,
    NORMALIZATION_ISSUES_FILENAME,
    NORMALIZATION_ISSUE_SCHEMA_VERSION,
    NormalizationWriteError,
    write_normalized_file,
)
from threat_hunting.schemas.canonical_event import CANONICAL_FIELDS
from threat_hunting.schemas.canonical_mapping import SYSMON_PROVIDER


CANONICAL_FIELD_NAMES = tuple(str(field["name"]) for field in CANONICAL_FIELDS)


def _clean_record(event_id: int, *, hostname: str = "host-a") -> dict[str, object]:
    return {
        "SourceName": SYSMON_PROVIDER,
        "EventID": event_id,
        "@timestamp": "2020-01-02T03:04:05Z",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Hostname": hostname,
        "Image": f"C:\\Tools\\process-{event_id}.exe",
        "ProcessId": str(100 + event_id),
        "ProcessGuid": f"{{PROCESS-{event_id}}}",
        "QueryName": "tên-miền.example",
    }


def _write_source(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
        newline="\n",
    )


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _temporary_artifacts(output: Path) -> list[Path]:
    return [path for path in output.iterdir() if path.name.startswith(".")]


def test_writes_two_events_in_order_with_exact_fields_and_stats(tmp_path: Path) -> None:
    source = tmp_path / "small.jsonl"
    output = tmp_path / "output"
    _write_source(source, [_clean_record(22), _clean_record(22, hostname="host-b")])

    stats = write_normalized_file(source, "jsonl", output)
    events = _read_jsonl(stats.canonical_events_path)

    assert stats.input_record_count == 2
    assert stats.output_event_count == 2
    assert stats.dropped_record_count == 0
    assert stats.event_with_issues_count == 0
    assert stats.issue_count == 0
    assert stats.issue_counts == {}
    assert stats.timestamp_null_count == 0
    assert [event["raw_record_ref"] for event in events] == [
        "jsonl:line:1",
        "jsonl:line:2",
    ]
    assert all(tuple(event) == CANONICAL_FIELD_NAMES for event in events)
    assert all(event["source_file"] == source.name for event in events)
    assert stats.canonical_events_path.name == CANONICAL_EVENTS_FILENAME
    assert stats.normalization_issues_path.name == NORMALIZATION_ISSUES_FILENAME
    assert stats.canonical_events_path.read_bytes().endswith(b"\n")


def test_event_with_two_issues_writes_two_issue_lines(tmp_path: Path) -> None:
    source = tmp_path / "issues.jsonl"
    output = tmp_path / "output"
    _write_source(
        source,
        [
            {
                "SourceName": "Unknown-Provider",
                "EventID": 999,
                "Channel": "Unknown/Operational",
                "Hostname": "unknown-host",
            }
        ],
    )

    stats = write_normalized_file(source, "jsonl", output)
    events = _read_jsonl(stats.canonical_events_path)
    issues = _read_jsonl(stats.normalization_issues_path)

    assert len(events) == 1
    assert stats.event_with_issues_count == 1
    assert stats.issue_count == 2
    assert stats.issue_counts == {
        "missing_expected_source": 1,
        "unsupported_context": 1,
    }
    assert [issue["raw_record_ref"] for issue in issues] == [
        "jsonl:line:1",
        "jsonl:line:1",
    ]
    assert {issue["code"] for issue in issues} == {
        "missing_expected_source",
        "unsupported_context",
    }
    assert all(
        issue["schema_version"] == NORMALIZATION_ISSUE_SCHEMA_VERSION
        for issue in issues
    )
    assert all(issue["source_file"] == source.name for issue in issues)
    assert "issues" not in events[0]


def test_clean_event_creates_empty_issue_file(tmp_path: Path) -> None:
    source = tmp_path / "clean.jsonl"
    output = tmp_path / "output"
    _write_source(source, [_clean_record(22)])

    stats = write_normalized_file(source, "jsonl", output)

    assert stats.issue_count == 0
    assert stats.normalization_issues_path.exists()
    assert stats.normalization_issues_path.read_bytes() == b""


def test_unicode_is_unescaped_and_output_is_deterministic(tmp_path: Path) -> None:
    source = tmp_path / "unicode.jsonl"
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    _write_source(source, [_clean_record(22, hostname="máy-chủ")])

    first = write_normalized_file(source, "jsonl", first_output)
    second = write_normalized_file(source, "jsonl", second_output)

    first_bytes = first.canonical_events_path.read_bytes()
    assert first_bytes == second.canonical_events_path.read_bytes()
    assert first.normalization_issues_path.read_bytes() == (
        second.normalization_issues_path.read_bytes()
    )
    assert "máy-chủ".encode() in first_bytes
    assert b"\\u00" not in first_bytes


def test_overwrite_false_rejects_existing_outputs_without_changes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    _write_source(source, [_clean_record(22)])
    first = write_normalized_file(source, "jsonl", output)
    canonical_before = first.canonical_events_path.read_bytes()
    issues_before = first.normalization_issues_path.read_bytes()

    with pytest.raises(NormalizationWriteError, match="overwrite=True"):
        write_normalized_file(source, "jsonl", output)

    assert first.canonical_events_path.read_bytes() == canonical_before
    assert first.normalization_issues_path.read_bytes() == issues_before
    assert _temporary_artifacts(output) == []


def test_overwrite_true_replaces_both_outputs(tmp_path: Path) -> None:
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    _write_source(source, [_clean_record(22, hostname="old-host")])
    write_normalized_file(source, "jsonl", output)
    _write_source(source, [_clean_record(22, hostname="new-host")])

    stats = write_normalized_file(source, "jsonl", output, overwrite=True)

    assert _read_jsonl(stats.canonical_events_path)[0]["host"] == "new-host"
    assert stats.normalization_issues_path.read_bytes() == b""
    assert _temporary_artifacts(output) == []


def test_midstream_failure_leaves_no_outputs_or_temporary_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    _write_source(source, [_clean_record(22)])

    def failing_iterator(*args: object, **kwargs: object):
        yield normalize_record(
            _clean_record(22),
            raw_record_ref="jsonl:line:1",
            source_file=source.name,
        )
        raise RuntimeError("simulated stream failure")

    monkeypatch.setattr(writer_module, "iter_normalized_records", failing_iterator)

    with pytest.raises(RuntimeError, match="simulated stream failure"):
        write_normalized_file(source, "jsonl", output)

    assert list(output.iterdir()) == []


def test_generation_failure_preserves_old_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    output.mkdir()
    canonical = output / CANONICAL_EVENTS_FILENAME
    issues = output / NORMALIZATION_ISSUES_FILENAME
    canonical.write_bytes(b"old canonical\n")
    issues.write_bytes(b"old issues\n")

    def failing_iterator(*args: object, **kwargs: object):
        raise RuntimeError("generation failed")
        yield  # pragma: no cover

    monkeypatch.setattr(writer_module, "iter_normalized_records", failing_iterator)

    with pytest.raises(RuntimeError, match="generation failed"):
        write_normalized_file(source, "jsonl", output, overwrite=True)

    assert canonical.read_bytes() == b"old canonical\n"
    assert issues.read_bytes() == b"old issues\n"
    assert _temporary_artifacts(output) == []


def test_validation_failure_preserves_old_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    _write_source(source, [_clean_record(22)])
    first = write_normalized_file(source, "jsonl", output)
    canonical_before = first.canonical_events_path.read_bytes()
    issues_before = first.normalization_issues_path.read_bytes()

    def fail_validation(path: Path, expected_count: int) -> int:
        raise NormalizationWriteError("validation failed")

    monkeypatch.setattr(writer_module, "_validate_issue_jsonl", fail_validation)

    with pytest.raises(NormalizationWriteError, match="validation failed"):
        write_normalized_file(source, "jsonl", output, overwrite=True)

    assert first.canonical_events_path.read_bytes() == canonical_before
    assert first.normalization_issues_path.read_bytes() == issues_before
    assert _temporary_artifacts(output) == []


def test_publish_failure_rolls_back_new_final_and_cleans_temporary_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    _write_source(source, [_clean_record(22)])
    real_replace = writer_module.os.replace

    def fail_second_publish(source_path: Path, destination_path: Path) -> None:
        if Path(destination_path).name == NORMALIZATION_ISSUES_FILENAME:
            raise OSError("second publish failed")
        real_replace(source_path, destination_path)

    monkeypatch.setattr(writer_module.os, "replace", fail_second_publish)

    with pytest.raises(OSError, match="second publish failed"):
        write_normalized_file(source, "jsonl", output)

    assert list(output.iterdir()) == []


def test_malformed_source_fails_without_outputs(tmp_path: Path) -> None:
    source = tmp_path / "malformed.jsonl"
    output = tmp_path / "output"
    source.write_text(
        json.dumps(_clean_record(22)) + "\n{malformed later line}\n",
        encoding="utf-8",
    )

    with pytest.raises(MordorParseError, match="line 2"):
        write_normalized_file(source, "jsonl", output)

    assert list(output.iterdir()) == []


def test_source_sha256_is_unchanged_and_one_to_one_is_reported(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    _write_source(source, [_clean_record(22), _clean_record(22)])
    before = hashlib.sha256(source.read_bytes()).hexdigest()

    stats = write_normalized_file(source, "jsonl", output)

    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert stats.input_record_count == stats.output_event_count == 2
    assert stats.dropped_record_count == 0


def test_writer_consumes_iterator_incrementally_without_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    writes: list[str] = []
    real_write_json_line = writer_module._write_json_line

    first = normalize_record(
        _clean_record(22),
        raw_record_ref="jsonl:line:1",
        source_file=source.name,
    )
    second = normalize_record(
        _clean_record(22),
        raw_record_ref="jsonl:line:2",
        source_file=source.name,
    )

    def streaming_iterator(*args: object, **kwargs: object):
        writes.append("yield-1")
        yield first
        assert writes == ["yield-1", "write-jsonl:line:1"]
        writes.append("yield-2")
        yield second

    def observing_write(stream: object, payload: dict[str, object]) -> None:
        raw_record_ref = payload.get("raw_record_ref")
        if isinstance(raw_record_ref, str) and "schema_version" not in payload:
            writes.append(f"write-{raw_record_ref}")
        real_write_json_line(stream, payload)

    monkeypatch.setattr(writer_module, "iter_normalized_records", streaming_iterator)
    monkeypatch.setattr(writer_module, "_write_json_line", observing_write)

    stats = write_normalized_file(source, "jsonl", output)

    assert writes == [
        "yield-1",
        "write-jsonl:line:1",
        "yield-2",
        "write-jsonl:line:2",
    ]
    assert stats.output_event_count == 2
    assert "list(" not in inspect.getsource(write_normalized_file)


def test_validation_rejects_missing_event_line_and_does_not_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    result = NormalizationResult(
        event=normalize_record(
            _clean_record(22),
            raw_record_ref="jsonl:line:1",
            source_file=source.name,
        ).event,
        issues=(),
    )

    def one_result(*args: object, **kwargs: object):
        yield result

    def discard_event_line(stream: object, payload: dict[str, object]) -> None:
        if "schema_version" in payload:
            writer_module.json.dump(payload, stream)
            stream.write("\n")

    monkeypatch.setattr(writer_module, "iter_normalized_records", one_result)
    monkeypatch.setattr(writer_module, "_write_json_line", discard_event_line)

    with pytest.raises(NormalizationWriteError, match="count mismatch"):
        write_normalized_file(source, "jsonl", output)

    assert list(output.iterdir()) == []
