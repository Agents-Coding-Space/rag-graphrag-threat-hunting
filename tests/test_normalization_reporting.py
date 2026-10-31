from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import threat_hunting.normalization_reporting as reporting_module
from threat_hunting.normalization_reporting import (
    CANONICAL_SCHEMA_FILENAME,
    NORMALIZATION_MANIFEST_FILENAME,
    NORMALIZATION_RUN_SCHEMA_VERSION,
    NORMALIZATION_SUMMARY_FILENAME,
    NormalizationRunError,
    build_normalization_manifest,
    normalization_summary_markdown,
    preflight_normalization_run,
    run_normalization,
    write_normalization_reports,
)
from threat_hunting.run_spec import InputSpec, RunSpec
from threat_hunting.schemas.canonical_event import CANONICAL_SCHEMA_VERSION
from threat_hunting.schemas.canonical_mapping import SYSMON_PROVIDER


def _record(index: int) -> dict[str, object]:
    return {
        "SourceName": SYSMON_PROVIDER,
        "EventID": 22,
        "@timestamp": f"2020-01-02T03:04:{index:02d}Z",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Hostname": "máy-chủ",
        "Image": "C:\\Windows\\System32\\dns.exe",
        "ProcessId": str(100 + index),
        "ProcessGuid": f"{{GUID-{index}}}",
        "QueryName": f"example-{index}.test",
    }


def _source(root: Path, name: str, count: int = 2) -> Path:
    path = root / "data" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(_record(index), ensure_ascii=False) + "\n"
            for index in range(1, count + 1)
        ),
        encoding="utf-8",
        newline="\n",
    )
    return path


def _spec(*names: str, expected: int = 2) -> RunSpec:
    return RunSpec(
        experiment_id="fixture-run",
        inputs=tuple(InputSpec(name, expected) for name in names),
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _completed_manifest() -> dict[str, object]:
    return build_normalization_manifest(
        "fixture-run",
        [
            {
                "input": "a.json",
                "repository_relative_path": "data/a.json",
                "source_filename": "a.json",
                "source_size_bytes": 10,
                "source_sha256": "a" * 64,
                "source_format": "jsonl",
                "status": "completed",
                "expected_record_count": 1,
                "input_record_count": 1,
                "output_event_count": 1,
                "dropped_record_count": 0,
                "event_with_issues_count": 0,
                "issue_count": 0,
                "issue_counts": {},
                "timestamp_null_count": 0,
                "canonical_events": "files/a/canonical_events.jsonl",
                "canonical_events_size_bytes": 10,
                "canonical_events_sha256": "b" * 64,
                "normalization_issues": "files/a/normalization_issues.jsonl",
                "normalization_issues_size_bytes": 0,
                "normalization_issues_sha256": hashlib.sha256(b"").hexdigest(),
            }
        ],
    )


def test_preflight_resolves_multiple_inputs_and_all_paths_before_writing(
    tmp_path: Path,
) -> None:
    first = _source(tmp_path, "b.json")
    second = _source(tmp_path, "a.json")
    output = tmp_path / "outputs" / "fixture-run"

    preflight = preflight_normalization_run(
        _spec(first.name, second.name), tmp_path, output
    )

    assert not output.exists()
    assert [item.source.path.name for item in preflight.inputs] == ["a.json", "b.json"]
    assert all(item.detection.source_format == "jsonl" for item in preflight.inputs)
    for item in preflight.inputs:
        expected_prefix = _sha256(item.source.path)[:12]
        assert item.output_directory.name.endswith(f"--{expected_prefix}")
        assert item.output_directory.is_absolute()


def test_completed_run_writes_valid_manifest_schema_summary_and_relative_paths(
    tmp_path: Path,
) -> None:
    first = _source(tmp_path, "one.json")
    second = _source(tmp_path, "two.json")
    source_hashes = {path.name: _sha256(path) for path in (first, second)}
    output = tmp_path / "outputs" / "fixture-run"

    manifest = run_normalization(
        _spec(first.name, second.name), tmp_path, output
    )

    assert manifest["schema_version"] == NORMALIZATION_RUN_SCHEMA_VERSION
    assert manifest["canonical_schema_version"] == CANONICAL_SCHEMA_VERSION
    assert manifest["status"] == "completed"
    assert manifest["input_count"] == 2
    assert manifest["successful_count"] == 2
    assert manifest["failed_count"] == 0
    assert manifest["total_input_records"] == 4
    assert manifest["total_output_events"] == 4
    assert manifest["total_dropped_records"] == 0
    assert manifest["total_issue_count"] == 0
    assert manifest["total_events_with_issues"] == 0

    readback = json.loads(
        (output / NORMALIZATION_MANIFEST_FILENAME).read_text(encoding="utf-8")
    )
    assert readback == manifest
    assert {path.name: _sha256(path) for path in (first, second)} == source_hashes
    serialized = json.dumps(manifest)
    assert str(tmp_path) not in serialized
    for entry in manifest["files"]:
        assert entry["source_sha256"] == source_hashes[entry["source_filename"]]
        assert not Path(entry["canonical_events"]).is_absolute()
        assert not Path(entry["normalization_issues"]).is_absolute()
        canonical = output / entry["canonical_events"]
        issues = output / entry["normalization_issues"]
        assert entry["canonical_events_sha256"] == _sha256(canonical)
        assert entry["normalization_issues_sha256"] == _sha256(issues)
        assert entry["canonical_events_size_bytes"] == canonical.stat().st_size
        assert entry["normalization_issues_size_bytes"] == issues.stat().st_size

    schema = json.loads(
        (output / CANONICAL_SCHEMA_FILENAME).read_text(encoding="utf-8")
    )
    assert schema["schema_version"] == "canonical-event/v2"
    assert schema["normalization_contract"] == {
        "cardinality": "one_raw_record_to_one_canonical_event",
        "filtering": "none",
        "deduplication": "none",
    }
    summary = (output / NORMALIZATION_SUMMARY_FILENAME).read_text(encoding="utf-8")
    assert "Input records" in summary
    assert "Canonical events" in summary
    assert "Dropped" in summary
    assert "chưa phải phát hiện hoặc kết luận tấn công" in summary
    assert "timestamp_conflict" in summary
    assert "unsupported_context" in summary
    assert "không filtering hoặc deduplication" in summary
    assert "C:\\Windows" not in summary
    for entry in manifest["files"]:
        assert f"]({entry['canonical_events']})" in summary
        assert f"]({entry['normalization_issues']})" in summary


def test_baseline_mismatch_is_completed_with_errors_and_keeps_one_to_one(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path, "mismatch.json", count=2)
    output = tmp_path / "output"

    manifest = run_normalization(
        _spec(source.name, expected=3), tmp_path, output
    )

    assert manifest["status"] == "completed_with_errors"
    assert manifest["successful_count"] == 0
    assert manifest["failed_count"] == 1
    assert manifest["total_input_records"] == 2
    assert manifest["total_output_events"] == 2
    assert manifest["total_dropped_records"] == 0
    assert manifest["files"][0]["status"] == "baseline_mismatch"


def test_manifest_summary_and_schema_bytes_are_deterministic(tmp_path: Path) -> None:
    source = _source(tmp_path, "same.json")
    first = tmp_path / "first"
    second = tmp_path / "second"

    run_normalization(_spec(source.name), tmp_path, first)
    run_normalization(_spec(source.name), tmp_path, second)

    for filename in (
        NORMALIZATION_MANIFEST_FILENAME,
        NORMALIZATION_SUMMARY_FILENAME,
        CANONICAL_SCHEMA_FILENAME,
    ):
        assert (first / filename).read_bytes() == (second / filename).read_bytes()


def test_preflight_rejects_missing_ambiguous_duplicate_and_missing_baseline(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    with pytest.raises(Exception, match="not found"):
        preflight_normalization_run(_spec("missing.json"), tmp_path, output)

    for directory in ("a", "b"):
        path = tmp_path / directory / "same.json"
        path.parent.mkdir()
        path.write_text("{}", encoding="utf-8")
    with pytest.raises(Exception, match="ambiguous"):
        preflight_normalization_run(_spec("same.json"), tmp_path, output)

    unique = _source(tmp_path, "unique.json")
    duplicate_spec = RunSpec(
        "fixture-run",
        (InputSpec(unique.name, 2), InputSpec("data/unique.json", 2)),
    )
    with pytest.raises(Exception, match="Duplicate resolved input"):
        preflight_normalization_run(duplicate_spec, tmp_path, output)

    no_baseline = RunSpec("fixture-run", (InputSpec(unique.name, None),))
    with pytest.raises(NormalizationRunError, match="expected_record_count"):
        preflight_normalization_run(no_baseline, tmp_path, output)
    assert not output.exists()


def test_output_collision_stops_before_any_writer_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path, "source.json")
    output = tmp_path / "output"
    output.mkdir()
    (output / NORMALIZATION_MANIFEST_FILENAME).write_text("old", encoding="utf-8")
    called = False

    def forbidden_writer(*args: object, **kwargs: object):
        nonlocal called
        called = True
        raise AssertionError("writer must not run")

    monkeypatch.setattr(reporting_module, "write_normalized_file", forbidden_writer)

    with pytest.raises(NormalizationRunError, match="Output already exists"):
        run_normalization(_spec(source.name), tmp_path, output)

    assert called is False
    assert list(output.iterdir()) == [output / NORMALIZATION_MANIFEST_FILENAME]


def test_overwrite_true_is_forwarded_to_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path, "source.json")
    output = tmp_path / "output"
    run_normalization(_spec(source.name), tmp_path, output)
    real_writer = reporting_module.write_normalized_file
    observed: list[bool] = []

    def observing_writer(*args: object, **kwargs: object):
        observed.append(bool(kwargs["overwrite"]))
        return real_writer(*args, **kwargs)

    monkeypatch.setattr(reporting_module, "write_normalized_file", observing_writer)
    manifest = run_normalization(
        _spec(source.name), tmp_path, output, overwrite=True
    )

    assert observed == [True]
    assert manifest["status"] == "completed"


def test_writer_failure_keeps_prior_completed_file_and_has_no_completed_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _source(tmp_path, "a.json")
    second = _source(tmp_path, "b.json")
    output = tmp_path / "output"
    real_writer = reporting_module.write_normalized_file
    calls = 0

    def failing_second_writer(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated writer failure")
        return real_writer(*args, **kwargs)

    monkeypatch.setattr(
        reporting_module, "write_normalized_file", failing_second_writer
    )

    with pytest.raises(NormalizationRunError, match="simulated writer failure"):
        run_normalization(_spec(first.name, second.name), tmp_path, output)

    assert calls == 2
    assert len(list(output.rglob("canonical_events.jsonl"))) == 1
    assert not (output / NORMALIZATION_MANIFEST_FILENAME).exists()
    assert not list(output.rglob("*.tmp"))


def test_report_failure_does_not_damage_previous_completed_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path, "source.json")
    output = tmp_path / "output"
    run_normalization(_spec(source.name), tmp_path, output)
    manifest_path = output / NORMALIZATION_MANIFEST_FILENAME
    before = manifest_path.read_bytes()

    def fail_reports(*args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated report failure")

    monkeypatch.setattr(reporting_module, "write_normalization_reports", fail_reports)

    with pytest.raises(NormalizationRunError, match="simulated report failure"):
        run_normalization(
            _spec(source.name), tmp_path, output, overwrite=True
        )

    assert manifest_path.read_bytes() == before


def test_atomic_report_publish_rolls_back_and_cleans_temporary_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    old = {
        CANONICAL_SCHEMA_FILENAME: b"old schema",
        NORMALIZATION_SUMMARY_FILENAME: b"old summary",
        NORMALIZATION_MANIFEST_FILENAME: b"old manifest",
    }
    for filename, content in old.items():
        (output / filename).write_bytes(content)

    real_replace = reporting_module.os.replace
    failed_once = False

    def fail_summary_once(source: Path, destination: Path) -> None:
        nonlocal failed_once
        if Path(destination).name == NORMALIZATION_SUMMARY_FILENAME and not failed_once:
            failed_once = True
            raise OSError("summary publish failed")
        real_replace(source, destination)

    monkeypatch.setattr(reporting_module.os, "replace", fail_summary_once)

    with pytest.raises(OSError, match="summary publish failed"):
        write_normalization_reports(
            output, _completed_manifest(), overwrite=True
        )

    for filename, content in old.items():
        assert (output / filename).read_bytes() == content
    assert not [path for path in output.iterdir() if path.name.startswith(".")]


def test_report_staging_failure_cleans_already_staged_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    real_stage = reporting_module._stage_bytes

    def fail_summary_stage(final_path: Path, payload: bytes) -> Path:
        if final_path.name == NORMALIZATION_SUMMARY_FILENAME:
            raise OSError("summary staging failed")
        return real_stage(final_path, payload)

    monkeypatch.setattr(reporting_module, "_stage_bytes", fail_summary_stage)

    with pytest.raises(OSError, match="summary staging failed"):
        write_normalization_reports(output, _completed_manifest())

    assert list(output.iterdir()) == []


def test_summary_renderer_is_deterministic_and_contains_no_attack_conclusion() -> None:
    manifest = _completed_manifest()

    first = normalization_summary_markdown(manifest)
    second = normalization_summary_markdown(manifest)

    assert first == second
    assert "chưa phải phát hiện hoặc kết luận tấn công" in first
    assert "Pipeline không filtering hoặc deduplication" in first
    assert "files/a/canonical_events.jsonl" in first


def test_manifest_builder_sorts_files_and_issue_codes_without_mutating_input() -> None:
    first_entry = dict(_completed_manifest()["files"][0])
    first_entry["repository_relative_path"] = "z/source.json"
    first_entry["issue_counts"] = {"unsupported_context": 1, "ambiguous_mapping": 2}
    second_entry = dict(first_entry)
    second_entry["repository_relative_path"] = "a/source.json"
    original_issue_order = tuple(first_entry["issue_counts"])

    manifest = build_normalization_manifest(
        "fixture-run", [first_entry, second_entry]
    )

    assert [entry["repository_relative_path"] for entry in manifest["files"]] == [
        "a/source.json",
        "z/source.json",
    ]
    assert tuple(manifest["files"][0]["issue_counts"]) == (
        "ambiguous_mapping",
        "unsupported_context",
    )
    assert tuple(first_entry["issue_counts"]) == original_issue_order
