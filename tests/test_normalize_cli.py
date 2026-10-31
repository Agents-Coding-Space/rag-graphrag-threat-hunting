from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import scripts.normalize_mordor as cli
from threat_hunting.run_spec import load_run_spec
from threat_hunting.schemas.canonical_mapping import SYSMON_PROVIDER


def _record(index: int) -> dict[str, object]:
    return {
        "SourceName": SYSMON_PROVIDER,
        "EventID": 22,
        "@timestamp": f"2020-01-02T03:04:{index:02d}Z",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Hostname": "fixture-host",
        "Image": "C:\\Windows\\System32\\dns.exe",
        "ProcessId": str(index),
        "ProcessGuid": f"{{GUID-{index}}}",
        "QueryName": f"example-{index}.test",
    }


def _source(root: Path, relative: str, count: int = 2) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(_record(index)) + "\n" for index in range(1, count + 1)),
        encoding="utf-8",
    )
    return path


def test_default_spec_and_output_directory_resolve_to_v2() -> None:
    arguments = argparse.Namespace(
        input=None,
        expected_record_count=[],
        spec=None,
        output_dir=None,
    )

    run_spec = cli._resolve_run_spec(arguments)
    output = cli._resolve_output_directory(arguments, run_spec)

    assert cli.DEFAULT_SPEC.name == "mordor_selected_v2.json"
    assert run_spec == load_run_spec(cli.DEFAULT_SPEC)
    assert run_spec.experiment_id == "mordor-selected-v2"
    assert output == (cli.DEFAULT_OUTPUT_ROOT / "mordor-selected-v2").resolve()


def test_cli_multiple_inputs_completed_exit_zero(tmp_path: Path) -> None:
    first = _source(tmp_path, "data/one.json")
    second = _source(tmp_path, "data/two.json")
    output = tmp_path / "output"

    exit_code = cli.main(
        [
            "--input",
            first.name,
            "--input",
            second.name,
            "--expected-record-count",
            f"{first.name}=2",
            "--expected-record-count",
            f"{second.name}=2",
            "--search-root",
            str(tmp_path),
            "--output-dir",
            str(output),
        ]
    )

    assert exit_code == 0
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed"
    assert manifest["input_count"] == 2


def test_cli_baseline_mismatch_returns_one(tmp_path: Path) -> None:
    source = _source(tmp_path, "data/source.json", count=2)
    output = tmp_path / "output"

    exit_code = cli.main(
        [
            "--input",
            source.name,
            "--expected-record-count",
            f"{source.name}=3",
            "--search-root",
            str(tmp_path),
            "--output-dir",
            str(output),
        ]
    )

    assert exit_code == 1
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed_with_errors"


@pytest.mark.parametrize("case", ["missing", "ambiguous", "duplicate"])
def test_cli_discovery_errors_return_two_without_partial_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    case: str,
) -> None:
    output = tmp_path / "output"
    if case == "missing":
        arguments = [
            "--input",
            "missing.json",
            "--expected-record-count",
            "missing.json=2",
        ]
    elif case == "ambiguous":
        for directory in ("a", "b"):
            _source(tmp_path, f"{directory}/same.json")
        arguments = [
            "--input",
            "same.json",
            "--expected-record-count",
            "same.json=2",
        ]
    else:
        _source(tmp_path, "data/same.json")
        arguments = [
            "--input",
            "same.json",
            "--input",
            "data/same.json",
            "--expected-record-count",
            "same.json=2",
            "--expected-record-count",
            "data/same.json=2",
        ]
    arguments.extend(
        ["--search-root", str(tmp_path), "--output-dir", str(output)]
    )

    exit_code = cli.main(arguments)

    assert exit_code == 2
    assert "normalize_mordor: error:" in capsys.readouterr().err
    assert not output.exists()


def test_cli_missing_expected_count_returns_two_before_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = _source(tmp_path, "data/source.json")
    output = tmp_path / "output"

    exit_code = cli.main(
        [
            "--input",
            source.name,
            "--search-root",
            str(tmp_path),
            "--output-dir",
            str(output),
        ]
    )

    assert exit_code == 2
    assert "requires --expected-record-count" in capsys.readouterr().err
    assert not output.exists()


def test_cli_output_collision_returns_two_before_writer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = _source(tmp_path, "data/source.json")
    output = tmp_path / "output"
    output.mkdir()
    manifest = output / "manifest.json"
    manifest.write_bytes(b"old manifest")

    exit_code = cli.main(
        [
            "--input",
            source.name,
            "--expected-record-count",
            f"{source.name}=2",
            "--search-root",
            str(tmp_path),
            "--output-dir",
            str(output),
        ]
    )

    assert exit_code == 2
    assert "Output already exists" in capsys.readouterr().err
    assert manifest.read_bytes() == b"old manifest"
    assert list(output.iterdir()) == [manifest]


def test_cli_forwards_overwrite_and_uses_requested_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}
    output = tmp_path / "requested"

    def fake_run(
        run_spec: object,
        search_root: Path,
        output_directory: Path,
        *,
        overwrite: bool,
    ) -> dict[str, object]:
        observed.update(
            run_spec=run_spec,
            search_root=search_root,
            output_directory=output_directory,
            overwrite=overwrite,
        )
        return {"status": "completed"}

    monkeypatch.setattr(cli, "run_normalization", fake_run)

    exit_code = cli.main(
        [
            "--input",
            "fixture.json",
            "--expected-record-count",
            "fixture.json=2",
            "--search-root",
            str(tmp_path),
            "--output-dir",
            str(output),
            "--overwrite",
        ]
    )

    assert exit_code == 0
    assert observed["overwrite"] is True
    assert observed["search_root"] == tmp_path
    assert observed["output_directory"] == output.resolve()
