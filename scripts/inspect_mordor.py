"""Inspect one or more Mordor JSON sources without modifying them."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threat_hunting.discovery import DiscoveryError, discover_inputs
from threat_hunting.mordor.format_detection import FormatDetectionError, detect_format
from threat_hunting.mordor.inspection import inspect_file
from threat_hunting.mordor.parser import MordorParseError
from threat_hunting.reporting import ReportingError, write_reports
from threat_hunting.run_spec import InputSpec, RunSpec, RunSpecError, load_run_spec


DEFAULT_SPEC = REPOSITORY_ROOT / "configs" / "experiments" / "mordor_selected_v1.json"


def _expected_count(value: str) -> tuple[str, int]:
    try:
        name, count_text = value.rsplit("=", 1)
        count = int(count_text)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("Expected INPUT=NON_NEGATIVE_INTEGER") from exc
    if not name or count < 0:
        raise argparse.ArgumentTypeError("Expected INPUT=NON_NEGATIVE_INTEGER")
    return name, count


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect Mordor JSONL, JSON array, or JSON object files. "
            "No canonical records or scenario evidence are generated."
        )
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--spec",
        type=Path,
        help=f"JSON run specification (default when no --input: {DEFAULT_SPEC})",
    )
    source.add_argument(
        "--input",
        action="append",
        help="Input path or exact filename; repeat for multiple files",
    )
    parser.add_argument(
        "--expected-record-count",
        action="append",
        default=[],
        type=_expected_count,
        metavar="INPUT=COUNT",
        help="Optional baseline for an --input value; repeat as needed",
    )
    parser.add_argument(
        "--search-root",
        type=Path,
        default=REPOSITORY_ROOT,
        help="Root used to resolve exact filenames",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPOSITORY_ROOT / "outputs" / "mordor_inspection",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Atomically replace report files that already exist",
    )
    return parser


def _resolve_run_spec(arguments: argparse.Namespace) -> RunSpec:
    if arguments.input:
        baseline_by_input = dict(arguments.expected_record_count)
        unknown = sorted(set(baseline_by_input) - set(arguments.input))
        if unknown:
            raise RunSpecError(
                "Baselines were provided for inputs not present in --input: "
                + ", ".join(unknown)
            )
        return RunSpec(
            experiment_id="cli-inputs",
            inputs=tuple(
                InputSpec(value, baseline_by_input.get(value)) for value in arguments.input
            ),
        )
    if arguments.expected_record_count:
        raise RunSpecError("--expected-record-count requires --input")
    return load_run_spec((arguments.spec or DEFAULT_SPEC).resolve())


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        run_spec = _resolve_run_spec(arguments)
        sources = discover_inputs(run_spec.inputs, arguments.search_root)
        reports = []
        for source in sources:
            print(f"Inspecting {source.repository_relative_path}...", file=sys.stderr)
            detection = detect_format(source.path)
            reports.append(inspect_file(source, detection))
        manifest = write_reports(
            arguments.output_dir.resolve(),
            run_spec.experiment_id,
            reports,
            overwrite=arguments.overwrite,
        )
    except (
        DiscoveryError,
        FormatDetectionError,
        MordorParseError,
        ReportingError,
        RunSpecError,
    ) as exc:
        print(f"inspect_mordor: error: {exc}", file=sys.stderr)
        return 2

    print(arguments.output_dir.resolve())
    return 0 if manifest["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
