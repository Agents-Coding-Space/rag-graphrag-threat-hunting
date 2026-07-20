"""Normalize one or more Mordor sources into canonical JSONL outputs."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threat_hunting.discovery import DiscoveryError
from threat_hunting.mordor.format_detection import FormatDetectionError
from threat_hunting.mordor.parser import MordorParseError
from threat_hunting.normalization_reporting import (
    NormalizationRunError,
    run_normalization,
)
from threat_hunting.normalization_writer import NormalizationWriteError
from threat_hunting.run_spec import InputSpec, RunSpec, RunSpecError, load_run_spec


DEFAULT_SPEC = REPOSITORY_ROOT / "configs" / "experiments" / "mordor_selected_v2.json"
DEFAULT_OUTPUT_ROOT = REPOSITORY_ROOT / "outputs" / "canonical"


def _expected_count(value: str) -> tuple[str, int]:
    try:
        name, count_text = value.rsplit("=", 1)
        count = int(count_text)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError(
            "Expected INPUT=NON_NEGATIVE_INTEGER"
        ) from exc
    if not name or count < 0:
        raise argparse.ArgumentTypeError("Expected INPUT=NON_NEGATIVE_INTEGER")
    return name, count


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Stream Mordor records into canonical-event/v2 JSONL without "
            "filtering or deduplication."
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
        help="Required baseline for each --input value; repeat as needed",
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
        help=(
            "Run output directory (default: "
            f"{DEFAULT_OUTPUT_ROOT / '<experiment_id>'})"
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Atomically replace outputs for the same run paths",
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
        missing = [value for value in arguments.input if value not in baseline_by_input]
        if missing:
            raise RunSpecError(
                "Normalization requires --expected-record-count for every --input: "
                + ", ".join(missing)
            )
        return RunSpec(
            experiment_id="cli-inputs",
            inputs=tuple(
                InputSpec(value, baseline_by_input[value]) for value in arguments.input
            ),
        )
    if arguments.expected_record_count:
        raise RunSpecError("--expected-record-count requires --input")
    return load_run_spec((arguments.spec or DEFAULT_SPEC).resolve())


def _resolve_output_directory(
    arguments: argparse.Namespace,
    run_spec: RunSpec,
) -> Path:
    requested = arguments.output_dir or DEFAULT_OUTPUT_ROOT / run_spec.experiment_id
    return requested.resolve()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        run_spec = _resolve_run_spec(arguments)
        output_directory = _resolve_output_directory(arguments, run_spec)
        manifest = run_normalization(
            run_spec,
            arguments.search_root,
            output_directory,
            overwrite=arguments.overwrite,
        )
    except (
        DiscoveryError,
        FormatDetectionError,
        MordorParseError,
        NormalizationRunError,
        NormalizationWriteError,
        RunSpecError,
        OSError,
    ) as exc:
        print(f"normalize_mordor: error: {exc}", file=sys.stderr)
        return 2

    print(output_directory)
    return 0 if manifest["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
