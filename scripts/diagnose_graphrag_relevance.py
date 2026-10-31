#!/usr/bin/env python3
"""Audit relevance separability using existing calibration artifacts only."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, NoReturn


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPOSITORY_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from threat_hunting.evaluation import (  # noqa: E402
    RelevanceDiagnosticsError, analyze_relevance_separability,
    load_calibration_report, load_relevance_calibration_dataset,
    load_relevance_diagnostics, validate_relevance_diagnostics,
)


class RelevanceDiagnosticsCliError(RelevanceDiagnosticsError):
    """Artifact diagnostics could not produce a complete verified output."""


def _expected_hash(value: str, option: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise RelevanceDiagnosticsCliError(
            f"{option} must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise RelevanceDiagnosticsCliError(f"cannot hash input {path}: {exc}") from exc
    return digest.hexdigest()


def _assert_input_hashes(inputs: dict[str, tuple[Path, str]], *, phase: str) -> None:
    for path, expected in inputs.values():
        actual = _sha256_file(path)
        if actual != expected:
            raise RelevanceDiagnosticsCliError(
                f"input SHA-256 mismatch {phase} for {path}: expected {expected}, got {actual}"
            )


def _serialize(document: object) -> bytes:
    return (json.dumps(
        document, ensure_ascii=False, sort_keys=True, allow_nan=False,
        separators=(",", ":"),
    ) + "\n").encode("utf-8", errors="strict")


def _protect_output(output_path: Path, inputs: dict[str, tuple[Path, str]]) -> None:
    resolved = output_path.resolve()
    if output_path.is_symlink():
        raise RelevanceDiagnosticsCliError(f"refusing symlink diagnostics output: {output_path}")
    for path, _ in inputs.values():
        if resolved == path.resolve() or (
            output_path.exists() and path.exists() and output_path.samefile(path)
        ):
            raise RelevanceDiagnosticsCliError(
                f"diagnostics output must differ from input artifact {path}"
            )


def _atomic_write_diagnostics(
    output_path: Path, serialized: bytes, *, overwrite: bool,
    expected_previous: bytes | None, check_inputs: Callable[[str], None],
    protect_output: Callable[[], None],
) -> None:
    """Validate same-directory bytes before installing, then read back and audit.

    A hard link provides creation without replacing a concurrent writer. Failed
    installed-output audits restore the earlier bytes atomically. Rollback never
    overwrites bytes that another writer has changed after the installation.
    """
    temporary: Path | None = None
    installed = False
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=output_path.parent, prefix=".diagnostics-", suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        load_relevance_diagnostics(temporary)
        if temporary.read_bytes() != serialized:
            raise RelevanceDiagnosticsCliError(f"temporary diagnostics bytes changed: {temporary}")
        protect_output()
        check_inputs("after temporary read-back, immediately before install")
        if expected_previous is None:
            os.link(temporary, output_path)
        else:
            if not overwrite or output_path.read_bytes() != expected_previous:
                raise RelevanceDiagnosticsCliError(f"output changed before overwrite: {output_path}")
            os.replace(temporary, output_path)
        installed = True
        load_relevance_diagnostics(output_path)
        if output_path.read_bytes() != serialized:
            raise RelevanceDiagnosticsCliError(f"installed diagnostics bytes changed: {output_path}")
        check_inputs("after output write and read-back")
    except Exception as exc:
        if installed:
            try:
                if output_path.is_symlink() or output_path.read_bytes() != serialized:
                    raise RelevanceDiagnosticsCliError(
                        "refusing to roll back another writer's changed output"
                    )
                if expected_previous is None:
                    output_path.unlink()
                else:
                    rollback: Path | None = None
                    try:
                        with tempfile.NamedTemporaryFile(
                            dir=output_path.parent, prefix=".diagnostics-rollback-",
                            suffix=".tmp", delete=False,
                        ) as handle:
                            rollback = Path(handle.name)
                            handle.write(expected_previous)
                            handle.flush()
                            os.fsync(handle.fileno())
                        os.replace(rollback, output_path)
                    finally:
                        if rollback is not None:
                            rollback.unlink(missing_ok=True)
            except Exception as rollback_error:
                raise RelevanceDiagnosticsCliError(
                    f"cannot write diagnostics {output_path}: {exc}; "
                    f"rollback failed: {rollback_error}"
                ) from exc
        raise RelevanceDiagnosticsCliError(
            f"cannot write diagnostics {output_path}: {exc}"
        ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_diagnostics(
    *, dataset_path: Path, calibration_report_path: Path, output_path: Path,
    dataset_sha256: str, calibration_report_sha256: str, overwrite: bool = False,
) -> dict[str, Any]:
    """Load locked inputs, call the in-memory analyzer once, and install its report."""
    try:
        inputs = {
            "dataset": (Path(dataset_path), _expected_hash(dataset_sha256, "--dataset-sha256")),
            "report": (Path(calibration_report_path), _expected_hash(
                calibration_report_sha256, "--calibration-report-sha256",
            )),
        }
        output_path = Path(output_path)
        _protect_output(output_path, inputs)
        previous = output_path.read_bytes() if output_path.exists() else None
        if previous is not None and not overwrite:
            raise RelevanceDiagnosticsCliError(
                f"diagnostics output already exists; use --overwrite: {output_path}"
            )

        def check_inputs(phase: str) -> None:
            _assert_input_hashes(inputs, phase=phase)

        with redirect_stdout(sys.stderr):
            check_inputs("before load")
            dataset = load_relevance_calibration_dataset(inputs["dataset"][0])
            calibration_report = load_calibration_report(inputs["report"][0])
            check_inputs("after load")
            diagnostics = analyze_relevance_separability(
                dataset, calibration_report,
                dataset_path=inputs["dataset"][0].as_posix(),
                dataset_sha256=inputs["dataset"][1],
                report_path=inputs["report"][0].as_posix(),
                report_sha256=inputs["report"][1],
            )
            check_inputs("after diagnostics build")
            validate_relevance_diagnostics(diagnostics)
            serialized = _serialize(diagnostics)
            check_inputs("after serialization")
            _atomic_write_diagnostics(
                output_path, serialized, overwrite=overwrite,
                expected_previous=previous, check_inputs=check_inputs,
                protect_output=lambda: _protect_output(output_path, inputs),
            )
        return diagnostics
    except RelevanceDiagnosticsCliError:
        raise
    except Exception as exc:
        raise RelevanceDiagnosticsCliError(f"relevance diagnostics failed: {exc}") from exc


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise RelevanceDiagnosticsCliError(message)


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("dataset", "calibration-report", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("dataset-sha256", "calibration-report-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        for stream in (sys.stdout, sys.stderr):
            reconfigure = getattr(stream, "reconfigure", None)
            if callable(reconfigure):
                reconfigure(encoding="utf-8", errors="strict", newline="\n")
        args = _build_parser().parse_args(argv)
        run_diagnostics(
            dataset_path=args.dataset, calibration_report_path=args.calibration_report,
            dataset_sha256=args.dataset_sha256,
            calibration_report_sha256=args.calibration_report_sha256,
            output_path=args.output, overwrite=args.overwrite,
        )
        summary = {"output": args.output.as_posix(), "sha256": _sha256_file(args.output)}
        sys.stdout.write(_serialize(summary).decode("utf-8"))
        sys.stdout.flush()
        return 0
    except Exception as exc:
        message = str(exc).encode("utf-8", errors="backslashreplace").decode("utf-8")
        print(f"error: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
