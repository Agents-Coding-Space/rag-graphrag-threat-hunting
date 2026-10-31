#!/usr/bin/env python3
"""Build and validate the production MSHTA Ground Truth Core document."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, NoReturn
from uuid import uuid4


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPOSITORY_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from threat_hunting.ground_truth import (  # noqa: E402
    GroundTruthBuildError,
    GroundTruthValidationError,
    build_ground_truth_core,
    validate_ground_truth_build_config,
    validate_ground_truth_document,
)


DEFAULT_SCENARIO_EVIDENCE = (
    REPOSITORY_ROOT
    / "outputs"
    / "evidence"
    / "mshta-powershell"
    / "scenario_evidence.json"
)
DEFAULT_SIGMA_REVIEW = (
    REPOSITORY_ROOT
    / "outputs"
    / "evidence"
    / "mshta-powershell"
    / "sigma_match_review.json"
)
DEFAULT_MITRE_RESOLUTION = (
    REPOSITORY_ROOT
    / "outputs"
    / "evidence"
    / "mshta-powershell"
    / "mitre_resolution.json"
)
DEFAULT_BUILD_CONFIG = (
    REPOSITORY_ROOT / "configs" / "ground_truth" / "mshta_powershell.json"
)
DEFAULT_OUTPUT = (
    REPOSITORY_ROOT
    / "outputs"
    / "ground_truth"
    / "mshta-powershell"
    / "scenario_ground_truth.json"
)

DEFAULT_SCENARIO_EVIDENCE_SHA256 = (
    "ea56d0bb07547da85a98339491af55d5b984d96ab8558eef3f8ec530955a4905"
)
DEFAULT_SIGMA_REVIEW_SHA256 = (
    "cafb455ce6ad59cc5cf5f62805a0d7354f6b88d69fc1414c6f860222fd147fe4"
)
DEFAULT_MITRE_RESOLUTION_SHA256 = (
    "f5eec09eaff36806e8567f215d9eed7edc7bc62dc3c3c9864dcbae3c6dcd608d"
)
DEFAULT_BUILD_CONFIG_SHA256 = (
    "f13f3efe1c783911ea512d98533826b4e2086349aead26795b7b6d57e49c247f"
)

_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")


class GroundTruthCliError(ValueError):
    """Raised when CLI inputs cannot safely produce a ground-truth document."""


@dataclass(frozen=True)
class BuildStats:
    scenario_id: str
    schema_version: str
    analysis_status: str
    review_status: str
    input_provenance: int
    entities: int
    facts: int
    relationships: int
    evidence: int
    sigma_findings: int
    mitre_assessments: int
    input_sha256: dict[str, str]
    output_path: str
    output_sha256: str


def _fail(message: str) -> NoReturn:
    raise GroundTruthCliError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GroundTruthCliError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> NoReturn:
    raise GroundTruthCliError(f"non-standard JSON constant is not allowed: {value}")


def _load_json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            document = json.load(
                handle,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonstandard_constant,
            )
    except GroundTruthCliError as exc:
        raise GroundTruthCliError(f"{label} {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GroundTruthCliError(
            f"{label} {path}: malformed JSON at line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise GroundTruthCliError(f"cannot read {label} {path}: {exc}") from exc

    if not isinstance(document, dict):
        raise GroundTruthCliError(f"{label} {path}: JSON top level must be an object")
    return document


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise GroundTruthCliError(f"cannot hash input {path}: {exc}") from exc
    return digest.hexdigest()


def _normalise_expected_hash(value: str, *, label: str) -> str:
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise GroundTruthCliError(
            f"expected SHA-256 for {label} must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return path.name


def _assert_distinct_paths(input_paths: dict[str, Path], output_path: Path) -> None:
    resolved_inputs: dict[Path, str] = {}
    for label, path in input_paths.items():
        resolved = path.resolve()
        if resolved in resolved_inputs:
            raise GroundTruthCliError(
                f"{label} and {resolved_inputs[resolved]} resolve to the same input path: {path}"
            )
        resolved_inputs[resolved] = label
    if output_path.resolve() in resolved_inputs:
        raise GroundTruthCliError(
            f"output path must differ from every input path: {output_path}"
        )


def _verify_input_hashes(
    input_paths: dict[str, Path], expected_hashes: dict[str, str]
) -> dict[str, str]:
    actual_hashes: dict[str, str] = {}
    for label, path in input_paths.items():
        expected = _normalise_expected_hash(expected_hashes[label], label=label)
        actual = _sha256_file(path)
        if actual != expected:
            raise GroundTruthCliError(
                f"SHA-256 mismatch for {label} {path}: expected {expected}, got {actual}"
            )
        actual_hashes[label] = actual
    return actual_hashes


def _assert_hashes_unchanged(
    input_paths: dict[str, Path], original_hashes: dict[str, str]
) -> None:
    for label, path in input_paths.items():
        current = _sha256_file(path)
        if current != original_hashes[label]:
            raise GroundTruthCliError(
                f"input changed while building ground truth: {label} {path}; "
                f"expected {original_hashes[label]}, got {current}"
            )


def _serialize_document(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _validate_serialized_document(payload: bytes, *, path: Path) -> dict[str, Any]:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
        )
    except (UnicodeError, json.JSONDecodeError, GroundTruthCliError) as exc:
        raise GroundTruthCliError(f"generated output {path} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise GroundTruthCliError(f"generated output {path} must be a JSON object")
    validate_ground_truth_document(document)
    if _serialize_document(document) != payload:
        raise GroundTruthCliError(f"generated output {path} is not canonically serialized")
    return document


def _write_atomic(
    output_path: Path,
    payload: bytes,
    *,
    overwrite: bool,
) -> None:
    if output_path.exists() and not overwrite:
        raise GroundTruthCliError(
            f"output already exists (pass --overwrite to replace it): {output_path}"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(
        f".{output_path.name}.{uuid4().hex}.tmp"
    )
    try:
        with temporary_path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_serialized_document(temporary_path.read_bytes(), path=temporary_path)
        os.replace(temporary_path, output_path)
    except Exception:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _input_provenance(
    *,
    documents: dict[str, dict[str, Any]],
    paths: dict[str, Path],
    hashes: dict[str, str],
) -> list[dict[str, Any]]:
    specifications = (
        ("scenario-evidence-input", "scenario_evidence", "scenario_evidence"),
        ("sigma-review-input", "sigma_review", "sigma_review"),
        ("mitre-resolution-input", "mitre_resolution", "mitre_resolution"),
    )
    return [
        {
            "input_id": input_id,
            "input_type": input_type,
            "path": _portable_path(paths[label]),
            "schema_version": documents[label].get("schema_version"),
            "sha256": hashes[label],
            "scenario_id": documents[label].get("scenario_id"),
        }
        for input_id, input_type, label in specifications
    ]


def build_document(
    *,
    scenario_evidence_path: Path,
    sigma_review_path: Path,
    mitre_resolution_path: Path,
    build_config_path: Path,
    output_path: Path,
    expected_scenario_evidence_sha256: str,
    expected_sigma_review_sha256: str,
    expected_mitre_resolution_sha256: str,
    expected_build_config_sha256: str,
    overwrite: bool,
) -> BuildStats:
    input_paths = {
        "scenario_evidence": scenario_evidence_path,
        "sigma_review": sigma_review_path,
        "mitre_resolution": mitre_resolution_path,
        "build_config": build_config_path,
    }
    expected_hashes = {
        "scenario_evidence": expected_scenario_evidence_sha256,
        "sigma_review": expected_sigma_review_sha256,
        "mitre_resolution": expected_mitre_resolution_sha256,
        "build_config": expected_build_config_sha256,
    }

    _assert_distinct_paths(input_paths, output_path)
    if output_path.exists() and not overwrite:
        raise GroundTruthCliError(
            f"output already exists (pass --overwrite to replace it): {output_path}"
        )

    original_hashes = _verify_input_hashes(input_paths, expected_hashes)
    documents = {
        label: _load_json_object(path, label=label.replace("_", " "))
        for label, path in input_paths.items()
    }

    validate_ground_truth_build_config(documents["build_config"])
    provenance = _input_provenance(
        documents=documents,
        paths=input_paths,
        hashes=original_hashes,
    )
    result = build_ground_truth_core(
        scenario_evidence=documents["scenario_evidence"],
        sigma_review=documents["sigma_review"],
        mitre_resolution=documents["mitre_resolution"],
        input_provenance=provenance,
        build_config=documents["build_config"],
    )
    validate_ground_truth_document(result)
    payload = _serialize_document(result)
    _validate_serialized_document(payload, path=output_path)

    _assert_hashes_unchanged(input_paths, original_hashes)
    _write_atomic(output_path, payload, overwrite=overwrite)
    written = _load_json_object(output_path, label="generated ground truth")
    validate_ground_truth_document(written)
    if written != result or output_path.read_bytes() != payload:
        raise GroundTruthCliError(
            f"generated output failed deterministic read-back verification: {output_path}"
        )
    _assert_hashes_unchanged(input_paths, original_hashes)

    return BuildStats(
        scenario_id=result["scenario"]["scenario_id"],
        schema_version=result["schema_version"],
        analysis_status=result["scenario"]["analysis_status"],
        review_status=result["review"]["review_status"],
        input_provenance=len(result["input_provenance"]),
        entities=len(result["entities"]),
        facts=len(result["facts"]),
        relationships=len(result["relationships"]),
        evidence=len(result["evidence"]),
        sigma_findings=len(result["sigma_findings"]),
        mitre_assessments=len(result["mitre_assessments"]),
        input_sha256=dict(original_hashes),
        output_path=_portable_path(output_path),
        output_sha256=hashlib.sha256(payload).hexdigest(),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the validated MSHTA production Ground Truth Core document."
    )
    parser.add_argument("--scenario-evidence", type=Path, default=DEFAULT_SCENARIO_EVIDENCE)
    parser.add_argument("--sigma-review", type=Path, default=DEFAULT_SIGMA_REVIEW)
    parser.add_argument("--mitre-resolution", type=Path, default=DEFAULT_MITRE_RESOLUTION)
    parser.add_argument("--build-config", type=Path, default=DEFAULT_BUILD_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--expected-scenario-evidence-sha256",
        default=DEFAULT_SCENARIO_EVIDENCE_SHA256,
    )
    parser.add_argument(
        "--expected-sigma-review-sha256", default=DEFAULT_SIGMA_REVIEW_SHA256
    )
    parser.add_argument(
        "--expected-mitre-resolution-sha256",
        default=DEFAULT_MITRE_RESOLUTION_SHA256,
    )
    parser.add_argument(
        "--expected-build-config-sha256", default=DEFAULT_BUILD_CONFIG_SHA256
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing output file atomically.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        stats = build_document(
            scenario_evidence_path=args.scenario_evidence,
            sigma_review_path=args.sigma_review,
            mitre_resolution_path=args.mitre_resolution,
            build_config_path=args.build_config,
            output_path=args.output,
            expected_scenario_evidence_sha256=args.expected_scenario_evidence_sha256,
            expected_sigma_review_sha256=args.expected_sigma_review_sha256,
            expected_mitre_resolution_sha256=args.expected_mitre_resolution_sha256,
            expected_build_config_sha256=args.expected_build_config_sha256,
            overwrite=args.overwrite,
        )
    except (
        GroundTruthCliError,
        GroundTruthBuildError,
        GroundTruthValidationError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(asdict(stats), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
