"""Resolve Sigma ATT&CK tags for the reviewed MSHTA production artifact."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import sys
import uuid


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from threat_hunting.mitre import (
    MitreLoadError,
    MitreResolutionError,
    build_resolution,
    deterministic_json_bytes,
    file_sha256,
    load_attack_bundle,
    load_sigma_review,
    load_source_manifest,
    validate_manifest,
    validate_resolution_document,
)


DEFAULT_SIGMA_INPUT = (
    REPOSITORY_ROOT
    / "outputs"
    / "evidence"
    / "mshta-powershell"
    / "sigma_match_review.json"
)
DEFAULT_MITRE_BUNDLE = (
    REPOSITORY_ROOT / "data" / "knowledge" / "Mitre" / "enterprise-attack.json"
)
DEFAULT_MANIFEST = (
    REPOSITORY_ROOT / "configs" / "knowledge" / "mitre_enterprise_attack.json"
)
DEFAULT_OUTPUT = (
    REPOSITORY_ROOT
    / "outputs"
    / "evidence"
    / "mshta-powershell"
    / "mitre_resolution.json"
)
DEFAULT_SCENARIO_ID = "mshta-powershell"


class MitreResolutionRunError(RuntimeError):
    """Raised when production input integrity or atomic output handling fails."""


@dataclass(frozen=True, slots=True)
class MitreResolutionStats:
    output_schema_version: str
    scenario_id: str
    analysis_status: str
    rule_count: int
    technique_tag_count: int
    technique_tag_occurrence_count: int
    resolved_technique_count: int
    unresolved_technique_tag_count: int
    candidate_link_count: int
    sigma_input_sha256: str
    mitre_bundle_sha256: str
    manifest_sha256: str
    output_sha256: str
    output_path: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()


def _assert_distinct_paths(output_path: Path, input_paths: tuple[Path, ...]) -> None:
    output_resolved = output_path.resolve()
    if any(output_resolved == item.resolve() for item in input_paths):
        raise MitreResolutionRunError("Output path must not overwrite an input file")


def _atomic_write(path: Path, payload: bytes, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise MitreResolutionRunError(
            f"Output already exists: {path}; pass --overwrite to replace it"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and not overwrite:
            raise MitreResolutionRunError(
                f"Output appeared while writing: {path}; refusing to overwrite it"
            )
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_resolution(
    *,
    sigma_input: Path,
    mitre_bundle: Path,
    manifest_path: Path,
    output_path: Path,
    scenario_id: str,
    overwrite: bool,
) -> MitreResolutionStats:
    """Validate inputs, resolve exact tags, and atomically write the artifact."""

    input_paths = (sigma_input, mitre_bundle, manifest_path)
    _assert_distinct_paths(output_path, input_paths)
    if output_path.exists() and not overwrite:
        raise MitreResolutionRunError(
            f"Output already exists: {output_path}; pass --overwrite to replace it"
        )

    hashes_before = {path.resolve(): file_sha256(path) for path in input_paths}
    sigma_review = load_sigma_review(
        sigma_input, expected_scenario_id=scenario_id
    )
    attack_index = load_attack_bundle(mitre_bundle)
    manifest = load_source_manifest(manifest_path)
    validate_manifest(attack_index, manifest)

    resolution = build_resolution(
        sigma_review=sigma_review,
        sigma_input_path=_portable_path(sigma_input),
        sigma_input_sha256=hashes_before[sigma_input.resolve()],
        attack_index=attack_index,
        manifest=manifest,
        manifest_path=_portable_path(manifest_path),
        manifest_sha256=hashes_before[manifest_path.resolve()],
    )
    validate_resolution_document(resolution)
    payload = deterministic_json_bytes(resolution)

    hashes_after_resolution = {
        path.resolve(): file_sha256(path) for path in input_paths
    }
    if hashes_after_resolution != hashes_before:
        raise MitreResolutionRunError("An input file changed during resolution")

    _atomic_write(output_path, payload, overwrite=overwrite)
    try:
        reloaded = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MitreResolutionRunError(
            f"Cannot validate written output {output_path}: {exc}"
        ) from exc
    if not isinstance(reloaded, dict):
        raise MitreResolutionRunError("Written resolution output is not a JSON object")
    validate_resolution_document(reloaded)
    if deterministic_json_bytes(reloaded) != payload:
        raise MitreResolutionRunError("Written output failed deterministic round-trip")

    hashes_after_write = {path.resolve(): file_sha256(path) for path in input_paths}
    if hashes_after_write != hashes_before:
        raise MitreResolutionRunError("An input file changed while writing the output")

    return MitreResolutionStats(
        output_schema_version=reloaded["schema_version"],
        scenario_id=reloaded["scenario_id"],
        analysis_status=reloaded["analysis_status"],
        rule_count=reloaded["rule_count"],
        technique_tag_count=reloaded["technique_tag_count"],
        technique_tag_occurrence_count=reloaded["technique_tag_occurrence_count"],
        resolved_technique_count=reloaded["resolved_technique_count"],
        unresolved_technique_tag_count=len(reloaded["unresolved_technique_tags"]),
        candidate_link_count=len(reloaded["rule_technique_candidate_links"]),
        sigma_input_sha256=hashes_before[sigma_input.resolve()],
        mitre_bundle_sha256=hashes_before[mitre_bundle.resolve()],
        manifest_sha256=hashes_before[manifest_path.resolve()],
        output_sha256=file_sha256(output_path),
        output_path=_portable_path(output_path),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve exact Sigma ATT&CK technique tags against a pinned "
            "Enterprise ATT&CK STIX 2.1 bundle."
        )
    )
    parser.add_argument("--sigma-input", type=Path, default=DEFAULT_SIGMA_INPUT)
    parser.add_argument("--mitre-bundle", type=Path, default=DEFAULT_MITRE_BUNDLE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--scenario-id", default=DEFAULT_SCENARIO_ID)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Atomically replace an existing output file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        stats = run_resolution(
            sigma_input=args.sigma_input,
            mitre_bundle=args.mitre_bundle,
            manifest_path=args.manifest,
            output_path=args.output,
            scenario_id=args.scenario_id,
            overwrite=args.overwrite,
        )
    except (MitreLoadError, MitreResolutionError, MitreResolutionRunError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(stats.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
