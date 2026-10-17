"""Publish an auditable provisional selection from an existing comparison report."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, NoReturn


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from threat_hunting.evaluation.embedding_model_selection import (  # noqa: E402
    evaluate_embedding_model_candidates,
)
from threat_hunting.evaluation.embedding_model_selection_schema import (  # noqa: E402
    validate_embedding_model_selection,
    validate_embedding_model_selection_policy,
)
from threat_hunting.evaluation.embedding_retrieval_comparison_schema import (  # noqa: E402
    snapshot_json,
    validate_embedding_retrieval_comparison_report,
)


class EmbeddingModelSelectionCliError(ValueError):
    """Raised when input verification or transactional publication fails."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise EmbeddingModelSelectionCliError(f"duplicate JSON object key {key!r}")
        document[key] = value
    return document


def _reject_constant(value: str) -> NoReturn:
    raise EmbeddingModelSelectionCliError(f"non-standard JSON number {value!r}")


def _parse_json_bytes(payload: bytes, *, source_path: str) -> dict[str, Any]:
    try:
        document = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs, parse_constant=_reject_constant,
        )
        document = snapshot_json(document, f"{source_path}:$")
        if not isinstance(document, dict):
            raise EmbeddingModelSelectionCliError("JSON document must be an object")
        return document
    except Exception as exc:
        raise EmbeddingModelSelectionCliError(f"{source_path}: cannot parse UTF-8 JSON: {exc}") from exc


def _repository_path(path: Path) -> Path:
    root = REPOSITORY_ROOT.resolve()
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root):
        raise EmbeddingModelSelectionCliError(f"{path}: path escapes the repository")
    return resolved


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or (
        first.exists() and second.exists() and first.samefile(second)
    )


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _assert_input_hashes(expected: dict[Path, str]) -> None:
    for path, digest in expected.items():
        if _sha256_file(path) != digest:
            raise EmbeddingModelSelectionCliError(f"{path}: input SHA-256 changed or does not match")


def _serialize_selection(selection: dict[str, Any]) -> bytes:
    return json.dumps(
        selection, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8") + b"\n"


def _read_back_selection(
    output: Path, payload: bytes, *, comparison_report: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    actual = output.read_bytes()
    selection = _parse_json_bytes(actual, source_path=output.as_posix())
    validate_embedding_model_selection(
        selection, comparison_report=comparison_report, policy=policy,
    )
    if actual != payload:
        raise EmbeddingModelSelectionCliError(f"{output}: read-back bytes differ from the serialized selection")


def _replace_bytes(
    output: Path, payload: bytes, *, create_only: bool = False,
    on_publish: Callable[[], None] | None = None,
    check_before_publish: Callable[[], None] | None = None,
) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=output.parent, prefix=f".{output.name}.",
            suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if check_before_publish is not None:
            check_before_publish()
        if create_only:
            # A competing writer must never be overwritten without authorization.
            os.link(temporary, output)
        else:
            os.replace(temporary, output)
        if on_publish is not None:
            on_publish()
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                # Retry transient cleanup errors while retaining the failure so
                # the caller rolls back a publication that already succeeded.
                temporary.unlink(missing_ok=True)
                raise


def _atomic_write_selection(
    output: Path, payload: bytes, *, overwrite: bool,
    comparison_report: dict[str, Any], policy: dict[str, Any],
    check_inputs: Callable[[], None],
) -> None:
    if output.exists() and not overwrite:
        raise EmbeddingModelSelectionCliError(f"{output}: output already exists; use --overwrite")
    old_bytes = output.read_bytes() if output.exists() else None
    check_inputs()
    output.parent.mkdir(parents=True, exist_ok=True)
    published = False
    complete = False

    def mark_published() -> None:
        nonlocal published
        published = True

    def before_publish() -> None:
        check_inputs()
        if old_bytes is not None and (
            not output.exists() or output.read_bytes() != old_bytes
        ):
            raise EmbeddingModelSelectionCliError(f"{output}: output changed before publication")

    try:
        _replace_bytes(
            output, payload, create_only=not overwrite, on_publish=mark_published,
            check_before_publish=before_publish,
        )
        _read_back_selection(
            output, payload, comparison_report=comparison_report, policy=policy,
        )
        check_inputs()
        complete = True
    finally:
        if published and not complete:
            if old_bytes is None:
                try:
                    output.unlink(missing_ok=True)
                except OSError:
                    output.unlink(missing_ok=True)
            else:
                try:
                    _replace_bytes(output, old_bytes)
                except OSError:
                    _replace_bytes(output, old_bytes)


def run_selection_cli(
    *, comparison_report_path: Path, comparison_report_sha256: str,
    policy_path: Path, output_path: Path, overwrite: bool,
) -> dict[str, Any]:
    """Verify existing inputs and publish one recommendation without model execution."""
    try:
        if re.fullmatch(r"[0-9a-f]{64}", comparison_report_sha256) is None:
            raise EmbeddingModelSelectionCliError("comparison report SHA-256 must be 64 lowercase hex characters")
        report_file = _repository_path(comparison_report_path)
        policy_file = _repository_path(policy_path)
        output = _repository_path(output_path)
        original_output = REPOSITORY_ROOT.resolve() / output_path

        def check_paths() -> None:
            if original_output.is_symlink():
                raise EmbeddingModelSelectionCliError(f"{output_path}: refusing symlink output")
            if _repository_path(output_path) != output:
                raise EmbeddingModelSelectionCliError(f"{output_path}: output path changed")
            if not output.is_relative_to((REPOSITORY_ROOT.resolve() / "outputs" / "evaluation")):
                raise EmbeddingModelSelectionCliError("selection output must be in outputs/evaluation")
            if _overlaps(report_file, policy_file):
                raise EmbeddingModelSelectionCliError("comparison report and policy overlap")
            if any(_overlaps(output, source) for source in (report_file, policy_file)):
                raise EmbeddingModelSelectionCliError("output overlaps a read-only input")
            if output.exists() and not output.is_file():
                raise EmbeddingModelSelectionCliError(f"{output}: output must be a regular file")
            if (
                _repository_path(comparison_report_path) != report_file
                or _repository_path(policy_path) != policy_file
            ):
                raise EmbeddingModelSelectionCliError("input path changed")

        check_paths()
        if output.exists() and not overwrite:
            raise EmbeddingModelSelectionCliError(f"{output}: output already exists; use --overwrite")
        report_payload = report_file.read_bytes()
        if sha256(report_payload).hexdigest() != comparison_report_sha256:
            raise EmbeddingModelSelectionCliError(f"{report_file}: comparison report SHA-256 does not match")
        policy_payload = policy_file.read_bytes()
        expected = {
            report_file: comparison_report_sha256,
            policy_file: sha256(policy_payload).hexdigest(),
        }
        report = _parse_json_bytes(report_payload, source_path=report_file.as_posix())
        policy = _parse_json_bytes(policy_payload, source_path=policy_file.as_posix())
        validate_embedding_retrieval_comparison_report(report)
        validate_embedding_model_selection_policy(policy, comparison_report=report)
        selection = evaluate_embedding_model_candidates(report, policy=policy)
        validate_embedding_model_selection(selection, comparison_report=report, policy=policy)
        payload = _serialize_selection(selection)

        def check_inputs() -> None:
            check_paths()
            _assert_input_hashes(expected)

        check_inputs()
        summary = {
            "output_path": output.relative_to(REPOSITORY_ROOT.resolve()).as_posix(),
            "output_size_bytes": len(payload), "output_sha256": sha256(payload).hexdigest(),
            "evaluation_id": selection["evaluation_id"],
            "baseline_candidate_id": selection["baseline_candidate_id"],
            "eligible_candidate_count": selection["metadata"]["eligible_candidate_count"],
            "decision": selection["decision"],
            "recommended_candidate_id": selection["recommended_candidate_id"],
            "review_status": selection["review"]["review_status"],
        }
        _atomic_write_selection(
            output, payload, overwrite=overwrite, comparison_report=report,
            policy=policy, check_inputs=check_inputs,
        )
        return summary
    except EmbeddingModelSelectionCliError:
        raise
    except Exception as exc:
        raise EmbeddingModelSelectionCliError(f"cannot select embedding model: {exc}") from exc


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise EmbeddingModelSelectionCliError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description=__doc__)
    parser.add_argument("--comparison-report", type=Path, required=True)
    parser.add_argument("--comparison-report-sha256", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    try:
        args = parser.parse_args(argv)
        summary = run_selection_cli(
            comparison_report_path=args.comparison_report,
            comparison_report_sha256=args.comparison_report_sha256,
            policy_path=args.policy, output_path=args.output, overwrite=args.overwrite,
        )
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
