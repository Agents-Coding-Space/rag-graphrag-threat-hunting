"""Load declarative inspection run specifications."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


class RunSpecError(ValueError):
    """Raised when a run specification is invalid."""


@dataclass(frozen=True)
class InputSpec:
    """One requested input and its optional integrity baseline."""

    input_value: str
    expected_record_count: int | None = None


@dataclass(frozen=True)
class RunSpec:
    """Inputs for one reproducible inspection run."""

    experiment_id: str
    inputs: tuple[InputSpec, ...]


def load_run_spec(path: Path) -> RunSpec:
    """Read and validate a JSON run specification."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunSpecError(f"Cannot read run specification {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise RunSpecError("Run specification root must be a JSON object")

    experiment_id = payload.get("experiment_id")
    raw_inputs = payload.get("inputs")
    if not isinstance(experiment_id, str) or not experiment_id.strip():
        raise RunSpecError("experiment_id must be a non-empty string")
    if not isinstance(raw_inputs, list) or not raw_inputs:
        raise RunSpecError("inputs must be a non-empty array")

    inputs: list[InputSpec] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_inputs):
        if not isinstance(item, dict):
            raise RunSpecError(f"inputs[{index}] must be an object")
        input_value = item.get("filename", item.get("path"))
        expected = item.get("expected_record_count")
        if not isinstance(input_value, str) or not input_value.strip():
            raise RunSpecError(f"inputs[{index}] needs a non-empty filename or path")
        if expected is not None and (not isinstance(expected, int) or expected < 0):
            raise RunSpecError(
                f"inputs[{index}].expected_record_count must be a non-negative integer"
            )
        if input_value in seen:
            raise RunSpecError(f"Duplicate input in run specification: {input_value}")
        seen.add(input_value)
        inputs.append(InputSpec(input_value=input_value, expected_record_count=expected))

    return RunSpec(experiment_id=experiment_id, inputs=tuple(inputs))

