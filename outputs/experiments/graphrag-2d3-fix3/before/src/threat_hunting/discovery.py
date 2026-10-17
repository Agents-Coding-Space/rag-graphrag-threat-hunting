"""Resolve requested inputs without embedding dataset paths in parsers."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Iterable

from .run_spec import InputSpec


class DiscoveryError(ValueError):
    """Raised when an input cannot be resolved unambiguously."""


@dataclass(frozen=True)
class DiscoveredInput:
    """A requested input resolved to one unique file."""

    requested_value: str
    path: Path
    repository_relative_path: str
    expected_record_count: int | None


_IGNORED_DIRECTORIES = {".git", ".venv", "__pycache__", "outputs"}


def _repository_relative(path: Path, search_root: Path) -> str:
    try:
        return path.relative_to(search_root).as_posix()
    except ValueError:
        return path.name


def _find_by_filename(filename: str, search_root: Path) -> list[Path]:
    matches: list[Path] = []
    for current_root, directories, files in os.walk(search_root):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in _IGNORED_DIRECTORIES
        )
        if filename in files:
            matches.append((Path(current_root) / filename).resolve())
    return sorted(matches, key=lambda item: item.as_posix().casefold())


def discover_input(spec: InputSpec, search_root: Path) -> DiscoveredInput:
    """Resolve one path-like input or exact filename beneath search_root."""

    root = search_root.resolve()
    raw_path = Path(spec.input_value)
    candidate = raw_path if raw_path.is_absolute() else root / raw_path

    if candidate.is_file():
        resolved = candidate.resolve()
    elif raw_path.name != spec.input_value:
        raise DiscoveryError(f"Input path does not exist: {spec.input_value}")
    else:
        matches = _find_by_filename(spec.input_value, root)
        if not matches:
            raise DiscoveryError(f"Input filename was not found: {spec.input_value}")
        if len(matches) > 1:
            rendered = ", ".join(_repository_relative(path, root) for path in matches)
            raise DiscoveryError(
                f"Input filename is ambiguous: {spec.input_value}; matches: {rendered}"
            )
        resolved = matches[0]

    return DiscoveredInput(
        requested_value=spec.input_value,
        path=resolved,
        repository_relative_path=_repository_relative(resolved, root),
        expected_record_count=spec.expected_record_count,
    )


def discover_inputs(
    specs: Iterable[InputSpec], search_root: Path
) -> tuple[DiscoveredInput, ...]:
    """Resolve all inputs and reject duplicate resolved files."""

    discovered: list[DiscoveredInput] = []
    seen: dict[Path, str] = {}
    for spec in specs:
        item = discover_input(spec, search_root)
        if item.path in seen:
            raise DiscoveryError(
                f"Duplicate resolved input {item.repository_relative_path}: "
                f"requested by {seen[item.path]!r} and {item.requested_value!r}"
            )
        seen[item.path] = item.requested_value
        discovered.append(item)
    return tuple(discovered)
