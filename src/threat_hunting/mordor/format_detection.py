"""Strict whole-file format detection for Mordor JSON sources."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .parser import MordorParseError, SupportedFormat, iter_json_array


class FormatDetectionError(ValueError):
    """Raised when a source is malformed or has an unsupported structure."""


@dataclass(frozen=True)
class FormatDetection:
    """A format classification backed by full-file validation."""

    source_format: SupportedFormat
    encoding: str
    fully_validated: bool
    validation_method: str
    validated_record_count: int
    blank_line_count: int


def _first_non_whitespace_character(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            while chunk := stream.read(64 * 1024):
                for character in chunk:
                    if not character.isspace():
                        return character
    except (OSError, UnicodeDecodeError) as exc:
        raise FormatDetectionError(f"Cannot read {path} as UTF-8: {exc}") from exc
    return None


def _validate_object_or_jsonl(path: Path) -> FormatDetection:
    line_record_count = 0
    blank_line_count = 0
    every_nonblank_line_is_object = True

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            for line in stream:
                if not line.strip():
                    blank_line_count += 1
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    every_nonblank_line_is_object = False
                    break
                if not isinstance(value, dict):
                    every_nonblank_line_is_object = False
                    break
                line_record_count += 1
    except (OSError, UnicodeDecodeError) as exc:
        raise FormatDetectionError(f"Cannot read {path} as UTF-8: {exc}") from exc

    if every_nonblank_line_is_object and line_record_count > 1:
        return FormatDetection(
            source_format="jsonl",
            encoding="utf-8-sig" if _has_utf8_bom(path) else "utf-8",
            fully_validated=True,
            validation_method="every_nonblank_line_is_one_json_object",
            validated_record_count=line_record_count,
            blank_line_count=blank_line_count,
        )

    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            root = json.load(stream)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormatDetectionError(
            f"File is neither strict JSON Lines nor one JSON object: {path}: {exc}"
        ) from exc
    if not isinstance(root, dict):
        raise FormatDetectionError(
            f"Expected an object root, got {type(root).__name__}: {path}"
        )
    return FormatDetection(
        source_format="json_object",
        encoding="utf-8-sig" if _has_utf8_bom(path) else "utf-8",
        fully_validated=True,
        validation_method="single_object_root_and_eof",
        validated_record_count=1,
        blank_line_count=blank_line_count,
    )


def _has_utf8_bom(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(3) == b"\xef\xbb\xbf"
    except OSError as exc:
        raise FormatDetectionError(f"Cannot read {path}: {exc}") from exc


def detect_format(path: Path) -> FormatDetection:
    """Classify a source only after its entire structure has validated."""

    first_character = _first_non_whitespace_character(path)
    if first_character is None:
        raise FormatDetectionError(f"Input is empty or whitespace-only: {path}")

    if first_character == "[":
        try:
            count = sum(1 for _ in iter_json_array(path))
        except MordorParseError as exc:
            raise FormatDetectionError(f"Invalid JSON array in {path}: {exc}") from exc
        return FormatDetection(
            source_format="json_array",
            encoding="utf-8-sig" if _has_utf8_bom(path) else "utf-8",
            fully_validated=True,
            validation_method="incremental_array_root_and_eof",
            validated_record_count=count,
            blank_line_count=0,
        )

    if first_character == "{":
        return _validate_object_or_jsonl(path)

    raise FormatDetectionError(
        f"Unsupported JSON root starting with {first_character!r}: {path}"
    )
