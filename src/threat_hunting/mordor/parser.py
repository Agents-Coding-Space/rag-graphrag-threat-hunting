"""Streaming record parsers for supported JSON container formats."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import IO, Iterator, Literal


SupportedFormat = Literal["jsonl", "json_array", "json_object"]


class MordorParseError(ValueError):
    """Raised when a source cannot be parsed as its confirmed format."""


@dataclass(frozen=True)
class ParsedRecord:
    """One source record and its stable within-file reference."""

    data: dict[str, object]
    raw_record_ref: str


class _IncrementalJSONReader:
    """Decode JSON values from a bounded text buffer."""

    def __init__(self, stream: IO[str], chunk_size: int = 64 * 1024) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        self._stream = stream
        self._chunk_size = chunk_size
        self._decoder = json.JSONDecoder()
        self._buffer = ""
        self._position = 0
        self._eof = False

    def _compact(self) -> None:
        if self._position:
            self._buffer = self._buffer[self._position :]
            self._position = 0

    def _read_more(self) -> bool:
        if self._eof:
            return False
        self._compact()
        chunk = self._stream.read(self._chunk_size)
        if chunk == "":
            self._eof = True
            return False
        self._buffer += chunk
        return True

    def _ensure_content(self) -> bool:
        while self._position >= len(self._buffer) and not self._eof:
            if not self._read_more():
                break
        return self._position < len(self._buffer)

    def skip_whitespace(self) -> None:
        while True:
            while self._position < len(self._buffer) and self._buffer[
                self._position
            ].isspace():
                self._position += 1
            if self._position < len(self._buffer) or self._eof:
                return
            self._read_more()

    def peek(self) -> str | None:
        self.skip_whitespace()
        if not self._ensure_content():
            return None
        return self._buffer[self._position]

    def consume(self, expected: str) -> None:
        actual = self.peek()
        if actual != expected:
            raise MordorParseError(f"Expected {expected!r}, found {actual!r}")
        self._position += 1

    def decode_value(self) -> object:
        self.skip_whitespace()
        while True:
            try:
                value, end = self._decoder.raw_decode(self._buffer, self._position)
            except json.JSONDecodeError as exc:
                if self._read_more():
                    continue
                raise MordorParseError(
                    f"Invalid or incomplete JSON value near character {exc.pos}: {exc.msg}"
                ) from exc
            self._position = end
            return value

    def require_eof(self) -> None:
        self.skip_whitespace()
        if self._ensure_content():
            raise MordorParseError("Unexpected data after the top-level JSON value")


def iter_json_array(path: Path, chunk_size: int = 64 * 1024) -> Iterator[ParsedRecord]:
    """Yield object elements from a JSON array without loading the array."""

    try:
        stream = path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise MordorParseError(f"Cannot open {path}: {exc}") from exc

    with stream:
        reader = _IncrementalJSONReader(stream, chunk_size=chunk_size)
        reader.consume("[")
        if reader.peek() == "]":
            reader.consume("]")
            reader.require_eof()
            return

        index = 0
        while True:
            value = reader.decode_value()
            if not isinstance(value, dict):
                raise MordorParseError(
                    f"JSON array item {index} must be an object, got "
                    f"{type(value).__name__}"
                )
            yield ParsedRecord(value, f"json-array:index:{index}")
            index += 1

            separator = reader.peek()
            if separator == ",":
                reader.consume(",")
                if reader.peek() == "]":
                    raise MordorParseError("Trailing comma is not valid JSON")
                continue
            if separator == "]":
                reader.consume("]")
                reader.require_eof()
                return
            raise MordorParseError(
                f"Expected ',' or ']' after JSON array item {index - 1}, "
                f"found {separator!r}"
            )


def iter_jsonl(path: Path) -> Iterator[ParsedRecord]:
    """Yield one object per non-blank physical line."""

    try:
        stream = path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise MordorParseError(f"Cannot open {path}: {exc}") from exc

    with stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise MordorParseError(
                    f"Invalid JSONL record at line {line_number}: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise MordorParseError(
                    f"JSONL record at line {line_number} must be an object, got "
                    f"{type(value).__name__}"
                )
            yield ParsedRecord(value, f"jsonl:line:{line_number}")


def iter_json_object(path: Path) -> Iterator[ParsedRecord]:
    """Yield a single root JSON object."""

    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise MordorParseError(f"Invalid JSON object in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MordorParseError(
            f"JSON object source must have an object root, got {type(value).__name__}"
        )
    yield ParsedRecord(value, "json-object:root")


def iter_records(path: Path, source_format: SupportedFormat) -> Iterator[ParsedRecord]:
    """Dispatch to a parser only after format detection has completed."""

    if source_format == "jsonl":
        yield from iter_jsonl(path)
    elif source_format == "json_array":
        yield from iter_json_array(path)
    elif source_format == "json_object":
        yield from iter_json_object(path)
    else:
        raise MordorParseError(f"Unsupported confirmed format: {source_format}")

