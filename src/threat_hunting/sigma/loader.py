"""Safe loader for the deliberately small Sigma subset used by this project."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from fnmatch import fnmatchcase
from pathlib import Path
import re
from types import MappingProxyType

import yaml


REQUIRED_RULE_FIELDS = (
    "title",
    "id",
    "status",
    "description",
    "references",
    "author",
    "date",
    "modified",
    "tags",
    "logsource",
    "detection",
    "level",
)
SUPPORTED_MODIFIERS = frozenset({"endswith", "contains"})
_SUPPORTED_CONDITION = re.compile(r"^all\s+of\s+([A-Za-z0-9_]+\*)$", re.IGNORECASE)


class SigmaRuleError(ValueError):
    """Raised when a Sigma document cannot be loaded without guessing."""


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """SafeLoader variant that also rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return copy.deepcopy(value)


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return copy.deepcopy(value)


def _required_text(document: Mapping[str, object], field: str) -> str:
    value = document.get(field)
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if not isinstance(value, str) or not value.strip():
        raise SigmaRuleError(f"Sigma rule field {field!r} must be a non-empty string")
    return value


def _required_string_sequence(
    document: Mapping[str, object],
    field: str,
) -> tuple[str, ...]:
    value = document.get(field)
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise SigmaRuleError(
            f"Sigma rule field {field!r} must be a list of non-empty strings"
        )
    return tuple(value)


def _field_expression(value: object) -> tuple[str, str | None]:
    if not isinstance(value, str) or not value.strip():
        raise SigmaRuleError("Sigma detection field names must be non-empty strings")
    parts = value.split("|")
    if len(parts) > 2 or not parts[0].strip():
        raise SigmaRuleError(f"Unsupported Sigma field expression: {value!r}")
    modifier = parts[1].strip().casefold() if len(parts) == 2 else None
    if modifier is not None and modifier not in SUPPORTED_MODIFIERS:
        raise SigmaRuleError(f"Unsupported Sigma modifier: {modifier!r}")
    return parts[0].strip(), modifier


def _validate_predicate_mapping(value: object, selection_name: str) -> None:
    if not isinstance(value, Mapping) or not value:
        raise SigmaRuleError(
            f"Sigma selection {selection_name!r} must be a non-empty mapping"
        )
    for field_expression, expected in value.items():
        _field_expression(field_expression)
        if isinstance(expected, str):
            if not expected:
                raise SigmaRuleError(
                    f"Sigma selection {selection_name!r} contains an empty value"
                )
            continue
        if (
            not isinstance(expected, Sequence)
            or isinstance(expected, (str, bytes, bytearray))
            or not expected
            or any(not isinstance(item, str) or not item for item in expected)
        ):
            raise SigmaRuleError(
                f"Sigma selection {selection_name!r} values must be strings "
                "or non-empty lists of strings"
            )


def condition_selection_names(detection: Mapping[str, object]) -> tuple[str, ...]:
    """Return all selected names for the one supported condition form."""

    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise SigmaRuleError("Sigma detection condition must be a string")
    match = _SUPPORTED_CONDITION.fullmatch(condition.strip())
    if match is None:
        raise SigmaRuleError(f"Unsupported Sigma condition: {condition!r}")
    pattern = match.group(1)
    selections = tuple(
        key for key in detection if isinstance(key, str) and key != "condition"
    )
    matched = tuple(name for name in selections if fnmatchcase(name, pattern))
    if not matched or set(matched) != set(selections):
        raise SigmaRuleError(
            "Supported 'all of' condition must select every detection selection"
        )
    return matched


def _validate_detection(value: object) -> None:
    if not isinstance(value, Mapping) or not value:
        raise SigmaRuleError("Sigma detection must be a non-empty mapping")
    selection_names = condition_selection_names(value)
    for selection_name in selection_names:
        selection = value[selection_name]
        if isinstance(selection, Mapping):
            _validate_predicate_mapping(selection, selection_name)
            continue
        if (
            not isinstance(selection, Sequence)
            or isinstance(selection, (str, bytes, bytearray))
            or not selection
        ):
            raise SigmaRuleError(
                f"Sigma selection {selection_name!r} must be a mapping or "
                "a non-empty list of mappings"
            )
        for alternative in selection:
            _validate_predicate_mapping(alternative, selection_name)


def _validate_logsource(value: object) -> None:
    if not isinstance(value, Mapping) or not value:
        raise SigmaRuleError("Sigma rule field 'logsource' must be a non-empty mapping")
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise SigmaRuleError("Sigma logsource keys must be non-empty strings")
        if not isinstance(item, str) or not item.strip():
            raise SigmaRuleError(
                f"Sigma logsource value for {key!r} must be a non-empty string"
            )


@dataclass(frozen=True)
class SigmaRule:
    """Immutable, validated Sigma rule plus source provenance."""

    title: str
    rule_id: str
    status: str
    description: str
    references: tuple[str, ...]
    author: str
    date: str
    modified: str
    tags: tuple[str, ...]
    logsource: Mapping[str, object]
    detection: Mapping[str, object]
    level: str
    sha256: str
    source_path: str

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "id": self.rule_id,
            "status": self.status,
            "description": self.description,
            "references": list(self.references),
            "author": self.author,
            "date": self.date,
            "modified": self.modified,
            "tags": list(self.tags),
            "logsource": _thaw(self.logsource),
            "detection": _thaw(self.detection),
            "level": self.level,
            "sha256": self.sha256,
            "source_path": self.source_path,
        }


def load_sigma_rule(path: Path, *, source_path: str | None = None) -> SigmaRule:
    """Load one safe, validated Sigma rule without ignoring unknown syntax."""

    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise SigmaRuleError(f"Cannot read Sigma rule {path}: {exc}") from exc
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SigmaRuleError(f"Sigma rule is not UTF-8: {path}") from exc
    try:
        document = yaml.load(text, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise SigmaRuleError(f"Invalid or unsafe Sigma YAML at {path}: {exc}") from exc
    if not isinstance(document, Mapping):
        raise SigmaRuleError(f"Sigma rule must be a YAML mapping: {path}")

    missing = [field for field in REQUIRED_RULE_FIELDS if field not in document]
    if missing:
        raise SigmaRuleError(
            f"Sigma rule {path} is missing required fields: {', '.join(missing)}"
        )
    logsource = document["logsource"]
    _validate_logsource(logsource)
    detection = document["detection"]
    _validate_detection(detection)

    return SigmaRule(
        title=_required_text(document, "title"),
        rule_id=_required_text(document, "id"),
        status=_required_text(document, "status"),
        description=_required_text(document, "description"),
        references=_required_string_sequence(document, "references"),
        author=_required_text(document, "author"),
        date=_required_text(document, "date"),
        modified=_required_text(document, "modified"),
        tags=_required_string_sequence(document, "tags"),
        logsource=_freeze(logsource),  # type: ignore[arg-type]
        detection=_freeze(detection),  # type: ignore[arg-type]
        level=_required_text(document, "level"),
        sha256=hashlib.sha256(payload).hexdigest(),
        source_path=source_path or path.as_posix(),
    )


def load_sigma_rules(
    paths: Sequence[Path],
    *,
    source_paths: Mapping[Path, str] | None = None,
) -> tuple[SigmaRule, ...]:
    """Load unique rules and return them ordered by rule ID."""

    loaded = tuple(
        load_sigma_rule(
            path,
            source_path=(source_paths or {}).get(path),
        )
        for path in paths
    )
    ids = [rule.rule_id for rule in loaded]
    if len(ids) != len(set(ids)):
        raise SigmaRuleError("Sigma rule IDs must be unique")
    return tuple(sorted(loaded, key=lambda rule: rule.rule_id))


__all__ = (
    "REQUIRED_RULE_FIELDS",
    "SUPPORTED_MODIFIERS",
    "SigmaRule",
    "SigmaRuleError",
    "condition_selection_names",
    "load_sigma_rule",
    "load_sigma_rules",
)
