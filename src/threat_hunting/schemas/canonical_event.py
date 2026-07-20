"""Versioned contract for a future canonical event representation."""

from __future__ import annotations


CANONICAL_SCHEMA_VERSION = "canonical-event/v2"


CANONICAL_FIELDS: tuple[dict[str, object], ...] = (
    {"name": "event_id", "type": "string", "nullable": True},
    {
        "name": "timestamp",
        "type": "rfc3339-utc-string",
        "nullable": True,
    },
    {"name": "channel", "type": "string", "nullable": True},
    {"name": "provider", "type": "string", "nullable": True},
    {"name": "host", "type": "string", "nullable": True},
    {
        "name": "user",
        "type": "string",
        "nullable": True,
        "description": (
            "Generic user value when the source does not express a reliable "
            "actor or target role."
        ),
    },
    {
        "name": "subject_user",
        "type": "string",
        "nullable": True,
        "description": "Actor or subject user when event semantics support that role.",
    },
    {
        "name": "target_user",
        "type": "string",
        "nullable": True,
        "description": "Account or user affected by the event.",
    },
    {"name": "source_ip", "type": "string", "nullable": True},
    {
        "name": "source_port",
        "type": "integer",
        "nullable": True,
        "expected_source_transformation": "validated string-to-integer",
    },
    {"name": "destination_ip", "type": "string", "nullable": True},
    {
        "name": "destination_port",
        "type": "integer",
        "nullable": True,
        "expected_source_transformation": "validated string-to-integer",
    },
    {"name": "process_name", "type": "string", "nullable": True},
    {"name": "process_id", "type": "string", "nullable": True},
    {"name": "process_guid", "type": "string", "nullable": True},
    {"name": "parent_process_name", "type": "string", "nullable": True},
    {"name": "parent_process_id", "type": "string", "nullable": True},
    {"name": "parent_process_guid", "type": "string", "nullable": True},
    {"name": "command_line", "type": "string", "nullable": True},
    {"name": "parent_command_line", "type": "string", "nullable": True},
    {"name": "file_path", "type": "string", "nullable": True},
    {"name": "registry_key", "type": "string", "nullable": True},
    {"name": "dns_query", "type": "string", "nullable": True},
    {"name": "raw_record_ref", "type": "string", "nullable": False},
    {"name": "source_file", "type": "string", "nullable": False},
)


def canonical_schema_document() -> dict[str, object]:
    """Return a JSON-serializable schema contract, not normalized data."""

    return {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "status": "proposed_reviewable",
        "description": (
            "Reusable canonical event contract used by normalization. Normalization "
            "emits one canonical event for every raw record and applies only "
            "reviewed, context-aware transformations. Unsupported context-specific "
            "fields remain null and are reported as review issues."
        ),
        "normalization_contract": {
            "cardinality": "one_raw_record_to_one_canonical_event",
            "filtering": "none",
            "deduplication": "none",
        },
        "fields": [dict(field) for field in CANONICAL_FIELDS],
        "raw_record_ref_formats": {
            "jsonl": "jsonl:line:<one-based-physical-line>",
            "json_array": "json-array:index:<zero-based-index>",
            "json_object": "json-object:root",
        },
    }
