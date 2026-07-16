"""Versioned contract for a future canonical event representation."""

from __future__ import annotations


CANONICAL_SCHEMA_VERSION = "canonical-event/v1"


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
    {"name": "user", "type": "string", "nullable": True},
    {"name": "source_ip", "type": "string", "nullable": True},
    {"name": "source_port", "type": "integer", "nullable": True},
    {"name": "destination_ip", "type": "string", "nullable": True},
    {"name": "destination_port", "type": "integer", "nullable": True},
    {"name": "process_name", "type": "string", "nullable": True},
    {"name": "process_id", "type": "string", "nullable": True},
    {"name": "parent_process_name", "type": "string", "nullable": True},
    {"name": "parent_process_id", "type": "string", "nullable": True},
    {"name": "command_line", "type": "string", "nullable": True},
    {"name": "file_path", "type": "string", "nullable": True},
    {"name": "registry_key", "type": "string", "nullable": True},
    {"name": "dns_query", "type": "string", "nullable": True},
    {"name": "raw_record_ref", "type": "string", "nullable": False},
    {"name": "source_file", "type": "string", "nullable": False},
)


SOURCE_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "event_id": ("EventID", "EventId", "event_id", "EventCode"),
    "timestamp": (
        "@timestamp",
        "EventTime",
        "TimeCreated",
        "UtcTime",
        "CreationUtcTime",
    ),
    "channel": ("Channel", "channel"),
    "provider": ("SourceName", "ProviderName", "provider"),
    "host": ("Hostname", "host", "Computer", "ComputerName"),
    "user": (
        "User",
        "SubjectUserName",
        "TargetUserName",
        "AccountName",
        "user",
    ),
    "source_ip": ("SourceIp", "SourceAddress", "Source_Network_Address"),
    "source_port": ("SourcePort",),
    "destination_ip": ("DestinationIp", "DestAddress"),
    "destination_port": ("DestinationPort", "DestPort"),
    "process_name": ("Image", "ProcessName", "NewProcessName"),
    "process_id": ("ProcessId", "ProcessID", "NewProcessId"),
    "parent_process_name": ("ParentImage", "ParentProcessName"),
    "parent_process_id": ("ParentProcessId",),
    "command_line": ("CommandLine",),
    "file_path": ("TargetFilename", "FileName", "KeyFilePath"),
    "registry_key": ("TargetObject", "RegistryKey"),
    "dns_query": ("QueryName",),
}


def canonical_schema_document() -> dict[str, object]:
    """Return a JSON-serializable schema contract, not normalized data."""

    return {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "description": (
            "Proposed reusable canonical event contract. The inspection step does "
            "not emit canonical events or apply conversions."
        ),
        "fields": [dict(field) for field in CANONICAL_FIELDS],
        "raw_record_ref_formats": {
            "jsonl": "jsonl:line:<one-based-physical-line>",
            "json_array": "json-array:index:<zero-based-index>",
            "json_object": "json-object:root",
        },
    }

