"""Shared provider and Event ID aware canonical mapping registry."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass


SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"

# These aliases identify the structural context only. They are not automatic
# source-to-canonical field mappings.
EVENT_ID_CONTEXT_ALIASES = ("EventID", "EventId", "event_id", "EventCode")
PROVIDER_CONTEXT_ALIASES = ("SourceName", "ProviderName", "provider")

TIMESTAMP_FIELDS = (
    "@timestamp",
    "TimeCreated",
    "EventTime",
    "UtcTime",
    "CreationUtcTime",
)
EVENT_OCCURRENCE_TIMESTAMP_FIELDS = (
    "@timestamp",
    "TimeCreated",
    "EventTime",
)
TIMESTAMP_REVIEW_ONLY_FIELDS = ("UtcTime",)
TIMESTAMP_EXCLUDED_OCCURRENCE_FIELDS = ("CreationUtcTime",)
TIMESTAMP_MAPPING_FIELDS = (
    EVENT_OCCURRENCE_TIMESTAMP_FIELDS + TIMESTAMP_REVIEW_ONLY_FIELDS
)
TIMESTAMP_CONFLICT_THRESHOLD_SECONDS = 60.0

BASE_FIELD_SOURCE_PATHS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("channel", ("/Channel",)),
    ("host", ("/Hostname", "/Computer", "/ComputerName", "/host/hostname")),
)

SECURITY_RELEVANT_CONTEXTS = (
    ("Security 4625", SECURITY_PROVIDER, "4625"),
    ("Security 4776", SECURITY_PROVIDER, "4776"),
    ("Security 4769", SECURITY_PROVIDER, "4769"),
    ("Sysmon 1", SYSMON_PROVIDER, "1"),
    ("Security 4688", SECURITY_PROVIDER, "4688"),
    ("Sysmon 3", SYSMON_PROVIDER, "3"),
    ("Security 5156", SECURITY_PROVIDER, "5156"),
    ("Sysmon 10", SYSMON_PROVIDER, "10"),
    ("Sysmon 12", SYSMON_PROVIDER, "12"),
    ("Sysmon 13", SYSMON_PROVIDER, "13"),
    ("Sysmon 14", SYSMON_PROVIDER, "14"),
    ("Sysmon 22", SYSMON_PROVIDER, "22"),
)

SYSMON_10_PROCESS_ROLES = (
    ("/SourceImage", "source_process_image"),
    ("/SourceProcessId", "source_process_id"),
    ("/SourceProcessGUID", "source_process_guid"),
    ("/TargetImage", "target_process_image"),
    ("/TargetProcessId", "target_process_id"),
    ("/TargetProcessGUID", "target_process_guid"),
)


@dataclass(frozen=True)
class EventContext:
    """Provider and Event ID values resolved without applying field mappings."""

    provider: str | None
    event_id: str | None
    provider_source_path: str | None
    event_id_source_path: str | None
    provider_raw_value: object | None
    event_id_raw_value: object | None


@dataclass(frozen=True)
class MappingRule:
    """One context-specific source-to-canonical mapping rule."""

    canonical_field: str
    provider: str
    event_id: str
    source_path: str
    rationale: str
    expected_transformation: str = "none"


def _first_structural_match(
    record: Mapping[str, object],
    aliases: tuple[str, ...],
) -> tuple[str, object] | None:
    folded = {
        str(key).casefold(): (str(key), value) for key, value in record.items()
    }
    for alias in aliases:
        if alias.casefold() in folded:
            return folded[alias.casefold()]
    return None


def _resolve_context(record: Mapping[str, object]) -> EventContext:
    """Resolve provider and Event ID only; do not normalize other fields."""

    provider_match = _first_structural_match(record, PROVIDER_CONTEXT_ALIASES)
    event_id_match = _first_structural_match(record, EVENT_ID_CONTEXT_ALIASES)
    provider = provider_match[1] if provider_match is not None else None
    event_id = event_id_match[1] if event_id_match is not None else None
    return EventContext(
        provider=str(provider) if provider is not None else None,
        event_id=str(event_id) if event_id is not None else None,
        provider_source_path=(
            f"/{provider_match[0]}" if provider_match is not None else None
        ),
        event_id_source_path=(
            f"/{event_id_match[0]}" if event_id_match is not None else None
        ),
        provider_raw_value=provider,
        event_id_raw_value=event_id,
    )


def _build_mapping_rules() -> tuple[MappingRule, ...]:
    rules: list[MappingRule] = []

    def add(
        canonical_field: str,
        provider: str,
        event_ids: tuple[str, ...] | list[str],
        source_paths: tuple[str, ...],
        rationale: str,
        expected_transformation: str = "none",
    ) -> None:
        for event_id in event_ids:
            for source_path in source_paths:
                rules.append(
                    MappingRule(
                        canonical_field=canonical_field,
                        provider=provider,
                        event_id=event_id,
                        source_path=source_path,
                        rationale=rationale,
                        expected_transformation=expected_transformation,
                    )
                )

    relevant_by_provider: dict[str, list[str]] = {}
    for _, provider, event_id in SECURITY_RELEVANT_CONTEXTS:
        relevant_by_provider.setdefault(provider, []).append(event_id)
    for provider, event_ids in relevant_by_provider.items():
        base_paths = dict(BASE_FIELD_SOURCE_PATHS)
        add(
            "event_id",
            provider,
            event_ids,
            ("/EventID", "/EventId", "/EventCode"),
            "Event identifier in this provider-specific structural context.",
        )
        add(
            "provider",
            provider,
            event_ids,
            ("/SourceName", "/ProviderName"),
            "Provider identity used to interpret Event ID semantics.",
        )
        add(
            "channel",
            provider,
            event_ids,
            base_paths["channel"],
            "Event channel in this provider and Event ID context.",
        )
        add(
            "host",
            provider,
            event_ids,
            base_paths["host"],
            "Host identity candidate; context is retained for review.",
        )
        add(
            "timestamp",
            provider,
            event_ids,
            tuple(f"/{field}" for field in TIMESTAMP_MAPPING_FIELDS),
            (
                "Timestamp candidate for this provider and Event ID. Source "
                "timezone semantics must be reviewed before normalization."
            ),
            "parse_after_timezone_semantics_review",
        )

    add(
        "process_name",
        SYSMON_PROVIDER,
        ("1",),
        ("/Image",),
        "Sysmon Event ID 1 Image is the created process image.",
    )
    add(
        "process_id",
        SYSMON_PROVIDER,
        ("1",),
        ("/ProcessId",),
        "Sysmon Event ID 1 ProcessId identifies the created process.",
    )
    add(
        "process_guid",
        SYSMON_PROVIDER,
        ("1",),
        ("/ProcessGuid",),
        "Sysmon Event ID 1 ProcessGuid identifies the created process.",
    )
    add(
        "parent_process_name",
        SYSMON_PROVIDER,
        ("1",),
        ("/ParentImage",),
        "Sysmon Event ID 1 ParentImage is the creator process image.",
    )
    add(
        "parent_process_id",
        SYSMON_PROVIDER,
        ("1",),
        ("/ParentProcessId",),
        "Sysmon Event ID 1 ParentProcessId identifies the creator process.",
    )
    add(
        "parent_process_guid",
        SYSMON_PROVIDER,
        ("1",),
        ("/ParentProcessGuid",),
        "Sysmon Event ID 1 ParentProcessGuid identifies the creator process.",
    )
    add(
        "command_line",
        SYSMON_PROVIDER,
        ("1",),
        ("/CommandLine",),
        "Sysmon Event ID 1 CommandLine belongs to the created process.",
    )
    add(
        "parent_command_line",
        SYSMON_PROVIDER,
        ("1",),
        ("/ParentCommandLine",),
        "Sysmon Event ID 1 ParentCommandLine belongs to the creator process.",
    )
    add(
        "user",
        SYSMON_PROVIDER,
        ("1",),
        ("/User",),
        "Sysmon Event ID 1 User is retained as a generic process user.",
    )

    add(
        "process_name",
        SECURITY_PROVIDER,
        ("4688",),
        ("/NewProcessName",),
        "Security Event ID 4688 NewProcessName is the created process image.",
    )
    add(
        "process_id",
        SECURITY_PROVIDER,
        ("4688",),
        ("/NewProcessId",),
        "Security Event ID 4688 NewProcessId identifies the created process.",
    )
    add(
        "parent_process_name",
        SECURITY_PROVIDER,
        ("4688",),
        ("/ParentProcessName",),
        "Security Event ID 4688 ParentProcessName is the creator process image.",
    )
    add(
        "parent_process_id",
        SECURITY_PROVIDER,
        ("4688",),
        ("/ProcessId",),
        (
            "Security Event ID 4688 ProcessId identifies the creator process, "
            "not the new process."
        ),
    )
    add(
        "command_line",
        SECURITY_PROVIDER,
        ("4688",),
        ("/CommandLine",),
        "Security Event ID 4688 CommandLine belongs to the new process.",
    )
    add(
        "subject_user",
        SECURITY_PROVIDER,
        ("4688",),
        ("/SubjectUserName",),
        "Security Event ID 4688 SubjectUserName is the actor creating the process.",
    )

    add(
        "subject_user",
        SECURITY_PROVIDER,
        ("4625",),
        ("/SubjectUserName",),
        "Security Event ID 4625 SubjectUserName identifies the authentication actor.",
    )
    add(
        "target_user",
        SECURITY_PROVIDER,
        ("4625", "4776", "4769"),
        ("/TargetUserName",),
        "Authentication event semantics identify TargetUserName as affected account.",
    )
    add(
        "process_name",
        SECURITY_PROVIDER,
        ("4625",),
        ("/ProcessName",),
        "Security Event ID 4625 ProcessName is the process involved in the failed logon.",
    )
    add(
        "source_ip",
        SECURITY_PROVIDER,
        ("4769",),
        ("/IpAddress",),
        "Security Event ID 4769 IpAddress is the Kerberos request source address.",
    )

    sysmon_process_contexts = ("3", "12", "13", "14", "22")
    add(
        "process_name",
        SYSMON_PROVIDER,
        sysmon_process_contexts,
        ("/Image",),
        "Sysmon Image identifies the process owning this contextual event.",
    )
    add(
        "process_id",
        SYSMON_PROVIDER,
        sysmon_process_contexts,
        ("/ProcessId",),
        "Sysmon ProcessId identifies the process owning this contextual event.",
    )
    add(
        "process_guid",
        SYSMON_PROVIDER,
        sysmon_process_contexts,
        ("/ProcessGuid",),
        "Sysmon ProcessGuid identifies the process owning this contextual event.",
    )
    add(
        "user",
        SYSMON_PROVIDER,
        ("3",),
        ("/User",),
        "Sysmon Event ID 3 User is retained as a generic network process user.",
    )

    add(
        "source_ip",
        SYSMON_PROVIDER,
        ("3",),
        ("/SourceIp",),
        "Sysmon Event ID 3 SourceIp is the network source address.",
    )
    add(
        "source_port",
        SYSMON_PROVIDER,
        ("3",),
        ("/SourcePort",),
        "Sysmon Event ID 3 SourcePort is the network source port.",
        "validated_string_to_integer",
    )
    add(
        "destination_ip",
        SYSMON_PROVIDER,
        ("3",),
        ("/DestinationIp",),
        "Sysmon Event ID 3 DestinationIp is the network destination address.",
    )
    add(
        "destination_port",
        SYSMON_PROVIDER,
        ("3",),
        ("/DestinationPort",),
        "Sysmon Event ID 3 DestinationPort is the network destination port.",
        "validated_string_to_integer",
    )
    add(
        "source_ip",
        SECURITY_PROVIDER,
        ("5156",),
        ("/SourceAddress",),
        "Security Event ID 5156 SourceAddress is the network source address.",
    )
    add(
        "source_port",
        SECURITY_PROVIDER,
        ("5156",),
        ("/SourcePort",),
        "Security Event ID 5156 SourcePort is the network source port.",
        "validated_string_to_integer",
    )
    add(
        "destination_ip",
        SECURITY_PROVIDER,
        ("5156",),
        ("/DestAddress",),
        "Security Event ID 5156 DestAddress is the destination address.",
    )
    add(
        "destination_port",
        SECURITY_PROVIDER,
        ("5156",),
        ("/DestPort",),
        "Security Event ID 5156 DestPort is the destination port.",
        "validated_string_to_integer",
    )

    add(
        "registry_key",
        SYSMON_PROVIDER,
        ("12", "13", "14"),
        ("/TargetObject",),
        "Sysmon registry Event IDs 12, 13, and 14 give TargetObject registry semantics.",
    )
    add(
        "dns_query",
        SYSMON_PROVIDER,
        ("22",),
        ("/QueryName",),
        "Sysmon Event ID 22 QueryName is a DNS query name.",
    )
    return tuple(rules)


_MAPPING_RULES = _build_mapping_rules()


@dataclass(frozen=True)
class MappingRegistry:
    """Immutable canonical mapping registry shared by all pipeline stages."""

    rules: tuple[MappingRule, ...]

    def resolve_context(self, record: Mapping[str, object]) -> EventContext:
        return _resolve_context(record)

    def iter_mapping_rules(self) -> Iterator[MappingRule]:
        return iter(self.rules)

    def rules_for(
        self,
        provider: str | None,
        event_id: str | None,
    ) -> tuple[MappingRule, ...]:
        if provider is None or event_id is None:
            return ()
        return tuple(
            rule
            for rule in self.rules
            if rule.provider == provider and rule.event_id == event_id
        )


DEFAULT_MAPPING_REGISTRY = MappingRegistry(rules=_MAPPING_RULES)


def resolve_context(record: Mapping[str, object]) -> EventContext:
    """Resolve context through the default shared registry."""

    return DEFAULT_MAPPING_REGISTRY.resolve_context(record)


def iter_mapping_rules() -> Iterator[MappingRule]:
    """Iterate over the immutable registry in deterministic declaration order."""

    return DEFAULT_MAPPING_REGISTRY.iter_mapping_rules()


def rules_for(provider: str | None, event_id: str | None) -> tuple[MappingRule, ...]:
    """Return all rules for an exact provider and Event ID context."""

    return DEFAULT_MAPPING_REGISTRY.rules_for(provider, event_id)
