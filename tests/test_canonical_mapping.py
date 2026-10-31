from __future__ import annotations

import unittest

from threat_hunting.mordor import inspection
from threat_hunting.schemas import canonical_mapping
from threat_hunting.schemas.canonical_event import (
    CANONICAL_FIELDS,
    canonical_schema_document,
)
from threat_hunting.schemas.canonical_mapping import (
    EVENT_OCCURRENCE_TIMESTAMP_FIELDS,
    SECURITY_PROVIDER,
    SYSMON_10_PROCESS_ROLES,
    SYSMON_PROVIDER,
    TIMESTAMP_EXCLUDED_OCCURRENCE_FIELDS,
    TIMESTAMP_MAPPING_FIELDS,
    TIMESTAMP_REVIEW_ONLY_FIELDS,
    iter_mapping_rules,
    resolve_context,
    rules_for,
)


class CanonicalMappingRegistryTests(unittest.TestCase):
    def test_registry_is_deterministic_unique_and_schema_bound(self) -> None:
        first = tuple(iter_mapping_rules())
        second = tuple(iter_mapping_rules())
        self.assertEqual(first, second)
        self.assertGreater(len(first), 0)

        identities = {
            (
                rule.provider,
                rule.event_id,
                rule.source_path,
                rule.canonical_field,
            )
            for rule in first
        }
        self.assertEqual(len(identities), len(first))

        canonical_fields = {str(field["name"]) for field in CANONICAL_FIELDS}
        self.assertTrue(
            all(rule.canonical_field in canonical_fields for rule in first)
        )
        for provider, event_id in {
            (rule.provider, rule.event_id) for rule in first
        }:
            self.assertEqual(
                rules_for(provider, event_id),
                tuple(
                    rule
                    for rule in first
                    if rule.provider == provider and rule.event_id == event_id
                ),
            )

    def test_process_id_semantics_are_context_specific(self) -> None:
        security_4688 = {
            (rule.source_path, rule.canonical_field)
            for rule in rules_for(SECURITY_PROVIDER, "4688")
        }
        self.assertIn(("/ProcessId", "parent_process_id"), security_4688)
        self.assertIn(("/NewProcessId", "process_id"), security_4688)
        self.assertNotIn(("/ProcessId", "process_id"), security_4688)

        sysmon_1 = {
            (rule.source_path, rule.canonical_field)
            for rule in rules_for(SYSMON_PROVIDER, "1")
        }
        self.assertIn(("/ProcessId", "process_id"), sysmon_1)

    def test_context_sensitive_fields_are_not_broad_aliases(self) -> None:
        rules = tuple(iter_mapping_rules())
        self.assertFalse(
            any(
                rule.source_path == "/AccountName"
                and rule.canonical_field == "target_user"
                for rule in rules
            )
        )
        self.assertEqual(resolve_context({"AccountName": "alice"}).provider, None)
        self.assertEqual(resolve_context({"AccountName": "alice"}).event_id, None)

        registry_contexts = {
            (rule.provider, rule.event_id)
            for rule in rules
            if rule.source_path == "/TargetObject"
            and rule.canonical_field == "registry_key"
        }
        self.assertEqual(
            registry_contexts,
            {
                (SYSMON_PROVIDER, "12"),
                (SYSMON_PROVIDER, "13"),
                (SYSMON_PROVIDER, "14"),
            },
        )

        security_4625 = {
            (rule.source_path, rule.canonical_field)
            for rule in rules_for(SECURITY_PROVIDER, "4625")
        }
        security_4769 = {
            (rule.source_path, rule.canonical_field)
            for rule in rules_for(SECURITY_PROVIDER, "4769")
        }
        self.assertIn(("/ProcessName", "process_name"), security_4625)
        self.assertNotIn(("/ProcessId", "process_id"), security_4625)
        self.assertIn(("/IpAddress", "source_ip"), security_4769)
        self.assertNotIn(("/SubjectUserName", "subject_user"), security_4769)
        self.assertFalse(
            any(
                rule.source_path in {"/ProcessName", "/IpAddress"}
                and (rule.provider, rule.event_id)
                not in {
                    (SECURITY_PROVIDER, "4625"),
                    (SECURITY_PROVIDER, "4769"),
                }
                for rule in rules
            )
        )

    def test_sysmon_ten_roles_are_not_parent_child_mappings(self) -> None:
        role_paths = {source_path for source_path, _ in SYSMON_10_PROCESS_ROLES}
        sysmon_ten = rules_for(SYSMON_PROVIDER, "10")
        self.assertFalse(
            any(
                rule.source_path in role_paths
                and rule.canonical_field
                in {
                    "process_name",
                    "process_id",
                    "process_guid",
                    "parent_process_name",
                    "parent_process_id",
                    "parent_process_guid",
                }
                for rule in sysmon_ten
            )
        )
        self.assertEqual(
            dict(SYSMON_10_PROCESS_ROLES)["/SourceImage"],
            "source_process_image",
        )
        self.assertEqual(
            dict(SYSMON_10_PROCESS_ROLES)["/TargetImage"],
            "target_process_image",
        )

    def test_timestamp_policy_is_explicit_and_shared(self) -> None:
        self.assertEqual(
            EVENT_OCCURRENCE_TIMESTAMP_FIELDS,
            ("@timestamp", "TimeCreated", "EventTime"),
        )
        self.assertEqual(TIMESTAMP_REVIEW_ONLY_FIELDS, ("UtcTime",))
        self.assertEqual(
            TIMESTAMP_EXCLUDED_OCCURRENCE_FIELDS,
            ("CreationUtcTime",),
        )
        self.assertIn("UtcTime", TIMESTAMP_MAPPING_FIELDS)
        self.assertNotIn("CreationUtcTime", TIMESTAMP_MAPPING_FIELDS)

        timestamp_paths = {
            rule.source_path
            for rule in rules_for(SYSMON_PROVIDER, "1")
            if rule.canonical_field == "timestamp"
        }
        self.assertIn("/UtcTime", timestamp_paths)
        self.assertNotIn("/CreationUtcTime", timestamp_paths)

    def test_inspection_uses_public_shared_registry(self) -> None:
        self.assertIs(inspection.iter_mapping_rules, canonical_mapping.iter_mapping_rules)
        self.assertIs(inspection.resolve_context, canonical_mapping.resolve_context)
        self.assertFalse(hasattr(inspection, "_mapping_rules"))
        self.assertFalse(hasattr(inspection, "_MappingRule"))

    def test_schema_declares_one_to_one_normalization_contract(self) -> None:
        document = canonical_schema_document()
        expected_description = (
            "Reusable canonical event contract used by normalization. Normalization "
            "emits one canonical event for every raw record and applies only "
            "reviewed, context-aware transformations. Unsupported context-specific "
            "fields remain null and are reported as review issues."
        )
        old_description_fragment = (
            "The inspection step does not emit canonical events or apply conversions."
        )

        self.assertEqual(document["schema_version"], "canonical-event/v2")
        self.assertEqual(document["status"], "proposed_reviewable")
        self.assertEqual(document["description"], expected_description)
        self.assertNotIn(old_description_fragment, str(document["description"]))
        self.assertEqual(document["fields"], [dict(field) for field in CANONICAL_FIELDS])
        self.assertEqual(
            document["normalization_contract"],
            {
                "cardinality": "one_raw_record_to_one_canonical_event",
                "filtering": "none",
                "deduplication": "none",
            },
        )


if __name__ == "__main__":
    unittest.main()
