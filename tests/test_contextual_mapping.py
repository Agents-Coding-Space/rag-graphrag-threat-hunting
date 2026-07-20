from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from threat_hunting.discovery import DiscoveredInput
from threat_hunting.mordor.format_detection import detect_format
from threat_hunting.mordor.inspection import inspect_file
from threat_hunting.reporting import write_reports
from threat_hunting.schemas.canonical_event import canonical_schema_document


FIXTURE = Path(__file__).parent / "fixtures" / "mordor" / "contextual-mapping.jsonl"
SYSMON = "Microsoft-Windows-Sysmon"
SECURITY = "Microsoft-Windows-Security-Auditing"


def _candidate(
    report: dict[str, object],
    canonical_field: str,
    source_path: str,
    provider: str,
    event_id: str,
) -> dict[str, object] | None:
    proposal = dict(dict(report["canonical_mapping_proposals"])[canonical_field])
    for candidate in proposal["candidates"]:
        item = dict(candidate)
        if (
            item["source_path"] == source_path
            and item["provider"] == provider
            and item["event_id"] == event_id
        ):
            return item
    return None


class ContextualMappingTests(unittest.TestCase):
    def test_timestamp_occurrence_policy_and_conflicts(self) -> None:
        records = [
            {
                "SourceName": SYSMON,
                "EventID": 1,
                "@timestamp": "2020-01-01T00:00:00Z",
                "TimeCreated": "2020-01-01T00:00:00Z",
                "EventTime": "2020-01-01T00:00:00Z",
                "UtcTime": "2020-01-01 00:00:00.000",
                "CreationUtcTime": "2019-12-31 23:59:59.000",
            },
            {
                "SourceName": SYSMON,
                "EventID": 1,
                "@timestamp": "invalid",
                "TimeCreated": "2020-01-01T00:00:01Z",
            },
            {
                "SourceName": SYSMON,
                "EventID": 1,
                "TimeCreated": "invalid",
                "EventTime": "2020-01-01T00:00:02Z",
            },
            {
                "SourceName": SYSMON,
                "EventID": 1,
                "CreationUtcTime": "2020-01-01 00:00:03.000",
            },
            {
                "SourceName": SYSMON,
                "EventID": 1,
                "UtcTime": "2020-01-01 00:00:04.000",
            },
            {
                "SourceName": SYSMON,
                "EventID": 1,
                "@timestamp": "2020-01-01T00:00:05Z",
                "UtcTime": "2020-01-01 04:00:05.000",
            },
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "timestamp-policy.jsonl"
            path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            source = DiscoveredInput(
                requested_value=path.name,
                path=path,
                repository_relative_path=f"tests/generated/{path.name}",
                expected_record_count=len(records),
            )
            report = inspect_file(source, detect_format(path))

            time_range = dict(report["time_range"])
            recommendation = dict(time_range["recommendation"])
            self.assertEqual(recommendation["primary_source_field"], "@timestamp")
            self.assertEqual(
                recommendation["fallback_source_fields"],
                ["TimeCreated", "EventTime"],
            )
            self.assertEqual(
                recommendation["review_only_source_fields"], ["UtcTime"]
            )
            self.assertEqual(
                recommendation["excluded_occurrence_source_fields"],
                ["CreationUtcTime"],
            )
            self.assertEqual(
                time_range["range_source_field_counts"],
                {"@timestamp": 2, "EventTime": 1, "TimeCreated": 1},
            )
            self.assertNotIn(
                "CreationUtcTime", time_range["range_source_field_counts"]
            )
            self.assertNotIn("UtcTime", time_range["range_source_field_counts"])
            self.assertGreater(time_range["conflicting_candidate_record_count"], 0)
            self.assertEqual(report["parsing"]["invalid_record_count"], 0)
            self.assertEqual(report["status"], "completed")
            self.assertTrue(
                any("Timestamp candidates differ" in warning for warning in report["warnings"])
            )

            mappings = dict(report["canonical_mapping_proposals"])
            timestamp_candidates = {
                dict(candidate)["source_path"]: dict(candidate)
                for candidate in dict(mappings["timestamp"])["candidates"]
            }
            self.assertNotIn("/CreationUtcTime", timestamp_candidates)
            self.assertEqual(
                timestamp_candidates["/UtcTime"]["review_status"], "needs_review"
            )

            naive_path = root / "naive-timestamp.jsonl"
            naive_path.write_text(
                json.dumps(
                    {
                        "SourceName": SYSMON,
                        "EventID": 1,
                        "@timestamp": "2020-01-01 12:34:56.000",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            naive_source = DiscoveredInput(
                requested_value=naive_path.name,
                path=naive_path,
                repository_relative_path=f"tests/generated/{naive_path.name}",
                expected_record_count=1,
            )
            naive_report = inspect_file(naive_source, detect_format(naive_path))
            naive_range = dict(naive_report["time_range"])
            self.assertEqual(naive_range["minimum"], "2020-01-01T12:34:56")
            self.assertIsNone(naive_range["minimum_utc"])
            self.assertEqual(naive_range["timezone_status"], "naive_or_unavailable")

    def test_contextual_mapping_timestamp_summary_and_raw_immutability(self) -> None:
        before = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
        source = DiscoveredInput(
            requested_value=FIXTURE.name,
            path=FIXTURE,
            repository_relative_path=f"tests/fixtures/mordor/{FIXTURE.name}",
            expected_record_count=6,
        )
        report = inspect_file(source, detect_format(FIXTURE))
        after = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()

        self.assertEqual(report["schema_version"], "mordor-inspection/v2")
        self.assertEqual(before, after)
        self.assertIsNotNone(
            _candidate(report, "process_name", "/Image", SYSMON, "1")
        )
        self.assertIsNotNone(
            _candidate(report, "parent_process_name", "/ParentImage", SYSMON, "1")
        )
        self.assertIsNotNone(
            _candidate(report, "process_id", "/NewProcessId", SECURITY, "4688")
        )
        self.assertIsNotNone(
            _candidate(report, "parent_process_id", "/ProcessId", SECURITY, "4688")
        )
        self.assertIsNone(
            _candidate(report, "process_id", "/ProcessId", SECURITY, "4688")
        )

        mappings = dict(report["canonical_mapping_proposals"])
        process_paths = {
            dict(candidate)["source_path"]
            for field in ("process_name", "parent_process_name")
            for candidate in dict(mappings[field])["candidates"]
        }
        self.assertNotIn("/SourceImage", process_paths)
        self.assertNotIn("/TargetImage", process_paths)
        unmapped_paths = {
            dict(candidate)["source_path"]
            for candidate in dict(mappings["context_specific_unmapped"])["candidates"]
        }
        self.assertIn("/SourceImage", unmapped_paths)
        self.assertIn("/TargetImage", unmapped_paths)

        registry_candidates = dict(mappings["registry_key"])["candidates"]
        self.assertEqual(len(registry_candidates), 1)
        self.assertEqual(dict(registry_candidates[0])["event_id"], "13")
        self.assertIsNotNone(
            _candidate(report, "subject_user", "/SubjectUserName", SECURITY, "4688")
        )
        self.assertIsNotNone(
            _candidate(report, "target_user", "/TargetUserName", SECURITY, "4625")
        )
        self.assertIsNone(
            _candidate(report, "target_user", "/TargetUserName", SECURITY, "4688")
        )

        destination_port = _candidate(
            report, "destination_port", "/DestinationPort", SYSMON, "3"
        )
        self.assertIsNotNone(destination_port)
        self.assertEqual(
            destination_port["expected_transformation"],
            "validated_string_to_integer",
        )
        self.assertGreater(
            report["time_range"]["conflicting_candidate_record_count"], 0
        )
        self.assertTrue(
            any("Timestamp candidates differ" in warning for warning in report["warnings"])
        )

        canonical = canonical_schema_document()
        self.assertEqual(canonical["schema_version"], "canonical-event/v2")
        canonical_fields = {field["name"] for field in canonical["fields"]}
        self.assertTrue(
            {
                "subject_user",
                "target_user",
                "process_guid",
                "parent_process_guid",
                "parent_command_line",
            }.issubset(canonical_fields)
        )
        for prohibited in (
            "canonical_events",
            "evidence",
            "sigma_matches",
            "mitre_mappings",
            "ground_truth",
        ):
            self.assertNotIn(prohibited, report)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "inspection"
            write_reports(output, "fixture-contexts", [report])
            summary = (output / "summary.md").read_text(encoding="utf-8")
            self.assertIn("Distinct field paths", summary)
            self.assertNotIn("Observed fields", summary)
            self.assertIn("Security-relevant structural contexts", summary)
            for json_path in output.rglob("*.json"):
                json.loads(json_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
