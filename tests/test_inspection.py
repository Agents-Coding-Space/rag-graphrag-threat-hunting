from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from threat_hunting.discovery import DiscoveredInput
from threat_hunting.mordor.format_detection import detect_format
from threat_hunting.mordor.inspection import inspect_file


class InspectionTests(unittest.TestCase):
    def test_missing_and_null_are_counted_separately_without_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "records.json"
            records = [
                {"EventID": 1, "nullable": None, "present": "a", "nested": {"x": 1}},
                {"EventID": 2, "present": "b", "nested": {}},
                {"EventID": None},
            ]
            path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            source = DiscoveredInput(
                requested_value=path.name,
                path=path,
                repository_relative_path=path.name,
                expected_record_count=4,
            )

            report = inspect_file(source, detect_format(path))
            fields = {
                item["path"]: item
                for item in report["observed_schema"]["field_paths"]
            }

            self.assertEqual(fields["/nullable"]["present_count"], 1)
            self.assertEqual(fields["/nullable"]["missing_count"], 2)
            self.assertEqual(fields["/nullable"]["null_count"], 1)
            self.assertEqual(fields["/nullable"]["non_null_count"], 0)
            self.assertEqual(fields["/present"]["missing_count"], 1)
            self.assertEqual(report["record_count_check"]["status"], "mismatch")
            self.assertEqual(report["status"], "baseline_mismatch")
            self.assertIn("distinct_field_path_count", report["observed_schema"])
            self.assertIn("top_level", report["observed_schema"])
            self.assertIn("canonical_mapping_proposals", report)
            self.assertNotIn("canonical_events", report)
            self.assertEqual(
                report["canonical_mapping_proposals"]["event_id"]["status"],
                "candidate",
            )


if __name__ == "__main__":
    unittest.main()
