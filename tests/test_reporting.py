from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from threat_hunting.reporting import (
    ReportingError,
    assign_output_directories,
    write_reports,
)


def _report(path: str) -> dict[str, object]:
    return {
        "status": "completed",
        "source": {
            "filename": "same.json",
            "repository_relative_path": path,
            "sha256": "a" * 64,
        },
        "record_count_check": {"expected": 1, "actual": 1, "status": "match"},
    }


class ReportingTests(unittest.TestCase):
    def test_output_names_are_collision_safe_and_deterministic(self) -> None:
        reports = [_report("z/same.json"), _report("a/same.json")]
        assigned = assign_output_directories(reports)
        self.assertEqual(assigned["a/same.json"], "same--aaaaaaaaaaaa--01")
        self.assertEqual(assigned["z/same.json"], "same--aaaaaaaaaaaa--02")

    def test_writes_separate_reports_and_refuses_unapproved_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "inspection"
            reports = [_report("a/same.json"), _report("b/same.json")]
            manifest = write_reports(output, "test", reports)
            self.assertEqual(manifest["input_count"], 2)
            report_paths = [output / item["report"] for item in manifest["files"]]
            self.assertEqual(len(set(report_paths)), 2)
            self.assertTrue(all(path.is_file() for path in report_paths))
            json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            with self.assertRaises(ReportingError):
                write_reports(output, "test", reports)


if __name__ == "__main__":
    unittest.main()
