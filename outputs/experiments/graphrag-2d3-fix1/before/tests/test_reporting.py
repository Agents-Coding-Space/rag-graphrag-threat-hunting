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


def _report(path: str, filename: str | None = None) -> dict[str, object]:
    source_filename = filename or Path(path).name
    return {
        "status": "completed",
        "source": {
            "filename": source_filename,
            "repository_relative_path": path,
            "sha256": "a" * 64,
        },
        "format_detection": {"format": "jsonl"},
        "record_count_check": {"expected": 1, "actual": 1, "status": "match"},
        "time_range": {
            "minimum_utc": "2020-01-01T00:00:00Z",
            "maximum_utc": "2020-01-01T00:01:00Z",
        },
        "observed_schema": {"distinct_field_path_count": 3},
        "distributions": {
            "event_id": [{"value": "1", "count": 1}],
            "provider": [{"value": "Microsoft-Windows-Sysmon", "count": 1}],
        },
        "canonical_mapping_proposals": {
            name: {"status": "unavailable", "candidates": []}
            for name in (
                "timestamp",
                "host",
                "user",
                "process_name",
                "parent_process_name",
                "process_id",
                "parent_process_id",
                "command_line",
                "source_ip",
                "destination_ip",
                "destination_port",
            )
        },
        "warnings": [],
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
            self.assertTrue((output / "summary.md").is_file())
            with self.assertRaises(ReportingError):
                write_reports(output, "test", reports)

    def test_v2_manifest_summary_and_json_outputs_use_only_active_inputs(self) -> None:
        active = (
            ("purplesharp_ad_playbook_I_2020-10-22042947.json", 25993),
            ("empire_launcher_sct_regsvr32_2020-07-21232741.json", 2390),
            ("cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json", 1127),
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "mordor-selected-v2"
            reports = []
            for filename, baseline in active:
                report = _report(f"data/raw/{filename}", filename)
                report["record_count_check"] = {
                    "expected": baseline,
                    "actual": baseline,
                    "status": "match",
                }
                reports.append(report)

            manifest = write_reports(output, "mordor-selected-v2", reports)
            inputs = {Path(item["input"]).name for item in manifest["files"]}
            self.assertEqual(inputs, {item[0] for item in active})
            self.assertNotIn(
                "psh_powershell_httplistener_2020-11-0204130683.json",
                inputs,
            )
            self.assertEqual(manifest["summary"], "summary.md")
            summary = (output / "summary.md").read_text(encoding="utf-8")
            self.assertIn("mordor-selected-v2", summary)
            self.assertIn("structural inspection", summary)
            self.assertIn("`timestamp`", summary)
            self.assertIn("Source candidates (context coverage)", summary)
            self.assertNotIn("Source candidates (coverage)", summary)
            self.assertIn("Time range based on @timestamp", summary)
            self.assertNotIn("| Time range |", summary)
            self.assertIn(
                "không đồng nghĩa record hoặc dataset invalid",
                summary,
            )
            self.assertNotIn("psh_powershell_httplistener", summary)
            for json_path in output.rglob("*.json"):
                json.loads(json_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
