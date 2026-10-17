from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from threat_hunting.mordor.format_detection import FormatDetectionError, detect_format
from threat_hunting.mordor.parser import iter_json_array, iter_records


FIXTURES = Path(__file__).parent / "fixtures" / "mordor"


class FormatAndParserTests(unittest.TestCase):
    def test_detects_and_fully_validates_all_supported_formats(self) -> None:
        cases = {
            "sample.jsonl": ("jsonl", 2),
            "sample-array.json": ("json_array", 2),
            "sample-object.json": ("json_object", 1),
        }
        for filename, expected in cases.items():
            with self.subTest(filename=filename):
                detection = detect_format(FIXTURES / filename)
                self.assertEqual(detection.source_format, expected[0])
                self.assertEqual(detection.validated_record_count, expected[1])
                self.assertTrue(detection.fully_validated)

    def test_raw_record_references_cover_jsonl_array_and_object(self) -> None:
        expected = {
            "sample.jsonl": ["jsonl:line:1", "jsonl:line:3"],
            "sample-array.json": ["json-array:index:0", "json-array:index:1"],
            "sample-object.json": ["json-object:root"],
        }
        for filename, references in expected.items():
            with self.subTest(filename=filename):
                path = FIXTURES / filename
                source_format = detect_format(path).source_format
                actual = [item.raw_record_ref for item in iter_records(path, source_format)]
                self.assertEqual(actual, references)

    def test_json_array_parser_streams_across_small_chunks(self) -> None:
        records = list(iter_json_array(FIXTURES / "sample-array.json", chunk_size=3))
        self.assertEqual([record.data["EventID"] for record in records], [1, 2])

    def test_malformed_array_is_rejected_after_full_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text('[{"a": 1},]', encoding="utf-8")
            with self.assertRaises(FormatDetectionError):
                detect_format(path)

    def test_single_line_single_object_has_deterministic_object_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "one.json"
            path.write_text('{"a": 1}\n', encoding="utf-8")
            self.assertEqual(detect_format(path).source_format, "json_object")


if __name__ == "__main__":
    unittest.main()
