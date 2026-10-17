from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from threat_hunting.discovery import DiscoveryError, discover_inputs
from threat_hunting.run_spec import InputSpec


class DiscoveryTests(unittest.TestCase):
    def test_resolves_exact_filename_and_rejects_duplicate_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "nested" / "record.json"
            source.parent.mkdir()
            source.write_text("{}", encoding="utf-8")

            discovered = discover_inputs((InputSpec("record.json", 1),), root)
            self.assertEqual(discovered[0].path, source.resolve())
            self.assertEqual(discovered[0].repository_relative_path, "nested/record.json")

            with self.assertRaisesRegex(DiscoveryError, "Duplicate resolved input"):
                discover_inputs(
                    (InputSpec("record.json"), InputSpec("nested/record.json")), root
                )

    def test_rejects_ambiguous_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ("a", "b"):
                path = root / directory / "same.json"
                path.parent.mkdir()
                path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(DiscoveryError, "ambiguous"):
                discover_inputs((InputSpec("same.json"),), root)


if __name__ == "__main__":
    unittest.main()
