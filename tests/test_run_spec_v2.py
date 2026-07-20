from __future__ import annotations

import argparse
from pathlib import Path
import unittest

from scripts.inspect_mordor import DEFAULT_SPEC, _resolve_output_directory
from threat_hunting.run_spec import load_run_spec


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class RunSpecV2Tests(unittest.TestCase):
    def test_v2_spec_contains_exact_active_inputs_and_baselines(self) -> None:
        self.assertEqual(DEFAULT_SPEC.name, "mordor_selected_v2.json")

        run_spec = load_run_spec(DEFAULT_SPEC)
        self.assertEqual(run_spec.experiment_id, "mordor-selected-v2")
        self.assertEqual(
            tuple(
                (item.input_value, item.expected_record_count)
                for item in run_spec.inputs
            ),
            (
                ("purplesharp_ad_playbook_I_2020-10-22042947.json", 25993),
                ("empire_launcher_sct_regsvr32_2020-07-21232741.json", 2390),
                ("cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json", 1127),
            ),
        )

    def test_default_output_is_scoped_to_v2_experiment(self) -> None:
        run_spec = load_run_spec(DEFAULT_SPEC)
        arguments = argparse.Namespace(output_dir=None)
        self.assertEqual(
            _resolve_output_directory(arguments, run_spec),
            (
                REPOSITORY_ROOT
                / "outputs"
                / "mordor_inspection"
                / "mordor-selected-v2"
            ).resolve(),
        )


if __name__ == "__main__":
    unittest.main()
