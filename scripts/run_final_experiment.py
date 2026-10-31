"""Frozen final comparison/recovery; default is zero-request dry-run."""
from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from threat_hunting.evaluation.final_experiment import run_final


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume-from", type=Path)
    parser.add_argument("--execution-pin", type=Path, help="Explicit diagnostic/stop-only code delta; generation pin stays unchanged")
    parser.add_argument("--continue-task", action="store_true", help="Resume pending first attempts and authorized failed-attempt recoveries using the existing task ledger")
    parser.add_argument("--balance-confirmation", type=Path, help="Operational receipt of an actual explicit user balance confirmation after the latest402")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    try:
        result = run_final(args.config, args.pin, args.preflight, args.output,
                           live=args.live, resume_from=args.resume_from, execution_pin=args.execution_pin,
                           continue_task=args.continue_task, balance_confirmation=args.balance_confirmation)
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}), flush=True)
        return 1
    except KeyboardInterrupt:
        print(json.dumps({"status": "interrupted"}), flush=True)
        return 130
    print(json.dumps({k: result[k] for k in ("planned_branch_count", "eligible_branch_count", "llm_http_attempts", "stopped_reason")}), flush=True)
    return 2 if result["stopped_reason"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
