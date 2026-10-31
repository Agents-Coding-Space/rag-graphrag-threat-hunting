"""Prepare, execute or recover frozen RAG/GraphRAG comparisons (offline by default)."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threat_hunting.evaluation.experimental_comparison import run_comparison
from threat_hunting.evaluation import experimental_comparison as pipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/evaluation/experimental_comparison.json")
    parser.add_argument("--output", type=Path, required=True, help="New directory; existing results are never overwritten")
    parser.add_argument("--live", action="store_true", help="Explicitly allow LLM HTTP requests; default is offline dry-run")
    parser.add_argument("--max-requests", type=int, help="Required with --live; hard cap 1..30, no retries")
    parser.add_argument("--case-ids", help="Predeclared comma-separated complete case pairs, e.g. PS02,RG03")
    parser.add_argument("--branch-keys", help="Explicit comma-separated CASE:rag or CASE:graphrag keys for a new study")
    parser.add_argument("--pin", type=Path, help="Frozen runtime/config provenance; required for integrated live evaluation")
    parser.add_argument("--resume-from", type=Path, help="Recover individual outcome=provider_error branches only")
    parser.add_argument("--include-not-run", action="store_true", help="With recovery, explicitly include pending not_run branches from the checkpoint")
    parser.add_argument("--harness-compatibility", type=Path, help="Explicit before/after orchestration hashes for recovery against a historical pin")
    parser.add_argument("--request-interval-seconds", type=float, default=0,
                        help="Minimum monotonic gap after an LLM attempt ends; default 0")
    args = parser.parse_args(argv)
    if args.live and args.max_requests is None:
        parser.error("--live requires an explicit --max-requests budget")
    if args.max_requests is not None and not 1 <= args.max_requests <= 30:
        parser.error("--max-requests must be in 1..30")
    if not math.isfinite(args.request_interval_seconds) or args.request_interval_seconds < 0:
        parser.error("--request-interval-seconds must be finite and nonnegative")
    if args.resume_from and (args.case_ids is not None or args.branch_keys is not None or args.pin is None):
        parser.error("--resume-from requires --pin and cannot be combined with case/branch selection")
    if args.include_not_run and not args.resume_from:
        parser.error("--include-not-run requires --resume-from")
    if args.branch_keys is not None and args.case_ids is not None:
        parser.error("Choose --branch-keys or --case-ids")
    if args.harness_compatibility and not args.resume_from:
        parser.error("--harness-compatibility is only valid with --resume-from")
    try:
        if args.resume_from:
            from threat_hunting.evaluation.experimental_recovery import preflight_recovery, run_recovery
            plan = preflight_recovery(args.config, args.resume_from, pin_path=args.pin,
                compatibility_path=args.harness_compatibility, live=args.live,
                max_requests=args.max_requests, request_interval_seconds=args.request_interval_seconds,
                include_not_run=args.include_not_run)
            print(json.dumps({"preflight": "passed", "source_outcomes": plan.source_outcomes,
                "selected_branches": [{key: row[key] for key in ("case_id", "branch")} for row in plan.selected],
                "required_request_budget": plan.budget, "request_interval_seconds": plan.interval,
                "code_compatibility": plan.compatibility["mode"]}, ensure_ascii=False), flush=True)
            result = run_recovery(plan, args.output, live=args.live)
            print(json.dumps({key: result[key] for key in ("mode", "planned_branch_count", "eligible_branch_count",
                "maximum_llm_requests", "llm_http_attempts", "stopped_reason", "stop_details")}, ensure_ascii=False))
            return 130 if result["stopped_reason"] == "keyboard_interrupt" else 2 if result["stopped_reason"] else 0
        config = pipeline._read(args.config)
        if args.live and config.get('schema_version') == 'experimental-comparison-config/v2' and args.pin is None:
            parser.error('Integrated live runs require --pin from a zero-request offline preflight')
        if args.pin is not None:
            pin = pipeline._read(args.pin)
            if pipeline.sha256(args.config) != pin['config_sha256'] or pipeline.sha256(ROOT / config['benchmark']) != pin['cases_sha256']:
                raise ValueError('Frozen configuration/questions changed')
            if pipeline._source_manifest(pipeline._runtime_sources(ROOT / config['runtime_artifacts'])) != pin['artifacts']:
                raise ValueError('Frozen consumers changed')
            if pipeline._code_manifest() != pin['code_sha256']:
                raise ValueError('Frozen runtime code changed')
            if pipeline.sha256(ROOT / config['gate_policy']) != pin['gate_policy_sha256']:
                raise ValueError('Frozen gate policy changed')
            from threat_hunting.llm.config import LLMConfig
            if pipeline._safe_config(LLMConfig.from_env()) != pin['model']:
                raise ValueError('Model/provider/generation settings changed since preflight')
        result = run_comparison(args.config, args.output, live=args.live, max_requests=args.max_requests or 0,
                                case_ids=tuple(args.case_ids.split(",")) if args.case_ids is not None else None,
                                request_interval_seconds=args.request_interval_seconds,
                                **({"branch_keys": tuple(tuple(key.split(":")) for key in args.branch_keys.split(","))} if args.branch_keys is not None else {}))
    except Exception as exc:
        # Do not print provider payloads, environment values or exception bodies.
        from threat_hunting.evaluation.experimental_recovery import RecoveryPreflightError
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__,
            "reason": str(exc) if isinstance(exc, RecoveryPreflightError) else "see_offline_provenance_checks",
            "output": str(args.output)}))
        return 1
    except KeyboardInterrupt:
        print(json.dumps({"status": "interrupted_before_run", "llm_http_attempts": 0}))
        return 130
    print(json.dumps({key: result[key] for key in ("mode", "planned_branch_count", "eligible_branch_count", "llm_http_attempts", "stopped_reason")}, ensure_ascii=False))
    return 130 if result["stopped_reason"] == "keyboard_interrupt" else 0 if result["stopped_reason"] is None else 2


if __name__ == "__main__":
    raise SystemExit(main())
