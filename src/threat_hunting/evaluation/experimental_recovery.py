"""Provenance-checked recovery of individual failed harness branches.

Only orchestration changes here: exact saved inputs go through the shared
single-attempt generator/validator. No retrieval, labels or benchmark merging.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import time
from typing import Any, Callable

from . import experimental_comparison as pipeline
from ..atomic_fs import replace_with_retry


class RecoveryPreflightError(ValueError):
    """Static public error codes, never provider bodies or environment values."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RecoveryPreflightError(code)


def _check_hashes(root: Path, hashes: dict[str, str]) -> None:
    for name, expected in hashes.items():
        path = (root / name).resolve()
        require(path.is_relative_to(root.resolve()) and path.is_file(), "source_file_missing_or_outside_root")
        require(pipeline.sha256(path) == expected, "source_artifact_hash_mismatch")


def check_code_compatibility(pin_path: Path, pin: dict[str, Any], compatibility_path: Path | None) -> dict[str, Any]:
    """Check exact historical code or an explicitly supplied orchestration delta.

    The historical pin is never updated. No runtime module wildcard exemption
    is allowed; every changed/added file has an exact before/after hash.
    """
    current = pipeline._code_manifest()
    if current == pin["code_sha256"]:
        return {"mode": "exact_historical_code", "changes": {}}
    require(compatibility_path is not None, "changed_harness_requires_explicit_compatibility_manifest")
    compatibility = pipeline._read(compatibility_path)
    require(compatibility.get("schema_version") in {"recovery-harness-compatibility/v1", "recovery-harness-compatibility/v2"}, "invalid_compatibility_schema")
    require(compatibility.get("historical_pin_sha256") == pipeline.sha256(pin_path), "compatibility_historical_pin_mismatch")
    allowed = {"scripts/evaluate_rag_graphrag.py",
               "src/threat_hunting/evaluation/experimental_comparison.py",
               "src/threat_hunting/evaluation/experimental_recovery.py"}
    if compatibility["schema_version"] == "recovery-harness-compatibility/v2":
        allowed |= {"src/threat_hunting/llm/generation_contract.py", "src/threat_hunting/server/experimental.py"}
    changes = {name: {"before": pin["code_sha256"].get(name), "after": current.get(name)}
               for name in set(current) | set(pin["code_sha256"])
               if current.get(name) != pin["code_sha256"].get(name)}
    require(bool(changes) and set(changes) <= allowed, "non_orchestration_code_changed")
    require(changes == compatibility.get("changes"), "compatibility_code_hash_mismatch")
    return {"mode": "explicit_orchestration_delta", "compatibility_sha256": pipeline.sha256(compatibility_path),
            "historical_pin_sha256": pipeline.sha256(pin_path), "changes": changes,
            "historical_pin_preserved": True}


@dataclass
class RecoveryPlan:
    source: Path
    config_path: Path
    pin_path: Path
    config: dict[str, Any]
    source_manifest: dict[str, Any]
    source_hashes: dict[str, str]
    selected: list[dict[str, Any]]
    prepared: list[dict[str, Any]] = field(repr=False)
    model: Any = field(repr=False)
    compatibility: dict[str, Any]
    interval: float
    budget: int
    source_outcomes: dict[str, int]
    provenance_chain: list[dict[str, Any]] = field(default_factory=list)


def _checkpoint_chain(source: Path, pin_path: Path, pin: dict[str, Any],
                      compatibility_path: Path | None) -> tuple[Path, list[dict[str, Any]]]:
    """Resolve actual checkpoint parents, verifying their immutable hash links."""
    authorized = [pin["code_sha256"]]
    if compatibility_path is not None:
        compatibility = pipeline._read(compatibility_path)
        for predecessor in compatibility.get("predecessor_compatibility", []):
            path = (pipeline.ROOT / predecessor["path"]).resolve()
            require(path.is_relative_to(pipeline.ROOT.resolve()) and pipeline.sha256(path) == predecessor["sha256"], "checkpoint_compatibility_file_mismatch")
            previous = pipeline._read(path)
            require(previous["historical_pin_sha256"] == pipeline.sha256(pin_path), "checkpoint_compatibility_pin_mismatch")
            code = deepcopy(pin["code_sha256"])
            for name, delta in previous["changes"].items():
                require(delta["before"] == code.get(name), "checkpoint_code_delta_mismatch")
                if delta["after"] is None:
                    code.pop(name, None)
                else:
                    code[name] = delta["after"]
            authorized.append(code)
        # Current delta is checked separately against the running code.
        authorized.append(pipeline._code_manifest())
    chain, seen = [], set()
    while True:
        require(source not in seen and len(seen) < 32, "recovery_provenance_cycle")
        seen.add(source)
        manifest, results = pipeline._read(source / "manifest.json"), pipeline._read(source / "results.json")
        require(manifest.get("mode") == "live" and results.get("mode") == "live", "source_must_be_completed_live_run")
        for key in ("model", "config_sha256", "cases_sha256", "gate_contract", "gate_policy_sha256", "runtime_artifacts_config_sha256", "artifacts"):
            require(manifest.get(key) == pin.get(key), "checkpoint_pin_mismatch_" + key)
        require(manifest["code_sha256"] in authorized, "checkpoint_code_not_authorized")
        hashes = {p.relative_to(source).as_posix(): pipeline.sha256(p) for p in sorted(source.rglob("*")) if p.is_file()}
        chain.append({"directory": str(source), "hashes": hashes})
        rows = results["rows"]
        require(len(rows) == results["planned_branch_count"], "source_planned_count_mismatch")
        pairs = [(r["case_id"], r["branch"]) for r in rows]
        require(len(pairs) == len(set(pairs)), "duplicate_source_branch")
        for row in rows:
            require(re.fullmatch(r"[A-Za-z0-9_-]+", row["case_id"]) is not None and row["branch"] in pipeline.BRANCHES, "invalid_source_branch_identity")
            require(pipeline._read(source / f"{row['case_id']}_{row['branch']}/result.json") == row, "source_branch_result_mismatch")
        if manifest.get("schema_version") != "experimental-recovery-manifest/v1":
            require(manifest["code_sha256"] == pin["code_sha256"], "root_source_code_pin_mismatch")
            return source, chain
        require(manifest["historical_pin_sha256"] == pipeline.sha256(pin_path), "checkpoint_historical_pin_mismatch")
        parent = Path(manifest["recovery_source"]).resolve()
        _check_hashes(parent, manifest["recovery_source_hashes"])
        require(set(pairs) == {(r["case_id"], r["branch"]) for r in manifest["selected_branches"]}, "checkpoint_selection_mismatch")
        parent_rows = {(r["case_id"], r["branch"]): r for r in pipeline._read(parent / "results.json")["rows"]}
        for selected in manifest["selected_branches"]:
            pair = (selected["case_id"], selected["branch"])
            require(pair in parent_rows and parent_rows[pair]["outcome"] in {"provider_error", "not_run"}, "checkpoint_selected_completed_branch")
            source_result = (parent / selected["source_result"]).resolve()
            require(source_result.is_relative_to(parent) and selected["source_result_sha256"] == pipeline.sha256(source_result), "checkpoint_source_result_hash_mismatch")
            for key in ("context_sha256", "messages_sha256"):
                require(selected[key] == parent_rows[pair].get(key), "checkpoint_input_hash_mismatch")
                current = next(r for r in rows if (r["case_id"], r["branch"]) == pair)
                require(current.get(key) == selected[key], "checkpoint_row_input_hash_mismatch")
            for name in ("context", "messages"):
                path = source / f"{pair[0]}_{pair[1]}" / (name + ".json")
                if path.is_file():
                    value = pipeline._read(path)
                    value = pipeline.supplied_context(value) if name == "context" else value["messages"]
                    require(hashlib.sha256(pipeline.canonical_bytes(value)).hexdigest() == selected[name + "_sha256"], "checkpoint_saved_input_mismatch")
        source = parent


def preflight_recovery(config_path: Path, source: Path, *, pin_path: Path,
                       compatibility_path: Path | None = None, live: bool = False,
                       max_requests: int | None = None, request_interval_seconds: float = 0,
                       include_not_run: bool = False) -> RecoveryPlan:
    """Validate ALL selected inputs before any client construction or output write."""
    pipeline.RequestPacer(request_interval_seconds)  # Reject NaN/inf/negative before work.
    source, config_path, pin_path = source.resolve(), config_path.resolve(), pin_path.resolve()
    require(source.is_dir(), "recovery_source_directory_missing")
    results = pipeline._read(source / "results.json")
    config, pin = pipeline._read(config_path), pipeline._read(pin_path)
    compatibility = check_code_compatibility(pin_path, pin, compatibility_path)
    origin, chain = _checkpoint_chain(source, pin_path, pin, compatibility_path)
    manifest = pipeline._read(origin / "manifest.json")
    require(manifest.get("mode") == "live" and results.get("mode") == "live", "source_must_be_completed_live_run")
    for key in ("model", "config_sha256", "cases_sha256", "gate_contract", "gate_policy_sha256",
                "runtime_artifacts_config_sha256", "artifacts", "code_sha256"):
        require(manifest.get(key) == pin.get(key), "source_manifest_pin_mismatch_" + key)
    require(pipeline.sha256(config_path) == pin["config_sha256"], "config_pin_mismatch")
    benchmark = pipeline.ROOT / config["benchmark"]
    require(pipeline.sha256(benchmark) == pin["cases_sha256"], "questions_pin_mismatch")
    require(pipeline.sha256(pipeline.ROOT / config["gate_policy"]) == pin["gate_policy_sha256"], "gate_policy_pin_mismatch")
    require(config.get("gate_contract", "legacy_graph_topology") == pin["gate_contract"], "gate_contract_pin_mismatch")
    require(pipeline.sha256(pipeline.ROOT / config["runtime_artifacts"]) == pin["runtime_artifacts_config_sha256"], "runtime_config_pin_mismatch")
    require(pipeline._source_manifest(pipeline._runtime_sources(pipeline.ROOT / config["runtime_artifacts"])) == pin["artifacts"], "consumers_pin_mismatch")
    model = replace(pipeline.LLMConfig.from_env(), max_retries=1)
    require(pipeline._safe_config(model) == pin["model"], "model_provider_settings_pin_mismatch")
    require(pipeline._read(origin / "configuration.json") == config, "source_configuration_mismatch")
    require(pipeline._read(origin / "cases.json") == pipeline._read(benchmark), "source_questions_mismatch")
    cases = {c["case_id"]: c for c in pipeline._read(benchmark)["cases"]}
    rows = results["rows"]
    pairs = [(row["case_id"], row["branch"]) for row in rows]
    require(len(pairs) == len(set(pairs)), "duplicate_source_branch")
    require(len(manifest["selected_case_ids"]) == len(set(manifest["selected_case_ids"]))
            and set(manifest["selected_case_ids"]) <= set(pin["selected_case_ids"]), "source_selected_case_ids_mismatch")
    planned = ({(r["case_id"], r["branch"]) for r in manifest["selected_branches"]}
               if "selected_branches" in manifest else
               {(cid, branch) for cid in manifest["selected_case_ids"] for branch in pipeline.BRANCHES})
    require(planned <= {(cid, b) for cid in manifest["selected_case_ids"] for b in pipeline.BRANCHES}, "source_selected_branches_mismatch")
    origin_rows = {(r["case_id"], r["branch"]): r for r in pipeline._read(origin / "results.json")["rows"]}
    require(set(origin_rows) == planned and set(pairs) <= planned, "source_branch_manifest_mismatch")
    require(results["planned_branch_count"] == len(rows), "source_planned_count_mismatch")
    source_hashes = {path.relative_to(source).as_posix(): pipeline.sha256(path)
                     for path in sorted(source.rglob("*")) if path.is_file()}
    selected, prepared = [], []
    for row in rows:
        cid, branch = row["case_id"], row["branch"]
        require(cid in cases and re.fullmatch(r"[A-Za-z0-9_-]+", cid) is not None
                and branch in pipeline.BRANCHES, "invalid_source_branch_identity")
        directory = source / f"{cid}_{branch}"
        require(pipeline._read(directory / "result.json") == row, "source_branch_result_mismatch")
        if row["outcome"] not in ({"provider_error", "not_run"} if include_not_run else {"provider_error"}):
            continue
        source_row = row
        row = origin_rows[(cid, branch)]
        directory = origin / f"{cid}_{branch}"
        require(row["outcome"] == "provider_error", "origin_branch_was_not_provider_error")
        require(all(source_row.get(k) == row[k] for k in ("context_sha256", "messages_sha256")), "checkpoint_origin_input_mismatch")
        require(row.get("scenario_id") == cases[cid]["scenario_id"], "source_scenario_mismatch")
        require(row.get("eligibility_decision") == "proceed" and row.get("gate_decision") == "proceed", "source_branch_not_eligible")
        eligibility = pipeline._read(directory / "eligibility.json")
        require(eligibility.get("decision") == "proceed" and not eligibility.get("budget_exceeded"), "source_eligibility_mismatch")
        require(pipeline._read(directory / "gate.json").get("decision") == "proceed", "source_gate_mismatch")
        context = pipeline.supplied_context(pipeline._read(directory / "context.json"))
        messages = pipeline._read(directory / "messages.json")["messages"]
        for key, value in (("context", context), ("messages", messages)):
            digest = hashlib.sha256(pipeline.canonical_bytes(value)).hexdigest()
            require(digest == row.get(key + "_sha256"), "source_" + key + "_hash_mismatch")
            require(len(pipeline.canonical_bytes(value)) <= config["maximum_" + key + "_utf8_bytes"], "source_input_exceeds_config_budget")
        selected.append({"case_id": cid, "branch": branch, "scenario_id": row["scenario_id"],
                         "source_result": f"{cid}_{branch}/result.json",
                         "source_result_sha256": source_hashes[f"{cid}_{branch}/result.json"],
                         "context_sha256": row["context_sha256"], "messages_sha256": row["messages_sha256"]})
        prepared.append({"row": row, "context": context, "messages": messages})
    require(bool(selected), "no_provider_error_branches_to_recover")
    budget = len(selected) if max_requests is None else max_requests
    require(not live or max_requests is not None, "live_recovery_requires_explicit_budget")
    require(type(budget) is int and budget == len(selected) and budget <= config["maximum_llm_requests"], "recovery_budget_must_equal_selected_branch_count")
    _check_hashes(source, source_hashes)
    return RecoveryPlan(source, config_path, pin_path, config, manifest, source_hashes,
                        selected, prepared, model, compatibility, request_interval_seconds,
                        budget, dict(Counter(row["outcome"] for row in rows)), chain)


def _snapshot(path: Path, value: Any) -> None:
    """Atomic checkpoint in a directory exclusively created by this run.

    Shares the transient-lock retry with every other writer via ``threat_hunting.atomic_fs``.
    """
    temporary = path.with_suffix(path.suffix + ".tmp")
    pipeline._write(temporary, value)
    replace_with_retry(temporary, path)


def run_recovery(plan: RecoveryPlan, output: Path, *, live: bool = False,
                 client_factory: Callable[..., Any] = pipeline.LLMClient,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """One attempt per selected branch, paced and checkpointed; never merge runs."""
    output = output.resolve()
    require(output != plan.source and not output.is_relative_to(plan.source)
            and not plan.source.is_relative_to(output), "recovery_output_overlaps_source")
    require(not output.exists(), "recovery_output_must_be_new")
    _check_hashes(plan.source, plan.source_hashes)
    for link in plan.provenance_chain:
        _check_hashes(Path(link["directory"]), link["hashes"])
    output.mkdir(parents=True, exist_ok=False)
    manifest = {key: deepcopy(plan.source_manifest[key]) for key in
                ("model", "config_sha256", "cases_sha256", "gate_contract", "gate_policy_sha256",
                 "runtime_artifacts_config_sha256", "artifacts")}
    manifest.update(schema_version="experimental-recovery-manifest/v1", mode="live" if live else "offline_dry_run",
        created_utc=datetime.now(timezone.utc).isoformat(), recovery_source=str(plan.source),
        recovery_source_hashes=plan.source_hashes, source_outcomes=plan.source_outcomes,
        historical_pin_sha256=pipeline.sha256(plan.pin_path), code_sha256=pipeline._code_manifest(),
        code_compatibility=plan.compatibility, selected_branches=plan.selected,
        provenance_chain=plan.provenance_chain,
        request_interval_seconds=plan.interval, configured_request_budget=plan.budget,
        maximum_llm_requests=plan.budget if live else 0, llm_http_attempts=0,
        stopped_reason=None, stop_details=None, automatic_retry=False, fallback=False,
        input_policy="Exact saved context/messages; source hashes checked before generation",
        review_status="pending_human_review", benchmark_merge="not_performed",
        provider_error_policy="401/403/429/503 stop entire run; other HTTP, connection, timeout and protocol errors retain existing classification, no retry; continue next selected branch")
    pipeline._write(output / "manifest.json", manifest)
    rows: list[dict[str, Any]] = []
    attempts, stopped, details = 0, None, None
    factory = pipeline.RequestPacer(plan.interval, clock=clock, sleep=sleep).wrap(client_factory)

    def checkpoint() -> dict[str, Any]:
        mapping = [{**entry, "recovery_result": f"{entry['case_id']}_{entry['branch']}/result.json",
                    "recovery_outcome": rows[i]["outcome"] if i < len(rows) else "not_run"}
                   for i, entry in enumerate(plan.selected)]
        summary = {"schema_version": "experimental-recovery-results/v1", "mode": manifest["mode"],
                   "planned_branch_count": len(plan.selected), "eligible_branch_count": len(plan.selected),
                   "configured_request_budget": plan.budget, "maximum_llm_requests": plan.budget if live else 0,
                   "llm_http_attempts": attempts, "stopped_reason": stopped, "stop_details": details,
                   "request_interval_seconds": plan.interval, "rows": rows,
                   "benchmark_merge": "not_performed", "human_review_required": True}
        manifest.update(llm_http_attempts=attempts, stopped_reason=stopped, stop_details=details,
                        completed_branch_count=len(rows), recovery_mapping=mapping)
        _snapshot(output / "manifest.json", manifest)
        _snapshot(output / "results.json", summary)
        _snapshot(output / "recovery_mapping.json", {"source": str(plan.source), "branches": mapping})
        return summary

    checkpoint()
    for selected, prepared in zip(plan.selected, plan.prepared):
        row = {"case_id": selected["case_id"], "branch": selected["branch"], "scenario_id": selected["scenario_id"],
               "eligibility_decision": "proceed", "gate_decision": "proceed", "llm_http_attempts": 0,
               "fallback_used": False, "human_review_required": True, "validation_status": "not_run",
               "source_result_sha256": selected["source_result_sha256"],
               "context_sha256": selected["context_sha256"], "messages_sha256": selected["messages_sha256"]}
        directory = output / f"{row['case_id']}_{row['branch']}"
        directory.mkdir()
        if stopped:
            row.update(outcome="not_run", not_run_reason=stopped)
        elif not live:
            row["outcome"] = "dry_run_no_generation"
        else:
            try:
                require(attempts < plan.budget, "request_budget_exhausted")
                pipeline._write(directory / "context.json", prepared["context"])
                pipeline._write(directory / "messages.json", {"messages": prepared["messages"]})
                generated, stopped = pipeline.generate_branch(prepared["messages"], prepared["context"], plan.model,
                    factory, lambda name, value: pipeline._write(directory / f"{name}.json", value))
                row.update(generated)
                attempts += row["llm_http_attempts"]
                if stopped:
                    details = row.get("provider_error")
            except KeyboardInterrupt:
                row.update(outcome="not_run", not_run_reason="keyboard_interrupt")
                stopped = "keyboard_interrupt"
        pipeline._write(directory / "result.json", row)
        rows.append(row)
        checkpoint()
    _check_hashes(plan.source, plan.source_hashes)
    return checkpoint()
