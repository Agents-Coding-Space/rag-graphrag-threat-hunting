"""Execute a frozen preflight through the shared generator with a durable budget.

One task ledger survives new processes; recovery is explicit and service-only.
No retrieval, prompt changes, answer selection or rubric enters live generation.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Callable

from . import experimental_comparison as p


def snapshot(path: Path, data: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    p._write(temporary, data)
    os.replace(temporary, path)


def utc_now() -> float:
    return datetime.now(timezone.utc).timestamp()


def _env_float(name: str, default: float) -> float:
    """Read a positive float from environment; fall back to default on bad input.

    Operational pacing lives in .env so it can be tuned or rotated without editing a
    frozen config; the value falls back to the pinned JSON policy when absent/invalid.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _env_int(name: str, default: int) -> int:
    """Read a positive int from environment; fall back to default on bad input."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def run_policy(config: dict[str, Any]) -> dict[str, Any]:
    """Pinned final_run_policy with optional env overrides (env wins when valid).

    Only pacing and attempt budgets are overridable; the ledger path and the
    recovery policy stay exactly as frozen in the config JSON.
    """
    policy = dict(config["final_run_policy"])
    policy["request_interval_seconds"] = _env_float("RUN_REQUEST_INTERVAL_SECONDS",
        policy["request_interval_seconds"])
    for key, name in (("initial_attempt_limit", "RUN_INITIAL_ATTEMPT_LIMIT"),
                      ("recovery_attempt_limit", "RUN_RECOVERY_ATTEMPT_LIMIT"),
                      ("total_attempt_limit", "RUN_TOTAL_ATTEMPT_LIMIT")):
        policy[key] = _env_int(name, policy[key])
    return policy


class TaskBudget:
    """Conservative attempt reservations, global caps and cross-process cooldown."""
    def __init__(self, path: Path, pin_sha256: str, *, wall: Callable[[], float] = utc_now,
                 sleep: Callable[[float], None] = time.sleep, initial: int = 16,
                 recovery: int = 4, total: int = 20, interval: float = 60,
                 clock: Callable[[], float] = time.monotonic, scope: str = "final") -> None:
        self.path, self.wall, self.sleep = path, wall, sleep
        self.clock, self.last_monotonic = clock, None
        self.limits = {"initial": initial, "recovery": recovery, "total": total, "interval": interval,
                       "scope": scope}
        self.pin_sha256 = pin_sha256
        if path.exists():
            state = p._read(path)
            if state["pin_sha256"] != pin_sha256 or state["limits"] != self.limits:
                raise ValueError("Task ledger profile or budget changed")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            p._write(path, {"pin_sha256": pin_sha256, "limits": self.limits, "attempts": [],
                            "last_finished_utc": None, "cooldown_until_utc": None})

    def remaining(self, phase: str) -> int:
        state = p._read(self.path)
        # A review subset spends from the same single pool as an initial phase; it is a declared
        # scope, not a second budget, so it must never read a separate allowance.
        bucket = "initial" if phase == "review" else phase
        used = sum(a["phase"] == phase for a in state["attempts"])
        return min(self.limits[bucket] - used, self.limits["total"] - len(state["attempts"]))

    def reserve(self, phase: str, key: str, batch: str) -> int:
        if self.remaining(phase) <= 0:
            raise ValueError("Persistent task request budget exhausted")
        state = p._read(self.path)
        due = max((state.get("last_finished_utc") or 0) + self.limits["interval"], state.get("cooldown_until_utc") or 0)
        delay = max(0, due - self.wall(),
                    (self.last_monotonic + self.limits["interval"] - self.clock()) if self.last_monotonic is not None else 0)
        if delay > 0:
            print(json.dumps({"waiting_seconds": round(delay, 3), "reason": "pacing_or_retry_after", "task_ledger": self.path.name}), flush=True)
        deadline = self.clock() + delay
        while deadline > self.clock():
            self.sleep(min(1.0, deadline - self.clock()))
        state = p._read(self.path)
        ordinal = len(state["attempts"]) + 1
        state["attempts"].append({"ordinal": ordinal, "phase": phase, "key": key, "batch": batch,
                                  "started_utc": self.wall(), "state": "reserved_inflight"})
        snapshot(self.path, state)
        return ordinal

    def finish(self, ordinal: int, count: int) -> None:
        state = p._read(self.path)
        attempt = state["attempts"][ordinal - 1]
        attempt.update(state="finished", actual_http_attempts=count, finished_utc=self.wall())
        state["last_finished_utc"] = self.wall()
        self.last_monotonic = self.clock()
        snapshot(self.path, state)

    def completed(self, key: str) -> bool:
        return any(a["key"] == key and a.get("outcome") in {"accepted_draft", "validation_failed"}
                   for a in p._read(self.path)["attempts"])

    def record_outcome(self, key: str, batch: str, row: dict[str, Any]) -> None:
        state = p._read(self.path)
        for attempt in reversed(state["attempts"]):
            if attempt["key"] == key and attempt["batch"] == batch:
                attempt["outcome"] = row["outcome"]
                attempt["provider_error"] = row.get("provider_error")
                break
        snapshot(self.path, state)

    def cooldown(self, error: dict[str, Any]) -> None:
        if error.get("http_status") in {429, 503}:
            state = p._read(self.path)
            state["cooldown_until_utc"] = self.wall() + max(self.limits["interval"], error.get("retry_after_seconds") or 0)
            snapshot(self.path, state)


def temporary_error(row: dict[str, Any]) -> bool:
    error = row.get("provider_error", {})
    return error.get("http_status") in {408, 429, 500, 502, 503, 504} or error.get("kind") in {"LLMConnectionError", "LLMTimeoutError"}


def verify_execution_pin(config_path: Path, pin_path: Path, pin: dict[str, Any], execution_pin: Path | None) -> None:
    current = p._code_manifest()
    if current == pin["code_sha256"]:
        return
    if execution_pin is None:
        raise ValueError("Frozen runtime changed; an explicit execution delta pin is required")
    delta = p._read(execution_pin)
    actual_changes = {name: {"before": pin["code_sha256"].get(name), "after": current.get(name)}
        for name in set(current) | set(pin["code_sha256"]) if current.get(name) != pin["code_sha256"].get(name)}
    allowed = {"src/threat_hunting/llm/client.py", "src/threat_hunting/llm/error_diagnostics.py",
        "src/threat_hunting/evaluation/experimental_comparison.py", "src/threat_hunting/evaluation/final_experiment.py",
        "scripts/run_final_experiment.py"}
    if (delta.get("schema_version") != "final-execution-delta/v1" or
            delta.get("generation_pin_sha256") != p.sha256(pin_path) or
            delta.get("config_sha256") != p.sha256(config_path) or
            delta.get("code_sha256") != current or delta.get("changes") != actual_changes or
            not set(actual_changes) <= allowed):
        raise ValueError("Execution delta does not match the frozen generation profile")
    anchor = delta["ledger_anchor"]
    ledger = p._read(p.ROOT / anchor["path"])
    if (ledger["pin_sha256"] != p.sha256(pin_path) or ledger["limits"] != anchor["limits"] or
            ledger["attempts"][:len(anchor["attempts"])] != anchor["attempts"] or
            len(ledger["attempts"]) < len(anchor["attempts"])):
        raise ValueError("Existing task ledger history was reset or changed")


def validate_preflight(config_path: Path, pin_path: Path, preflight: Path,
                       execution_pin: Path | None = None) -> tuple[dict, dict, dict, Any]:
    config, pin = p._read(config_path), p._read(pin_path)
    manifest, results = p._read(preflight / "manifest.json"), p._read(preflight / "results.json")
    if p.sha256(config_path) != pin["config_sha256"]:
        raise ValueError("Frozen final config changed")
    verify_execution_pin(config_path, pin_path, pin, execution_pin)
    for key in ("config_sha256", "cases_sha256", "model", "code_sha256", "artifacts", "gate_policy_sha256", "runtime_artifacts_config_sha256", "generation_contract"):
        if manifest[key] != pin[key]:
            raise ValueError("Preflight differs from final pin: " + key)
    if results["mode"] != "offline_dry_run" or results["llm_http_attempts"]:
        raise ValueError("Expected a zero-request offline preflight")
    if len(results["rows"]) != 2 * config["expected_case_count"] or len({(r["case_id"], r["branch"]) for r in results["rows"]}) != len(results["rows"]):
        raise ValueError("Preflight must include all distinct configured branch pairs")
    if p.sha256(p.ROOT / config["benchmark"]) != pin["cases_sha256"] or p.sha256(p.ROOT / config["gate_policy"]) != pin["gate_policy_sha256"]:
        raise ValueError("Questions or gate policy changed")
    if p.sha256(p.ROOT / config["runtime_artifacts"]) != pin["runtime_artifacts_config_sha256"] or p._source_manifest(p._runtime_sources(p.ROOT / config["runtime_artifacts"])) != pin["artifacts"]:
        raise ValueError("Consumers/provenance changed")
    model = replace(p.LLMConfig.from_env(), max_retries=1)
    if p._safe_config(model) != pin["model"]:
        raise ValueError("Final model/provider/config changed")
    for row in results["rows"]:
        directory = preflight / f"{row['case_id']}_{row['branch']}"
        for name in ("context", "messages"):
            doc = p._read(directory / (name + ".json"))
            value = doc if name == "context" else doc["messages"]
            if hashlib.sha256(p.canonical_bytes(value)).hexdigest() != row[name + "_sha256"]:
                raise ValueError("Preflight model input hash mismatch")
        if row["outcome"] not in {"abstain", "dry_run_no_generation"}:
            raise ValueError("Preflight has a failed branch")
    return config, pin, results, model


def require_balance_confirmation(path: Path | None, ledger: dict[str, Any], pin_sha: str) -> None:
    """A real user statement is an operational receipt, not GT human approval.

    The agent must create a confirmed receipt only AFTER the user explicitly
    confirms checking/resolving the OpenRouter balance; never from elapsed time.
    A new402 invalidates an older receipt.
    """
    failures = [a for a in ledger["attempts"] if (a.get("provider_error") or {}).get("http_status") == 402]
    if not failures:
        return
    if path is None or not path.is_file():
        raise ValueError("Awaiting explicit user confirmation of OpenRouter balance handling")
    receipt = p._read(path)
    last = max(failures, key=lambda a: a["ordinal"])
    try:
        confirmed_at = datetime.fromisoformat(receipt["confirmed_at_utc"].replace("Z", "+00:00")).timestamp()
    except (KeyError, ValueError, TypeError):
        confirmed_at = 0
    if (receipt.get("schema_version") != "openrouter-balance-confirmation/v1" or
            receipt.get("confirmed") is not True or receipt.get("confirmation_source") != "explicit_user_reply" or
            receipt.get("task_pin_sha256") != pin_sha or
            receipt.get("after_attempt_ordinal", 0) < last["ordinal"] or
            confirmed_at < last.get("finished_utc", last["started_utc"])):
        raise ValueError("Awaiting fresh explicit user confirmation after the latest HTTP402")


def prepare_continuation(prepared: dict[str, Any], ledger: dict[str, Any], pin_sha: str,
                         preflight: Path) -> list[dict[str, Any]]:
    """Reconstruct pending keys from real ledger/batches + frozen preflight.

    A partial checkpoint does not make the other preflight branches disappear.
    No fake parent run is created; completed answers/rejections are excluded.
    """
    latest: dict[str, dict[str, Any]] = {}
    base = {f"{r['case_id']}_{r['branch']}": r for r in prepared["rows"]}
    for attempt in ledger["attempts"]:
        key = attempt["key"]
        if key not in base or attempt["state"] != "finished" or not attempt.get("outcome"):
            raise ValueError("Incomplete or unknown ledger attempt requires review before continuation")
        batch = Path(attempt["batch"]).resolve()
        if not batch.is_relative_to((p.ROOT / "outputs/experiments").resolve()):
            raise ValueError("Ledger batch is outside the experiment workspace")
        manifest = p._read(batch / "manifest.json")
        if manifest["runtime_pin_sha256"] != pin_sha or manifest["preflight"] != str(preflight.resolve()):
            raise ValueError("Ledger batch belongs to a different frozen study")
        row = p._read(batch / key / "result.json")
        if row["outcome"] != attempt["outcome"] or any(row.get(k) != base[key][k] for k in ("context_sha256", "messages_sha256")):
            raise ValueError("Ledger result or generation input mismatch")
        latest[key] = row
    selected = []
    for before in prepared["rows"]:
        if before["eligibility_decision"] != "proceed":
            continue
        key = f"{before['case_id']}_{before['branch']}"
        previous = latest.get(key)
        if previous is None:
            row = deepcopy(before)
            row.update(outcome="not_run", request_budget_phase="initial", continuation_origin="unattempted_frozen_preflight")
        elif temporary_error(previous) or previous.get("provider_error", {}).get("http_status") == 402:
            row = deepcopy(previous)
            row.update(request_budget_phase="recovery", continuation_origin="real_ledger_failed_attempt")
        else:
            continue
        selected.append(row)
    return selected


# --- F07: bounded review subset ------------------------------------------------------
# A review subset is a pre-declared selection of already-frozen preflight branches, run through
# the same generator, pin verification, durable ledger and stop policy as the full study. It
# exists so a small contract check can be performed without opening the 16-request budget, and
# it can never authorize more requests than the ceilings below.
REVIEW_MAX_BRANCHES = 6
REVIEW_MAX_ATTEMPTS = 6
REVIEW_EXECUTION_MODES = ("live", "offline_dry_run")


def parse_review_selection(selection: str | None) -> list[tuple[str, str]]:
    """Parse ``CASE:branch,CASE:branch`` into an ordered, de-duplicated list."""
    if selection is None:
        return []
    if not selection.strip():
        raise ValueError("Review selection is empty")
    pairs: list[tuple[str, str]] = []
    for item in selection.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError("Review selection entries must be CASE_ID:branch")
        case_id, branch = (part.strip() for part in item.split(":", 1))
        if branch not in ("rag", "graphrag"):
            raise ValueError(f"Review selection branch must be rag or graphrag: {item}")
        if (case_id, branch) not in pairs:
            pairs.append((case_id, branch))
    if not pairs:
        raise ValueError("Review selection is empty")
    if len(pairs) > REVIEW_MAX_BRANCHES:
        raise ValueError(f"Review selection cannot exceed {REVIEW_MAX_BRANCHES} branches")
    return pairs


def review_policy(config: dict[str, Any], pairs: list[tuple[str, str]],
                  interval: float | None = None, max_attempts: int | None = None) -> dict[str, Any]:
    """Build a self-contained review budget that is strictly smaller than the study budget."""
    policy = dict(config["final_run_policy"])
    if interval is not None:
        # Pacing may be raised for a subset but never lowered below the frozen study value.
        policy["request_interval_seconds"] = max(float(interval), float(policy["request_interval_seconds"]))
    cap = min(max_attempts or REVIEW_MAX_ATTEMPTS, REVIEW_MAX_ATTEMPTS, len(pairs))
    policy["initial_attempt_limit"] = min(cap, len(pairs))
    policy["recovery_attempt_limit"] = 0
    policy["total_attempt_limit"] = policy["initial_attempt_limit"]
    policy["task_ledger"] = str(p.ROOT / "outputs/final" / config["profile_id"] / "review_request_budget.json")
    policy["recovery_policy"] = "review subsets do not authorise recovery; rerun a new declared subset"
    return policy


def select_review_branches(prepared: dict[str, Any], pairs: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Resolve declared pairs against the frozen preflight; every pair must exist."""
    index = {(r["case_id"], r["branch"]): r for r in prepared["rows"]}
    missing = [f"{c}:{b}" for c, b in pairs if (c, b) not in index]
    if missing:
        raise ValueError("Review selection is not part of the frozen preflight: " + ", ".join(missing))
    return [deepcopy(index[pair]) for pair in pairs]


def run_final(config_path: Path, pin_path: Path, preflight: Path, output: Path, *, live: bool = False,
              resume_from: Path | None = None, client_factory: Any = p.LLMClient,
              execution_pin: Path | None = None, continue_task: bool = False,
              balance_confirmation: Path | None = None, review_selection: str | None = None,
              review_interval_seconds: float | None = None, review_max_attempts: int | None = None,
              clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = utc_now,
              sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    if execution_pin is None:
        config, pin, prepared, model = validate_preflight(config_path, pin_path, preflight)
    else:
        config, pin, prepared, model = validate_preflight(config_path, pin_path, preflight, execution_pin)
    review_pairs = parse_review_selection(review_selection)
    if review_pairs:
        if resume_from is not None or continue_task or execution_pin is not None:
            raise ValueError("A review subset is an independent run; it cannot resume or reuse a delta pin")
        policy = review_policy(config, review_pairs, review_interval_seconds, review_max_attempts)
        if (policy["total_attempt_limit"] > REVIEW_MAX_ATTEMPTS
                or policy["total_attempt_limit"] > len(review_pairs)
                or policy["recovery_attempt_limit"] != 0):
            raise ValueError("Review budget exceeds the declared subset or the review ceiling")
    else:
        policy = run_policy(config)
        eligible = sum(r["eligibility_decision"] == "proceed" for r in prepared["rows"])
        # The hard ceiling is a scientific constraint, not an operational knob: the
        # .env override may lower it but can never authorize more requests.
        if (eligible != policy["initial_attempt_limit"] or policy["recovery_attempt_limit"] > 4
                or policy["total_attempt_limit"] > 20 or policy["request_interval_seconds"] < 60):
            raise ValueError("Frozen eligibility or authorized budget changed")
    output = output.resolve()
    if output.exists() or not output.is_relative_to((p.ROOT / "outputs/experiments").resolve()):
        raise ValueError("Final output must be a new experiment directory")
    phase = "review" if review_pairs else "continuation" if continue_task else "recovery" if resume_from else "initial"
    if continue_task and resume_from is None:
        raise ValueError("Continuation requires the real previous checkpoint")
    ledger_path = p.ROOT / policy["task_ledger"]
    ledger_before = p._read(ledger_path) if ledger_path.exists() else None
    ledger_before_sha = p.sha256(ledger_path) if ledger_path.exists() else None
    if live and ledger_before:
        require_balance_confirmation(balance_confirmation, ledger_before, p.sha256(pin_path))
    source_hashes = {}
    if resume_from:
        previous_manifest = p._read(resume_from / "manifest.json")
        if previous_manifest["runtime_pin_sha256"] != p.sha256(pin_path) or previous_manifest["preflight"] != str(preflight.resolve()):
            raise ValueError("Recovery source is not from this frozen final study")
        source = p._read(resume_from / "results.json")
        if source["stopped_reason"] in {"provider_http_401", "provider_http_403"}:
            raise ValueError("Credential stop prohibits further requests until explicitly resolved")
        original_map = {(r["case_id"], r["branch"]): r for r in prepared["rows"]}
        for r in source["rows"]:
            before = original_map[(r["case_id"], r["branch"])]
            if any(r.get(k) != before[k] for k in ("context_sha256", "messages_sha256")):
                raise ValueError("Recovery input differs from final preflight")
        if continue_task:
            if ledger_before is None:
                raise ValueError("Continuation cannot create/reset the task ledger")
            selected = prepare_continuation(prepared, ledger_before, p.sha256(pin_path), preflight)
        else:
            selected = [r for r in source["rows"] if r["outcome"] == "not_run" or temporary_error(r)]
        source_hashes = {q.relative_to(resume_from).as_posix(): p.sha256(q) for q in resume_from.rglob("*") if q.is_file()}
    elif review_pairs:
        selected = select_review_branches(prepared, review_pairs)
    else:
        selected = prepared["rows"]
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"mode": "live" if live else "offline_dry_run", "phase": phase,
        "preflight": str(preflight.resolve()), "runtime_pin_sha256": p.sha256(pin_path),
        "config_sha256": p.sha256(config_path), "model": p._safe_config(model),
        "selected_branches": [{"case_id": r["case_id"], "branch": r["branch"]} for r in selected],
        "task_ledger": str(ledger_path), "source": str(resume_from) if resume_from else None,
        "source_hashes": source_hashes, "request_interval_seconds": policy["request_interval_seconds"],
        "execution_pin_sha256": p.sha256(execution_pin) if execution_pin else None,
        "ledger_before_sha256": ledger_before_sha,
        "balance_confirmation_sha256": p.sha256(balance_confirmation) if balance_confirmation and balance_confirmation.is_file() else None,
        "balance_confirmation_required_before_live": bool(ledger_before and any((a.get("provider_error") or {}).get("http_status") == 402 for a in ledger_before["attempts"])),
        "budget_assignments": [{"case_id":r["case_id"],"branch":r["branch"],"phase":r.get("request_budget_phase",phase)} for r in selected],
        "execution_scope": "review_subset" if review_pairs else "frozen_study",
        "review_declaration": {
            "selection": [f"{c}:{b}" for c, b in review_pairs],
            "max_branches": REVIEW_MAX_BRANCHES,
            "max_attempts": REVIEW_MAX_ATTEMPTS,
            "declared_before_run": True,
            "claim_scope": ("smoke/contract check on the declared branches only; not a benchmark result "
                            "and not evidence about any branch that was not run"),
        } if review_pairs else None,
        "automatic_retry": False, "fallback": False, "human_review_required": True}
    p._write(output / "manifest.json", manifest)
    rows = []
    stopped, attempts, details = None, 0, None
    budget = None
    lock = ledger_path.with_suffix(".lock")
    if live:
        lock.parent.mkdir(parents=True, exist_ok=True)
        handle = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(handle)
        try:
            if ledger_before_sha and p.sha256(ledger_path) != ledger_before_sha:
                raise ValueError("Task ledger changed while preparing continuation")
            budget = TaskBudget(ledger_path, p.sha256(pin_path), wall=wall, sleep=sleep, clock=clock,
                initial=policy["initial_attempt_limit"], recovery=policy["recovery_attempt_limit"],
                total=policy["total_attempt_limit"], interval=policy["request_interval_seconds"],
                scope="review_subset" if review_pairs else "frozen_study")
            if phase in ("initial", "review") and p._read(ledger_path)["attempts"]:
                raise ValueError("This task ledger already has attempts; declare a new review subset "
                                 "or use explicit service recovery")
        except BaseException:
            lock.unlink()
            raise

    def checkpoint() -> dict[str, Any]:
        value = {"mode": manifest["mode"], "phase": phase,
            "execution_scope": manifest["execution_scope"],
            "planned_branch_count": len(selected),
            "eligible_branch_count": sum(r["eligibility_decision"] == "proceed" for r in selected),
            "llm_http_attempts": attempts, "stopped_reason": stopped, "stop_details": details,
            "completed_branch_count": len(rows), "rows": rows, "human_review_required": True}
        snapshot(output / "results.json", value)
        snapshot(output / "progress.json", {k: v for k,v in value.items() if k != "rows"})
        return value

    checkpoint()
    try:
        for before in selected:
            charge_phase = before.get("request_budget_phase", phase)
            row = deepcopy(before)
            row.update(outcome="not_run", llm_http_attempts=0, human_review_required=True)
            for key in ("provider_error", "generation_validation_seconds", "end_to_end_seconds", "validation_status"):
                row.pop(key, None)
            key = f"{row['case_id']}_{row['branch']}"
            directory = output / key
            directory.mkdir()
            origin = preflight / key
            for file in origin.glob("*.json"):
                if file.name != "result.json":
                    (directory / file.name).write_bytes(file.read_bytes())
            if before["eligibility_decision"] != "proceed":
                row.update(outcome="abstain", abstention_stage=before.get("abstention_stage"))
            elif stopped:
                row.update(outcome="not_run", not_run_reason=stopped)
            elif not live:
                row["outcome"] = "dry_run_no_generation"
            elif budget.completed(key):
                row.update(outcome="not_run", not_run_reason="already_completed_in_task_ledger")
            elif budget.remaining(charge_phase) <= 0:
                row.update(outcome="not_run", not_run_reason="task_budget_exhausted")
                stopped = "task_budget_exhausted"
            else:
                messages = p._read(origin / "messages.json")["messages"]
                context = p._read(origin / "context.json")
                class BudgetedClient:
                    def __init__(self, **kwargs: Any) -> None:
                        self.client = client_factory(**kwargs)
                    @property
                    def last_attempt_count(self) -> int:
                        return self.client.last_attempt_count
                    def generate(self, supplied: Any) -> str:
                        require_balance_confirmation(balance_confirmation, p._read(ledger_path), p.sha256(pin_path))
                        ordinal = budget.reserve(charge_phase, key, str(output))
                        try:
                            return self.client.generate(supplied)
                        finally:
                            budget.finish(ordinal, self.client.last_attempt_count)
                generated, stopped = p.generate_branch(messages, context, model, BudgetedClient,
                    lambda name, value: p._write(directory / (name + ".json"), value))
                row.update(generated)
                attempts += row["llm_http_attempts"]
                if row.get("provider_error"):
                    budget.cooldown(row["provider_error"])
                if stopped:
                    details = row.get("provider_error")
            p._write(directory / "result.json", row)
            if live:
                budget.record_outcome(key, str(output), row)
            rows.append(row)
            checkpoint()
            print(json.dumps({"case_id": row["case_id"], "branch": row["branch"], "outcome": row["outcome"],
                              "phase_attempts": attempts, "stop": stopped}), flush=True)
    finally:
        if live:
            lock.unlink()
    return checkpoint()
