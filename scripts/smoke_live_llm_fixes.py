"""One versioned RG04/RG05 run, gated by read-only provider health. No retries."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from threat_hunting.llm.config import LLMConfig

CONTRACT = "provider-error-and-structured-validation/v1"
PROVIDER_SQL = "SELECT provider,updatedAt,json_extract(data,'$.testStatus') AS testStatus,json_extract(data,'$.errorCode') AS errorCode,json_extract(data,'$.lastErrorAt') AS lastErrorAt,json_extract(data,'$.rateLimitedUntil') AS rateLimitedUntil,json_extract(data,'$.backoffLevel') AS backoffLevel FROM providerConnections WHERE provider='openrouter'"


def observe_provider() -> dict:
    """Never read credential columns, full connection data or error text."""
    path = Path(os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming"))) / "9router/db/data.sqlite"
    try:
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as conn:
            conn.row_factory = sqlite3.Row
            rows = [dict(row) for row in conn.execute(PROVIDER_SQL)]
    except sqlite3.Error as exc:
        return {"state": "unverified", "error_type": type(exc).__name__, "rows": []}
    return {"state": "observed", "rows": rows, "method": "SQLite mode=ro; allowlisted fields only"}


def provider_ready(observation: dict) -> bool:
    rows = observation.get("rows", [])
    # Historical 429 is a stop condition until the router records recovery.
    return bool(rows) and all(
        str(row.get("errorCode") or "") not in ("429", "401", "403")
        and str(row.get("testStatus", "")).lower() in ("active", "available", "connected", "success", "valid")
        for row in rows
    )


def stopped_by_response(http_status: int, body: dict) -> bool:
    error = body.get("provider_error") or {}
    return http_status in (401, 403, 429) or error.get("http_status") in (401, 403, 429) or error.get("kind") in ("rate_limited", "authentication_error")


def save(path: Path, document: object) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def run(*, execute: bool = False) -> Path:
    started = datetime.now(timezone.utc)
    directory = ROOT / "outputs/review/live_llm_fixes" / started.strftime("%Y%m%dT%H%M%S_%fZ")
    directory.mkdir(parents=True, exist_ok=False)
    cfg = LLMConfig.from_env()
    baseline = ROOT / "outputs/review/live_llm_functional_smoke/cases.json"
    selected = [c for c in json.loads(baseline.read_text(encoding="utf-8"))["cases"] if c["case_id"] in ("RG04", "RG05")]
    config = {name: getattr(cfg, name) for name in ("provider", "model_name", "base_url", "temperature", "max_tokens", "timeout_seconds", "max_retries", "retry_delay_seconds")}
    save(directory / "cases.json", {"frozen_at_utc": started.isoformat(), "cases": selected,
        "source_cases_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(), "criteria_sent_to_backend": False})
    provider = observe_provider()
    save(directory / "provider_before.json", {"observed_at_utc": datetime.now(timezone.utc).isoformat(), **provider})
    manifest = {"review_type": "AI-assisted corrective smoke; not independent validation or held-out",
        "started_at_utc": started.isoformat(), "configuration": config, "execute_requested": execute,
        "backend": "http://127.0.0.1:8000", "post_requests": 0, "get_requests": 0, "client_retries": 0,
        "router_upstream_retries": "not_observable", "streaming_requests": 0,
        "runtime_artifacts_sha256": hashlib.sha256((ROOT / "configs/runtime_artifacts.json").read_bytes()).hexdigest()}
    stop = "not_executed_read_only" if not execute else None
    if not provider_ready(provider):
        stop = "blocked_provider_rate_limited_or_unverified"
    if cfg.model_name != "openrouter/gemma-4-31b-it" or cfg.base_url != "http://127.0.0.1:20128/v1" or cfg.max_retries != 1:
        stop = "configuration_differs_from_baseline_or_retry_limit"
    if stop is None:
        manifest["get_requests"] += 1
        try:
            with urllib.request.urlopen(manifest["backend"] + "/api/health", timeout=10) as response:
                health = json.load(response)
            save(directory / "health.json", health)
            if health.get("review_contract") != CONTRACT:
                stop = "backend_restart_required"
        except Exception as exc:
            stop = "backend_preflight_" + type(exc).__name__
    results = []
    for case in selected:
        row = {"case_id": case["case_id"], "outcome": "not_run", "reason": stop, "http_status": None, "client_seconds": None, "review_status": "needs_human_review"}
        if stop is None:
            req = urllib.request.Request(manifest["backend"] + "/api/hunt", data=json.dumps(case["request"]).encode("utf-8"), headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
            manifest["post_requests"] += 1
            before = time.perf_counter()
            try:
                with urllib.request.urlopen(req, timeout=cfg.timeout_seconds + 120) as response:
                    row["http_status"] = response.status
                    body = json.load(response)
                save(directory / (case["case_id"] + ".json"), body)
                execution = body.get("execution", {})
                row["outcome"] = ("abstain" if body.get("status") == "abstained" else
                    "offline_fallback" if execution.get("fallback_used") else
                    "real_llm_draft" if execution.get("source") == "llm" and execution.get("generation_succeeded") else "operational_error")
                row["reason"] = body.get("status")
                if stopped_by_response(row["http_status"], body):
                    stop = "stopped_provider_authentication_or_rate_limit"
            except urllib.error.HTTPError as exc:
                row.update(http_status=exc.code, outcome="operational_error", reason="backend_http_error")
                exc.close()
                stop = "stopped_http_error"
            except Exception as exc:
                row.update(outcome="operational_error", reason=type(exc).__name__)
                stop = "stopped_operational_error"
            row["client_seconds"] = round(time.perf_counter() - before, 6)
        results.append(row)
        save(directory / (case["case_id"] + "_observation.json"), row)
    manifest.update(finished_at_utc=datetime.now(timezone.utc).isoformat(), stop_reason=stop, results=results)
    save(directory / "run_summary.json", manifest)
    with (directory / "results.csv").open("x", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    return directory


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Send RG04/RG05 only if provider recovery and updated backend are verified")
    arguments = parser.parse_args()
    print(run(execute=arguments.execute).relative_to(ROOT).as_posix())
