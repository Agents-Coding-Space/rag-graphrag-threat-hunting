"""Recovery orchestration with mocked HTTP and a fake monotonic clock only."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import urllib.error
import urllib.request

import pytest

from threat_hunting.evaluation import experimental_comparison as pipeline
from threat_hunting.evaluation import experimental_recovery as recovery
from threat_hunting.llm.config import LLMConfig

ROOT = Path(__file__).resolve().parents[1]


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class FakeClock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = []
        self.interrupt = False

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        if self.interrupt:
            raise KeyboardInterrupt
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def original(tmp_path, monkeypatch):
    """Three small cases, including a successful sibling of a failed branch."""
    monkeypatch.setattr(pipeline, "ROOT", tmp_path)
    config_model = LLMConfig(base_url="http://mock-provider/v1", model_name="synthetic",
                             api_key="fixture-secret-never-persist", max_retries=9)
    monkeypatch.setattr(LLMConfig, "from_env", classmethod(lambda cls: deepcopy(config_model)))
    config = {"schema_version": "experimental-comparison-config/v2", "branches": list(pipeline.BRANCHES),
              "maximum_llm_requests": 24, "benchmark": "questions.json", "gate_policy": "policy.json",
              "runtime_artifacts": "runtime.json", "gate_contract": "source-evidence-contract/v2",
              "maximum_context_utf8_bytes": 4096, "maximum_messages_utf8_bytes": 4096}
    cases = {"cases": [{"case_id": f"C{i}", "scenario_id": "synthetic", "request": {"query": "test"}}
                       for i in range(3)]}
    put(tmp_path / "config.json", config)
    put(tmp_path / "questions.json", cases)
    put(tmp_path / "policy.json", {})
    paths = {name: f"{name}.json" for name in ("gt_path", "corpus_path", "graph_path", "index_path")}
    for name in paths.values():
        put(tmp_path / name, {})
    put(tmp_path / "runtime.json", {"scenarios": {"synthetic": {
        "paths": paths, "sha256": {name: pipeline.sha256(tmp_path / name) for name in paths.values()}}}})
    code_names = ["scripts/evaluate_rag_graphrag.py", "src/threat_hunting/evaluation/experimental_comparison.py",
                  "src/threat_hunting/llm/guardrail.py"]
    for name in code_names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("historical", encoding="utf-8")
    def code_manifest():
        return {p.relative_to(tmp_path).as_posix(): pipeline.sha256(p)
                for p in sorted(tmp_path.rglob("*.py"))}
    monkeypatch.setattr(pipeline, "_code_manifest", code_manifest)
    pin = {"model": pipeline._safe_config(config_model), "config_sha256": pipeline.sha256(tmp_path / "config.json"),
           "selected_case_ids": ["C0", "C1", "C2"],
           "cases_sha256": pipeline.sha256(tmp_path / "questions.json"), "gate_contract": config["gate_contract"],
           "gate_policy_sha256": pipeline.sha256(tmp_path / "policy.json"),
           "runtime_artifacts_config_sha256": pipeline.sha256(tmp_path / "runtime.json"),
           "artifacts": pipeline._source_manifest(pipeline._runtime_sources(tmp_path / "runtime.json")),
           "code_sha256": code_manifest()}
    put(tmp_path / "pin.json", pin)
    source = tmp_path / "original"
    put(source / "manifest.json", {**pin, "mode": "live", "selected_case_ids": ["C0", "C1", "C2"]})
    put(source / "configuration.json", config)
    put(source / "cases.json", cases)
    outcomes = ["accepted_draft", "provider_error", "validation_failed", "abstain", "provider_error", "provider_error"]
    rows = []
    import hashlib
    for i, outcome in enumerate(outcomes):
        cid, branch = f"C{i // 2}", pipeline.BRANCHES[i % 2]
        directory = source / f"{cid}_{branch}"
        context = {"traversal": {}, "retrieval": {"hits": []}}
        messages = [{"role": "user", "content": f"query for {cid} {branch}"}]
        row = {"case_id": cid, "scenario_id": "synthetic", "branch": branch, "outcome": outcome,
               "gate_decision": "abstain" if outcome == "abstain" else "proceed",
               "eligibility_decision": "abstain" if outcome == "abstain" else "proceed",
               "llm_http_attempts": 0 if outcome == "abstain" else 1,
               "context_sha256": hashlib.sha256(pipeline.canonical_bytes(context)).hexdigest(),
               "messages_sha256": hashlib.sha256(pipeline.canonical_bytes(messages)).hexdigest()}
        if outcome == "provider_error":
            row["provider_error"] = {"http_status": 503, "retry_after_seconds": 120}
        put(directory / "result.json", row)
        put(directory / "context.json", context)
        put(directory / "messages.json", {"messages": messages})
        put(directory / "gate.json", {"decision": row["gate_decision"]})
        put(directory / "eligibility.json", {"decision": row["eligibility_decision"], "budget_exceeded": False})
        rows.append(row)
    put(source / "results.json", {"mode": "live", "planned_branch_count": len(rows), "rows": rows})
    # Simulate only the intended, explicitly hash-pinned orchestration delta.
    (tmp_path / code_names[0]).write_text("new harness", encoding="utf-8")
    current = code_manifest()
    compatibility = {"schema_version": "recovery-harness-compatibility/v1",
        "historical_pin_sha256": pipeline.sha256(tmp_path / "pin.json"),
        "changes": {name: {"before": pin["code_sha256"].get(name), "after": current.get(name)}
                    for name in current if current[name] != pin["code_sha256"].get(name)}}
    put(tmp_path / "compatibility.json", compatibility)
    return SimpleNamespace(root=tmp_path, source=source, config=tmp_path / "config.json",
                           pin=tmp_path / "pin.json", compatibility=tmp_path / "compatibility.json", rows=rows)


def preflight(original, **kwargs):
    return recovery.preflight_recovery(original.config, original.source, pin_path=original.pin,
        compatibility_path=original.compatibility, **kwargs)


def mock_http(monkeypatch, clock, statuses=None):
    starts, payloads = [], []
    statuses = iter(statuses or [200, 200, 200])
    def urlopen(request, **kwargs):
        starts.append(clock())
        payloads.append(json.loads(request.data))
        clock.now += 2
        status = next(statuses)
        if status == "interrupt":
            raise KeyboardInterrupt
        if status != 200:
            raise urllib.error.HTTPError("http://mock-provider/v1", status, "mock error",
                {"Retry-After": "120"}, io.BytesIO(b"private upstream body must not persist"))
        report = {"verdict": "INSUFFICIENT_EVIDENCE", "executive_summary": "", "technical_analysis": ""}
        response = io.BytesIO(json.dumps({"choices": [{"message": {"content": json.dumps(report)}}]}).encode())
        response.headers = {"Content-Type": "application/json"}
        return response
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return starts, payloads


def test_exact_branch_selection_dry_run_never_constructs_client(original, monkeypatch):
    plan = preflight(original, request_interval_seconds=60)
    assert [(r["case_id"], r["branch"]) for r in plan.selected] == [("C0", "graphrag"), ("C2", "rag"), ("C2", "graphrag")]
    assert plan.source_outcomes == {"accepted_draft": 1, "provider_error": 3, "validation_failed": 1, "abstain": 1}
    def forbidden(**kwargs):
        raise AssertionError("dry-run constructed provider client")
    result = recovery.run_recovery(plan, original.root / "dry", client_factory=forbidden)
    assert result["planned_branch_count"] == result["eligible_branch_count"] == 3
    assert result["maximum_llm_requests"] == result["llm_http_attempts"] == 0
    assert result["configured_request_budget"] == 3


def test_real_client_mock_http_paces_after_http_end_and_keeps_source(original, monkeypatch, caplog):
    plan = preflight(original, live=True, max_requests=3, request_interval_seconds=60)
    clock = FakeClock()
    starts, payloads = mock_http(monkeypatch, clock)
    # Twenty seconds of local validation consume part of the interval, not an extra 60s.
    validate = pipeline.validate_generated
    def slow_validation(*args):
        clock.now += 20
        return validate(*args)
    monkeypatch.setattr(pipeline, "validate_generated", slow_validation)
    output = original.root / "recovery"
    result = recovery.run_recovery(plan, output, live=True, clock=clock, sleep=clock.sleep)
    assert starts == [100, 162, 224]
    assert sum(clock.sleeps) == 80
    assert result["llm_http_attempts"] == 3
    assert all(p["messages"] == entry["messages"] for p, entry in zip(payloads, plan.prepared))
    assert all(p["model"] == "synthetic" for p in payloads)
    assert "Waiting" in caplog.text
    recovery._check_hashes(plan.source, plan.source_hashes)
    mapping = pipeline._read(output / "recovery_mapping.json")["branches"]
    assert all(row["source_result_sha256"] and row["recovery_outcome"] == "accepted_draft" for row in mapping)
    text = (output / "manifest.json").read_text(encoding="utf-8")
    assert "fixture-secret" not in text
    assert "private upstream body" not in text


@pytest.mark.parametrize("status", [401, 403, 429, 503])
def test_http_stop_preserves_retry_after_and_does_not_wait_or_call_next(original, monkeypatch, status):
    plan = preflight(original, live=True, max_requests=3, request_interval_seconds=60)
    clock = FakeClock()
    starts, _ = mock_http(monkeypatch, clock, [status])
    output = original.root / "stopped"
    result = recovery.run_recovery(plan, output, live=True, clock=clock, sleep=clock.sleep)
    assert len(starts) == result["llm_http_attempts"] == 1
    assert clock.sleeps == []
    assert result["stopped_reason"] == f"provider_http_{status}"
    assert result["stop_details"]["http_status"] == status
    assert result["stop_details"]["retry_after_seconds"] == 120
    assert result["rows"][0]["outcome"] == ("rate_limited" if status == 429 else "provider_error")
    assert [row["outcome"] for row in result["rows"][1:]] == ["not_run", "not_run"]
    assert pipeline._read(output / "manifest.json")["stopped_reason"] == result["stopped_reason"]


def test_other_http_errors_keep_classification_without_retry_or_stop(original, monkeypatch):
    plan = preflight(original, live=True, max_requests=3)
    clock = FakeClock()
    starts, _ = mock_http(monkeypatch, clock, [400, 500, 502])
    result = recovery.run_recovery(plan, original.root / "other-errors", live=True, clock=clock, sleep=clock.sleep)
    assert len(starts) == result["llm_http_attempts"] == 3
    assert result["stopped_reason"] is None
    assert [row["provider_error"]["http_status"] for row in result["rows"]] == [400, 500, 502]
    assert all(row["outcome"] == "provider_error" for row in result["rows"])


@pytest.mark.parametrize("target", ["context", "messages"])
def test_late_branch_input_mismatch_blocks_all_generation(original, monkeypatch, target):
    path = original.source / "C2_graphrag" / (target + ".json")
    value = pipeline._read(path)
    value["tampered"] = True
    put(path, value)
    calls = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: calls.append(a))
    # messages hash is over the enclosed messages, so change those directly.
    if target == "messages":
        value["messages"][0]["content"] = "changed"
        put(path, value)
    with pytest.raises(recovery.RecoveryPreflightError, match="source_.*_hash_mismatch"):
        preflight(original, live=True, max_requests=3)
    assert calls == []


@pytest.mark.parametrize("target", ["pin", "config", "model", "runtime", "unlisted_code", "compatibility", "missing_compatibility"])
def test_pin_and_provenance_mismatch_block_before_client(original, monkeypatch, target):
    if target == "pin":
        value = pipeline._read(original.pin)
        value["model"]["model_name"] = "different"
        put(original.pin, value)
    elif target == "config":
        value = pipeline._read(original.config)
        value["maximum_context_utf8_bytes"] = 99
        put(original.config, value)
    elif target == "model":
        monkeypatch.setattr(LLMConfig, "from_env", classmethod(lambda cls: cls(model_name="different")))
    elif target == "runtime":
        put(original.root / "gt_path.json", {"changed": True})
    elif target == "unlisted_code":
        (original.root / "src/threat_hunting/llm/guardrail.py").write_text("changed", encoding="utf-8")
    elif target == "compatibility":
        value = pipeline._read(original.compatibility)
        next(iter(value["changes"].values()))["after"] = "0" * 64
        put(original.compatibility, value)
    elif target == "missing_compatibility":
        original.compatibility = None
    with pytest.raises(ValueError):
        preflight(original, live=True, max_requests=3)


@pytest.mark.parametrize("budget", [None, 0, 2, 4, True, 3.5])
def test_invalid_live_budget_rejected_before_request(original, budget):
    with pytest.raises(ValueError):
        preflight(original, live=True, max_requests=budget)


@pytest.mark.parametrize("interval", [-1, float("nan"), float("inf")])
def test_invalid_interval_rejected(original, interval):
    with pytest.raises(ValueError):
        preflight(original, request_interval_seconds=interval)


def test_existing_or_overlapping_output_rejected_before_requests(original, monkeypatch):
    plan = preflight(original, live=True, max_requests=3)
    def forbidden(**kwargs):
        raise AssertionError("no request may execute")
    for output in (original.source, original.source / "nested", original.root):
        with pytest.raises(ValueError):
            recovery.run_recovery(plan, output, live=True, client_factory=forbidden)
    existing = original.root / "existing"
    existing.mkdir()
    with pytest.raises(ValueError):
        recovery.run_recovery(plan, existing, live=True, client_factory=forbidden)


@pytest.mark.parametrize("stage", ["waiting", "inflight"])
def test_ctrl_c_saves_completed_results_and_marks_pending_not_run(original, monkeypatch, stage):
    plan = preflight(original, live=True, max_requests=3, request_interval_seconds=60)
    clock = FakeClock()
    if stage == "waiting":
        clock.interrupt = True
    starts, _ = mock_http(monkeypatch, clock, [200, "interrupt"])
    output = original.root / "interrupted"
    result = recovery.run_recovery(plan, output, live=True, clock=clock, sleep=clock.sleep)
    assert result["stopped_reason"] == "keyboard_interrupt"
    assert result["llm_http_attempts"] == (1 if stage == "waiting" else 2)
    assert result["rows"][0]["outcome"] == "accepted_draft"
    assert result["rows"][1]["outcome"] == ("not_run" if stage == "waiting" else "interrupted")
    assert result["rows"][2]["outcome"] == "not_run"
    assert pipeline._read(output / "results.json") == result
    assert pipeline._read(output / "manifest.json")["llm_http_attempts"] == len(starts)


def load_cli():
    spec = importlib.util.spec_from_file_location("harness_cli", ROOT / "scripts/evaluate_rag_graphrag.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    return cli


def test_cli_legacy_defaults_are_unchanged(original, monkeypatch):
    cli = load_cli()
    calls = []
    def run(*args, **kwargs):
        calls.append(kwargs)
        return dict(mode="offline_dry_run", planned_branch_count=6, eligible_branch_count=3,
                    llm_http_attempts=0, stopped_reason=None)
    monkeypatch.setattr(cli, "run_comparison", run)
    assert cli.main(["--config", str(original.config), "--output", str(original.root / "legacy")]) == 0
    assert calls == [{"live": False, "max_requests": 0, "case_ids": None, "request_interval_seconds": 0}]


def test_cli_recovery_live_syntax_without_executing_live(original, monkeypatch, capsys):
    cli = load_cli()
    calls = []
    def no_execution(plan, output, *, live):
        calls.append((plan, output, live))
        return dict(mode="live", planned_branch_count=3, eligible_branch_count=3,
                    maximum_llm_requests=3, llm_http_attempts=0, stopped_reason=None, stop_details=None)
    monkeypatch.setattr(recovery, "run_recovery", no_execution)
    args = ["--config", str(original.config), "--pin", str(original.pin), "--resume-from", str(original.source),
            "--harness-compatibility", str(original.compatibility), "--request-interval-seconds", "60",
            "--live", "--max-requests", "3", "--output", str(original.root / "live-syntax-only")]
    assert cli.main(args) == 0
    assert calls[0][0].interval == 60 and calls[0][0].budget == 3 and calls[0][2] is True
    assert "fixture-secret" not in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(args + ["--case-ids", "C0"])


def test_checkpoint_resume_explicitly_includes_pending_and_keeps_origin_inputs(original, monkeypatch):
    first = preflight(original, live=True, max_requests=3)
    clock = FakeClock()
    mock_http(monkeypatch, clock, [200, 503])
    checkpoint = original.root / "checkpoint"
    result = recovery.run_recovery(first, checkpoint, live=True, clock=clock, sleep=clock.sleep)
    assert [r["outcome"] for r in result["rows"]] == ["accepted_draft", "provider_error", "not_run"]
    second = recovery.preflight_recovery(original.config, checkpoint, pin_path=original.pin,
        compatibility_path=original.compatibility, include_not_run=True, max_requests=2)
    assert [(r["case_id"], r["branch"]) for r in second.selected] == [("C2", "rag"), ("C2", "graphrag")]
    assert len(second.provenance_chain) == 2
    assert second.prepared[1]["messages"] == first.prepared[2]["messages"]
    assert not (checkpoint / "C2_graphrag/context.json").exists()
    only_error = recovery.preflight_recovery(original.config, checkpoint, pin_path=original.pin,
        compatibility_path=original.compatibility, max_requests=1)
    assert len(only_error.selected) == 1
    put(original.source / "C2_graphrag/context.json", {"tampered": True})
    with pytest.raises(ValueError, match="source_artifact_hash_mismatch"):
        recovery.preflight_recovery(original.config, checkpoint, pin_path=original.pin,
            compatibility_path=original.compatibility, include_not_run=True, max_requests=2)


def test_recovery_respects_an_explicit_partial_branch_root_study(original):
    manifest = pipeline._read(original.source / "manifest.json")
    manifest["selected_case_ids"] = ["C2"]
    manifest["selected_branches"] = [{"case_id": "C2", "branch": "rag"}]
    put(original.source / "manifest.json", manifest)
    put(original.source / "results.json", {"mode": "live", "planned_branch_count": 1,
        "rows": [r for r in original.rows if (r["case_id"], r["branch"]) == ("C2", "rag")]})
    plan = preflight(original, max_requests=1)
    assert [(r["case_id"], r["branch"]) for r in plan.selected] == [("C2", "rag")]
