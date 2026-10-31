"""Final-study budgets, cooldown and source policy with fake HTTP and clock."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import io
import json
from pathlib import Path
import urllib.error
import urllib.request

import pytest

from threat_hunting.evaluation import experimental_comparison as p
from threat_hunting.evaluation import final_experiment as final
from threat_hunting.llm import generation_contract_v3 as policy
from threat_hunting.llm.client import retry_after_delay
from threat_hunting.llm.config import LLMConfig

ROOT = Path(__file__).resolve().parents[1]


class Clock:
    now = 100.0
    def __call__(self): return self.now
    def sleep(self, seconds): self.now += seconds


@pytest.fixture
def study(tmp_path, monkeypatch):
    monkeypatch.setattr(p, "ROOT", tmp_path)
    preflight = tmp_path / "preflight"
    preflight.mkdir()
    pin = tmp_path / "pin.json"
    p._write(pin, {"fixture": True})
    config_path = tmp_path / "config.json"
    config = {"final_run_policy": {"initial_attempt_limit": 16, "recovery_attempt_limit": 4,
        "total_attempt_limit": 20, "request_interval_seconds": 60, "task_ledger": "ledger.json"}}
    p._write(config_path, config)
    rows = []
    import hashlib
    for i in range(24):
        row = {"case_id": f"C{i//2}", "branch": ("rag", "graphrag")[i%2], "scenario_id": "fixture",
               "eligibility_decision": "proceed" if i < 16 else "abstain", "gate_decision": "proceed" if i < 16 else "abstain",
               "outcome": "dry_run_no_generation" if i < 16 else "abstain", "llm_http_attempts": 0}
        directory = preflight / f"{row['case_id']}_{row['branch']}"
        directory.mkdir()
        context = {"retrieval": {"hits": []}, "traversal": {}}
        messages = [{"role": "user", "content": "fixture question"}]
        for name, value in (("context", context), ("messages", messages)):
            row[name + "_sha256"] = hashlib.sha256(p.canonical_bytes(value)).hexdigest()
            p._write(directory / (name + ".json"), value if name == "context" else {"messages": value})
        rows.append(row)
    model = LLMConfig(model_name="fixture", base_url="http://mock-provider/v1", max_retries=1)
    monkeypatch.setattr(final, "validate_preflight", lambda *args: (config, {}, {"rows": rows}, model))
    return tmp_path, config_path, pin, preflight


def mock_http(monkeypatch, clock, statuses):
    statuses = iter(statuses)
    calls = []
    def urlopen(request, **kwargs):
        calls.append(clock())
        clock.now += 2
        status = next(statuses)
        if status == "interrupt": raise KeyboardInterrupt
        if status != 200:
            raise urllib.error.HTTPError("http://mock-provider/v1", status, "private", {"Retry-After": "120"}, io.BytesIO(b"private body"))
        raw = {"verdict": "INSUFFICIENT_EVIDENCE", "executive_summary": "", "technical_analysis": ""}
        response = io.BytesIO(json.dumps({"choices": [{"message": {"content": json.dumps(raw)}}]}).encode())
        response.headers = {"Content-Type": "application/json"}
        return response
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return calls


def execute(study, name, clock, **kwargs):
    root, config, pin, preflight = study
    return final.run_final(config, pin, preflight, root / "outputs/experiments" / name,
        clock=clock, wall=clock, sleep=clock.sleep, **kwargs)


def test_final_first_phase_calls_eligible_only_and_spaces_attempts(study, monkeypatch):
    clock = Clock()
    calls = mock_http(monkeypatch, clock, [200] * 16)
    result = execute(study, "initial", clock, live=True)
    assert len(calls) == result["llm_http_attempts"] == 16
    assert len(result["rows"]) == 24
    assert sum(r["outcome"] == "abstain" for r in result["rows"]) == 8
    assert all(b - a >= 62 for a,b in zip(calls, calls[1:]))
    with pytest.raises(ValueError, match="This task ledger already has attempts"):
        execute(study, "second-initial", clock, live=True)
    assert len(calls) == 16


def test_503_stops_and_recovery_respects_cooldown_global_caps(study, monkeypatch):
    root = study[0]
    clock = Clock()
    calls = mock_http(monkeypatch, clock, [503] + [200] * 4)
    first = execute(study, "initial", clock, live=True)
    assert first["llm_http_attempts"] == 1 and first["stopped_reason"] == "provider_http_503"
    assert first["stop_details"]["retry_after_seconds"] == 120
    assert sum(r["outcome"] == "not_run" for r in first["rows"]) == 15
    second = execute(study, "recovery", clock, live=True, resume_from=root / "outputs/experiments/initial")
    assert calls[1] >= 222  # First request finished at102 plus Retry-After120.
    assert second["llm_http_attempts"] == 4
    assert len(p._read(root / "ledger.json")["attempts"]) == 5
    third = execute(study, "recovery-again", clock, live=True, resume_from=root / "outputs/experiments/recovery")
    assert third["llm_http_attempts"] == 0 and len(calls) == 5
    assert third["stopped_reason"] == "task_budget_exhausted"


@pytest.mark.parametrize("status", [401, 403])
def test_credential_error_prohibits_recovery(study, monkeypatch, status):
    clock = Clock()
    calls = mock_http(monkeypatch, clock, [status])
    first = execute(study, "initial", clock, live=True)
    assert first["stopped_reason"] == f"provider_http_{status}"
    with pytest.raises(ValueError, match="Credential stop"):
        execute(study, "recovery", clock, live=True, resume_from=study[0] / "outputs/experiments/initial")
    assert len(calls) == 1


def test_dry_never_calls_http_or_creates_task_ledger(study, monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: pytest.fail("Dry-run HTTP"))
    result = execute(study, "dry", Clock())
    assert result["llm_http_attempts"] == 0 and not (study[0] / "ledger.json").exists()


def test_ctrl_c_counts_attempt_and_keeps_completed_checkpoint(study, monkeypatch):
    clock = Clock()
    mock_http(monkeypatch, clock, ["interrupt"])
    result = execute(study, "interrupted", clock, live=True)
    assert result["stopped_reason"] == "keyboard_interrupt" and result["llm_http_attempts"] == 1
    assert p._read(study[0] / "ledger.json")["attempts"][0]["actual_http_attempts"] == 1


def test_http_date_retry_after_and_global_ledger_pin_mismatch(tmp_path):
    assert retry_after_delay("120") == 120
    assert 118 <= retry_after_delay(format_datetime(datetime.now(timezone.utc) + timedelta(seconds=120))) <= 120
    assert retry_after_delay("not a header date") is None
    final.TaskBudget(tmp_path / "ledger.json", "pin-A")
    with pytest.raises(ValueError, match="profile or budget changed"):
        final.TaskBudget(tmp_path / "ledger.json", "pin-B")


def manual_reports():
    return sorted((ROOT / "outputs/demo/integrated-v6-manual-live-01").rglob("raw_report_before_sanitize.json"))


def test_reproduced_dashboard_errors_are_rejected_without_changing_old_files():
    """Historical v6 drafts keep their genuine defect; negated boundary caveats are not defects.

    Draft 20261030T181517 asserted a physical activity duration from a canonical span and must
    stay rejected. Draft 20261030T182105 only says C2/HTTP outcomes were *not* verified, which is
    a correct limitation for the question asked, so it must no longer be rejected.
    """
    found, caveats = set(), 0
    for path in manual_reports():
        raw = p._read(path)
        context = policy.annotate_context(p._read(path.parent / "context.json"))
        audit = policy.check_clock_and_scope(raw, context)
        found.update(i["code"] for i in audit["issues"])
        caveats += sum(1 for c in audit["checks"] if c.get("status") == "negated_boundary_caveat")
    assert "unsupported_physical_duration_inference" in found
    assert "unrequested_network_claim" not in found
    assert caveats > 0


def test_asserted_network_claims_are_still_rejected():
    """The negative-only relaxation must not whitelist genuine out-of-scope assertions."""
    path = manual_reports()[0]
    context = policy.annotate_context(p._read(path.parent / "context.json"))
    for text in ("Hai host giao tiếp với C2 để nhận lệnh từ máy chủ điều khiển.",
                 "Dữ liệu exfiltration đã hoàn tất 2 MB.",
                 "Giống nhau: few attempts/account. Khác: host đã bị C2."):
        codes = [i["code"] for i in policy.check_clock_and_scope({"technical_analysis": text}, context)["issues"]]
        assert "unrequested_network_claim" in codes


@pytest.mark.parametrize("text", [
    "Mục đích C2 hoặc kết quả truyền tải dữ liệu qua HTTP không được xác minh.",
    "CTI là external technical context, không thiết lập hành vi, compromise hoặc C2 purpose trên host.",
    "Không có bằng chứng về kênh C2 trong dữ liệu hiện có."])
def test_negated_network_boundary_is_not_an_out_of_scope_claim(text):
    path = manual_reports()[0]
    context = policy.annotate_context(p._read(path.parent / "context.json"))
    assert policy.check_clock_and_scope({"technical_analysis": text}, context)["issues"] == []


@pytest.mark.parametrize("text", [
    "Khoảng dấu thời gian canonical của observations có thời lượng 0.012 giây; không chứng minh thời lượng hoạt động thực tế.",
    "Không thể kết luận thời lượng 0.012 giây của hoạt động thực tế từ canonical timestamp."])
def test_clock_scope_allows_explicit_canonical_or_negated_duration(text):
    path = manual_reports()[0]
    context = policy.annotate_context(p._read(path.parent / "context.json"))
    assert policy.check_clock_and_scope({"technical_analysis": text}, context)["issues"] == []


def test_comparison_policy_uses_query_only_and_keeps_scope_general():
    focus = policy.question_focus("Đối chiếu mẫu phân bố telemetry với CTI, giống và khác ở đâu?")
    assert focus == {"comparison_requested": True, "network_requested": False}
    assert policy.question_focus("Giới hạn HTTP completion và C2 của network connections")['network_requested']
    assert not policy.question_focus("Đối chiếu report về CovertNetwork-1658 với telemetry")['network_requested']
    assert "AUTH-" not in policy.INSTRUCTIONS and "expected answer" not in policy.INSTRUCTIONS.casefold().replace("reference answer", "")


def confirmation(study, clock, ordinal=1):
    path = study[0] / f"balance-confirmation-{ordinal}.json"
    p._write(path, {"schema_version":"openrouter-balance-confirmation/v1", "confirmed":True,
        "confirmation_source":"explicit_user_reply", "task_pin_sha256":p.sha256(study[2]),
        "after_attempt_ordinal":ordinal, "confirmed_at_utc":datetime.fromtimestamp(clock(),timezone.utc).isoformat()})
    return path


def test_402_stops_and_continuation_is_blocked_without_user_receipt(study, monkeypatch):
    clock = Clock()
    calls = mock_http(monkeypatch, clock, [402])
    first = execute(study,"initial",clock,live=True)
    assert len(calls) == first["llm_http_attempts"] == 1
    assert first["stopped_reason"] == "provider_http_402"
    ledger = study[0] / "ledger.json"
    before = ledger.read_bytes()
    source = study[0] / "outputs/experiments/initial"
    with pytest.raises(ValueError,match="explicit user confirmation"):
        execute(study,"blocked",clock,live=True,resume_from=source,continue_task=True)
    assert ledger.read_bytes() == before and len(calls) == 1
    assert not (study[0]/"outputs/experiments/blocked").exists()
    dry = execute(study,"dry-continuation",clock,resume_from=source,continue_task=True)
    assert dry["planned_branch_count"] == 16 and dry["llm_http_attempts"] == 0
    assert ledger.read_bytes() == before
    manifest = p._read(study[0]/"outputs/experiments/dry-continuation/manifest.json")
    assert sum(r["phase"]=="initial" for r in manifest["budget_assignments"])==15
    assert sum(r["phase"]=="recovery" for r in manifest["budget_assignments"])==1


def test_confirmed_continuation_uses_15_unattempted_slots_plus_one_recovery_without_reset(study, monkeypatch):
    clock = Clock()
    calls = mock_http(monkeypatch,clock,[402]+[200]*16)
    execute(study,"initial",clock,live=True)
    prefix = deepcopy(p._read(study[0]/"ledger.json")["attempts"])
    receipt = confirmation(study,clock)
    result = execute(study,"continued",clock,live=True,continue_task=True,
        resume_from=study[0]/"outputs/experiments/initial",balance_confirmation=receipt)
    ledger = p._read(study[0]/"ledger.json")
    assert len(calls)==len(ledger["attempts"])==17 and result["llm_http_attempts"]==16
    assert ledger["attempts"][:1]==prefix
    assert sum(a["phase"]=="initial" for a in ledger["attempts"])==16
    assert sum(a["phase"]=="recovery" for a in ledger["attempts"])==1
    assert all(r["outcome"]=="accepted_draft" for r in result["rows"])
    again = execute(study,"no-regeneration",clock,resume_from=study[0]/"outputs/experiments/continued",continue_task=True)
    assert again["planned_branch_count"]==0 and again["llm_http_attempts"]==0
    assert len(calls)==17


def test_second_402_keeps_new_diagnostic_stops_and_requires_fresh_confirmation(study, monkeypatch):
    clock = Clock()
    calls = mock_http(monkeypatch,clock,[402,402])
    execute(study,"initial",clock,live=True)
    receipt = confirmation(study,clock)
    second = execute(study,"continued",clock,live=True,resume_from=study[0]/"outputs/experiments/initial",
        continue_task=True,balance_confirmation=receipt)
    assert second["stopped_reason"]=="provider_http_402" and second["llm_http_attempts"]==1
    assert second["stop_details"]["diagnostic"]["http_status"]==402
    assert sum(r["outcome"]=="not_run" for r in second["rows"])==15
    before=(study[0]/"ledger.json").read_bytes()
    with pytest.raises(ValueError,match="fresh explicit user confirmation"):
        execute(study,"stale-confirmation",clock,live=True,resume_from=study[0]/"outputs/experiments/continued",
            continue_task=True,balance_confirmation=receipt)
    assert (study[0]/"ledger.json").read_bytes()==before and len(calls)==2


def test_validation_failed_branch_is_never_selected_for_continuation(study, monkeypatch):
    clock=Clock()
    count=0
    def invalid_then_402(request,**kwargs):
        nonlocal count
        count+=1
        clock.now+=2
        if count==1:
            response=io.BytesIO(json.dumps({"choices":[{"message":{"content":"{}"}}]}).encode())
            response.headers={"Content-Type":"application/json"}
            return response
        raise urllib.error.HTTPError("http://mock-provider/v1",402,"error",{},io.BytesIO(b"Payment required"))
    monkeypatch.setattr(urllib.request,"urlopen",invalid_then_402)
    first=execute(study,"initial",clock,live=True)
    assert first["rows"][0]["outcome"]=="validation_failed"
    plan=execute(study,"dry",clock,resume_from=study[0]/"outputs/experiments/initial",continue_task=True)
    assert not any((r["case_id"],r["branch"])==("C0","rag") for r in plan["rows"])
    assert plan["planned_branch_count"]==15


# --- F01: negation locality regression ------------------------------------------------
# A negator in one clause must never mask an assertion in another clause.
F01_CLAIM_PROBES = [
    "Không có IP nguồn, nhưng host dùng C2 để nhận lệnh.",
    "C2 đã gửi dữ liệu ra ngoài nhưng chưa xác định tài khoản.",
    "Host dùng C2 để nhận lệnh; chưa xác định tài khoản.",
    "No source IP, but the host uses C2 for tasking.",
    "Host bị C2 qua HTTP tới 10.10.10.5.",
    "Dữ liệu exfiltration đã hoàn tất 2 MB.",
    "The host exfiltrated 2MB over HTTP.",
    "Host dùng C2 để nhận lệnh.",
]
F01_CAVEAT_PROBES = [
    "Mục đích C2 hoặc kết quả truyền tải dữ liệu qua HTTP không được xác minh.",
    "CTI là external context, không thiết lập hành vi, compromise hoặc C2 purpose trên host.",
    "Không có bằng chứng về kênh C2 trong dữ liệu hiện có.",
    "The actor used HTTP but C2 was not established.",
    "Các quan sát không chứng minh exfiltration, C2 hay compromise.",
]


@pytest.mark.parametrize("text", F01_CLAIM_PROBES)
def test_negation_in_another_clause_does_not_mask_a_positive_network_claim(text):
    path = manual_reports()[0]
    context = policy.annotate_context(p._read(path.parent / "context.json"))
    assert policy.is_negated_network_statement(policy.normalize(text)) is False
    codes = [i["code"] for i in policy.check_clock_and_scope({"technical_analysis": text}, context)["issues"]]
    assert "unrequested_network_claim" in codes


@pytest.mark.parametrize("text", F01_CAVEAT_PROBES)
def test_true_boundary_caveats_are_still_accepted(text):
    path = manual_reports()[0]
    context = policy.annotate_context(p._read(path.parent / "context.json"))
    assert policy.is_negated_network_statement(policy.normalize(text)) is True
    assert policy.check_clock_and_scope({"technical_analysis": text}, context)["issues"] == []


def test_network_topic_spans_report_clause_locality():
    detail = policy.network_topic_spans(policy.normalize("Không có IP nguồn, nhưng host dùng C2 để nhận lệnh."))
    assert detail and all(d["negated"] is False for d in detail)
    caveat = policy.network_topic_spans(policy.normalize("Mục đích C2 không được xác minh."))
    assert caveat and all(d["negated"] is True for d in caveat)


# --- F02: authentication Status/SubStatus must bind to its event ----------------------
def _auth_context():
    path = ROOT / "outputs/experiments/integrated-final-v8-live-01/AUTH-CTI_graphrag/context.json"
    return policy.annotate_context(p._read(path))


def test_saved_v8_auth_cti_graphrag_status_merge_is_rejected():
    """Historical report merged 4625 Status 0xc000006d into 0xc000006a. It must be rejected."""
    raw = p._read(ROOT / "outputs/experiments/integrated-final-v8-live-01/"
                         "AUTH-CTI_graphrag/raw_report_before_sanitize.json")
    audit = policy.check_auth_field_binding(raw, _auth_context())
    assert "auth_status_views_merged" in {i["code"] for i in audit["issues"]}
    assert sorted(audit["events_in_context"]) == ["4625", "4776"]


def test_correct_auth_status_report_is_not_flagged():
    raw = p._read(ROOT / "outputs/experiments/integrated-final-v8-live-01/"
                         "AUTH-DIRECT_rag/raw_report_before_sanitize.json")
    assert policy.check_auth_field_binding(raw, _auth_context())["issues"] == []


@pytest.mark.parametrize("text,expect_code", [
    ("Event 4625 ghi Status 0xc000006a và SubStatus 0xc000006a.",
     "auth_status_event_mismatch"),
    ("Event 4776 ghi Status 0xc000006a và SubStatus 0xc000006a.",
     "auth_status_event_mismatch"),
    ("Status 0xc000006a, SubStatus 0xc000006a cho cả hai view.",
     "auth_status_views_merged"),
])
def test_auth_status_contract_violations(text, expect_code):
    audit = policy.check_auth_field_binding({"technical_analysis": text}, _auth_context())
    assert expect_code in {i["code"] for i in audit["issues"]}


@pytest.mark.parametrize("text", [
    "Event 4625 có Status 0xc000006d và SubStatus 0xc000006a.",
    "Event 4776 có Status 0xc000006a và không ghi SubStatus.",
])
def test_auth_status_correct_values_are_accepted(text):
    assert policy.check_auth_field_binding({"technical_analysis": text}, _auth_context())["issues"] == []


def test_auth_binding_skips_when_context_has_no_auth_events():
    audit = policy.check_auth_field_binding({"technical_analysis": "Status 0xc000006a"},
                                            {"query": {"text": "nothing"}, "retrieval": {"hits": []}})
    assert audit["issues"] == [] and audit["events_in_context"] == []


# --- F03: validator policy must be pinned ---------------------------------------------
def test_safe_config_carries_validator_policy():
    from threat_hunting.evaluation import experimental_comparison as comp
    from threat_hunting.llm.config import LLMConfig
    safe = comp._safe_config(LLMConfig.from_env())
    assert "validator_policy" in safe
    assert safe["validator_policy"]["policy_id"] == policy.VALIDATOR_POLICY_ID
    assert safe["validator_policy"]["negation_scope"] == "clause-local"


def test_validator_parameter_change_alters_pin_safe_config(monkeypatch):
    from threat_hunting.evaluation import experimental_comparison as comp
    from threat_hunting.llm.config import LLMConfig
    before = comp._safe_config(LLMConfig.from_env())
    monkeypatch.setenv("VALIDATOR_NETWORK_LOOKBEHIND", "200")
    after = comp._safe_config(LLMConfig.from_env())
    assert before != after
    assert after["validator_policy"]["network_lookbehind"] == 200


@pytest.mark.parametrize("raw,expected", [("abc", 120), ("0", 120), ("-5", 120), ("", 120),
                                          ("99999", 400), ("250", 250)])
def test_validator_window_bounds_and_fallback(monkeypatch, raw, expected):
    monkeypatch.setenv("VALIDATOR_NETWORK_LOOKBEHIND", raw)
    assert policy.effective_validator_policy()["network_lookbehind"] == expected


def test_validator_window_can_change_outcome_but_is_visible():
    """The knob really does change an outcome; that is exactly why it must be pinned."""
    text = policy.normalize("Mục đích C2 hoặc kết quả truyền tải dữ liệu qua HTTP không được xác minh.")
    assert policy.effective_validator_policy()["network_lookbehind"] == 120
    assert policy.is_negated_network_statement(text) is True
