"""Reusable off-line verification for env-centralized operational config.

Zero LLM calls, zero writes outside stdout. Run with PYTHONDONTWRITEBYTECODE=1.
(a) validator claim/caveat matrix  (a2) cross-clause negation probes (F01)
(b) live v8 clean scan  (c) v6 historical-draft regression
(d) authentication Status/SubStatus event binding (F02)  (e) validator policy pinned (F03)
Exit code is the number of failed groups, so 0 means every group passed.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threat_hunting.evaluation import experimental_comparison as p  # noqa: E402
from threat_hunting.llm import generation_contract_v3 as policy  # noqa: E402

CLAIM_MATRIX = [
    ("Mục đích C2 hoặc kết quả truyền tải dữ liệu qua HTTP không được xác minh.", True),
    ("Các quan sát thất bại không chứng minh cracking, compromised credentials, exfiltration, C2 hay account compromise.", True),
    ("CTI mô tả distributed low-volume spraying nhưng không chứng minh host local, actor, IOC, HTTP completion, C2 hoặc compromise trong dataset PurpleSharp.", True),
    ("Tuy nhiên, dữ liệu telemetry chỉ dừng ở mức quan sát các sự kiện thất bại, không đủ để kết luận về mục đích C2 hoặc xác định danh tính tác nhân tấn công.", True),
    ("Không có bằng chứng về kênh C2 trong dữ liệu hiện có.", True),
    ("CTI là external technical context, không thiết lập hành vi, compromise, attribution hoặc C2 purpose trên host Mordor/PurpleSharp.", True),
    ("Hai host giao tiếp với C2 để nhận lệnh từ máy chủ điều khiển.", False),
    ("Kẻ tấn công dùng HTTP để tải payload PowerShell từ một máy chủ ngoài.", False),
    ("Kết nối exfiltration đã gửi dữ liệu qua C2 channel trong 3 phút.", False),
]


def matrix() -> bool:
    print("(a) validator claim/caveat matrix")
    ok = 0
    for text, expected in CLAIM_MATRIX:
        got = policy.is_negated_network_statement(policy.normalize(text))
        good = got == expected
        ok += good
        print(f"    {'PASS' if good else 'FAIL'} caveat={got!s:5} | {text[:70]}")
    print(f"    RESULT {ok}/{len(CLAIM_MATRIX)}")
    return ok == len(CLAIM_MATRIX)


def scan(directory: Path) -> dict[str, list[str]]:
    out = {}
    for case in sorted(q for q in directory.iterdir() if q.is_dir()):
        result = case / "result.json"
        raw_path = case / "raw_report_before_sanitize.json"
        if not raw_path.is_file():
            continue
        ctx = policy.annotate_context(p._read(case / "context.json"))
        out[case.name] = [i["code"] for i in policy.check_clock_and_scope(p._read(raw_path), ctx)["issues"]]
    return out


def live_v8() -> bool:
    print("\n(b) live v8 clean scan")
    base = ROOT / "outputs/experiments/integrated-final-v8-live-01"
    bad = 0
    for name in ("AUTH-DIRECT_rag", "AUTH-CTI_rag", "AUTH-CTI_graphrag"):
        ctx = policy.annotate_context(p._read(base / name / "context.json"))
        raw = p._read(base / name / "validation.json")["raw_report_before_sanitize"]
        issues = [i["code"] for i in policy.check_clock_and_scope(raw, ctx)["issues"]]
        bad += bool(issues)
        print(f"    {name:22} {'CLEAN' if not issues else issues}")
    print(f"    RESULT {'3/3 CLEAN' if not bad else f'{bad}/3 NOT CLEAN'}")
    return bad == 0


def v6_regression() -> bool:
    """Historical drafts: the duration defect must stay rejected; the network sentence is a caveat.

    The v3.0 validator also flagged "Muc dich C2 ... khong duoc xac minh" in draft 20261030T182105.
    That sentence states a limitation the question asked for, so v3.1 accepts it on purpose.
    Cross-clause masking is covered by group (a2) instead, where a negator in one clause must not
    hide an assertion in another.
    """
    print("\n(c) v6 historical drafts: duration defect rejected, network sentence is a caveat")
    found, caveats = set(), 0
    for path in sorted((ROOT / "outputs/demo/integrated-v6-manual-live-01").rglob("raw_report_before_sanitize.json")):
        ctx = policy.annotate_context(p._read(path.parent / "context.json"))
        audit = policy.check_clock_and_scope(p._read(path), ctx)
        found.update(i["code"] for i in audit["issues"])
        caveats += sum(1 for c in audit["checks"] if c.get("status") == "negated_boundary_caveat")
    ok = "unsupported_physical_duration_inference" in found and caveats > 0
    print(f"    found={sorted(found)}  negated_caveats={caveats}")
    print(f"    RESULT {'PASS' if ok else 'FAIL'}")
    return ok


AUTH_STATUS_MATRIX = [
    ("Event 4625 ghi Status 0xc000006d và SubStatus 0xc000006a.", None),
    ("Event 4776 ghi Status 0xc000006a và không ghi SubStatus.", None),
    ("Event 4625 ghi Status 0xc000006a và SubStatus 0xc000006a.", "auth_status_event_mismatch"),
    ("Event 4776 ghi Status 0xc000006a và SubStatus 0xc000006a.", "auth_status_event_mismatch"),
    ("Status 0xc000006a, SubStatus 0xc000006a cho cả hai view.", "auth_status_views_merged"),
]
CROSS_CLAUSE_MATRIX = [
    ("Không có IP nguồn, nhưng host dùng C2 để nhận lệnh.", False),
    ("C2 đã gửi dữ liệu ra ngoài nhưng chưa xác định tài khoản.", False),
    ("No source IP, but the host uses C2 for tasking.", False),
    ("Host dùng C2 để nhận lệnh.", False),
    ("The actor used HTTP but C2 was not established.", True),
    ("Các quan sát không chứng minh exfiltration, C2 hay compromise.", True),
]


def auth_binding() -> bool:
    print("\n(d) authentication Status/SubStatus binding to event (F02)")
    ctx = policy.annotate_context(p._read(
        ROOT / "outputs/experiments/integrated-final-v8-live-01/AUTH-CTI_graphrag/context.json"))
    bad = 0
    for text, want in AUTH_STATUS_MATRIX:
        codes = {i["code"] for i in policy.check_auth_field_binding({"technical_analysis": text}, ctx)["issues"]}
        got = sorted(codes)[0] if codes else None
        ok = got == want
        bad += 0 if ok else 1
        print(f"    {'PASS' if ok else 'FAIL'} want={want} got={got} | {text[:60]}")
    print(f"    RESULT {len(AUTH_STATUS_MATRIX) - bad}/{len(AUTH_STATUS_MATRIX)}")
    return bad == 0


def cross_clause() -> bool:
    print("\n(a2) cross-clause negation probes (F01)")
    bad = 0
    for text, want in CROSS_CLAUSE_MATRIX:
        got = policy.is_negated_network_statement(policy.normalize(text))
        ok = got == want
        bad += 0 if ok else 1
        print(f"    {'PASS' if ok else 'FAIL'} caveat={got!s:<5} want={want!s:<5} | {text[:56]}")
    print(f"    RESULT {len(CROSS_CLAUSE_MATRIX) - bad}/{len(CROSS_CLAUSE_MATRIX)}")
    return bad == 0


def pinned_validator() -> bool:
    print("\n(e) validator policy is part of the pinned safe-config (F03)")
    from threat_hunting.llm.config import LLMConfig
    pol = (p._safe_config(LLMConfig.from_env()).get("validator_policy") or {})
    ok = (pol.get("policy_id") == policy.VALIDATOR_POLICY_ID
          and pol.get("negation_scope") == "clause-local"
          and pol.get("network_lookbehind") == policy._env_int("VALIDATOR_NETWORK_LOOKBEHIND", 120, 400))
    print(f"    policy_id={pol.get('policy_id')} lookbehind={pol.get('network_lookbehind')}")
    print(f"    RESULT {'PASS' if ok else 'FAIL'}")
    return ok


def main() -> int:
    pol = policy.effective_validator_policy()
    print(f"validator policy in effect: {pol['policy_id']} "
          f"lookbehind={pol['network_lookbehind']} lookahead={pol['network_lookahead']} "
          f"scope={pol['negation_scope']}")
    results = [matrix(), cross_clause(), live_v8(), v6_regression(), auth_binding(), pinned_validator()]
    failed = sum(1 for r in results if not r)
    print(f"\nOVERALL: {'PASS' if failed == 0 else str(failed) + ' GROUP(S) FAILED'}")
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
