"""Reusable off-line verification for env-centralized operational config.

Zero LLM calls, zero writes outside stdout. Run with PYTHONDONTWRITEBYTECODE=1.
(a) validator claim/caveat matrix  (b) live v8 clean scan  (c) v6 regression.
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
    print("\n(c) v6 regression (2 historical bad drafts)")
    found = set()
    for path in sorted((ROOT / "outputs/demo/integrated-v6-manual-live-01").rglob("raw_report_before_sanitize.json")):
        ctx = policy.annotate_context(p._read(path.parent / "context.json"))
        found.update(i["code"] for i in policy.check_clock_and_scope(p._read(path), ctx)["issues"])
    wanted = {"unsupported_physical_duration_inference", "unrequested_network_claim"}
    print(f"    found={sorted(found)}")
    print(f"    RESULT {'BOTH PRESENT' if wanted <= found else 'MISSING ' + str(wanted - found)}")
    return wanted <= found


def main() -> int:
    print(f"validator windows in effect: lookbehind={policy._env_int('VALIDATOR_NETWORK_LOOKBEHIND', 120)} "
          f"lookahead={policy._env_int('VALIDATOR_NETWORK_LOOKAHEAD', 80)}")
    return 0 if all((matrix(), live_v8(), v6_regression())) else 1


if __name__ == "__main__":
    raise SystemExit(main())
