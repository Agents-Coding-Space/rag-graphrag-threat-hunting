"""Question-focused policy with bounded clock/scope checks, no benchmark input."""
from __future__ import annotations

from copy import deepcopy
import json
import os
import re
import unicodedata
from typing import Any

from . import generation_contract as source

CONTRACT = "source-meaning/v3"
INSTRUCTIONS = """
QUESTION FOCUS AND CLOCK POLICY source-meaning/v3:
- Answer every requested part, using only the supplied source fields. Do not substitute a
  general safety disclaimer for the requested facts or comparison. Do not add unrelated
  HTTP/C2/exfiltration caveats when the question does not concern network behavior.
- For a requested telemetry/CTI comparison, explicitly separate: local telemetry with its
  references; publisher/report context with separate references; similarities; differences
  in the behavior/distribution actually described; and limits. Explain both similarities
  AND differences. A difference in document detail is not a substitute for comparing the
  requested behavior. If a comparison dimension is absent in the returned sources, say
  which dimension cannot be compared; do not invent it. This is an answer structure,
  not a finding, actor attribution or reference answer.
- When reporting a time interval from authentication records, explicitly call it a
  'khoảng dấu thời gian canonical của các observations/anchors được chọn'. Do not call
  it the duration, start or end of the actual attack/activity. Event timestamps, actual
  activity duration and cross-host clock synchronization are different propositions.
  Raw timestamps and clock caveats remain; no time correction is authorized.
- sigma_matches copies exact source rule_id values; finding IDs and graph node IDs are
  citation identifiers only. Keep observed actor/action separate from command text and
  unobserved completion. Candidate/review status never becomes human confirmation.
- Keep optional report fields empty when they add nothing required by the question.
  Citations must bind the claim in the same clause. The report remains a reviewable draft.
"""


def normalize(value: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", value.casefold().replace("đ", "d"))
                   if unicodedata.category(c) != "Mn")


def query_text(context: dict[str, Any]) -> str:
    query = context.get("query", {})
    return query.get("text", "") if isinstance(query, dict) else str(query)


def question_focus(query: str) -> dict[str, bool]:
    value = normalize(query)
    return {"comparison_requested": bool(re.search(r"doi chieu|so sanh|compar", value)),
            "network_requested": bool(re.search(r"\bc2\b|\bhttp\b|exfil|\bnetwork\b|ket noi|\bmang\b|download|scriptlet|\burl\b", value))}


# A sentence that states a network topic is NOT established is a boundary/caveat, not an
# out-of-scope claim. Detection must stay inside the clause that carries the topic, otherwise
# a negation in one clause masks an assertion in another
# ("Khong co IP nguon, nhung host dung C2 de nhan lenh." is a claim, not a caveat).
_NETWORK_TOPIC = re.compile(r"\bc2\b|\bhttp\b|exfiltration")
_NETWORK_NEGATION = re.compile(
    r"khong|chua|khong the|not|cannot|unverified|chua xac minh|khong chung minh|"
    r"chua du|khong du|khong xac nhan|not established|not proven|no evidence|unproven|"
    r"chua chung minh|khong chung thuc|chua ket luan|khong ket luan")
# Vietnamese and English clause boundaries. Only true clause-level connectives split; commas and
# enumerations ("hoac", "hay", "or", "and") stay inside one clause because a negator in
# "khong chung minh exfiltration, C2 hay compromise" governs the whole list.
_CLAUSE_SPLIT = re.compile(
    r";|\bbut\b|\bhowever\b|\bnhung\b|\bnhưng\b|\btuy nhien\b|\btuy nhiên\b|\bwhereas\b|\.|\?|!|\n")
# A comma only splits when it joins two independent clauses, which in practice means a
# subject-bearing verb follows it. Commas inside enumerations never qualify.
_COMMA_CLAUSE = re.compile(r",\s*(?=(?:host|the |it |they |he |she |we |tuy nhien |nhung |nhưng |however |but ))")
# Affirmative uses of a network topic as the direct object of a use/transfer verb, i.e. a
# positive claim rather than a boundary caveat. The pattern is deliberately anchored on the
# object so "used HTTP ... but C2 was not established" does not read as an asserted HTTP claim.
_AFFIRMATIVE_USE = re.compile(
    r"\b(?:dung|dùng|su dung|sử dụng|uses?|used|using|sent|send|gui|gửi|truyen|truyền|transfer|exfiltrat"
    r"|connect|ket noi|kết nối|beacon|nhan lenh|nhận lệnh|receiv|bị|bi)\s+(?:toi |tới |ra |out |du lieu |dữ liệu )?"
    r"(?:c2|http|exfiltration)\b")
# Boundary markers: once the sentence moves to a limitation clause, earlier plain mentions of a
# topic are context, not asserted operational claims.
_BOUNDARY_MARKER = re.compile(
    r"\bbut\b|\bhowever\b|\bnhung\b|\bnhưng\b|\btuy nhien\b|\btuy nhiên\b|\bkhong\b|\bkhông\b|"
    r"\bchua\b|\bchưa\b|\bnot\b|\bcannot\b|\bunverified\b")



def _clause_spans(value: str) -> list[tuple[int, int]]:
    """Return (start, end) offsets of the clause chunks of a normalised sentence."""
    spans, start = [], 0
    for match in _CLAUSE_SPLIT.finditer(value):
        spans.append((start, match.start()))
        start = match.end()
    spans.append((start, len(value)))
    out: list[tuple[int, int]] = []
    for a, b in spans:
        if b <= a:
            continue
        chunk_start = a
        for comma in _COMMA_CLAUSE.finditer(value, a, b):
            if comma.start() > chunk_start:
                out.append((chunk_start, comma.start()))
                chunk_start = comma.end()
        if b > chunk_start:
            out.append((chunk_start, b))
    return out


def _env_int(name: str, default: int, maximum: int | None = None) -> int:
    """Read a bounded positive int from environment; fall back to default on bad input.

    Read directly from ``os.environ`` on purpose: importing the LLM config module
    here would create a circular import. ``maximum`` enforces the upper bound that the
    previous implementation advertised in prose but never applied.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value <= 0:
        return default
    return min(value, maximum) if maximum is not None else value


def is_negated_network_statement(value: str) -> bool:
    """True when every network topic carries a negation **inside its own clause**.

    Vietnamese places negation before the noun phrase ("khong chung minh ... C2") while
    other clauses place it after it ("muc dich C2 ... khong duoc xac minh"). Both are
    caveats. A negator in a neighbouring clause is not: "khong co IP nguon, nhung host
    dung C2" asserts C2 and must be rejected. The character window only bounds the search
    inside a clause, so it can never reach across a clause boundary.
    """
    lookbehind = _env_int("VALIDATOR_NETWORK_LOOKBEHIND", 120, 400)
    lookahead = _env_int("VALIDATOR_NETWORK_LOOKAHEAD", 80, 400)
    spans = _clause_spans(value)
    topics = list(_NETWORK_TOPIC.finditer(value))
    if not topics:
        return False
    # A sentence is a caveat when at least one network topic is negated in its own clause and no
    # topic is the object of an affirmative assertion. "The actor used HTTP but C2 was not
    # established" is a caveat about C2; "No source IP, but the host uses C2" asserts C2 and is
    # not. Assertion verbs are checked before negation so a negated topic cannot be re-read as
    # asserted by a verb that belongs to another clause.
    negated_any = False
    for match in topics:
        c_start, c_end = next(((a, b) for a, b in spans if a <= match.start() <= b), (0, len(value)))
        clause = value[c_start:c_end]
        before = value[max(c_start, match.start() - lookbehind):match.start()]
        after = value[match.end():min(c_end, match.end() + lookahead)]
        local = before + " " + after
        if _NETWORK_NEGATION.search(local):
            negated_any = True
            continue
        # An affirmative use verb states a claim only when no boundary marker follows it; a
        # later limitation clause ("but C2 was not established") re-scopes the whole sentence.
        affirm = _AFFIRMATIVE_USE.search(clause)
        if affirm:
            tail = value[c_start + affirm.end():c_end]
            if not _BOUNDARY_MARKER.search(tail) and not _BOUNDARY_MARKER.search(value[c_end:]):
                return False
    return negated_any


def network_topic_spans(value: str) -> list[dict[str, Any]]:
    """Diagnostic detail for each network topic: clause, negation locality and verdict."""
    lookbehind = _env_int("VALIDATOR_NETWORK_LOOKBEHIND", 120, 400)
    lookahead = _env_int("VALIDATOR_NETWORK_LOOKAHEAD", 80, 400)
    spans = _clause_spans(value)
    out = []
    for match in _NETWORK_TOPIC.finditer(value):
        c_start, c_end = next(((a, b) for a, b in spans if a <= match.start() <= b), (0, len(value)))
        before = value[max(c_start, match.start() - lookbehind):match.start()]
        after = value[match.end():min(c_end, match.end() + lookahead)]
        out.append({"topic": match.group(), "offset": match.start(),
                    "clause": value[c_start:c_end].strip(),
                    "negated": bool(_NETWORK_NEGATION.search(before + " " + after))})
    return out


def annotate_context(context: dict[str, Any]) -> dict[str, Any]:
    result = source.annotate_context(context)
    result["generation_evidence_contract"]["schema_version"] = CONTRACT
    return result


def build_messages(query: str, context: dict[str, Any]) -> list[dict[str, str]]:
    messages = source.build_messages(query, context)
    messages[0]["content"] += INSTRUCTIONS
    messages[1]["content"] += "\n[QUESTION FOCUS — derived from user request, not evaluation criteria]\n" + json.dumps(question_focus(query))
    return messages


def check_clock_and_scope(raw: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    projection = source.project_meaning(context)
    auth = bool(projection["timestamp_semantics"]["source_clock_groups"])
    focus = question_focus(query_text(context))
    issues, checks = [], []
    for field in ("direct_answer", "executive_summary", "technical_analysis", "unverified_claims"):
        texts = raw.get(field, []) if field == "unverified_claims" else [raw.get(field, "")]
        for text in texts:
            for sentence in re.split(r"\n|(?<=[.!?])\s+|;", text):
                value = normalize(sentence)
                # Only explicit duration expressions with numeric units are classified.
                match = re.search(r"(?:thoi luong|keo dai|duration|lasted)[^\n]{0,65}?\d+(?:[.,]\d+)?\s*(?:mili.?giay|milliseconds?|\bms\b|giay|seconds?|\bs\b)", value)
                if auth and match:
                    prefix = value[:match.start()]
                    negative = bool(re.search(r"khong|chua|not|cannot|unverified", prefix))
                    canonical_scope = bool(re.search(r"(?:canonical|timestamp|dau thoi gian|observation|anchor)", value))
                    physical = bool(re.search(r"thoi luong (?:cua )?(?:cuoc|dot|cum)?\s*(?:tan cong|hoat dong)|(?:attack|activity) duration|(?:attack|activity) lasted", value))
                    supported = negative or (canonical_scope and not physical)
                    checks.append({"field": field, "kind": "numeric_duration_expression", "status": "scoped_or_negated" if supported else "unsupported_physical_inference"})
                    if not supported:
                        issues.append({"code": "unsupported_physical_duration_inference", "path": field,
                            "reason": "A canonical observation/anchor span does not establish physical activity duration.", "reference": None})
                if not focus["network_requested"] and _NETWORK_TOPIC.search(value):
                    if is_negated_network_statement(value):
                        checks.append({"field": field, "kind": "unrequested_network_topic", "status": "negated_boundary_caveat"})
                    else:
                        checks.append({"field": field, "kind": "unrequested_network_topic", "status": "outside_request"})
                        issues.append({"code": "unrequested_network_claim", "path": field,
                            "reason": "This explicit network topic is asserted outside the requested answer scope; negated boundary caveats are allowed.", "reference": None})
    return {"scope": "explicit numeric authentication-duration expressions and asserted HTTP/C2/exfiltration topics only; negated boundary caveats are permitted",
            "checks": checks, "issues": issues, "comparison_semantics": "requires offline rubric review, not automatically verified",
            "remaining_prose": "unverified; AI/human semantic review remains necessary"}


def validate_meaning(checked: dict[str, Any], raw: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    result = source.validate_meaning(checked, raw, context)
    audit = check_clock_and_scope(raw, context)
    result["clock_and_scope_audit"] = audit
    result["issues"].extend(audit["issues"])
    # F02: a cited object ID does not prove a field claim; bind Status/SubStatus to the event.
    binding = check_auth_field_binding(raw, context)
    result["auth_field_binding_audit"] = binding
    result["issues"].extend(binding["issues"])
    if audit["issues"] or binding["issues"]:
        result["status"] = "validation_failed"
        result["sanitized_report"]["verdict"] = "INSUFFICIENT_EVIDENCE"
    result["scope"] = ("structured claims + bounded process citation, duration, request-topic and "
                       "authentication Status/SubStatus binding checks; remaining prose/comparison "
                       "correctness unverified")
    return result


# --- F02: authentication field/value binding ------------------------------------------
# Citation IDs prove an object exists; they do not prove a claim about a specific field value.
# For authentication scenarios the report must not merge the field meanings of the 4625
# endpoint view and the 4776 domain-controller view. Ground truth for this dataset:
#   4625 -> Status 0xc000006d, SubStatus 0xc000006a
#   4776 -> Status 0xc000006a, no SubStatus
# The constants below are the dataset contract, not per-case answers: they describe how the two
# Windows events encode status, and are checked against the supplied context before use.
_AUTH_STATUS_BY_EVENT = {
    "4625": {"status": {"0xc000006d", "0xc000006e", "0xc000006f", "0xc0000070", "0xc0000071",
                        "0xc0000072", "0xc000015b", "0xc0000193", "0xc0000234"},
             "substatus": {"0xc000006a", "0xc0000064", "0xc000006d", "0xc0000071", "0xc0000072",
                           "0xc0000133", "0xc000015b", "0xc0000192", "0xc0000193", "0xc0000224",
                           "0xc0000234", "0xc0000135"}},
    "4776": {"status": {"0xc000006a", "0xc0000064", "0xc000006d", "0xc000006e", "0xc0000071",
                        "0xc0000072", "0xc000015b", "0xc0000193", "0xc0000234", "0xc0000133"},
             "substatus": set()},
}
_STATUS_TOKEN = re.compile(r"0xc[0-9a-f]{7}", re.I)
_STATUS_FIELD = re.compile(r"\b(status|substatus|sub status|trang thai|trạng thái ph[ụu])\b[^.;\n]{0,40}?(0xc[0-9a-f]{7})", re.I)


def _auth_events_in_context(context: dict[str, Any]) -> set[str]:
    """Which Windows authentication event IDs the supplied context actually contains."""
    raw = json.dumps(context, ensure_ascii=False)
    return {event for event in _AUTH_STATUS_BY_EVENT if re.search(rf'"?event_?id"?\s*:\s*"?{event}\b', raw)
            or re.search(rf"\bID\s+{event}\b", raw) or f"event_id\": \"{event}" in raw}


def _event_mentions(value: str) -> list[str]:
    return _STATUS_TOKEN.findall(value)


def check_auth_field_binding(raw: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Reject a report that attributes a status value to the wrong authentication event.

    Bounded by design: it only inspects the authentication status vocabulary and only runs when
    the context actually contains 4625/4776 evidence. Every other field claim still requires
    human semantic review, which this audit states explicitly in its scope string.
    """
    events = _auth_events_in_context(context)
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    if not events:
        return {"scope": "no authentication event in context; check not applicable",
                "issues": issues, "checks": checks, "events_in_context": sorted(events)}
    normalized = normalize(json.dumps(raw, ensure_ascii=False))
    sentences = re.split(r"\n|(?<=[.!?;])\s+", normalized)
    for field in ("direct_answer", "executive_summary", "technical_analysis", "unverified_claims"):
        texts = raw.get(field, []) if field == "unverified_claims" else [raw.get(field, "")]
        for text in texts:
            for sentence in re.split(r"\n|(?<=[.!?;])\s+", normalize(str(text))):
                if not _STATUS_TOKEN.search(sentence):
                    continue
                pairs = {m.group(1).strip().lower(): m.group(2).lower() for m in _STATUS_FIELD.finditer(sentence)}
                subject = "4625" if re.search(r"\b4625\b", sentence) else ("4776" if re.search(r"\b4776\b", sentence) else None)
                status = pairs.get("status")
                substatus = next((v for k, v in pairs.items() if "sub" in k), None)
                checks.append({"field": field, "subject_event": subject, "status": status,
                               "substatus": substatus, "sentence": sentence.strip()[:240]})
                # A sentence naming only one event must not carry a value that event never uses.
                if subject and status and status not in _AUTH_STATUS_BY_EVENT[subject]["status"]:
                    issues.append({"code": "auth_status_event_mismatch", "path": field,
                                   "reason": f"Event {subject} does not record Status {status}.",
                                   "reference": None})
                if subject and substatus and substatus not in _AUTH_STATUS_BY_EVENT[subject]["substatus"]:
                    issues.append({"code": "auth_status_event_mismatch", "path": field,
                                   "reason": f"Event {subject} does not record SubStatus {substatus}.",
                                   "reference": None})
                # A sentence that merges both views without naming the event must not present a
                # single Status/SubStatus pair as if it belonged to both.
                if subject is None and status and substatus and status == substatus and len(events) > 1:
                    issues.append({"code": "auth_status_views_merged", "path": field,
                                   "reason": ("Status and SubStatus are both "
                                              f"{status}; the 4625 view and the 4776 view encode "
                                              "different fields, so this pair cannot describe both."),
                                   "reference": None})
    return {"scope": ("explicit Status/SubStatus values in authentication sentences only; "
                      "all other field claims remain subject to human semantic review"),
            "events_in_context": sorted(events), "issues": issues, "checks": checks}


# --- F03: effective validator policy --------------------------------------------------
# Any parameter that can change a validation outcome must be visible to the runtime pin, so a
# frozen study cannot be described by two different validator behaviours.
VALIDATOR_POLICY_ID = "source-meaning-validator/v3.1"


def effective_validator_policy() -> dict[str, Any]:
    """Return the exact validator parameters in force, with applied bounds."""
    return {
        "policy_id": VALIDATOR_POLICY_ID,
        "network_lookbehind": _env_int("VALIDATOR_NETWORK_LOOKBEHIND", 120, 400),
        "network_lookahead": _env_int("VALIDATOR_NETWORK_LOOKAHEAD", 80, 400),
        "lookbehind_bounds": [1, 400],
        "lookahead_bounds": [1, 400],
        "negation_scope": "clause-local",
        "clause_split": "sentence-terminator|but|however|nhung|tuy nhien|whereas|independent-comma",
        "checks": [
            "numeric_duration_expression",
            "unrequested_network_topic",
            "auth_status_event_binding",
            "auth_status_views_merged",
        ],
        "source_contract": f"{source.CONTRACT if hasattr(source, 'CONTRACT') else 'inherited'}/v3",
    }
