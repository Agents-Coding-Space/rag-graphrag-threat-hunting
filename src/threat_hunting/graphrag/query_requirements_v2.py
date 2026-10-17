"""Clause-local EN/VI evidence requests with original query role traces.

This separate experimental contract preserves the FIX2 parser and its replay.
The parser consumes public language vocabulary and source scope only. It never
uses available evidence to repair a request or makes a security conclusion.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import re
from typing import Any
import unicodedata

from . import query_requirements as legacy


QUERY_REQUIREMENTS_SCHEMA_VERSION = "query-requirements/v2"
QueryRequirementsError = legacy.QueryRequirementsError
_SPAN_ROLES = {
    "request", "subject", "action", "object", "parent", "child", "target",
    "requested_field", "context",
}
_REQUEST_START = (
    r"(?:also\s+)?(?:tell|explain|describe|show|identify|list|give|provide|what|"
    r"which|who|why|how|when|where|does|did|is|are|can|cho|hay|neu|giai|mo|"
    r"liet|xac|cai|ai|tai|o|co|can)\b"
)
_CLAUSE_SPLIT = re.compile(
    r"[;?\n]+|\s+(?:and|va)\s+(?=" + _REQUEST_START
    + r"|(?:the\s+)?(?:launch command|command line|commandline|output|completion|service state|"
    r"download url|url|endpoint|source references|review limitations|analysis status|"
    r"dong lenh|cau lenh|ket qua|dau ra|gioi han|trang thai)\b)",
)
_REVIEW_FACETS = {
    "timestamp": ["timestamp", "timecreated", "utctime", "timezone", "thoi gian", "mui gio"],
    "completion": ["completion", "output", "cmdlet", "service state", "hoan tat", "hoan thanh", "ket qua", "trang thai dich vu"],
    "negative_scan": ["negative scan", "absence", "globally absent", "full dataset", "toan bo dataset", "toan tep", "vang mat"],
    "candidate_status": ["candidate", "mitre", "technique", "needs_review", "ky thuat"],
    "core_boundaries": ["conhost", "deletion", "clearing", "outside", "ngoai", "xoa tep", "xoa log"],
    "scope": ["scope", "pham vi", "evidence groups", "nhom bang chung"],
    "review_status": ["analysis status", "review status", "trang thai phan tich", "trang thai review"],
}


def _fold_map(query: str) -> tuple[str, list[int]]:
    chars, positions = [], []
    for index, char in enumerate(query):
        for part in unicodedata.normalize("NFKD", char.lower().replace("đ", "d")):
            if not unicodedata.combining(part):
                chars.append(part)
                positions.append(index)
    return "".join(chars), positions


def _phrase(text: str, phrases: list[str]) -> re.Match[str] | None:
    candidates = [
        match for phrase in phrases
        if (match := re.search(r"(?<![a-z0-9_])" + re.escape(legacy._fold(phrase)) + r"(?![a-z0-9_])", text))
    ]
    return min(candidates, key=lambda match: (match.start(), -len(match.group()))) if candidates else None


def _clauses(text: str, vocabulary: Mapping[str, Any]) -> list[tuple[int, int, str]]:
    """Partition flat requests and explicitly marked contextual chain phrases."""
    ranges, start = [], 0
    for match in _CLAUSE_SPLIT.finditer(text):
        ranges.append((start, match.start()))
        start = match.end()
    ranges.append((start, len(text)))
    result = []
    for start, end in ranges:
        while start < end and text[start].isspace():
            start += 1
        while end > start and text[end - 1].isspace():
            end -= 1
        if start == end:
            continue
        local = text[start:end]
        # A marked chain preface/suffix is background only when the main clause
        # asks a distinct field. Unmarked named relationships are never erased.
        field_request = legacy._contains(local, vocabulary["concepts"]["network"] + vocabulary["concepts"]["command"])
        marker = re.search(r"\b(?:in|within|inside|trong)\s+(?:(?:the|observed)\s+)?(?:chuoi|cay tien trinh|(?:(?:[a-z0-9_.-]+|process)\s+){0,3}chain)\b", local)
        if field_request and marker:
            marker_start = start + marker.start()
            comma = text.find(",", marker_start, end)
            if marker.start() == 0 and comma != -1:
                result.append((start, comma, "background"))
                result.append((comma + 1, end, "request"))
                continue
            if marker.start() == 0:
                question = re.search(r"\b(?:which|what|where|how|url nao|endpoint nao|dia chi nao|cau lenh nao|dong lenh nao)\b", local[marker.end():])
                if question:
                    boundary = start + marker.end() + question.start()
                    result.append((start, boundary, "background"))
                    result.append((boundary, end, "request"))
                    continue
            elif marker.start() > 0:
                result.append((start, marker_start, "request"))
                result.append((marker_start, end, "background"))
                continue
        result.append((start, end, "request"))
    return [(start, end, role) for start, end, role in result if text[start:end].strip()]


def _relationships(text: str, mentions: list[tuple[int, int, str]]) -> tuple[list[dict[str, Any]], bool, str]:
    names = list(dict.fromkeys(name for _, _, name in mentions))
    if "->" in text or "→" in text:
        links, unresolved = [], False
        for left, right in zip(mentions, mentions[1:]):
            if re.search(r"(?:->|→)", text[left[1]:right[0]]):
                links.append({"parent": left[2], "child": right[2], "chain": False})
            else:
                unresolved = True
        return links or [{"parent": None, "child": None, "chain": True}], unresolved or not links, "explicit_directed_process_links"
    if len(names) == 1:
        name = names[0]
        start, end, _ = mentions[0]
        before, after = text[:start], text[end:]
        ancestor_request = legacy._contains(text, ["chain", "chuoi", "process tree", "cay tien trinh"]) and (
            legacy._contains(before, ["led to", "leading to", "leads to", "ending in", "resulted in", "to", "dan den", "dan toi", "ket thuc o", "toi", "den"])
            or legacy._contains(text, ["ancestors", "ancestor chain", "trace back", "truy nguoc", "to tien"])
        )
        if ancestor_request:
            return [{"parent": None, "child": name, "chain": True}], False, "target_only_ancestor_request"
        if legacy._contains(before, ["parent of", "spawned", "spawns", "cha cua", "sinh ra", "sinh", "khoi chay"]):
            return [{"parent": None, "child": name, "chain": False}], False, "directed_process_role_request"
        if legacy._contains(before, ["child of", "child process of", "spawned by", "con cua"]) or legacy._contains(after, ["child", "spawn", "spawned", "spawns", "tien trinh con"]):
            return [{"parent": name, "child": None, "chain": False}], False, "directed_process_role_request"
    if len(names) == 2:
        left = mentions[0]
        right = next(item for item in mentions if item[2] != left[2])
        between = text[left[1]:right[0]]
        if legacy._contains(between, ["child of", "spawned by", "launched by", "la con cua", "duoc sinh boi", "duoc tao boi", "duoc khoi chay boi"]):
            return [{"parent": right[2], "child": left[2], "chain": False}], False, "directed_process_role_request"
        creation = legacy._contains(text, ["process creation", "process-creation", "tao tien trinh", "khoi tao tien trinh"])
        if legacy._contains(between, ["spawn", "spawned", "spawns", "launched", "launches", "parent of", "sinh", "sinh ra", "tao", "cha cua"]):
            return [{"parent": left[2], "child": right[2], "chain": False}], False, "directed_process_role_request"
        if creation and re.search(r"\b(?:to|sang|toi|den)\b", between):
            return [{"parent": left[2], "child": right[2], "chain": False}], False, "directed_creation_endpoints_request"
    params, unresolved = legacy._relationship_parameters(text, mentions)
    return params, unresolved, "process_relationship_request"


def _bound_process(text: str, mentions: list[tuple[int, int, str]], action: str) -> tuple[str | None, bool]:
    names = list(dict.fromkeys(name for _, _, name in mentions))
    if len(names) == 1:
        return names[0], False
    if not names:
        return None, False
    # Passive launches bind the launched object, not a named launcher/context.
    if action == "launch":
        for start, end, name in mentions:
            if re.search(r"\b(?:command(?:\s+line)?|commandline|dong lenh|cau lenh|lenh)\s+(?:(?:for|of|cua)\s+)?$", text[:start]):
                return name, False
        for start, end, name in mentions:
            if re.match(r"\s+(?:was|is|were|duoc|da duoc)\s+(?:launched|started|khoi chay|tao)\b", text[end:]):
                return name, False
            if re.match(r"\s+(?:launched|started)\s+(?:with|using|by)\b", text[end:]):
                return name, False
        for left, right in zip(mentions, mentions[1:]):
            if re.search(r"\b(?:launched|launches|spawned|spawns|khoi chay|sinh ra)\b", text[left[1]:right[0]]):
                return right[2], False
    if action in {"download", "connect", "network"}:
        words = {
            "download": r"download(?:ed|s|ing)?|tai xuong|tai payload|tai tep|tai file",
            "connect": r"connect(?:ed|s|ion)?|ket noi",
            "network": r"connect(?:ed|s|ion)?|ket noi|download(?:ed|s|ing)?|tai xuong",
        }[action]
        bindings = []
        for start, end, name in mentions:
            after = text[end:]
            if re.match(r"\s+(?:(?:did|does|has|had|da|dang)\s+)?(?:" + words + r")\b", after):
                bindings.append(name)
            # Endpoint ... downloaded by A / URL do A tải xuống.
            before = text[:start]
            if re.search(r"\b(?:downloaded|connected)\s+by\s*$|\b(?:do|boi)\s*$", before) and legacy._contains(text, ["download", "downloaded", "connect", "connected", "tai xuong", "ket noi"]):
                bindings.append(name)
        bindings = list(dict.fromkeys(bindings))
        if len(bindings) == 1:
            return bindings[0], False
    return None, True


def analyze_query_requirements_v2(
    query: str, *, vocabulary: Mapping[str, Any] | None = None,
    scope_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Parse the declared clause/role subset without runtime evidence or IO."""
    if not isinstance(query, str) or not query.strip():
        raise QueryRequirementsError("query must be a nonempty string")
    if scope_metadata is not None and not isinstance(scope_metadata, Mapping):
        raise QueryRequirementsError("scope_metadata must be an object")
    metadata = None if scope_metadata is None else legacy._json_copy(dict(scope_metadata), "scope_metadata")
    if metadata is not None and set(metadata) - {"platforms", "mechanisms"}:
        raise QueryRequirementsError("scope_metadata has unsupported fields")
    lexicon = legacy._vocabulary(vocabulary)
    text, positions = _fold_map(query)
    scope, ambiguous = legacy._scope(text, lexicon, metadata)
    reasons: list[str] = []
    requirements: list[dict[str, Any]] = []
    roles: dict[str, set[str]] = {}
    clauses: list[dict[str, Any]] = []

    def source_span(clause: dict[str, Any], start: int, end: int, role: str) -> dict[str, Any]:
        original_start, original_end = positions[start], positions[end - 1] + 1
        while original_end < len(query) and unicodedata.combining(query[original_end]):
            original_end += 1
        return {"clause_id": clause["clause_id"], "start": original_start, "end": original_end,
                "text": query[original_start:original_end], "role": role}

    for start, end, clause_role in _clauses(text, lexicon):
        while start < end and text[start].isspace():
            start += 1
        while end > start and text[end - 1].isspace():
            end -= 1
        clause = {"clause_id": f"c{len(clauses) + 1}", "role": clause_role}
        clause_span = source_span(clause, start, end, "request")
        clause.update({key: clause_span[key] for key in ("start", "end", "text")})
        clauses.append(clause)
        local = text[start:end]
        mentions = legacy._process_mentions(local, lexicon["entity_aliases"])
        for _, _, name in mentions:
            roles.setdefault(name, set())
        if clause_role == "background":
            continue
        concepts = {key: legacy._contains(local, phrases) for key, phrases in lexicon["concepts"].items()}
        concepts["command"] |= bool(re.search(r"\b(?:what|which|show|give|provide)\s+(?:the\s+)?commands?\b", local))
        clause_requirement_start = len(requirements)

        def add(kind: str, params: dict[str, Any], unresolved: bool = False,
                reason: str | None = None, action_phrases: list[str] | None = None) -> None:
            nonlocal ambiguous
            ambiguous |= unresolved
            spans = [source_span(clause, start, end, "request")]
            parameter_roles = {"process": "subject", "actor": "subject", "parent": "parent", "child": "child"}
            for parameter, role in parameter_roles.items():
                name = params.get(parameter)
                if name is None:
                    continue
                roles.setdefault(name, set()).add("actor" if parameter == "actor" else role)
                for left, right, actual in mentions:
                    if actual == name:
                        trace_role = "target" if kind == "process_relationship" and params.get("chain") and params.get("parent") is None and parameter == "child" else role
                        spans.append(source_span(clause, start + left, start + right, trace_role))
                        if trace_role == "target":
                            spans.append(source_span(clause, start + left, start + right, "object"))
            phrases = action_phrases or lexicon["concepts"].get({
                "process_relationship": "relationship", "launch_command": "command",
                "command_completion": "completion", "service_state": "service_state",
                "network_url": params.get("action", "network"), "evidence_provenance": "provenance",
                "review_limitations": "limitations", "technique_assessment": "technique",
            }[kind], [])
            if (match := _phrase(local, phrases)) is not None:
                spans.append(source_span(clause, start + match.start(), start + match.end(), "action"))
            field_phrases = {
                "launch_command": ["command line", "commandline", "command-line", "launch command", "cau lenh", "dong lenh", "lenh nao", "lenh gi"],
                "network_url": ["url", "uri"] if params.get("field") == "url" else ["endpoint", "ip address", "dia chi ip", "dich mang"],
                "review_limitations": [phrase for facet in params.get("facets", []) for phrase in _REVIEW_FACETS.get(facet, [])],
            }.get(kind, [])
            if (match := _phrase(local, field_phrases)) is not None:
                spans.append(source_span(clause, start + match.start(), start + match.end(), "requested_field"))
            requirements.append({"requirement_id": f"r{len(requirements) + 1}", "kind": kind,
                                 "mandatory": True, "parameters": params,
                                 "analysis_status": "ambiguous" if unresolved else "supported",
                                 "reason_codes": [reason or ("unresolved_entity_roles" if unresolved else f"recognized_{kind}_concept")],
                                 "source_spans": spans})

        human_approval = legacy._contains(local, ["reviewer", "approval timestamp", "approval time", "human approval", "human review status", "nguoi duyet", "thoi diem phe duyet", "phe duyet boi ai"])
        if human_approval:
            reasons.append("human_approval_metadata_outside_runtime_contract")
            ambiguous = True
            continue
        if not mentions and legacy._contains(local, ["it", "its", "they", "their", "no", "cua no"]):
            ambiguous = True
            reasons.append("unresolved_cross_clause_pronoun")
        grounded_follow_up = legacy._contains(local, ["check next", "check further", "investigate next", "investigate further", "further checks", "kiem tra them", "dieu tra them", "can kiem tra", "can xac minh"]) and legacy._contains(text, ["review", "evidence", "scope", "limitation", "bang chung", "pham vi", "gioi han", "phan tich"])
        evidence_limits = concepts["limitations"] or grounded_follow_up
        review_status = legacy._contains(local, _REVIEW_FACETS["review_status"])
        limiting_negative = evidence_limits and legacy._contains(local, ["not established", "not proven", "cannot conclude", "chua chung minh", "khong chung minh", "chua duoc chung minh"])
        relation_requested = concepts["relationship"] or "->" in local or "→" in local or legacy._contains(local, ["process creation relationship", "process-creation relationship", "quan he tao tien trinh"])
        # Command launch and URL questions do not implicitly request every
        # relationship mentioned to locate the actor. Explicit independent
        # relationship/evidence requests still produce mandatory requirements.
        if relation_requested and not concepts["network"] and not concepts["command"] and not evidence_limits:
            params_list, unresolved, relation_reason = _relationships(local, mentions)
            for params in params_list:
                add("process_relationship", params, unresolved, relation_reason)
        if concepts["command"] and not evidence_limits:
            process, unresolved = _bound_process(local, mentions, "launch")
            add("launch_command", {"process": process}, unresolved)
        if concepts["completion"] and not evidence_limits:
            process, unresolved = _bound_process(local, mentions, "completion")
            add("command_completion", {"process": process}, unresolved)
        if concepts["service_state"] and not evidence_limits:
            process, unresolved = _bound_process(local, mentions, "state")
            add("service_state", {"process": process}, unresolved)
        if concepts["network"] and not evidence_limits:
            field = "url" if legacy._contains(local, ["url", "uri", "download", "downloaded", "tai xuong"]) else "endpoint"
            actions = [action for action in ("download", "connect") if concepts[action]] or ["network"]
            for action in actions:
                process, unresolved = _bound_process(local, mentions, action)
                add("network_url", {"actor": process, "action": action, "field": field}, unresolved)
        if concepts["provenance"] and not evidence_limits:
            process, unresolved = _bound_process(local, mentions, "provenance")
            relations = [req for req in requirements[clause_requirement_start:] if req["kind"] == "process_relationship"]
            if relations and not unresolved:
                process = relations[-1]["parameters"].get("child") or relations[-1]["parameters"].get("parent")
            elif relations:
                # The requested raw observation is the creation of the child.
                process = relations[-1]["parameters"].get("child")
                unresolved = process is None and bool(mentions)
            add("evidence_provenance", {"process": process}, unresolved)
        if evidence_limits or review_status:
            facets = [facet for facet, phrases in _REVIEW_FACETS.items() if legacy._contains(local, phrases)]
            if evidence_limits:
                facets = [facet for facet in facets if facet != "scope"] or ["all"]
                if legacy._contains(local, ["all", "every", "complete list", "tat ca", "toan bo", "day du"]) or grounded_follow_up and not facets:
                    facets = ["all"] + (["review_status"] if review_status else [])
            add("review_limitations", {"facets": facets}, reason="requested_follow_up_review" if grounded_follow_up else "requested_review_scope_or_limits")
        technique_ids = list(dict.fromkeys(match.upper() for match in re.findall(r"\bt\d{4}(?:\.\d{3})?\b", local)))
        if (concepts["technique"] or technique_ids) and not evidence_limits:
            proof = legacy._contains(local, ["prove", "proof", "establish", "chung minh"])
            confirmed = legacy._contains(local, ["confirmed", "confirmation", "xac nhan", "chac chan"])
            for technique_id in technique_ids or [None]:
                add("technique_assessment", {"technique_id": technique_id, "certainty": "confirmed" if proof and confirmed else "assessment"})

        negation = re.sub(r"\b(?:khong|chua)\s*[?!.]*\s*$", "", local)
        negation = re.sub(r"\b(?:not|exclude|excluding|ignore|khong xet|loai tru|bo qua)\s+(?:linux|windows|unix|posix|macos)\b", "", negation)
        if not limiting_negative and re.search(r"\b(?:not|never|without|isn't|isnt|didn't|didnt|khong|chua|chang)\b", negation):
            ambiguous = True
            reasons.append("negation_scope_not_resolved")
            if scope["status"] == "mismatch":
                scope["status"], scope["reason_codes"] = "ambiguous", ["negated_scope_unresolved"]
        if legacy._contains(local, ["compare", "comparison", "versus", "vs", "unlike", "rather than", "so sanh", "khac biet", "doi chieu"]):
            ambiguous = True
            reasons.append("comparison_predicate_not_resolved")
        if legacy._contains(local, ["attacker", "threat actor", "attribution", "campaign", "malware family", "country of origin", "ke tan cong", "nhom tan cong", "chien dich", "ho ma doc", "quoc gia"]):
            ambiguous = True
            reasons.append("unsupported_attribution_or_identity_requirement")
        uncovered = legacy._uncovered_claim_reasons(local, {**concepts, "limitations": evidence_limits})
        if concepts["provenance"] and mentions and not any(concepts[key] for key in ("relationship", "command", "completion", "service_state", "network", "technique")) and not evidence_limits:
            tail = re.sub(r"\b(?:khong|chua|nao|what|which)\s*$", "", local[mentions[-1][1]:]).strip(" .!?")
            if tail and not re.match(r"(?:from|in|with|source|event|record|raw|log|tu|trong|nguon|ban ghi)\b", tail):
                uncovered.append("requested_assertion_predicate_not_supported")
        # The v2 directed creation grammar is a declared supported predicate.
        if any(req["kind"] == "process_relationship" and req["analysis_status"] == "supported" for req in requirements[clause_requirement_start:]):
            uncovered = [reason for reason in uncovered if reason != "requested_assertion_predicate_not_supported"]
        if uncovered:
            ambiguous = True
            reasons.extend(uncovered)
        if len(requirements) == clause_requirement_start:
            exclusion = re.fullmatch(r"(?:not|exclude|excluding|ignore|khong xet|loai tru|bo qua)\s+(?:linux|windows|unix|posix|macos)(?:\s+cron)?[.!]*", local)
            if exclusion:
                clause["role"] = "background"
            else:
                reasons.append("unrecognized_requested_clause")
                ambiguous |= len(clauses) > 1 or bool(requirements)

    if scope["status"] == "ambiguous":
        ambiguous = True
        reasons.append("scope_analysis_ambiguous")
    if "unrecognized_requested_clause" in reasons and requirements:
        ambiguous = True
    status = "ambiguous" if ambiguous else "supported" if requirements else "unsupported"
    reasons.append("recognized_clause_local_requirements" if requirements else "unsupported_information_request")
    document = {
        "schema_version": QUERY_REQUIREMENTS_SCHEMA_VERSION, "query": query,
        "analysis_status": status, "scope": scope,
        "entities": [{"name": name, "roles": sorted(value) or ["unspecified"]} for name, value in roles.items()],
        "requirements": requirements, "reason_codes": list(dict.fromkeys(reasons)),
        "limitations": [
            "Deterministic clause-local EN/VI subset; complex negation/comparison and unresolved roles remain explicit.",
            "Requested evidence is independent of evidence availability; no completion, absence or security conclusion is inferred.",
            "Follow-up review requirements identify evidence limits to check, not completed investigation or generated advice.",
        ],
        "clauses": clauses,
    }
    return validate_query_requirements_document_v2(document)


def requirements_v1_projection(document: object) -> dict[str, Any]:
    """Project selection-compatible parameters, preserving the original v2 elsewhere.

    ``review_status`` selects scenario/scope metadata in old enrichment only.
    This helper does not assert v1 verification is semantically equivalent.
    """
    value = validate_query_requirements_document_v2(document)
    return _projection(value)


def _projection(value: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(value)
    result["schema_version"] = legacy.QUERY_REQUIREMENTS_SCHEMA_VERSION
    result.pop("clauses")
    for requirement in result["requirements"]:
        requirement.pop("source_spans")
        if requirement["kind"] == "review_limitations":
            requirement["parameters"]["facets"] = list(dict.fromkeys(
                "scope" if facet == "review_status" else facet for facet in requirement["parameters"]["facets"]))
    return result


def validate_query_requirements_document_v2(document: object) -> dict[str, Any]:
    """Validate finite strict v2 fields, core kinds and exact original spans."""
    value = legacy._json_copy(document, "requirements")
    fields = {"schema_version", "query", "analysis_status", "scope", "entities", "requirements", "reason_codes", "limitations", "clauses"}
    if not isinstance(value, dict) or set(value) != fields or value.get("schema_version") != QUERY_REQUIREMENTS_SCHEMA_VERSION:
        raise QueryRequirementsError("requirements v2 fields/schema are invalid")
    if not isinstance(value["query"], str) or not value["query"].strip() or not isinstance(value["clauses"], list) or not value["clauses"]:
        raise QueryRequirementsError("requirements v2 query/clauses are invalid")
    query = value["query"]
    clauses: dict[str, dict[str, Any]] = {}

    def check_span(span: object, *, source: bool) -> dict[str, Any]:
        fields = {"clause_id", "start", "end", "text", "role"}
        if not isinstance(span, dict) or set(span) != fields:
            raise QueryRequirementsError("requirements v2 span fields are invalid")
        left, right = span["start"], span["end"]
        if type(left) is not int or type(right) is not int or not 0 <= left < right <= len(query) or span["text"] != query[left:right]:
            raise QueryRequirementsError("requirements v2 span must resolve to original query text")
        roles = _SPAN_ROLES if source else {"request", "background"}
        if not isinstance(span["role"], str) or span["role"] not in roles or not isinstance(span["clause_id"], str) or not re.fullmatch(r"c[1-9]\d*", span["clause_id"]):
            raise QueryRequirementsError("requirements v2 span role/clause is invalid")
        return span

    previous_end = -1
    for clause in value["clauses"]:
        item = check_span(clause, source=False)
        if item["clause_id"] in clauses or item["start"] < previous_end:
            raise QueryRequirementsError("requirements v2 clauses must be unique and ordered")
        clauses[item["clause_id"]] = item
        previous_end = item["end"]
    if not isinstance(value["requirements"], list):
        raise QueryRequirementsError("requirements v2 requirements must be an array")
    for requirement in value["requirements"]:
        expected = {"requirement_id", "kind", "mandatory", "parameters", "analysis_status", "reason_codes", "source_spans"}
        if not isinstance(requirement, dict) or set(requirement) != expected or not isinstance(requirement["source_spans"], list) or not requirement["source_spans"]:
            raise QueryRequirementsError("requirements v2 requirement fields/spans are invalid")
        for span in requirement["source_spans"]:
            item = check_span(span, source=True)
            clause = clauses.get(item["clause_id"])
            if clause is None or clause["role"] != "request" or not clause["start"] <= item["start"] < item["end"] <= clause["end"]:
                raise QueryRequirementsError("requirement span must belong to a request clause")
        params = requirement["parameters"]
        if requirement["kind"] == "review_limitations" and isinstance(params, dict) and isinstance(params.get("facets"), list):
            if any(not isinstance(facet, str) or facet not in {*legacy.REVIEW_LIMITATION_FACETS, "review_status"} for facet in params["facets"]):
                raise QueryRequirementsError("requirements v2 limitation facet is unsupported")
    legacy.validate_query_requirements_document(_projection(value))
    return value


__all__ = (
    "QUERY_REQUIREMENTS_SCHEMA_VERSION", "QueryRequirementsError",
    "analyze_query_requirements_v2", "validate_query_requirements_document_v2",
    "requirements_v1_projection",
)
