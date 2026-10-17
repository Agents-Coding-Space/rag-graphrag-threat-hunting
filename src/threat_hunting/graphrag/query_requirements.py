"""Parse a declared EN/VI query subset without evaluation data or model calls.

This is a conservative concept-and-role parser, not general natural language
understanding. A parsed requirement describes requested evidence, never an
assertion that the evidence exists. Unknown semantics remain explicit. Public
vocabulary and source scope are the only optional inputs; this module has no IO.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import json
import re
from typing import Any
import unicodedata


QUERY_REQUIREMENTS_SCHEMA_VERSION = "query-requirements/v1"
REQUIREMENT_KINDS = (
    "process_relationship", "launch_command", "command_completion", "service_state",
    "network_url", "evidence_provenance", "review_limitations", "technique_assessment",
)
REVIEW_LIMITATION_FACETS = (
    "all", "scope", "timestamp", "completion", "negative_scan", "candidate_status",
    "core_boundaries",
)

# These are reusable language concepts, not query templates or a process allowlist.
DEFAULT_QUERY_VOCABULARY: dict[str, Any] = {
    "entity_aliases": {"cmd": "cmd.exe", "mshta": "mshta.exe", "powershell": "powershell.exe"},
    "platforms": {
        "windows": ["windows", "win32", "win64"],
        "linux": ["linux", "gnu/linux"],
        "unix": ["unix", "posix"],
        "macos": ["macos", "mac os", "darwin"],
    },
    "mechanisms": {"cron": ["cron", "crontab", "cronjob", "cron job"]},
    "concepts": {
        "relationship": ["parent", "child", "spawn", "spawned", "spawns", "chain", "process tree", "process relationship", "parent-child", "quan he", "chuoi", "tien trinh cha", "tien trinh con", "sinh ra", "sinh", "tao tien trinh", "proxy execution"],
        "command": ["command line", "command lines", "commandline", "commandlines", "launch command", "command-line", "cau lenh", "dong lenh", "lenh khoi chay", "lenh nao", "lenh gi"],
        "completion": ["successful", "successfully", "success", "completion", "completed", "complete", "output", "result", "thanh cong", "hoan tat", "hoan thanh", "dau ra", "ket qua"],
        "service_state": ["service state", "service status", "service running", "service stopped", "trang thai dich vu", "dich vu dang chay", "dich vu da dung"],
        "network": ["url", "uri", "endpoint", "network", "connection", "connect", "connected", "destination", "ip address", "download", "downloaded", "tai xuong", "ket noi", "dia chi ip", "dich mang"],
        "download": ["download", "downloaded", "downloading", "tai xuong", "tai payload", "tai tep", "tai file"],
        "connect": ["connect", "connected", "connection", "ket noi"],
        "provenance": ["evidence", "provenance", "raw", "record", "records", "event id", "source reference", "source references", "source log", "bang chung", "ban ghi", "nguon", "tham chieu", "su kien"],
        "limitations": ["limitation", "limitations", "scope", "caveat", "caveats", "boundary", "boundaries", "review limit", "review limits", "gioi han", "pham vi", "han che", "luu y"],
        "technique": ["technique", "techniques", "mitre", "attack mapping", "att&ck", "ky thuat", "anh xa", "candidate", "needs_review"],
    },
}


class QueryRequirementsError(ValueError):
    """Raised when public parser inputs or a requirements document are invalid."""


def _fold(value: str) -> str:
    return "".join(
        char for char in unicodedata.normalize("NFKD", value.lower().replace("đ", "d"))
        if not unicodedata.combining(char)
    )


def _contains(text: str, phrases: list[str]) -> bool:
    return any(re.search(r"(?<![a-z0-9_])" + re.escape(_fold(phrase)) + r"(?![a-z0-9_])", text) for phrase in phrases)


def _json_copy(value: object, label: str) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError, OverflowError) as error:
        raise QueryRequirementsError(f"{label} must contain finite JSON values") from error


def _vocabulary(value: Mapping[str, Any] | None) -> dict[str, Any]:
    result = deepcopy(DEFAULT_QUERY_VOCABULARY)
    if value is not None:
        if not isinstance(value, Mapping):
            raise QueryRequirementsError("vocabulary must be an object")
        supplied = _json_copy(dict(value), "vocabulary")
        if set(supplied) - set(result):
            raise QueryRequirementsError("vocabulary has unsupported fields")
        for group, entries in supplied.items():
            if not isinstance(entries, dict):
                raise QueryRequirementsError(f"vocabulary.{group} must be an object")
            result[group].update(entries)
    for group, entries in result.items():
        for key, item in entries.items():
            if not isinstance(key, str) or not key.strip():
                raise QueryRequirementsError(f"vocabulary.{group} keys must be nonempty strings")
            if group == "entity_aliases":
                if not isinstance(item, str) or not item.strip():
                    raise QueryRequirementsError("entity aliases must map to nonempty names")
            elif not isinstance(item, list) or not item or any(not isinstance(part, str) or not part.strip() for part in item):
                raise QueryRequirementsError(f"vocabulary.{group}.{key} must be nonempty phrases")
    return result


def _process_mentions(text: str, aliases: Mapping[str, str]) -> list[tuple[int, int, str]]:
    mentions = [(match.start(), match.end(), match.group().lower()) for match in re.finditer(r"(?<![a-z0-9_.-])[a-z0-9_-]+\.exe\b", text)]
    for alias, name in aliases.items():
        for match in re.finditer(r"(?<![a-z0-9_.-])" + re.escape(_fold(alias)) + r"(?![a-z0-9_.-])", text):
            if not any(start <= match.start() < end for start, end, _ in mentions):
                mentions.append((match.start(), match.end(), name.lower()))
    return sorted(mentions)


def _scope(text: str, vocabulary: dict[str, Any], metadata: Mapping[str, Any] | None) -> tuple[dict[str, Any], bool]:
    requested: list[str] = []
    excluded: list[str] = []
    for platform, phrases in vocabulary["platforms"].items():
        for phrase in phrases:
            for match in re.finditer(r"(?<![a-z0-9_.-])" + re.escape(_fold(phrase)) + r"(?![a-z0-9_.-])", text):
                prefix = text[max(0, match.start() - 48):match.start()]
                # Only direct exclusions have an unambiguous local scope.
                exclusion = re.search(r"(?:\bnot|\bexclude|\bexcluding|\bignore|\bkhong xet|\bloai tru|\bbo qua)\s*$", prefix)
                (excluded if exclusion else requested).append(platform)
    requested = sorted(set(requested))
    excluded = sorted(set(excluded))
    mechanisms: list[str] = []
    for mechanism, phrases in vocabulary["mechanisms"].items():
        for phrase in phrases:
            for match in re.finditer(r"(?<![a-z0-9_.-])" + re.escape(_fold(phrase)) + r"(?![a-z0-9_.-])", text):
                clause_prefix = re.split(r"[;,]", text[:match.start()])[-1]
                excluded_clause = any(
                    re.search(r"\b(?:not|exclude|excluding|ignore|khong xet|loai tru|bo qua)\s+" + re.escape(platform) + r"\b", clause_prefix)
                    for platform in excluded
                )
                if not excluded_clause:
                    mechanisms.append(mechanism)
    mechanisms = sorted(set(mechanisms))
    comparison = _contains(text, ["compare", "comparison", "versus", "vs", "unlike", "rather than", "so sanh", "khac biet", "doi chieu"])
    ambiguous = len(requested) > 1 or bool(set(requested) & set(excluded)) or (comparison and bool(requested or mechanisms))
    available = [] if metadata is None else metadata.get("platforms", [])
    available_mechanisms = [] if metadata is None else metadata.get("mechanisms", [])
    if not isinstance(available, list) or any(not isinstance(item, str) or not item for item in available):
        raise QueryRequirementsError("scope_metadata.platforms must be a string list")
    if not isinstance(available_mechanisms, list) or any(not isinstance(item, str) or not item for item in available_mechanisms):
        raise QueryRequirementsError("scope_metadata.mechanisms must be a string list")
    available = [_fold(item) for item in available]
    reasons: list[str] = []
    if ambiguous:
        status = "ambiguous"
        reasons.append("mixed_or_comparative_scope")
    elif requested and available and any(item not in available for item in requested):
        status = "mismatch"
        reasons.append("requested_platform_not_in_source")
    elif mechanisms and available_mechanisms and any(item not in available_mechanisms for item in mechanisms):
        status = "mismatch"
        reasons.append("requested_mechanism_not_in_source")
    elif requested and available:
        status = "in_scope"
        reasons.append("requested_platform_in_source")
    else:
        status = "unspecified"
        reasons.append("no_resolved_explicit_scope")
    return {
        "requested_platforms": requested, "excluded_platforms": excluded,
        "mechanisms": mechanisms, "comparison": comparison, "status": status,
        "reason_codes": reasons,
    }, ambiguous


def _relationship_parameters(text: str, mentions: list[tuple[int, int, str]]) -> tuple[list[dict[str, Any]], bool]:
    names = list(dict.fromkeys(name for _, _, name in mentions))
    if "->" in text or "→" in text:
        links = []
        unresolved = len(mentions) < 2
        for left, right in zip(mentions, mentions[1:]):
            between = text[left[1]:right[0]]
            if ("->" in between or "→" in between) and left[2] != right[2]:
                links.append({"parent": left[2], "child": right[2], "chain": False})
            else:
                unresolved = True
        return links or [{"parent": None, "child": None, "chain": True}], unresolved
    if len(names) == 2:
        left, right = mentions[0], next(item for item in mentions if item[2] != mentions[0][2])
        between = text[left[1]:right[0]]
        if _contains(between, ["child of", "spawned by", "la con cua", "duoc sinh boi", "duoc tao boi"]):
            return [{"parent": right[2], "child": left[2], "chain": False}], False
        if _contains(between, ["spawn", "spawned", "spawns", "launched", "launches", "parent of", "sinh", "sinh ra", "tao", "cha cua"]):
            return [{"parent": left[2], "child": right[2], "chain": False}], False
        # A request about the chain connecting named endpoints is not a directed
        # edge claim. Verification must establish an actual returned path.
        if _contains(text, ["chain", "chuoi", "process tree"]):
            return [{"parent": left[2], "child": right[2], "chain": True}], False
        return [{"parent": None, "child": None, "chain": False}], True
    if len(names) == 1:
        name = names[0]
        start, end, _ = mentions[0]
        before, after = text[:start], text[end:]
        if _contains(before, ["parent of", "spawned", "spawns", "cha cua", "sinh ra", "sinh"]):
            return [{"parent": None, "child": name, "chain": False}], False
        if _contains(before, ["child of", "child process of", "spawned by", "con cua"]) or _contains(after, ["child", "spawn", "spawned", "spawns", "tien trinh con"]):
            return [{"parent": name, "child": None, "chain": False}], False
        return [{"parent": None, "child": None, "chain": True}], True
    if len(names) > 2:
        # A wildcard path must not discard three named identity constraints.
        # Explicit arrows above are the only supported multi-edge grammar.
        return [{"parent": None, "child": None, "chain": True}], True
    process_anchor = _contains(text, [
        "process", "processes", "parent", "child", "parent-child", "proxy execution",
        "tien trinh", "quan he cha con",
    ])
    return [{"parent": None, "child": None, "chain": True}], not process_anchor


def _uncovered_claim_reasons(text: str, concepts: dict[str, bool]) -> list[str]:
    """Detect requested claims that broad evidence/chain nouns cannot satisfy.

    Assertion complement grammar identifies a requested predicate. Only declared
    evidence kinds may cover that predicate; an arbitrary action is not reduced
    to provenance merely because the request contains the word ``evidence``.
    These are language/capability concepts, not benchmark statements.
    """
    reasons: list[str] = []
    complement = re.search(
        r"\b(?:evidence\s+(?:that|of)|proof\s+(?:that|of)|show(?:s)?\s+that|"
        r"cho thay|chung minh rang|bang chung\s+(?:rang|ve viec))\b(?P<claim>.*)",
        text,
    )
    if complement:
        claim = complement.group("claim")
        # Source/record questions ask for provenance itself. Positive actions
        # need a supported relation, launch, network, completion or state kind.
        provenance_object = _contains(claim, [
            "raw event", "raw events", "source record", "source records", "event id",
            "source reference", "source references", "provenance", "ban ghi goc", "tham chieu nguon",
        ])
        supported_predicate = any(concepts[key] for key in (
            "command", "completion", "service_state", "network", "technique",
        )) or _contains(claim, [
            "spawn", "spawned", "spawns", "parent of", "child of", "launched",
            "launches", "spawned by", "sinh ra", "tao tien trinh", "cha cua", "con cua",
        ])
        if not provenance_object and not supported_predicate:
            reasons.append("requested_assertion_predicate_not_supported")
    conclusion_goal = _contains(text, [
        "conclude", "conclusion", "determine", "prove", "establish", "definitively",
        "khang dinh", "ket luan", "nhan dinh cuoi", "chung minh",
    ])
    security_outcome = _contains(text, [
        "malicious", "attack", "compromise", "compromised", "intent", "attribution",
        "tan cong", "ac y", "y do", "pha hoai",
    ])
    if conclusion_goal and security_outcome and not concepts["limitations"]:
        reasons.append("requested_security_conclusion_not_supported")
    return reasons


def analyze_query_requirements(
    query: str, *, vocabulary: Mapping[str, Any] | None = None,
    scope_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return evidence requirements for the documented deterministic subset.

    Vocabulary overrides merge public concept phrases/aliases. Source metadata
    may declare platforms and mechanisms; no observed/evaluation answers are
    consumed. Ambiguity is retained rather than resolved from available evidence.
    """
    if not isinstance(query, str) or not query.strip():
        raise QueryRequirementsError("query must be a nonempty string")
    if scope_metadata is not None and not isinstance(scope_metadata, Mapping):
        raise QueryRequirementsError("scope_metadata must be an object")
    metadata = None if scope_metadata is None else _json_copy(dict(scope_metadata), "scope_metadata")
    if metadata is not None and set(metadata) - {"platforms", "mechanisms"}:
        raise QueryRequirementsError("scope_metadata has unsupported fields")
    lexicon = _vocabulary(vocabulary)
    text = _fold(query)
    mentions = _process_mentions(text, lexicon["entity_aliases"])
    names = list(dict.fromkeys(name for _, _, name in mentions))
    concepts = {key: _contains(text, phrases) for key, phrases in lexicon["concepts"].items()}
    scope, ambiguous = _scope(text, lexicon, metadata)
    reasons: list[str] = []
    requirements: list[dict[str, Any]] = []
    roles: dict[str, set[str]] = {name: set() for name in names}

    def add(kind: str, parameters: dict[str, Any], unresolved: bool = False) -> None:
        nonlocal ambiguous
        ambiguous |= unresolved
        if any(item["kind"] == kind and item["parameters"] == parameters for item in requirements):
            return
        requirements.append({
            "requirement_id": f"r{len(requirements) + 1}", "kind": kind,
            "mandatory": True, "parameters": parameters,
            "analysis_status": "ambiguous" if unresolved else "supported",
            "reason_codes": ["unresolved_entity_roles" if unresolved else f"recognized_{kind}_concept"],
        })

    if concepts["relationship"] or "->" in text or "→" in text:
        parameters_list, unresolved = _relationship_parameters(text, mentions)
        for parameters in parameters_list:
            add("process_relationship", parameters, unresolved)
            for role in ("parent", "child"):
                if parameters[role] in roles:
                    roles[parameters[role]].add(role)
    process = names[0] if len(names) == 1 else None
    if concepts["command"]:
        add("launch_command", {"process": process}, len(names) > 1)
        if process:
            roles[process].add("subject")
    if concepts["completion"] and not concepts["limitations"]:
        add("command_completion", {"process": process}, len(names) > 1)
    if concepts["service_state"]:
        add("service_state", {"process": process}, len(names) > 1)
    if concepts["network"]:
        action = "download" if concepts["download"] else "connect" if concepts["connect"] else "network"
        field = "url" if _contains(text, ["url", "uri", "download", "downloaded", "tai xuong"]) else "endpoint"
        add("network_url", {"actor": process, "action": action, "field": field}, len(names) > 1)
        if process:
            roles[process].add("actor")
    if concepts["provenance"]:
        add("evidence_provenance", {"process": process}, len(names) > 1 and not concepts["relationship"])
    if concepts["limitations"]:
        facets: list[str] = []
        for facet, phrases in {
            "timestamp": ["timestamp", "timecreated", "utctime", "timezone", "thoi gian", "mui gio"],
            "completion": ["completion", "output", "service state", "hoan tat", "ket qua", "trang thai dich vu"],
            "negative_scan": ["negative scan", "absence", "globally absent", "full dataset", "toan bo dataset", "toan tep", "vang mat"],
            "candidate_status": ["candidate", "mitre", "technique", "needs_review", "ky thuat"],
            "core_boundaries": ["conhost", "deletion", "clearing", "outside", "ngoai", "xoa tep", "xoa log"],
            "scope": ["scope", "pham vi", "evidence groups", "nhom bang chung"],
        }.items():
            if _contains(text, phrases):
                facets.append(facet)
        if not facets or _contains(text, ["all", "every", "complete list", "tat ca", "toan bo", "day du"]):
            facets = ["all"]
        add("review_limitations", {"facets": facets})
    technique_ids = list(dict.fromkeys(match.upper() for match in re.findall(r"\bt\d{4}(?:\.\d{3})?\b", text)))
    if concepts["technique"] or technique_ids:
        # A question about confirmation can be answered by its actual candidate
        # status. A demand for affirmative proof requires confirmed evidence.
        affirmative_proof = _contains(text, ["prove", "proof", "establish", "chung minh"])
        confirmed = _contains(text, ["confirmed", "confirmation", "xac nhan", "chac chan"])
        for technique_id in technique_ids or [None]:
            add("technique_assessment", {"technique_id": technique_id, "certainty": "confirmed" if affirmative_proof and confirmed else "assessment"})

    # Scope exclusions are safe only in the explicitly recognized local form.
    # Vietnamese trailing 'không?' is a question particle rather than negation.
    negation_text = re.sub(r"\bkhong\s*[?!.]*\s*$", "", text)
    negation_text = re.sub(r"\b(?:not|exclude|excluding|ignore|khong xet|loai tru|bo qua)\s+(?:linux|windows|unix|posix|macos)\b", "", negation_text)
    if re.search(r"\b(?:not|never|without|isn't|isnt|didn't|didnt|khong|chua|chang)\b", negation_text):
        ambiguous = True
        reasons.append("negation_scope_not_resolved")
        if scope["status"] == "mismatch":
            # An unresolved negation can change whether the lexical platform
            # mention is requested at all. Do not label that uncertainty as a
            # clear outside-source intent.
            scope["status"] = "ambiguous"
            scope["reason_codes"] = ["negated_scope_unresolved"]
    # Detect an independent flat request that none of the declared concepts can
    # parse. Do not silently discard it merely because another clause is known.
    clauses = re.split(
        r";|\s+(?:and|va)\s+(?=(?:also\s+)?(?:tell|explain|describe|show|identify|list|give|provide|what|which|who|why|how|when|where|cho|hay|giai|mo|liet|xac|cai|ai|tai|o)\b)",
        text,
    )
    if len(clauses) > 1:
        for clause in clauses:
            if not clause.strip() or not re.search(r"[a-z0-9]", clause):
                continue
            if not any(_contains(clause, phrases) for phrases in lexicon["concepts"].values()) and not _contains(clause, [phrase for phrases in lexicon["platforms"].values() for phrase in phrases]):
                ambiguous = True
                reasons.append("unrecognized_conjoined_request")
                break
    # Evidence is a qualifier in many requests. It cannot change an unsupported
    # requested attribution/identity into a provenance-only question.
    unsupported_identity = _contains(text, ["attacker", "threat actor", "attribution", "campaign", "malware family", "country of origin", "ke tan cong", "nhom tan cong", "chien dich", "ho ma doc", "quoc gia"])
    identity_question = _contains(text, ["who", "which", "what", "identify", "name", "ai", "nao", "xac dinh", "ten"])
    if unsupported_identity and identity_question:
        ambiguous = True
        reasons.append("unsupported_attribution_or_identity_requirement")
    uncovered_claims = _uncovered_claim_reasons(text, concepts)
    if uncovered_claims:
        ambiguous = True
        reasons.extend(uncovered_claims)
    if scope["status"] == "ambiguous":
        reasons.append("scope_analysis_ambiguous")
    if not requirements:
        reasons.append("unsupported_information_request")
        status = "ambiguous" if ambiguous else "unsupported"
    else:
        status = "ambiguous" if ambiguous else "supported"
        reasons.append("recognized_concept_requirements")
    document = {
        "schema_version": QUERY_REQUIREMENTS_SCHEMA_VERSION, "query": query,
        "analysis_status": status, "scope": scope,
        "entities": [{"name": name, "roles": sorted(roles[name]) or ["unspecified"]} for name in names],
        "requirements": requirements, "reason_codes": reasons,
        "limitations": [
            "Deterministic EN/VI concept-and-role subset; not general natural language understanding.",
            "Complex negation/comparison and unresolved roles remain ambiguous; unrecognized information requests remain unsupported.",
            "Requirements describe requested returned evidence, not real-world absence or a security conclusion.",
        ],
    }
    return validate_query_requirements_document(document)


def validate_query_requirements_document(document: object) -> dict[str, Any]:
    """Validate and detach a finite requirements document without artifact IO."""
    root = _json_copy(document, "requirements")
    expected = {"schema_version", "query", "analysis_status", "scope", "entities", "requirements", "reason_codes", "limitations"}
    if not isinstance(root, dict) or set(root) != expected:
        raise QueryRequirementsError("requirements fields are invalid")
    if root["schema_version"] != QUERY_REQUIREMENTS_SCHEMA_VERSION or not isinstance(root["analysis_status"], str) or root["analysis_status"] not in {"supported", "ambiguous", "unsupported"}:
        raise QueryRequirementsError("requirements schema/status is unsupported")
    if not isinstance(root["query"], str) or not root["query"].strip():
        raise QueryRequirementsError("requirements.query must be nonempty")
    scope = root["scope"]
    if not isinstance(scope, dict) or set(scope) != {"requested_platforms", "excluded_platforms", "mechanisms", "comparison", "status", "reason_codes"}:
        raise QueryRequirementsError("requirements.scope fields are invalid")
    if not isinstance(scope["status"], str) or scope["status"] not in {"in_scope", "mismatch", "ambiguous", "unspecified"} or type(scope["comparison"]) is not bool:
        raise QueryRequirementsError("requirements.scope status/comparison is invalid")
    for field in ("requested_platforms", "excluded_platforms", "mechanisms", "reason_codes"):
        if not isinstance(scope[field], list) or any(not isinstance(item, str) or not item for item in scope[field]):
            raise QueryRequirementsError(f"requirements.scope.{field} must contain strings")
    for field in ("reason_codes", "limitations"):
        if not isinstance(root[field], list) or any(not isinstance(item, str) or not item for item in root[field]):
            raise QueryRequirementsError(f"requirements.{field} must contain strings")
    if not isinstance(root["entities"], list) or not isinstance(root["requirements"], list):
        raise QueryRequirementsError("requirements entities/requirements must be arrays")
    for entity in root["entities"]:
        if not isinstance(entity, dict) or set(entity) != {"name", "roles"} or not isinstance(entity["name"], str) or not entity["name"] or not isinstance(entity["roles"], list) or not entity["roles"] or any(not isinstance(item, str) or item not in {"subject", "actor", "parent", "child", "unspecified"} for item in entity["roles"]):
            raise QueryRequirementsError("requirements entity is invalid")
    ids: set[str] = set()
    for item in root["requirements"]:
        if not isinstance(item, dict) or set(item) != {"requirement_id", "kind", "mandatory", "parameters", "analysis_status", "reason_codes"}:
            raise QueryRequirementsError("requirement fields are invalid")
        if not isinstance(item["requirement_id"], str) or not re.fullmatch(r"r[1-9]\d*", item["requirement_id"]) or item["requirement_id"] in ids:
            raise QueryRequirementsError("requirement IDs must be unique local rN identifiers")
        ids.add(item["requirement_id"])
        if not isinstance(item["kind"], str) or item["kind"] not in REQUIREMENT_KINDS or item["mandatory"] is not True or not isinstance(item["analysis_status"], str) or item["analysis_status"] not in {"supported", "ambiguous", "unsupported"} or not isinstance(item["parameters"], dict) or not isinstance(item["reason_codes"], list) or any(not isinstance(code, str) or not code for code in item["reason_codes"]):
            raise QueryRequirementsError("requirement kind/status/metadata is invalid")
        parameters = item["parameters"]
        fields = {
            "process_relationship": {"parent", "child", "chain"}, "launch_command": {"process"},
            "command_completion": {"process"}, "service_state": {"process"},
            "network_url": {"actor", "action", "field"}, "evidence_provenance": {"process"},
            "review_limitations": {"facets"}, "technique_assessment": {"technique_id", "certainty"},
        }[item["kind"]]
        if set(parameters) != fields:
            raise QueryRequirementsError("requirement parameters do not match kind")
        for field in fields & {"parent", "child", "process", "actor", "technique_id"}:
            if parameters[field] is not None and (not isinstance(parameters[field], str) or not parameters[field]):
                raise QueryRequirementsError("requirement identity must be a nonempty string or null")
        if item["kind"] == "process_relationship" and type(parameters["chain"]) is not bool:
            raise QueryRequirementsError("relationship chain must be boolean")
        if item["kind"] == "network_url" and (not isinstance(parameters["action"], str) or parameters["action"] not in {"download", "connect", "network"} or not isinstance(parameters["field"], str) or parameters["field"] not in {"url", "endpoint"}):
            raise QueryRequirementsError("network action/field is unsupported")
        if item["kind"] == "technique_assessment" and (not isinstance(parameters["certainty"], str) or parameters["certainty"] not in {"assessment", "confirmed"}):
            raise QueryRequirementsError("technique certainty is unsupported")
        if item["kind"] == "review_limitations" and (not isinstance(parameters["facets"], list) or not parameters["facets"] or any(not isinstance(facet, str) or facet not in REVIEW_LIMITATION_FACETS for facet in parameters["facets"])):
            raise QueryRequirementsError("limitation facets are unsupported")
    if root["analysis_status"] == "supported" and not root["requirements"]:
        raise QueryRequirementsError("supported analysis requires at least one requirement")
    if root["analysis_status"] == "supported" and any(item["analysis_status"] != "supported" for item in root["requirements"]):
        raise QueryRequirementsError("supported analysis cannot contain unresolved requirements")
    return root
