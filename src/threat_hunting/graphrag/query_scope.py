"""Conservative request-scope guard, independent of retrieval scores or labels.

This is an eligibility rule, not a calibrated classifier or an answerability
decision. It uses requested security fields/tasks and runtime source anchors;
unknown tasks abstain. It reads no benchmark or reference answers.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterator


def _fold(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text.casefold().replace("đ", "d")) if not unicodedata.combining(c))


def _objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _objects(child)


_INTENTS = {
    "process": r"\b(parent|child|process|spawn\w*|tien trinh|quan he|chuoi|sinh)\b",
    "command": r"\b(command(?: line)?|cmdlet|script(?:let)?|vbscript|javascript|tham so|dong lenh|lenh khoi|co che script|(?:get|set|start|stop|invoke|new|remove)-[a-z]+|/t)\b",
    "telemetry": r"\b(event(?: id)?|provider|raw_record_ref|telemetry|su kien|nguon log|ban ghi|observation|quan sat)\b",
    "network": r"\b(network|connection|connect\w*|endpoint|port|ip|http|tcp|dns|ket noi|dia chi|giao thuc|cong mang|exfiltration|danh cap|dung luong)\b",
    "authentication": r"\b(authenticat\w*|kerberos|kerberoast\w*|spray\w*|password|crack\w*|mat khau|tai khoan|dang nhap|ticket)\b",
    "limits": r"\b(evidence|completion|output|service state|hoan tat|thanh cong|trang thai dich vu|gioi han|chung minh|du bang chung)\b",
    "knowledge": r"\b(mitre|att&ck|sigma|technique|ky thuat|quy tac|phat hien)\b",
    "summary": r"\b(evidence summary|summarize.*evidence|tom tat.*bang chung|phan tich.*(?:log|bang chung|tien trinh)|limitations|gioi han bang chung)\b",
}
_REQUEST = r"\b(what|which|who|how|when|where|why|can|does|did|is|are|show|list|identify|describe|summarize|analy[sz]e|explain|count|confirm|prove|nao|gi|ai|bao nhieu|hay|co|vi sao|doi chieu|co the|co du|co chung minh|co nen|trinh bay|tom tat|phan tich|liet ke|neu|dung)\b"
_ANCHOR_KEYS = {"process_name", "parent_process_name", "host", "user", "target_user", "subject_user", "destination_ip", "source_ip", "ip", "external_id", "Image", "ParentImage", "NewProcessName", "Hostname", "SourceName"}


def assess_query_scope(query: str, *, corpus: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(corpus, dict) or not isinstance(graph, dict):
        raise ValueError("Scope guard requires runtime corpus and graph objects")
    text = _fold(query).strip()
    intents = [name for name, pattern in _INTENTS.items() if re.search(pattern, text)]
    anchors = set()
    for obj in _objects({"chunks": corpus.get("chunks", []), "nodes": graph.get("nodes", [])}):
        for key in _ANCHOR_KEYS:
            value = obj.get(key)
            if isinstance(value, str) and value.strip():
                value = _fold(value.replace("\\", "/").rsplit("/", 1)[-1])
                anchors.add(value)
                if value.endswith(".exe"):
                    anchors.add(value[:-4])
        if obj.get("entity_type") and isinstance(obj.get("name"), str):
            anchors.add(_fold(obj["name"]))
    matches = sorted(a for a in anchors if a and re.search(r"(?<!\w)" + re.escape(a) + r"(?!\w)", text))
    # Requested source dimensions are also domain anchors: no particular entity
    # is needed to ask which providers or evidence limitations a scenario has.
    domain_task = bool(re.search(
        r"\b(tien trinh|parent process|child process|process (?:creation|chain)|process.*(?:parent|child)|"
        r"command line|cmdlet|dong lenh|tham so|lenh khoi|(?:get|set|start|stop|invoke|new|remove)-[a-z]+|"
        r"event id|provider|raw_record_ref|telemetry|su kien|ban ghi|quan sat|"
        r"network|connection|ket noi|giao thuc|kerberos|kerberoast\w*|spray\w*|"
        r"crack\w*|mat khau|dang nhap|mitre|att&ck|sigma|evidence|bang chung|limitations)\b", text))
    has_request = bool(re.search(_REQUEST, text))
    # A bare named entity plus a generic imperative is not an investigation.
    proceed = bool(text and has_request and intents and (matches or domain_task))
    if not text:
        reason = "empty_query"
    elif not has_request or not intents:
        reason = "investigation_task_not_recognized"
    elif not matches and not domain_task:
        reason = "source_scope_unresolved"
    else:
        reason = None
    return {"schema_version": "query-scope-decision/v1", "decision": "proceed" if proceed else "abstain",
            "reason_codes": [] if proceed else [reason], "matched_intents": intents, "matched_source_anchors": matches,
            "interpretation": "request_scope_only_not_evidence_support", "security_conclusion_made": False}
