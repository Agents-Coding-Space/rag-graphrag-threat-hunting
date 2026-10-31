"""Small explicit reference evaluator for selected Security rule hypotheses."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml

from threat_hunting.evidence.slice_provenance import digest


def evaluate_security_rule(path: Path, observations: list[dict]) -> dict[str, Any]:
    """Support selection AND NOT reduction only; reject every unsupported field."""
    rule = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if rule["logsource"] != {"product": "windows", "service": "security"}:
        raise ValueError(f"Unsupported logsource: {path.name}")
    detection = rule["detection"]
    if set(detection) != {"selection", "reduction", "condition"} or detection["condition"] != "selection and not reduction":
        raise ValueError(f"Unsupported Security detection condition: {path.name}")
    supported = {"EventID", "TicketOptions", "TicketEncryptionType", "ServiceName"}
    for name in ("selection", "reduction"):
        for expression in detection[name]:
            parts = expression.split("|")
            if parts[0] not in supported or len(parts) > 2 or (len(parts) == 2 and parts[1] != "endswith"):
                raise ValueError(f"Unsupported field/modifier: {path.name}: {expression}")

    def matches(raw: dict, selection: dict) -> bool:
        for expression, wanted in selection.items():
            field, _, modifier = expression.partition("|")
            actual = raw.get(field)
            if actual is None or isinstance(actual, (list, dict)):
                return False
            choices = wanted if isinstance(wanted, list) else [wanted]
            if modifier == "endswith":
                matched = any(str(actual).casefold().endswith(str(v).casefold()) for v in choices)
            else:
                matched = any(str(actual).casefold() == str(v).casefold() for v in choices)
            if not matched:
                return False
        return True

    result = []
    for observation in observations:
        raw = observation["original_fields"]
        if matches(raw, detection["selection"]) and not matches(raw, detection["reduction"]):
            result.append({"observation_id": observation["observation_id"], "raw_record_ref": observation["raw_record_ref"],
                           "timestamp": observation["timestamp"], "status": "candidate",
                           "matching_fields": {k.split("|")[0]: raw.get(k.split("|")[0]) for group in ("selection", "reduction") for k in detection[group]},
                           "interpretation": "RC4 service-ticket rule hypothesis, not proof of cracking, password recovery or successful compromise."})
    # Safe YAML dates become date objects; make a JSON-safe metadata copy.
    return {"schema_version": "security-sigma-reference-evaluation/v1", "rule_filename": path.name,
            "rule_sha256": digest(path), "metadata": {k: str(v) if k in {"date", "modified"} else v for k, v in rule.items()},
            "observation_count_examined": len(observations), "unsupported_fields": [], "matches": result,
            "review_status": "pending_human_review", "backend": "offline_explicit_subset_not_production_sigma_backend"}
