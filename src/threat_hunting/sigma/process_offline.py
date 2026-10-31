"""Tri-state raw-field evaluator for the selected process_creation Sigma subset."""
from fnmatch import fnmatchcase
from pathlib import Path
import re
import yaml

from threat_hunting.evidence.slice_provenance import digest


def evaluate_process_rule(path: Path, rows: list[dict]) -> dict:
    rule = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if rule["logsource"] != {"category": "process_creation", "product": "windows"}:
        raise ValueError(f"Unsupported logsource: {path.name}")
    detection = rule["detection"]
    condition = detection["condition"]
    names = set(detection) - {"condition"}
    all_match = re.fullmatch(r"all of ([a-zA-Z_]+\*)", condition)
    filter_match = re.fullmatch(r"([a-zA-Z_]+) and not 1 of ([a-zA-Z_]+\*)", condition)
    if all_match:
        positives = sorted(n for n in names if fnmatchcase(n, all_match[1])); filters = []
    elif filter_match:
        positives = [filter_match[1]]; filters = sorted(n for n in names if fnmatchcase(n, filter_match[2]))
        if not filters:
            raise ValueError(f"Filter wildcard selects nothing: {path.name}")
    else:
        raise ValueError(f"Unsupported condition: {path.name}: {condition}")
    if not positives or set(positives + filters) != names:
        raise ValueError(f"Unconsumed selection: {path.name}")
    allowed = {"Image", "ParentImage", "CommandLine", "OriginalFileName"}

    def validate(selection):
        if isinstance(selection, list):
            if not selection: raise ValueError(f"Empty selection: {path.name}")
            for alternative in selection: validate(alternative)
        elif isinstance(selection, dict):
            for expression, value in selection.items():
                parts = expression.split("|")
                if parts[0] not in allowed or len(parts) > 2 or (len(parts) == 2 and parts[1] not in {"endswith", "contains"}):
                    raise ValueError(f"Unsupported field/modifier: {path.name}: {expression}")
                if not isinstance(value, (str, list)) or (isinstance(value, list) and not all(isinstance(v, str) for v in value)):
                    raise ValueError(f"Unsupported value: {path.name}: {expression}")
        else:
            raise ValueError(f"Unsupported selection: {path.name}")
    for name in names: validate(detection[name])

    def combine(values, *, any_of=False):
        if any_of:
            return True if True in values else None if None in values else False
        return False if False in values else None if None in values else True

    def matches(selection, fields):
        if isinstance(selection, list): return combine([matches(s, fields) for s in selection], any_of=True)
        values = []
        for expression, wanted in selection.items():
            field, _, modifier = expression.partition("|")
            actual = fields.get(field)
            if not isinstance(actual, str): values.append(None); continue
            choices = wanted if isinstance(wanted, list) else [wanted]
            actual = actual.casefold()
            values.append(any(actual.endswith(w.casefold()) if modifier == "endswith" else w.casefold() in actual if modifier == "contains" else actual == w.casefold() for w in choices))
        return combine(values)
    found, unknown = [], []
    examined = 0
    for row in rows:
        event, original = row["canonical_fields"], row["original_fields"]
        if (event.get("provider"), str(event.get("event_id"))) not in {("Microsoft-Windows-Sysmon", "1"), ("Microsoft-Windows-Security-Auditing", "4688")}:
            continue
        examined += 1
        fields = {"Image": event.get("process_name"), "ParentImage": event.get("parent_process_name"),
                  "CommandLine": event.get("command_line"), "OriginalFileName": original.get("OriginalFileName")}
        positive = combine([matches(detection[n], fields) for n in positives])
        negative = combine([matches(detection[n], fields) for n in filters], any_of=True) if filters else False
        result = combine([positive, None if negative is None else not negative])
        info = {"source_file": row["source_file"], "raw_record_ref": row["raw_record_ref"], "fields": fields,
                "selection_results": {n: matches(detection[n], fields) for n in sorted(names)}}
        if result is True: found.append(info)
        elif result is None: unknown.append(info)
    return {"schema_version": "process-sigma-offline-evaluation/v1", "rule_filename": path.name, "rule_sha256": digest(path),
            "metadata": {k: str(v) if k in {"date", "modified"} else v for k,v in rule.items()},
            "process_creation_observations_examined": examined, "matches": found, "indeterminate": unknown,
            "unsupported_conditions": [], "status": "candidate", "review_status": "pending_human_review",
            "semantics": "Map fields AND; list alternatives OR; missing fields unknown; unknown exclusion never becomes a match."}
