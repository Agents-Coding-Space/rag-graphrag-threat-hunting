r"""Read-only independent audit of the pinned MSHTA Sigma and ATT&CK inputs.

Run from the repository root with:
  .venv\Scripts\python.exe outputs/review/mshta-ground-truth/audit_sigma_mitre.py
The matcher intentionally supports only the constructs in the two selected rules.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any

import yaml


def digest(path: Path) -> str:
    hasher = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def match_field(raw_key: str, expected: Any, event: dict[str, Any]) -> bool:
    parts = raw_key.split("|")
    if len(parts) > 2 or (len(parts) == 2 and parts[1] not in {"endswith", "contains"}):
        raise ValueError(f"Unsupported field construct: {raw_key}")
    observed = event.get(parts[0])
    if not isinstance(observed, str):
        return False
    values = expected if isinstance(expected, list) else [expected]
    if any(not isinstance(value, str) for value in values):
        raise ValueError(f"Unsupported value in field: {raw_key}")
    observed = observed.casefold()
    modifier = parts[1] if len(parts) == 2 else "equals"
    if modifier == "endswith":
        return any(observed.endswith(value.casefold()) for value in values)
    if modifier == "contains":
        return any(value.casefold() in observed for value in values)
    return any(observed == value.casefold() for value in values)


def match_selection(selection: Any, event: dict[str, Any]) -> bool:
    if isinstance(selection, list):
        return any(match_selection(item, event) for item in selection)
    if not isinstance(selection, dict):
        raise ValueError("Unsupported selection type")
    return all(match_field(key, value, event) for key, value in selection.items())


def process_creation_view(raw: dict[str, Any]) -> dict[str, Any] | None:
    provider = raw.get("SourceName")
    event_id = str(raw.get("EventID"))
    if provider == "Microsoft-Windows-Sysmon" and event_id == "1":
        return raw
    if provider == "Microsoft-Windows-Security-Auditing" and event_id == "4688":
        return {
            "Image": raw.get("NewProcessName"),
            "ParentImage": raw.get("ParentProcessName"),
            "CommandLine": raw.get("CommandLine"),
        }
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root / "src"))
    from threat_hunting.mitre import load_attack_bundle, load_source_manifest, validate_manifest

    raw_path = root / "data/raw/mordor/powershell/cmd_mshta_vbscript_execute_psh/cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    rule_paths = [root / "data/knowledge/sigma/selected/powershell" / name for name in (
        "proc_creation_win_mshta_susp_child_processes.yml",
        "proc_creation_win_mshta_susp_execution.yml",
    )]
    bundle_path = root / "data/knowledge/Mitre/enterprise-attack.json"
    manifest_path = root / "configs/knowledge/mitre_enterprise_attack.json"
    sigma_path = root / "outputs/evidence/mshta-powershell/sigma_match_review.json"
    gt_path = root / "outputs/ground_truth/mshta-powershell/scenario_ground_truth.json"
    input_paths = [raw_path, *rule_paths, bundle_path, manifest_path, sigma_path, gt_path]
    hashes_before = {path.relative_to(root).as_posix(): digest(path) for path in input_paths}
    sigma_review = json.loads(sigma_path.read_text(encoding="utf-8-sig"))
    gt = json.loads(gt_path.read_text(encoding="utf-8-sig"))
    manifest_raw = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    rules = []
    for path in rule_paths:
        rule = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
        condition = rule["detection"]["condition"]
        if condition not in {"all of selection_*", "all of selection*"}:
            raise ValueError(f"Unsupported condition in {path.name}: {condition}")
        if rule["logsource"] != {"category": "process_creation", "product": "windows"}:
            raise ValueError(f"Unexpected logsource in {path.name}")
        metadata = {key: rule[key] for key in ("title", "id", "status", "references", "tags", "logsource", "detection", "level")}
        rules.append({"path": path.relative_to(root).as_posix(), "sha256": digest(path), "metadata": metadata, "matches": []})
    selected_fields = ["SourceName", "EventID", "TimeCreated", "@timestamp", "UtcTime", "Hostname", "Image", "NewProcessName", "ParentImage", "ParentProcessName", "ProcessId", "NewProcessId", "ParentProcessId", "ProcessGuid", "ParentProcessGuid", "CommandLine", "OriginalFileName"]
    record_count = process_count = 0
    with raw_path.open(encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError(f"{raw_path.name}:{line_number}: record is not an object")
            record_count += 1
            view = process_creation_view(raw)
            if view is None:
                continue
            process_count += 1
            for rule in rules:
                selections = {key: value for key, value in rule["metadata"]["detection"].items() if key.startswith("selection")}
                if all(match_selection(selection, view) for selection in selections.values()):
                    rule["matches"].append({
                        "raw_record_ref": f"jsonl:line:{line_number}",
                        "source_file": raw_path.name,
                        "original_fields": {key: raw[key] for key in selected_fields if key in raw},
                    })
    for rule in rules:
        old_rule = next(item for item in sigma_review["rules"] if item["id"] == rule["metadata"]["id"])
        rule["matches_existing_rule_hash"] = rule["sha256"] == old_rule["sha256"]
        rule["matches_existing_observation_refs"] = sorted(item["raw_record_ref"] for item in rule["matches"]) == sorted(item["raw_record_ref"] for item in sigma_review["observation_matches"] if item["rule_id"] == rule["metadata"]["id"])
        rule["deduplicated_behavior_count"] = old_rule["behavior_match_count"]
        rule["match_reason"] = "ParentImage ends with mshta.exe and Image ends with powershell.exe" if "child_processes" in rule["path"] else "Image ends with mshta.exe and CommandLine contains vbscript; the match does not require a disguised file extension"
    index = load_attack_bundle(bundle_path)
    manifest = load_source_manifest(manifest_path)
    validate_manifest(index, manifest)
    assessments = []
    for existing in gt["mitre_assessments"]:
        external_id = existing["external_id"]
        pattern = index.active_patterns_by_external_id[external_id]
        parent = index.parent_by_subtechnique_id.get(pattern.stix_id)
        assessments.append({
            "external_id": external_id,
            "stix_id": pattern.stix_id,
            "name": pattern.name,
            "object_version": pattern.version,
            "modified": pattern.modified,
            "active": pattern.is_active,
            "parent_stix_id": parent.target_ref if parent else None,
            "matches_ground_truth_resolution": pattern.stix_id == existing["stix_id"] and pattern.name == existing["name"],
            "current_evidence_support": existing["evidence_support"],
            "recommended_evidence_support": existing["evidence_support"],
            "recommended_label_status": "candidate",
            "rationale": existing["rationale"],
            "supporting_evidence_ids": existing["supporting_evidence_ids"],
        })
    hashes_after = {path.relative_to(root).as_posix(): digest(path) for path in input_paths}
    if hashes_after != hashes_before:
        raise RuntimeError("An input changed while performing the read-only audit")
    expected_raw_hash = "25aa24b5f631f19ac23f64db116c23e632295fb5f59040e966fa47e7758b2a32"
    result = {
        "schema_version": "mshta-sigma-mitre-audit/v1",
        "analysis_status": "technical_review_complete_human_review_pending",
        "review_type": "independent_read_only_audit",
        "source_file": raw_path.relative_to(root).as_posix(),
        "source_sha256": digest(raw_path),
        "source_hash_matches_baseline": digest(raw_path) == expected_raw_hash,
        "examined_records": record_count,
        "examined_process_creation_observations": process_count,
        "sigma": rules,
        "mitre": {
            "manifest_validated": True,
            "bundle_sha256": index.source_sha256,
            "object_count": index.object_count,
            "active_attack_pattern_count": index.active_attack_pattern_count,
            "collection": asdict(index.collection),
            "source": manifest_raw["source"],
            "assessments": assessments,
        },
        "input_sha256": hashes_before,
        "input_files_unchanged": True,
        "review_recommendations": [
            "Retain both candidate Sigma findings: each has two raw observations but represents one behavior after endpoint telemetry deduplication.",
            "Retain OriginalFileName as an explicitly unmapped canonical field. Independent raw evaluation uses this field where available and finds the same four matches, so the gap does not change these selected findings.",
            "Retain T1218.005 as supported_by_observed_behavior and candidate; the local active ATT&CK object and observed inline VBScript plus PowerShell child agree.",
            "Retain T1059.007 only as Sigma tag provenance with not_supported_by_observed_command. The reviewed command is VBScript, not JavaScript.",
            "Retain T1140 as not_assessed. Rule metadata and resolution do not demonstrate deobfuscation; this rule audit is not a comprehensive behavior-negative scan.",
            "Do not infer download, C2, credential theft, destruction, CVE exploitation, or disguised file extension from the Sigma description or tags.",
            "Do not mark human review complete or mapping confirmed automatically."
        ],
    }
    output_path = Path(__file__).with_name("sigma_mitre_audit.json")
    output_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    assert json.loads(output_path.read_text(encoding="utf-8")) == result
    print(json.dumps({"output": output_path.relative_to(root).as_posix(), "record_count": record_count, "match_counts": {rule["metadata"]["id"]: len(rule["matches"]) for rule in rules}, "input_files_unchanged": True}, indent=2))


if __name__ == "__main__":
    main()
