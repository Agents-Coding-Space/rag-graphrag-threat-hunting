"""Extract complete PurpleSharp authentication evidence offline, versioned separately."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))
from scripts.inventory_offline_inputs import write_json
from threat_hunting.evidence.authentication import survey_authentication, correlate_failures, detect_spraying, assess_logons
from threat_hunting.evidence.slice_provenance import digest
from threat_hunting.mitre.loader import load_attack_bundle, load_source_manifest, validate_manifest
from threat_hunting.sigma.security_offline import evaluate_security_rule


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rule", type=Path, default=ROOT / "configs/knowledge/derived/win_security_password_spray_correlation.yml")
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"Output already exists: {args.output}")
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))

    def selected(filename: str) -> dict:
        items = [i for i in inventory["inputs"] if i["filename"] == filename]
        if not items:
            raise FileNotFoundError(f"Missing selected input: {filename}")
        if len(items) > 1:
            preferred = [i for i in items if "selected" in Path(i["path"]).parts]
            if len({i["sha256"] for i in items}) != 1 or len(preferred) != 1:
                raise ValueError(f"Ambiguous selected input: {filename}")
            return preferred[0]
        return items[0]

    source = selected("purplesharp_ad_playbook_I_2020-10-22042947.json")
    survey = survey_authentication(Path(source["path"]), Path(source["canonical_path"]),
                                   expected_raw_sha256=source["sha256"], expected_canonical_sha256=source["canonical_sha256"])
    correlation = correlate_failures(survey["observations"])
    base_rule, derived = list(yaml.safe_load_all(args.rule.read_text(encoding="utf-8")))
    config = derived["correlation"]
    if (base_rule["detection"] != {"selection": {"EventID": [4625, 4776], "Outcome": "failure"}, "condition": "selection"}
            or base_rule.get("taxonomy") != "project_authentication_attempt_v1"
            or config["type"] != "value_count" or config["group-by"] != ["SourceContext"]
            or config["condition"]["field"] != "TargetUserName" or config["rules"] != [base_rule["name"]]
            or config["timespan"] != "1m"):
        raise ValueError(f"Unsupported derived correlation contract: {args.rule}")
    sprays = detect_spraying(correlation["attempts"], window_seconds=60, min_accounts=config["condition"]["gte"])
    logons = assess_logons(survey["observations"], correlation["attempts"])
    sigma_input = selected("win_security_susp_rc4_kerberos.yml")
    sigma = evaluate_security_rule(Path(sigma_input["path"]), survey["observations"])
    mitre_input = selected("enterprise-attack.json")
    index = load_attack_bundle(Path(mitre_input["path"]))
    manifest = load_source_manifest(ROOT / "configs/knowledge/mitre_enterprise_attack.json")
    validate_manifest(index, manifest)
    resolved = []
    for external_id in ("T1110.003", "T1558.003", "T1218.005", "T1218.010"):
        obj = index.active_patterns_by_external_id[external_id]
        resolved.append({"external_id": external_id, "stix_id": obj.stix_id, "name": obj.name, "version": obj.version,
                         "modified": obj.modified, "url": obj.attack_external_reference.url,
                         "status": "candidate", "resolution": "active_object_resolved_not_telemetry_confirmation"})
    mitre = {"schema_version": "offline-knowledge-resolution/v1", "source_sha256": index.source_sha256,
             "manifest_sha256": digest(ROOT / "configs/knowledge/mitre_enterprise_attack.json"),
             "collection_version": index.collection.version, "tag": manifest.tag, "techniques": resolved}
    args.output.mkdir(parents=True)
    findings = {"schema_version": "suspected-password-spraying/v1", "review_status": "pending_human_review",
                "derived_rule_path": str(args.rule.relative_to(ROOT)), "derived_rule_sha256": digest(args.rule),
                "implementation": "offline reference evaluator after deduplication, not production Sigma conversion",
                "findings": sprays}
    for filename, document in (("authentication_survey.json", survey), ("authentication_correlation.json", correlation),
                               ("password_spraying_candidates.json", findings), ("logon_investigation.json", logons),
                               ("sigma_rc4_evaluation.json", sigma), ("mitre_resolution.json", mitre)):
        write_json(args.output / filename, document)
    # Publish the derived input stream explicitly; it is not canonical-event/v2.
    with (args.output / "normalized_auth_attempts.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
        for attempt in correlation["attempts"]:
            if not attempt["source_context"]["value"] or not attempt["target_account"]:
                continue
            row = {"schema_version": "normalized-auth-attempt/v1", "attempt_id": attempt["attempt_id"],
                   "EventID": 4625 if len(attempt["observation_ids"]) == 2 else int(next(o["event_id"] for o in survey["observations"] if o["observation_id"] == attempt["observation_ids"][0])),
                   "Outcome": "failure", "TargetUserName": attempt["target_account"].casefold(),
                   "SourceContext": json.dumps(attempt["source_context"], sort_keys=True), "timestamp": attempt["timestamp"],
                   "raw_record_refs": attempt["raw_record_refs"], "status": attempt["status"]}
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    evidence = [{"evidence_id": o["observation_id"], "raw_record_ref": o["raw_record_ref"], "source_file": o["source_file"],
                 "timestamp": o["timestamp"], "original_fields": o["original_fields"], "status": "observed",
                 "why_relevant": "Authentication failure" if o["outcome"] == "failure" else "Service ticket hypothesis"}
                for o in survey["observations"] if o["event_id"] in {"4625", "4776"} or o["observation_id"] in {m["observation_id"] for m in sigma["matches"]}]
    ground_truth = {"schema_version": "authentication-ground-truth-draft/v1", "scenario_id": "purplesharp-ad",
                    "scenario_name": "3.3.1 Kịch bản brute force và đăng nhập bất thường",
                    "source_log_file": source["filename"], "analysis_status": "draft_reviewable", "review_status": "pending_human_review",
                    "input_provenance": survey["input_provenance"], "time_window": survey["time_window"],
                    "observed_entities": {"hosts": sorted({o["host"] for o in survey["observations"] if o["host"]}),
                                          "failed_accounts": sorted({a["target_account"] for a in correlation["attempts"] if a["target_account"]})},
                    "evidence": evidence, "sigma_rules": [sigma, {"filename": args.rule.name, "sha256": digest(args.rule), "origin": "project_derived", "status": "candidate"}],
                    "mitre_techniques": [{**next(t for t in resolved if t["external_id"] == technique), "evidence_support": support,
                                          "support_ids": ids, "source_sha256": index.source_sha256}
                                         for technique, support, ids in (("T1110.003", "supported_suspicion" if sprays else "insufficient_evidence", [f["finding_id"] for f in sprays]),
                                                                         ("T1558.003", "rc4_ticket_hypothesis" if sigma["matches"] else "insufficient_evidence", [m["observation_id"] for m in sigma["matches"]]))],
                    "expected_relationships": [{"relationship": "two_views_of_authentication_attempt", "attempt_id": a["attempt_id"],
                                                "observation_ids": a["observation_ids"], "status": a["status"]} for a in correlation["attempts"]],
                    "expected_summary": f"Toàn bộ {survey['raw_records_read']} raw/canonical records đã được đối chiếu; {correlation['failure_observations']} failure observations, {correlation['countable_attempts']} correlated attempts, {len(sprays)} suspected spraying cluster(s), {len(sigma['matches'])} RC4 rule matches. Không xác nhận compromise.",
                    "investigation_questions": ["Nguồn nào thử những tài khoản nào, trong bao lâu?", "4625/4776 có đếm trùng không?", "Có đăng nhập thành công cùng tên tài khoản trước/sau lỗi không; liên kết nào còn thiếu?", "RC4 ticket request hỗ trợ giả thuyết nào và chưa chứng minh điều gì?"],
                    "review_notes": ["Offline evidence draft; not the runtime GT v3 schema and not integrated into consumers.", survey["timestamp_policy"],
                                     "Launch /t is intent only; failure clustering and ticket evidence are evaluated independently.",
                                     "One failed attempt per account does not establish repeated brute force against a single account. Password sameness is not logged.",
                                     "Successful logon is observed, but abnormality/causality/compromise requires historical and session context."]}
    write_json(args.output / "scenario_ground_truth.json", ground_truth)
    summary = {"records": survey["raw_records_read"], "auth_ids": survey["auth_event_ids"], "pairs": correlation["paired_attempts"],
               "attempts": correlation["countable_attempts"], "ambiguous": len(correlation["ambiguous_observations"]),
               "spraying_clusters": len(sprays), "rc4_matches": len(sigma["matches"]), "successes": logons["success_count"],
               "success_by_account": logons["successes_by_account"], "success_by_type": logons["successes_by_logon_type"],
               "temporal_candidates": len(logons["same_name_temporal_candidates"]),
               "temporal_directions": dict(Counter(c["direction"] for c in logons["same_name_temporal_candidates"]))}
    write_json(args.output / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
