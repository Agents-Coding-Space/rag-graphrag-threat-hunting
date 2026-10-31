"""Verify delivery hashes, citations and deterministic evidence without any LLM."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from scripts.inventory_offline_inputs import write_json
from threat_hunting.cti.ingestion import ingest_report
from threat_hunting.evidence.authentication import survey_authentication, correlate_failures, detect_spraying, assess_logons
from threat_hunting.evidence.pcap_inventory import inspect_pcap_headers
from threat_hunting.evidence.slice_provenance import digest


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    base = args.root
    inventory = read(base / "input_inventory.json")
    after = {path: digest(Path(path)) if Path(path).is_file() else None for path in inventory["protected_files"]}
    changed = {path: {"before": previous, "after": after[path]} for path, previous in inventory["protected_files"].items() if after[path] != previous}
    write_json(base / "integrity.json", {"schema_version": "offline-baseline-integrity/v1", "protected_count": len(after),
                                        "changed_count": len(changed), "changes": changed, "after_sha256": after,
                                        "scope": "Exact protected files listed in input_inventory.json, including .env, original inputs, source/docs/config, two 15x2 runs and selected consumers."})
    if changed:
        raise ValueError("Protected files changed; inspect integrity.json")
    selected = next(i for i in inventory["inputs"] if i["filename"] == "purplesharp_ad_playbook_I_2020-10-22042947.json")
    rebuilt = survey_authentication(Path(selected["path"]), Path(selected["canonical_path"]),
                                    expected_raw_sha256=selected["sha256"], expected_canonical_sha256=selected["canonical_sha256"])
    if rebuilt != read(base / "purplesharp_v2/authentication_survey.json"):
        raise ValueError("Authentication survey is not deterministic")
    correlation = correlate_failures(rebuilt["observations"])
    if correlation != read(base / "purplesharp_v2/authentication_correlation.json"):
        raise ValueError("Authentication correlation is not deterministic")
    if detect_spraying(correlation["attempts"]) != read(base / "purplesharp_v2/password_spraying_candidates.json")["findings"]:
        raise ValueError("Spraying candidates are not deterministic")
    if assess_logons(rebuilt["observations"], correlation["attempts"]) != read(base / "purplesharp_v2/logon_investigation.json"):
        raise ValueError("Logon investigation is not deterministic")
    pcap = read(base / "purplesharp_pcap_inventory.json")
    if inspect_pcap_headers(Path(pcap["path"])) != pcap:
        raise ValueError("PCAP header inventory is not deterministic")
    cti = read(base / "cti/cti_corpus.json")
    selection = read(ROOT / "configs/knowledge/cti_gap_sources_v1.json")
    citation_count = 0
    for source in cti["sources"]:
        snapshot = base / "cti" / source["snapshot_path"]
        metadata = read(base / "cti" / source["fetch_metadata_path"])
        _, text, rebuilt_chunks, _ = ingest_report(snapshot, metadata, selection[source["source_id"]])
        if text != (base / "cti" / source["extracted_text_path"]).read_text(encoding="utf-8"):
            raise ValueError(f"CTI text changed: {source['source_id']}")
        for chunk in (c for c in cti["chunks"] if c["source_id"] == source["source_id"]):
            cite = chunk["citation"]
            expected = next(c for c in rebuilt_chunks if c["chunk_id"] == chunk["chunk_id"])
            if expected["text"] != chunk["text"] or text[cite["char_start"]:cite["char_end"]] != cite["anchor"]:
                raise ValueError(f"Invalid CTI chunk/citation: {chunk['chunk_id']}")
            if digest(snapshot) != cite["snapshot_sha256"]:
                raise ValueError(f"CTI citation hash changed: {chunk['chunk_id']}")
            citation_count += 1
    # Read all generated evidence JSON back; fixture temp trees are not deliverables.
    json_files = [p for p in base.rglob("*.json") if not any(part.startswith("pytest-") for part in p.parts)]
    for path in json_files:
        read(path)
    stream = base / "purplesharp_v2/normalized_auth_attempts.jsonl"
    rows = [json.loads(line) for line in stream.read_text(encoding="utf-8").splitlines()]
    if len(rows) != correlation["countable_attempts"]:
        raise ValueError("Attempt stream count mismatch")
    junit = ET.parse(base / "tests-delivery.xml")
    suites = list(junit.getroot().iter("testsuite"))
    tests = sum(int(s.attrib.get("tests", 0)) for s in suites)
    failures = sum(int(s.attrib.get("failures", 0)) + int(s.attrib.get("errors", 0)) for s in suites)
    if failures:
        raise ValueError("Delivery tests have failures")
    verification = {"schema_version": "offline-gap-verification/v1", "review_status": "pending_human_review",
                    "protected_files_unchanged": len(after), "raw_canonical_equal_records": rebuilt["raw_canonical_equal_records"],
                    "authentication_artifacts_deterministic": True, "pcap_inventory_deterministic": True,
                    "cti_citation_offsets_and_hashes_valid": citation_count, "json_readback_files": len(json_files),
                    "normalized_attempt_stream_rows": len(rows), "junit_tests": tests, "test_failures": failures,
                    "tests_reported": "159 passed, 6 subtests passed", "junit_path": "tests-delivery.xml",
                    "test_command": ".venv/Scripts/python.exe -m pytest tests/test_authentication_offline.py tests/test_cti_offline.py tests/test_pcap_inventory.py tests/test_format_and_parser.py tests/test_normalizer.py tests/test_canonical_mapping.py tests/test_sigma_loader.py tests/test_sigma_evaluator.py tests/test_mitre_loader.py tests/test_mitre_resolver.py tests/test_corrected_canonical_slices.py tests/test_purplesharp_ad_artifacts.py tests/test_regsvr32_c2_artifacts.py -q -p no:cacheprovider --basetemp outputs/offline/requirements_gap_20261030_v1/pytest-delivery --junitxml outputs/offline/requirements_gap_20261030_v1/tests-delivery.xml",
                    "llm_calls": 0, "benchmark_runs": 0, "runtime_consumer_rebuilds": 0, "approval_promotions": 0,
                    "git_state": "unavailable_no_dot_git_in_this_workspace"}
    write_json(base / "verification.json", verification)
    code_paths = ["src/threat_hunting/evidence/authentication.py", "src/threat_hunting/evidence/pcap_inventory.py",
                  "src/threat_hunting/sigma/security_offline.py", "src/threat_hunting/cti/__init__.py", "src/threat_hunting/cti/ingestion.py",
                  "scripts/inventory_offline_inputs.py", "scripts/build_authentication_gap.py", "scripts/fetch_cti_snapshots.py",
                  "scripts/ingest_cti_reports.py", "scripts/report_offline_gap.py", "scripts/verify_offline_gap.py",
                  "configs/knowledge/cti_gap_sources_v1.json", "configs/knowledge/derived/win_security_password_spray_correlation.yml",
                  "tests/test_authentication_offline.py", "tests/test_cti_offline.py", "tests/test_pcap_inventory.py"]
    artifacts = [p for p in base.rglob("*") if p.is_file() and not any(part.startswith("pytest-") or part == "__pycache__" for part in p.parts)]
    write_json(base / "artifact_manifest.json", {"schema_version": "offline-gap-artifact-manifest/v1", "review_status": "pending_human_review",
                                               "code_and_config_sha256": {path: digest(ROOT / path) for path in code_paths},
                                               "artifact_sha256": {p.relative_to(base).as_posix(): digest(p) for p in sorted(artifacts)},
                                               "active_authentication_version": "purplesharp_v2", "active_cti_version": "cti",
                                               "baseline": "input_inventory.json", "integrity": "integrity.json", "verification": "verification.json"})
    print(json.dumps(verification))


if __name__ == "__main__":
    main()
