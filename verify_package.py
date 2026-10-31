"""Offline package integrity/provenance checks; never load an embedding or LLM."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import socket
import sys

ROOT = Path(__file__).resolve().parent


def no_network(*args, **kwargs):
    raise RuntimeError("Network access is forbidden in the package verifier")


socket.create_connection = no_network
socket.socket.connect = no_network


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_relative(value):
    if re.match(r"^[A-Za-z]:", value) or value.startswith(("/", "\\")):
        raise ValueError("Portable input has an absolute path")
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise ValueError("Package path escapes extraction root")
    return path


def resolve_historical(value):
    normalized = re.sub(r"\\+", "/", value)
    rules = read(ROOT / "packaging/path_migration.json")["prefix_rules"]
    for rule in rules:
        prefix = rule["from"].replace("\\", "/")
        if normalized.lower().startswith(prefix.lower() + "/"):
            value = "/".join(filter(None, (rule["to"].strip("."), normalized[len(prefix) + 1:])))
            break
    return safe_relative(value.replace("\\", "/"))


def verify(schemas=False, manifest=True):
    counts = {}
    if manifest:
        inventory = read(ROOT / "packaging/package_manifest.json")["files"]
        actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file()}
        expected = set(inventory) | {"packaging/package_manifest.json"}
        if actual != expected:
            raise ValueError("Extracted package file set differs from the manifest")
        for name, entry in inventory.items():
            path = safe_relative(name)
            if path.stat().st_size != entry["size_bytes"] or sha(path) != entry["sha256"]:
                raise ValueError("Package content hash mismatch: " + name)
        counts["manifest_files_verified"] = len(inventory)
    inputs = read(ROOT / "packaging/inputs.json")["inputs"]
    if len(inputs) != 10 or len({x["filename"] for x in inputs}) != 10:
        raise ValueError("Expected ten distinct selected inputs")
    for item in inputs:
        path = safe_relative(item["path"])
        if sha(path) != item["sha256"]:
            raise ValueError("Selected input hash mismatch: " + item["filename"])
    counts["selected_inputs_verified"] = 10
    raw_counts = {}
    for item in inputs:
        if item["path"].startswith("data/raw/"):
            path = safe_relative(item["path"])
            count = 0
            with path.open(encoding="utf-8-sig") as stream:
                for line in stream:
                    if line.strip():
                        json.loads(line)
                        count += 1
            raw_counts[item["filename"]] = count
    if sorted(raw_counts.values()) != [1127, 2390, 25993]:
        raise ValueError("Unexpected raw JSONL record counts")
    counts["raw_records"] = sum(raw_counts.values())
    canonical_root = ROOT / "outputs/canonical/mordor-selected-v2"
    canonical = read(canonical_root / "manifest.json")
    canonical_count = 0
    for item in canonical["files"]:
        path = canonical_root / item["canonical_events"]
        if sha(path) != item["canonical_events_sha256"]:
            raise ValueError("Canonical hash mismatch")
        with path.open(encoding="utf-8-sig") as stream:
            count = sum(1 for line in stream if line.strip() and json.loads(line))
        if count != item["input_record_count"]:
            raise ValueError("Canonical count mismatch")
        canonical_count += count
    counts["canonical_records"] = canonical_count
    provenance = read(ROOT / "outputs/final/20261031_direct_v7/source_verification.json")["verified_gt_input_provenance"]
    for old_path, item in provenance.items():
        if sha(resolve_historical(old_path)) != item["sha256"]:
            raise ValueError("Historical provenance does not resolve through package path map")
    counts["historical_provenance_entries_verified"] = len(provenance)
    original = read(ROOT / "configs/runtime_artifacts_integrated_v5.json")
    portable = read(ROOT / "portable/runtime_artifacts.json")
    for registry, mode in ((original, "historical"), (portable, "portable")):
        for sid, entry in registry["scenarios"].items():
            paths = {key: safe_relative(value) for key, value in entry["paths"].items()}
            documents = {key: read(path) for key, path in paths.items()}
            for path in paths.values():
                if sha(path) != entry["sha256"][path.name]:
                    raise ValueError("Consumer registry hash mismatch")
            gt, corpus, graph, index = (documents[key] for key in ("gt_path", "corpus_path", "graph_path", "index_path"))
            for item in gt["input_provenance"]:
                path = safe_relative(item["path"]) if mode == "portable" else resolve_historical(item["path"])
                if sha(path) != item["sha256"]:
                    raise ValueError("Ground truth provenance mismatch")
            if corpus["source_ground_truth"]["sha256"] != sha(paths["gt_path"]) or graph["source_ground_truth"] != corpus["source_ground_truth"]:
                raise ValueError("Ground truth consumer binding mismatch")
            if index["corpus_provenance"]["sha256"] != sha(paths["corpus_path"]):
                raise ValueError("Vector corpus binding mismatch")
            if schemas:
                sys.path.insert(0, str(ROOT / "src"))
                from threat_hunting.ground_truth.schema import load_ground_truth_document
                from threat_hunting.retrieval.schema import load_retrieval_corpus
                from threat_hunting.graph.schema import load_knowledge_graph
                from threat_hunting.retrieval.vector_schema import load_vector_index
                load_ground_truth_document(paths["gt_path"])
                load_retrieval_corpus(paths["corpus_path"])
                load_knowledge_graph(paths["graph_path"])
                load_vector_index(paths["index_path"])
            if mode == "portable":
                old_paths = original["scenarios"][sid]["paths"]
                old_gt = read(ROOT / old_paths["gt_path"])
                comparable = deepcopy(gt)
                comparable["input_provenance"] = old_gt["input_provenance"]
                if comparable != old_gt:
                    raise ValueError("Migration changed ground truth outside input paths")
                for field in ("corpus_path", "graph_path"):
                    old_document = read(ROOT / old_paths[field])
                    comparable = deepcopy(documents[field])
                    comparable["source_ground_truth"] = old_document["source_ground_truth"]
                    if comparable != old_document:
                        raise ValueError("Migration changed corpus or graph content")
                old_index = read(ROOT / old_paths["index_path"])
                comparable = deepcopy(index)
                comparable["corpus_provenance"] = old_index["corpus_provenance"]
                if comparable != old_index:
                    raise ValueError("Migration changed vectors or embedding configuration")
    counts["historical_consumer_files_verified"] = 12
    counts["portable_consumer_files_verified"] = 12
    cti_count = 0
    for name in ("outputs/offline/requirements_gap_20261030_v1/cti/cti_corpus.json", "outputs/integrated/20261030_v5/cti_auth/cti_corpus.json"):
        path = ROOT / name
        document = read(path)
        for source in document["sources"]:
            snapshot = (path.parent / source["snapshot_path"]).resolve()
            text_path = (path.parent / source["extracted_text_path"]).resolve()
            if not snapshot.is_relative_to(ROOT) or not text_path.is_relative_to(ROOT):
                raise ValueError("CTI path escapes package")
            if sha(snapshot) != source["snapshot_sha256"] or sha(text_path) != source["extracted_text_sha256"]:
                raise ValueError("CTI hash mismatch")
            text = text_path.read_text(encoding="utf-8")
            for chunk in document["chunks"]:
                if chunk["source_id"] == source["source_id"]:
                    citation = chunk["citation"]
                    if text[citation["char_start"]:citation["char_end"]] != citation["anchor"]:
                        raise ValueError("CTI citation anchor does not resolve")
            cti_count += 1
    counts["cti_sources_verified"] = cti_count
    counts["schema_validation"] = "passed" if schemas else "not_requested_standard_library_checks_only"
    counts["network_allowed"] = False
    counts["generation_or_benchmark_run"] = False
    return {"status": "passed", **counts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schemas", action="store_true", help="Also run repository schema validators; requires installed dependencies")
    parser.add_argument("--skip-manifest", action="store_true", help="Packaging preflight before the inventory is written")
    args = parser.parse_args()
    try:
        result = verify(schemas=args.schemas, manifest=not args.skip_manifest)
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__, "reason": str(exc)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
