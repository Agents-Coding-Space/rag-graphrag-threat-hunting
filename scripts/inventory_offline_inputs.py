"""Inventory local evidence and freeze the checkpoint without modifying inputs."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from threat_hunting.evidence.slice_provenance import digest
from threat_hunting.mordor.format_detection import detect_format
from threat_hunting.mordor.parser import iter_records

SIGMA = (
    "win_security_susp_rc4_kerberos.yml",
    "proc_creation_win_regsvr32_http_ip_pattern.yml",
    "proc_creation_win_regsvr32_susp_child_process.yml",
    "proc_creation_win_regsvr32_susp_parent.yml",
    "proc_creation_win_mshta_susp_child_processes.yml",
    "proc_creation_win_mshta_susp_execution.yml",
)


def write_json(path: Path, value: object) -> None:
    """Write only a new artifact and validate its JSON readback."""
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    assert json.loads(path.read_text(encoding="utf-8")) == value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error(f"Output already exists: {args.output}")
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / "outputs/canonical/mordor-selected-v2/manifest.json").read_text(encoding="utf-8"))
    names = [f["source_filename"] for f in manifest["files"]] + list(SIGMA) + ["enterprise-attack.json"]
    inventory: dict = {"schema_version": "offline-input-inventory/v1", "accessed_at": datetime.now().astimezone().isoformat(),
                       "search_roots": [str(p.resolve()) for p in args.data_root], "inputs": [], "raw_files": [],
                       "missing_selected_inputs": [], "cti_before_ingestion": [], "protected_files": {}}
    paths: set[Path] = set()
    for base in args.data_root:
        if not base.is_dir():
            continue
        # Data roots are explicit; do not scan unrelated machine projects or .env.
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if path.name in names:
                item = {"filename": path.name, "path": str(path.resolve()), "size_bytes": path.stat().st_size,
                        "sha256": digest(path), "origin": "pre_existing_local_input"}
                inventory["inputs"].append(item)
                paths.add(path.resolve())
            relative = path.relative_to(base)
            if relative.parts[0].casefold() == "raw":
                inventory["raw_files"].append({"path": str(path.resolve()), "size_bytes": path.stat().st_size,
                                               "sha256": digest(path), "selected": path.name in names})
                paths.add(path.resolve())
            if "cti" in [part.casefold() for part in relative.parts] or path.suffix.lower() in {".pdf", ".html", ".htm"}:
                inventory["cti_before_ingestion"].append(str(path.resolve()))
    inventory["missing_selected_inputs"] = sorted(set(names) - {i["filename"] for i in inventory["inputs"]})
    for entry in manifest["files"]:
        canonical = ROOT / "outputs/canonical/mordor-selected-v2" / entry["canonical_events"]
        paths.add(canonical)
        actual = digest(canonical)
        if actual != entry["canonical_events_sha256"]:
            raise ValueError(f"Canonical hash mismatch: {canonical}")
        matches = [i for i in inventory["inputs"] if i["filename"] == entry["source_filename"]]
        for item in matches:
            if item["sha256"] != entry["source_sha256"]:
                raise ValueError(f"Raw hash mismatch: {item['path']}")
            raw = Path(item["path"])
            fmt = detect_format(raw)
            providers: Counter = Counter()
            events: Counter = Counter()
            count = 0
            for parsed in iter_records(raw, fmt.source_format):
                count += 1
                events[str(parsed.data.get("EventID"))] += 1
                providers[str(parsed.data.get("SourceName"))] += 1
            item.update(format=fmt.source_format, encoding=fmt.encoding,
                        record_count=count, event_ids=dict(sorted(events.items())), providers=dict(sorted(providers.items())),
                        canonical_path=str(canonical.resolve()), canonical_sha256=actual)
            if count != entry["input_record_count"]:
                raise ValueError(f"Raw count mismatch: {raw}")
    protected_dirs = ["configs", "benchmarks", "src", "scripts", "tests", "docs",
                      "outputs/canonical", "outputs/evidence", "outputs/ground_truth", "outputs/retrieval", "outputs/graph",
                      "outputs/review/mshta-ground-truth", "outputs/review/rag_graphrag_combined_semantic_20261027",
                      "outputs/review/live_llm_fixes/20261025/artifacts-v2",
                      "outputs/experiments/rag-graphrag-pilot-source-contract-02",
                      "outputs/experiments/rag-graphrag-remaining-source-contract-01"]
    for directory in protected_dirs:
        paths.update(p for p in (ROOT / directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    paths.update(ROOT / f for f in (".env", "AGENTS.md", "PROJECT_CONTEXT.md", "PROJECT_PROGRESS.md", "pyproject.toml", "README.md") if (ROOT / f).is_file())
    inventory["protected_files"] = {str(p.resolve()): digest(p) for p in sorted(paths)}
    write_json(args.output / "input_inventory.json", inventory)
    print(json.dumps({"selected_files_found": len(inventory["inputs"]), "missing": inventory["missing_selected_inputs"],
                      "protected_count": len(paths), "original_cti_files": inventory["cti_before_ingestion"]}))


if __name__ == "__main__":
    main()
