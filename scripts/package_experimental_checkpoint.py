"""Package the current experimental source and pinned inputs, excluding secrets."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def package(destination: Path) -> dict:
    """Create a new source/artifact ZIP and a separate integrity manifest."""
    paths = set()
    for directory, suffixes in (("src/threat_hunting", {".py"}), ("scripts", {".py"}),
                                ("configs", {".json"}), ("docs", {".md"}), ("tests", {".py", ".json", ".jsonl", ".yml"}),
                                ("frontend/src", {".ts", ".tsx", ".css"})):
        paths.update(p for p in (ROOT / directory).rglob("*") if p.is_file() and p.suffix in suffixes and "__pycache__" not in p.parts)
    paths.update(p for p in (ROOT / "frontend").iterdir() if p.is_file() and p.suffix in {".json", ".ts", ".js", ".mjs", ".html"})
    paths.update(ROOT / name for name in ("AGENTS.md", "PROJECT_CONTEXT.md", "PROJECT_PROGRESS.md", "README.md", "pyproject.toml", "run_backend.py"))
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(ROOT))
    from threat_hunting.server.app import SCENARIO_REGISTRY
    from scripts.serve_ui_replay import CASES
    for scenario in SCENARIO_REGISTRY.values():
        paths.update(Path(scenario[name]) for name in ("gt_path", "corpus_path", "graph_path", "index_path"))
    paths.update(CASES.values())
    paths.update(p for p in (ROOT / "frontend/dist").rglob("*") if p.is_file())
    history = ROOT / "outputs/review/live_llm_functional_smoke"
    paths.update(history / name for name in ("cases.json", "results.json", "results.csv", "report.md"))
    paths.update(p for p in (ROOT / "outputs/review/mshta-human-approval").rglob("*") if p.is_file() and p.suffix in {".json", ".md"})
    review = ROOT / "outputs/review/experimental_checkpoint_20261026"
    paths.update(review / name for name in ("report.md", "retrieval_audit.md", "retrieval_audit.json", "ui-service-health-restarted.json", "ui-http-checks.json", "runtime-tests-verified.xml", "harness-ui-final-tests.xml"))
    paths.update(p for p in (review / "comparison_dry_run_final").rglob("*.json") if p.is_file())
    paths.update(p for p in (review / "ui").glob("*.md") if p.is_file())
    selected = sorted(p for p in paths if p.is_file())
    for path in selected:
        if not path.resolve().is_relative_to(ROOT) or path.name.startswith(".env") or path.suffix in {".key", ".pem"}:
            raise ValueError("Unacceptable checkpoint path")
    versions = {item.metadata["Name"]: item.version for item in importlib.metadata.distributions() if item.metadata.get("Name")}
    manifest = {"schema_version": "experimental-package/v1", "created_utc": datetime.now(timezone.utc).isoformat(),
                "python": platform.python_version(), "platform": platform.system(),
                "installed_package_versions": dict(sorted(versions.items())),
                "excluded": ["environment files", "credentials", "logs", "model weights", "unavailable original inputs"],
                "files": {}}
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in selected:
            relative = path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            manifest["files"][relative] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            archive.writestr(relative, data)
        archive.writestr("checkpoint_package_manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError("Checkpoint ZIP integrity failed")
        for relative, entry in manifest["files"].items():
            if hashlib.sha256(archive.read(relative)).hexdigest() != entry["sha256"]:
                raise ValueError("Checkpoint ZIP content hash mismatch")
    with destination.open("rb") as handle:
        manifest["archive_sha256"] = hashlib.file_digest(handle, "sha256").hexdigest()
    manifest["archive"] = destination.name
    manifest_path = destination.with_suffix(".manifest.json")
    with manifest_path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = package(args.output)
    print(json.dumps({"files": len(result["files"]), "archive": result["archive"], "sha256": result["archive_sha256"]}))
