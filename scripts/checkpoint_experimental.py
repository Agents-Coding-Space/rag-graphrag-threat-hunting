"""Snapshot non-secret experiment files without requiring Git metadata."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {"node_modules", "__pycache__", ".git", ".venv", "dist", ".pytest_cache"}


def snapshot(destination: Path) -> dict:
    """Hash sources and saved artifacts; never inspect environment files or keys."""
    destination = destination.resolve()
    files = []
    for name in ("src", "scripts", "tests", "configs", "benchmarks", "docs", "frontend", "outputs"):
        base = ROOT / name
        if not base.exists():
            continue
        for path in base.rglob("*"):
            rel = path.relative_to(ROOT)
            if not path.is_file() or any(part in SKIP_DIRS for part in rel.parts):
                continue
            if destination.parent in path.resolve().parents or path.resolve() == destination:
                continue
            if path.name.startswith(".env") or path.suffix.lower() in {".log", ".pyc", ".pem", ".key"}:
                continue
            files.append(path)
    files.extend(path for path in ROOT.iterdir() if path.is_file() and path.suffix in {".md", ".toml", ".py"})
    entries = {}
    for path in sorted(set(files)):
        with path.open("rb") as handle:
            value = hashlib.file_digest(handle, "sha256").hexdigest()
        entries[path.relative_to(ROOT).as_posix()] = {"sha256": value, "bytes": path.stat().st_size}
    git = {}
    for field, args in (("branch", ["branch", "--show-current"]), ("head", ["rev-parse", "HEAD"]), ("status", ["status", "--short"])):
        result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False)
        git[field] = result.stdout.strip() if result.returncode == 0 else None
    git["metadata_available"] = git["head"] is not None
    payload = {"schema_version": "experimental-checkpoint/v1", "created_utc": datetime.now(timezone.utc).isoformat(),
               "git": git, "exclusions": ["environment files", "keys", "logs", "caches", "dependencies", "frontend build", "current review directory"],
               "files": entries}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    json.loads(destination.read_text(encoding="utf-8"))
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = snapshot(args.output)
    print(json.dumps({"files": len(result["files"]), "git": result["git"]}))
