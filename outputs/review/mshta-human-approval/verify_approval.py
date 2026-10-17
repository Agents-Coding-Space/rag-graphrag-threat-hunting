"""Verify the actual approved JSON, metadata-only diff, provenance and file hashes."""

from copy import deepcopy
from pathlib import Path
import hashlib
import json
import subprocess

from threat_hunting.ground_truth.approval_update import serialize_review_document
from threat_hunting.ground_truth.review_artifacts import validate_review_bundle
from threat_hunting.ground_truth.schema import load_ground_truth_document

from record_approval import AUDIT, NAMES, REVIEW, ROOT


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def main() -> None:
    preflight = json.loads((AUDIT / "preflight.json").read_text(encoding="utf-8"))
    before = [json.loads((AUDIT / f"before_{name}").read_text(encoding="utf-8")) for name in NAMES]
    after = [json.loads((REVIEW / name).read_text(encoding="utf-8")) for name in NAMES]
    gt, answers, manifest = after
    load_ground_truth_document(REVIEW / NAMES[0])
    validate_review_bundle(
        *after, ground_truth_sha256=digest(REVIEW / NAMES[0]),
        reference_answers_sha256=digest(REVIEW / NAMES[1]),
    )
    restored = deepcopy(after)
    for old, current in zip(before, restored, strict=True):
        current["schema_version"] = old["schema_version"]
    for field in ("review_status", "reviewer", "reviewed_at"):
        restored[0]["review"][field] = before[0]["review"][field]
    for field in ("review_status", "human_reviewer", "human_approved_at"):
        restored[1]["review"][field] = before[1]["review"][field]
    restored[1]["sources"]["ground_truth"]["sha256"] = before[1]["sources"]["ground_truth"]["sha256"]
    restored[2]["human_review_status"] = before[2]["human_review_status"]
    for field in ("human_reviewer", "human_approved_at", "approval_provenance"):
        del restored[2][field]
    for name in NAMES[:2]:
        restored[2]["artifacts"][name] = before[2]["artifacts"][name]
    assert restored == before, "Unexpected content/provenance/label change"
    for name, old in zip(NAMES, before, strict=True):
        previous = digest(AUDIT / f"before_{name}")
        assert previous == hashlib.sha256(serialize_review_document(old)).hexdigest()
        assert manifest["approval_provenance"]["previous_artifacts"][name] == previous
    mutable = {(REVIEW / name).relative_to(ROOT).as_posix() for name in NAMES}
    inventory = {
        path.relative_to(ROOT).as_posix()
        for folder in ("data", "outputs", "benchmarks", "configs")
        for path in (ROOT / folder).rglob("*")
        if path.is_file() and AUDIT not in path.parents and "__pycache__" not in path.parts
    }
    inventory.update(("AGENTS.md", "PROJECT_CONTEXT.md", "PROJECT_PROGRESS.md", "README.md"))
    assert inventory == set(preflight["hashes"]), {
        "added": sorted(inventory - set(preflight["hashes"])),
        "missing": sorted(set(preflight["hashes"]) - inventory),
    }
    hashes_after = {}
    unexpected_changes = []
    for relative, expected in preflight["hashes"].items():
        actual = digest(ROOT / relative)
        hashes_after[relative] = actual
        if actual != expected and relative not in mutable:
            unexpected_changes.append(relative)
    assert not unexpected_changes, unexpected_changes
    for group in ("original_sources", "baseline_inputs"):
        for path, expected in manifest[group].items():
            assert hashes_after[path] == expected, f"Provenance mismatch: {path}"
    for name, expected in manifest["artifacts"].items():
        assert digest(REVIEW / name) == expected, f"Artifact hash mismatch: {name}"
    assert not subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=ROOT), "Staging changed"
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == preflight["head"]
    assert subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip() == preflight["branch"]
    subprocess.run(["git", "diff", "--check"], cwd=ROOT, check=True)
    result = {
        "json_and_bundle_validation": "passed", "metadata_only_content_preservation": "passed",
        "provenance_validation": "passed", "protected_files_checked": len(preflight["hashes"]),
        "unchanged_protected_files": len(preflight["hashes"]) - len(mutable),
        "unexpected_hash_changes": unexpected_changes,
        "reviewer": gt["review"]["reviewer"], "reviewed_at": gt["review"]["reviewed_at"],
        "case_count": len(answers["cases"]), "decision_counts": answers["metadata"]["decision_counts"],
        "staging_empty": True, "branch_and_head_unchanged": True, "git_diff_check": "passed",
        "protected_inventory_unchanged": True,
        "artifact_hashes": {
            name: {"before": digest(AUDIT / f"before_{name}"), "after": digest(REVIEW / name)} for name in NAMES
        },
        "hashes_after": hashes_after,
    }
    (AUDIT / "postflight.json").write_bytes(serialize_review_document(result))
    print(json.dumps({key: value for key, value in result.items() if key != "hashes_after"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
