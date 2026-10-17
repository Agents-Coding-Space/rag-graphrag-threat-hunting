"""Verify protected inputs and frozen replay, then package the finished review.

Run only after reports, test_results.json and the append-only progress update
are stable. This script performs no model/retrieval calls or held-out execution.
It writes only protected_hashes.json, review_inventory.json, the review ZIP and
zip_verification.json. The inventory excludes its own hash; the external ZIP
sidecar records that hash and the final archive hash without a circular digest.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
REVIEW = Path(__file__).resolve().parent
ZIP_PATH = ROOT / "outputs/review/graphrag_two_stage_gate_calibration_review.zip"
PROGRESS = "PROJECT_PROGRESS.md"
BACKUP = REVIEW / "before_PROJECT_PROGRESS.md"
EXPECTED_PROTECTED_COUNT = 5017
RUNNER = "scripts/calibrate_two_stage_gate.py"
ADDITIONAL_FILES = (
    "tests/test_two_stage_calibration.py",
    "tests/test_two_stage_review.py",
    "tests/test_calibrate_two_stage_gate_cli.py",
    "tests/test_review_package.py",
    "tests/test_ground_truth_approval.py",
    "tests/fixtures/graphrag/two_stage_gate/expected_two_stage_gate_decisions.json",
    "tests/fixtures/ground_truth/scenario_ground_truth_minimal.json",
    "pyproject.toml",
    "PROJECT_PROGRESS.md",
    "docs/human_approval.md",
)
REQUIRED_REVIEW_FILES = (
    "preflight.json", "consumer_audit.json", "split_manifest.json",
    "retrieval_configuration.json", "frozen_retrieval_configuration.json",
    "selection_plan.json", "signals.json", "contexts.json", "query_embeddings.json",
    "external_context_adjudication.json", "candidate_policies.json",
    "calibration_results.json", "selected_policy.json", "evaluation_code_hashes.json",
    "policy_freeze.json", "replay_result.json", "heldout_status.json",
    "proposed_test_set.json", "proposed_test_notes.md", "test_results.json",
    "report.md", "per_case_report.md", "before_PROJECT_PROGRESS.md",
)


class FinalizationError(ValueError):
    """A stable input changed, an invariant failed, or a package is unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FinalizationError(message)


def no_links(path: Path) -> None:
    for component in (path, *path.parents):
        info = component.lstat()
        require(not stat.S_ISLNK(info.st_mode), f"Symlink path forbidden: {component}")
        require(not getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
                f"Reparse path forbidden: {component}")


def relative_path(name: str) -> Path:
    require(isinstance(name, str) and bool(name), "Repo-relative path must be nonempty text")
    require(not PurePosixPath(name).is_absolute() and not PureWindowsPath(name).drive
            and "\\" not in name and ":" not in name
            and all(part not in ("", ".", "..") for part in name.split("/")),
            f"Unsafe repo-relative path: {name!r}")
    path = ROOT / name
    no_links(path)
    require(stat.S_ISREG(path.stat().st_mode), f"Expected a regular file: {name}")
    require(path.resolve().is_relative_to(ROOT), f"Path escapes repository: {name}")
    return path


def relative_name(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def file_sha(path: Path) -> str:
    no_links(path)
    require(stat.S_ISREG(path.stat().st_mode), f"Expected a regular file: {path}")
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def read_json(path: Path) -> Any:
    no_links(path)
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(name: str, document: object) -> None:
    require(name in ("protected_hashes.json", "review_inventory.json", "zip_verification.json"),
            f"Finalizer attempted an unauthorized output: {name}")
    path = REVIEW / name
    if path.exists():
        no_links(path)
    path.write_text(json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2) + "\n",
                    encoding="utf-8", newline="\n")
    require(read_json(path) == document, f"JSON round-trip failed: {path}")


def git(*arguments: str) -> str:
    completed = subprocess.run(["git", *arguments], cwd=ROOT, text=True, encoding="utf-8",
                               capture_output=True, check=False)
    require(completed.returncode == 0,
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()} {completed.stdout.strip()}")
    return completed.stdout


def repo_state(preflight: dict[str, Any]) -> dict[str, Any]:
    state = {"branch": git("branch", "--show-current").strip(),
             "head": git("rev-parse", "HEAD").strip(),
             "staging": git("diff", "--cached", "--name-only"),
             "working_tree": git("status", "--short"),
             "diff_check": git("diff", "--check")}
    require(state["branch"] == preflight["branch"], "Branch changed since preflight")
    require(state["head"] == preflight["head"], "HEAD changed since preflight")
    require(state["staging"] == preflight["staging"] == "", "Staging must remain empty")
    require(not state["diff_check"], "git diff --check was not clean")
    return state


def protected_state(preflight: dict[str, Any]) -> dict[str, Any]:
    before = preflight["protected_hashes"]
    require(len(before) == EXPECTED_PROTECTED_COUNT,
            f"Expected {EXPECTED_PROTECTED_COUNT} protected baseline hashes, found {len(before)}")
    after = {name: file_sha(relative_path(name)) for name in sorted(before)}
    changed = [name for name in sorted(before) if before[name] != after[name]]
    require(set(changed) <= {PROGRESS}, f"Protected files changed unexpectedly: {changed}")
    before_progress = relative_path(relative_name(BACKUP)).read_bytes()
    require(hashlib.sha256(before_progress).hexdigest() == before[PROGRESS],
            "Progress backup differs from the original preflight bytes")
    current_progress = relative_path(PROGRESS).read_bytes()
    require(current_progress.startswith(before_progress),
            "PROJECT_PROGRESS.md must preserve every original byte as a prefix")
    return {
        "schema_version": "two-stage-calibration-protected-hashes/v1",
        "baseline": {"path": relative_name(REVIEW / "preflight.json"),
                     "sha256": file_sha(REVIEW / "preflight.json")},
        "protected_file_count": len(before), "unchanged_count": len(before) - len(changed),
        "changed_count": len(changed), "changed_files": changed,
        "allowed_changes": {PROGRESS: "Append-only project progress; original bytes preserved"},
        "progress_append_check": {
            "backup_path": relative_name(BACKUP), "backup_sha256": before[PROGRESS],
            "original_byte_count": len(before_progress), "current_byte_count": len(current_progress),
            "appended_byte_count": len(current_progress) - len(before_progress),
            "original_prefix_preserved": True,
        },
        "before": before, "after": after,
    }


def source_paths_from_runner() -> dict[str, str]:
    """Read the exact static source allowlist without importing a model runner."""
    tree = ast.parse(relative_path(RUNNER).read_text(encoding="utf-8"))
    matches = [node.value for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == "SOURCE_PATHS" for target in node.targets)]
    require(len(matches) == 1, "Runner must declare exactly one static SOURCE_PATHS")
    paths = ast.literal_eval(matches[0])
    require(isinstance(paths, dict) and set(paths) == {"ground_truth", "answers", "manifest", "dataset", "corpus", "graph", "index"},
            "Runner SOURCE_PATHS must name exactly the seven approved evaluation sources")
    for name in paths.values():
        relative_path(name)
    require(len(set(paths.values())) == 7, "Runner source artifacts must be distinct")
    return paths


def walk_regular_files(folder: Path) -> list[Path]:
    no_links(folder)
    result = []
    for directory, children, names in os.walk(folder, followlinks=False):
        children[:] = sorted(child for child in children if child != "__pycache__"
                             and not child.startswith("test-tmp") and child not in (".pytest_cache", ".cache"))
        for child in children:
            no_links(Path(directory) / child)
        for name in sorted(names):
            path = Path(directory) / name
            no_links(path)
            require(stat.S_ISREG(path.stat().st_mode), f"Special review file forbidden: {path}")
            result.append(path)
    return result


def verify_frozen_replay() -> dict[str, Any]:
    """Re-evaluate only the saved calibration signals under the frozen policy."""
    from threat_hunting.evaluation.two_stage_calibration import (
        canonical_sha256, evaluate_policy, validate_freeze,
    )
    from threat_hunting.graphrag import extract_graphrag_gate_signals

    policy = read_json(REVIEW / "selected_policy.json")
    code_hashes = read_json(REVIEW / "evaluation_code_hashes.json")
    current_code_names = {RUNNER, *(relative_name(path) for path in walk_regular_files(ROOT / "src")
                                   if path.suffix == ".py")}
    require(set(code_hashes) == current_code_names, "Frozen source closure differs from current source files")
    for name, expected in code_hashes.items():
        require(file_sha(relative_path(name)) == expected, f"Frozen evaluation source changed: {name}")
    code_digest = canonical_sha256(code_hashes)
    config = read_json(REVIEW / "frozen_retrieval_configuration.json")
    base_config = read_json(REVIEW / "retrieval_configuration.json")
    extra_bindings = {
        "query_embeddings_sha256": "query_embeddings.json",
        "external_context_adjudication_sha256": "external_context_adjudication.json",
        "consumer_audit_sha256": "consumer_audit.json",
        "quarantined_test_manifest_sha256": "proposed_test_set.json",
    }
    require(set(config) == set(base_config) | set(extra_bindings), "Unexpected frozen retrieval configuration fields")
    require(all(config[key] == value for key, value in base_config.items()),
            "Frozen retrieval configuration differs from predeclared retrieval configuration")
    for key, filename in extra_bindings.items():
        require(config[key] == file_sha(REVIEW / filename), f"Frozen artifact changed: {filename}")
    source_paths = source_paths_from_runner()
    require(set(config["sources"]) == set(source_paths), "Frozen source inventory differs from runner allowlist")
    for key, name in source_paths.items():
        require(config["sources"][key]["path"] == name
                and config["sources"][key]["sha256"] == file_sha(relative_path(name)),
                f"Frozen source artifact changed: {name}")
    split = read_json(REVIEW / "split_manifest.json")
    require(all(value == "calibration" for value in split["assignments"].values()),
            "This review finalizer must not execute held-out cases")
    criteria = read_json(REVIEW / "selection_plan.json")
    signals = read_json(REVIEW / "signals.json")
    contexts = read_json(REVIEW / "contexts.json")
    reviewed_dataset = read_json(relative_path(source_paths["dataset"]))
    reviewed_cases = {case["case_id"]: case for case in reviewed_dataset["cases"]}
    require(len(reviewed_dataset["cases"]) == len(reviewed_cases) == 32,
            "This fixed review must contain exactly the 32 approved historical cases")
    require(set(contexts) == set(signals) == set(split["assignments"]) == set(reviewed_cases),
            "Saved contexts/signals differ from calibration membership")
    for case_id, context in contexts.items():
        require(context["query"]["text"] == signals[case_id]["query"]["text"] == reviewed_cases[case_id]["query"],
                f"Saved context/signal query differs from the approved current query: {case_id}")
        require(extract_graphrag_gate_signals(context) == signals[case_id],
                f"Returned context no longer reproduces saved signals: {case_id}")
    query_embeddings = read_json(REVIEW / "query_embeddings.json")
    model_inputs = query_embeddings["vectors_by_exact_model_input"]
    expected_model_inputs = {config["embedding"]["query_prefix"] + case["query"]
                             for case in reviewed_cases.values()}
    require(len(expected_model_inputs) == len(model_inputs) == 32
            and set(model_inputs) == expected_model_inputs,
            "Cached embedding inputs must be exactly the 32 prefixed approved current queries")
    require(query_embeddings["embedding"] == config["embedding"]
            and query_embeddings["input_contract"] == config["query_input_boundary"],
            "Cached embedding model or input contract differs from frozen retrieval configuration")
    frozen = read_json(REVIEW / "policy_freeze.json")
    bindings = {"retrieval_config": config, "split_manifest": split,
                "evaluation_code_sha256": code_digest, "criteria": criteria,
                "calibration_signals": signals}
    validate_freeze(frozen, policy, **bindings)
    adjudication = read_json(REVIEW / "external_context_adjudication.json")
    records = [{**case, "signals": signals[case["case_id"]]} for case in adjudication["cases"]]
    replay = evaluate_policy(records, policy=policy, freeze=frozen, replay=True, **bindings)
    calibration = read_json(REVIEW / "calibration_results.json")
    chosen = calibration["selected_result"]
    require(chosen is not None and chosen["policy"] == policy == calibration["selected_policy"],
            "Selected policy differs between saved calibration artifacts")
    require(replay["cases"] == chosen["cases"] and replay["summary"] == chosen["summary"],
            "Frozen replay differs from calibration cases or metrics")
    saved_replay = read_json(REVIEW / "replay_result.json")
    require(saved_replay["status"] == "identical_saved_signal_replay"
            and saved_replay["result"] == replay and saved_replay["heldout_run"] is False,
            "Current replay differs from the previously saved frozen replay")
    heldout = read_json(REVIEW / "heldout_status.json")
    require(heldout["status"] == "not_run" and heldout["labels_approved"] is False
            and heldout["heldout_queries_embedded"] == 0 and heldout["heldout_gate_calls"] == 0,
            "Held-out status contradicts the permitted diagnostic-only review")
    require(calibration["policy_qualified"] is False, "Stale consumers cannot qualify this policy")
    return {"frozen_bindings_verified": True, "policy_lock_sha256": frozen["lock_sha256"],
            "evaluation_code_sha256": code_digest, "code_file_hashes": code_hashes,
            "calibration_replay_identical": True, "case_count": len(records),
            "current_query_only_boundary_verified": True,
            "approved_current_query_count": len(reviewed_cases),
            "cached_query_embedding_count": len(model_inputs),
            "proposed_query_ids_in_calibration": 0,
            "heldout_run": False, "new_embedding_calls": 0, "new_llm_calls": 0}


def entry_inventory(files: dict[str, Path]) -> list[dict[str, Any]]:
    return [{"filename": name, "sha256": file_sha(path), "size": path.stat().st_size}
            for name, path in sorted(files.items())]


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    from threat_hunting.evaluation.review_package import create_review_zip, verify_review_zip

    for name in REQUIRED_REVIEW_FILES:
        relative_path(relative_name(REVIEW / name))
    preflight = read_json(REVIEW / "preflight.json")
    state = repo_state(preflight)
    protected = protected_state(preflight)
    frozen_verification = verify_frozen_replay()
    write_json("protected_hashes.json", protected)
    config = read_json(REVIEW / "frozen_retrieval_configuration.json")
    split = read_json(REVIEW / "split_manifest.json")
    audit = read_json(REVIEW / "consumer_audit.json")
    calibration = read_json(REVIEW / "calibration_results.json")
    tests = read_json(REVIEW / "test_results.json")
    source_paths = source_paths_from_runner()
    files = {relative_name(path): path for path in walk_regular_files(ROOT / "src") if path.suffix == ".py"}
    for name in (RUNNER, *ADDITIONAL_FILES, *source_paths.values()):
        files[name] = relative_path(name)
    for path in walk_regular_files(REVIEW):
        if path.name not in ("zip_verification.json", "review_inventory.json"):
            files[relative_name(path)] = path
    inventory = {
        "schema_version": "graphrag-two-stage-gate-calibration-review-inventory/v1",
        "client_date": preflight["client_date"],
        "baseline": {key: preflight[key] for key in ("branch", "head", "working_tree", "staging")},
        "final_repository_state": state,
        "preflight": {"path": relative_name(REVIEW / "preflight.json"), "sha256": file_sha(REVIEW / "preflight.json")},
        "source_artifacts": config["sources"],
        "test_results": tests,
        "test_results_source": {"path": relative_name(REVIEW / "test_results.json"), "sha256": file_sha(REVIEW / "test_results.json")},
        "retrieval_configuration": config,
        "data_usage_history": split["usage_history"],
        "split_manifest": {"path": relative_name(REVIEW / "split_manifest.json"), "sha256": file_sha(REVIEW / "split_manifest.json")},
        "protected_before_after": {
            "path": relative_name(REVIEW / "protected_hashes.json"),
            "sha256": file_sha(REVIEW / "protected_hashes.json"),
            "protected_file_count": protected["protected_file_count"],
            "unchanged_count": protected["unchanged_count"], "changed_count": protected["changed_count"],
            "changed_files": protected["changed_files"], "full_hash_maps_in_referenced_file": True,
            "progress_original_prefix_preserved": True,
        },
        "frozen_replay_verification": frozen_verification,
        "policy_selection": {key: calibration[key] for key in (
            "selection_rule", "selection_status", "selected_policy", "policy_qualified",
            "meets_calibration_error_constraints", "calibration_acceptance_failures")},
        "heldout": read_json(REVIEW / "heldout_status.json"),
        "consumer_evidence_findings": audit["stale_evidence_findings"],
        "evaluation_limits": [
            "All 32 historical cases were exposed to development; calibration is not independent validation.",
            "Frozen corpus/graph/index contain material stale evidence; no qualified or production-ready policy is claimed.",
            "Returned-context sufficiency uses an explicit conservative AI rubric, with unknown labels reported separately.",
            "New AI-proposed stress probes are not approved independent held-out labels and were not evaluated or embedded.",
            "The proposed test manifest is hashed as quarantined bytes; its labels do not select thresholds.",
            "Replay repeats saved calibration signals under identical locked inputs; it is not a new independent experiment.",
            "No raw data, approved labels, corpus, graph, indexes or production CLI were modified.",
            "No LLM/UI integration or production policy deployment was performed.",
        ],
        "archive_integrity_design": {
            "archive_path": relative_name(ZIP_PATH),
            "member_paths": "Repo-relative POSIX paths preserve the saved replay layout.",
            "own_inventory_hash_excluded": True,
            "excluded_archive_sidecar": relative_name(REVIEW / "zip_verification.json"),
            "sidecar_contains_inventory_and_final_archive_hashes": True,
            "raw_logs_packaged": False,
            "read_only_source_snapshot_count": len(source_paths),
        },
        "file_inventory_excluding_this_inventory_and_archive_sidecar": entry_inventory(files),
    }
    write_json("review_inventory.json", inventory)
    files[relative_name(REVIEW / "review_inventory.json")] = REVIEW / "review_inventory.json"
    package = create_review_zip(ZIP_PATH, files)
    expected = {entry["filename"]: entry["sha256"] for entry in package["entries"]}
    verify_review_zip(ZIP_PATH, expected)
    # Check every original input again after packaging, in addition to the
    # package API's per-source checks. No protected file is ever written here.
    after_package = protected_state(preflight)
    require(after_package == protected, "Protected bytes changed during final packaging")
    for key, source in config["sources"].items():
        require(file_sha(relative_path(source["path"])) == source["sha256"],
                f"Source artifact changed after ZIP verification: {key}")
    repo_state(preflight)
    sidecar = {
        "schema_version": "graphrag-two-stage-gate-review-zip-verification/v1",
        "archive_path": relative_name(ZIP_PATH), "archive_sha256": package["archive_sha256"],
        "archive_size": ZIP_PATH.stat().st_size, "entry_count": len(package["entries"]),
        "entries": package["entries"], "testzip_passed": package["testzip_passed"],
        "unique_normalized_names": True, "no_symlinks_or_special_members": True,
        "no_absolute_paths_or_traversal": True, "payload_hashes_match_exact_source_bytes": True,
        "source_hashes_rechecked_after_packaging": True,
        "inventory_path": relative_name(REVIEW / "review_inventory.json"),
        "inventory_sha256": file_sha(REVIEW / "review_inventory.json"),
        "protected_hashes_sha256": file_sha(REVIEW / "protected_hashes.json"),
        "sidecar_not_in_archive": True,
    }
    write_json("zip_verification.json", sidecar)
    print(json.dumps({
        "protected_file_count": protected["protected_file_count"],
        "unchanged_count": protected["unchanged_count"], "changed_count": protected["changed_count"],
        "changed_files": protected["changed_files"], "source_snapshot_count": len(source_paths),
        "code_file_count": len(frozen_verification["code_file_hashes"]),
        "replay_identical": True, "zip_entry_count": len(package["entries"]),
        "archive_sha256": package["archive_sha256"], "inventory_sha256": sidecar["inventory_sha256"],
        "protected_hashes_sha256": sidecar["protected_hashes_sha256"],
        "zip_verification_sha256": file_sha(REVIEW / "zip_verification.json"),
        "testzip_passed": True,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        raise SystemExit(f"Review finalization failed: {type(exc).__name__}: {exc}") from exc
