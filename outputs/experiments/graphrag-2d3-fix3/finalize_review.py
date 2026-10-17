"""Verify saved FIX3 development results and package an immutable review closure.

Phases are explicit: this helper never runs a benchmark, pytest, embeddings or
models. Test commands and progress prose must be supplied from actual root work.
"""
from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import version
import importlib.util
import json
from pathlib import Path
import platform
import re
import subprocess
from zipfile import ZipFile

from threat_hunting.evaluation.review_package import create_review_zip, verify_review_zip
from threat_hunting.evaluation.two_stage_review import load_approved_evaluation_bundle
from threat_hunting.graph import load_knowledge_graph
from threat_hunting.graphrag.gate_signals import extract_graphrag_gate_signals
from threat_hunting.graphrag.query_context import validate_query_evidence_context
from threat_hunting.graphrag.query_context_v2 import (
    enrich_query_context_v2, upgrade_evidence_context,
    validate_query_evidence_context_v2,
)
from threat_hunting.graphrag.query_gate import assess_query_aware_gate
from threat_hunting.graphrag.query_policy import assess_combined_query_gate
from threat_hunting.graphrag.query_requirements import validate_query_requirements_document
from threat_hunting.graphrag.query_requirements_v2 import validate_query_requirements_document_v2
from threat_hunting.retrieval import load_retrieval_corpus, load_vector_index


ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
REVIEW = ROOT / "outputs/review/graphrag-parser-policy-fix3"
ZIP = ROOT / "outputs/review/graphrag_parser_policy_fix3_review.zip"
FIX1 = ROOT / "outputs/experiments/graphrag-2d3-fix1"
FIX2 = ROOT / "outputs/experiments/graphrag-2d3-fix2"
ARMS = ("E0", "E1", "E2", "E3", "E4")
NEW_FILES = (
    "src/threat_hunting/graphrag/query_requirements_v2.py",
    "src/threat_hunting/graphrag/query_context_v2.py",
    "src/threat_hunting/graphrag/query_support_v2.py",
    "src/threat_hunting/graphrag/query_policy.py",
    "scripts/evaluate_parser_policy_fix3.py",
    "tests/test_query_requirements_v2.py",
    "tests/test_query_context_v2.py",
    "tests/test_query_support_v2.py",
    "tests/test_query_policy.py",
    "tests/test_parser_policy_fix3_runner.py",
)


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8"))
    assert read(path) == value


def encoded(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True, encoding="utf-8")


def load_runner():
    spec = importlib.util.spec_from_file_location("fix3_frozen_runner_for_verification", ROOT / "scripts/evaluate_parser_policy_fix3.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def capture_test_results() -> None:
    """Read actual completed logs and exact commands, never reconstruct a run."""
    declared = read(OUT / "test_commands.json")
    assert isinstance(declared, dict) and isinstance(declared.get("final_runs"), list)
    assert {item["scope"] for item in declared["final_runs"]} == {"focused", "related regression", "full suite"}
    results = []
    for run in declared["final_runs"]:
        assert run["exit_code"] == 0 and isinstance(run["command"], str) and run["command"].strip()
        path = OUT / run["log"]
        assert path.parent == OUT and path.name in {"focused_final.log", "regression_final.log", "full_final.log"}
        payload = path.read_bytes()
        decoded = payload.decode("utf-16") if payload.startswith((b"\xff\xfe", b"\xfe\xff")) else payload.decode("utf-8-sig")
        summaries = [line.strip() for line in decoded.splitlines() if re.search(r"\d+ passed.* in [0-9.]+s", line)]
        assert summaries, f"No completed pytest summary in {path.name}"
        summary = summaries[-1]
        counts = {}
        for key, expression in (("passed", r"(\d+) passed"), ("subtests_passed", r"(\d+) subtests passed"),
                                ("failed", r"(\d+) failed"), ("skipped", r"(\d+) skipped"), ("errors", r"(\d+) errors?")):
            match = re.search(expression, summary)
            counts[key] = int(match.group(1)) if match else 0
        assert counts["passed"] > 0 and counts["failed"] == counts["errors"] == 0, summary
        # Only this new derived log is normalized; pytest output text is exact.
        path.write_bytes(decoded.encode("utf-8"))
        results.append({**run, **counts, "seconds": float(re.search(r" in ([0-9.]+)s", summary).group(1)),
                        "actual_pytest_summary": summary, "log_sha256": digest(path)})
    write(REVIEW / "tests.json", {
        "schema_version": "parser-policy-fix3-test-results/v1", "final_runs": results,
        "earlier_development_runs": declared.get("earlier_development_runs", []),
        "experiment_commands": declared.get("experiment_commands", []),
        "logs_normalized_to_utf8_without_text_changes": True,
        "no_test_or_experiment_is_claimed_as_independent_or_heldout": True,
    })


def protected_audit() -> dict:
    baseline = read(OUT / "preflight.json")
    assert git("branch", "--show-current").strip() == baseline["branch"]
    assert git("rev-parse", "HEAD").strip() == baseline["head"]
    assert not git("diff", "--cached", "--name-only")
    entries = {name: {"before": original, "after": digest(ROOT / name)}
               for name, original in baseline["protected_hashes"].items()}
    for value in entries.values():
        value["unchanged"] = value["before"] == value["after"]
    changed = [name for name, value in entries.items() if not value["unchanged"]]
    assert set(changed) <= {"PROJECT_PROGRESS.md"}, changed
    original_progress = (OUT / "before/PROJECT_PROGRESS.md").read_bytes()
    assert (ROOT / "PROJECT_PROGRESS.md").read_bytes().startswith(original_progress)
    current = set(git("ls-files", "--cached", "--others", "--exclude-standard").splitlines())
    assert current - set(entries) == set(NEW_FILES), current - set(entries)
    result = {
        "schema_version": "parser-policy-fix3-protected-hashes/v1",
        "baseline_file_count": len(entries), "unchanged_count": len(entries) - len(changed),
        "changed_existing_files": changed, "original_progress_bytes_preserved_as_prefix": True,
        "all_existing_source_tests_fixtures_raw_approved_FIX1_FIX2_artifacts_and_old_zips_unchanged": all(
            item["unchanged"] for name, item in entries.items() if name != "PROJECT_PROGRESS.md"),
        "entries": entries,
    }
    write(OUT / "protected_hashes_after.json", result)
    return result


def pointer_value(document: object, pointer: str):
    assert isinstance(pointer, str) and pointer.startswith("/")
    value = document
    for escaped in pointer.split("/")[1:]:
        part = escaped.replace("~1", "/").replace("~0", "~")
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def _validate_traces(context: dict, support: dict) -> int:
    count = 0
    for requirement in support["requirements"]:
        for trace in requirement["traces"]:
            actual = pointer_value(context, trace["context_pointer"])
            assert trace["quote"] == (actual if isinstance(actual, str) else encoded(actual))
            wrapper_pointer = trace["context_pointer"].split("/payload", 1)[0]
            item = pointer_value(context, wrapper_pointer)
            assert item["item_id"] == trace["item_id"] and item["kind"] == trace["kind"]
            assert trace["source_pointer"] == item["payload"]["source"]["json_pointer"]
            count += 1
    return count


def validate_results() -> dict:
    """Replay only saved contexts/requirements against frozen runtime sources."""
    gt, _, _ = load_approved_evaluation_bundle(ROOT / "outputs/review/mshta-ground-truth")
    runner = load_runner()
    config = read(OUT / "experiment_configuration.json")
    freeze = read(OUT / "pre_evaluation_freeze.json")
    for name, expected in config["runtime_code_sha256"].items():
        assert digest(ROOT / name) == expected
    assert config["runtime_code_sha256"] == freeze["runtime_code_sha256"]
    assert digest(ROOT / "scripts/evaluate_parser_policy_fix3.py") == config["runner_sha256"] == freeze["runner_sha256"]
    assert digest(OUT / "combined_policy.json") == config["frozen_policy_sha256"] == freeze["combined_policy_sha256"]
    assert digest(OUT / "design_note.md") == config["design_note_sha256"] == freeze["design_note_sha256"]
    assert freeze["benchmark_results_existed"] is False
    assert digest(FIX2 / "enriched_contexts.json") == config["frozen_FIX2_contexts_sha256"]
    for name, expected in config["source_hashes"].items():
        assert digest(FIX1 / name) == expected
    corpus = load_retrieval_corpus(FIX1 / "retrieval_corpus.json")
    graph = load_knowledge_graph(FIX1 / "knowledge_graph.json")
    index = load_vector_index(FIX1 / "vector_index.json")
    helper = runner.old_helpers()
    helper.check_index_bindings(corpus, index, digest(FIX1 / "retrieval_corpus.json"))
    requirements, contexts, decisions, signals = (read(OUT / name) for name in (
        "requirements.json", "contexts.json", "decisions.json", "signals.json"))
    old_contexts, old_queries = read(FIX2 / "enriched_contexts.json"), read(FIX2 / "query_requirements.json")
    old_decisions = read(FIX2 / "decisions.json")["D"]
    policy, legacy_policy = read(OUT / "combined_policy.json"), read(FIX2 / "fixed_policy.json")
    assert policy == config["combined_policy"] and legacy_policy == config["legacy_policy"]
    assert set(requirements) == set(contexts) == set(decisions) == set(signals) == set(ARMS)
    traces, replays, authenticated = 0, 0, 0
    audit = read(ROOT / "outputs/review/graphrag-two-stage-gate-calibration/consumer_audit.json")
    descriptors = {case["case_id"]: case for case in audit["cases"]}
    adjudication = read(OUT / "external_context_adjudication.json")
    for arm in ARMS:
        assert set(contexts[arm]) == set(old_contexts) and len(contexts[arm]) == 32
        for identifier, context in contexts[arm].items():
            requested, saved = requirements[arm][identifier], decisions[arm][identifier]
            if arm == "E0":
                validate_query_requirements_document(requested)
                validate_query_evidence_context(context)
            else:
                (validate_query_requirements_document if arm == "E2" else validate_query_requirements_document_v2)(requested)
                validate_query_evidence_context_v2(context)
            assert context["initial_context"] == old_contexts[identifier]["initial_context"]
            if arm in {"E0", "E1", "E2", "E3"}:
                assert context["final_items"] == old_contexts[identifier]["final_items"]
                assert context["supplementary_items"] == old_contexts[identifier]["supplementary_items"]
            # Authentication/inventory construction does not add positive items.
            upgraded = upgrade_evidence_context(context, corpus, graph)
            assert upgraded["final_items"] == context["final_items"]
            authenticated += 1
            if arm in {"E0", "E2"}:
                assert requested == old_queries[identifier]
            if arm == "E0":
                checked = assess_query_aware_gate(context, requested, policy=legacy_policy)
                assert checked == old_decisions[identifier]["trace"]
            elif arm == "E1":
                checked = runner.and_legacy_v2(context, requested, legacy_policy, max_chain_depth=policy["max_chain_depth"])
            else:
                checked = assess_combined_query_gate(context, requested, corpus=corpus, graph=graph,
                    policy=policy, legacy_policy=legacy_policy)
            assert checked == saved["trace"]
            assert saved["decision"] == checked["final_decision"]
            assert saved["abstention_stage"] == checked["abstention_stage"]
            assert saved["reason_codes"] == checked["reason_codes"]
            assert checked["security_conclusion_made"] is False
            assert signals[arm][identifier]["ranked_retrieval"] == extract_graphrag_gate_signals(context["initial_context"])
            assert signals[arm][identifier]["final_evidence_context"] == runner.context_metrics(context)
            traces += _validate_traces(context, checked["support_assessment"])
            if "verification_guards" in checked:
                traces += _validate_traces(context, checked["verification_guards"])
            if arm == "E4":
                assert context == enrich_query_context_v2(context["initial_context"], corpus, graph, requested,
                    budget=config["context_budget"], max_chain_depth=policy["max_chain_depth"])
            assert adjudication[arm][identifier] == helper.external_diagnostic(context, descriptors[identifier], audit["answer_units"], gt)
            replays += 1
    json_files = [path for path in OUT.rglob("*.json") if "before" not in path.relative_to(OUT).parts]
    for path in json_files:
        read(path)
    result = {
        "json_readback_count": len(json_files), "decision_replays": replays,
        "saved_all_five_arms_replay_matches": True, "E0_exact_saved_FIX2_D_trace_matches": True,
        "replay_is_consistency_verification_not_an_independent_experiment": True,
        "trace_field_quotes_item_ids_and_source_pointers_verified": traces,
        "authenticated_context_count": authenticated,
        "fixed_context_upgrades_change_inventory_only": True,
        "E4_supplementation_replay_matches_without_ranking_or_model_call": True,
        "runtime_runner_policy_and_design_hashes_match_pre_evaluation_freeze": True,
        "external_AI_diagnostic_rubric_replay_matches": True,
        "legacy_FIX2_sources_fixtures_artifacts_verified_separately_by_protected_hash_audit": True,
    }
    write(OUT / "validation_results.json", result)
    return result


def append_progress() -> None:
    """Append root-reviewed UTF-8 prose, preserving every original progress byte."""
    original = (OUT / "before/PROJECT_PROGRESS.md").read_bytes()
    appendix = (OUT / "progress_appendix.md").read_bytes()
    appendix.decode("utf-8", errors="strict")
    assert appendix.strip(), "A reviewed progress appendix is required"
    target = ROOT / "PROJECT_PROGRESS.md"
    if target.read_bytes() == original + appendix:
        return
    assert target.read_bytes() == original, "Refusing to overwrite non-baseline progress changes"
    target.write_bytes(original + appendix)
    assert target.read_bytes().startswith(original)


def package() -> None:
    assert not ZIP.exists(), "Refusing to overwrite an existing FIX3 review ZIP"
    for name in ("report.md", "per_case_report.md", "tests.json"):
        assert (REVIEW / name).is_file(), name
    tests = read(REVIEW / "tests.json")
    assert len(tests["final_runs"]) == 3 and all(run["exit_code"] == 0 for run in tests["final_runs"])
    protected, validation = protected_audit(), validate_results()
    check = subprocess.run(["git", "diff", "--check"], cwd=ROOT, capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    dependencies = {
        "python": platform.python_version(), "platform": platform.platform(),
        "installed_versions": {name: version(name) for name in (
            "PyYAML", "pytest", "sentence-transformers", "transformers", "torch", "numpy")},
        "new_dependencies": [], "model_calls": 0, "corpus_or_index_rebuilds": 0,
    }
    write(REVIEW / "dependencies.json", dependencies)
    raw_names = {
        "purplesharp_ad_playbook_I_2020-10-22042947.json",
        "empire_launcher_sct_regsvr32_2020-07-21232741.json",
        "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json", "enterprise-attack.json",
    }
    selected = [name for name in protected["entries"] if name.startswith("data/")
                and (Path(name).name in raw_names or "/sigma/selected/" in name)]
    selected += ["outputs/review/mshta-ground-truth/" + name for name in (
        "scenario_ground_truth.json", "reference_answers.json", "review_manifest.json")]
    selected += ["outputs/experiments/graphrag-2d3-fix1/" + name for name in (
        "retrieval_corpus.json", "knowledge_graph.json", "vector_index.json")]
    selected += ["outputs/experiments/graphrag-2d3-fix2/" + name for name in (
        "enriched_contexts.json", "query_requirements.json", "decisions.json", "fixed_policy.json", "experiment_configuration.json", "ablation_results.json")]
    selected += ["outputs/review/" + name for name in (
        "graphrag_two_stage_gate_calibration_review.zip", "graphrag_ground_truth_v2_consumer_sync_review.zip", "graphrag_query_aware_answerability_review.zip")]
    lines = ["# Protected SHA-256 before/after", "",
             "Protected hashes below are identical before/after FIX3. The full baseline audit is in `outputs/experiments/graphrag-2d3-fix3/protected_hashes_after.json`.", "",
             "| Protected path | SHA-256 before = after |", "| --- | --- |"]
    for name in selected:
        item = protected["entries"][name]
        assert item["unchanged"], name
        lines.append(f"| `{name}` | `{item['before']}` |")
    (REVIEW / "protected_hash_summary.md").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    files: dict[str, Path] = {}

    def add(path: Path, name: str | None = None) -> None:
        key = name or path.relative_to(ROOT).as_posix()
        assert key not in files, key
        files[key] = path

    for folder in ("src", "tests"):
        for path in sorted((ROOT / folder).rglob("*")):
            if path.is_file() and not {"__pycache__", ".pytest_cache"}.intersection(path.parts) and path.suffix not in {".pyc", ".pyo"}:
                add(path)
    for name in ("pyproject.toml", "AGENTS.md", "PROJECT_CONTEXT.md", "PROJECT_PROGRESS.md", "README.md"):
        add(ROOT / name)
    for path in sorted((ROOT / "scripts").glob("*.py")):
        add(path)
    add(OUT / "before/PROJECT_PROGRESS.md", "fix3_baseline/PROJECT_PROGRESS.md")
    for path in sorted(OUT.rglob("*")):
        if path.is_file() and "before" not in path.relative_to(OUT).parts and "__pycache__" not in path.parts and path.suffix in {".json", ".md", ".py", ".log"}:
            add(path)
    for name in ("retrieval_corpus.json", "knowledge_graph.json", "vector_index.json"):
        add(FIX1 / name)
    # The frozen research runner verifies every protected FIX2 dependency and
    # approved-review file before evaluation. Include that entire exact closure,
    # including prior development snapshots, rather than only the six JSON inputs.
    baseline = read(OUT / "preflight.json")
    for name in sorted(baseline["protected_hashes"]):
        if name.startswith(("outputs/experiments/graphrag-2d3-fix2/", "outputs/review/mshta-ground-truth/")):
            add(ROOT / name)
    add(ROOT / "outputs/review/graphrag-two-stage-gate-calibration/consumer_audit.json")
    for path in sorted(REVIEW.iterdir()):
        if path.is_file() and path.name not in {"review_inventory.json", "zip_verification.json"}:
            add(path)
    baseline = read(OUT / "preflight.json")
    inventory = {
        "schema_version": "parser-policy-fix3-review-inventory/v1", "review_date": "2026-10-17",
        "baseline": {key: baseline[key] for key in ("branch", "head", "working_tree", "staging")},
        "new_change_scope": {"new_source_tests_runner": list(NEW_FILES), "existing_source_modified": [], "progress": "append_only"},
        "final_working_tree": git("status", "--short"), "staging_empty": not git("diff", "--cached", "--name-only"),
        "tests": tests, "dependencies": dependencies,
        "diff_check": {"command": "git diff --check", "exit_code": check.returncode, "output": check.stdout + check.stderr},
        "experiment_configuration": read(OUT / "experiment_configuration.json"),
        "pre_evaluation_freeze": read(OUT / "pre_evaluation_freeze.json"),
        "ablation_results": read(OUT / "ablation_results.json"), "validation": validation,
        "protected_summary": {key: value for key, value in protected.items() if key != "entries"},
        "protected_hashes_before_after": "outputs/experiments/graphrag-2d3-fix3/protected_hashes_after.json",
        "status": "development_ablation_complete_awaiting_FIX3_review_no_independent_validation",
        "package_payloads_excluding_inventory_itself": {
            name: {"sha256": digest(path), "size": path.stat().st_size} for name, path in sorted(files.items())},
        "inventory_self_hash_and_archive_hash_recorded_in_external_zip_verification_sidecar": True,
    }
    write(REVIEW / "review_inventory.json", inventory)
    add(REVIEW / "review_inventory.json")
    verification = create_review_zip(ZIP, files)
    verify_review_zip(ZIP, {entry["filename"]: entry["sha256"] for entry in verification["entries"]})
    with ZipFile(ZIP) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(set(archive.namelist()))
        assert all(archive.getinfo(entry["filename"]).file_size == entry["size"] for entry in verification["entries"])
    verification.update(
        archive=ZIP.relative_to(ROOT).as_posix(), archive_size=ZIP.stat().st_size,
        entry_count=len(verification["entries"]), testzip_result=None,
        safe_unique_regular_entries=True, payload_sizes_and_hashes_match=True,
        inventory_sha256=digest(REVIEW / "review_inventory.json"),
    )
    write(REVIEW / "zip_verification.json", verification)
    print(json.dumps({key: value for key, value in verification.items() if key != "entries"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("tests", "audit", "progress", "package"), required=True)
    args = parser.parse_args()
    REVIEW.mkdir(parents=True, exist_ok=True)
    if args.phase == "tests":
        capture_test_results()
    elif args.phase == "audit":
        protected = protected_audit()
        print(json.dumps({key: value for key, value in protected.items() if key != "entries"}, indent=2))
        print(json.dumps(validate_results(), indent=2))
    elif args.phase == "progress":
        append_progress()
    else:
        package()
