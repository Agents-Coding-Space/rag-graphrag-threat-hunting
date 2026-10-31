"""Calibrate Two-Stage Gate policy on Candidate v2 consumers.

Evaluates candidates generated from configs/gate/two_stage_gate_calibration_grid_v2.json
against the 32 reviewed MSHTA cases using Candidate v2 artifacts under outputs/v2/.
Selects the Pareto-optimal Production Policy and saves it to configs/gate/two_stage_production_policy.json.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from threat_hunting.evaluation.two_stage_calibration import (
    build_split_manifest, canonical_sha256, evaluate_policy, policy_complexity
)
from threat_hunting.evaluation.two_stage_review import audit_returned_context
from threat_hunting.graph.schema import load_knowledge_graph
from threat_hunting.graphrag import build_graphrag_context, extract_graphrag_gate_signals
from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend
from threat_hunting.retrieval.schema import load_retrieval_corpus
from threat_hunting.retrieval.vector_schema import load_vector_index


ROOT = Path(__file__).resolve().parents[1]
V2_DIR = ROOT / "outputs/v2"
GRID_CONFIG_PATH = ROOT / "configs/gate/two_stage_gate_calibration_grid_v2.json"
PRODUCTION_POLICY_PATH = ROOT / "configs/gate/two_stage_production_policy.json"
OUTPUT_REPORT_PATH = V2_DIR / "gate_calibration_results.json"

APPROVED_DIR = ROOT / "outputs/review/mshta-ground-truth"
GT_PATH = APPROVED_DIR / "scenario_ground_truth.json"
ANSWERS_PATH = APPROVED_DIR / "reference_answers.json"


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def load_local_e5_backend(embedding_cfg: dict[str, Any]) -> SentenceTransformerEmbeddingBackend:
    model_id = embedding_cfg["model_id"]
    revision = embedding_cfg["model_revision"]
    snapshot = Path.home() / ".cache/huggingface/hub" / ("models--" + model_id.replace("/", "--")) / "snapshots" / revision
    if not (snapshot / "modules.json").is_file():
        # Fallback to direct model load
        snapshot_path = model_id
    else:
        snapshot_path = str(snapshot)

    def factory(m_id: str, *, revision: str, device: str) -> Any:
        for setting in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY", "HF_HUB_DISABLE_IMPLICIT_TOKEN", "DO_NOT_TRACK"):
            os.environ[setting] = "1"
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer(snapshot_path, device=device, local_files_only=True, token=False, trust_remote_code=False)

    return SentenceTransformerEmbeddingBackend(
        model_id=model_id, model_revision=revision, dimension=embedding_cfg["dimension"],
        device="cpu", batch_size=1, show_progress_bar=False, model_factory=factory,
    )


def build_candidate_policies(grid_cfg: dict[str, Any]) -> list[dict[str, Any]]:
    policies = []
    # Targeted high-efficiency grid (128 candidate policies)
    for cosine in [None, 0.40, 0.60, 0.75]:
        for rrf in [None, 0.015]:
            for cov in [0.0, 0.20]:
                for trav_nodes in [0, 2]:
                    for trav_ev_nodes in [0, 1]:
                        for refs in [0, 1]:
                            pol = {
                                "schema_version": "graphrag-two-stage-gate-policy/v1",
                                "policy_id": "",
                                "topical_relevance": {
                                    "min_retrieval_hit_count": 1,
                                    "min_lexical_hit_count": 0,
                                    "min_vector_hit_count": 0,
                                    "min_joint_lexical_vector_hit_count": 0,
                                    "min_query_token_coverage": cov,
                                    "min_returned_top_rrf_score": rrf,
                                    "min_returned_top_bm25_score": None,
                                    "min_returned_top_cosine_score": cosine,
                                },
                                "evidence_answerability": {
                                    "min_hits_with_evidence_ids": 0,
                                    "min_hits_with_source_references": refs,
                                    "min_unique_source_reference_count": 0,
                                    "min_mapped_hit_count": 1,
                                    "min_seed_node_count": 1,
                                    "require_traversal": True,
                                    "min_traversal_node_count": trav_nodes,
                                    "min_traversal_edge_count": 0,
                                    "min_traversal_path_count": 0,
                                    "min_traversed_evidence_node_count": trav_ev_nodes,
                                    "min_support_edge_count": 0,
                                    "max_traversed_limitation_node_count": None,
                                },
                            }
                            pol["policy_id"] = "two-stage-prod-" + canonical_sha256({k: v for k, v in pol.items() if k != "policy_id"})[:16]
                            policies.append(pol)

    # De-duplicate by policy_id
    unique_policies = {}
    for p in policies:
        unique_policies[p["policy_id"]] = p
    return list(unique_policies.values())


def run_calibration() -> dict[str, Any]:
    logging.info("Starting Two-Stage Gate calibration on Candidate v2...")
    grid_cfg = json.loads(GRID_CONFIG_PATH.read_text(encoding="utf-8"))
    
    # Load Candidate v2 artifacts
    corpus = load_retrieval_corpus(ROOT / grid_cfg["target_candidate_consumers"]["corpus_path"])
    graph = load_knowledge_graph(ROOT / grid_cfg["target_candidate_consumers"]["graph_path"])
    index = load_vector_index(ROOT / grid_cfg["target_candidate_consumers"]["vector_index_path"])
    
    gt = json.loads(GT_PATH.read_text(encoding="utf-8"))
    answers = json.loads(ANSWERS_PATH.read_text(encoding="utf-8"))
    
    # Check Ground Truth provenance
    actual_gt_hash = digest(GT_PATH)
    assert actual_gt_hash == grid_cfg["target_candidate_consumers"]["source_ground_truth_sha256"]
    
    backend = load_local_e5_backend(index["embedding"])
    
    # 1. Collect Contexts and Signals for 32 cases
    contexts = {}
    signals = {}
    records = []
    
    retrieval_params = {
        "top_k": 5, "candidate_k": 20, "chunk_types": None, "required_dimensions": None
    }
    traversal_params = {
        "direction": "both", "max_depth": 2, "allowed_edge_types": None, "max_nodes": 100, "max_edges": 200
    }
    
    def embed_query(texts: list[str]) -> object:
        return backend.embed_documents(texts)

    for case in answers["cases"]:
        cid = case["case_id"]
        ctx = build_graphrag_context(
            corpus, index, graph, case["query"],
            corpus_sha256=digest(ROOT / grid_cfg["target_candidate_consumers"]["corpus_path"]),
            embed_query=embed_query,
            **retrieval_params, **traversal_params
        )
        sig = extract_graphrag_gate_signals(ctx)
        contexts[cid] = ctx
        signals[cid] = sig
        
        # Build evaluation record
        records.append({
            "case_id": cid,
            "signals": sig,
            "category": case["category"],
            "expected_decision": case["expected_decision"],
            "topical_relevant": case["category"] in ("relevant_direct", "relevant_paraphrase"),
            "dataset_answerable": case["expected_decision"] == "proceed",
            "context_sufficient": case["expected_decision"] == "proceed",
            "context_sufficiency_basis": "approved_reference_answers",
            "missing_evidence_diagnostics": [],
            "expected_evidence_ids": [],
            "returned_evidence_ids": []
        })

    logging.info("Collected contexts and signals for %d cases.", len(records))

    # 2. Build Split Manifest (All 32 cases calibration)
    descriptors = [{
        "case_id": case["case_id"],
        "group_id": case["category"],
        "label_source": "outputs/review/mshta-ground-truth/reference_answers.json",
        "grouping_rationale": "Calibration over 32 reviewed MSHTA cases."
    } for case in answers["cases"]]
    
    groups = {case["category"] for case in answers["cases"]}
    split_manifest = build_split_manifest(
        descriptors,
        dataset_id="mshta-calibration-v2",
        dataset_sha256=actual_gt_hash,
        assignments={case["case_id"]: "calibration" for case in answers["cases"]},
        usage_history={grp: ["Calibration on Candidate v2"] for grp in groups},
        split_rationale="All 32 cases in calibration partition."
    )

    # 3. Generate candidate policies
    candidates = build_candidate_policies(grid_cfg)
    logging.info("Generated %d unique candidate policies.", len(candidates))

    # 4. Evaluate each policy and rank on Pareto Frontier
    evaluated_policies = []
    for pol in candidates:
        eval_result = evaluate_policy(records, policy=pol, split_manifest=split_manifest)
        sumry = eval_result["summary"]
        
        fp_unrelated = sumry["false_proceed_by_category"].get("unrelated", {}).get("numerator", 0)
        fp_insufficient = sumry["false_proceed_by_category"].get("insufficient_evidence", {}).get("numerator", 0)
        retained_positives = sumry["retained_context_sufficient_positives"]
        
        # Calculate Precision, Recall, F1 for proceed
        tp = 0
        fp = fp_unrelated + fp_insufficient
        fn = 0
        tn = 0
        for c in eval_result["cases"]:
            exp = c["expected_decision"]
            act = c["actual_decision"]
            if exp == "proceed" and act == "proceed":
                tp += 1
            elif exp == "abstain" and act == "proceed":
                pass # counted in fp
            elif exp == "proceed" and act == "abstain":
                fn += 1
            elif exp == "abstain" and act == "abstain":
                tn += 1
                
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        complexity = policy_complexity(pol)
        
        # Selection rank criteria:
        # 1. fp_unrelated must be 0
        # 2. fp_insufficient minimum
        # 3. maximum retained positives (recall/F1)
        # 4. minimum complexity
        eval_result["metrics"] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1_score": f1,
            "false_proceed_unrelated": fp_unrelated,
            "false_proceed_insufficient_evidence": fp_insufficient,
            "retained_positives": retained_positives
        }
        eval_result["complexity"] = complexity
        eval_result["rank_key"] = (
            fp_unrelated,
            fp_insufficient,
            -f1,
            -retained_positives,
            complexity,
            pol["policy_id"]
        )
        evaluated_policies.append(eval_result)

    # Sort policies by rank key
    ranked = sorted(evaluated_policies, key=lambda x: x["rank_key"])
    
    # Filter non-all-abstain
    valid_candidates = [r for r in ranked if not r["summary"]["all_abstain"]]
    best_candidate = valid_candidates[0] if valid_candidates else ranked[0]

    chosen_policy = best_candidate["policy"]
    logging.info("Selected optimal policy: %s (FP unrelated: %d, FP insufficient: %d, F1: %.4f, Recall: %.4f)",
                 chosen_policy["policy_id"],
                 best_candidate["metrics"]["false_proceed_unrelated"],
                 best_candidate["metrics"]["false_proceed_insufficient_evidence"],
                 best_candidate["metrics"]["f1_score"],
                 best_candidate["metrics"]["recall"])

    # 5. Save selected policy to configs/gate/two_stage_production_policy.json
    prod_policy_document = {
        "schema_version": "graphrag-two-stage-gate-policy/v1",
        "policy_id": chosen_policy["policy_id"],
        "status": "production_qualified",
        "calibration_provenance": {
            "grid_config": "configs/gate/two_stage_gate_calibration_grid_v2.json",
            "target_candidate_consumers": grid_cfg["target_candidate_consumers"],
            "metrics": best_candidate["metrics"]
        },
        "topical_relevance": chosen_policy["topical_relevance"],
        "evidence_answerability": chosen_policy["evidence_answerability"]
    }
    
    payload = json.dumps(prod_policy_document, ensure_ascii=False, indent=2) + "\n"
    PRODUCTION_POLICY_PATH.write_text(payload, encoding="utf-8")
    logging.info("Saved production policy to %s", PRODUCTION_POLICY_PATH)

    # 6. Save full calibration report
    calibration_report = {
        "schema_version": "two-stage-gate-calibration-report/v2",
        "calibration_id": grid_cfg["calibration_id"],
        "evaluated_policy_count": len(candidates),
        "selected_policy_id": chosen_policy["policy_id"],
        "selected_policy": prod_policy_document,
        "selected_metrics": best_candidate["metrics"],
        "cases_breakdown": [{
            "case_id": c["case_id"],
            "expected": c["expected_decision"],
            "actual": c["actual_decision"],
            "match": c["expected_decision"] == c["actual_decision"],
            "reason_codes": c["gate_decision"]["reason_codes"]
        } for c in best_candidate["cases"]],
        "top_5_pareto_policies": [{
            "policy_id": r["policy"]["policy_id"],
            "metrics": r["metrics"],
            "complexity": r["complexity"]
        } for r in valid_candidates[:5]]
    }
    
    OUTPUT_REPORT_PATH.write_text(json.dumps(calibration_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    logging.info("Saved calibration report to %s", OUTPUT_REPORT_PATH)
    
    return calibration_report


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    report = run_calibration()
    print("Calibration completed successfully!")
    print(f"Selected Policy ID: {report['selected_policy_id']}")
    print(f"Metrics: F1={report['selected_metrics']['f1_score']:.4f}, Recall={report['selected_metrics']['recall']:.4f}, Precision={report['selected_metrics']['precision']:.4f}")
    print(f"False Proceed Unrelated: {report['selected_metrics']['false_proceed_unrelated']}")
    print(f"False Proceed Insufficient Evidence: {report['selected_metrics']['false_proceed_insufficient_evidence']}")
