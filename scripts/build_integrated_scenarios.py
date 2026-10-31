"""Build versioned common consumers for all three scenarios, entirely offline."""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from scripts.inventory_offline_inputs import write_json
from threat_hunting.cti.ingestion import ingest_collection
from threat_hunting.evidence.integrated import authentication_adapter, regsvr32_adapter, attach_cti, finish, enrich_consumers
from threat_hunting.evidence.process_network import read_aligned, correlate_process_network
from threat_hunting.evidence.slice_provenance import digest
from threat_hunting.graph import build_knowledge_graph, load_knowledge_graph
from threat_hunting.ground_truth.schema import load_ground_truth_document
from threat_hunting.retrieval import build_retrieval_corpus, build_vector_index, load_retrieval_corpus, load_vector_index
from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend
from threat_hunting.sigma.process_offline import evaluate_process_rule


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def display(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "outputs/offline/requirements_gap_20261030_v1")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/integrated/20261030_v1")
    parser.add_argument("--registry", type=Path, default=ROOT / "configs/runtime_artifacts_integrated_v1.json")
    parser.add_argument("--auth-cti-sources", type=Path)
    parser.add_argument("--profile-id", default="integrated-three-scenarios-cti-v1")
    args = parser.parse_args()
    base, source = args.output, args.source
    base.mkdir(parents=True,exist_ok=True)
    if (base / "consumers").exists(): raise FileExistsError("Consumer version already exists")
    inventory = read(source / "input_inventory.json")
    def selected(filename):
        found = [i for i in inventory["inputs"] if i["filename"] == filename]
        preferred = [i for i in found if "selected" in Path(i["path"]).parts]
        if not found: raise FileNotFoundError(filename)
        if len(found) > 1 and len({i['sha256'] for i in found}) != 1: raise ValueError(f"Ambiguous input: {filename}")
        result = preferred[0] if preferred else found[0]
        if digest(Path(result["path"])) != result["sha256"]: raise ValueError(f"Input hash changed: {filename}")
        return result
    previous_manifest = read(source / "artifact_manifest.json")
    for relative, expected in previous_manifest["artifact_sha256"].items():
        if digest(source / relative) != expected: raise ValueError(f"Prior offline artifact changed: {relative}")
    reg = selected("empire_launcher_sct_regsvr32_2020-07-21232741.json")
    rows, stats = read_aligned(Path(reg["path"]), Path(reg["canonical_path"]), reg["sha256"], reg["canonical_sha256"])
    correlation = correlate_process_network(rows)
    sigma_files = [selected(filename) for filename in ("proc_creation_win_regsvr32_http_ip_pattern.yml", "proc_creation_win_regsvr32_susp_child_process.yml", "proc_creation_win_regsvr32_susp_parent.yml")]
    sigma = [evaluate_process_rule(Path(i["path"]), rows) for i in sigma_files]
    write_json(base / "regsvr32_full_survey.json", {"schema_version": "regsvr32-full-survey/v1", "stats": stats, "correlation": correlation, "sigma": sigma})
    auth_cti = ingest_collection(args.auth_cti_sources or base / "cti_auth_sources", read(ROOT / "configs/knowledge/cti_auth_integrated_v1.json"), base / "cti_auth")
    previous_cti = read(source / "cti/cti_corpus.json")
    techniques = read(source / "purplesharp_v2/mitre_resolution.json")["techniques"]
    def provenance(sid, items):
        return [{"input_id": stable, "input_type": kind, "path": display(path) if path.is_relative_to(ROOT) else str(path.resolve()),
                 "schema_version": version, "sha256": digest(path), "scenario_id": sid}
                for stable, kind, version, path in items]
    auth_path = source / "purplesharp_v2"
    auth = authentication_adapter(*[read(auth_path / f) for f in ("authentication_survey.json", "authentication_correlation.json", "password_spraying_candidates.json", "logon_investigation.json", "sigma_rc4_evaluation.json", "scenario_ground_truth.json")], techniques,
        provenance("purplesharp-ad", [("authentication-draft", "authentication_evidence", "authentication-ground-truth-draft/v1", auth_path / "scenario_ground_truth.json"),
                                    ("auth-survey", "authentication_evidence", "authentication-survey/v1", auth_path / "authentication_survey.json"),
                                    ("auth-correlation", "authentication_correlation", "authentication-correlation/v1", auth_path / "authentication_correlation.json")]))
    regdoc = regsvr32_adapter(correlation, sigma, techniques, provenance("regsvr32-c2", [("raw-regsvr32", "raw_mordor", "jsonl", Path(reg["path"])),
                         ("canonical-regsvr32", "canonical_events", "canonical-event/v2", Path(reg["canonical_path"])),
                         ("regsvr32-full-evidence", "evidence", "regsvr32-full-survey/v1", base / "regsvr32_full_survey.json")]))
    mshta_path = ROOT / "outputs/review/mshta-ground-truth/scenario_ground_truth.json"
    mshta = deepcopy(load_ground_truth_document(mshta_path))
    mshta["schema_version"] = "scenario-ground-truth/v3"
    mshta["scenario"]["scenario_name"] = "3.3.2 Kịch bản thực thi PowerShell nghi vấn"
    mshta["review"] = {"review_status": "pending_human_review", "reviewer": None, "reviewed_at": None, "decisions": [],
                      "notes": ["New integrated consumers are draft; prior source bundle approval is historical and not transferred."]}
    mshta["input_provenance"] += provenance("mshta-powershell", [("reviewed-mshta-source", "reviewed_ground_truth", "scenario-ground-truth/v2", mshta_path)])
    # Resolve paths against the discovered originals, not absent workspace data/.
    for item in mshta["input_provenance"]:
        matching = [i for i in inventory["inputs"] if i["filename"] == Path(item["path"]).name and i["sha256"] == item["sha256"]]
        if matching: item["path"] = next((i for i in matching if "selected" in Path(i["path"]).parts), matching[0])["path"]
    docs = {"purplesharp-ad": auth, "mshta-powershell": mshta, "regsvr32-c2": regdoc}
    legacy_index = load_vector_index(ROOT / "outputs/v2/retrieval/mshta-powershell/vector_index_e5.json")
    embedding = legacy_index["embedding"]
    if (embedding["model_id"], embedding["model_revision"]) != ("intfloat/multilingual-e5-small", "614241f622f53c4eeff9890bdc4f31cfecc418b3"):
        raise ValueError("Unexpected pinned embedding model")
    for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY", "HF_HUB_DISABLE_IMPLICIT_TOKEN", "DO_NOT_TRACK"):
        os.environ[name] = "1"
    def local_model(model_id, *, revision, device):
        from sentence_transformers import SentenceTransformer
        snapshot = Path.home() / ".cache/huggingface/hub" / ("models--" + model_id.replace("/", "--")) / "snapshots" / revision
        if not (snapshot / "modules.json").is_file(): raise FileNotFoundError("Pinned local E5 snapshot missing")
        return SentenceTransformer(str(snapshot), device=device, local_files_only=True, token=False, trust_remote_code=False)
    backend = SentenceTransformerEmbeddingBackend(model_id=embedding["model_id"], model_revision=embedding["model_revision"], dimension=embedding["dimension"],
                                                 device="cpu", batch_size=32, show_progress_bar=False, model_factory=local_model)
    registry = {"schema_version": "runtime-scenario-artifacts/v1", "profile_id": args.profile_id, "review_status": "pending_human_review", "scenarios": {}}
    counts = {}
    for sid, doc in docs.items():
        cti = auth_cti if sid == "purplesharp-ad" else previous_cti
        cti_path = base / "cti_auth/cti_corpus.json" if sid == "purplesharp-ad" else source / "cti/cti_corpus.json"
        source_id = {"purplesharp-ad": "microsoft-password-spray", "mshta-powershell": "redcanary-mshta", "regsvr32-c2": "uptycs-regsvr32"}[sid]
        sigma_names={
            'purplesharp-ad':['win_security_susp_rc4_kerberos.yml'],
            'mshta-powershell':['proc_creation_win_mshta_susp_child_processes.yml','proc_creation_win_mshta_susp_execution.yml'],
            'regsvr32-c2':[item['filename'] for item in sigma_files],
        }[sid]
        knowledge_inputs=[selected('enterprise-attack.json')]+[selected(name) for name in sigma_names]
        for item in knowledge_inputs:
            if not any(i['sha256']==item['sha256'] for i in doc['input_provenance']):
                doc['input_provenance']+=provenance(sid,[("knowledge-"+item['filename'],"mitre_stix" if item['filename'].endswith('.json') else "sigma_rule",
                                                     "stix/2.1" if item['filename'].endswith('.json') else "sigma-yaml",Path(item['path']))])
        if sid=='purplesharp-ad':
            item=selected('purplesharp_ad_playbook_I_2020-10-22042947.json')
            doc['input_provenance']+=provenance(sid,[("raw-authentication","raw_mordor","jsonl",Path(item['path'])),
                                                  ("canonical-authentication","canonical_events","canonical-event/v2",Path(item['canonical_path']))])
        doc['input_provenance']+=provenance(sid,[("external-cti-context","cti_context","cti-context-corpus/v1",cti_path)])
        attach_cti(doc, cti["sources"], [c for c in cti["chunks"] if c["source_id"] == source_id], display(cti_path), digest(cti_path))
        finish(doc)
        directory = base / "consumers" / sid
        directory.mkdir(parents=True, exist_ok=False)
        gt_path, corpus_path, graph_path, index_path = [directory / f for f in ("scenario_ground_truth.json", "retrieval_corpus.json", "knowledge_graph.json", "vector_index_e5.json")]
        write_json(gt_path, doc)
        corpus = build_retrieval_corpus(doc, source_ground_truth_path=display(gt_path), source_ground_truth_sha256=digest(gt_path))
        graph = build_knowledge_graph(doc, ground_truth_path=display(gt_path), ground_truth_sha256=digest(gt_path))
        enrich_consumers(doc, corpus, graph)
        write_json(corpus_path, corpus); write_json(graph_path, graph)
        index = build_vector_index(corpus, corpus_path=display(corpus_path), corpus_sha256=digest(corpus_path), embedding=embedding, embed_documents=backend.embed_documents)
        write_json(index_path, index)
        load_ground_truth_document(gt_path); load_retrieval_corpus(corpus_path); load_knowledge_graph(graph_path); load_vector_index(index_path)
        paths = {field: display(path) for field,path in (("gt_path",gt_path),("corpus_path",corpus_path),("graph_path",graph_path),("index_path",index_path))}
        registry["scenarios"][sid] = {"paths": paths, "sha256": {p.name:digest(p) for p in (gt_path,corpus_path,graph_path,index_path)}, "review_status":"pending_human_review"}
        counts[sid] = {"facts":len(doc["facts"]),"evidence_groups":len(doc["evidence"]),"cti_chunks":sum(c['chunk_type']=='cti_report' for c in corpus['chunks']),"chunks":len(corpus['chunks']),"nodes":len(graph['nodes']),"edges":len(graph['edges'])}
    write_json(args.registry, registry)
    write_json(base / "build_manifest.json", {"schema_version":"integrated-build/v1","counts":counts,"embedding":embedding,"registry_sha256":digest(args.registry),
        "regsvr32_records":stats,"regsvr32_selected_connections":len(correlation['connections']),"ambiguous_links":len(correlation['ambiguous_links']),
        "sigma_results":[{"file":r['rule_filename'],"matches":len(r['matches']),"indeterminate":len(r['indeterminate'])} for r in sigma],"llm_calls":0,"review_status":"pending_human_review"})
    print(json.dumps(counts))


if __name__ == "__main__": main()
