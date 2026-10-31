"""Build corrected, explicitly versioned canonical slices without replacing consumers."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from threat_hunting.evidence.purplesharp_ad import extract_purplesharp_evidence
from threat_hunting.evidence.regsvr32_c2 import extract_regsvr32_evidence
from threat_hunting.evidence.slice_provenance import digest
from threat_hunting.graph import build_knowledge_graph, load_knowledge_graph
from threat_hunting.ground_truth.schema import load_ground_truth_document
from threat_hunting.retrieval import build_retrieval_corpus, build_vector_index, load_retrieval_corpus, load_vector_index
from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend


SLICES = {
    "purplesharp-ad": {
        "canonical": "outputs/canonical/mordor-selected-v2/files/purplesharp_ad_playbook_i_2020_10_22042947--d86d22f0c02a/canonical_events.jsonl",
        "sha256": "72b954c1bed401f77d666151abcdd5487c71473773de2128019e556c6a1b9305",
        "source_filenames": ["purplesharp_ad_playbook_I_2020-10-22042947.json", "win_security_susp_rc4_kerberos.yml", "enterprise-attack.json"],
        "extract": extract_purplesharp_evidence,
    },
    "regsvr32-c2": {
        "canonical": "outputs/canonical/mordor-selected-v2/files/empire_launcher_sct_regsvr32_2020_07_21232741--8b619d07ad79/canonical_events.jsonl",
        "sha256": "f46667756b6bf1e869b0791597f3363190a0fa41eb3e76bc2b21587e4074e114",
        "source_filenames": ["empire_launcher_sct_regsvr32_2020-07-21232741.json", "proc_creation_win_regsvr32_http_ip_pattern.yml", "proc_creation_win_regsvr32_susp_child_process.yml", "proc_creation_win_regsvr32_susp_parent.yml", "enterprise-attack.json"],
        "extract": extract_regsvr32_evidence,
    },
}


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def write_artifacts(
    ground_truth: dict[str, Any], output_dir: Path, *, embedding: dict[str, Any],
    embed_documents: Callable[..., object],
) -> dict[str, Any]:
    """Create one new artifact directory; never overwrite an existing artifact."""
    output_dir = output_dir.resolve()
    for protected in ("outputs/canonical", "outputs/ground_truth", "outputs/retrieval", "outputs/graph", "outputs/review/live_llm_functional_smoke"):
        if output_dir.is_relative_to((ROOT / protected).resolve()):
            raise ValueError(f"Output directory is protected: {protected}")
    if output_dir.exists():
        raise FileExistsError(f"Versioned output already exists: {output_dir.name}")
    # Artifact provenance uses repository paths; test callers may use a fresh
    # workspace directory too, without committing machine-specific temp paths.
    def display(path: Path) -> str:
        try:
            return _relative(path)
        except ValueError:
            return path.name
    output_dir.mkdir(parents=True, exist_ok=False)
    gt_path = output_dir / "scenario_ground_truth.json"
    corpus_path = output_dir / "retrieval_corpus.json"
    graph_path = output_dir / "knowledge_graph.json"
    index_path = output_dir / "vector_index_e5.json"

    def save(path: Path, document: dict[str, Any]) -> str:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(document, ensure_ascii=False, indent=2) + "\n")
        return digest(path)

    gt_hash = save(gt_path, ground_truth)
    load_ground_truth_document(gt_path)
    corpus = build_retrieval_corpus(ground_truth, source_ground_truth_path=display(gt_path), source_ground_truth_sha256=gt_hash)
    corpus_hash = save(corpus_path, corpus)
    load_retrieval_corpus(corpus_path)
    graph = build_knowledge_graph(ground_truth, ground_truth_path=display(gt_path), ground_truth_sha256=gt_hash)
    save(graph_path, graph)
    load_knowledge_graph(graph_path)
    index = build_vector_index(corpus, corpus_path=display(corpus_path), corpus_sha256=corpus_hash, embedding=embedding, embed_documents=embed_documents)
    save(index_path, index)
    load_vector_index(index_path)
    return {"paths": {name: display(path) for name, path in (("gt_path", gt_path), ("corpus_path", corpus_path), ("graph_path", graph_path), ("index_path", index_path))},
            "sha256": {path.name: digest(path) for path in (gt_path, corpus_path, graph_path, index_path)},
            "counts": {"evidence_groups": len(ground_truth["evidence"]), "observations": sum(len(item["observations"]) for item in ground_truth["evidence"]), "chunks": len(corpus["chunks"]), "nodes": len(graph["nodes"]), "edges": len(graph["edges"]), "index_records": len(index["records"])}}


def main(scenario_id: str | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    if scenario_id is None:
        parser.add_argument("--scenario", choices=tuple(SLICES), required=True)
    parser.add_argument("--output-root", type=Path, required=True, help="New version directory; existing artifacts are never replaced")
    args = parser.parse_args()
    selected = scenario_id or args.scenario
    config = SLICES[selected]
    canonical = ROOT / config["canonical"]
    if digest(canonical) != config["sha256"]:
        raise ValueError(f"Canonical hash mismatch for {selected}; build stopped")
    old_paths = [ROOT / f"outputs/ground_truth/{selected}/scenario_ground_truth.json", ROOT / f"outputs/retrieval/{selected}/retrieval_corpus.json", ROOT / f"outputs/graph/{selected}/knowledge_graph.json", ROOT / f"outputs/retrieval/{selected}/vector_index_e5.json"]
    protected_before = {_relative(path): digest(path) for path in old_paths + [canonical]}
    legacy_index = load_vector_index(old_paths[-1])
    embedding = legacy_index["embedding"]
    if embedding["model_id"] != "intfloat/multilingual-e5-small" or embedding["model_revision"] != "614241f622f53c4eeff9890bdc4f31cfecc418b3":
        raise ValueError("Unexpected embedding model/revision; build stopped")
    for setting in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY", "HF_HUB_DISABLE_IMPLICIT_TOKEN", "DO_NOT_TRACK"):
        os.environ[setting] = "1"

    def local_model(model_id: str, *, revision: str, device: str) -> object:
        from sentence_transformers import SentenceTransformer
        snapshot = Path.home() / ".cache/huggingface/hub" / ("models--" + model_id.replace("/", "--")) / "snapshots" / revision
        if not (snapshot / "modules.json").is_file():
            raise FileNotFoundError("Pinned local E5 model snapshot is unavailable; no download attempted")
        return SentenceTransformer(str(snapshot), device=device, local_files_only=True, token=False, trust_remote_code=False)

    backend = SentenceTransformerEmbeddingBackend(model_id=embedding["model_id"], model_revision=embedding["model_revision"], dimension=embedding["dimension"], device="cpu", batch_size=32, show_progress_bar=False, model_factory=local_model)
    ground_truth = config["extract"](canonical)
    result = write_artifacts(ground_truth, args.output_root / selected, embedding=embedding, embed_documents=backend.embed_documents)
    protected_after = {path: digest(ROOT / path) for path in protected_before}
    if protected_after != protected_before:
        raise ValueError("Protected input/artifact hash changed during build")
    data_root = ROOT / "data"
    availability = []
    for filename in config["source_filenames"]:
        found = sorted(data_root.rglob(filename)) if data_root.is_dir() else []
        availability.append({"filename": filename, "status": "unverified" if found else "unavailable", "paths": [_relative(path) for path in found], "used_for_evaluation_or_resolution": False})
    result.update({"schema_version": "corrected-slice-build/v1", "scenario_id": selected, "review_status": "pending_human_review", "source_availability": availability, "protected_hashes_before": protected_before, "protected_hashes_after": protected_after, "embedding": embedding})
    manifest = args.output_root / selected / "build_manifest.json"
    with manifest.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({"scenario_id": selected, "manifest": _relative(manifest), **result["counts"]}))


if __name__ == "__main__":
    main()
