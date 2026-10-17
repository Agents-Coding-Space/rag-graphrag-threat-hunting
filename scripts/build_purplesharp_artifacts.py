"""Build Ground Truth, Retrieval Corpus, Knowledge Graph and 25 Reference Answers for PurpleSharp AD."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from threat_hunting.evidence.purplesharp_ad import extract_purplesharp_evidence
from threat_hunting.graph import build_knowledge_graph
from threat_hunting.retrieval import build_retrieval_corpus, build_vector_index
from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_PATH = ROOT / "outputs/canonical/mordor-selected-v2/files/purplesharp_ad_playbook_i_2020_10_22042947--d86d22f0c02a/canonical_events.jsonl"

OUT_GT_DIR = ROOT / "outputs/ground_truth/purplesharp-ad"
OUT_RET_DIR = ROOT / "outputs/retrieval/purplesharp-ad"
OUT_GRAPH_DIR = ROOT / "outputs/graph/purplesharp-ad"

GT_FILE = OUT_GT_DIR / "scenario_ground_truth.json"
CORPUS_FILE = OUT_RET_DIR / "retrieval_corpus.json"
GRAPH_FILE = OUT_GRAPH_DIR / "knowledge_graph.json"
INDEX_FILE = OUT_RET_DIR / "vector_index_e5.json"
ANSWERS_FILE = OUT_GT_DIR / "reference_answers.json"


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def generate_25_reference_answers(gt: dict[str, Any]) -> dict[str, Any]:
    """Generate exactly 25 balanced reference questions for PurpleSharp AD scenario."""
    # 12 proceed, 7 insufficient_evidence, 6 unrelated
    cases = [
        # 1-12: PROCEED (Relevant Direct & Paraphrase)
        {
            "case_id": "ps-01-command-line",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Which command line parameters were passed to PurpleSharp.exe?",
            "reference_answer": "PurpleSharp.exe was executed with '/t T1110.003,T1558.003,T1135,T1021.006'.",
        },
        {
            "case_id": "ps-02-parent-process",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "What process spawned PurpleSharp.exe?",
            "reference_answer": "cmd.exe spawned PurpleSharp.exe.",
        },
        {
            "case_id": "ps-03-targeted-accounts",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Which domain user accounts were targeted during the adversary simulation?",
            "reference_answer": "Accounts including pgustavo, lrodriguez, sbeavers, mscott, and pbeesly were targeted.",
        },
        {
            "case_id": "ps-04-domain-controller",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "What is the hostname of the target domain controller in the PurpleSharp log?",
            "reference_answer": "The target domain controller hostname is MORDORDC.theshire.local.",
        },
        {
            "case_id": "ps-05-password-spraying-technique",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Which MITRE ATT&CK technique ID corresponds to the password spraying simulation in PurpleSharp?",
            "reference_answer": "T1110.003 corresponds to Password Spraying.",
        },
        {
            "case_id": "ps-06-kerberoasting-technique",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Which MITRE technique ID corresponds to Kerberoasting in the PurpleSharp command line?",
            "reference_answer": "T1558.003 corresponds to Kerberoasting (Steal or Forge Kerberos Tickets).",
        },
        {
            "case_id": "ps-07-network-share-discovery",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Did PurpleSharp simulate network share discovery?",
            "reference_answer": "Yes, technique T1135 (Network Share Discovery) was specified in the /t parameter.",
        },
        {
            "case_id": "ps-08-winrm-technique",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Was Windows Remote Management WinRM requested by PurpleSharp?",
            "reference_answer": "Yes, technique T1021.006 (WinRM) was passed as a simulation parameter.",
        },
        {
            "case_id": "ps-09-cmd-spawns-purplesharp-evidence",
            "category": "relevant_paraphrase",
            "expected_decision": "proceed",
            "query": "Tiến trình nào đã khởi chạy công cụ PurpleSharp trên máy chủ miền?",
            "reference_answer": "cmd.exe đã khởi chạy PurpleSharp.exe.",
        },
        {
            "case_id": "ps-10-vi-password-spraying-hoi",
            "category": "relevant_paraphrase",
            "expected_decision": "proceed",
            "query": "Hệ thống có phát hiện hành vi tấn công dò quét mật khẩu Password Spraying không?",
            "reference_answer": "Có, công cụ PurpleSharp đã được thực thi với tham số kỹ thuật T1110.003 (Password Spraying).",
        },
        {
            "case_id": "ps-11-vi-kerberoasting-hoi",
            "category": "relevant_paraphrase",
            "expected_decision": "proceed",
            "query": "Kỹ thuật trích xuất vé dịch vụ Kerberoasting nào đã được yêu cầu?",
            "reference_answer": "Kỹ thuật T1558.003 (Kerberoasting) đã được yêu cầu thực thi.",
        },
        {
            "case_id": "ps-12-vi-target-users",
            "category": "relevant_paraphrase",
            "expected_decision": "proceed",
            "query": "Những tài khoản người dùng Active Directory nào bị nhắm tới?",
            "reference_answer": "Các tài khoản bao gồm pgustavo, lrodriguez, sbeavers, mscott, pbeesly trên miền theshire.local.",
        },

        # 13-19: INSUFFICIENT EVIDENCE (7 cases - negative/unrecorded telemetry)
        {
            "case_id": "ps-13-password-cracked",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "Which user password was successfully cracked and dumped to disk by PurpleSharp?",
            "reference_answer": "Insufficient evidence: Log contains simulation launch commands, but no plaintext passwords or successful password cracking results are recorded in telemetry.",
        },
        {
            "case_id": "ps-14-kerberos-ticket-payload",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "What was the decrypted plaintext service ticket hash retrieved during Kerberoasting?",
            "reference_answer": "Insufficient evidence: Process creation telemetry does not include decrypted ticket payload contents.",
        },
        {
            "case_id": "ps-15-exfiltrated-c2-ip",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "To which external public IP did PurpleSharp exfiltrate the Active Directory database?",
            "reference_answer": "Insufficient evidence: No external C2 exfiltration network connection is observed for PurpleSharp in this dataset.",
        },
        {
            "case_id": "ps-16-registry-persistence",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "Which registry run key was installed by PurpleSharp to maintain persistence?",
            "reference_answer": "Insufficient evidence: No persistence registry keys were created or recorded in telemetry.",
        },
        {
            "case_id": "ps-17-vi-mat-khau-lo",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "Mật khẩu của tài khoản Administrator đã bị lộ ra ngoài qua file nào?",
            "reference_answer": "Không đủ bằng chứng: Log không ghi nhận việc mật khẩu bị lộ ra file.",
        },
        {
            "case_id": "ps-18-vi-downtime",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "Dịch vụ Domain Controller có bị ngừng hoạt động (downtime) do cuộc tấn công không?",
            "reference_answer": "Không đủ bằng chứng: Không có sự kiện ghi nhận dịch vụ Domain Controller bị sập hoặc downtime.",
        },
        {
            "case_id": "ps-19-vi-ransomware-encryption",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "Các file trên máy chủ miền có bị mã hóa đòi tiền chuộc bởi PurpleSharp không?",
            "reference_answer": "Không đủ bằng chứng: PurpleSharp là công cụ mô phỏng playbook, không có hành vi mã hóa file ransomware.",
        },

        # 20-25: UNRELATED (6 cases - outside security & scope)
        {
            "case_id": "ps-20-unrelated-weather",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "What is the average rainfall in Hanoi during October?",
            "reference_answer": "Unrelated: The question is unrelated to cybersecurity log telemetry.",
        },
        {
            "case_id": "ps-21-unrelated-recipe",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "How do you cook traditional Vietnamese pho bo?",
            "reference_answer": "Unrelated: The question is outside cybersecurity and threat hunting scope.",
        },
        {
            "case_id": "ps-22-unrelated-sports",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "Who won the FIFA World Cup final in 2022?",
            "reference_answer": "Unrelated: Sports query unrelated to system logs.",
        },
        {
            "case_id": "ps-23-vi-thoi-tiet",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "Dự báo thời tiết ngày mai có mưa rào không?",
            "reference_answer": "Không liên quan: Câu hỏi ngoài phạm vi giám sát an toàn thông tin.",
        },
        {
            "case_id": "ps-24-vi-lap-trinh",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "Cách viết thuật toán quicksort bằng ngôn ngữ C++?",
            "reference_answer": "Không liên quan: Câu hỏi lập trình cơ bản ngoài phạm vi log hệ thống.",
        },
        {
            "case_id": "ps-25-vi-chung-khoan",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "Giá vàng và chỉ số chứng khoán VN-Index hôm nay tăng hay giảm?",
            "reference_answer": "Không liên quan: Câu hỏi tài chính ngoài phạm vi an ninh mạng.",
        },
    ]

    return {
        "schema_version": "reference-answers/v1",
        "scenario_id": "purplesharp-ad",
        "metadata": {
            "total_cases": len(cases),
            "decision_counts": {
                "proceed": sum(1 for c in cases if c["expected_decision"] == "proceed"),
                "abstain": sum(1 for c in cases if c["expected_decision"] == "abstain"),
            },
            "category_counts": {
                "relevant_direct": sum(1 for c in cases if c["category"] == "relevant_direct"),
                "relevant_paraphrase": sum(1 for c in cases if c["category"] == "relevant_paraphrase"),
                "insufficient_evidence": sum(1 for c in cases if c["category"] == "insufficient_evidence"),
                "unrelated": sum(1 for c in cases if c["category"] == "unrelated"),
            },
        },
        "cases": cases,
    }


def main() -> None:
    for d in (OUT_GT_DIR, OUT_RET_DIR, OUT_GRAPH_DIR):
        d.mkdir(parents=True, exist_ok=True)

    print("1. Extracting PurpleSharp Ground Truth from canonical events...")
    gt = extract_purplesharp_evidence(CANONICAL_PATH)
    gt_payload = json.dumps(gt, ensure_ascii=False, indent=2) + "\n"
    GT_FILE.write_text(gt_payload, encoding="utf-8")
    gt_hash = digest(GT_FILE)
    print(f"   Ground Truth saved to {GT_FILE} (SHA256: {gt_hash})")

    print("2. Building Retrieval Corpus...")
    corpus = build_retrieval_corpus(
        gt, source_ground_truth_path="outputs/ground_truth/purplesharp-ad/scenario_ground_truth.json",
        source_ground_truth_sha256=gt_hash
    )
    corpus_payload = json.dumps(corpus, ensure_ascii=False, indent=2) + "\n"
    CORPUS_FILE.write_text(corpus_payload, encoding="utf-8")
    corpus_hash = digest(CORPUS_FILE)
    print(f"   Retrieval Corpus saved to {CORPUS_FILE} ({len(corpus['chunks'])} chunks, SHA256: {corpus_hash})")

    print("3. Building Knowledge Graph...")
    graph = build_knowledge_graph(
        gt, ground_truth_path="outputs/ground_truth/purplesharp-ad/scenario_ground_truth.json",
        ground_truth_sha256=gt_hash
    )
    graph_payload = json.dumps(graph, ensure_ascii=False, indent=2) + "\n"
    GRAPH_FILE.write_text(graph_payload, encoding="utf-8")
    graph_hash = digest(GRAPH_FILE)
    print(f"   Knowledge Graph saved to {GRAPH_FILE} ({len(graph['nodes'])} nodes, {len(graph['edges'])} edges, SHA256: {graph_hash})")

    print("4. Building Vector Index (Multilingual-E5)...")
    embedding_cfg = {
        "provider": "sentence-transformers",
        "model_id": "intfloat/multilingual-e5-small",
        "model_revision": "614241f622f53c4eeff9890bdc4f31cfecc418b3",
        "dimension": 384,
        "distance_metric": "cosine",
        "normalization": "l2",
        "document_prefix": "passage: ",
        "query_prefix": "query: ",
    }
    backend = SentenceTransformerEmbeddingBackend(
        model_id=embedding_cfg["model_id"], model_revision=embedding_cfg["model_revision"],
        dimension=embedding_cfg["dimension"], device="cpu", batch_size=32, show_progress_bar=False
    )
    index = build_vector_index(
        corpus, corpus_path="outputs/retrieval/purplesharp-ad/retrieval_corpus.json",
        corpus_sha256=corpus_hash, embedding=embedding_cfg,
        embed_documents=backend.embed_documents
    )
    index_payload = json.dumps(index, ensure_ascii=False, indent=2) + "\n"
    INDEX_FILE.write_text(index_payload, encoding="utf-8")
    index_hash = digest(INDEX_FILE)
    print(f"   Vector Index saved to {INDEX_FILE} ({len(index['records'])} records, SHA256: {index_hash})")

    print("5. Generating 25 Reference Answers...")
    ref_answers = generate_25_reference_answers(gt)
    ref_payload = json.dumps(ref_answers, ensure_ascii=False, indent=2) + "\n"
    ANSWERS_FILE.write_text(ref_payload, encoding="utf-8")
    answers_hash = digest(ANSWERS_FILE)
    print(f"   Reference Answers saved to {ANSWERS_FILE} (25 cases, SHA256: {answers_hash})")

    print("\nAll PurpleSharp AD artifacts built successfully!")


if __name__ == "__main__":
    main()
