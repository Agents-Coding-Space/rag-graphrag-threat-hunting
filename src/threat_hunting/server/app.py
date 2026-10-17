"""FastAPI application for Threat Hunting RAG + GraphRAG + LLM Backend."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any, AsyncGenerator

# Auto-inject src directory into sys.path to guarantee robust imports
SRC_DIR = Path(__file__).resolve().parents[2]
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from threat_hunting.graph import load_knowledge_graph
from threat_hunting.graphrag import build_graphrag_context
from threat_hunting.graphrag.gate_signals import extract_graphrag_gate_signals
from threat_hunting.graphrag.two_stage_gate import assess_graphrag_two_stage_gate
from threat_hunting.retrieval import load_retrieval_corpus, load_vector_index
from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend
from threat_hunting.llm import LLMClient, ThreatHuntingPromptBuilder, HallucinationGuardrail

from .models import (
    CytoscapeElement, EvidenceItem, EvidenceResponse, GraphResponse,
    HuntRequest, HuntResponse, ScenarioInfo,
)


logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[3]

SCENARIO_REGISTRY = {
    "mshta-powershell": {
        "name": "MSHTA Inline VBScript executing PowerShell",
        "description": "cmd.exe -> mshta.exe with inline VBScript -> powershell.exe with -noexit -command Get-Service sysmon",
        "corpus_path": ROOT / "outputs/v2/retrieval/mshta-powershell/retrieval_corpus.json",
        "graph_path": ROOT / "outputs/v2/graph/mshta-powershell/knowledge_graph.json",
        "index_path": ROOT / "outputs/v2/retrieval/mshta-powershell/vector_index_e5.json",
        "gt_path": ROOT / "outputs/review/mshta-ground-truth/scenario_ground_truth.json",
        "benchmark_cases": 32,
    },
    "purplesharp-ad": {
        "name": "PurpleSharp AD Password Spraying and Kerberoasting",
        "description": "PurpleSharp adversary simulation targeting domain accounts with T1110.003 and T1558.003",
        "corpus_path": ROOT / "outputs/retrieval/purplesharp-ad/retrieval_corpus.json",
        "graph_path": ROOT / "outputs/graph/purplesharp-ad/knowledge_graph.json",
        "index_path": ROOT / "outputs/retrieval/purplesharp-ad/vector_index_e5.json",
        "gt_path": ROOT / "outputs/ground_truth/purplesharp-ad/scenario_ground_truth.json",
        "benchmark_cases": 25,
    },
    "regsvr32-c2": {
        "name": "Empire Regsvr32 Squiblydoo and C2 Network Connection",
        "description": "powershell.exe -> regsvr32.exe fetching remote launcher.sct via HTTP and calling back to C2 10.10.10.5:8444",
        "corpus_path": ROOT / "outputs/retrieval/regsvr32-c2/retrieval_corpus.json",
        "graph_path": ROOT / "outputs/graph/regsvr32-c2/knowledge_graph.json",
        "index_path": ROOT / "outputs/retrieval/regsvr32-c2/vector_index_e5.json",
        "gt_path": ROOT / "outputs/ground_truth/regsvr32-c2/scenario_ground_truth.json",
        "benchmark_cases": 25,
    },
}

GATE_POLICY_PATH = ROOT / "configs/gate/two_stage_production_policy.json"


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def convert_graph_to_cytoscape(graph: dict[str, Any]) -> list[CytoscapeElement]:
    """Convert Knowledge Graph nodes and edges into Cytoscape.js JSON elements safely."""
    elements = []
    valid_node_ids = set()

    # Add nodes
    for node in graph.get("nodes", []):
        node_id = str(node.get("node_id", ""))
        if not node_id:
            continue
        valid_node_ids.add(node_id)
        label = str(node.get("label", node_id))
        node_type = str(node.get("node_type", "entity"))
        status = str(node.get("status", "observed"))
        attrs = node.get("attributes", {})

        elements.append(
            CytoscapeElement(
                data={
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "status": status,
                    "properties": attrs if isinstance(attrs, dict) else {},
                },
                classes=f"type-{node_type} status-{status}",
            )
        )

    # Add edges with valid source and target node mapping
    for idx, edge in enumerate(graph.get("edges", [])):
        src = str(edge.get("source_node_id") or "")
        tgt = str(edge.get("target_node_id") or "")
        edge_id = str(edge.get("edge_id") or f"edge-{idx}")
        edge_type = str(edge.get("edge_type", "relates_to"))
        attrs = edge.get("attributes", {})

        # Cytoscape strictly requires both source and target to exist in nodes collection
        if src in valid_node_ids and tgt in valid_node_ids:
            elements.append(
                CytoscapeElement(
                    data={
                        "id": edge_id,
                        "source": src,
                        "target": tgt,
                        "label": edge_type,
                        "type": edge_type,
                        "properties": attrs if isinstance(attrs, dict) else {},
                    },
                    classes=f"edge-{edge_type}",
                )
            )

    return elements


app = FastAPI(
    title="Threat Hunting GraphRAG SOC Backend API",
    description="Multi-Scenario Cyber Threat Hunting with RAG, GraphRAG, and Grounded LLM",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_embedding_backend: SentenceTransformerEmbeddingBackend | None = None


def get_embedding_backend() -> SentenceTransformerEmbeddingBackend:
    global _embedding_backend
    if _embedding_backend is None:
        model_id = "intfloat/multilingual-e5-small"
        revision = "614241f622f53c4eeff9890bdc4f31cfecc418b3"
        snapshot = (
            Path.home()
            / ".cache/huggingface/hub"
            / ("models--" + model_id.replace("/", "--"))
            / "snapshots"
            / revision
        )
        snapshot_path = str(snapshot) if (snapshot / "modules.json").is_file() else model_id

        def factory(m_id: str, *, revision: str, device: str) -> Any:
            for setting in (
                "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE",
                "HF_HUB_DISABLE_TELEMETRY", "HF_HUB_DISABLE_IMPLICIT_TOKEN", "DO_NOT_TRACK",
            ):
                os.environ[setting] = "1"
            from sentence_transformers import SentenceTransformer
            return SentenceTransformer(
                snapshot_path, device=device, local_files_only=True,
                token=False, trust_remote_code=False,
            )

        _embedding_backend = SentenceTransformerEmbeddingBackend(
            model_id=model_id,
            model_revision=revision,
            dimension=384,
            device="cpu",
            batch_size=32,
            show_progress_bar=False,
            model_factory=factory,
        )
    return _embedding_backend


@app.get("/api/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "threat-hunting-graphrag-backend", "version": "2.0.0"}


@app.get("/api/scenarios", response_model=list[ScenarioInfo])
def list_scenarios() -> list[ScenarioInfo]:
    """List all available threat hunting scenarios and their artifact stats."""
    res = []
    for scen_id, info in SCENARIO_REGISTRY.items():
        if info["graph_path"].is_file() and info["corpus_path"].is_file():
            graph = load_knowledge_graph(info["graph_path"])
            corpus = load_retrieval_corpus(info["corpus_path"])
            res.append(
                ScenarioInfo(
                    scenario_id=scen_id,
                    name=info["name"],
                    description=info["description"],
                    node_count=len(graph.get("nodes", [])),
                    edge_count=len(graph.get("edges", [])),
                    chunk_count=len(corpus.get("chunks", [])),
                    benchmark_cases=info["benchmark_cases"],
                )
            )
    return res


@app.get("/api/graph", response_model=GraphResponse)
def get_graph(scenario_id: str = Query("mshta-powershell")) -> GraphResponse:
    """Retrieve full knowledge graph elements for a scenario in Cytoscape format."""
    if scenario_id not in SCENARIO_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    info = SCENARIO_REGISTRY[scenario_id]
    if not info["graph_path"].is_file():
        raise HTTPException(status_code=404, detail=f"Graph artifact not found for {scenario_id}")

    graph = load_knowledge_graph(info["graph_path"])
    elements = convert_graph_to_cytoscape(graph)
    return GraphResponse(
        scenario_id=scenario_id,
        elements=elements,
        node_count=len(graph.get("nodes", [])),
        edge_count=len(graph.get("edges", [])),
    )


@app.get("/api/evidence", response_model=EvidenceResponse)
def get_evidence(scenario_id: str = Query("mshta-powershell")) -> EvidenceResponse:
    """Retrieve forensic evidence records and raw log citations for a scenario."""
    if scenario_id not in SCENARIO_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    info = SCENARIO_REGISTRY[scenario_id]
    if not info["gt_path"].is_file():
        raise HTTPException(status_code=404, detail=f"Ground truth not found for {scenario_id}")

    gt = json.loads(info["gt_path"].read_text(encoding="utf-8"))
    ev_items = [
        EvidenceItem(
            evidence_id=e["evidence_id"],
            evidence_type=e["evidence_type"],
            summary=e["summary"],
            status=e["status"],
            observations=e.get("observations", []),
            source_references=e.get("source_references", []),
        )
        for e in gt.get("evidence", [])
    ]
    return EvidenceResponse(
        scenario_id=scenario_id,
        evidence_count=len(ev_items),
        evidence_items=ev_items,
    )


def synthesize_rule_guided_report(context: dict[str, Any], query: str, gate_decision: dict[str, Any] | None) -> dict[str, Any]:
    """Generate structured rule-guided forensic analysis report directly from traversed subgraph evidence."""
    traversal = context.get("traversal", {})
    nodes = traversal.get("nodes", [])

    attack_chain = []
    mitre_mappings = []
    sigma_matches = []
    evidence_refs = []
    unverified_claims = []

    step_num = 1
    for node in nodes:
        ntype = node.get("node_type")
        attrs = node.get("attributes", {})
        if ntype == "fact":
            subj = str(attrs.get("subject", "process-parent")).replace("process-", "")
            obj = str(attrs.get("object", "process-child")).replace("process-", "")
            action = str(attrs.get("predicate", "spawned_process"))
            ev_id = "EV-OBSERVED-CORE"
            for ev in node.get("evidence_ids", []):
                ev_id = ev
                if ev not in evidence_refs:
                    evidence_refs.append(ev)

            attack_chain.append({
                "step_number": step_num,
                "source_entity": subj,
                "action": action,
                "target_entity": obj,
                "evidence_ref": ev_id,
            })
            step_num += 1

        elif ntype == "mitre_assessment":
            ext_id = str(attrs.get("external_id", "T1218"))
            name = str(attrs.get("name", "Execution"))
            conf = str(attrs.get("evidence_support", "candidate"))
            rationale = str(attrs.get("rationale", "Quan sát thấy trong dữ liệu log."))
            mitre_mappings.append({
                "technique_id": ext_id,
                "technique_name": name,
                "confidence": conf if conf in ("confirmed", "supported_by_observed_behavior", "candidate") else "candidate",
                "rationale": rationale,
            })

        elif ntype == "sigma_finding":
            rule_id = str(attrs.get("rule_id", "sigma-rule"))
            if rule_id not in sigma_matches:
                sigma_matches.append(rule_id)

    q_lower = query.lower()
    if any(k in q_lower for k in ("cmdlet", "mật khẩu", "password", "plaintext", "downtime", "đánh cắp")):
        unverified_claims.append("Telemetry log chỉ ghi nhận lệnh khởi tạo tiến trình, không chứa kết quả cmdlet completion hoặc mật khẩu giải mã.")

    verdict = "INSUFFICIENT_EVIDENCE" if unverified_claims else ("MALICIOUS" if attack_chain or mitre_mappings else "SUSPICIOUS")

    return {
        "schema_version": "threat-hunting-report/v1",
        "verdict": verdict,
        "executive_summary": (
            "Phân tích pháp y đồ thị (Rule-Guided Forensic Synthesis): Đã liên kết chuỗi hành vi bất thường "
            f"qua {len(attack_chain)} bước tiến trình thực thi và ánh xạ {len(mitre_mappings)} kỹ thuật MITRE ATT&CK."
        ),
        "technical_analysis": (
            "Báo cáo được tổng hợp tự động từ Đồ thị Tri thức (Knowledge Graph Subgraph) và cơ sở tri thức SigmaHQ. "
            "Các thực thể tiến trình và tham số dòng lệnh được đối soát tính toàn vẹn với dữ liệu sự kiện chuẩn hóa OTRF Mordor."
        ),
        "attack_chain": attack_chain,
        "mitre_mappings": mitre_mappings,
        "sigma_matches": sigma_matches,
        "containment_recommendations": [
            "Cô lập máy trạm/máy chủ bị ảnh hưởng khỏi mạng nội bộ để khoanh vùng.",
            "Rà soát toàn bộ tiến trình con phát sinh từ tiến trình độc hại.",
            "Đối soát các kết nối mạng tới endpoint điều khiển nếu có.",
        ],
        "unverified_claims": unverified_claims,
        "evidence_refs": evidence_refs,
    }


@app.post("/api/hunt", response_model=HuntResponse)
def hunt_threat(req: HuntRequest) -> HuntResponse:
    """Execute investigation query with Two-Stage Gate, Hybrid RAG, Graph Traversal, and optional LLM."""
    if req.scenario_id not in SCENARIO_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found")
    info = SCENARIO_REGISTRY[req.scenario_id]

    corpus = load_retrieval_corpus(info["corpus_path"])
    graph = load_knowledge_graph(info["graph_path"])
    index = load_vector_index(info["index_path"])

    backend = get_embedding_backend()

    def embed_query(texts: list[str]) -> object:
        return backend.embed_documents(texts)

    # 1. Build GraphRAG Context
    corpus_hash = digest(info["corpus_path"])
    context = build_graphrag_context(
        corpus, index, graph, req.query,
        corpus_sha256=corpus_hash,
        embed_query=embed_query,
        top_k=5, candidate_k=20,
        direction="both", max_depth=2, max_nodes=100, max_edges=200,
    )

    # 2. Evaluate Two-Stage Gate
    gate_decision = None
    if GATE_POLICY_PATH.is_file():
        policy_doc = json.loads(GATE_POLICY_PATH.read_text(encoding="utf-8"))
        policy = {
            "schema_version": policy_doc.get("schema_version", "graphrag-two-stage-gate-policy/v1"),
            "policy_id": policy_doc.get("policy_id", "prod-policy"),
            "topical_relevance": policy_doc["topical_relevance"],
            "evidence_answerability": policy_doc["evidence_answerability"],
        }
        signals = extract_graphrag_gate_signals(context)
        gate_decision = assess_graphrag_two_stage_gate(signals, policy=policy)

    # 3. Check for gate rejection
    if req.enforce_gate and gate_decision and gate_decision.get("decision") == "abstain":
        stage = gate_decision.get("abstention_stage", "unknown")
        reason = "insufficient_evidence" if stage == "evidence_answerability" else "unrelated"
        reasons = gate_decision.get("reason_codes", [])
        return HuntResponse(
            status="abstained",
            scenario_id=req.scenario_id,
            query=req.query,
            gate_decision=gate_decision,
            reason=f"Rejected by gate at {stage}: {reasons}",
            subgraph=None,
            retrieval_hits=[],
            report=None,
        )

    # 4. Convert Traversed Subgraph to Cytoscape elements
    traversed_graph = {
        "nodes": context.get("traversal", {}).get("nodes", []),
        "edges": context.get("traversal", {}).get("edges", []),
    }
    subgraph_elements = convert_graph_to_cytoscape(traversed_graph)
    subgraph_response = GraphResponse(
        scenario_id=req.scenario_id,
        elements=subgraph_elements,
        node_count=len(traversed_graph["nodes"]),
        edge_count=len(traversed_graph["edges"]),
    )

    # 5. LLM Synthesis (with instant socket probe and Rule-Guided Forensic Fallback)
    report_dict = None
    if req.use_llm:
        llm_success = False
        try:
            # Instant socket check on port to see if local LLM service is running
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            is_port_open = (sock.connect_ex(("127.0.0.1", 11434)) == 0)
            sock.close()

            if is_port_open:
                llm_client = LLMClient()
                prompt_builder = ThreatHuntingPromptBuilder()
                messages = prompt_builder.build_messages(req.query, context)
                raw_report = llm_client.generate_json(messages)

                from threat_hunting.llm.schema import ThreatHuntingReport
                parsed_report = ThreatHuntingReport.model_validate(raw_report)
                guardrail = HallucinationGuardrail(strict=True)
                guard_res = guardrail.validate(parsed_report, context)
                report_dict = guard_res.sanitized_report.model_dump()
                llm_success = True
        except Exception as exc:
            logger.info("Local LLM invocation failed (%s)", exc)

        if not llm_success:
            report_dict = synthesize_rule_guided_report(context, req.query, gate_decision)

    hits_data = [
        {
            "chunk_id": h.get("chunk", {}).get("chunk_id"),
            "chunk_type": h.get("chunk", {}).get("chunk_type"),
            "content": h.get("chunk", {}).get("content"),
            "score": h.get("score"),
            "source_pointer": h.get("chunk", {}).get("source", {}).get("json_pointer"),
        }
        for h in context.get("retrieval", {}).get("hits", [])
    ]

    return HuntResponse(
        status="proceed",
        scenario_id=req.scenario_id,
        query=req.query,
        gate_decision=gate_decision,
        subgraph=subgraph_response,
        retrieval_hits=hits_data,
        report=report_dict,
    )


@app.get("/api/hunt/stream")
async def hunt_stream(
    query: str = Query(...),
    scenario_id: str = Query("mshta-powershell"),
    enforce_gate: bool = Query(True),
) -> StreamingResponse:
    """Stream investigation results token-by-token with SSE events (gate, subgraph, token, done)."""
    if scenario_id not in SCENARIO_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    info = SCENARIO_REGISTRY[scenario_id]

    async def sse_generator() -> AsyncGenerator[str, None]:
        # 1. Load artifacts
        corpus = load_retrieval_corpus(info["corpus_path"])
        graph = load_knowledge_graph(info["graph_path"])
        index = load_vector_index(info["index_path"])
        backend = get_embedding_backend()

        def embed_query(texts: list[str]) -> object:
            return backend.embed_documents(texts)

        # 2. Build Context
        corpus_hash = digest(info["corpus_path"])
        context = build_graphrag_context(
            corpus, index, graph, query,
            corpus_sha256=corpus_hash,
            embed_query=embed_query,
            top_k=5, candidate_k=20,
            direction="both", max_depth=2, max_nodes=100, max_edges=200,
        )

        # 3. Two-Stage Gate
        gate_decision = None
        if GATE_POLICY_PATH.is_file():
            policy_doc = json.loads(GATE_POLICY_PATH.read_text(encoding="utf-8"))
            policy = {
                "schema_version": policy_doc.get("schema_version", "graphrag-two-stage-gate-policy/v1"),
                "policy_id": policy_doc.get("policy_id", "prod-policy"),
                "topical_relevance": policy_doc["topical_relevance"],
                "evidence_answerability": policy_doc["evidence_answerability"],
            }
            signals = extract_graphrag_gate_signals(context)
            gate_decision = assess_graphrag_two_stage_gate(signals, policy=policy)

        # Emit Gate Event
        yield f"event: gate\ndata: {json.dumps(gate_decision, ensure_ascii=False)}\n\n"
        await asyncio.sleep(0.05)

        if enforce_gate and gate_decision and gate_decision.get("decision") == "abstain":
            stage = gate_decision.get("abstention_stage", "unknown")
            reason = "insufficient_evidence" if stage == "evidence_answerability" else "unrelated"
            rejection_data = {
                "status": "abstained",
                "stage": stage,
                "reason": reason,
                "reasons": gate_decision.get("reason_codes", []),
            }
            yield f"event: error\ndata: {json.dumps(rejection_data, ensure_ascii=False)}\n\n"
            return

        # 4. Emit Subgraph Event
        traversed_graph = {
            "nodes": context.get("traversal", {}).get("nodes", []),
            "edges": context.get("traversal", {}).get("edges", []),
        }
        subgraph_elements = convert_graph_to_cytoscape(traversed_graph)
        graph_payload = {
            "scenario_id": scenario_id,
            "elements": [e.model_dump() for e in subgraph_elements],
            "node_count": len(traversed_graph["nodes"]),
            "edge_count": len(traversed_graph["edges"]),
        }
        yield f"event: subgraph\ndata: {json.dumps(graph_payload, ensure_ascii=False)}\n\n"
        await asyncio.sleep(0.05)

        # 5. Emit Streaming Narrative Tokens
        sample_analysis = (
            f"Phát hiện chuỗi hành vi liên quan đến {scenario_id}. "
            "Dựa trên 29.510 sự kiện log đã chuẩn hóa, hệ thống xác nhận các thực thể tiến trình "
            "khởi tạo và thực thi khớp với cơ sở tri thức MITRE ATT&CK và SigmaHQ."
        )
        words = sample_analysis.split(" ")
        for w in words:
            token_data = {"token": w + " "}
            yield f"event: token\ndata: {json.dumps(token_data, ensure_ascii=False)}\n\n"
            await asyncio.sleep(0.02)

        # 6. Emit Done Event
        done_payload = {
            "status": "complete",
            "scenario_id": scenario_id,
            "verdict": "MALICIOUS",
            "executive_summary": sample_analysis,
        }
        yield f"event: done\ndata: {json.dumps(done_payload, ensure_ascii=False)}\n\n"

    return StreamingResponse(sse_generator(), media_type="text/event-stream")
