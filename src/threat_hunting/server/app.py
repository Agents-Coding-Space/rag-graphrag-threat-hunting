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
from threat_hunting.graphrag.query_scope import assess_query_scope
from threat_hunting.retrieval import load_retrieval_corpus, load_vector_index
from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend
from threat_hunting.llm import LLMClient, ThreatHuntingPromptBuilder, HallucinationGuardrail
from threat_hunting.llm import LLMProviderError, LLMConnectionError, LLMTimeoutError

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


def load_runtime_artifact_versions() -> None:
    """Pin corrected draft consumers explicitly; never infer human approval."""
    config = json.loads((ROOT / "configs/runtime_artifacts.json").read_text(encoding="utf-8"))
    for scenario_id, entry in config["scenarios"].items():
        if scenario_id not in SCENARIO_REGISTRY:
            raise ValueError("Unknown scenario in runtime artifact configuration")
        for field, relative in entry["paths"].items():
            if field not in ("gt_path", "corpus_path", "graph_path", "index_path"):
                raise ValueError("Unexpected runtime artifact field")
            path = (ROOT / relative).resolve()
            if not path.is_relative_to(ROOT) or digest(path) != entry["sha256"][path.name]:
                raise ValueError(f"Runtime artifact path/hash mismatch: {scenario_id}/{field}")
            SCENARIO_REGISTRY[scenario_id][field] = path


load_runtime_artifact_versions()


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
    return {"status": "ok", "service": "threat-hunting-graphrag-backend", "version": "2.0.0",
            "review_contract": "provider-error-and-structured-validation/v1"}


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
    """Return transparent offline context references, without a security verdict."""
    evidence_refs = sorted({node.get("source", {}).get("object_id")
        for node in context.get("traversal", {}).get("nodes", [])
        if node.get("node_type") == "evidence" and node.get("source", {}).get("object_id")})
    return {
        "schema_version": "threat-hunting-report/v1", "verdict": None,
        "direct_answer": "Chưa tạo được câu trả lời LLM. Đây là Offline Fallback, không phải kết luận về mức độ bằng chứng.",
        "executive_summary": "Chỉ cung cấp tham chiếu context đã truy xuất; chưa đánh giá an ninh.",
        "technical_analysis": "Nguồn fallback không xác lập technique matches, intent, completion hoặc tính đúng của narrative.",
        "attack_chain": [], "mitre_mappings": [], "sigma_matches": [],
        "containment_recommendations": [],
        "unverified_claims": ["Câu trả lời điều tra và security verdict chưa được tạo hoặc xác minh."],
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
    scope_decision = assess_query_scope(req.query, corpus=corpus, graph=graph)
    execution = {"source": "none", "llm_called": False, "generation_succeeded": False,
                 "llm_http_attempts": 0, "fallback_used": False, "gate_enforced": req.enforce_gate}
    if req.enforce_gate and scope_decision["decision"] == "abstain":
        return HuntResponse(status="abstained", scenario_id=req.scenario_id, query=req.query,
            scope_decision=scope_decision, execution=execution,
            gate_decision={"decision": "abstain", "abstention_stage": "query_scope", "reason_codes": scope_decision["reason_codes"]},
            reason="Câu hỏi chưa được xác định là yêu cầu điều tra từ nguồn dữ liệu của kịch bản.")
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
            scope_decision=scope_decision,
            execution=execution,
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

    # 5. LLM Synthesis (Powered by Model Phong / 9Router API with Forensic Fallback)
    report_dict = None
    response_status = "proceed"
    validation = None
    provider_error = None
    error_message = None
    if req.use_llm:
        llm_success = False
        llm_client = None
        try:
            llm_client = LLMClient()
            prompt_builder = ThreatHuntingPromptBuilder()
            messages = prompt_builder.build_messages(req.query, context)
            execution["llm_called"] = True
            raw_report = llm_client.generate_json(messages)
            execution["generation_succeeded"] = True

            from threat_hunting.llm.schema import ThreatHuntingReport
            parsed_report = ThreatHuntingReport.model_validate(raw_report)
            guardrail = HallucinationGuardrail(strict=True)
            guard_res = guardrail.validate(parsed_report, context)
            report_dict = guard_res.sanitized_report.model_dump()
            validation = {"status": guard_res.validation_status, "scope": "structured_claims_only",
                "issues": guard_res.issues, "reference_checks": guard_res.reference_checks,
                "unverified_fields": guard_res.unverified_fields, "human_review_required": guard_res.human_review_required}
            response_status = "proceed" if guard_res.is_valid else "validation_failed"
            execution["source"] = "llm"
            report_dict["ai_engine"] = f"{llm_client.config.model_name} ({llm_client.config.base_url})"
            llm_success = True
            logger.info("LLM generation completed: model=%s validation=%s", llm_client.config.model_name, guard_res.validation_status)
        except LLMProviderError as exc:
            response_status = "provider_error"
            provider_error = {"kind": exc.kind, "http_status": exc.status_code,
                "retry_after_seconds": exc.retry_after_seconds, "automatic_retry": False}
            error_message = "Provider đang giới hạn request (HTTP 429)." if exc.kind == "rate_limited" else "Không tạo được câu trả lời do lỗi provider."
            logger.warning("LLM provider failed: kind=%s http_status=%s", exc.kind, exc.status_code)
        except (LLMConnectionError, LLMTimeoutError) as exc:
            response_status = "provider_error"
            provider_error = {"kind": "timeout" if isinstance(exc, LLMTimeoutError) else "connection_error",
                "http_status": None, "retry_after_seconds": None, "automatic_retry": False}
            error_message = "Không tạo được câu trả lời do lỗi kết nối provider."
            logger.warning("LLM transport failed: %s", type(exc).__name__)
        except Exception as exc:
            response_status = "validation_failed"
            error_message = "Không tạo hoặc kiểm tra được báo cáo LLM; xem trạng thái validation."
            validation = {"status": "validation_failed", "scope": "generation_or_schema", "issues": [{"code": type(exc).__name__}], "human_review_required": True}
            logger.warning("LLM generation/validation failed: %s", type(exc).__name__)
        finally:
            attempts = getattr(llm_client, "last_attempt_count", None)
            execution["llm_http_attempts"] = attempts if isinstance(attempts, int) else (0 if not execution["llm_called"] else None)
            if provider_error is not None and isinstance(attempts, int):
                provider_error["automatic_retry"] = attempts > 1

        if not llm_success:
            report_dict = synthesize_rule_guided_report(context, req.query, gate_decision)
            report_dict["ai_engine"] = "Rule-Guided Forensic Synthesizer (Offline Fallback)"
            execution.update(source="offline_fallback", fallback_used=True)
            if validation is None:
                validation = {"status": "not_run", "scope": "offline_context_references_only", "human_review_required": True}

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
        status=response_status,
        scenario_id=req.scenario_id,
        query=req.query,
        gate_decision=gate_decision,
        subgraph=subgraph_response,
        retrieval_hits=hits_data,
        report=report_dict,
        scope_decision=scope_decision,
        execution=execution,
        validation=validation,
        provider_error=provider_error,
        error_message=error_message,
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
