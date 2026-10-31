"""Offline-first, explicitly gate-confounded RAG/GraphRAG regression harness.

This reuses runtime retrieval, prompt, schema and guardrail without changing
their policy. It never equates structured validation with semantic correctness.
Benchmark expectations are consulted only after runtime processing.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import time
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from threat_hunting.graph import load_knowledge_graph
from threat_hunting.graphrag import build_graphrag_context
from threat_hunting.graphrag.gate_signals import extract_graphrag_gate_signals
from threat_hunting.graphrag.query_scope import assess_query_scope
from threat_hunting.graphrag.two_stage_gate import assess_graphrag_two_stage_gate
from threat_hunting.llm.client import (
    LLMClient, LLMClientError, LLMConnectionError, LLMProviderError, LLMTimeoutError, extract_json_text,
)
from threat_hunting.llm.config import LLMConfig
from threat_hunting.llm.guardrail import HallucinationGuardrail, context_catalog
from threat_hunting.llm.prompt import ThreatHuntingPromptBuilder
from threat_hunting.llm.schema import ThreatHuntingReport
from threat_hunting.retrieval import load_retrieval_corpus, load_vector_index
from threat_hunting.retrieval.embedding_backend import SentenceTransformerEmbeddingBackend
from threat_hunting.retrieval.hybrid import retrieve_hybrid

ROOT = Path(__file__).resolve().parents[3]
BRANCHES = ("rag", "graphrag")
OUTCOMES = ("accepted_draft", "validation_failed", "abstain", "provider_error", "rate_limited", "fallback", "dry_run_no_generation", "not_run_request_limit", "not_run_after_stop", "not_run", "interrupted", "runtime_error")
STOP_HTTP = (401, 402, 403, 429, 503)
logger = logging.getLogger(__name__)


class RequestPacer:
    """Minimum monotonic gap after an attempted client call, before the next.

    The client is constrained to one HTTP attempt. Its generate() end (including
    response parsing) is a conservative HTTP-end boundary, before validation.
    Branches that do not call generate() neither wait nor reset this boundary.
    """

    def __init__(self, interval: float = 0, *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if not math.isfinite(interval) or interval < 0:
            raise ValueError("request_interval_seconds must be finite and nonnegative")
        self.interval, self.clock, self.sleep = interval, clock, sleep
        self.last_finished: float | None = None

    def wrap(self, factory: Callable[..., Any]) -> Callable[..., Any]:
        pacer = self

        class PacedClient:
            def __init__(self, **kwargs: Any) -> None:
                self.client = factory(**kwargs)

            @property
            def last_attempt_count(self) -> int:
                return self.client.last_attempt_count

            def generate(self, messages: list[dict[str, str]]) -> str:
                if pacer.last_finished is not None and pacer.interval:
                    deadline = pacer.last_finished + pacer.interval
                    remaining = deadline - pacer.clock()
                    if remaining > 0:
                        logger.warning("Waiting %.3f seconds before next LLM HTTP attempt; Ctrl+C stops the run", remaining)
                    while remaining > 0:
                        pacer.sleep(min(remaining, 1.0))
                        remaining = deadline - pacer.clock()
                try:
                    return self.client.generate(messages)
                finally:
                    if self.client.last_attempt_count:
                        pacer.last_finished = pacer.clock()

        return PacedClient


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")
    _read(path) if isinstance(value, dict) else json.loads(path.read_text(encoding="utf-8"))


def _safe_config(config: LLMConfig) -> dict[str, Any]:
    parts = urlsplit(config.base_url)
    host = parts.hostname or ""
    if parts.port:
        host += f":{parts.port}"
    return {"provider": config.provider, "model_name": config.model_name,
            "base_url": urlunsplit((parts.scheme, host, parts.path, "", "")),
            "temperature": config.temperature, "max_tokens": config.max_tokens,
            "timeout_seconds": config.timeout_seconds, "maximum_http_attempts_per_generation": 1,
            "automatic_retry": False,
            "validator_policy": _safe_validator_policy()}


def _safe_validator_policy() -> dict[str, Any]:
    """Validator parameters in force, so a pin cannot describe two different outcomes.

    Imported lazily: ``generation_contract_v3`` pulls in the schema/guardrail stack that this
    module also uses, and a module-level import here would create a cycle.
    """
    from threat_hunting.llm.generation_contract_v3 import effective_validator_policy
    return effective_validator_policy()


def run_reporting_metadata(*, live: bool, max_requests: int, harness_ceiling: int,
                           interpretation: str) -> dict[str, Any]:
    """Report the effective per-run cap separately from the supported ceiling.

    Reporting only: the request guard, eligibility, generation and budgets are
    unchanged. An offline run cannot make a request even if a budget was passed.
    """
    mode = "Live execution" if live else "Offline dry-run"
    return {"maximum_llm_requests": max_requests if live else 0,
            "harness_request_ceiling": harness_ceiling,
            "configured_request_budget": max_requests,
            "warning": mode + ": " + interpretation.removeprefix("Offline ")}


def rag_context(retrieval: dict[str, Any], corpus: dict[str, Any], graph_id: str) -> dict[str, Any]:
    """Envelope with no graph objects, mappings or aliases added to retrieved hits."""
    ids = {"corpus_id": corpus["corpus_id"], "graph_id": graph_id, "scenario_id": corpus["scenario_id"],
           "source_ground_truth": deepcopy(corpus["source_ground_truth"]), "query": deepcopy(retrieval["query"])}
    seeds = {"schema_version": "graphrag-seed-map/v1", **deepcopy(ids), "retrieval_method": retrieval["retrieval_method"],
             "hit_mappings": [], "seed_node_ids": [], "warnings": [], "metadata": {
                 "retrieval_hit_count": len(retrieval["hits"]), "mapped_hit_count": 0,
                 "direct_node_mapping_count": 0, "relationship_edge_mapping_count": 0, "seed_node_count": 0}}
    return {"schema_version": "graphrag-context/v1", **ids, "retrieval": deepcopy(retrieval),
            "seed_mapping": seeds, "traversal": None, "warnings": ["Comparison RAG branch: graph mapping and traversal disabled."],
            "metadata": {"retrieval_hit_count": len(retrieval["hits"]), "mapped_hit_count": 0, "seed_node_count": 0,
                         "traversal_performed": False, "traversed_node_count": 0, "traversed_edge_count": 0, "traversed_path_count": 0}}


def supplied_context(context: dict[str, Any]) -> dict[str, Any]:
    """Prompt and validator receive exactly the same returned evidence objects."""
    result = deepcopy(context)
    if result.get("traversal") is None:
        # Prompt/guardrail APIs expect a map, whereas gate schema expects null.
        result["traversal"] = {}
    return result


def validate_generated(raw_report: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Retain pre-sanitize values independently from the guardrail's checked copy."""
    before = deepcopy(raw_report)
    parsed = ThreatHuntingReport.model_validate(raw_report)
    checked = HallucinationGuardrail(strict=True).validate(parsed, context)
    return {"raw_report_before_sanitize": before, "sanitized_report": checked.sanitized_report.model_dump(),
            "status": checked.validation_status, "scope": "structured_claims_only", "issues": checked.issues,
            "reference_checks": checked.reference_checks, "unverified_fields": checked.unverified_fields,
            "human_review_required": checked.human_review_required}


def gate_metrics(rows: list[dict[str, Any]], cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Score only mandatory historical decisions; overreach permits either path."""
    expected = {c["case_id"]: c["category"] for c in cases}
    values: dict[str, Any] = {}
    for branch in BRANCHES:
        selected = [row for row in rows if row["branch"] == branch and row.get("gate_decision") in ("proceed", "abstain")]
        positives = [r for r in selected if expected[r["case_id"]] == "answerable"]
        negatives = [r for r in selected if expected[r["case_id"]] == "out_of_scope"]
        fp = sum(r["gate_decision"] == "proceed" for r in negatives)
        fn = sum(r["gate_decision"] == "abstain" for r in positives)
        mandatory = len(positives) + len(negatives)
        outcomes = Counter(r["outcome"] for r in rows if r["branch"] == branch)
        accepted = outcomes["accepted_draft"]
        total = sum(outcomes.values())
        eligible = sum(r["gate_decision"] == "proceed" for r in selected)
        values[branch] = {
            "planned_cases": total, "gate_assessed_cases": len(selected),
            "mandatory_gate_accuracy": {"numerator": mandatory - fp - fn, "denominator": mandatory},
            "false_proceed": {"numerator": fp, "denominator": len(negatives), "population": "out_of_scope_only"},
            "false_abstain": {"numerator": fn, "denominator": len(positives), "population": "answerable_only"},
            "gate_coverage": {"numerator": eligible, "denominator": len(selected)},
            "final_eligibility_coverage": {"numerator": sum(r.get("eligibility_decision", r.get("gate_decision")) == "proceed" for r in selected), "denominator": len(selected)},
            "context_budget_abstentions": sum(r.get("abstention_stage") == "context_budget" for r in selected),
            "overreach_permissible_either": Counter(r["gate_decision"] for r in selected if expected[r["case_id"]] == "overreach"),
            "accepted_draft_coverage": {"numerator": accepted, "denominator": total},
            "outcomes": {key: outcomes[key] for key in OUTCOMES},
            "answer_semantic_accuracy": {"numerator": None, "denominator": 0, "status": "pending_manual_review"},
            "citation_semantic_accuracy": {"numerator": None, "denominator": 0, "status": "pending_manual_review"},
        }
    return values


def _runtime_sources(config_path: Path | None = None) -> dict[str, dict[str, Path]]:
    if config_path is not None:
        configuration = _read(config_path)
        result = {}
        for sid, entry in configuration["scenarios"].items():
            result[sid] = {}
            for field in ("gt_path", "corpus_path", "graph_path", "index_path"):
                path = (ROOT / entry["paths"][field]).resolve()
                if not path.is_relative_to(ROOT) or sha256(path) != entry["sha256"][path.name]:
                    raise ValueError(f"Runtime artifact provenance mismatch: {sid}/{field}")
                result[sid][field] = path
        return result
    # Reuse the same validated registry the actual POST endpoint imports.
    from threat_hunting.server.app import SCENARIO_REGISTRY
    return {sid: {field: Path(info[field]) for field in ("gt_path", "corpus_path", "graph_path", "index_path")}
            for sid, info in SCENARIO_REGISTRY.items()}


def _source_manifest(paths: dict[str, dict[str, Path]]) -> dict[str, Any]:
    return {sid: {field: {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256(path)} for field, path in item.items()}
            for sid, item in paths.items()}


def _code_manifest() -> dict[str, str]:
    paths = list((ROOT / "src/threat_hunting").rglob("*.py"))
    paths += [ROOT / "scripts/evaluate_rag_graphrag.py", ROOT / "configs/evaluation/experimental_comparison.json"]
    final_runner = ROOT / "scripts/run_final_experiment.py"
    if final_runner.is_file():
        paths.append(final_runner)
    return {p.relative_to(ROOT).as_posix(): sha256(p) for p in sorted(paths)}


def _manual_template(cases: list[dict[str, Any]], source_contract: bool = False) -> dict[str, Any]:
    return {"review_status": "pending_human_review", "rules": [
        "Use frozen cases.json criteria unchanged. Existing scores are historical, not current labels.",
        "Score returned context separately from gate and final prose; ID existence alone is not semantic support.",
        "Rejected output, fallback and provider errors are not successful LLM answers.",
        "Overreach permits either abstain or evidence-limited answer; do not score proceed as automatically wrong.",
        ("Gate witnesses and rubric completeness are distinct; source-contract migration is not independent validation."
         if source_contract else "Do not claim GraphRAG answer superiority: the unchanged graph-dependent gate structurally blocks RAG.")],
        "cases": [{"case_id": c["case_id"], "branch": b, "context_sufficiency": None, "retrieval_relevance": None,
                   "answer_correctness": None, "citation_support": None, "over_inference": None, "false_refusal": None,
                   "reviewer": None, "notes": ""} for c in cases for b in BRANCHES]}


def prepare_branch(query: str, branch: str, p: dict[str, Path], corpus: dict[str, Any],
                   index: dict[str, Any], backend: Any, config: dict[str, Any], policy: dict[str, Any],
                   emit: Callable[[str, Any], None]) -> dict[str, Any]:
    """Shared evaluated retrieval, evidence gate, prompt and byte budgets.

    Scope must already pass corpus-only assessment. No benchmark labels enter.
    """
    if branch not in BRANCHES:
        raise ValueError("Unknown experimental branch")
    source_contract = config.get("gate_contract") in {"source-evidence-contract/v1", "source-evidence-contract/v2"}
    row: dict[str, Any] = {}
    retrieval_started = time.perf_counter()
    graph = load_knowledge_graph(p["graph_path"]) if branch == "graphrag" else None
    if branch == "graphrag":
        context = build_graphrag_context(corpus, index, graph, query,
            corpus_sha256=sha256(p["corpus_path"]), embed_query=backend.embed_documents,
            **config["retrieval"], **config["graph_expansion"])
    else:
        retrieval = retrieve_hybrid(corpus, index, query,
            corpus_sha256=sha256(p["corpus_path"]), embed_query=backend.embed_documents, **config["retrieval"])
        context = rag_context(retrieval, corpus, "comparison-rag-no-graph")
    row["retrieval_context_seconds"] = time.perf_counter() - retrieval_started
    context_for_model = supplied_context(context)
    packed = config.get("gate_contract") == "source-evidence-contract/v2"
    if packed:
        from threat_hunting.retrieval.context_packing import pack_context
        context_for_model = pack_context(context_for_model)
    signals = extract_graphrag_gate_signals(context)
    gate = assess_graphrag_two_stage_gate(signals, policy=policy)
    if source_contract:
        from .evidence_contract import assess_source_evidence_gate
        if config.get("gate_contract") == "source-evidence-contract/v2":
            from .evidence_contract_v2 import assess_integrated_evidence_gate as assess_source_evidence_gate
        emit("legacy_gate", gate)
        gate, projection = assess_source_evidence_gate(query, context_for_model, gate)
        emit("evidence_contract", projection)
    emit("signals", signals)
    emit("gate", gate)
    generation_contract = config.get("generation_contract")
    if generation_contract is not None:
        if generation_contract == "source-meaning/v3":
            from threat_hunting.llm.generation_contract_v3 import CONTRACT, annotate_context, build_messages
        else:
            from threat_hunting.llm.generation_contract import CONTRACT, annotate_context, build_messages
        if generation_contract != CONTRACT:
            raise ValueError("Unknown generation meaning contract")
        context_for_model = annotate_context(context_for_model)
        messages = build_messages(query, context_for_model)
    else:
        messages = ThreatHuntingPromptBuilder().build_messages(query, context_for_model)
    emit("context", context_for_model)
    emit("messages", {"messages": messages})
    context_size, message_size = len(canonical_bytes(context_for_model)), len(canonical_bytes(messages))
    catalog = context_catalog(context_for_model)
    row.update(gate_decision=gate["decision"], policy_gate_decision=gate["decision"], eligibility_decision=gate["decision"], abstention_stage=gate.get("abstention_stage"),
        context_utf8_bytes=context_size, messages_utf8_bytes=message_size,
        context_sha256=hashlib.sha256(canonical_bytes(context_for_model)).hexdigest(),
        messages_sha256=hashlib.sha256(canonical_bytes(messages)).hexdigest(),
        retrieval_sha256=hashlib.sha256(canonical_bytes(context["retrieval"])).hexdigest(),
        retrieval_hit_ids=[h["chunk"]["chunk_id"] for h in context["retrieval"]["hits"]],
        returned_graph_nodes=len(context_for_model["traversal"].get("nodes", [])),
        returned_graph_edges=len(context_for_model["traversal"].get("edges", [])),
        available_reference_count=len(catalog), validation_status="not_run")
    budget_exceeded = context_size > config["maximum_context_utf8_bytes"] or message_size > config["maximum_messages_utf8_bytes"]
    emit("eligibility", {"policy_decision": gate["decision"],
        "decision": "abstain" if budget_exceeded else gate["decision"],
        "context_utf8_bytes": context_size, "messages_utf8_bytes": message_size,
        "budget_exceeded": budget_exceeded, "stage": "context_budget" if budget_exceeded else gate.get("abstention_stage")})
    return {"row": row, "context": context_for_model, "messages": messages, "gate": gate, "budget_exceeded": budget_exceeded}


def generate_branch(messages: list[dict[str, str]], context_for_model: dict[str, Any],
                    effective_llm: LLMConfig, client_factory: Callable[..., Any],
                    emit: Callable[[str, Any], None]) -> tuple[dict[str, Any], str | None]:
    """Shared one-attempt generation/validation. No retry or fallback."""
    row: dict[str, Any] = {}
    stopped = None
    client = client_factory(config=effective_llm)
    generation_started = time.perf_counter()
    try:
        # Capture text and structured values BEFORE schema validation/sanitization.
        raw_text = client.generate(messages)
        safe_text = raw_text.replace(effective_llm.api_key, "[REDACTED]") if effective_llm.api_key else raw_text
        emit("raw_model_output", {"text": safe_text})
        raw = json.loads(extract_json_text(safe_text))
        emit("raw_report_before_sanitize", raw)
        checked = validate_generated(raw, context_for_model)
        if "generation_evidence_contract" in context_for_model:
            if context_for_model["generation_evidence_contract"].get("schema_version") == "source-meaning/v3":
                from threat_hunting.llm.generation_contract_v3 import CONTRACT, validate_meaning
            else:
                from threat_hunting.llm.generation_contract import CONTRACT, validate_meaning
            if context_for_model["generation_evidence_contract"].get("schema_version") != CONTRACT:
                raise ValueError("Unknown generation meaning contract")
            checked = validate_meaning(checked, raw, context_for_model)
        emit("validation", checked)
        row.update(outcome="accepted_draft" if checked["status"] == "passed" else "validation_failed",
                   validation_status=checked["status"])
    except LLMProviderError as exc:
        row.update(outcome="rate_limited" if exc.status_code == 429 else "provider_error",
                   provider_error={"kind": exc.kind, "http_status": exc.status_code,
                       "retry_after_seconds": exc.retry_after_seconds, "automatic_retry": False})
        if exc.diagnostic is not None:
            row["provider_error"]["diagnostic"] = exc.diagnostic
            emit("provider_diagnostic", exc.diagnostic)
        if exc.status_code in STOP_HTTP:
            stopped = f"provider_http_{exc.status_code}"
    except KeyboardInterrupt:
        row.update(outcome="interrupted" if client.last_attempt_count else "not_run",
                   validation_status="not_run", interruption_stage="generation_or_validation" if client.last_attempt_count else "before_http_attempt")
        stopped = "keyboard_interrupt"
    except (LLMConnectionError, LLMTimeoutError) as exc:
        row.update(outcome="provider_error", provider_error={"kind": type(exc).__name__, "automatic_retry": False})
    except LLMClientError as exc:
        row.update(outcome="provider_error", provider_error={"kind": "protocol_error", "error_type": type(exc).__name__, "automatic_retry": False})
    except Exception as exc:
        row.update(outcome="validation_failed", validation_status="validation_failed",
                   error_type=type(exc).__name__)
        failure = {"status": "validation_failed", "phase": "model_content_or_schema",
                   "error_type": type(exc).__name__, "human_review_required": True}
        if isinstance(exc, json.JSONDecodeError):
            failure["json_error"] = {"line": exc.lineno, "column": exc.colno, "position": exc.pos}
        if hasattr(exc, "errors"):
            failure["schema_errors"] = [{"location": item["loc"], "type": item["type"]} for item in exc.errors()]
        emit("validation_failure", failure)
    finally:
        row["generation_validation_seconds"] = time.perf_counter() - generation_started
        row["llm_http_attempts"] = client.last_attempt_count
    return row, stopped


def run_comparison(config_path: Path, output: Path, *, live: bool = False, max_requests: int = 0,
                   embedding_factory: Callable[..., Any] = SentenceTransformerEmbeddingBackend,
                   client_factory: Callable[..., Any] = LLMClient,
                   case_ids: tuple[str, ...] | None = None,
                   branch_keys: tuple[tuple[str, str], ...] | None = None,
                   request_interval_seconds: float = 0,
                   clock: Callable[[], float] = time.monotonic,
                   sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """Run branches sequentially; default performs no provider request or fallback."""
    if live and not 1 <= max_requests <= 30:
        raise ValueError("Live runs require an explicit request budget in 1..30")
    pacer = RequestPacer(request_interval_seconds, clock=clock, sleep=sleep)
    paced_factory = pacer.wrap(client_factory)
    config_path, output = config_path.resolve(), output.resolve()
    config = _read(config_path)
    if live and config.get("final_run_policy"):
        raise ValueError("Final live runs require run_final_experiment.py and its persistent task budget")
    integrated = config.get("schema_version") == "experimental-comparison-config/v2"
    ceiling = config["maximum_llm_requests"]
    if config["branches"] != list(BRANCHES) or ceiling != (24 if integrated else 30) or (live and max_requests > ceiling):
        raise ValueError("Unsupported branch/request contract")
    cases_path = ROOT / config["benchmark"]
    benchmark = _read(cases_path)
    cases = benchmark["cases"]
    expected_count = 12 if integrated else 15
    if len(cases) != config["expected_case_count"] or len(cases) != expected_count or len({c["case_id"] for c in cases}) != expected_count:
        raise ValueError("Expected the frozen configured benchmark")
    source_contract = config.get("gate_contract") in {"source-evidence-contract/v1", "source-evidence-contract/v2"}
    if case_ids is not None:
        if not case_ids or len(set(case_ids)) != len(case_ids) or set(case_ids) - {c["case_id"] for c in cases}:
            raise ValueError("case_ids must be distinct IDs from the frozen benchmark")
        cases = [next(c for c in cases if c["case_id"] == case_id) for case_id in case_ids]
    if branch_keys is not None:
        allowed = {(c["case_id"], b) for c in cases for b in BRANCHES}
        if case_ids is not None or not branch_keys or len(set(branch_keys)) != len(branch_keys) or set(branch_keys) - allowed:
            raise ValueError("branch_keys must be distinct configured case/branch pairs; cannot combine with case_ids")
        cases = [c for c in cases if any(key[0] == c["case_id"] for key in branch_keys)]
    planned_count = len(branch_keys) if branch_keys is not None else 2 * len(cases)
    if live and source_contract and max_requests < planned_count:
        raise ValueError("Select a case-pair subset or provide a cap covering all planned branches; no order-based truncation")
    output.mkdir(parents=True, exist_ok=False)
    _write(output / "cases.json", benchmark)
    _write(output / "configuration.json", config)
    _write(output / "manual_review.json", _manual_template(cases, source_contract))
    paths = _runtime_sources(ROOT / config["runtime_artifacts"]) if integrated else _runtime_sources()
    sources_before = _source_manifest(paths)
    policy_doc = _read(ROOT / config["gate_policy"])
    policy = {key: policy_doc[key] for key in ("schema_version", "policy_id", "topical_relevance", "evidence_answerability")}
    llm_config = LLMConfig.from_env()
    effective_llm = replace(llm_config, max_retries=1)
    reporting = run_reporting_metadata(live=live, max_requests=max_requests,
        harness_ceiling=config["maximum_llm_requests"], interpretation=config["interpretation"])
    # Only local embeddings may execute in dry-run; prevent model downloads.
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    manifest = {"mode": "live" if live else "offline_dry_run", "created_utc": datetime.now(timezone.utc).isoformat(),
                "review_type": "corrective_regression_not_independent_validation", "model": _safe_config(effective_llm),
                "cases_sha256": sha256(cases_path), "config_sha256": sha256(config_path),
                "selected_case_ids": [c["case_id"] for c in cases],
                "selected_branches": [{"case_id": c["case_id"], "branch": b} for i,c in enumerate(cases)
                                      for b in (BRANCHES if i % 2 == 0 else tuple(reversed(BRANCHES)))
                                      if branch_keys is None or (c["case_id"], b) in branch_keys],
                "generation_contract": config.get("generation_contract", "v5_original"),
                "gate_contract": config.get("gate_contract", "legacy_graph_topology"),
                "gate_policy_sha256": sha256(ROOT / config["gate_policy"]),
                "runtime_artifacts_config_sha256": sha256(ROOT / config["runtime_artifacts"]),
                "artifacts": sources_before, "code_sha256": _code_manifest(),
                "hardcoded_benchmark_excluded": "scripts/evaluate_rag_triad_benchmark.py",
                "differences": ["GraphRAG adds exact seed mapping and bounded graph traversal; RAG has only hybrid hits.",
                    "Both use corpus-only scope anchors, differing from POST which also scans full graph anchors.",
                    ("Source-evidence gate replaces topology admission identically for both branches; legacy gate is diagnostic only."
                     if source_contract else "Same graph-dependent gate policy structurally blocks RAG; generation outcomes are confounded."),
                    "Corpus already contains relationship/fact/evidence chunks; RAG is not a document-only baseline."],
                "limits": {**{key: reporting[key] for key in ("maximum_llm_requests", "harness_request_ceiling", "configured_request_budget")},
                    "retry": False, "stop_on_http": list(STOP_HTTP), "fallback": False,
                    "request_interval_seconds": request_interval_seconds,
                    "maximum_context_utf8_bytes": config["maximum_context_utf8_bytes"],
                    "maximum_messages_utf8_bytes": config["maximum_messages_utf8_bytes"]},
                "timing": "Sequential per-branch wall time includes artifact loading/query embedding/retrieval/gate/prompt/generation/validation and artifact writing before final row; model warmup is separate. Dry-run is not LLM latency."}
    _write(output / "manifest.json", manifest)
    backends: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    attempts = 0
    stopped: str | None = None
    warmups: dict[str, float] = {}
    for case_index, case in enumerate(cases):
        # Fixed alternating order reduces a systematic branch order bias.
        order = BRANCHES if case_index % 2 == 0 else tuple(reversed(BRANCHES))
        for branch in order:
            if branch_keys is not None and (case["case_id"], branch) not in branch_keys:
                continue
            started = time.perf_counter()
            row = {"case_id": case["case_id"], "scenario_id": case["scenario_id"], "branch": branch,
                   "outcome": "runtime_error", "gate_decision": None, "eligibility_decision": None, "policy_gate_decision": None, "llm_http_attempts": 0,
                   "fallback_used": False, "human_review_required": True}
            directory = output / f"{case['case_id']}_{branch}"
            directory.mkdir()
            if stopped:
                row.update(outcome="not_run", not_run_reason=stopped)
            else:
                try:
                    sid = case["scenario_id"]
                    p = paths[sid]
                    corpus = load_retrieval_corpus(p["corpus_path"])
                    # Scope uses common source corpus only, before either branch retrieves.
                    scope = assess_query_scope(case["request"]["query"], corpus=corpus, graph={})
                    _write(directory / "scope.json", scope)
                    if scope["decision"] == "abstain":
                        row.update(outcome="abstain", gate_decision="abstain", eligibility_decision="abstain", abstention_stage="query_scope")
                    else:
                        index = load_vector_index(p["index_path"])
                        embedding = index["embedding"]
                        model_key = embedding["model_id"] + "@" + embedding["model_revision"]
                        if model_key not in backends:
                            backend = embedding_factory(model_id=embedding["model_id"], model_revision=embedding["model_revision"],
                                dimension=embedding["dimension"], device="cpu", batch_size=32, show_progress_bar=False)
                            warmup_start = time.perf_counter()
                            backend.load()
                            warmups[model_key] = time.perf_counter() - warmup_start
                            backends[model_key] = backend
                            # Warmup is explicitly reported and excluded equally from branch timing.
                            started += warmups[model_key]
                        backend = backends[model_key]
                        prepared = prepare_branch(case["request"]["query"], branch, p, corpus, index, backend,
                            config, policy, lambda name, value: _write(directory / f"{name}.json", value))
                        row.update(prepared["row"])
                        context_for_model, messages, gate = (prepared[key] for key in ("context", "messages", "gate"))
                        budget_exceeded = prepared["budget_exceeded"]
                        if budget_exceeded:
                            row.update(outcome="abstain", eligibility_decision="abstain", abstention_stage="context_budget", budget_exceeded=True)
                        elif gate["decision"] == "abstain":
                            row["outcome"] = "abstain"
                        elif not live:
                            row["outcome"] = "dry_run_no_generation"
                        elif attempts >= max_requests:
                            row["outcome"] = "not_run_request_limit"
                        else:
                            generated, stopped = generate_branch(messages, context_for_model, effective_llm,
                                paced_factory, lambda name, value: _write(directory / f"{name}.json", value))
                            row.update(generated)
                            attempts += row["llm_http_attempts"]
                except KeyboardInterrupt:
                    row.update(outcome="not_run", not_run_reason="keyboard_interrupt")
                    stopped = "keyboard_interrupt"
                except Exception as exc:
                    row.update(outcome="runtime_error", error_type=type(exc).__name__)
            row["end_to_end_seconds"] = time.perf_counter() - started
            _write(directory / "result.json", row)
            rows.append(row)
    if _source_manifest(paths) != sources_before:
        raise ValueError("Runtime artifacts changed during comparison")
    pair_audit = []
    for case in cases:
        pair = {r["branch"]: r for r in rows if r["case_id"] == case["case_id"]}
        both_retrieved = all(pair.get(b, {}).get("retrieval_sha256") for b in BRANCHES)
        equal = pair.get("rag", {}).get("retrieval_sha256") == pair.get("graphrag", {}).get("retrieval_sha256") if both_retrieved else None
        pair_audit.append({"case_id": case["case_id"], "both_retrieved": both_retrieved, "identical_hybrid_retrieval": equal})
    if any(p["identical_hybrid_retrieval"] is False for p in pair_audit):
        raise ValueError("Paired branches returned different hybrid retrieval")
    _write(output / "paired_retrieval_audit.json", {"cases": pair_audit})
    metrics = gate_metrics(rows, cases)
    summary = {"schema_version": "experimental-comparison-results/v1", "mode": manifest["mode"],
               "planned_branch_count": planned_count, "eligible_branch_count": sum(r.get("eligibility_decision") == "proceed" for r in rows),
               "llm_http_attempts": attempts, "maximum_llm_requests": reporting["maximum_llm_requests"],
               "harness_request_ceiling": reporting["harness_request_ceiling"],
               "configured_request_budget": max_requests, "stopped_reason": stopped,
               "stop_details": next((r["provider_error"] for r in rows if r.get("provider_error", {}).get("http_status") in STOP_HTTP), None),
               "request_interval_seconds": request_interval_seconds,
               "model_warmup_seconds": warmups, "metrics": metrics, "rows": rows,
               "warning": reporting["warning"], "runtime_artifacts_unchanged": True,
               "semantic_answer_and_citation_scoring": "pending_manual_review; structured validation alone is insufficient"}
    _write(output / "results.json", summary)
    return summary
