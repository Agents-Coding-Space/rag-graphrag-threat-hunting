"""Explicit demo adapter for the evaluated experimental harness, offline by default.

This service has no production hunt, SSE, policy override, retries or fallback.
Cases are used only for preset text and saved-result lookup, never as gate input.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from threat_hunting.evaluation import experimental_comparison as pipeline
from threat_hunting.llm.config import LLMConfig

ROOT = pipeline.ROOT
CONFIG = ROOT / "configs/evaluation/experimental_comparison_evidence.json"
PILOT = ROOT / "outputs/experiments/rag-graphrag-pilot-source-contract-02"
REMAINING = ROOT / "outputs/experiments/rag-graphrag-remaining-source-contract-01"
DEMO_IDS = ("PS02", "RG04", "RG05")
FIXTURE_IDS = ("accepted_draft", "validation_failed", "provider_error", "rate_limited", "abstain",
               "dry_run_no_generation", "runtime_error", "not_run_request_limit", "not_run_after_stop")


class ExperimentalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=12000)
    scenario_id: Literal["mshta-powershell", "purplesharp-ad", "regsvr32-c2"]
    branch: Literal["rag", "graphrag"]


def read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write(path: Path, value: Any) -> None:
    pipeline._write(path, value)


class ExperimentalSession:
    """One sequential session with a global attempt cap and an auth/429 stop latch."""

    def __init__(self, output: Path, *, live: bool = False, max_requests: int = 0,
                 backend: Any = None, client_factory: Any = None, config_path: Path | None = None,
                 pin_path: Path | None = None) -> None:
        if live and not 1 <= max_requests <= 30:
            raise ValueError("--live requires --max-requests in 1..30")
        if not live and max_requests:
            raise ValueError("Offline mode requires zero requests")
        self.config_path = config_path or CONFIG
        self.config = read(self.config_path)
        if live and self.config.get("final_run_policy"):
            raise ValueError("The final study profile permits offline/replay dashboard only; live generation uses its task ledger")
        self.integrated = self.config.get("schema_version") == "experimental-comparison-config/v2"
        self.pin_path = pin_path if pin_path else PILOT / "manifest.json"
        self.pin = read(self.pin_path)
        if self.config.get("generation_contract"):
            # The new version has its own full code pin; no historical wildcard exemptions.
            if pipeline._code_manifest() != self.pin["code_sha256"]:
                raise ValueError("Versioned integrated runtime code pin mismatch")
            if self.pin.get("generation_contract") != self.config["generation_contract"]:
                raise ValueError("Generation meaning contract differs from pin")
            if pipeline.sha256(ROOT / self.config["benchmark"]) != self.pin["cases_sha256"]:
                raise ValueError("Locked questions differ from pin")
        if self.config.get("gate_contract") not in {"source-evidence-contract/v1", "source-evidence-contract/v2"}:
            raise ValueError("Experimental source contract must be selected explicitly")
        if pipeline.sha256(self.config_path) != self.pin["config_sha256"]:
            raise ValueError("Evaluated experimental config changed")
        self.paths = pipeline._runtime_sources(ROOT / self.config["runtime_artifacts"]) if self.integrated else pipeline._runtime_sources()
        self.sources = pipeline._source_manifest(self.paths)
        if self.sources != self.pin["artifacts"]:
            raise ValueError("Evaluated artifact provenance changed")
        if pipeline.sha256(ROOT / self.config["gate_policy"]) != self.pin["gate_policy_sha256"]:
            raise ValueError("Evaluated gate policy changed")
        if pipeline.sha256(ROOT / self.config["runtime_artifacts"]) != self.pin["runtime_artifacts_config_sha256"]:
            raise ValueError("Evaluated runtime artifact configuration changed")
        if live and max_requests > self.config["maximum_llm_requests"]:
            raise ValueError("Request cap exceeds this profile's ceiling")
        frozen_modules = ("llm/prompt.py", "llm/schema.py", "llm/guardrail.py", "llm/client.py", "llm/config.py",
                          "evaluation/evidence_contract.py", "graphrag/query_scope.py", "graphrag/two_stage_gate.py")
        if self.integrated:
            frozen_modules += ("evaluation/evidence_contract_v2.py", "retrieval/context_packing.py", "graphrag/gate_signals.py",
                               "graphrag/relevance.py", "graphrag/seed_mapping.py", "evaluation/experimental_comparison.py")
        self.evaluated_sources = {}
        for module in frozen_modules:
            relative = "src/threat_hunting/" + module
            expected = self.pin["code_sha256"][relative]
            if pipeline.sha256(pipeline.ROOT / relative) != expected:
                raise ValueError(f"Evaluated runtime module changed: {relative}")
            self.evaluated_sources[relative] = expected
        policy_doc = read(ROOT / self.config["gate_policy"])
        self.policy = {key: policy_doc[key] for key in ("schema_version", "policy_id", "topical_relevance", "evidence_answerability")}
        self.llm_config = replace(LLMConfig.from_env(), max_retries=1)
        if pipeline._safe_config(self.llm_config) != self.pin["model"]:
            raise ValueError("LLM configuration differs from the evaluated model/provider/settings")
        # Never allow a demo directory to overwrite benchmark or review artifacts.
        demo_root = (ROOT / "outputs/demo").resolve()
        self.output = output.resolve()
        if not self.output.is_relative_to(demo_root) or self.output == demo_root:
            raise ValueError("Demo output must be a new child directory of outputs/demo")
        self.output.mkdir(parents=True, exist_ok=False)
        self.live, self.max_requests = live, max_requests
        self.attempts = 0
        self.stopped: str | None = None
        self.backend = backend
        self.client_factory = client_factory or pipeline.LLMClient
        self.lock = Lock()
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        write(self.output / "manifest.json", self.metadata())

    def metadata(self) -> dict[str, Any]:
        return {"mode": "experimental_live_demo" if self.live else "experimental_offline_demo",
                "profile_id": self.config.get("profile_id", "historical-15x2"),
                "generation_contract": self.config.get("generation_contract", "v5_original"),
                "artifact_profiles": [{"id":self.config.get("profile_id", "historical-15x2"),"label":"Integrated CTI + ba kịch bản · draft" if self.integrated else "Historical 15×2"},
                                      {"id":"historical-replay","label":"Checkpoint 15×2 · saved replay only"}],
                "gate_contract": self.config["gate_contract"], "config": self.config,
                "config_sha256": pipeline.sha256(self.config_path), "model": pipeline._safe_config(self.llm_config),
                "gate_policy_sha256": self.pin["gate_policy_sha256"], "gate_policy": self.policy,
                "evaluated_sources_sha256": self.evaluated_sources, "artifacts": self.sources,
                "llm_http_attempts": self.attempts, "maximum_llm_requests": self.max_requests,
                "stopped_reason": self.stopped, "fallback": False, "automatic_retry": False,
                "output_directory": self.output.relative_to(ROOT).as_posix(),
                "human_review_required": True, "benchmark_result": False}

    def presets(self) -> list[dict[str, str]]:
        benchmark = ROOT / self.config["benchmark"]
        if pipeline.sha256(benchmark) != self.pin["cases_sha256"]:
            raise ValueError("Locked cases changed")
        cases = read(benchmark)["cases"]
        # Only query/scenario/ID go to the UI; expected answers are never runtime input.
        ids = [c["case_id"] for c in cases] if self.integrated else DEMO_IDS
        return [{"case_id": case_id, "query": next(c for c in cases if c["case_id"] == case_id)["request"]["query"],
                 "scenario_id": next(c for c in cases if c["case_id"] == case_id)["scenario_id"]} for case_id in ids]

    def run(self, request: ExperimentalRequest) -> dict[str, Any]:
        with self.lock:
            directory = self.output / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "_" + uuid4().hex)
            directory.mkdir()
            artifacts: dict[str, Any] = {}

            def emit(name: str, value: Any) -> None:
                artifacts[name] = deepcopy(value)
                write(directory / f"{name}.json", value)

            emit("request", request.model_dump())
            emit("configuration", self.metadata())
            row: dict[str, Any] = {"branch": request.branch, "scenario_id": request.scenario_id,
                "outcome": "runtime_error", "llm_http_attempts": 0, "fallback_used": False,
                "human_review_required": True}
            try:
                if pipeline._source_manifest(self.paths) != self.sources:
                    raise ValueError("Pinned artifacts changed during demo session")
                paths = self.paths[request.scenario_id]
                corpus = pipeline.load_retrieval_corpus(paths["corpus_path"])
                scope = pipeline.assess_query_scope(request.query, corpus=corpus, graph={})
                emit("scope", scope)
                if scope["decision"] == "abstain":
                    row.update(outcome="abstain", gate_decision="abstain", eligibility_decision="abstain", abstention_stage="query_scope")
                else:
                    index = pipeline.load_vector_index(paths["index_path"])
                    if self.backend is None:
                        # Use the same pinned E5 backend, forced to local cache only.
                        embedding = index["embedding"]
                        self.backend = pipeline.SentenceTransformerEmbeddingBackend(model_id=embedding["model_id"],
                            model_revision=embedding["model_revision"], dimension=embedding["dimension"],
                            device="cpu", batch_size=32, show_progress_bar=False)
                        self.backend.load()
                    prepared = pipeline.prepare_branch(request.query, request.branch, paths, corpus, index,
                        self.backend, self.config, self.policy, emit)
                    row.update(prepared["row"])
                    if prepared["budget_exceeded"]:
                        row.update(outcome="abstain", eligibility_decision="abstain", abstention_stage="context_budget", budget_exceeded=True)
                    elif prepared["gate"]["decision"] == "abstain":
                        row["outcome"] = "abstain"
                    elif not self.live:
                        row["outcome"] = "dry_run_no_generation"
                    elif self.stopped:
                        row["outcome"] = "not_run_after_stop"
                    elif self.attempts >= self.max_requests:
                        row["outcome"] = "not_run_request_limit"
                    else:
                        generated, self.stopped = pipeline.generate_branch(prepared["messages"], prepared["context"],
                            self.llm_config, self.client_factory, emit)
                        row.update(generated)
                        self.attempts += row["llm_http_attempts"]
                if pipeline._source_manifest(self.paths) != self.sources:
                    raise ValueError("Pinned artifacts changed during demo request")
            except Exception as exc:
                # Do not expose provider payloads, credentials, local paths or exception text.
                row.update(outcome="runtime_error", error_type=type(exc).__name__)
            response = response_payload(request, row, artifacts, self.metadata(),
                {"mode": "new_demo_run", "directory": directory.relative_to(ROOT).as_posix(), "benchmark_result": False})
            emit("result", row)
            emit("response", response)
            return response

    def saved(self, case_id: str, branch: str) -> dict[str, Any]:
        if self.integrated:
            if branch not in pipeline.BRANCHES or case_id not in {p['case_id'] for p in self.presets()}:
                raise KeyError("Unknown integrated case")
            replay_manifest = self.config.get("saved_results_manifest")
            if replay_manifest and (ROOT / replay_manifest).is_file():
                index = read(ROOT / replay_manifest)
                if index["config_sha256"] != pipeline.sha256(self.config_path) or index["runtime_pin_sha256"] != pipeline.sha256(self.pin_path):
                    raise ValueError("Saved results profile/pin mismatch")
                entry = index["branches"][case_id + ":" + branch]
                source = (ROOT / entry["directory"]).resolve()
                if not source.is_relative_to((ROOT / "outputs").resolve()) or pipeline.sha256(source / "result.json") != entry["result_sha256"]:
                    raise ValueError("Saved result source hash mismatch")
                for filename, digest in entry.get("files_sha256", {}).items():
                    file = (source / filename).resolve()
                    if file.parent != source or pipeline.sha256(file) != digest:
                        raise ValueError("Saved evidence/report artifact hash mismatch")
                preset = next(p for p in self.presets() if p['case_id']==case_id)
                artifacts = {name:read(source / f"{name}.json") for name in ('scope','context','messages','gate','eligibility','evidence_contract','validation','validation_failure') if (source / f"{name}.json").is_file()}
                row = read(source / "result.json")
                return response_payload(ExperimentalRequest(query=preset['query'],scenario_id=preset['scenario_id'],branch=branch),
                    row, artifacts, self.metadata(), {"mode":"saved_experimental_replay", "source_directory":source.relative_to(ROOT).as_posix(),
                    "source_result_sha256":entry["result_sha256"], "llm_requests_this_replay":0,
                    "historical_llm_http_attempts":row["llm_http_attempts"], "benchmark_result":False})
            source = ROOT / self.pin["offline_preflight_path"] / f"{case_id}_{branch}"
            preset = next(p for p in self.presets() if p['case_id']==case_id)
            artifacts = {name:read(source / f"{name}.json") for name in ('scope','context','messages','gate','eligibility','evidence_contract') if (source / f"{name}.json").is_file()}
            return response_payload(ExperimentalRequest(query=preset['query'],scenario_id=preset['scenario_id'],branch=branch),
                read(source / 'result.json'), artifacts, self.metadata(), {"mode":"saved_offline_preflight", "source_directory":source.relative_to(ROOT).as_posix(),"llm_requests_this_replay":0,"benchmark_result":False})
        if case_id not in DEMO_IDS or branch not in pipeline.BRANCHES:
            raise KeyError("Unknown demo case or branch")
        preset = next(p for p in self.presets() if p["case_id"] == case_id)
        source = (PILOT if case_id == "PS02" else REMAINING) / f"{case_id}_{branch}"
        names = ("scope", "context", "messages", "gate", "eligibility", "evidence_contract", "validation", "validation_failure")
        artifacts = {name: read(source / f"{name}.json") for name in names if (source / f"{name}.json").is_file()}
        request = ExperimentalRequest(query=preset["query"], scenario_id=preset["scenario_id"], branch=branch)
        row = read(source / "result.json")
        return response_payload(request, row, artifacts, self.metadata(), {"mode": "saved_experimental_replay",
            "source_directory": source.relative_to(ROOT).as_posix(), "source_result_sha256": pipeline.sha256(source / "result.json"),
            "llm_requests_this_replay": 0, "historical_llm_http_attempts": row["llm_http_attempts"]})


def response_payload(request: ExperimentalRequest, row: dict[str, Any], artifacts: dict[str, Any],
                     metadata: dict[str, Any], provenance: dict[str, Any]) -> dict[str, Any]:
    validation = artifacts.get("validation", artifacts.get("validation_failure"))
    accepted = row["outcome"] == "accepted_draft" and validation and validation.get("status") == "passed"
    return {"request": request.model_dump(), "outcome": row["outcome"], "result": row,
            "scope": artifacts.get("scope"), "gate": artifacts.get("gate"), "eligibility": artifacts.get("eligibility"),
            "validation": validation, "report": validation.get("sanitized_report") if accepted else None,
            "diagnostic": validation if row["outcome"] == "validation_failed" else None,
            "context": artifacts.get("context"), "messages": artifacts.get("messages"),
            "evidence_contract": artifacts.get("evidence_contract"), "configuration": metadata,
            "provenance": provenance, "human_review_required": True}


def synthetic_fixture(outcome: str, metadata: dict[str, Any]) -> dict[str, Any]:
    """Transport/UI state fixtures; no security claims or invented log evidence."""
    if outcome not in FIXTURE_IDS:
        raise KeyError(outcome)
    scope = {"decision": "proceed", "reason_codes": []}
    gate = {"decision": "abstain" if outcome == "abstain" else "proceed", "reason_codes": ["synthetic_fixture_only"]}
    row = {"outcome": outcome, "gate_decision": gate["decision"], "eligibility_decision": gate["decision"],
           "llm_http_attempts": 0, "fallback_used": False, "human_review_required": True}
    artifacts: dict[str, Any] = {"scope": scope, "gate": gate}
    if outcome in ("accepted_draft", "validation_failed"):
        artifacts["validation"] = {"status": "passed" if outcome == "accepted_draft" else "validation_failed",
            "human_review_required": True, "issues": [] if outcome == "accepted_draft" else [{"reason": "synthetic_validation_rejection"}],
            "sanitized_report": {"direct_answer": "[SYNTHETIC UI FIXTURE] Draft minh họa trạng thái; không phải phân tích log."}}
    if outcome in ("provider_error", "rate_limited"):
        row["provider_error"] = {"kind": outcome, "http_status": 429 if outcome == "rate_limited" else 503, "automatic_retry": False}
    request = ExperimentalRequest(query="[SYNTHETIC UI FIXTURE] Không gọi provider.", scenario_id="regsvr32-c2", branch="rag")
    return response_payload(request, row, artifacts, metadata, {"mode": "synthetic_fixture", "fixture_id": outcome,
        "source_file": "src/threat_hunting/server/experimental.py:synthetic_fixture", "llm_requests": 0, "benchmark_result": False})


def create_app(session: ExperimentalSession) -> FastAPI:
    app = FastAPI(title="Experimental evidence-contract demo", docs_url=None, redoc_url=None)

    def validate_profile(profile):
        if profile not in {None, session.config.get('profile_id','historical-15x2'), 'historical-replay'}:
            raise HTTPException(422,'Unknown artifact profile')

    @app.get("/experimental-api/config")
    def configuration(profile: str | None = None) -> dict[str, Any]:
        validate_profile(profile)
        if profile == "historical-replay":
            return historical_configuration(session)
        return {**session.metadata(), "presets": session.presets(), "fixture_ids": FIXTURE_IDS}

    @app.post("/experimental-api/hunt")
    def hunt(request: ExperimentalRequest, profile: str | None = None) -> dict[str, Any]:
        validate_profile(profile)
        if profile == "historical-replay":
            raise HTTPException(409, "Historical profile permits saved replay only")
        return session.run(request)

    @app.get("/experimental-api/saved")
    def saved(case_id: str, branch: str, profile: str | None = None) -> dict[str, Any]:
        validate_profile(profile)
        try:
            if profile == "historical-replay":
                return historical_saved(session,case_id,branch)
            return session.saved(case_id, branch)
        except KeyError:
            raise HTTPException(404, "Unknown locked demo case/branch")

    @app.get("/experimental-api/fixture")
    def fixture(outcome: str) -> dict[str, Any]:
        try:
            return synthetic_fixture(outcome, session.metadata())
        except KeyError:
            raise HTTPException(404, "Unknown labeled fixture")

    # Explicit build entry; this service never mounts production API routes.
    app.mount("/", StaticFiles(directory=ROOT / "frontend/dist", html=True), name="frontend")
    return app


def historical_configuration(session: ExperimentalSession) -> dict:
    pin=read(PILOT / "manifest.json")
    config=read(CONFIG)
    cases=read(ROOT / config['benchmark'])['cases']
    return {**session.metadata(),"mode":"historical_replay_only","profile_id":"historical-replay","maximum_llm_requests":0,
            "config":config,"config_sha256":pin['config_sha256'],"model":pin['model'],"artifacts":pin['artifacts'],"generation_disabled":True,
            "evaluated_sources_sha256":pin['code_sha256'],"gate_policy_sha256":pin['gate_policy_sha256'],
            "served_by_runtime_source_sha256":session.evaluated_sources,
            "presets":[{'case_id':c['case_id'],'scenario_id':c['scenario_id'],'query':c['request']['query']} for c in cases if c['case_id'] in DEMO_IDS],
            "interpretation":"Saved checkpoint; current integrated code does not rerun or revise historical outcomes."}


def historical_saved(session: ExperimentalSession, case_id: str, branch: str) -> dict:
    if case_id not in DEMO_IDS or branch not in pipeline.BRANCHES: raise KeyError(case_id)
    preset=next(p for p in historical_configuration(session)['presets'] if p['case_id']==case_id)
    source=(PILOT if case_id=='PS02' else REMAINING)/f'{case_id}_{branch}'
    artifacts={name:read(source/f'{name}.json') for name in ('scope','context','messages','gate','eligibility','evidence_contract','validation','validation_failure') if (source/f'{name}.json').is_file()}
    return response_payload(ExperimentalRequest(query=preset['query'],scenario_id=preset['scenario_id'],branch=branch),read(source/'result.json'),artifacts,
        historical_configuration(session),{'mode':'saved_experimental_replay','source_directory':source.relative_to(ROOT).as_posix(),
                                         'source_result_sha256':pipeline.sha256(source/'result.json'),'llm_requests_this_replay':0})
