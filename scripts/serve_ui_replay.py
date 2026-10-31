"""Serve the built production UI components with saved responses; no LLM routes."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import importlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "outputs/review"
CASES = {
    "RG04": REVIEW / "rg04_generation_fix/20261025T220357_735920Z/response.json",
    "RG05": REVIEW / "live_llm_fixes/20261025T212918_870968Z/RG05.json",
    **{case: REVIEW / f"three_case_corrective_regression/20261025T223111_976089Z/{case}_response.json" for case in ("MS01", "MS04", "PS02")},
}
CASE_IDS = (*CASES, "provider_error", "rate_limited", "loading")


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def imported_source_manifest() -> dict:
    """Import production modules for identity only; never construct an LLM client."""
    sys.path.insert(0, str(ROOT / "src"))
    result = {}
    for name in ("server.app", "llm.prompt", "llm.schema", "llm.guardrail"):
        module = importlib.import_module(f"threat_hunting.{name}")
        path = Path(module.__file__).resolve()
        result[name] = {"file": path.relative_to(ROOT).as_posix(), "loaded_source_sha256": digest(path)}
    return result


def load_replay(case_id: str) -> dict:
    """Return historical response unchanged apart from explicit replay metadata."""
    if case_id not in CASE_IDS:
        raise KeyError(case_id)
    if case_id == "loading":
        return {"case_id": case_id, "response": None, "evidence_items": [], "provenance": {"mode": "synthetic_fixture", "source_file": "scripts/serve_ui_replay.py:loading", "sha256": digest(Path(__file__))}}
    if case_id in CASES:
        source = CASES[case_id]
        response = json.loads(source.read_text(encoding="utf-8"))
        provenance = {"mode": "saved_response", "source_file": source.relative_to(ROOT).as_posix(), "sha256": digest(source), "case_id": case_id}
    else:
        # Synthetic transport failure: no security entities or verdict are invented.
        response = {"status": "provider_error", "scenario_id": "mshta-powershell", "query": "[SYNTHETIC UI FIXTURE] Kiểm tra thông báo lỗi provider.",
                    "gate_decision": {"decision": "proceed"}, "subgraph": None, "retrieval_hits": [],
                    "report": {"schema_version": "threat-hunting-report/v1", "verdict": None, "ai_engine": "Offline Fallback (synthetic UI fixture)", "direct_answer": "Không có câu trả lời LLM. Đây là fixture kiểm tra lỗi kết nối.", "executive_summary": "", "technical_analysis": "", "attack_chain": [], "mitre_mappings": [], "sigma_matches": [], "containment_recommendations": [], "unverified_claims": [], "evidence_refs": []},
                    "error_message": "Provider rate limited (synthetic fixture)." if case_id == "rate_limited" else "Provider unavailable (synthetic fixture).",
                    "provider_error": {"kind": "rate_limited" if case_id == "rate_limited" else "connection_error", "http_status": 429 if case_id == "rate_limited" else None, "retry_after_seconds": 60 if case_id == "rate_limited" else None, "automatic_retry": False},
                    "validation": {"status": "not_evaluated", "scope": "structured_claims_only", "human_review_required": True, "issues": [], "reference_checks": []},
                    "execution": {"source": "offline_fallback", "llm_called": False, "generation_succeeded": False, "llm_http_attempts": 0, "fallback_used": True, "gate_enforced": True}}
        provenance = {"mode": "synthetic_fixture", "source_file": f"scripts/serve_ui_replay.py:{case_id}", "sha256": digest(Path(__file__)), "case_id": case_id}
    response = deepcopy(response)
    response["replay"] = provenance
    scenario_id = response["scenario_id"]
    runtime = json.loads((ROOT / "configs/runtime_artifacts.json").read_text(encoding="utf-8"))
    if scenario_id in runtime["scenarios"]:
        entry = runtime["scenarios"][scenario_id]
        gt_path = ROOT / entry["paths"]["gt_path"]
        if digest(gt_path) != entry["sha256"][gt_path.name]:
            raise ValueError(f"Pinned ground truth hash mismatch: {scenario_id}")
    else:
        gt_path = ROOT / "outputs/review/mshta-ground-truth/scenario_ground_truth.json"
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    evidence = [{key: item.get(key, []) if key in ("observations", "source_references") else item[key]
                 for key in ("evidence_id", "evidence_type", "summary", "status", "observations", "source_references")}
                for item in gt.get("evidence", [])]
    return {"case_id": case_id, "response": response, "evidence_items": evidence,
            "provenance": {**provenance, "evidence_source": gt_path.relative_to(ROOT).as_posix(), "evidence_sha256": digest(gt_path)}}


class ReplayHandler(BaseHTTPRequestHandler):
    """Only fixed read-only QA routes and built assets are exposed."""

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:5173")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        url = urlparse(self.path)
        if url.path == "/qa-api/health":
            payload = {"mode": "replay_only", "llm_routes": False, "cases": CASE_IDS,
                       "loaded_server_sha256": self.server.loaded_sha256,
                       "current_server_sha256": digest(Path(__file__)),
                       "imported_production_sources": getattr(self.server, "imported_sources", {}),
                       "frontend_sources": {p.relative_to(ROOT).as_posix(): digest(p) for p in (ROOT / "frontend/src").rglob("*") if p.is_file()},
                       "frontend_assets": {p.relative_to(ROOT / "frontend/dist").as_posix(): digest(p) for p in (ROOT / "frontend/dist").rglob("*") if p.is_file()}}
        elif url.path == "/qa-api/replay":
            case_id = parse_qs(url.query).get("case", ["RG04"])[0]
            try:
                payload = load_replay(case_id)
            except KeyError:
                self.send_bytes(404, b"Unknown fixed replay case", "text/plain")
                return
        elif url.path in ("/", "/qa.html") or url.path.startswith("/assets/"):
            relative = "qa.html" if url.path in ("/", "/qa.html") else url.path.lstrip("/")
            base = (ROOT / "frontend/dist").resolve()
            asset = (base / relative).resolve()
            if not asset.is_relative_to(base) or not asset.is_file():
                self.send_bytes(404, b"Build frontend first: npm run build", "text/plain")
                return
            self.send_bytes(200, asset.read_bytes(), mimetypes.guess_type(asset.name)[0] or "application/octet-stream")
            return
        else:
            self.send_bytes(404, b"Replay-only server. No production API routes.", "text/plain")
            return
        self.send_bytes(200, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_POST(self) -> None:
        self.send_bytes(405, b"No POST or LLM routes in replay server", "text/plain")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), ReplayHandler)
    server.loaded_sha256 = digest(Path(__file__))
    server.imported_sources = imported_source_manifest()
    print(f"REPLAY/MOCK only: http://127.0.0.1:{args.port}/qa.html?case=RG04", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
