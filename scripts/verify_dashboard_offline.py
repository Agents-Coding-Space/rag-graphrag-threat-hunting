"""HTTP smoke for the main build + existing experimental contract; refuse a live service."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8003")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to((ROOT / "outputs/demo").resolve()):
        parser.error("Output must be inside outputs/demo")
    output.mkdir(parents=True, exist_ok=False)

    def get(path: str) -> bytes:
        with urlopen(args.base_url + path, timeout=180) as response:
            return response.read()

    config = json.loads(get("/experimental-api/config"))
    assert config["mode"] == "experimental_offline_demo", "Refusing hunt on a live server"
    assert config["maximum_llm_requests"] == config["llm_http_attempts"] == 0
    checks = []
    for route, file in (("/", "index.html"), ("/experimental.html", "experimental.html")):
        body = get(route)
        assert body == (ROOT / "frontend/dist" / file).read_bytes()
        checks.append({"route": route, "sha256": hashlib.sha256(body).hexdigest()})
    for branch in ("rag", "graphrag"):
        request = {"query": "Which command line launched PurpleSharp.exe? Trả lời bằng tiếng Việt.",
                   "scenario_id": "purplesharp-ad", "branch": branch}
        assert all(preset["query"] != request["query"] for preset in config["presets"])
        with urlopen(Request(args.base_url + "/experimental-api/hunt",
                             data=json.dumps(request, ensure_ascii=False).encode("utf-8"),
                             headers={"Content-Type": "application/json"}, method="POST"), timeout=180) as handle:
            response = json.load(handle)
        assert response["request"] == request
        assert response["outcome"] in ("dry_run_no_generation", "abstain"), response["outcome"]
        assert response["report"] is None
        assert response["result"]["llm_http_attempts"] == 0
        (output / f"free_query_{branch}.json").write_text(json.dumps(response, ensure_ascii=False, indent=2), encoding="utf-8")
        checks.append({"branch": branch, "outcome": response["outcome"], "free_query": True,
                       "evidence_units": len((response["evidence_contract"] or {}).get("units", [])),
                       "traversal_nodes": len(((response["context"] or {}).get("traversal") or {}).get("nodes", []))})
        saved = json.loads(get(f"/experimental-api/saved?case_id=PS02&branch={branch}"))
        assert saved["outcome"] == "accepted_draft" and saved["validation"]["status"] == "passed"
        assert saved["provenance"]["llm_requests_this_replay"] == 0
        (output / f"saved_PS02_{branch}.json").write_text(json.dumps(saved, ensure_ascii=False, indent=2), encoding="utf-8")
        checks.append({"branch": branch, "saved_replay": "accepted_draft", "new_llm_requests": 0})
    final = json.loads(get("/experimental-api/config"))
    assert final["llm_http_attempts"] == 0 and final["mode"] == "experimental_offline_demo"
    result = {"passed": True, "checks": checks, "llm_http_attempts": 0,
              "scope": "HTTP smoke only; not browser QA"}
    (output / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
