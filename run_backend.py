#!/usr/bin/env python3
"""One-click entrypoint to launch Threat Hunting FastAPI Backend server."""

from pathlib import Path
import sys

# Detect project directories
REPO_ROOT = Path(__file__).resolve().parent
SRC_ROOT = REPO_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print("🛡️  THREAT HUNTING GRAPHRAG SOC BACKEND API SERVER")
    print("=" * 70)
    print(f"Project Root : {REPO_ROOT}")
    print(f"Source Root  : {SRC_ROOT}")
    print("API Endpoints:")
    print("  - http://127.0.0.1:8000/api/health")
    print("  - http://127.0.0.1:8000/api/scenarios")
    print("  - http://127.0.0.1:8000/api/graph?scenario_id=mshta-powershell")
    print("  - http://127.0.0.1:8000/api/hunt (POST)")
    print("  - http://127.0.0.1:8000/api/hunt/stream (SSE GET)")
    print("  - http://127.0.0.1:8000/docs (Swagger UI)")
    print("=" * 70)
    uvicorn.run("threat_hunting.server.app:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
