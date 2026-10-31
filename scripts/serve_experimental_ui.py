"""Serve the explicit experimental UI, offline by default; never run a benchmark."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8002)
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/demo" / datetime.now(timezone.utc).strftime("experimental-ui-%Y%m%dT%H%M%S%fZ"))
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--max-requests", type=int, default=0)
    parser.add_argument("--config", type=Path, help="Explicit versioned research artifact configuration")
    parser.add_argument("--pin", type=Path, help="Frozen runtime provenance manifest for the selected version")
    args = parser.parse_args()
    if args.live != (1 <= args.max_requests <= 30):
        parser.error("Use offline defaults or --live --max-requests <1..30>")
    if not (ROOT / "frontend/dist/index.html").is_file():
        parser.error("Build frontend first: cd frontend && npm run build")
    from threat_hunting.server.experimental import ExperimentalSession, create_app
    import uvicorn
    try:
        session = ExperimentalSession(args.output, live=args.live, max_requests=args.max_requests, config_path=args.config, pin_path=args.pin)
    except Exception as exc:
        parser.exit(1, f"Experimental session failed: {type(exc).__name__}: {exc}\n")
    print(f"EXPERIMENTAL {'LIVE' if args.live else 'OFFLINE'}; cap={args.max_requests}; no retry/fallback", flush=True)
    print(f"http://127.0.0.1:{args.port}/", flush=True)
    uvicorn.run(create_app(session), host="127.0.0.1", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
