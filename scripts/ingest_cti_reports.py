"""Build provenance-linked CTI context entirely offline from fetched snapshots."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from threat_hunting.cti.ingestion import ingest_collection


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--selection", type=Path, default=ROOT / "configs/knowledge/cti_gap_sources_v1.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = ingest_collection(args.sources, json.loads(args.selection.read_text(encoding="utf-8")), args.output)
    print(json.dumps({"sources": len(result["sources"]), "chunks": len(result["chunks"]), "links": len(result["links"])}))


if __name__ == "__main__":
    main()
