"""Fetch explicitly selected public reports as NEW inputs, never original Mordor evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

SOURCES = (
    ("redcanary-mshta", "https://redcanary.com/threat-detection-report/techniques/mshta/", "Red Canary", "Mshta | Red Canary Threat Detection Report"),
    ("uptycs-regsvr32", "https://www.uptycs.com/blog/threat-research-report-team/attackers-increasingly-adopting-regsvr32-utility-execution-via-office-documents", "Uptycs", "Attackers Increasingly Using Office Docs Regsvr32 Utility Execution"),
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for source_id, url, publisher, title in SOURCES:
        html_path = args.output / (source_id + ".html")
        metadata_path = args.output / (source_id + ".fetch.json")
        if html_path.exists() or metadata_path.exists():
            raise FileExistsError(f"Snapshot already exists: {html_path}")
        request = Request(url, headers={"User-Agent": "AcademicThreatHuntingResearch/1.0"})
        with urlopen(request, timeout=45) as response:
            content = response.read(5_000_001)
            if len(content) > 5_000_000:
                raise ValueError(f"Report exceeds snapshot limit: {url}")
            metadata = {"source_id": source_id, "url": url, "final_url": response.url, "title": title, "publisher": publisher,
                        "accessed_at": datetime.now(timezone.utc).isoformat(), "content_type": response.headers.get("Content-Type"),
                        "encoding": response.headers.get_content_charset() or "utf-8", "status": response.status,
                        "sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content), "snapshot_path": html_path.name,
                        "origin": "new_public_cti_report_acquired_for_20261030_gap_work", "evidence_layer": "cti_context"}
        with html_path.open("xb") as stream:
            stream.write(content)
        with metadata_path.open("x", encoding="utf-8") as stream:
            json.dump(metadata, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        print(json.dumps(metadata))


if __name__ == "__main__":
    main()
