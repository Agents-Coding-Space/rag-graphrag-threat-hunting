"""Record the execution environment next to a frozen profile; reads no network, writes one file."""
from __future__ import annotations

import argparse
import json
import platform as pf
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="integrated-final-direct-v13",
                        help="Profile id; output goes to outputs/final/<profile>/execution_environment.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    import importlib.metadata as meta
    import numpy
    import torch

    def version(name: str) -> str | None:
        try:
            return meta.version(name)
        except Exception:
            return None

    index_path = ROOT / "outputs/integrated/20261030_v5/consumers/mshta-powershell/vector_index_e5.json"
    embedding = json.loads(index_path.read_text(encoding="utf-8-sig"))["embedding"]

    record = {
        "schema_version": "execution-environment/v1",
        "profile": args.profile,
        "python": pf.python_version(),
        "implementation": pf.python_implementation(),
        "platform": pf.platform(),
        "machine": pf.machine(),
        "packages": {name: version(name) for name in (
            "numpy", "torch", "transformers", "huggingface-hub", "sentence-transformers",
            "scikit-learn", "scipy", "PyYAML", "fastapi", "uvicorn", "pydantic",
            "httpx", "python-dotenv", "pytest")},
        "numeric_runtime": {
            "numpy": numpy.__version__,
            "torch": torch.__version__,
            "cuda_available": bool(torch.cuda.is_available()),
            "torch_threads": torch.get_num_threads(),
        },
        "embedding": {
            "model_id": embedding["model_id"],
            "model_revision": embedding["model_revision"],
            "dimension": embedding["dimension"],
            "distance_metric": embedding.get("distance_metric"),
            "normalization": embedding.get("normalization"),
            "query_prefix": embedding.get("query_prefix"),
            "document_prefix": embedding.get("document_prefix"),
        },
        "tolerance_policy": {
            "policy_id": "reproducibility-tolerance/v1",
            "applies_to": "vector similarity scores and RRF component scores inside a context document",
            "absolute": 1e-6,
            "relative": 1e-6,
            "exact_fields": ["hit order", "chunk ids", "evidence ids", "gate reason codes", "all non-numeric fields"],
            "note": "Frozen artifact hashes are always exact; tolerance never applies to a stored file.",
        },
        "reproducibility_doc": "docs/REPRODUCIBILITY.md",
    }

    output = args.output or ROOT / f"outputs/final/{args.profile}/execution_environment.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(output.relative_to(ROOT).as_posix()),
                      "python": record["python"], "numpy": record["numeric_runtime"]["numpy"],
                      "torch": record["numeric_runtime"]["torch"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
