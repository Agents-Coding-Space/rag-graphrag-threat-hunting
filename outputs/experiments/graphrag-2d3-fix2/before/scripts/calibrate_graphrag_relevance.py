#!/usr/bin/env python3
"""Calibrate explicit relevance policies against reused offline GraphRAG contexts."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, NoReturn


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPOSITORY_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from threat_hunting.evaluation.calibration_config import (  # noqa: E402
    generate_policy_candidates, load_calibration_config,
)
from threat_hunting.evaluation.calibration_schema import (  # noqa: E402
    build_calibration_report, load_calibration_report, validate_calibration_report,
)
from threat_hunting.evaluation.relevance_calibration import calibrate_relevance_policies  # noqa: E402
from threat_hunting.evaluation.relevance_dataset import load_relevance_calibration_dataset  # noqa: E402
from threat_hunting.graph import load_knowledge_graph  # noqa: E402
from threat_hunting.graphrag import build_graphrag_context  # noqa: E402
from threat_hunting.ground_truth import load_ground_truth_document  # noqa: E402
from threat_hunting.retrieval import (  # noqa: E402
    SentenceTransformerEmbeddingBackend, load_retrieval_corpus, load_vector_index,
)


class GraphRAGCalibrationCliError(ValueError):
    """Calibration could not produce a complete, verified report."""


def _expected_hash(value: str, option: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise GraphRAGCalibrationCliError(f"{option} must contain exactly 64 hexadecimal characters")
    return value.lower()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise GraphRAGCalibrationCliError(f"cannot hash input {path}: {exc}") from exc
    return digest.hexdigest()


def _assert_input_hashes(inputs: dict[str, tuple[Path, str]], *, phase: str) -> None:
    for path, expected in inputs.values():
        actual = _sha256_file(path)
        if actual != expected:
            raise GraphRAGCalibrationCliError(
                f"input SHA-256 mismatch {phase} for {path}: expected {expected}, got {actual}"
            )


def _serialize(document: object) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("utf-8", errors="strict")


def _preflight(
    documents: dict[str, Any], inputs: dict[str, tuple[Path, str]],
) -> None:
    dataset, config, corpus, index, graph, ground_truth = (
        documents[name] for name in ("dataset", "config", "corpus", "index", "graph", "ground_truth")
    )
    index_source = index["corpus_provenance"]
    for name in ("corpus_id", "scenario_id", "schema_version"):
        if index_source[name] != corpus[name]:
            raise GraphRAGCalibrationCliError(f"preflight: Vector Index {name} differs from Retrieval Corpus")
    if index_source["sha256"].lower() != inputs["corpus"][1]:
        raise GraphRAGCalibrationCliError("preflight: Vector Index corpus SHA-256 differs from input")
    scenario = corpus["scenario_id"]
    if any(identifier != scenario for identifier in (
        graph["scenario_id"], dataset["scenario_id"], ground_truth["scenario"]["scenario_id"],
    )):
        raise GraphRAGCalibrationCliError("preflight: dataset, corpus, graph and Ground Truth scenario_id mismatch")
    source = corpus["source_ground_truth"]
    if _serialize(source) != _serialize(graph["source_ground_truth"]):
        raise GraphRAGCalibrationCliError("preflight: corpus/graph Ground Truth provenance mismatch")
    if (
        source["sha256"].lower() != inputs["ground_truth"][1]
        or source["schema_version"] != ground_truth["schema_version"]
        or source["scenario_id"] != scenario
        or Path(source["path"]).resolve() != inputs["ground_truth"][0].resolve()
    ):
        raise GraphRAGCalibrationCliError("preflight: Ground Truth provenance does not match supplied input")
    if len(dataset["cases"]) != config["expected_case_count"]:
        raise GraphRAGCalibrationCliError("preflight: dataset case count differs from config expected_case_count")
    embedding = index["embedding"]
    if embedding["provider"] != "sentence-transformers":
        raise GraphRAGCalibrationCliError("Vector Index embedding.provider must be sentence-transformers")
    if re.fullmatch(r"[0-9a-fA-F]{40}", embedding["model_revision"]) is None:
        raise GraphRAGCalibrationCliError("Vector Index model_revision must be a full 40-character hexadecimal commit SHA")


def _offline_model_factory(cache_dir: Path) -> Callable[..., Any]:
    def factory(model_id: str, *, revision: str, device: str) -> Any:
        for setting in (
            "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY",
            "HF_HUB_DISABLE_IMPLICIT_TOKEN", "HF_HUB_DISABLE_PROGRESS_BARS", "DO_NOT_TRACK",
        ):
            os.environ[setting] = "1"
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer(
            model_id, revision=revision, device=device, cache_folder=str(cache_dir),
            local_files_only=True, token=False, trust_remote_code=False,
        )
    return factory


def _atomic_write_report(
    output_path: Path, serialized: bytes, *, overwrite: bool,
    expected_previous: bytes | None, check_inputs: Callable[[str], None],
) -> None:
    """Install verified bytes atomically; restore the previous report on failure.

    A hard link implements create-without-overwrite even if another writer races.
    Replacement checks the original bytes again before install. Every temporary
    file is in the destination directory and is removed on all exception paths.
    """
    temporary: Path | None = None
    installed = False
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output_path.parent, prefix=".calibration-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        load_calibration_report(temporary)
        if temporary.read_bytes() != serialized:
            raise GraphRAGCalibrationCliError(f"temporary report bytes changed: {temporary}")
        check_inputs("after serialization and temporary read-back, before install")
        if expected_previous is None:
            os.link(temporary, output_path)
        else:
            if not overwrite or output_path.read_bytes() != expected_previous:
                raise GraphRAGCalibrationCliError(f"report changed before overwrite: {output_path}")
            os.replace(temporary, output_path)
        installed = True
        load_calibration_report(output_path)
        if output_path.read_bytes() != serialized:
            raise GraphRAGCalibrationCliError(f"installed report bytes changed: {output_path}")
        check_inputs("after report write and read-back")
    except Exception as exc:
        if installed:
            try:
                if output_path.read_bytes() != serialized:
                    raise GraphRAGCalibrationCliError("refusing to roll back another writer's changed report")
                if expected_previous is None:
                    output_path.unlink()
                else:
                    with tempfile.NamedTemporaryFile(dir=output_path.parent, prefix=".calibration-rollback-", suffix=".tmp", delete=False) as handle:
                        rollback = Path(handle.name)
                        try:
                            handle.write(expected_previous)
                            handle.flush()
                            os.fsync(handle.fileno())
                        except Exception:
                            handle.close()
                            rollback.unlink(missing_ok=True)
                            raise
                    try:
                        os.replace(rollback, output_path)
                    finally:
                        rollback.unlink(missing_ok=True)
            except Exception as rollback_error:
                raise GraphRAGCalibrationCliError(f"cannot write report {output_path}: {exc}; rollback failed: {rollback_error}") from exc
        raise GraphRAGCalibrationCliError(f"cannot write report {output_path}: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_calibration(
    *, dataset_path: Path, config_path: Path, corpus_path: Path,
    vector_index_path: Path, graph_path: Path, ground_truth_path: Path,
    output_path: Path, cache_dir: Path,
    expected_dataset_sha256: str, expected_config_sha256: str,
    expected_corpus_sha256: str, expected_index_sha256: str,
    expected_graph_sha256: str, expected_ground_truth_sha256: str,
    overwrite: bool = False, backend_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Generate each context once and reuse one lazy backend for the complete run."""
    try:
        inputs = {
            name: (Path(path), _expected_hash(expected, "--expected-" + name.replace("_", "-") + "-sha256"))
            for name, path, expected in (
                ("dataset", dataset_path, expected_dataset_sha256),
                ("config", config_path, expected_config_sha256),
                ("corpus", corpus_path, expected_corpus_sha256),
                ("index", vector_index_path, expected_index_sha256),
                ("graph", graph_path, expected_graph_sha256),
                ("ground_truth", ground_truth_path, expected_ground_truth_sha256),
            )
        }
        output_path, cache_dir = Path(output_path), Path(cache_dir).resolve()
        resolved_output = output_path.resolve()
        if resolved_output in {path.resolve() for path, _ in inputs.values()}:
            raise GraphRAGCalibrationCliError("report output must differ from every input artifact")
        if cache_dir.is_relative_to(REPOSITORY_ROOT.resolve()):
            raise GraphRAGCalibrationCliError("embedding cache must be outside the repository")
        if not cache_dir.is_dir() or resolved_output.is_relative_to(cache_dir):
            raise GraphRAGCalibrationCliError("cache must be an existing directory separate from report output")
        if output_path.is_symlink():
            raise GraphRAGCalibrationCliError(f"refusing symlink report output: {output_path}")
        previous = output_path.read_bytes() if output_path.exists() else None
        if previous is not None and not overwrite:
            raise GraphRAGCalibrationCliError(f"report already exists; use --overwrite: {output_path}")

        def check_inputs(phase: str) -> None:
            _assert_input_hashes(inputs, phase=phase)

        with redirect_stdout(sys.stderr):
            check_inputs("before load")
            loaders = {
                "dataset": load_relevance_calibration_dataset, "config": load_calibration_config,
                "corpus": load_retrieval_corpus, "index": load_vector_index,
                "graph": load_knowledge_graph, "ground_truth": load_ground_truth_document,
            }
            documents = {name: loader(inputs[name][0]) for name, loader in loaders.items()}
            _preflight(documents, inputs)
            check_inputs("after preflight")
            config, index = documents["config"], documents["index"]
            embedding, runtime = index["embedding"], config["embedding_runtime"]
            candidates = generate_policy_candidates(config["candidate_search_space"], max_candidate_policies=config["max_candidate_policies"])
            if backend_factory is None:
                snapshot = cache_dir / ("models--" + embedding["model_id"].replace("/", "--")) / "snapshots" / embedding["model_revision"]
                if not (snapshot / "modules.json").is_file():
                    raise GraphRAGCalibrationCliError(f"offline embedding snapshot is missing: {snapshot}")
            backend: Any = None

            def embed_query(texts: list[str]) -> object:
                nonlocal backend
                if backend is None:
                    factory = backend_factory if backend_factory is not None else SentenceTransformerEmbeddingBackend
                    backend = factory(
                        model_id=embedding["model_id"], model_revision=embedding["model_revision"],
                        dimension=embedding["dimension"], device=runtime["device"],
                        batch_size=runtime["batch_size"], show_progress_bar=runtime["show_progress_bar"],
                        model_factory=_offline_model_factory(cache_dir),
                    )
                    if not callable(getattr(backend, "embed_documents", None)):
                        raise GraphRAGCalibrationCliError("embedding backend must provide embed_documents()")
                return backend.embed_documents(texts)

            contexts = {}
            for case in documents["dataset"]["cases"]:
                contexts[case["case_id"]] = build_graphrag_context(
                    documents["corpus"], index, documents["graph"], case["query"],
                    corpus_sha256=inputs["corpus"][1], embed_query=embed_query,
                    **config["retrieval"], **config["traversal"],
                )
                check_inputs("after query " + case["case_id"])
            print(f"calibration: {len(contexts)} contexts; {len(candidates)} candidate policies", file=sys.stderr)
            result = calibrate_relevance_policies(
                documents["dataset"], contexts, candidate_policies=candidates,
                selection_constraints=config["selection_constraints"],
            )
            check_inputs("after calibration")
            provenance = {}
            for name, identity in (
                ("dataset", ("dataset_id", "scenario_id")), ("config", ("calibration_id",)),
                ("corpus", ("corpus_id", "scenario_id")), ("index", ("index_id",)),
                ("graph", ("graph_id", "scenario_id")), ("ground_truth", ()),
            ):
                document = documents[name]
                descriptor = {"path": inputs[name][0].as_posix(), "sha256": inputs[name][1],
                              "schema_version": document["schema_version"],
                              **{field: document[field] for field in identity}}
                if name == "index":
                    descriptor.update({field: document["corpus_provenance"][field] for field in ("corpus_id", "scenario_id")})
                if name == "ground_truth":
                    descriptor["scenario_id"] = document["scenario"]["scenario_id"]
                provenance["vector_index" if name == "index" else name] = descriptor
            provenance["embedding"] = embedding
            report = build_calibration_report(
                result, calibration_id=config["calibration_id"], provenance=provenance,
                candidate_search_space=config["candidate_search_space"],
                execution={"graphrag_context_count": len(contexts), "embedding_backend_count": int(backend is not None),
                           **{name: config[name] for name in ("retrieval", "traversal", "embedding_runtime")}},
            )
            validate_calibration_report(report)
            serialized = _serialize(report)
            check_inputs("after serialization")
            _atomic_write_report(output_path, serialized, overwrite=overwrite,
                                 expected_previous=previous, check_inputs=check_inputs)
        return report
    except GraphRAGCalibrationCliError:
        raise
    except Exception as exc:
        raise GraphRAGCalibrationCliError(f"GraphRAG calibration failed: {exc}") from exc


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise GraphRAGCalibrationCliError(message)


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(description=__doc__, allow_abbrev=False)
    for option in ("dataset", "config", "corpus", "vector-index", "graph", "ground-truth", "output", "cache-dir"):
        parser.add_argument("--" + option, type=Path, required=True)
    for name in ("dataset", "config", "corpus", "index", "graph", "ground-truth"):
        parser.add_argument("--expected-" + name + "-sha256", required=True)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None, *, backend_factory: Callable[..., Any] | None = None) -> int:
    try:
        for stream in (sys.stdout, sys.stderr):
            reconfigure = getattr(stream, "reconfigure", None)
            if callable(reconfigure):
                reconfigure(encoding="utf-8", errors="strict", newline="\n")
        args = _build_parser().parse_args(argv)
        report = run_calibration(
            **{name + "_path": getattr(args, name) for name in ("dataset", "config", "corpus", "vector_index", "graph", "ground_truth")},
            **{name: getattr(args, name) for name in (
                "expected_dataset_sha256", "expected_config_sha256", "expected_corpus_sha256",
                "expected_index_sha256", "expected_graph_sha256", "expected_ground_truth_sha256",
            )},
            output_path=args.output, cache_dir=args.cache_dir, overwrite=args.overwrite,
            backend_factory=backend_factory,
        )
        summary = {"output": args.output.as_posix(), "sha256": _sha256_file(args.output),
                   "case_count": report["calibration"]["case_count"], "candidate_count": report["calibration"]["candidate_count"],
                   "selection_status": report["calibration"]["selection_status"]}
        sys.stdout.write(_serialize(summary).decode("utf-8"))
        sys.stdout.flush()
        return 0
    except Exception as exc:
        message = str(exc).encode("utf-8", errors="backslashreplace").decode("utf-8")
        print(f"error: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
