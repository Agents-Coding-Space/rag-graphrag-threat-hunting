#!/usr/bin/env python3
"""Compare existing vector indexes using pinned, local CPU query models.

No document embeddings are rebuilt. All source bytes are verified and all
provenance is validated before constructing any model backend. Model snapshots
must already exist outside the repository; both CLI modes prohibit downloads.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Iterator


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from threat_hunting.evaluation import (  # noqa: E402
    parse_embedding_retrieval_json_bytes,
    prepare_embedding_retrieval_run,
    run_embedding_retrieval_comparison,
    serialize_embedding_retrieval_comparison_report,
    validate_embedding_retrieval_comparison_report,
    validate_embedding_retrieval_run_config,
)
from threat_hunting.retrieval.embedding_backend import (  # noqa: E402
    SentenceTransformerEmbeddingBackend,
)


class EmbeddingRetrievalCliError(ValueError):
    """A run cannot safely load its sources or publish its report."""


_OFFLINE_ENV = {
    "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
    "HF_HUB_DISABLE_TELEMETRY": "1", "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
    "HF_HUB_DISABLE_PROGRESS_BARS": "1", "HF_HUB_DISABLE_SYMLINKS_WARNING": "1",
    "TOKENIZERS_PARALLELISM": "false", "DO_NOT_TRACK": "1",
}


def _repository_path(path: Path) -> Path:
    root = REPOSITORY_ROOT.resolve()
    candidate = (root / path).resolve()
    if not candidate.is_relative_to(root):
        raise EmbeddingRetrievalCliError("path must remain inside the repository")
    return candidate


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _assert_input_hashes(expected: Mapping[Path, str]) -> None:
    for path, digest in expected.items():
        if _sha256_file(path) != digest:
            label = path.relative_to(REPOSITORY_ROOT.resolve()).as_posix()
            raise EmbeddingRetrievalCliError(f"{label}: input SHA-256 mismatch")


def _resolve_offline_snapshot(embedding: Mapping[str, Any]) -> Path:
    """Locate the exact pinned commit without importing model libraries."""
    explicit = os.environ.get("HF_HUB_CACHE") or os.environ.get("HUGGINGFACE_HUB_CACHE")
    if explicit:
        cache = Path(explicit).expanduser()
    elif os.environ.get("HF_HOME"):
        cache = Path(os.environ["HF_HOME"]).expanduser() / "hub"
    else:
        base = Path(os.environ["XDG_CACHE_HOME"]).expanduser() if os.environ.get("XDG_CACHE_HOME") else Path.home() / ".cache"
        cache = base / "huggingface" / "hub"
    cache = cache.resolve()
    root = REPOSITORY_ROOT.resolve()
    if cache.is_relative_to(root):
        raise EmbeddingRetrievalCliError("offline model cache must be outside the repository")
    model_id, revision = embedding["model_id"], embedding["model_revision"]
    if len(model_id.split("/")) != 2 or any(
        not part or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in part)
        or part in (".", "..") for part in model_id.split("/")
    ):
        raise EmbeddingRetrievalCliError("model_id must identify a safe cached model")
    snapshot = (cache / ("models--" + model_id.replace("/", "--")) / "snapshots" / revision).resolve()
    if not snapshot.is_relative_to(cache) or snapshot.is_relative_to(root):
        raise EmbeddingRetrievalCliError("offline snapshot must remain in the external model cache")
    required = ("config.json", "modules.json", "tokenizer_config.json", "tokenizer.json")
    if any(not (snapshot / name).is_file() for name in required) or not any(
        (snapshot / name).is_file() for name in ("model.safetensors", "pytorch_model.bin")
    ):
        raise EmbeddingRetrievalCliError(f"missing offline snapshot for {model_id}@{revision}")
    manifest = parse_embedding_retrieval_json_bytes(
        b'{"modules":' + (snapshot / "modules.json").read_bytes() + b'}',
        source_path="cached modules.json",
    )
    if set(manifest) != {"modules"}:
        raise EmbeddingRetrievalCliError("invalid cached module manifest")
    modules = manifest["modules"]
    # These pinned SentenceTransformer models only use built-in modules. A
    # Normalize module legitimately has no directory or configuration file.
    if not isinstance(modules, list) or not modules:
        raise EmbeddingRetrievalCliError(f"invalid cached modules for {model_id}@{revision}")
    allowed = {"sentence_transformers.models.Transformer", "sentence_transformers.models.Pooling", "sentence_transformers.models.Normalize"}
    for module in modules:
        if not isinstance(module, dict) or module.get("type") not in allowed:
            raise EmbeddingRetrievalCliError("unsupported cached model module")
        label = module.get("path")
        if not isinstance(label, str) or "\\" in label or ":" in label or label.startswith("/") or any(part == ".." for part in label.split("/")):
            raise EmbeddingRetrievalCliError("unsafe cached model module path")
        if module["type"].endswith(".Pooling"):
            pooling = (snapshot / label / "config.json").resolve()
            if not pooling.is_relative_to(cache) or pooling.is_relative_to(root):
                raise EmbeddingRetrievalCliError("pooling configuration escapes the external cache")
            if not pooling.is_file():
                raise EmbeddingRetrievalCliError("missing offline pooling configuration")
    for name in required:
        resolved = (snapshot / name).resolve()
        if not resolved.is_relative_to(cache) or resolved.is_relative_to(root):
            raise EmbeddingRetrievalCliError("cached model file escapes the external cache")
    for name in ("model.safetensors", "pytorch_model.bin"):
        if (snapshot / name).is_file():
            resolved = (snapshot / name).resolve()
            if not resolved.is_relative_to(cache) or resolved.is_relative_to(root):
                raise EmbeddingRetrievalCliError("cached model weights escape the external cache")
    return snapshot


@contextmanager
def _offline_environment() -> Iterator[None]:
    previous = {key: os.environ.get(key) for key in _OFFLINE_ENV}
    os.environ.update(_OFFLINE_ENV)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _offline_model_factory(snapshot: Path) -> Callable[..., Any]:
    def load(model_id: str, *, revision: str, device: str) -> Any:
        # Import only after every source/index and every snapshot passed preflight.
        import torch
        from sentence_transformers import SentenceTransformer

        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        return SentenceTransformer(
            str(snapshot), revision=revision, device=device,
            cache_folder=str(snapshot.parents[2]), local_files_only=True,
            trust_remote_code=False, token=False,
        )
    return load


def _serialize_report(report: object) -> bytes:
    return serialize_embedding_retrieval_comparison_report(report)


def _read_back_report(path: Path, payload: bytes) -> None:
    actual = path.read_bytes()
    validate_embedding_retrieval_comparison_report(
        parse_embedding_retrieval_json_bytes(actual, source_path=path.name)
    )
    if actual != payload:
        raise EmbeddingRetrievalCliError("report read-back bytes differ from serialized output")


def _replace_bytes(path: Path, payload: bytes, *, create_only: bool = False) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if create_only:
            # Creating a hard link is atomic and fails if another writer has
            # created the output after the initial --overwrite check.
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _atomic_write_report(
    output: Path, payload: bytes, *, overwrite: bool, check_inputs: Callable[[], None],
) -> None:
    if output.exists() and not overwrite:
        raise EmbeddingRetrievalCliError("output already exists; use --overwrite")
    old_bytes = output.read_bytes() if output.exists() else None
    output.parent.mkdir(parents=True, exist_ok=True)
    complete = False
    publication_attempted = False
    published = False
    try:
        if (output.read_bytes() if output.exists() else None) != old_bytes:
            raise EmbeddingRetrievalCliError("output changed before publication")
        publication_attempted = True
        if overwrite:
            _replace_bytes(output, payload)
        else:
            _replace_bytes(output, payload, create_only=True)
        published = True
        _read_back_report(output, payload)
        check_inputs()
        complete = True
    finally:
        # finally also restores a publication interrupted by process-control
        # exceptions; those exceptions are never caught or converted.
        if not complete and publication_attempted:
            # A competing writer's output is not owned by this transaction.
            # Once publication succeeded, rollback must not require reading
            # the new file: read-back itself may be the failed operation.
            owned = published
            if not owned:
                owned = output.exists() and output.read_bytes() == payload
            if owned:
                if old_bytes is None:
                    output.unlink(missing_ok=True)
                else:
                    _replace_bytes(output, old_bytes)


def run_comparison_cli(
    *, config_path: Path, output_path: Path, offline: bool, overwrite: bool,
    backend_factory: Callable[..., Any] = SentenceTransformerEmbeddingBackend,
) -> dict[str, Any]:
    """Run using local caches, then transactionally publish one validated report."""
    try:
        original_output = REPOSITORY_ROOT.resolve() / output_path
        if original_output.is_symlink():
            raise EmbeddingRetrievalCliError("refusing symlink report output")
        config_file, output = _repository_path(config_path), _repository_path(output_path)
        if not output.is_relative_to((REPOSITORY_ROOT / "outputs" / "evaluation").resolve()):
            raise EmbeddingRetrievalCliError("report output must be in outputs/evaluation")
        config_payload = config_file.read_bytes()
        config = parse_embedding_retrieval_json_bytes(config_payload, source_path=config_path.as_posix())
        validate_embedding_retrieval_run_config(config)
        specs = {source["path"]: source["sha256"] for source in config["sources"].values()}
        for candidate in config["candidates"]:
            for kind in ("build_config", "vector_index"):
                specs[candidate[f"{kind}_path"]] = candidate[f"{kind}_sha256"]
        paths = {label: _repository_path(Path(label)) for label in specs}
        if len(set(paths.values())) != len(paths) or config_file in paths.values():
            raise EmbeddingRetrievalCliError("input paths resolve to overlapping files")
        if output in {config_file, *paths.values()}:
            raise EmbeddingRetrievalCliError("output overlaps a read-only input")
        if output.exists() and not overwrite:
            raise EmbeddingRetrievalCliError("output already exists; use --overwrite")
        expected = {config_file: sha256(config_payload).hexdigest(), **{paths[label]: digest for label, digest in specs.items()}}
        # Hash every referenced file BEFORE parsing any referenced JSON.
        _assert_input_hashes(expected)
        payloads = {label: path.read_bytes() for label, path in paths.items()}
        for label, payload in payloads.items():
            if sha256(payload).hexdigest() != specs[label]:
                raise EmbeddingRetrievalCliError(f"{label}: input SHA-256 changed while loading")
        documents = {label: parse_embedding_retrieval_json_bytes(payload, source_path=label) for label, payload in payloads.items()}
        plan = prepare_embedding_retrieval_run(config, documents, payloads)
        snapshots = {candidate["candidate_id"]: _resolve_offline_snapshot(candidate["embedding"]) for candidate in plan["candidates"]}
        query_counts = {candidate["candidate_id"]: 0 for candidate in plan["candidates"]}
        backends = {}
        # --offline expresses the caller's intent; cache-only loading is also
        # enforced without that flag. There is no network-enabled mode.
        with _offline_environment(), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            for candidate in plan["candidates"]:
                candidate_id = candidate["candidate_id"]
                embedding = candidate["embedding"]
                backends[candidate_id] = backend_factory(
                    model_id=embedding["model_id"], model_revision=embedding["model_revision"],
                    dimension=embedding["dimension"], device="cpu", batch_size=1,
                    show_progress_bar=False, model_factory=_offline_model_factory(snapshots[candidate_id]),
                )

            def callback(candidate_id: str) -> Callable[[list[str]], object]:
                def embed(texts: list[str]) -> object:
                    query_counts[candidate_id] += len(texts)
                    return backends[candidate_id](texts)
                return embed

            report = run_embedding_retrieval_comparison(
                config, documents, payloads,
                embedding_callbacks={candidate_id: callback(candidate_id) for candidate_id in backends},
            )
        if len(backends) != len(config["candidates"]) or any(count != len(plan["dataset"]["cases"]) for count in query_counts.values()):
            raise EmbeddingRetrievalCliError("backend/query counts do not match the complete evaluation")
        _assert_input_hashes(expected)
        payload = _serialize_report(report)
        _assert_input_hashes(expected)
        summary = {
            "output_path": output.relative_to(REPOSITORY_ROOT.resolve()).as_posix(),
            "output_sha256": sha256(payload).hexdigest(), "evaluation_id": report["evaluation_id"],
            "baseline_candidate_id": report["baseline_candidate_id"],
            "candidate_ids": [candidate["candidate_id"] for candidate in report["candidates"]],
            "case_count": report["metadata"]["case_count"], "ranking_limit": config["ranking_limit"],
            "pareto_result": {comparison["candidate_id"]: comparison["pareto"]["result"] for comparison in report["comparisons"]},
            "review_status": report["review"]["review_status"],
        }
        _atomic_write_report(output, payload, overwrite=overwrite, check_inputs=lambda: _assert_input_hashes(expected))
        return summary
    except EmbeddingRetrievalCliError:
        raise
    except Exception as exc:
        raise EmbeddingRetrievalCliError(f"cannot compare embedding retrieval models: {exc}") from exc


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise EmbeddingRetrievalCliError(message)


def main(
    argv: list[str] | None = None, *,
    backend_factory: Callable[..., Any] = SentenceTransformerEmbeddingBackend,
) -> int:
    parser = _ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    try:
        args = parser.parse_args(argv)
        summary = run_comparison_cli(
            config_path=args.config, output_path=args.output, offline=args.offline,
            overwrite=args.overwrite, backend_factory=backend_factory,
        )
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
