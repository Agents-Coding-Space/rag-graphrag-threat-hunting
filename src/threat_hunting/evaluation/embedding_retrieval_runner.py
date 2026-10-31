"""Run a reproducible comparison with caller-provided query embedding callbacks.

All paths are provenance labels. This module performs no file I/O, model
loading, network access, or document embedding. Exact raw source bytes bind
every supplied document before any callback runs. Labels are validated for
referential integrity, while retrieval receives only the original query.

Scores are preserved exactly as returned by the existing vector retriever:
it rounds cosine similarities to eight decimal places before ordering and
omits scores that are non-positive at that precision. The runner adds no
threshold, prefix, normalization, relevance filter, or metric calculation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from hashlib import sha256
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Any, NoReturn
import unicodedata

from ..retrieval.schema import RETRIEVAL_CORPUS_SCHEMA_VERSION
from ..retrieval.vector_schema import EMBEDDING_FIELDS, validate_vector_index
from ..retrieval.vector_search import retrieve_vector
from .embedding_retrieval_comparison import compare_embedding_retrieval_rankings
from .embedding_retrieval_comparison_schema import snapshot_json
from .retrieval_judgments import resolve_retrieval_judgments


EMBEDDING_RETRIEVAL_RUN_CONFIG_SCHEMA_VERSION = "embedding-retrieval-run-config/v1"
_BUILD_CONFIG_SCHEMA_VERSION = "vector-index-build-config/v1"
_CONFIG_FIELDS = (
    "schema_version", "baseline_candidate_id", "ranking_limit", "sources", "candidates",
)
_SOURCE_ROLES = ("calibration_dataset", "retrieval_judgments", "retrieval_corpus")
_CANDIDATE_FIELDS = (
    "candidate_id", "build_config_path", "build_config_sha256",
    "vector_index_path", "vector_index_sha256",
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_CREDENTIAL_FIELDS = frozenset({
    "token", "tokens", "credential", "credentials", "secret", "secrets",
    "password", "api_key", "apikey", "access_token", "refresh_token",
    "auth_token", "authorization", "authentication_token", "private_key",
})
_CONFIG_QUERY_FIELDS = frozenset({"query", "queries", "question", "questions", "expected_decision"})


class EmbeddingRetrievalRunnerError(ValueError):
    """Raised when configuration, provenance, or query retrieval is invalid."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _normalized(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold().replace("-", "_").strip()


def _scan_guards(value: object, path: str, *, config: bool) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = _normalized(key)
            if normalized in _CREDENTIAL_FIELDS or (config and normalized in _CONFIG_QUERY_FIELDS):
                raise EmbeddingRetrievalRunnerError(f"{path}.{key} is forbidden")
            _scan_guards(child, f"{path}.{key}", config=config)
    elif isinstance(value, list):
        for position, child in enumerate(value):
            _scan_guards(child, f"{path}[{position}]", config=config)


def _snapshot(value: object, path: str, *, config: bool = False) -> Any:
    detached = snapshot_json(value, path)
    _scan_guards(detached, path, config=config)
    return detached


def _object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EmbeddingRetrievalRunnerError(f"{path} must be a JSON object")
    return value


def _exact_fields(value: Mapping[str, Any], fields: tuple[str, ...], path: str) -> None:
    missing = sorted(set(fields) - set(value))
    unexpected = sorted(set(value) - set(fields))
    if missing or unexpected:
        raise EmbeddingRetrievalRunnerError(
            f"{path} fields must match the contract: missing {missing!r}; unexpected {unexpected!r}"
        )


def _text(value: object, path: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value.strip()):
        qualifier = "a string" if empty else "a non-empty string"
        raise EmbeddingRetrievalRunnerError(f"{path} must be {qualifier}")
    return value


def _positive_integer(value: object, path: str) -> int:
    if type(value) is not int or value < 1:
        raise EmbeddingRetrievalRunnerError(f"{path} must be a positive integer, not a boolean")
    return value


def _digest(value: object, path: str) -> str:
    digest = _text(value, path)
    if _SHA256_PATTERN.fullmatch(digest) is None:
        raise EmbeddingRetrievalRunnerError(f"{path} must be a lowercase full SHA-256")
    return digest


def _safe_path(value: object, path: str) -> str:
    label = _text(value, path)
    if (
        "\\" in label or ":" in label or PurePosixPath(label).is_absolute()
        or PureWindowsPath(label).drive
        or any(part in ("", ".", "..") for part in label.split("/"))
        or any(ord(character) < 32 for character in label)
    ):
        raise EmbeddingRetrievalRunnerError(f"{path} must be a safe repository-relative POSIX path")
    return label


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise EmbeddingRetrievalRunnerError(f"duplicate JSON object key {key!r}")
        document[key] = value
    return document


def _reject_nonstandard_number(value: str) -> NoReturn:
    raise EmbeddingRetrievalRunnerError(f"non-standard JSON number {value!r}")


def parse_embedding_retrieval_json_bytes(
    payload: bytes, *, source_path: str = "<memory>",
) -> dict[str, Any]:
    """Strictly parse an in-memory UTF-8 JSON object without accessing its path.

    Source dataset queries and expected decisions are allowed. Recursive
    answer/model-output, credential, and confirmed guards apply to all sources;
    the run configuration has an additional query-field guard.
    """
    try:
        if type(payload) is not bytes:
            raise EmbeddingRetrievalRunnerError(f"{source_path}: JSON payload must be bytes")
        document = json.loads(
            payload.decode("utf-8", errors="strict"), object_pairs_hook=_unique_pairs,
            parse_constant=_reject_nonstandard_number,
        )
        is_run_config = (
            isinstance(document, Mapping)
            and document.get("schema_version") == EMBEDDING_RETRIEVAL_RUN_CONFIG_SCHEMA_VERSION
        )
        detached = _snapshot(document, f"{source_path}:$", config=is_run_config)
        return dict(_object(detached, f"{source_path}:$"))
    except EmbeddingRetrievalRunnerError as exc:
        raise EmbeddingRetrievalRunnerError(f"{source_path}: cannot parse JSON: {exc}") from exc
    except Exception as exc:
        raise EmbeddingRetrievalRunnerError(f"{source_path}: cannot parse JSON: {exc}") from exc


def _validate_config(config: Mapping[str, Any]) -> None:
    _exact_fields(config, _CONFIG_FIELDS, "$config")
    if config["schema_version"] != EMBEDDING_RETRIEVAL_RUN_CONFIG_SCHEMA_VERSION:
        raise EmbeddingRetrievalRunnerError(
            f"$config.schema_version must be {EMBEDDING_RETRIEVAL_RUN_CONFIG_SCHEMA_VERSION!r}"
        )
    if _positive_integer(config["ranking_limit"], "$config.ranking_limit") != 10:
        raise EmbeddingRetrievalRunnerError("$config.ranking_limit must be 10")
    baseline = _text(config["baseline_candidate_id"], "$config.baseline_candidate_id")
    sources = _object(config["sources"], "$config.sources")
    _exact_fields(sources, _SOURCE_ROLES, "$config.sources")
    paths: set[str] = set()

    def register_path(value: object, path: str) -> None:
        label = _safe_path(value, path)
        if label in paths:
            raise EmbeddingRetrievalRunnerError(f"{path} duplicates an input path {label!r}")
        paths.add(label)

    for role in _SOURCE_ROLES:
        source = _object(sources[role], f"$config.sources.{role}")
        _exact_fields(source, ("path", "sha256"), f"$config.sources.{role}")
        register_path(source["path"], f"$config.sources.{role}.path")
        _digest(source["sha256"], f"$config.sources.{role}.sha256")
    candidates = config["candidates"]
    if not isinstance(candidates, list) or len(candidates) < 2:
        raise EmbeddingRetrievalRunnerError("$config.candidates must contain at least two candidates")
    ids: list[str] = []
    for position, value in enumerate(candidates):
        path = f"$config.candidates[{position}]"
        candidate = _object(value, path)
        _exact_fields(candidate, _CANDIDATE_FIELDS, path)
        ids.append(_text(candidate["candidate_id"], f"{path}.candidate_id"))
        for kind in ("build_config", "vector_index"):
            register_path(candidate[f"{kind}_path"], f"{path}.{kind}_path")
            _digest(candidate[f"{kind}_sha256"], f"{path}.{kind}_sha256")
    if ids != sorted(set(ids)):
        raise EmbeddingRetrievalRunnerError("$config.candidates must have unique, sorted candidate IDs")
    if baseline not in ids:
        raise EmbeddingRetrievalRunnerError("$config.baseline_candidate_id must identify a declared candidate")


def validate_embedding_retrieval_run_config(config: object) -> None:
    """Validate the exact run contract, including safe paths and fixed limit."""
    try:
        detached = _object(_snapshot(config, "$config", config=True), "$config")
        _validate_config(detached)
    except EmbeddingRetrievalRunnerError:
        raise
    except Exception as exc:
        raise EmbeddingRetrievalRunnerError(f"cannot validate embedding retrieval run config: {exc}") from exc


def _input_specs(config: Mapping[str, Any]) -> dict[str, str]:
    specs = {config["sources"][role]["path"]: config["sources"][role]["sha256"] for role in _SOURCE_ROLES}
    for candidate in config["candidates"]:
        for kind in ("build_config", "vector_index"):
            specs[candidate[f"{kind}_path"]] = candidate[f"{kind}_sha256"]
    return specs


def _exact_input_mapping(value: object, paths: set[str], label: str) -> Mapping[str, Any]:
    mapping = _object(value, label)
    if any(not isinstance(key, str) for key in mapping):
        raise EmbeddingRetrievalRunnerError(f"{label} must have string path labels")
    if set(mapping) != paths:
        raise EmbeddingRetrievalRunnerError(
            f"{label} must contain exactly the declared paths: "
            f"missing {sorted(paths - set(mapping))!r}; unexpected {sorted(set(mapping) - paths)!r}"
        )
    return mapping


def _validate_build_config(config: Mapping[str, Any], path: str) -> None:
    _exact_fields(config, ("schema_version", "embedding", "runtime"), path)
    if config["schema_version"] != _BUILD_CONFIG_SCHEMA_VERSION:
        raise EmbeddingRetrievalRunnerError(f"{path}.schema_version must be {_BUILD_CONFIG_SCHEMA_VERSION!r}")
    embedding = _object(config["embedding"], f"{path}.embedding")
    _exact_fields(embedding, EMBEDDING_FIELDS, f"{path}.embedding")
    if embedding["provider"] != "sentence-transformers":
        raise EmbeddingRetrievalRunnerError(f"{path}.embedding.provider must be 'sentence-transformers'")
    _text(embedding["model_id"], f"{path}.embedding.model_id")
    revision = _text(embedding["model_revision"], f"{path}.embedding.model_revision")
    if _REVISION_PATTERN.fullmatch(revision) is None:
        raise EmbeddingRetrievalRunnerError(f"{path}.embedding.model_revision must be a full lowercase 40-hex commit SHA")
    _positive_integer(embedding["dimension"], f"{path}.embedding.dimension")
    if embedding["distance_metric"] != "cosine":
        raise EmbeddingRetrievalRunnerError(f"{path}.embedding.distance_metric must be 'cosine'")
    if embedding["normalization"] not in ("none", "l2"):
        raise EmbeddingRetrievalRunnerError(f"{path}.embedding.normalization must be 'none' or 'l2'")
    for field in ("document_prefix", "query_prefix"):
        _text(embedding[field], f"{path}.embedding.{field}", empty=True)
    runtime = _object(config["runtime"], f"{path}.runtime")
    _exact_fields(runtime, ("device", "batch_size", "show_progress_bar"), f"{path}.runtime")
    if runtime["device"] != "cpu":
        raise EmbeddingRetrievalRunnerError(f"{path}.runtime.device must be 'cpu'")
    _positive_integer(runtime["batch_size"], f"{path}.runtime.batch_size")
    if runtime["show_progress_bar"] is not False:
        raise EmbeddingRetrievalRunnerError(f"{path}.runtime.show_progress_bar must be false")


def _validate_index_links(
    index: Mapping[str, Any], build_config: Mapping[str, Any],
    corpus: Mapping[str, Any], corpus_source: Mapping[str, Any], path: str,
) -> None:
    validate_vector_index(index)
    if _canonical(index["embedding"]) != _canonical(build_config["embedding"]):
        raise EmbeddingRetrievalRunnerError(f"{path}.embedding must exactly match its build configuration")
    expected_provenance = {
        "path": corpus_source["path"], "sha256": corpus_source["sha256"],
        "schema_version": RETRIEVAL_CORPUS_SCHEMA_VERSION,
        "corpus_id": corpus["corpus_id"], "scenario_id": corpus["scenario_id"],
    }
    if _canonical(index["corpus_provenance"]) != _canonical(expected_provenance):
        raise EmbeddingRetrievalRunnerError(f"{path}.corpus_provenance must match the exact supplied corpus source")
    if index["metadata"]["complete_corpus_coverage"] is not True:
        raise EmbeddingRetrievalRunnerError(f"{path}.metadata.complete_corpus_coverage must be true")
    chunks = {chunk["chunk_id"]: chunk for chunk in corpus["chunks"]}
    records = index["records"]
    if {record["chunk_id"] for record in records} != set(chunks):
        raise EmbeddingRetrievalRunnerError(f"{path}.records must cover exactly every corpus chunk")
    for record in records:
        chunk = chunks[record["chunk_id"]]
        if record["chunk_type"] != chunk["chunk_type"]:
            raise EmbeddingRetrievalRunnerError(f"{path}.records chunk {record['chunk_id']!r} has a chunk_type mismatch")
        digest = sha256(chunk["content"].encode("utf-8", errors="strict")).hexdigest()
        if record["content_sha256"].lower() != digest:
            raise EmbeddingRetrievalRunnerError(f"{path}.records chunk {record['chunk_id']!r} has a content_sha256 mismatch")


def prepare_embedding_retrieval_run(
    config: object, documents: Mapping[str, object], source_bytes: Mapping[str, bytes],
) -> dict[str, Any]:
    """Validate and detach all inputs before callbacks or backend construction.

    Both mappings must contain exactly the configured source paths. Hashes use
    the supplied bytes, never reserialized JSON. Resolved relevance labels are
    discarded after integrity checks; source documents remain available for
    the comparison core after retrieval finishes.
    """
    try:
        checked_config = _object(_snapshot(config, "$config", config=True), "$config")
        _validate_config(checked_config)
        specs = _input_specs(checked_config)
        paths = set(specs)
        checked_documents = _exact_input_mapping(documents, paths, "$.documents")
        checked_bytes = _exact_input_mapping(source_bytes, paths, "$.source_bytes")
        payloads = {path: checked_bytes[path] for path in specs}
        detached: dict[str, Any] = {}
        for path, expected_hash in specs.items():
            payload = payloads[path]
            if type(payload) is not bytes:
                raise EmbeddingRetrievalRunnerError(f"{path}: source payload must be bytes")
            if sha256(payload).hexdigest() != expected_hash:
                raise EmbeddingRetrievalRunnerError(f"{path}: source SHA-256 mismatch")
            parsed = parse_embedding_retrieval_json_bytes(payload, source_path=path)
            supplied = _object(_snapshot(checked_documents[path], f"$.documents[{path!r}]"), path)
            if _canonical(parsed) != _canonical(supplied):
                raise EmbeddingRetrievalRunnerError(f"{path}: raw bytes do not match the supplied document")
            detached[path] = parsed
        sources = checked_config["sources"]
        dataset_path = sources["calibration_dataset"]["path"]
        judgments_path = sources["retrieval_judgments"]["path"]
        corpus_path = sources["retrieval_corpus"]["path"]
        dataset, judgments, corpus = (detached[path] for path in (dataset_path, judgments_path, corpus_path))
        # Resolve for preflight referential integrity only. Resolved relevance
        # labels are never retained in the query plan or passed to retrieval.
        resolve_retrieval_judgments(
            judgments, dataset, corpus,
            source_dataset_path=dataset_path, source_dataset_bytes=payloads[dataset_path],
            source_corpus_path=corpus_path, source_corpus_bytes=payloads[corpus_path],
        )
        if "chunk_count" in corpus["metadata"]:
            count = corpus["metadata"]["chunk_count"]
            if type(count) is not int or count != len(corpus["chunks"]):
                raise EmbeddingRetrievalRunnerError("$.corpus.metadata.chunk_count must equal the actual integer chunk count")
        support_groups = {(case["category"], case["language"]) for case in dataset["cases"]}
        for category in ("relevant_direct", "relevant_paraphrase", "insufficient_evidence"):
            for language in ("en", "vi"):
                if (category, language) not in support_groups:
                    raise EmbeddingRetrievalRunnerError(f"$.dataset.cases missing required support group {category!r} + {language!r}")
        candidates = []
        index_ids: set[str] = set()
        for candidate in checked_config["candidates"]:
            build_config_path = candidate["build_config_path"]
            index_path = candidate["vector_index_path"]
            build_config = detached[build_config_path]
            index = detached[index_path]
            _validate_build_config(build_config, build_config_path)
            _validate_index_links(index, build_config, corpus, sources["retrieval_corpus"], index_path)
            if index["index_id"] in index_ids:
                raise EmbeddingRetrievalRunnerError(f"{index_path}: duplicate index_id {index['index_id']!r}")
            index_ids.add(index["index_id"])
            candidates.append({
                "candidate_id": candidate["candidate_id"], "build_config": build_config,
                "vector_index": index, "embedding": dict(index["embedding"]),
                "index_sha256": candidate["vector_index_sha256"],
            })
        return {
            "config": dict(checked_config), "dataset": dataset, "judgments": judgments,
            "corpus": corpus, "candidates": candidates,
        }
    except EmbeddingRetrievalRunnerError:
        raise
    except Exception as exc:
        raise EmbeddingRetrievalRunnerError(f"cannot prepare embedding retrieval run: {exc}") from exc


def run_embedding_retrieval_comparison(
    config: object, documents: Mapping[str, object], source_bytes: Mapping[str, bytes], *,
    embedding_callbacks: Mapping[str, Callable[[list[str]], object]],
) -> dict[str, Any]:
    """Retrieve every case for every candidate, then call the comparison core.

    Callback instances are reused for each candidate and receive only query
    text through retrieve_vector, which adds the index query prefix exactly
    once. Input documents are detached before callbacks can mutate their
    callers' references. KeyboardInterrupt and SystemExit remain interrupts.
    """
    try:
        if not isinstance(source_bytes, Mapping):
            raise EmbeddingRetrievalRunnerError("$.source_bytes must be a mapping")
        payloads = dict(source_bytes)
        prepared = prepare_embedding_retrieval_run(config, documents, payloads)
        candidates = prepared["candidates"]
        candidate_ids = {candidate["candidate_id"] for candidate in candidates}
        callback_mapping = _object(embedding_callbacks, "$.embedding_callbacks")
        if set(callback_mapping) != candidate_ids:
            raise EmbeddingRetrievalRunnerError("$.embedding_callbacks must identify exactly the declared candidates")
        callbacks = {candidate_id: callback_mapping[candidate_id] for candidate_id in candidate_ids}
        if any(not callable(callback) for callback in callbacks.values()):
            raise EmbeddingRetrievalRunnerError("$.embedding_callbacks values must be callable")
        run_config = prepared["config"]
        sources = run_config["sources"]
        corpus_source = sources["retrieval_corpus"]
        query_plan = sorted(
            ((case["case_id"], case["query"]) for case in prepared["dataset"]["cases"]),
            key=lambda case: case[0],
        )
        candidate_runs = []
        for candidate in candidates:
            candidate_id = candidate["candidate_id"]
            index = candidate["vector_index"]
            rankings = []
            for case_id, query in query_plan:
                result = retrieve_vector(
                    prepared["corpus"], index, query,
                    corpus_sha256=corpus_source["sha256"],
                    embed_query=callbacks[candidate_id], top_k=run_config["ranking_limit"],
                    chunk_types=None, required_dimensions=None,
                )
                rankings.append({
                    "case_id": case_id,
                    "hits": [{"chunk_id": hit["chunk"]["chunk_id"], "score": hit["score"]}
                             for hit in result["hits"]],
                })
            candidate_runs.append({
                "candidate_id": candidate_id, "index_id": index["index_id"],
                "index_sha256": candidate["index_sha256"], "embedding": candidate["embedding"],
                "ranking_limit": run_config["ranking_limit"], "rankings": rankings,
            })
        dataset_source = sources["calibration_dataset"]
        judgments_source = sources["retrieval_judgments"]
        return compare_embedding_retrieval_rankings(
            prepared["dataset"], prepared["judgments"], prepared["corpus"], candidate_runs,
            source_dataset_path=dataset_source["path"], source_dataset_bytes=payloads[dataset_source["path"]],
            source_judgments_path=judgments_source["path"], source_judgments_bytes=payloads[judgments_source["path"]],
            source_corpus_path=corpus_source["path"], source_corpus_bytes=payloads[corpus_source["path"]],
            baseline_candidate_id=run_config["baseline_candidate_id"],
        )
    except EmbeddingRetrievalRunnerError:
        raise
    except Exception as exc:
        raise EmbeddingRetrievalRunnerError(f"cannot run embedding retrieval comparison: {exc}") from exc


__all__ = (
    "EMBEDDING_RETRIEVAL_RUN_CONFIG_SCHEMA_VERSION", "EmbeddingRetrievalRunnerError",
    "parse_embedding_retrieval_json_bytes", "validate_embedding_retrieval_run_config",
    "prepare_embedding_retrieval_run", "run_embedding_retrieval_comparison",
)
