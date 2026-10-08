"""In-memory orchestration contracts with synthetic artifacts and fake vectors.

Regenerate only the expected context fixture after intentional contract changes:
    python -c "import runpy; runpy.run_path('tests/test_graphrag_orchestrator.py')['_regenerate_expected_fixture']()"
The helper executes the real API with query='synthetic', vector=[1, 0, 0], and
default options. It never reads production artifacts or loads an embedding model.
"""

from __future__ import annotations

import ast
import builtins
from collections.abc import Iterator
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import socket
from typing import Any

import pytest

from threat_hunting import graphrag
from threat_hunting.graph import traverse_knowledge_graph, validate_knowledge_graph
from threat_hunting.graphrag import (
    GRAPHRAG_CONTEXT_SCHEMA_VERSION,
    GraphRAGOrchestrationError,
    build_graphrag_context,
    map_hybrid_hits_to_graph_seeds,
)
from threat_hunting.graphrag import orchestrator
from threat_hunting.retrieval import (
    retrieve_hybrid,
    validate_retrieval_corpus,
    validate_vector_index,
)


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "tests/fixtures/retrieval/builder/expected_retrieval_corpus.json"
INDEX_PATH = ROOT / "tests/fixtures/retrieval/vector_builder/expected_vector_index.json"
GRAPH_PATH = ROOT / "tests/fixtures/graph/builder/expected_knowledge_graph.json"
EXPECTED_PATH = ROOT / "tests/fixtures/graphrag/orchestrator/expected_graphrag_context.json"
IMPLEMENTATION_PATH = ROOT / "src/threat_hunting/graphrag/orchestrator.py"
CONTEXT_FIELDS = {
    "schema_version", "corpus_id", "graph_id", "scenario_id", "source_ground_truth",
    "query", "retrieval", "seed_mapping", "traversal", "warnings", "metadata",
}
METADATA_FIELDS = {
    "retrieval_hit_count", "mapped_hit_count", "seed_node_count", "traversal_performed",
    "traversed_node_count", "traversed_edge_count", "traversed_path_count",
}
SKIP_WARNING = "Graph traversal skipped: no retrieval hits or graph seeds are available."
ArtifactSet = tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_artifacts() -> ArtifactSet:
    corpus, index, graph = (_json(path) for path in (CORPUS_PATH, INDEX_PATH, GRAPH_PATH))
    validate_retrieval_corpus(corpus)
    validate_vector_index(index)
    validate_knowledge_graph(graph)
    digest = sha256(CORPUS_PATH.read_bytes()).hexdigest()
    assert digest == index["corpus_provenance"]["sha256"]
    assert corpus["source_ground_truth"] == graph["source_ground_truth"]
    return corpus, index, graph, digest


@pytest.fixture
def artifacts() -> ArtifactSet:
    return _load_artifacts()


def _embed(texts: list[str]) -> list[list[float]]:
    return [[1.0, 0.0, 0.0] for _ in texts]


def _build(artifacts: ArtifactSet, **options: Any) -> dict[str, Any]:
    corpus, index, graph, digest = artifacts
    return build_graphrag_context(
        corpus, index, graph, options.pop("query", "synthetic"),
        corpus_sha256=options.pop("corpus_sha256", digest),
        embed_query=options.pop("embed_query", _embed), **options,
    )


def _serialize(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                       indent=2) + "\n").encode("utf-8")


def _regenerate_expected_fixture() -> None:
    """Rebuild only this synthetic output from the documented API invocation."""
    first, second = _build(_load_artifacts()), _build(_load_artifacts())
    assert _serialize(first) == _serialize(second)
    EXPECTED_PATH.parent.mkdir(parents=True, exist_ok=True)
    EXPECTED_PATH.write_bytes(_serialize(first))
    assert _json(EXPECTED_PATH) == first


def _walk(value: object) -> Iterator[object]:
    yield value
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk(item)


def _containers(value: object) -> set[int]:
    return {id(item) for item in _walk(value) if isinstance(item, (dict, list))}


def _assert_detached(copied: object, original: object) -> None:
    assert copied == original
    assert _containers(copied).isdisjoint(_containers(original))


def _key(source: dict[str, Any]) -> tuple[str, str | None, str]:
    return source["object_type"], source["object_id"], source["json_pointer"]


def _match(graph: dict[str, Any], chunk: dict[str, Any]) -> dict[str, Any]:
    objects = graph["edges"] if chunk["chunk_type"] == "relationship" else graph["nodes"]
    matches = [item for item in objects if _key(item["source"]) == _key(chunk["source"])]
    assert len(matches) == 1
    return matches[0]


def _component_results(artifacts: ArtifactSet) -> tuple[dict[str, Any], ...]:
    corpus, index, graph, digest = artifacts
    retrieval = retrieve_hybrid(corpus, index, "synthetic", corpus_sha256=digest,
                                embed_query=_embed)
    mapping = map_hybrid_hits_to_graph_seeds(corpus, retrieval, graph)
    traversal = traverse_knowledge_graph(graph, seed_node_ids=mapping["seed_node_ids"])
    return retrieval, mapping, traversal


def _patch_components(monkeypatch: pytest.MonkeyPatch, results: tuple[dict[str, Any], ...]) -> None:
    for name, result in zip(
        ("retrieve_hybrid", "map_hybrid_hits_to_graph_seeds", "traverse_knowledge_graph"),
        results, strict=True,
    ):
        monkeypatch.setattr(orchestrator, name, lambda *args, _result=result, **kwargs: _result)


def test_public_exports_exact_envelope_and_complete_components(artifacts) -> None:
    corpus, _, graph, _ = artifacts
    result = _build(artifacts)
    retrieval, mapping, traversal = _component_results(artifacts)
    assert GRAPHRAG_CONTEXT_SCHEMA_VERSION == "graphrag-context/v1"
    assert issubclass(GraphRAGOrchestrationError, ValueError)
    assert build_graphrag_context is orchestrator.build_graphrag_context
    assert GraphRAGOrchestrationError is orchestrator.GraphRAGOrchestrationError
    assert graphrag.map_hybrid_hits_to_graph_seeds is map_hybrid_hits_to_graph_seeds
    assert set(result) == CONTEXT_FIELDS
    assert set(result["metadata"]) == METADATA_FIELDS
    assert result["schema_version"] == GRAPHRAG_CONTEXT_SCHEMA_VERSION
    assert result["corpus_id"] == corpus["corpus_id"]
    assert result["graph_id"] == graph["graph_id"]
    assert result["scenario_id"] == corpus["scenario_id"] == graph["scenario_id"]
    assert result["source_ground_truth"] == corpus["source_ground_truth"]
    assert result["query"] == retrieval["query"]
    assert result["retrieval"] == retrieval
    assert result["seed_mapping"] == mapping
    assert result["traversal"] == traversal
    assert result["metadata"] == {
        "retrieval_hit_count": len(retrieval["hits"]),
        "mapped_hit_count": len(mapping["hit_mappings"]),
        "seed_node_count": len(mapping["seed_node_ids"]), "traversal_performed": True,
        "traversed_node_count": len(traversal["nodes"]),
        "traversed_edge_count": len(traversal["edges"]),
        "traversed_path_count": len(traversal["paths"]),
    }


@pytest.mark.parametrize("chunk_type", [
    "scenario_summary", "entity", "fact", "evidence", "sigma_finding",
    "mitre_assessment", "limitation",
])
def test_single_direct_hit_has_exactly_one_seed(artifacts, chunk_type: str) -> None:
    result = _build(artifacts, chunk_types=[chunk_type], top_k=1, max_depth=0)
    chunk = result["retrieval"]["hits"][0]["chunk"]
    node = _match(artifacts[2], chunk)
    mapping = result["seed_mapping"]["hit_mappings"][0]
    assert chunk["chunk_type"] == chunk_type
    assert mapping["mapping_kind"] == "direct_node"
    assert mapping["matched_node_ids"] == [node["node_id"]]
    assert mapping["matched_edge_ids"] == []
    assert result["seed_mapping"]["seed_node_ids"] == [node["node_id"]]
    assert result["traversal"]["seed_node_ids"] == [node["node_id"]]
    assert result["metadata"]["seed_node_count"] == 1
    if chunk_type in {"scenario_summary", "limitation"}:
        assert chunk["source"]["object_id"] is None
        assert node["source"]["object_id"] is None


def test_relationship_hit_maps_edge_and_only_two_endpoint_seeds(artifacts) -> None:
    result = _build(artifacts, chunk_types=["relationship"], top_k=1, max_depth=0)
    chunk = result["retrieval"]["hits"][0]["chunk"]
    edge = _match(artifacts[2], chunk)
    endpoints = sorted({edge["source_node_id"], edge["target_node_id"]})
    mapping = result["seed_mapping"]["hit_mappings"][0]
    assert len(endpoints) == 2
    assert mapping["mapping_kind"] == "relationship_edge"
    assert mapping["matched_edge_ids"] == [edge["edge_id"]]
    assert mapping["matched_node_ids"] == endpoints
    assert result["seed_mapping"]["seed_node_ids"] == endpoints
    assert result["traversal"]["seed_node_ids"] == endpoints
    assert [node["node_id"] for node in result["traversal"]["nodes"]] == endpoints
    assert set(edge["supporting_node_ids"]).isdisjoint(endpoints)


def test_all_hits_keep_rank_order_and_all_deduplicated_seeds_reach_traversal(artifacts) -> None:
    result = _build(artifacts, top_k=15)
    retrieval, mapping, traversal = (result[name] for name in ("retrieval", "seed_mapping", "traversal"))
    assert len(retrieval["hits"]) == len(artifacts[0]["chunks"]) == 15
    assert [item["chunk_id"] for item in mapping["hit_mappings"]] == [
        hit["chunk"]["chunk_id"] for hit in retrieval["hits"]
    ]
    assert [item["hit_rank"] for item in mapping["hit_mappings"]] == list(range(1, 16))
    all_nodes = [node_id for item in mapping["hit_mappings"] for node_id in item["matched_node_ids"]]
    assert len(all_nodes) > len(set(all_nodes))
    assert mapping["seed_node_ids"] == sorted(set(all_nodes))
    assert traversal["seed_node_ids"] == mapping["seed_node_ids"]
    assert traversal["request"]["seed_node_ids"] == mapping["seed_node_ids"]
    assert set(mapping["seed_node_ids"]).issubset(node["node_id"] for node in traversal["nodes"])
    for item, hit in zip(mapping["hit_mappings"], retrieval["hits"], strict=True):
        assert item["hit_score"] == hit["score"]
        assert item["components"] == hit["components"]
        assert item["source"] == hit["chunk"]["source"]


@pytest.mark.parametrize("direction", ["outgoing", "incoming", "both"])
def test_traversal_direction_is_forwarded_unchanged(artifacts, direction: str) -> None:
    result = _build(artifacts, direction=direction)
    expected = traverse_knowledge_graph(artifacts[2],
        seed_node_ids=result["seed_mapping"]["seed_node_ids"], direction=direction)
    assert result["traversal"] == expected
    assert result["traversal"]["request"]["direction"] == direction


@pytest.mark.parametrize("depth", [0, 1, 3])
def test_max_depth_is_forwarded_and_respected(artifacts, depth: int) -> None:
    result = _build(artifacts, max_depth=depth)
    traversal = result["traversal"]
    assert traversal["request"]["max_depth"] == depth
    assert all(path["depth"] <= depth for path in traversal["paths"])
    if depth == 0:
        assert traversal["edges"] == []


@pytest.mark.parametrize("allowed", [None, [], ["supports"], ["synthetic_unknown"]])
def test_edge_filter_is_forwarded_including_empty_collection(artifacts, allowed) -> None:
    result = _build(artifacts, allowed_edge_types=allowed)
    traversal = result["traversal"]
    assert traversal["request"]["allowed_edge_types"] == allowed
    assert allowed is None or all(edge["edge_type"] in allowed for edge in traversal["edges"])
    if allowed == [] or allowed == ["synthetic_unknown"]:
        assert traversal["edges"] == []


@pytest.mark.parametrize("chunk_type,node_limit,edge_limit,counts,applied_limit", [
    ("entity", 1, 200, (1, 0, 1, 0), "max_nodes"),
    ("entity", 100, 1, (2, 1, 2, 1), "max_edges"),
    ("relationship", 2, 200, (2, 1, 4, 1), "max_nodes"),
    ("relationship", 100, 1, (3, 1, 3, 1), "max_edges"),
])
def test_traversal_limits_and_truncation_metadata_are_preserved(
    artifacts, chunk_type, node_limit, edge_limit, counts, applied_limit,
) -> None:
    result = _build(artifacts, chunk_types=[chunk_type], top_k=1,
                    max_nodes=node_limit, max_edges=edge_limit)
    traversal = result["traversal"]
    assert traversal["request"]["max_nodes"] == node_limit
    assert traversal["request"]["max_edges"] == edge_limit
    assert len(traversal["nodes"]) <= node_limit
    assert len(traversal["edges"]) <= edge_limit
    nodes, edges, paths, reached_depth = counts
    assert traversal["metadata"] == {
        "node_count": nodes, "edge_count": edges, "path_count": paths,
        "max_reached_depth": reached_depth, "truncated": True,
        "applied_limits": [applied_limit],
    }
    warning = f"Traversal result truncated by {applied_limit}={traversal['request'][applied_limit]}."
    assert warning in traversal["warnings"]
    assert warning in result["warnings"]
    assert set(traversal["warnings"]).issubset(result["warnings"])
    assert result["metadata"]["traversed_node_count"] == traversal["metadata"]["node_count"]
    assert result["metadata"]["traversed_edge_count"] == traversal["metadata"]["edge_count"]
    assert result["metadata"]["traversed_path_count"] == traversal["metadata"]["path_count"]


def test_relationship_edge_keeps_supporting_references_outside_bounded_neighborhood(artifacts) -> None:
    graph = artifacts[2]
    relationship_types = sorted({edge["edge_type"] for edge in graph["edges"]
                                 if edge["source"]["object_type"] == "relationship"})
    result = _build(artifacts, chunk_types=["relationship"], top_k=1, max_depth=1,
                    max_nodes=2, allowed_edge_types=relationship_types)
    chunk = result["retrieval"]["hits"][0]["chunk"]
    original = _match(graph, chunk)
    traversal = result["traversal"]
    returned_ids = {node["node_id"] for node in traversal["nodes"]}
    assert len(returned_ids) == 2
    assert traversal["edges"] == [original]
    assert original["supporting_node_ids"]
    assert set(original["supporting_node_ids"]).isdisjoint(returned_ids)
    assert set(original["supporting_node_ids"]).issubset(node["node_id"] for node in graph["nodes"])
    _assert_detached(traversal["edges"][0], original)


def test_component_calls_receive_original_inputs_complete_options_and_all_seeds(artifacts, monkeypatch) -> None:
    corpus, index, graph, digest = artifacts
    calls = []

    def retrieve(*args, **kwargs):
        calls.append(("retrieval", args, kwargs))
        return retrieve_hybrid(*args, **kwargs)

    def mapping(*args, **kwargs):
        calls.append(("mapping", args, kwargs))
        return map_hybrid_hits_to_graph_seeds(*args, **kwargs)

    def traversal(*args, **kwargs):
        calls.append(("traversal", args, kwargs))
        return traverse_knowledge_graph(*args, **kwargs)

    for name, function in (("retrieve_hybrid", retrieve),
                           ("map_hybrid_hits_to_graph_seeds", mapping),
                           ("traverse_knowledge_graph", traversal)):
        monkeypatch.setattr(orchestrator, name, function)
    dimensions = ["provenance"]
    types = ["entity", "relationship"]
    edges = ["supports"]
    result = _build(artifacts, query="synthetic activity", top_k=3, candidate_k=7,
        chunk_types=types, required_dimensions=dimensions, direction="incoming",
        max_depth=1, allowed_edge_types=edges, max_nodes=12, max_edges=8)
    assert [call[0] for call in calls] == ["retrieval", "mapping", "traversal"]
    assert calls[0][1] == (corpus, index, "synthetic activity")
    assert calls[0][1][0] is corpus and calls[0][1][1] is index
    assert calls[0][2] == {"corpus_sha256": digest, "embed_query": _embed,
        "top_k": 3, "candidate_k": 7, "chunk_types": types, "required_dimensions": dimensions}
    assert calls[1][1][0] is corpus and calls[1][1][2] is graph
    assert calls[1][1][1] == result["retrieval"]
    assert calls[2][1][0] is graph
    assert calls[2][2] == {"seed_node_ids": result["seed_mapping"]["seed_node_ids"],
        "direction": "incoming", "max_depth": 1, "allowed_edge_types": edges,
        "max_nodes": 12, "max_edges": 8}


def test_selected_graph_objects_statuses_attributes_and_provenance_are_unchanged(artifacts) -> None:
    result = _build(artifacts, top_k=15)
    graph = artifacts[2]
    for collection, field in (("nodes", "node_id"), ("edges", "edge_id")):
        originals = {item[field]: item for item in graph[collection]}
        for item in result["traversal"][collection]:
            assert item == originals[item[field]]
            _assert_detached(item, originals[item[field]])
    assert result["source_ground_truth"] == graph["source_ground_truth"]


def test_mitre_assessment_remains_candidate_without_confirmed_promotion(artifacts) -> None:
    result = _build(artifacts, chunk_types=["mitre_assessment"], top_k=1, max_depth=0)
    chunk = result["retrieval"]["hits"][0]["chunk"]
    node = result["traversal"]["nodes"][0]
    original = _match(artifacts[2], chunk)
    assert chunk["status"] == node["status"] == "candidate"
    assert node == original
    assert "confirmed" not in list(_walk(result))


def test_no_hits_produce_null_traversal_zero_counts_and_skip_warning(artifacts) -> None:
    result = _build(artifacts, chunk_types=[])
    assert result["retrieval"]["hits"] == []
    assert result["seed_mapping"]["hit_mappings"] == []
    assert result["seed_mapping"]["seed_node_ids"] == []
    assert result["traversal"] is None
    assert SKIP_WARNING in result["warnings"]
    assert result["metadata"] == {"retrieval_hit_count": 0, "mapped_hit_count": 0,
        "seed_node_count": 0, "traversal_performed": False, "traversed_node_count": 0,
        "traversed_edge_count": 0, "traversed_path_count": 0}
    assert set(result["retrieval"]["warnings"]).issubset(result["warnings"])
    assert set(result["seed_mapping"]["warnings"]).issubset(result["warnings"])


def test_no_hits_never_call_traversal_and_still_use_current_embedding_contract(artifacts, monkeypatch) -> None:
    calls = []

    def forbidden(*args, **kwargs):
        pytest.fail("Traversal must not be called without hits/seeds")

    def embedding(texts):
        calls.append(deepcopy(texts))
        return _embed(texts)

    monkeypatch.setattr(orchestrator, "traverse_knowledge_graph", forbidden)
    result = _build(artifacts, chunk_types=[], embed_query=embedding)
    assert result["traversal"] is None
    assert calls == [[artifacts[1]["embedding"]["query_prefix"] + "synthetic"]]


@pytest.mark.parametrize("mismatch", ["scenario_id", "ground_truth_hash"])
def test_no_hits_still_run_mapper_and_reject_graph_corpus_mismatches(artifacts, monkeypatch, mismatch) -> None:
    graph = artifacts[2]
    if mismatch == "scenario_id":
        graph["scenario_id"] = graph["source_ground_truth"]["scenario_id"] = "synthetic-other-scenario"
    else:
        graph["source_ground_truth"]["sha256"] = "0" * 64
    before = deepcopy(artifacts)
    mapper_inputs = []

    def mapping(*args, **kwargs):
        mapper_inputs.append(args)
        return map_hybrid_hits_to_graph_seeds(*args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("Traversal must not run after a no-hit mapping failure")

    monkeypatch.setattr(orchestrator, "map_hybrid_hits_to_graph_seeds", mapping)
    monkeypatch.setattr(orchestrator, "traverse_knowledge_graph", forbidden)
    with pytest.raises(GraphRAGOrchestrationError, match="^Graph seed mapping failed:"):
        _build(artifacts, chunk_types=[])
    assert len(mapper_inputs) == 1
    assert mapper_inputs[0][1]["hits"] == []
    assert artifacts == before


def test_hits_without_seeds_skip_traversal_explicitly(artifacts, monkeypatch) -> None:
    retrieval, mapping, _ = _component_results(artifacts)
    assert retrieval["hits"]
    mapping["seed_node_ids"] = []
    mapping["metadata"]["seed_node_count"] = 0
    before = deepcopy((retrieval, mapping))

    def forbidden(*args, **kwargs):
        pytest.fail("Traversal must not be called when the mapper supplies no seeds")

    monkeypatch.setattr(orchestrator, "retrieve_hybrid", lambda *args, **kwargs: retrieval)
    monkeypatch.setattr(orchestrator, "map_hybrid_hits_to_graph_seeds", lambda *args, **kwargs: mapping)
    monkeypatch.setattr(orchestrator, "traverse_knowledge_graph", forbidden)
    result = _build(artifacts)
    assert result["retrieval"] == retrieval
    assert result["seed_mapping"] == mapping
    assert result["traversal"] is None
    assert SKIP_WARNING in result["warnings"]
    assert result["metadata"] == {
        "retrieval_hit_count": len(retrieval["hits"]),
        "mapped_hit_count": len(mapping["hit_mappings"]), "seed_node_count": 0,
        "traversal_performed": False, "traversed_node_count": 0,
        "traversed_edge_count": 0, "traversed_path_count": 0,
    }
    assert (retrieval, mapping) == before


def test_context_adds_no_answers_verdicts_or_claims_and_accepts_confirmed_in_query(artifacts) -> None:
    query = "synthetic confirmed?"
    result = _build(artifacts, query=query)
    assert result["query"]["text"] == query
    forbidden_fields = {"answer", "answers", "confidence", "question", "questions",
                        "question_text", "expected_answer", "expected_answers", "verdict"}
    for item in _walk(result):
        if isinstance(item, dict):
            assert forbidden_fields.isdisjoint(item)
            if "status" in item:
                assert item["status"] != "confirmed"
    assert result["seed_mapping"]["query"]["text"] == query
    assert "confirmed" in result["query"]["normalized_terms"]


def test_embedding_is_injected_once_with_prefix_and_query_unicode_preserved(artifacts) -> None:
    calls = []
    query = "  synthetic hoạt động?  "

    def embedding(texts):
        calls.append(deepcopy(texts))
        return _embed(texts)

    result = _build(artifacts, query=query, embed_query=embedding)
    assert calls == [[artifacts[1]["embedding"]["query_prefix"] + query]]
    assert result["query"]["text"] == result["retrieval"]["query"]["text"] == query
    assert json.loads(_serialize(result)) == result


@pytest.mark.parametrize("empty", [False, True])
def test_input_artifacts_and_fixture_bytes_are_not_mutated(artifacts, empty) -> None:
    snapshot = deepcopy(artifacts)
    before = {path: sha256(path.read_bytes()).hexdigest() for path in (CORPUS_PATH, INDEX_PATH, GRAPH_PATH)}
    _build(artifacts, chunk_types=[] if empty else None)
    assert artifacts == snapshot
    assert before == {path: sha256(path.read_bytes()).hexdigest() for path in before}


def test_output_is_detached_from_inputs_components_and_other_output_envelopes(artifacts, monkeypatch) -> None:
    components = _component_results(artifacts)
    before = deepcopy(components)
    _patch_components(monkeypatch, components)
    first = _build(artifacts)
    second = _build(artifacts)
    assert components == before
    for key, original in zip(("retrieval", "seed_mapping", "traversal"), components, strict=True):
        _assert_detached(first[key], original)
    _assert_detached(first["query"], components[0]["query"])
    _assert_detached(first["source_ground_truth"], artifacts[0]["source_ground_truth"])
    assert _containers(first).isdisjoint(_containers(artifacts))
    assert _containers(first).isdisjoint(_containers(second))
    assert _containers(first["query"]).isdisjoint(_containers(first["retrieval"]["query"]))
    assert _containers(first["retrieval"]).isdisjoint(_containers(first["seed_mapping"]))
    assert _containers(first["seed_mapping"]).isdisjoint(_containers(first["traversal"]))
    first["retrieval"]["hits"][0]["chunk"]["source"]["json_pointer"] = "/changed"
    first["seed_mapping"]["hit_mappings"][0]["source"]["json_pointer"] = "/also_changed"
    first["traversal"]["nodes"][0]["attributes"]["synthetic_output_change"] = True
    first["metadata"]["retrieval_hit_count"] = -1
    assert components == before
    assert second == _build(artifacts)


@pytest.mark.parametrize("options", [{}, {"chunk_types": []},
    {"chunk_types": ["scenario_summary"], "top_k": 1},
    {"chunk_types": ["relationship"], "top_k": 1}, {"allowed_edge_types": []}])
def test_repeated_runs_are_byte_identical(artifacts, options) -> None:
    first = _build(artifacts, **options)
    second = _build(artifacts, **options)
    assert first == second
    assert _serialize(first) == _serialize(second)


def test_global_warnings_are_sorted_deduplicated_without_changing_stage_warnings(artifacts, monkeypatch) -> None:
    retrieval, mapping, traversal = _component_results(artifacts)
    retrieval["warnings"] = ["z warning", "shared warning", "shared warning"]
    mapping["warnings"] = ["shared warning", "a warning"]
    traversal["warnings"] = ["b warning", "shared warning"]
    components = (retrieval, mapping, traversal)
    before = deepcopy(components)
    _patch_components(monkeypatch, components)
    result = _build(artifacts)
    assert result["warnings"] == ["a warning", "b warning", "shared warning", "z warning"]
    assert components == before
    assert result["retrieval"]["warnings"] == retrieval["warnings"]
    assert result["seed_mapping"]["warnings"] == mapping["warnings"]
    assert result["traversal"]["warnings"] == traversal["warnings"]


@pytest.mark.parametrize("mismatch,prefix", [
    ("corpus_id", "Hybrid retrieval failed"),
    ("index_hash", "Hybrid retrieval failed"),
    ("index_corpus_id", "Hybrid retrieval failed"),
    ("index_content_hash", "Hybrid retrieval failed"),
    ("graph_scenario_id", "Graph seed mapping failed"),
    ("graph_ground_truth_hash", "Graph seed mapping failed"),
    ("graph_scenario_source", "Graph seed mapping failed"),
])
def test_artifact_mismatches_fail_closed_at_the_responsible_stage(artifacts, mismatch, prefix) -> None:
    corpus, index, graph, _ = artifacts
    if mismatch == "corpus_id":
        corpus["corpus_id"] = "synthetic-other-corpus"
    elif mismatch == "index_hash":
        index["corpus_provenance"]["sha256"] = "0" * 64
    elif mismatch == "index_corpus_id":
        index["corpus_provenance"]["corpus_id"] = "synthetic-other-corpus"
    elif mismatch == "index_content_hash":
        index["records"][0]["content_sha256"] = "0" * 64
    elif mismatch == "graph_scenario_id":
        graph["scenario_id"] = graph["source_ground_truth"]["scenario_id"] = "synthetic-other-scenario"
    elif mismatch == "graph_ground_truth_hash":
        graph["source_ground_truth"]["sha256"] = "0" * 64
    else:
        scenario = next(node for node in graph["nodes"] if node["node_type"] == "scenario")
        scenario["source"]["object_id"] = corpus["scenario_id"]
    snapshot = deepcopy(artifacts)
    options = {"chunk_types": ["scenario_summary"], "top_k": 1} if mismatch == "graph_scenario_source" else {}
    with pytest.raises(GraphRAGOrchestrationError, match=f"^{prefix}") as error:
        _build(artifacts, **options)
    assert error.value.__cause__ is not None
    assert artifacts == snapshot


STAGES = [
    ("retrieve_hybrid", "Hybrid retrieval failed"),
    ("map_hybrid_hits_to_graph_seeds", "Graph seed mapping failed"),
    ("traverse_knowledge_graph", "Graph traversal failed"),
    ("_validate_context", "GraphRAG output validation failed"),
]


@pytest.mark.parametrize("malformed,exception_type", [
    ("mapping_missing_seeds", KeyError),
    ("mapping_not_object", TypeError),
    ("retrieval_missing_hits", KeyError),
])
def test_malformed_component_gate_is_wrapped_as_mapping_stage(artifacts, monkeypatch, malformed, exception_type) -> None:
    retrieval, mapping, _ = _component_results(artifacts)
    if malformed == "mapping_missing_seeds":
        del mapping["seed_node_ids"]
    elif malformed == "mapping_not_object":
        mapping = None
    else:
        del retrieval["hits"]

    def forbidden(*args, **kwargs):
        pytest.fail("Traversal must not run after a malformed component gate")

    monkeypatch.setattr(orchestrator, "retrieve_hybrid", lambda *args, **kwargs: retrieval)
    monkeypatch.setattr(orchestrator, "map_hybrid_hits_to_graph_seeds", lambda *args, **kwargs: mapping)
    monkeypatch.setattr(orchestrator, "traverse_knowledge_graph", forbidden)
    with pytest.raises(GraphRAGOrchestrationError, match="^Graph seed mapping failed:") as error:
        _build(artifacts)
    assert isinstance(error.value.__cause__, exception_type)


@pytest.mark.parametrize("stage,prefix", STAGES)
@pytest.mark.parametrize("exception_type", [RuntimeError, ValueError, TypeError])
def test_component_exceptions_are_wrapped_with_stage_and_original_cause(artifacts, monkeypatch, stage, prefix, exception_type) -> None:
    failure = exception_type("synthetic component failure")

    def reject(*args, **kwargs):
        raise failure

    monkeypatch.setattr(orchestrator, stage, reject)
    with pytest.raises(GraphRAGOrchestrationError, match=f"^{prefix}:") as error:
        _build(artifacts)
    assert error.value.__cause__ is failure
    assert "synthetic component failure" in str(error.value)


@pytest.mark.parametrize("stage,prefix", STAGES)
@pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit])
def test_baseexceptions_are_never_caught(artifacts, monkeypatch, stage, prefix, exception_type) -> None:
    failure = exception_type("synthetic cancellation")

    def reject(*args, **kwargs):
        raise failure

    monkeypatch.setattr(orchestrator, stage, reject)
    with pytest.raises(exception_type) as error:
        _build(artifacts)
    assert error.value is failure


@pytest.mark.parametrize("corruption", [
    "schema", "identity", "query", "count", "bool_count", "traversal_flag",
    "nan", "infinity", "tuple", "non_string_key", "invalid_unicode",
])
def test_final_output_validation_fails_closed_for_envelope_or_json_corruption(artifacts, monkeypatch, corruption) -> None:
    validate = orchestrator._validate_context

    def corrupt(context, corpus, graph):
        if corruption == "schema":
            context["schema_version"] = "synthetic-invalid/v1"
        elif corruption == "identity":
            context["scenario_id"] = "synthetic-other-scenario"
        elif corruption == "query":
            context["query"]["text"] = "synthetic changed query"
        elif corruption == "count":
            context["metadata"]["mapped_hit_count"] += 1
        elif corruption == "bool_count":
            context["metadata"]["seed_node_count"] = True
        elif corruption == "traversal_flag":
            context["metadata"]["traversal_performed"] = False
        elif corruption in {"nan", "infinity"}:
            context["retrieval"]["hits"][0]["score"] = float("nan" if corruption == "nan" else "inf")
        elif corruption == "tuple":
            context["retrieval"]["warnings"] = tuple(context["retrieval"]["warnings"])
        elif corruption == "non_string_key":
            context["retrieval"]["metadata"][1] = "synthetic invalid key"
        else:
            context["retrieval"]["warnings"].append("\ud800")
        return validate(context, corpus, graph)

    monkeypatch.setattr(orchestrator, "_validate_context", corrupt)
    with pytest.raises(GraphRAGOrchestrationError, match="^GraphRAG output validation failed:"):
        _build(artifacts)


def test_expected_fixture_matches_real_api_exactly(artifacts) -> None:
    expected = _json(EXPECTED_PATH)
    result = _build(artifacts)
    assert result == expected
    assert _serialize(result) == EXPECTED_PATH.read_bytes()
    assert json.loads(EXPECTED_PATH.read_bytes()) == expected


def test_orchestration_needs_no_files_network_model_or_cli(artifacts, monkeypatch) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("In-memory orchestration attempted filesystem or network access")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    result = _build(artifacts)
    assert result["metadata"]["traversal_performed"] is True


def test_implementation_is_generic_and_only_orchestrates_existing_components() -> None:
    source = IMPLEMENTATION_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
    assert not any(name and any(part in name for part in (
        "sentence_transformers", "embedding_backend", "requests", "subprocess", "scripts",
    )) for name in imports)
    calls = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert {"retrieve_hybrid", "map_hybrid_hits_to_graph_seeds", "traverse_knowledge_graph"}.issubset(calls)
    assert not calls.intersection({"retrieve_lexical", "retrieve_vector", "embed_query",
        "build_vector_index", "traverse", "uuid4", "open"})
    for forbidden in ("mshta", "powershell", "t1218.005", "outputs/", "jsonl:line:"):
        assert forbidden not in source.casefold()
    corpus, _, graph, _ = _load_artifacts()
    for identifier in [corpus["corpus_id"], graph["graph_id"], corpus["scenario_id"],
                       *[chunk["chunk_id"] for chunk in corpus["chunks"]],
                       *[node["node_id"] for node in graph["nodes"]]]:
        assert identifier not in source
