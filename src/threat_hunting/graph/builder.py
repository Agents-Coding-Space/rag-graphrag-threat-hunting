"""Pure, deterministic mapping of Ground Truth objects to a Knowledge Graph.

Source IDs define identity; original collection positions define provenance.
Only explicit relationships, exact entity references, and declared support links
become edges. File access and serialization belong to the caller.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
import copy
import hashlib
import json
import os
from typing import Any, cast

from ..ground_truth.schema import (
    SCENARIO_GROUND_TRUTH_SCHEMA_VERSION,
    validate_ground_truth_document,
)
from .schema import (
    KNOWLEDGE_GRAPH_SCHEMA_VERSION,
    SHA256_PATTERN,
    validate_knowledge_graph,
)


MAPPING_VERSION = "ground-truth-to-knowledge-graph/v1"
_NODE_COLLECTIONS = (
    ("entity", "entities", "entity_id", "name", "evidence_ids"),
    ("fact", "facts", "fact_id", "predicate", "evidence_ids"),
    ("evidence", "evidence", "evidence_id", "summary", None),
    ("sigma_finding", "sigma_findings", "finding_id", "rule_title", "evidence_ids"),
    (
        "mitre_assessment", "mitre_assessments", "assessment_id", None,
        "supporting_evidence_ids",
    ),
)
_DIMENSIONS = {
    "scenario": ("provenance",),
    "entity": ("entity", "provenance"),
    "evidence": ("evidence", "provenance"),
    "sigma_finding": ("sigma_rule", "evidence", "provenance"),
    "mitre_assessment": ("mitre_technique", "evidence", "provenance"),
    "relationship": ("relationship", "evidence", "provenance"),
    "limitation": ("provenance",),
}
_ATTRIBUTE_ID_LISTS = (
    "observation_match_ids", "behavior_match_ids", "supporting_sigma_rule_ids",
)


class KnowledgeGraphBuildError(ValueError):
    """Raised when a graph cannot be built without losing source integrity."""


def _ground_truth_path(value: object) -> str:
    try:
        text = os.fspath(value)
    except (TypeError, ValueError) as exc:
        raise KnowledgeGraphBuildError(
            "ground_truth_path must be a non-empty string or a text path"
        ) from exc
    if not isinstance(text, str) or not text.strip() or "\x00" in text:
        raise KnowledgeGraphBuildError(
            "ground_truth_path must be non-empty text without NUL characters"
        )
    try:
        text.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise KnowledgeGraphBuildError("ground_truth_path must be valid UTF-8 text") from exc
    return text


def _ground_truth_digest(value: object) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise KnowledgeGraphBuildError(
            "ground_truth_sha256 must contain exactly 64 hexadecimal characters"
        )
    return value


def _deterministic_id(prefix: str, identity: Mapping[str, Any]) -> str:
    payload = {"mapping_version": MAPPING_VERSION, **identity}
    encoded = json.dumps(
        payload, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}--{hashlib.sha256(encoded).hexdigest()}"


def _source(object_type: str, object_id: str | None, pointer: str) -> dict[str, Any]:
    return {
        "object_type": object_type,
        "object_id": object_id,
        "json_pointer": pointer,
    }


def _source_identity(source: Mapping[str, Any]) -> dict[str, str]:
    identity = {"object_type": source["object_type"]}
    if source["object_id"] is None:
        identity["json_pointer"] = source["json_pointer"]
    else:
        identity["object_id"] = source["object_id"]
    return identity


def _references(item: Mapping[str, Any]) -> list[dict[str, str]]:
    pairs = {
        (reference["source_file"], reference["raw_record_ref"])
        for reference in item.get("source_references", [])
    }
    return [
        {"source_file": source_file, "raw_record_ref": raw_record_ref}
        for source_file, raw_record_ref in sorted(pairs)
    ]


def _attributes(
    item: Mapping[str, Any], id_field: str, evidence_field: str | None,
) -> dict[str, Any]:
    excluded = {id_field, "status", "source_references", evidence_field}
    attributes = {
        field: copy.deepcopy(value)
        for field, value in item.items()
        if field not in excluded
    }
    for field in _ATTRIBUTE_ID_LISTS:
        if field in attributes:
            attributes[field] = sorted(set(attributes[field]))
    return attributes


class _GraphBuilder:
    """Keep source-object registries separate from generated graph identities."""

    def __init__(self, ground_truth: Mapping[str, Any]) -> None:
        self.ground_truth = ground_truth
        self.scenario_id = ground_truth["scenario"]["scenario_id"]
        self.dimensions = set(ground_truth["queryable_dimensions"])
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.object_nodes: dict[str, dict[str, dict[str, Any]]] = {}
        self.source_keys: set[tuple[str, str | None, str | None]] = set()

    def _register_source(self, source: Mapping[str, Any]) -> None:
        key = (
            source["object_type"], source["object_id"],
            source["json_pointer"] if source["object_id"] is None else None,
        )
        if key in self.source_keys:
            raise KnowledgeGraphBuildError(
                f"Duplicate source object ID at {source['json_pointer']}: "
                f"{source['object_type']} {source['object_id']!r}"
            )
        self.source_keys.add(key)

    def _dimensions(
        self, object_type: str, item: Mapping[str, Any] | None = None,
    ) -> list[str]:
        if object_type == "fact":
            candidates = ("fact", "evidence", "provenance", item["predicate"])
        else:
            candidates = _DIMENSIONS[object_type]
        return sorted(self.dimensions.intersection(candidates))

    def _add_node(
        self, *, source: Mapping[str, Any], label: str, status: str,
        attributes: Mapping[str, Any], evidence_ids: Sequence[str],
        references: Sequence[Mapping[str, str]], dimensions: Sequence[str],
    ) -> dict[str, Any]:
        self._register_source(source)
        node_id = _deterministic_id("graph-node", {
            "scenario_id": self.scenario_id, **_source_identity(source),
        })
        if node_id in self.nodes:
            raise KnowledgeGraphBuildError(f"Deterministic node ID collision: {node_id!r}")
        node = {
            "node_id": node_id,
            "node_type": source["object_type"],
            "label": label,
            "status": status,
            "source": copy.deepcopy(dict(source)),
            "attributes": copy.deepcopy(dict(attributes)),
            "evidence_ids": sorted(set(evidence_ids)),
            "source_references": copy.deepcopy(list(references)),
            "dimensions": sorted(set(dimensions)),
        }
        self.nodes[node_id] = node
        if source["object_id"] is not None:
            self.object_nodes.setdefault(source["object_type"], {})[source["object_id"]] = node
        return node

    def _object_node(self, object_type: str, object_id: str, context: str) -> dict[str, Any]:
        node = self.object_nodes.get(object_type, {}).get(object_id)
        if node is None:
            raise KnowledgeGraphBuildError(
                f"{context} references unknown {object_type} ID {object_id!r}"
            )
        return node

    def _supporters(self, evidence_ids: Sequence[str], context: str) -> list[str]:
        return sorted({
            self._object_node("evidence", evidence_id, context)["node_id"]
            for evidence_id in evidence_ids
        })

    def _add_edge(
        self, *, mapping_kind: str, edge_type: str, source_node_id: str,
        target_node_id: str, source: Mapping[str, Any], status: str,
        evidence_ids: Sequence[str], references: Sequence[Mapping[str, str]],
        attributes: Mapping[str, Any], dimensions: Sequence[str],
        supporting_node_ids: Sequence[str],
    ) -> None:
        edge_id = _deterministic_id("graph-edge", {
            "scenario_id": self.scenario_id,
            "mapping_kind": mapping_kind,
            "edge_type": edge_type,
            "source_node_id": source_node_id,
            "target_node_id": target_node_id,
            "source_object": _source_identity(source),
        })
        edge = {
            "edge_id": edge_id,
            "edge_type": edge_type,
            "source_node_id": source_node_id,
            "target_node_id": target_node_id,
            "directed": True,
            "status": status,
            "source": copy.deepcopy(dict(source)),
            "supporting_node_ids": sorted(set(supporting_node_ids)),
            "evidence_ids": sorted(set(evidence_ids)),
            "source_references": copy.deepcopy(list(references)),
            "attributes": copy.deepcopy(dict(attributes)),
            "dimensions": sorted(set(dimensions)),
        }
        existing = self.edges.get(edge_id)
        if existing is not None and existing != edge:
            raise KnowledgeGraphBuildError(
                f"Deterministic edge ID collision with different content: {edge_id!r}"
            )
        self.edges[edge_id] = edge

    def create_nodes(self) -> None:
        scenario = self.ground_truth["scenario"]
        self._add_node(
            source=_source("scenario", None, "/scenario"),
            label=scenario["scenario_name"], status="reviewable",
            attributes={
                key: copy.deepcopy(value)
                for key, value in scenario.items()
                if key not in {"scenario_id", "scenario_name"}
            },
            evidence_ids=[], references=[], dimensions=self._dimensions("scenario"),
        )
        for object_type, collection, id_field, label_field, evidence_field in _NODE_COLLECTIONS:
            for index, item in enumerate(self.ground_truth[collection]):
                object_id = item[id_field]
                label = (
                    f"{item['external_id']} - {item['name']}"
                    if object_type == "mitre_assessment" else item[label_field]
                )
                evidence_ids = (
                    [object_id] if object_type == "evidence" else item[evidence_field]
                )
                self._add_node(
                    source=_source(object_type, object_id, f"/{collection}/{index}"),
                    label=label, status=item["status"],
                    attributes=_attributes(item, id_field, evidence_field),
                    evidence_ids=evidence_ids, references=_references(item),
                    dimensions=self._dimensions(object_type, item),
                )
        for index, limitation in enumerate(self.ground_truth["summary"]["limitations"]):
            self._add_node(
                source=_source("limitation", None, f"/summary/limitations/{index}"),
                label=limitation, status="reviewable", attributes={},
                evidence_ids=[], references=[], dimensions=self._dimensions("limitation"),
            )

    def relationship_edges(self) -> None:
        for index, item in enumerate(self.ground_truth["relationships"]):
            pointer = f"/relationships/{index}"
            source = _source("relationship", item["relationship_id"], pointer)
            self._register_source(source)
            self._add_edge(
                mapping_kind="relationship", edge_type=item["relationship_type"],
                source_node_id=self._object_node(
                    "entity", item["source_entity_id"], pointer,
                )["node_id"],
                target_node_id=self._object_node(
                    "entity", item["target_entity_id"], pointer,
                )["node_id"],
                source=source, status=item["status"], evidence_ids=item["evidence_ids"],
                references=_references(item), attributes=item["attributes"],
                dimensions=self._dimensions("relationship"),
                supporting_node_ids=self._supporters(item["evidence_ids"], pointer),
            )

    def fact_edges(self) -> None:
        entities = self.object_nodes.get("entity", {})
        for index, item in enumerate(self.ground_truth["facts"]):
            pointer = f"/facts/{index}"
            fact_node = self._object_node("fact", item["fact_id"], pointer)
            for field, edge_type in (("subject", "fact_subject"), ("object", "fact_object")):
                term = item[field]
                if not isinstance(term, str) or term not in entities:
                    continue
                entity_node = self._object_node("entity", term, f"{pointer}/{field}")
                source_node, target_node = (
                    (entity_node, fact_node) if field == "subject" else (fact_node, entity_node)
                )
                self._add_edge(
                    mapping_kind="fact_connection", edge_type=edge_type,
                    source_node_id=source_node["node_id"], target_node_id=target_node["node_id"],
                    source=_source("fact", item["fact_id"], f"{pointer}/{field}"),
                    status=item["status"], evidence_ids=item["evidence_ids"],
                    references=_references(item), attributes=item["attributes"],
                    dimensions=self._dimensions("fact", item),
                    supporting_node_ids=self._supporters(item["evidence_ids"], pointer),
                )

    def evidence_support_edges(self) -> None:
        for object_type, collection, id_field, _, evidence_field in _NODE_COLLECTIONS:
            if evidence_field is None:
                continue
            for index, item in enumerate(self.ground_truth[collection]):
                pointer = f"/{collection}/{index}"
                target = self._object_node(object_type, item[id_field], pointer)
                for evidence_id in sorted(set(item[evidence_field])):
                    source_node = self._object_node("evidence", evidence_id, pointer)
                    first_index = item[evidence_field].index(evidence_id)
                    self._add_edge(
                        mapping_kind="evidence_support", edge_type="supports",
                        source_node_id=source_node["node_id"], target_node_id=target["node_id"],
                        source=_source(
                            object_type, item[id_field], f"{pointer}/{evidence_field}/{first_index}",
                        ),
                        status=item["status"], evidence_ids=[evidence_id],
                        references=_references(item), attributes={},
                        dimensions=self._dimensions(object_type, item), supporting_node_ids=[],
                    )

    def sigma_assessment_edges(self) -> None:
        findings_by_rule: dict[str, list[str]] = {}
        for item in self.ground_truth["sigma_findings"]:
            node = self._object_node("sigma_finding", item["finding_id"], "sigma_findings")
            findings_by_rule.setdefault(item["rule_id"], []).append(node["node_id"])
        for index, item in enumerate(self.ground_truth["mitre_assessments"]):
            pointer = f"/mitre_assessments/{index}"
            target = self._object_node("mitre_assessment", item["assessment_id"], pointer)
            rule_ids = item["supporting_sigma_rule_ids"]
            for rule_id in sorted(set(rule_ids)):
                if rule_id not in findings_by_rule:
                    raise KnowledgeGraphBuildError(
                        f"{pointer} references unknown Sigma rule ID {rule_id!r}"
                    )
                first_index = rule_ids.index(rule_id)
                for finding_node_id in sorted(findings_by_rule[rule_id]):
                    self._add_edge(
                        mapping_kind="sigma_assessment", edge_type="supports_assessment",
                        source_node_id=finding_node_id, target_node_id=target["node_id"],
                        source=_source(
                            "mitre_assessment", item["assessment_id"],
                            f"{pointer}/supporting_sigma_rule_ids/{first_index}",
                        ),
                        status=item["status"], evidence_ids=item["supporting_evidence_ids"],
                        references=_references(item), attributes={},
                        dimensions=self._dimensions("mitre_assessment"),
                        supporting_node_ids=self._supporters(item["supporting_evidence_ids"], pointer),
                    )


def _build_knowledge_graph(
    ground_truth: object, *, ground_truth_path: object, ground_truth_sha256: object,
) -> dict[str, Any]:
    try:
        validate_ground_truth_document(ground_truth)
    except Exception as exc:
        raise KnowledgeGraphBuildError(f"Invalid Ground Truth document: {exc}") from exc
    path = _ground_truth_path(ground_truth_path)
    digest = _ground_truth_digest(ground_truth_sha256)
    root = cast(Mapping[str, Any], ground_truth)
    builder = _GraphBuilder(root)
    builder.create_nodes()
    builder.relationship_edges()
    builder.fact_edges()
    builder.evidence_support_edges()
    builder.sigma_assessment_edges()
    nodes = [builder.nodes[node_id] for node_id in sorted(builder.nodes)]
    edges = [builder.edges[edge_id] for edge_id in sorted(builder.edges)]
    node_counts = Counter(node["node_type"] for node in nodes)
    edge_counts = Counter(edge["edge_type"] for edge in edges)
    output = {
        "schema_version": KNOWLEDGE_GRAPH_SCHEMA_VERSION,
        "graph_id": _deterministic_id("knowledge-graph", {
            "schema_version": KNOWLEDGE_GRAPH_SCHEMA_VERSION,
            "scenario_id": builder.scenario_id,
            "ground_truth_sha256": digest,
        }),
        "scenario_id": builder.scenario_id,
        "source_ground_truth": {
            "path": path,
            "schema_version": SCENARIO_GROUND_TRUTH_SCHEMA_VERSION,
            "sha256": digest,
            "scenario_id": builder.scenario_id,
        },
        "nodes": nodes,
        "edges": edges,
        "queryable_dimensions": sorted(builder.dimensions),
        "review": {"status": "pending_human_review", "reviewer": None, "reviewed_at": None},
        "warnings": sorted(copy.deepcopy(root["warnings"])),
        "metadata": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_type_counts": dict(sorted(node_counts.items())),
            "edge_type_counts": dict(sorted(edge_counts.items())),
            "mapping_version": MAPPING_VERSION,
        },
    }
    try:
        validate_knowledge_graph(output)
    except Exception as exc:
        raise KnowledgeGraphBuildError(f"Built Knowledge Graph failed validation: {exc}") from exc
    return output


def build_knowledge_graph(
    ground_truth: object, *, ground_truth_path: object, ground_truth_sha256: object,
) -> dict[str, Any]:
    """Map validated Ground Truth to a graph without file access or inference.

    Provenance path and SHA-256 are caller supplied. IDs use canonical UTF-8 JSON
    with a fixed mapping version. Fact connections require an exact string match
    to an existing entity ID; other fact terms remain unchanged in node attributes.
    All source statuses are preserved, with aggregate nodes remaining reviewable.
    """
    try:
        return _build_knowledge_graph(
            ground_truth, ground_truth_path=ground_truth_path,
            ground_truth_sha256=ground_truth_sha256,
        )
    except KnowledgeGraphBuildError:
        raise
    except Exception as exc:
        raise KnowledgeGraphBuildError(f"Knowledge Graph build failed: {exc}") from exc


__all__ = ("KnowledgeGraphBuildError", "build_knowledge_graph")
