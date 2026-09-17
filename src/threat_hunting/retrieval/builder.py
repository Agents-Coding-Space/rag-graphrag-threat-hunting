"""Pure in-memory Ground Truth to Retrieval Corpus transformation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import copy
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from threat_hunting.ground_truth import (
    SCENARIO_GROUND_TRUTH_SCHEMA_VERSION,
    GroundTruthValidationError,
    validate_ground_truth_document,
)

from .schema import (
    RETRIEVAL_CORPUS_SCHEMA_VERSION,
    RetrievalCorpusValidationError,
    validate_retrieval_corpus,
)


SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
CHUNK_TYPE_ORDER = (
    "scenario_summary",
    "entity",
    "fact",
    "relationship",
    "evidence",
    "sigma_finding",
    "mitre_assessment",
    "limitation",
)
CHUNK_TYPE_RANK = {
    chunk_type: index for index, chunk_type in enumerate(CHUNK_TYPE_ORDER)
}
GENERAL_QUERYABLE_DIMENSIONS = frozenset(
    {
        "scenario",
        "entity",
        "fact",
        "relationship",
        "evidence",
        "sigma_rule",
        "mitre_technique",
        "limitation",
        "provenance",
    }
)


class RetrievalCorpusBuildError(ValueError):
    """Raised when valid retrieval chunks cannot be built without guessing."""


def _deterministic_id(prefix: str, *identity: str) -> str:
    digest = sha256("\x00".join(identity).encode("utf-8")).hexdigest()
    return f"{prefix}--{digest}"


def _source_path_text(value: object) -> str:
    if isinstance(value, Path):
        text = value.as_posix()
    elif isinstance(value, str):
        text = value
    else:
        raise RetrievalCorpusBuildError(
            "source_ground_truth_path must be a non-empty string or Path"
        )
    if not text.strip():
        raise RetrievalCorpusBuildError(
            "source_ground_truth_path must be a non-empty string or Path"
        )
    return text


def _source_hash_text(value: object) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise RetrievalCorpusBuildError(
            "source_ground_truth_sha256 must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _json_text(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _fact_term_text(value: object) -> str:
    return value if isinstance(value, str) else _json_text(value)


def _reference_documents(
    references: Iterable[Mapping[str, object]],
) -> list[dict[str, str]]:
    pairs = {
        (str(reference["source_file"]), str(reference["raw_record_ref"]))
        for reference in references
    }
    return [
        {"source_file": source_file, "raw_record_ref": raw_record_ref}
        for source_file, raw_record_ref in sorted(pairs)
    ]


def _references_for_evidence_ids(
    evidence_ids: Iterable[str],
    evidence_by_id: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, str]]:
    references: list[Mapping[str, object]] = []
    for evidence_id in evidence_ids:
        evidence = evidence_by_id.get(evidence_id)
        if evidence is not None:
            references.extend(evidence["source_references"])
    return _reference_documents(references)


def _observation_descriptor(observation: Mapping[str, object]) -> str:
    provider = observation["provider"] if observation["provider"] is not None else "null"
    event_id = observation["event_id"] if observation["event_id"] is not None else "null"
    timestamp = (
        observation["timestamp"] if observation["timestamp"] is not None else "null"
    )
    return f"provider={provider}, event_id={event_id}, timestamp={timestamp}"


def _make_chunk(
    *,
    scenario_id: str,
    chunk_type: str,
    identity: str,
    title: str,
    content: str,
    status: str,
    object_type: str,
    object_id: str | None,
    json_pointer: str,
    entity_ids: Iterable[str] = (),
    fact_ids: Iterable[str] = (),
    relationship_ids: Iterable[str] = (),
    evidence_ids: Iterable[str] = (),
    sigma_rule_ids: Iterable[str] = (),
    mitre_external_ids: Iterable[str] = (),
    source_references: Iterable[Mapping[str, object]] = (),
    queryable_dimensions: Iterable[str] = (),
    metadata: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "chunk_id": _deterministic_id(
            "retrieval-chunk", scenario_id, chunk_type, identity
        ),
        "chunk_type": chunk_type,
        "scenario_id": scenario_id,
        "title": title,
        "content": content,
        "status": status,
        "source": {
            "artifact_type": "scenario_ground_truth",
            "object_type": object_type,
            "object_id": object_id,
            "json_pointer": json_pointer,
        },
        "entity_ids": sorted(set(entity_ids)),
        "fact_ids": sorted(set(fact_ids)),
        "relationship_ids": sorted(set(relationship_ids)),
        "evidence_ids": sorted(set(evidence_ids)),
        "sigma_rule_ids": sorted(set(sigma_rule_ids)),
        "mitre_external_ids": sorted(set(mitre_external_ids)),
        "source_references": _reference_documents(source_references),
        "queryable_dimensions": sorted(set(queryable_dimensions)),
        "metadata": copy.deepcopy(dict(metadata or {})),
    }


def _chunk_sort_key(chunk: Mapping[str, object]) -> tuple[int, str]:
    source = chunk["source"]
    assert isinstance(source, Mapping)
    identity = source["object_id"] or source["json_pointer"]
    return CHUNK_TYPE_RANK[str(chunk["chunk_type"])], str(identity)


def _scenario_chunk(
    ground_truth: Mapping[str, Any],
    *,
    scenario_id: str,
    relationships_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, object]:
    scenario = ground_truth["scenario"]
    summary = ground_truth["summary"]
    behaviors = sorted(set(summary["observed_behavior"]))
    behavior_text = " ".join(behaviors) if behaviors else "No observed behavior is listed."
    content = (
        f"Scenario {scenario['scenario_name']}. Description: {scenario['description']} "
        f"Analysis status: {scenario['analysis_status']}. "
        f"Observed behavior: {behavior_text}"
    )
    relationship_ids = sorted(
        relationship_id
        for relationship_id in set(summary["key_relationships"])
        if relationship_id in relationships_by_id
    )
    references: list[Mapping[str, object]] = []
    for relationship_id in relationship_ids:
        references.extend(relationships_by_id[relationship_id]["source_references"])
    known_entity_ids = {item["entity_id"] for item in ground_truth["entities"]}
    entity_ids = [
        entity_id
        for entity_id in summary["key_entities"]
        if entity_id in known_entity_ids
    ]
    dimensions = set(ground_truth["queryable_dimensions"])
    dimensions.update({"scenario", "provenance"})
    return _make_chunk(
        scenario_id=scenario_id,
        chunk_type="scenario_summary",
        identity="/scenario",
        title=str(scenario["scenario_name"]),
        content=content,
        status="reviewable",
        object_type="scenario",
        object_id=None,
        json_pointer="/scenario",
        entity_ids=entity_ids,
        relationship_ids=relationship_ids,
        source_references=references,
        queryable_dimensions=dimensions,
        metadata={
            "analysis_status": scenario["analysis_status"],
            "time_window": scenario["time_window"],
            "observed_behavior_count": len(summary["observed_behavior"]),
            "source_review_status": ground_truth["review"]["review_status"],
        },
    )


def _entity_chunks(
    ground_truth: Mapping[str, Any],
    *,
    scenario_id: str,
    entity_by_id: Mapping[str, Mapping[str, Any]],
    evidence_by_id: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, object]]:
    chunks: list[dict[str, object]] = []
    for index, entity in enumerate(ground_truth["entities"]):
        entity_id = str(entity["entity_id"])
        evidence_ids = list(entity["evidence_ids"])
        relationship_ids = [
            str(item["relationship_id"])
            for item in ground_truth["relationships"]
            if entity_id in (item["source_entity_id"], item["target_entity_id"])
        ]
        fact_ids = [
            str(item["fact_id"])
            for item in ground_truth["facts"]
            if entity_id == item["subject"] or entity_id == item["object"]
        ]
        content = (
            f"Entity {entity['name']}. Type: {entity['entity_type']}. "
            f"Status: {entity['status']}. "
            f"Attributes: {_json_text(entity['attributes'])}."
        )
        chunks.append(
            _make_chunk(
                scenario_id=scenario_id,
                chunk_type="entity",
                identity=entity_id,
                title=str(entity["name"]),
                content=content,
                status=str(entity["status"]),
                object_type="entity",
                object_id=entity_id,
                json_pointer=f"/entities/{index}",
                entity_ids=(entity_id,),
                fact_ids=fact_ids,
                relationship_ids=relationship_ids,
                evidence_ids=evidence_ids,
                source_references=_references_for_evidence_ids(
                    evidence_ids, evidence_by_id
                ),
                queryable_dimensions=(
                    "entity",
                    "evidence",
                    "fact",
                    "provenance",
                    "relationship",
                ),
                metadata={
                    "entity_type": entity["entity_type"],
                    "attributes": entity["attributes"],
                },
            )
        )
    return chunks


def _fact_chunks(
    ground_truth: Mapping[str, Any],
    *,
    scenario_id: str,
    entity_by_id: Mapping[str, Mapping[str, Any]],
    relationships_by_id: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, object]]:
    chunks: list[dict[str, object]] = []
    for index, fact in enumerate(ground_truth["facts"]):
        fact_id = str(fact["fact_id"])
        entity_ids = [
            term
            for term in (fact["subject"], fact["object"])
            if isinstance(term, str) and term in entity_by_id
        ]
        relationship_ids: list[str] = []
        relationship_id = fact["attributes"].get("relationship_id")
        if isinstance(relationship_id, str) and relationship_id in relationships_by_id:
            relationship_ids.append(relationship_id)
        content = (
            f"Fact {fact_id}. Subject: {_fact_term_text(fact['subject'])}. "
            f"Predicate: {fact['predicate']}. Object: {_fact_term_text(fact['object'])}. "
            f"Status: {fact['status']}. Attributes: {_json_text(fact['attributes'])}."
        )
        chunks.append(
            _make_chunk(
                scenario_id=scenario_id,
                chunk_type="fact",
                identity=fact_id,
                title=str(fact["predicate"]),
                content=content,
                status=str(fact["status"]),
                object_type="fact",
                object_id=fact_id,
                json_pointer=f"/facts/{index}",
                entity_ids=entity_ids,
                fact_ids=(fact_id,),
                relationship_ids=relationship_ids,
                evidence_ids=fact["evidence_ids"],
                source_references=fact["source_references"],
                queryable_dimensions=(
                    "entity",
                    "evidence",
                    "fact",
                    "provenance",
                    "relationship",
                ),
                metadata={"attributes": fact["attributes"]},
            )
        )
    return chunks


def _relationship_chunks(
    ground_truth: Mapping[str, Any],
    *,
    scenario_id: str,
    entity_by_id: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, object]]:
    chunks: list[dict[str, object]] = []
    for index, relationship in enumerate(ground_truth["relationships"]):
        relationship_id = str(relationship["relationship_id"])
        source_id = str(relationship["source_entity_id"])
        target_id = str(relationship["target_entity_id"])
        source_name = entity_by_id[source_id]["name"]
        target_name = entity_by_id[target_id]["name"]
        content = (
            f"Relationship {relationship_id}. Source: {source_name} ({source_id}). "
            f"Type: {relationship['relationship_type']}. "
            f"Target: {target_name} ({target_id}). "
            f"Status: {relationship['status']}."
        )
        chunks.append(
            _make_chunk(
                scenario_id=scenario_id,
                chunk_type="relationship",
                identity=relationship_id,
                title=str(relationship["relationship_type"]),
                content=content,
                status=str(relationship["status"]),
                object_type="relationship",
                object_id=relationship_id,
                json_pointer=f"/relationships/{index}",
                entity_ids=(source_id, target_id),
                relationship_ids=(relationship_id,),
                evidence_ids=relationship["evidence_ids"],
                source_references=relationship["source_references"],
                queryable_dimensions=(
                    "entity",
                    "evidence",
                    "provenance",
                    "relationship",
                ),
                metadata={"attributes": relationship["attributes"]},
            )
        )
    return chunks


def _evidence_chunks(
    ground_truth: Mapping[str, Any],
    *,
    scenario_id: str,
) -> list[dict[str, object]]:
    chunks: list[dict[str, object]] = []
    for index, evidence in enumerate(ground_truth["evidence"]):
        evidence_id = str(evidence["evidence_id"])
        entity_ids = [
            str(item["entity_id"])
            for item in ground_truth["entities"]
            if evidence_id in item["evidence_ids"]
        ]
        fact_ids = [
            str(item["fact_id"])
            for item in ground_truth["facts"]
            if evidence_id in item["evidence_ids"]
        ]
        relationship_ids = [
            str(item["relationship_id"])
            for item in ground_truth["relationships"]
            if evidence_id in item["evidence_ids"]
        ]
        sigma_rule_ids = [
            str(item["rule_id"])
            for item in ground_truth["sigma_findings"]
            if evidence_id in item["evidence_ids"]
        ]
        mitre_external_ids = [
            str(item["external_id"])
            for item in ground_truth["mitre_assessments"]
            if evidence_id in item["supporting_evidence_ids"]
        ]
        descriptors = sorted(
            _observation_descriptor(observation)
            for observation in evidence["observations"]
        )
        descriptor_text = "; ".join(descriptors) if descriptors else "none"
        content = (
            f"Evidence {evidence_id}. Type: {evidence['evidence_type']}. "
            f"Summary: {evidence['summary']} Status: {evidence['status']}. "
            f"Observations: {descriptor_text}."
        )
        chunks.append(
            _make_chunk(
                scenario_id=scenario_id,
                chunk_type="evidence",
                identity=evidence_id,
                title=str(evidence["summary"]),
                content=content,
                status=str(evidence["status"]),
                object_type="evidence",
                object_id=evidence_id,
                json_pointer=f"/evidence/{index}",
                entity_ids=entity_ids,
                fact_ids=fact_ids,
                relationship_ids=relationship_ids,
                evidence_ids=(evidence_id,),
                sigma_rule_ids=sigma_rule_ids,
                mitre_external_ids=mitre_external_ids,
                source_references=evidence["source_references"],
                queryable_dimensions=(
                    "entity",
                    "evidence",
                    "fact",
                    "mitre_technique",
                    "provenance",
                    "relationship",
                    "sigma_rule",
                ),
                metadata={"observation_count": len(evidence["observations"])},
            )
        )
    return chunks


def _sigma_chunks(
    ground_truth: Mapping[str, Any],
    *,
    scenario_id: str,
) -> list[dict[str, object]]:
    chunks: list[dict[str, object]] = []
    for index, finding in enumerate(ground_truth["sigma_findings"]):
        finding_id = str(finding["finding_id"])
        rule_id = str(finding["rule_id"])
        mitre_external_ids = [
            str(item["external_id"])
            for item in ground_truth["mitre_assessments"]
            if rule_id in item["supporting_sigma_rule_ids"]
        ]
        caveats = sorted(set(finding["caveats"]))
        caveat_text = "; ".join(caveats) if caveats else "none"
        evidence_text = ", ".join(sorted(set(finding["evidence_ids"]))) or "none"
        content = (
            f"Sigma finding {finding['rule_title']}. Rule ID: {rule_id}. "
            f"Status: {finding['status']}. Caveats: {caveat_text}. "
            f"Evidence IDs: {evidence_text}."
        )
        chunks.append(
            _make_chunk(
                scenario_id=scenario_id,
                chunk_type="sigma_finding",
                identity=finding_id,
                title=str(finding["rule_title"]),
                content=content,
                status=str(finding["status"]),
                object_type="sigma_finding",
                object_id=finding_id,
                json_pointer=f"/sigma_findings/{index}",
                evidence_ids=finding["evidence_ids"],
                sigma_rule_ids=(rule_id,),
                mitre_external_ids=mitre_external_ids,
                source_references=finding["source_references"],
                queryable_dimensions=(
                    "evidence",
                    "mitre_technique",
                    "provenance",
                    "sigma_rule",
                ),
                metadata={
                    "rule_sha256": finding["rule_sha256"],
                    "observation_match_ids": finding["observation_match_ids"],
                    "behavior_match_ids": finding["behavior_match_ids"],
                    "caveats": caveats,
                },
            )
        )
    return chunks


def _mitre_chunks(
    ground_truth: Mapping[str, Any],
    *,
    scenario_id: str,
    evidence_by_id: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, object]]:
    chunks: list[dict[str, object]] = []
    for index, assessment in enumerate(ground_truth["mitre_assessments"]):
        assessment_id = str(assessment["assessment_id"])
        content = (
            f"MITRE assessment {assessment['external_id']}: {assessment['name']}. "
            f"Status: {assessment['status']}. "
            f"Evidence support: {assessment['evidence_support']}. "
            f"Rationale: {assessment['rationale']} "
            f"Review status: {assessment['review_status']}."
        )
        chunks.append(
            _make_chunk(
                scenario_id=scenario_id,
                chunk_type="mitre_assessment",
                identity=assessment_id,
                title=f"{assessment['external_id']} - {assessment['name']}",
                content=content,
                status=str(assessment["status"]),
                object_type="mitre_assessment",
                object_id=assessment_id,
                json_pointer=f"/mitre_assessments/{index}",
                evidence_ids=assessment["supporting_evidence_ids"],
                sigma_rule_ids=assessment["supporting_sigma_rule_ids"],
                mitre_external_ids=(str(assessment["external_id"]),),
                source_references=_references_for_evidence_ids(
                    assessment["supporting_evidence_ids"], evidence_by_id
                ),
                queryable_dimensions=(
                    "evidence",
                    "mitre_technique",
                    "provenance",
                    "sigma_rule",
                ),
                metadata={
                    "stix_id": assessment["stix_id"],
                    "origin": assessment["origin"],
                    "evidence_support": assessment["evidence_support"],
                    "review_status": assessment["review_status"],
                },
            )
        )
    return chunks


def _limitation_chunks(
    ground_truth: Mapping[str, Any], *, scenario_id: str
) -> list[dict[str, object]]:
    return [
        _make_chunk(
            scenario_id=scenario_id,
            chunk_type="limitation",
            identity=f"/summary/limitations/{index}",
            title="Ground Truth scope limitation",
            content=str(limitation),
            status="reviewable",
            object_type="limitation",
            object_id=None,
            json_pointer=f"/summary/limitations/{index}",
            queryable_dimensions=("limitation", "provenance"),
            metadata={"source_summary_field": "limitations"},
        )
        for index, limitation in enumerate(ground_truth["summary"]["limitations"])
    ]


def build_retrieval_corpus(
    ground_truth: object,
    *,
    source_ground_truth_path: str | Path,
    source_ground_truth_sha256: str,
) -> dict[str, object]:
    """Convert one validated Ground Truth Core document into retrieval chunks."""

    try:
        validate_ground_truth_document(ground_truth)
    except GroundTruthValidationError as exc:
        raise RetrievalCorpusBuildError(
            f"Invalid Ground Truth Core input: {exc}"
        ) from exc

    source_path = _source_path_text(source_ground_truth_path)
    source_hash = _source_hash_text(source_ground_truth_sha256)
    assert isinstance(ground_truth, Mapping)
    root: Mapping[str, Any] = ground_truth
    scenario_id = str(root["scenario"]["scenario_id"])

    entity_by_id = {str(item["entity_id"]): item for item in root["entities"]}
    evidence_by_id = {
        str(item["evidence_id"]): item for item in root["evidence"]
    }
    relationships_by_id = {
        str(item["relationship_id"]): item for item in root["relationships"]
    }

    chunks = [
        _scenario_chunk(
            root,
            scenario_id=scenario_id,
            relationships_by_id=relationships_by_id,
        )
    ]
    chunks.extend(
        _entity_chunks(
            root,
            scenario_id=scenario_id,
            entity_by_id=entity_by_id,
            evidence_by_id=evidence_by_id,
        )
    )
    chunks.extend(
        _fact_chunks(
            root,
            scenario_id=scenario_id,
            entity_by_id=entity_by_id,
            relationships_by_id=relationships_by_id,
        )
    )
    chunks.extend(
        _relationship_chunks(
            root,
            scenario_id=scenario_id,
            entity_by_id=entity_by_id,
        )
    )
    chunks.extend(_evidence_chunks(root, scenario_id=scenario_id))
    chunks.extend(_sigma_chunks(root, scenario_id=scenario_id))
    chunks.extend(
        _mitre_chunks(
            root,
            scenario_id=scenario_id,
            evidence_by_id=evidence_by_id,
        )
    )
    chunks.extend(_limitation_chunks(root, scenario_id=scenario_id))
    chunks.sort(key=_chunk_sort_key)

    dimensions = sorted(
        set(root["queryable_dimensions"]) | GENERAL_QUERYABLE_DIMENSIONS
    )
    output: dict[str, object] = {
        "schema_version": RETRIEVAL_CORPUS_SCHEMA_VERSION,
        "corpus_id": _deterministic_id(
            "retrieval-corpus", scenario_id, source_hash
        ),
        "scenario_id": scenario_id,
        "source_ground_truth": {
            "path": source_path,
            "schema_version": SCENARIO_GROUND_TRUTH_SCHEMA_VERSION,
            "sha256": source_hash,
            "scenario_id": scenario_id,
        },
        "chunks": chunks,
        "queryable_dimensions": dimensions,
        "review": {
            "review_status": "pending_human_review",
            "reviewer": None,
            "reviewed_at": None,
            "notes": [
                "This corpus was generated automatically from a validated Ground Truth Core document.",
                "The generated corpus has not been reviewed by a human.",
            ],
        },
        "warnings": sorted(set(root["warnings"])),
        "metadata": {
            "builder_contract": "ground-truth-to-retrieval-corpus/v1",
            "chunk_count": len(chunks),
            "source_analysis_status": root["scenario"]["analysis_status"],
            "source_review_status": root["review"]["review_status"],
        },
    }
    try:
        validate_retrieval_corpus(output)
    except RetrievalCorpusValidationError as exc:
        raise RetrievalCorpusBuildError(
            f"Built Retrieval Corpus failed validation: {exc}"
        ) from exc
    return output


__all__ = ("RetrievalCorpusBuildError", "build_retrieval_corpus")
