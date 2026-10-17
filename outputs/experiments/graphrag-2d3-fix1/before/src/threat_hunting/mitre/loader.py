"""Fail-closed loader for pinned Enterprise ATT&CK STIX 2.1 bundles."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping


ATTACK_EXTERNAL_ID_PATTERN = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
STIX_ID_PATTERN = re.compile(
    r"^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
SOURCE_MANIFEST_SCHEMA = "mitre-source-manifest/v1"


class MitreLoadError(ValueError):
    """Raised when ATT&CK input cannot be accepted without guessing."""


@dataclass(frozen=True, slots=True)
class ExternalReference:
    source_name: str
    external_id: str | None
    url: str | None
    description: str | None


@dataclass(frozen=True, slots=True)
class KillChainPhase:
    kill_chain_name: str
    phase_name: str


@dataclass(frozen=True, slots=True)
class AttackPattern:
    stix_id: str
    external_id: str
    name: str
    description: str | None
    created: str
    modified: str
    version: str | None
    domains: tuple[str, ...]
    is_subtechnique: bool
    kill_chain_phases: tuple[KillChainPhase, ...]
    external_references: tuple[ExternalReference, ...]
    attack_external_reference: ExternalReference
    revoked: bool
    deprecated: bool

    @property
    def is_active(self) -> bool:
        return not self.revoked and not self.deprecated


@dataclass(frozen=True, slots=True)
class SubtechniqueRelationship:
    stix_id: str
    source_ref: str
    target_ref: str


@dataclass(frozen=True, slots=True)
class MitreCollection:
    stix_id: str
    name: str
    version: str
    created: str
    modified: str


@dataclass(frozen=True, slots=True)
class MitreAttackIndex:
    bundle_id: str | None
    source_path: Path
    source_sha256: str
    object_count: int
    objects_by_id: Mapping[str, str]
    attack_patterns_by_stix_id: Mapping[str, AttackPattern]
    active_patterns_by_external_id: Mapping[str, AttackPattern]
    inactive_patterns_by_external_id: Mapping[str, tuple[AttackPattern, ...]]
    subtechnique_relationships: tuple[SubtechniqueRelationship, ...]
    parent_by_subtechnique_id: Mapping[str, SubtechniqueRelationship]
    collection: MitreCollection | None

    @property
    def active_attack_pattern_count(self) -> int:
        return len(self.active_patterns_by_external_id)


@dataclass(frozen=True, slots=True)
class MitreSourceManifest:
    source_path: Path
    source_name: str
    repository: str
    tag: str
    commit: str
    url: str
    bundle_path: str
    bundle_sha256: str
    data_type: str
    stix_version: str
    object_count: int
    active_attack_pattern_count: int
    subtechnique_of_relationship_count: int
    collection: MitreCollection


def file_sha256(path: Path) -> str:
    """Return the SHA-256 of *path* without changing it."""

    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MitreLoadError(f"Cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MitreLoadError(f"{label} {path} must contain a JSON object")
    return value


def _nonempty_string(value: object, *, field: str, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise MitreLoadError(f"{context} field {field!r} must be a non-empty string")
    return value


def _optional_string(value: object, *, field: str, context: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise MitreLoadError(f"{context} field {field!r} must be a string or null")
    return value


def _boolean(value: object, *, field: str, context: str, default: bool | None = None) -> bool:
    if value is None and default is not None:
        return default
    if not isinstance(value, bool):
        raise MitreLoadError(f"{context} field {field!r} must be a boolean")
    return value


def _integer(value: object, *, field: str, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise MitreLoadError(f"{context} field {field!r} must be a non-negative integer")
    return value


def _string_list(value: object, *, field: str, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise MitreLoadError(f"{context} field {field!r} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(
            _nonempty_string(item, field=f"{field}[{index}]", context=context)
        )
    return tuple(result)


def _validate_stix_id(value: object, *, context: str) -> str:
    stix_id = _nonempty_string(value, field="id", context=context)
    if STIX_ID_PATTERN.fullmatch(stix_id) is None:
        raise MitreLoadError(f"{context} has invalid STIX ID {stix_id!r}")
    return stix_id


def _parse_external_references(
    value: object,
    *,
    context: str,
) -> tuple[tuple[ExternalReference, ...], ExternalReference]:
    if not isinstance(value, list):
        raise MitreLoadError(f"{context} field 'external_references' must be a list")
    references: list[ExternalReference] = []
    attack_references: list[ExternalReference] = []
    for index, item in enumerate(value):
        item_context = f"{context} external_references[{index}]"
        if not isinstance(item, dict):
            raise MitreLoadError(f"{item_context} must be an object")
        reference = ExternalReference(
            source_name=_nonempty_string(
                item.get("source_name"), field="source_name", context=item_context
            ),
            external_id=_optional_string(
                item.get("external_id"), field="external_id", context=item_context
            ),
            url=_optional_string(item.get("url"), field="url", context=item_context),
            description=_optional_string(
                item.get("description"), field="description", context=item_context
            ),
        )
        references.append(reference)
        if reference.source_name == "mitre-attack":
            attack_references.append(reference)

    if len(attack_references) != 1:
        raise MitreLoadError(
            f"{context} must contain exactly one 'mitre-attack' external reference"
        )
    attack_reference = attack_references[0]
    if (
        attack_reference.external_id is None
        or ATTACK_EXTERNAL_ID_PATTERN.fullmatch(attack_reference.external_id) is None
    ):
        raise MitreLoadError(
            f"{context} has invalid ATT&CK external ID "
            f"{attack_reference.external_id!r}"
        )
    return tuple(references), attack_reference


def _parse_kill_chain_phases(value: object, *, context: str) -> tuple[KillChainPhase, ...]:
    if not isinstance(value, list):
        raise MitreLoadError(f"{context} field 'kill_chain_phases' must be a list")
    phases: list[KillChainPhase] = []
    for index, item in enumerate(value):
        item_context = f"{context} kill_chain_phases[{index}]"
        if not isinstance(item, dict):
            raise MitreLoadError(f"{item_context} must be an object")
        phases.append(
            KillChainPhase(
                kill_chain_name=_nonempty_string(
                    item.get("kill_chain_name"),
                    field="kill_chain_name",
                    context=item_context,
                ),
                phase_name=_nonempty_string(
                    item.get("phase_name"), field="phase_name", context=item_context
                ),
            )
        )
    return tuple(phases)


def _parse_attack_pattern(raw: Mapping[str, Any], *, stix_id: str) -> AttackPattern:
    context = f"attack-pattern {stix_id}"
    references, attack_reference = _parse_external_references(
        raw.get("external_references"), context=context
    )
    domains_value = raw.get("x_mitre_domains", [])
    return AttackPattern(
        stix_id=stix_id,
        external_id=attack_reference.external_id or "",
        name=_nonempty_string(raw.get("name"), field="name", context=context),
        description=_optional_string(
            raw.get("description"), field="description", context=context
        ),
        created=_nonempty_string(raw.get("created"), field="created", context=context),
        modified=_nonempty_string(raw.get("modified"), field="modified", context=context),
        version=_optional_string(
            raw.get("x_mitre_version"), field="x_mitre_version", context=context
        ),
        domains=_string_list(domains_value, field="x_mitre_domains", context=context),
        is_subtechnique=_boolean(
            raw.get("x_mitre_is_subtechnique"),
            field="x_mitre_is_subtechnique",
            context=context,
        ),
        kill_chain_phases=_parse_kill_chain_phases(
            raw.get("kill_chain_phases"), context=context
        ),
        external_references=references,
        attack_external_reference=attack_reference,
        revoked=_boolean(raw.get("revoked"), field="revoked", context=context, default=False),
        deprecated=_boolean(
            raw.get("x_mitre_deprecated"),
            field="x_mitre_deprecated",
            context=context,
        ),
    )


def _parse_collection(raw: Mapping[str, Any], *, stix_id: str) -> MitreCollection:
    context = f"x-mitre-collection {stix_id}"
    return MitreCollection(
        stix_id=stix_id,
        name=_nonempty_string(raw.get("name"), field="name", context=context),
        version=_nonempty_string(
            raw.get("x_mitre_version"), field="x_mitre_version", context=context
        ),
        created=_nonempty_string(raw.get("created"), field="created", context=context),
        modified=_nonempty_string(raw.get("modified"), field="modified", context=context),
    )


def load_attack_bundle(path: Path) -> MitreAttackIndex:
    """Load and index a STIX 2.1 ATT&CK bundle, rejecting ambiguous input."""

    source_path = path.resolve()
    raw_bundle = _read_json_object(source_path, label="MITRE STIX bundle")
    if raw_bundle.get("type") != "bundle":
        raise MitreLoadError(f"MITRE STIX bundle {source_path} must have type 'bundle'")
    bundle_id_value = raw_bundle.get("id")
    bundle_id = None
    if bundle_id_value is not None:
        bundle_id = _validate_stix_id(bundle_id_value, context="STIX bundle")
        if not bundle_id.startswith("bundle--"):
            raise MitreLoadError(f"STIX bundle has invalid bundle ID {bundle_id!r}")
    raw_objects = raw_bundle.get("objects")
    if not isinstance(raw_objects, list):
        raise MitreLoadError(f"MITRE STIX bundle {source_path} field 'objects' must be a list")

    raw_by_id: dict[str, Mapping[str, Any]] = {}
    object_types: dict[str, str] = {}
    for index, raw in enumerate(raw_objects):
        context = f"objects[{index}]"
        if not isinstance(raw, dict):
            raise MitreLoadError(f"{context} must be an object")
        object_type = _nonempty_string(raw.get("type"), field="type", context=context)
        stix_id = _validate_stix_id(raw.get("id"), context=context)
        if not stix_id.startswith(f"{object_type}--"):
            raise MitreLoadError(
                f"{context} ID {stix_id!r} does not match type {object_type!r}"
            )
        if stix_id in raw_by_id:
            raise MitreLoadError(f"Duplicate STIX ID {stix_id!r}")
        spec_version = raw.get("spec_version")
        if spec_version is not None and spec_version != "2.1":
            raise MitreLoadError(
                f"STIX object {stix_id} declares unsupported spec_version {spec_version!r}"
            )
        raw_by_id[stix_id] = raw
        object_types[stix_id] = object_type

    patterns_by_id: dict[str, AttackPattern] = {}
    active_by_external_id: dict[str, AttackPattern] = {}
    inactive_lists: dict[str, list[AttackPattern]] = {}
    collections: list[MitreCollection] = []
    for stix_id, raw in raw_by_id.items():
        object_type = object_types[stix_id]
        if object_type == "attack-pattern":
            pattern = _parse_attack_pattern(raw, stix_id=stix_id)
            patterns_by_id[stix_id] = pattern
            if pattern.is_active:
                previous = active_by_external_id.get(pattern.external_id)
                if previous is not None:
                    raise MitreLoadError(
                        f"Duplicate active ATT&CK external ID {pattern.external_id!r}: "
                        f"{previous.stix_id} and {pattern.stix_id}"
                    )
                active_by_external_id[pattern.external_id] = pattern
            else:
                inactive_lists.setdefault(pattern.external_id, []).append(pattern)
        elif object_type == "x-mitre-collection":
            collections.append(_parse_collection(raw, stix_id=stix_id))

    relationships: list[SubtechniqueRelationship] = []
    relationships_by_source: dict[str, list[SubtechniqueRelationship]] = {}
    for stix_id, raw in raw_by_id.items():
        if object_types[stix_id] != "relationship":
            continue
        context = f"relationship {stix_id}"
        relationship_type = _nonempty_string(
            raw.get("relationship_type"), field="relationship_type", context=context
        )
        source_ref = _nonempty_string(
            raw.get("source_ref"), field="source_ref", context=context
        )
        target_ref = _nonempty_string(
            raw.get("target_ref"), field="target_ref", context=context
        )
        if source_ref not in raw_by_id or target_ref not in raw_by_id:
            raise MitreLoadError(
                f"{context} references an object not present in the bundle: "
                f"{source_ref!r} -> {target_ref!r}"
            )
        if relationship_type != "subtechnique-of":
            continue
        if source_ref not in patterns_by_id or target_ref not in patterns_by_id:
            raise MitreLoadError(
                f"{context} must connect two attack-pattern objects"
            )
        source_pattern = patterns_by_id[source_ref]
        target_pattern = patterns_by_id[target_ref]
        if not source_pattern.is_subtechnique or target_pattern.is_subtechnique:
            raise MitreLoadError(
                f"{context} does not connect a sub-technique to a parent technique"
            )
        relationship = SubtechniqueRelationship(
            stix_id=stix_id,
            source_ref=source_ref,
            target_ref=target_ref,
        )
        relationships.append(relationship)
        relationships_by_source.setdefault(source_ref, []).append(relationship)

    parent_by_subtechnique_id: dict[str, SubtechniqueRelationship] = {}
    for pattern in patterns_by_id.values():
        if not pattern.is_subtechnique or not pattern.is_active:
            continue
        candidates = relationships_by_source.get(pattern.stix_id, [])
        active_candidates = [
            relationship
            for relationship in candidates
            if patterns_by_id[relationship.target_ref].is_active
        ]
        target_ids = {relationship.target_ref for relationship in active_candidates}
        if len(active_candidates) != 1 or len(target_ids) != 1:
            raise MitreLoadError(
                f"Active sub-technique {pattern.external_id} ({pattern.stix_id}) must "
                "have exactly one active parent"
            )
        parent_by_subtechnique_id[pattern.stix_id] = active_candidates[0]

    collection: MitreCollection | None = None
    if len(collections) == 1:
        collection = collections[0]
    elif len(collections) > 1:
        raise MitreLoadError("MITRE STIX bundle contains multiple collection objects")

    inactive_by_external_id = {
        external_id: tuple(sorted(items, key=lambda item: item.stix_id))
        for external_id, items in inactive_lists.items()
    }
    return MitreAttackIndex(
        bundle_id=bundle_id,
        source_path=source_path,
        source_sha256=file_sha256(source_path),
        object_count=len(raw_objects),
        objects_by_id=MappingProxyType(dict(object_types)),
        attack_patterns_by_stix_id=MappingProxyType(dict(patterns_by_id)),
        active_patterns_by_external_id=MappingProxyType(dict(active_by_external_id)),
        inactive_patterns_by_external_id=MappingProxyType(inactive_by_external_id),
        subtechnique_relationships=tuple(sorted(relationships, key=lambda item: item.stix_id)),
        parent_by_subtechnique_id=MappingProxyType(dict(parent_by_subtechnique_id)),
        collection=collection,
    )


def load_source_manifest(path: Path) -> MitreSourceManifest:
    """Read the deterministic provenance manifest for a pinned ATT&CK bundle."""

    source_path = path.resolve()
    raw = _read_json_object(source_path, label="MITRE source manifest")
    context = f"MITRE source manifest {source_path}"
    schema_version = _nonempty_string(
        raw.get("schema_version"), field="schema_version", context=context
    )
    if schema_version != SOURCE_MANIFEST_SCHEMA:
        raise MitreLoadError(
            f"{context} has unsupported schema_version {schema_version!r}"
        )
    source = raw.get("source")
    file_metadata = raw.get("file")
    collection = raw.get("collection")
    if not isinstance(source, dict):
        raise MitreLoadError(f"{context} field 'source' must be an object")
    if not isinstance(file_metadata, dict):
        raise MitreLoadError(f"{context} field 'file' must be an object")
    if not isinstance(collection, dict):
        raise MitreLoadError(f"{context} field 'collection' must be an object")

    bundle_sha256 = _nonempty_string(
        file_metadata.get("sha256"), field="file.sha256", context=context
    )
    if re.fullmatch(r"[0-9a-f]{64}", bundle_sha256) is None:
        raise MitreLoadError(f"{context} field 'file.sha256' is invalid")
    commit = _nonempty_string(source.get("commit"), field="source.commit", context=context)
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise MitreLoadError(f"{context} field 'source.commit' is invalid")

    manifest_collection = MitreCollection(
        stix_id=_validate_stix_id(collection.get("id"), context="manifest collection"),
        name=_nonempty_string(collection.get("name"), field="collection.name", context=context),
        version=_nonempty_string(
            collection.get("version"), field="collection.version", context=context
        ),
        created=_nonempty_string(
            collection.get("created"), field="collection.created", context=context
        ),
        modified=_nonempty_string(
            collection.get("modified"), field="collection.modified", context=context
        ),
    )
    if not manifest_collection.stix_id.startswith("x-mitre-collection--"):
        raise MitreLoadError(f"{context} collection ID has the wrong STIX type")

    return MitreSourceManifest(
        source_path=source_path,
        source_name=_nonempty_string(source.get("name"), field="source.name", context=context),
        repository=_nonempty_string(
            source.get("repository"), field="source.repository", context=context
        ),
        tag=_nonempty_string(source.get("tag"), field="source.tag", context=context),
        commit=commit,
        url=_nonempty_string(source.get("url"), field="source.url", context=context),
        bundle_path=_nonempty_string(
            file_metadata.get("path"), field="file.path", context=context
        ),
        bundle_sha256=bundle_sha256,
        data_type=_nonempty_string(
            file_metadata.get("data_type"), field="file.data_type", context=context
        ),
        stix_version=_nonempty_string(
            file_metadata.get("stix_version"), field="file.stix_version", context=context
        ),
        object_count=_integer(
            file_metadata.get("object_count"), field="file.object_count", context=context
        ),
        active_attack_pattern_count=_integer(
            file_metadata.get("active_attack_pattern_count"),
            field="file.active_attack_pattern_count",
            context=context,
        ),
        subtechnique_of_relationship_count=_integer(
            file_metadata.get("subtechnique_of_relationship_count"),
            field="file.subtechnique_of_relationship_count",
            context=context,
        ),
        collection=manifest_collection,
    )


def validate_manifest(index: MitreAttackIndex, manifest: MitreSourceManifest) -> None:
    """Require the loaded bundle to match every pinned manifest invariant."""

    mismatches: list[str] = []
    if manifest.data_type != "enterprise-attack":
        mismatches.append(f"data_type={manifest.data_type!r}")
    if manifest.stix_version != "2.1":
        mismatches.append(f"stix_version={manifest.stix_version!r}")
    if index.source_sha256 != manifest.bundle_sha256:
        mismatches.append(
            f"sha256 expected {manifest.bundle_sha256}, got {index.source_sha256}"
        )
    if index.object_count != manifest.object_count:
        mismatches.append(
            f"object_count expected {manifest.object_count}, got {index.object_count}"
        )
    if index.active_attack_pattern_count != manifest.active_attack_pattern_count:
        mismatches.append(
            "active_attack_pattern_count expected "
            f"{manifest.active_attack_pattern_count}, got {index.active_attack_pattern_count}"
        )
    if (
        len(index.subtechnique_relationships)
        != manifest.subtechnique_of_relationship_count
    ):
        mismatches.append(
            "subtechnique_of_relationship_count expected "
            f"{manifest.subtechnique_of_relationship_count}, got "
            f"{len(index.subtechnique_relationships)}"
        )
    if index.collection != manifest.collection:
        mismatches.append("collection metadata does not match the manifest")
    if mismatches:
        raise MitreLoadError("MITRE bundle does not match source manifest: " + "; ".join(mismatches))
