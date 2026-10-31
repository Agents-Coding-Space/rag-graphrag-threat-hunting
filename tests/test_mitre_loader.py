from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from threat_hunting.mitre.loader import MitreLoadError, load_attack_bundle


FIXTURE = Path(__file__).parent / "fixtures" / "mitre" / "enterprise_attack_minimal.json"


def _bundle() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _write_bundle(tmp_path: Path, bundle: object) -> Path:
    path = tmp_path / "enterprise-attack.json"
    path.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
    return path


def _object(bundle: dict[str, object], stix_id: str) -> dict[str, object]:
    objects = bundle["objects"]
    assert isinstance(objects, list)
    return next(item for item in objects if item["id"] == stix_id)


def test_loads_valid_stix_21_bundle_and_builds_indexes() -> None:
    index = load_attack_bundle(FIXTURE)

    assert index.object_count == 10
    assert index.active_attack_pattern_count == 5
    assert len(index.subtechnique_relationships) == 2
    assert index.active_patterns_by_external_id["T1140"].name.startswith("Deobfuscate")
    assert index.collection is not None
    assert index.collection.version == "0.1"


@pytest.mark.parametrize(
    "document, message",
    [
        ([], "JSON object"),
        ({"type": "not-a-bundle", "objects": []}, "type 'bundle'"),
        ({"type": "bundle", "objects": {}}, "must be a list"),
        ({"type": "bundle", "objects": [{}]}, "field 'type'"),
    ],
)
def test_rejects_invalid_bundle_structures(
    tmp_path: Path, document: object, message: str
) -> None:
    with pytest.raises(MitreLoadError, match=message):
        load_attack_bundle(_write_bundle(tmp_path, document))


def test_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text("{", encoding="utf-8")

    with pytest.raises(MitreLoadError, match="Cannot read"):
        load_attack_bundle(path)


def test_rejects_duplicate_stix_id(tmp_path: Path) -> None:
    bundle = _bundle()
    objects = bundle["objects"]
    assert isinstance(objects, list)
    objects.append(deepcopy(objects[0]))

    with pytest.raises(MitreLoadError, match="Duplicate STIX ID"):
        load_attack_bundle(_write_bundle(tmp_path, bundle))


def test_rejects_duplicate_active_attack_external_id(tmp_path: Path) -> None:
    bundle = _bundle()
    duplicate = deepcopy(
        _object(bundle, "attack-pattern--00000000-0000-4000-8000-000000000005")
    )
    duplicate["id"] = "attack-pattern--00000000-0000-4000-8000-000000000099"
    duplicate["name"] = "Duplicate T1140"
    objects = bundle["objects"]
    assert isinstance(objects, list)
    objects.append(duplicate)

    with pytest.raises(MitreLoadError, match="Duplicate active ATT&CK external ID"):
        load_attack_bundle(_write_bundle(tmp_path, bundle))


def test_distinguishes_active_revoked_and_deprecated_patterns() -> None:
    index = load_attack_bundle(FIXTURE)

    assert "T1140" in index.active_patterns_by_external_id
    assert "T9999" not in index.active_patterns_by_external_id
    assert index.inactive_patterns_by_external_id["T9999"][0].revoked is True
    assert "T9998" not in index.active_patterns_by_external_id
    assert index.inactive_patterns_by_external_id["T9998"][0].deprecated is True


def test_reads_subtechnique_parent_from_relationship() -> None:
    index = load_attack_bundle(FIXTURE)
    child = index.active_patterns_by_external_id["T1218.005"]
    relationship = index.parent_by_subtechnique_id[child.stix_id]
    parent = index.attack_patterns_by_stix_id[relationship.target_ref]

    assert relationship.stix_id.endswith("000000000001")
    assert parent.external_id == "T1218"


def test_rejects_relationship_reference_not_in_bundle(tmp_path: Path) -> None:
    bundle = _bundle()
    relationship = _object(
        bundle, "relationship--00000000-0000-4000-8000-000000000001"
    )
    relationship["target_ref"] = (
        "attack-pattern--00000000-0000-4000-8000-000000009999"
    )

    with pytest.raises(MitreLoadError, match="not present in the bundle"):
        load_attack_bundle(_write_bundle(tmp_path, bundle))


def test_rejects_active_subtechnique_without_parent(tmp_path: Path) -> None:
    bundle = _bundle()
    objects = bundle["objects"]
    assert isinstance(objects, list)
    bundle["objects"] = [
        item
        for item in objects
        if item["id"] != "relationship--00000000-0000-4000-8000-000000000001"
    ]

    with pytest.raises(MitreLoadError, match="exactly one active parent"):
        load_attack_bundle(_write_bundle(tmp_path, bundle))


def test_rejects_active_subtechnique_with_conflicting_parents(tmp_path: Path) -> None:
    bundle = _bundle()
    relationship = deepcopy(
        _object(bundle, "relationship--00000000-0000-4000-8000-000000000001")
    )
    relationship["id"] = "relationship--00000000-0000-4000-8000-000000000099"
    relationship["target_ref"] = (
        "attack-pattern--00000000-0000-4000-8000-000000000003"
    )
    objects = bundle["objects"]
    assert isinstance(objects, list)
    objects.append(relationship)

    with pytest.raises(MitreLoadError, match="exactly one active parent"):
        load_attack_bundle(_write_bundle(tmp_path, bundle))


def test_rejects_invalid_attack_external_id(tmp_path: Path) -> None:
    bundle = _bundle()
    pattern = _object(
        bundle, "attack-pattern--00000000-0000-4000-8000-000000000005"
    )
    pattern["external_references"][0]["external_id"] = "TA1140"

    with pytest.raises(MitreLoadError, match="invalid ATT&CK external ID"):
        load_attack_bundle(_write_bundle(tmp_path, bundle))


def test_rejects_non_stix_21_declared_object(tmp_path: Path) -> None:
    bundle = _bundle()
    pattern = _object(
        bundle, "attack-pattern--00000000-0000-4000-8000-000000000005"
    )
    pattern["spec_version"] = "2.0"

    with pytest.raises(MitreLoadError, match="unsupported spec_version"):
        load_attack_bundle(_write_bundle(tmp_path, bundle))
