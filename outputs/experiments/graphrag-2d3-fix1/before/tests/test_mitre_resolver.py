from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from threat_hunting.mitre.loader import (
    MitreCollection,
    MitreSourceManifest,
    load_attack_bundle,
)
from threat_hunting.mitre.resolver import (
    assert_review_only,
    build_resolution,
    deterministic_json_bytes,
)


FIXTURE = Path(__file__).parent / "fixtures" / "mitre" / "enterprise_attack_minimal.json"
SIGMA_HASH = "a" * 64
MANIFEST_HASH = "b" * 64
RULE_ONE_HASH = "c" * 64
RULE_TWO_HASH = "d" * 64


def _review() -> dict[str, object]:
    return {
        "schema_version": "sigma-match-review/v1",
        "scenario_id": "fixture-scenario",
        "analysis_status": "needs_review",
        "canonical_input": {"sha256": "e" * 64},
        "evidence_input": {"sha256": "f" * 64},
        "rule_count": 2,
        "rules": [
            {
                "id": "rule-1",
                "title": "Rule one",
                "source_path": "rules/one.yml",
                "sha256": RULE_ONE_HASH,
                "tags": [
                    "attack.stealth",
                    "attack.t1218.005",
                    "car.2013-02-003",
                ],
            },
            {
                "id": "rule-2",
                "title": "Rule two",
                "source_path": "rules/two.yml",
                "sha256": RULE_TWO_HASH,
                "tags": [
                    "attack.t1140",
                    "attack.t1218.005",
                    "attack.execution",
                    "attack.t1059.007",
                    "cve.2020-1599",
                ],
            },
        ],
    }


def _manifest() -> MitreSourceManifest:
    return MitreSourceManifest(
        source_path=Path("manifest.json"),
        source_name="MITRE ATT&CK Fixture",
        repository="https://example.invalid/fixture",
        tag="v0.1",
        commit="0" * 40,
        url="https://example.invalid/fixture.json",
        bundle_path="tests/fixtures/mitre/enterprise_attack_minimal.json",
        bundle_sha256=sha256(FIXTURE.read_bytes()).hexdigest(),
        data_type="enterprise-attack",
        stix_version="2.1",
        object_count=10,
        active_attack_pattern_count=5,
        subtechnique_of_relationship_count=2,
        collection=MitreCollection(
            stix_id="x-mitre-collection--00000000-0000-4000-8000-000000000001",
            name="Enterprise ATT&CK Fixture",
            version="0.1",
            created="2020-01-01T00:00:00.000Z",
            modified="2025-01-01T00:00:00.000Z",
        ),
    )


def _resolve(review: dict[str, object] | None = None) -> dict[str, object]:
    return build_resolution(
        sigma_review=review or _review(),
        sigma_input_path="outputs/sigma.json",
        sigma_input_sha256=SIGMA_HASH,
        attack_index=load_attack_bundle(FIXTURE),
        manifest=_manifest(),
        manifest_path="configs/manifest.json",
        manifest_sha256=MANIFEST_HASH,
    )


def test_exactly_resolves_techniques_and_subtechniques() -> None:
    result = _resolve()

    assert result["technique_tag_count"] == 3
    assert result["technique_tag_occurrence_count"] == 4
    assert result["resolved_technique_count"] == 3
    assert {
        item["external_id"] for item in result["resolved_techniques"]
    } == {"T1218.005", "T1140", "T1059.007"}
    assert result["unresolved_technique_tags"] == []


def test_reads_parent_relationships_from_stix_index() -> None:
    result = _resolve()
    relationships = {
        item["subtechnique_external_id"]: item["parent_external_id"]
        for item in result["parent_subtechnique_relationships"]
    }

    assert relationships == {"T1059.007": "T1059", "T1218.005": "T1218"}
    assert "T1140" not in relationships


def test_separates_non_technique_attack_and_other_taxonomy_tags() -> None:
    result = _resolve()

    assert {item["tag"] for item in result["non_technique_attack_tags"]} == {
        "attack.execution",
        "attack.stealth",
    }
    assert {item["tag"] for item in result["other_rule_tags"]} == {
        "car.2013-02-003",
        "cve.2020-1599",
    }


def test_does_not_fuzzy_match_malformed_technique_tag() -> None:
    review = _review()
    review["rules"][0]["tags"].append("attack.t1140x")
    result = _resolve(review)

    assert result["technique_tag_count"] == 3
    assert "attack.t1140x" in {
        item["tag"] for item in result["non_technique_attack_tags"]
    }


def test_marks_revoked_and_deprecated_only_ids_inactive() -> None:
    review = _review()
    review["rules"][0]["tags"].extend(["attack.t9999", "attack.t9998"])
    result = _resolve(review)
    unresolved = {
        item["normalized_external_id"]: item
        for item in result["unresolved_technique_tags"]
    }

    assert unresolved["T9999"]["status"] == "inactive"
    assert unresolved["T9999"]["inactive_objects"][0]["revoked"] is True
    assert unresolved["T9998"]["status"] == "inactive"
    assert unresolved["T9998"]["inactive_objects"][0]["x_mitre_deprecated"] is True


def test_preserves_rule_provenance_in_each_candidate_link() -> None:
    result = _resolve()
    links = result["rule_technique_candidate_links"]

    assert len(links) == 4
    shared = [item for item in links if item["normalized_external_id"] == "T1218.005"]
    assert {item["rule_id"] for item in shared} == {"rule-1", "rule-2"}
    assert {item["provenance"]["rule_sha256"] for item in shared} == {
        RULE_ONE_HASH,
        RULE_TWO_HASH,
    }
    assert all(item["provenance"]["sigma_input_sha256"] == SIGMA_HASH for item in links)


def test_never_creates_confirmed_state() -> None:
    result = _resolve()

    assert result["analysis_status"] == "needs_review"
    assert all(
        item["status"] == "candidate"
        and item["evidence_assessment"] == "not_assessed"
        for item in result["rule_technique_candidate_links"]
    )
    assert all(
        item["evidence_assessment"] == "not_assessed"
        for item in result["resolved_techniques"]
    )
    assert_review_only(result)


def test_deterministic_ids_and_serialization() -> None:
    first = _resolve()
    second = _resolve()

    first_ids = [item["link_id"] for item in first["rule_technique_candidate_links"]]
    second_ids = [item["link_id"] for item in second["rule_technique_candidate_links"]]
    assert first_ids == second_ids
    assert len(first_ids) == len(set(first_ids))
    assert all(item.startswith("mitre-link--") for item in first_ids)
    assert deterministic_json_bytes(first) == deterministic_json_bytes(second)


def test_does_not_mutate_sigma_input() -> None:
    review = _review()
    before = deepcopy(review)

    _resolve(review)

    assert review == before
