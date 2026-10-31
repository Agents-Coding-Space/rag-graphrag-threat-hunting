from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from threat_hunting.sigma import SigmaRuleError, load_sigma_rule, load_sigma_rules


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sigma"
EXECUTION_RULE = FIXTURE_ROOT / "mshta_execution.yml"
CHILD_RULE = FIXTURE_ROOT / "mshta_child.yml"


def test_safe_loader_preserves_required_metadata_sha_and_input() -> None:
    before = EXECUTION_RULE.read_bytes()
    rule = load_sigma_rule(EXECUTION_RULE, source_path="fixtures/mshta_execution.yml")

    assert rule.to_dict() == {
        "title": "Fixture MSHTA Suspicious Execution",
        "id": "11111111-1111-4111-8111-111111111111",
        "status": "test",
        "description": "Fixture rule for safe Sigma subset tests.",
        "references": ["https://example.test/mshta-execution"],
        "author": "Test Author",
        "date": "2020-01-01",
        "modified": "2025-01-02",
        "tags": ["attack.t1218.005", "attack.t1140", "attack.t1059.007"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_img": [
                {"Image|endswith": "\\mshta.exe"},
                {"OriginalFileName": "mshta.exe"},
            ],
            "selection_cli": {
                "CommandLine|contains": [".png", "vbscript"],
            },
            "condition": "all of selection_*",
        },
        "level": "high",
        "sha256": hashlib.sha256(before).hexdigest(),
        "source_path": "fixtures/mshta_execution.yml",
    }
    assert EXECUTION_RULE.read_bytes() == before


def test_loader_uses_safe_yaml_and_rejects_unsafe_tags(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    path = tmp_path / "unsafe.yml"
    path.write_text(
        EXECUTION_RULE.read_text(encoding="utf-8").replace(
            "description: Fixture rule for safe Sigma subset tests.",
            f"description: !!python/object/apply:pathlib.Path.touch ['{marker}']",
        ),
        encoding="utf-8",
    )

    with pytest.raises(SigmaRuleError, match="unsafe Sigma YAML"):
        load_sigma_rule(path)
    assert not marker.exists()


def test_loader_rejects_non_mapping_missing_fields_and_duplicate_keys(
    tmp_path: Path,
) -> None:
    non_mapping = tmp_path / "list.yml"
    non_mapping.write_text("- not\n- a\n- rule\n", encoding="utf-8")
    with pytest.raises(SigmaRuleError, match="must be a YAML mapping"):
        load_sigma_rule(non_mapping)

    missing = tmp_path / "missing.yml"
    missing.write_text(
        EXECUTION_RULE.read_text(encoding="utf-8").replace("level: high\n", ""),
        encoding="utf-8",
    )
    with pytest.raises(SigmaRuleError, match="missing required fields: level"):
        load_sigma_rule(missing)

    duplicate = tmp_path / "duplicate.yml"
    duplicate.write_text(
        EXECUTION_RULE.read_text(encoding="utf-8") + "title: duplicate\n",
        encoding="utf-8",
    )
    with pytest.raises(SigmaRuleError, match="duplicate key"):
        load_sigma_rule(duplicate)


@pytest.mark.parametrize(
    ("replacement", "message"),
    (
        ("logsource: windows", "must be a non-empty mapping"),
        (
            "logsource:\n    product: windows\n    category: 1",
            "value for 'category' must be a non-empty string",
        ),
        (
            "logsource:\n    product: windows\n    1: process_creation",
            "keys must be non-empty strings",
        ),
    ),
)
def test_loader_rejects_invalid_logsource_types(
    tmp_path: Path,
    replacement: str,
    message: str,
) -> None:
    path = tmp_path / "invalid-logsource.yml"
    path.write_text(
        EXECUTION_RULE.read_text(encoding="utf-8").replace(
            "logsource:\n    category: process_creation\n    product: windows",
            replacement,
        ),
        encoding="utf-8",
    )

    with pytest.raises(SigmaRuleError, match=message):
        load_sigma_rule(path)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    (
        ("Image|endswith", "Image|startswith", "Unsupported Sigma modifier"),
        (
            "condition: all of selection_*",
            "condition: selection_img and selection_cli",
            "Unsupported Sigma condition",
        ),
        (
            (
                "selection_cli:\n"
                "        CommandLine|contains:\n"
                "            - '.png'\n"
                "            - 'vbscript'"
            ),
            "selection_cli: vbscript",
            "must be a mapping or a non-empty list of mappings",
        ),
    ),
)
def test_loader_rejects_unsupported_modifier_condition_and_structure(
    tmp_path: Path,
    old: str,
    new: str,
    message: str,
) -> None:
    path = tmp_path / "unsupported.yml"
    path.write_text(
        EXECUTION_RULE.read_text(encoding="utf-8").replace(old, new),
        encoding="utf-8",
    )
    with pytest.raises(SigmaRuleError, match=message):
        load_sigma_rule(path)


def test_load_rules_is_deterministic_and_rejects_duplicate_ids(tmp_path: Path) -> None:
    first = load_sigma_rules((CHILD_RULE, EXECUTION_RULE))
    second = load_sigma_rules((EXECUTION_RULE, CHILD_RULE))
    assert [rule.rule_id for rule in first] == [rule.rule_id for rule in second]

    duplicate = tmp_path / "duplicate-id.yml"
    duplicate.write_bytes(EXECUTION_RULE.read_bytes())
    with pytest.raises(SigmaRuleError, match="IDs must be unique"):
        load_sigma_rules((EXECUTION_RULE, duplicate))
