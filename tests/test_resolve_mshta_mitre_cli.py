from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import scripts.resolve_mshta_mitre as cli


FIXTURE = Path(__file__).parent / "fixtures" / "mitre" / "enterprise_attack_minimal.json"


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _sigma_review(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "sigma-match-review/v1",
                "scenario_id": "mshta-powershell",
                "analysis_status": "needs_review",
                "canonical_input": {"sha256": "1" * 64},
                "evidence_input": {"sha256": "2" * 64},
                "rule_count": 1,
                "rules": [
                    {
                        "id": "fixture-rule",
                        "title": "Fixture rule",
                        "source_path": "rules/fixture.yml",
                        "sha256": "3" * 64,
                        "tags": [
                            "attack.t1218.005",
                            "attack.execution",
                            "cve.2020-1599",
                        ],
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def _manifest(path: Path, bundle: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "mitre-source-manifest/v1",
                "source": {
                    "name": "MITRE ATT&CK Fixture",
                    "repository": "https://example.invalid/fixture",
                    "tag": "v0.1",
                    "commit": "0" * 40,
                    "url": "https://example.invalid/fixture.json",
                },
                "file": {
                    "path": bundle.as_posix(),
                    "sha256": _sha(bundle),
                    "data_type": "enterprise-attack",
                    "stix_version": "2.1",
                    "object_count": 10,
                    "active_attack_pattern_count": 5,
                    "subtechnique_of_relationship_count": 2,
                },
                "collection": {
                    "id": "x-mitre-collection--00000000-0000-4000-8000-000000000001",
                    "name": "Enterprise ATT&CK Fixture",
                    "version": "0.1",
                    "created": "2020-01-01T00:00:00.000Z",
                    "modified": "2025-01-01T00:00:00.000Z",
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    bundle = tmp_path / "enterprise-attack.json"
    bundle.write_bytes(FIXTURE.read_bytes())
    sigma = tmp_path / "sigma.json"
    _sigma_review(sigma)
    manifest = tmp_path / "manifest.json"
    _manifest(manifest, bundle)
    return sigma, bundle, manifest, tmp_path / "resolution.json"


def _arguments(
    sigma: Path, bundle: Path, manifest: Path, output: Path
) -> list[str]:
    return [
        "--sigma-input",
        str(sigma),
        "--mitre-bundle",
        str(bundle),
        "--manifest",
        str(manifest),
        "--output",
        str(output),
        "--scenario-id",
        "mshta-powershell",
    ]


def test_cli_resolves_tags_and_preserves_all_input_hashes(
    tmp_path: Path, capsys
) -> None:
    sigma, bundle, manifest, output = _inputs(tmp_path)
    inputs = (sigma, bundle, manifest)
    hashes_before = {path: _sha(path) for path in inputs}

    assert cli.main(_arguments(sigma, bundle, manifest, output)) == 0
    stats = json.loads(capsys.readouterr().out)
    document = json.loads(output.read_text(encoding="utf-8"))

    assert stats["output_schema_version"] == "mitre-resolution/v1"
    assert stats["resolved_technique_count"] == 1
    assert stats["candidate_link_count"] == 1
    assert stats["output_sha256"] == _sha(output)
    assert document["analysis_status"] == "needs_review"
    assert document["resolved_techniques"][0]["external_id"] == "T1218.005"
    assert {path: _sha(path) for path in inputs} == hashes_before


def test_cli_rejects_wrong_sigma_schema(tmp_path: Path, capsys) -> None:
    sigma, bundle, manifest, output = _inputs(tmp_path)
    document = json.loads(sigma.read_text(encoding="utf-8"))
    document["schema_version"] = "wrong/v1"
    sigma.write_text(json.dumps(document), encoding="utf-8")

    assert cli.main(_arguments(sigma, bundle, manifest, output)) == 2
    assert "unsupported schema_version" in capsys.readouterr().err
    assert not output.exists()


def test_cli_rejects_wrong_scenario_id(tmp_path: Path, capsys) -> None:
    sigma, bundle, manifest, output = _inputs(tmp_path)
    arguments = _arguments(sigma, bundle, manifest, output)
    arguments[-1] = "different-scenario"

    assert cli.main(arguments) == 2
    assert "does not match expected" in capsys.readouterr().err
    assert not output.exists()


def test_cli_rejects_existing_output_without_overwrite(
    tmp_path: Path, capsys
) -> None:
    sigma, bundle, manifest, output = _inputs(tmp_path)
    output.write_text("existing", encoding="utf-8")

    assert cli.main(_arguments(sigma, bundle, manifest, output)) == 2
    assert "pass --overwrite" in capsys.readouterr().err
    assert output.read_text(encoding="utf-8") == "existing"


def test_cli_atomic_overwrite_is_byte_deterministic(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    sigma, bundle, manifest, output = _inputs(tmp_path)
    arguments = [*_arguments(sigma, bundle, manifest, output), "--overwrite"]

    assert cli.main(arguments) == 0
    first = output.read_bytes()
    first_stats = json.loads(capsys.readouterr().out)

    replacements: list[tuple[Path, Path]] = []
    real_replace = cli.os.replace

    def recording_replace(source: str | Path, target: str | Path) -> None:
        replacements.append((Path(source), Path(target)))
        real_replace(source, target)

    monkeypatch.setattr(cli.os, "replace", recording_replace)
    assert cli.main(arguments) == 0
    second = output.read_bytes()
    second_stats = json.loads(capsys.readouterr().out)

    assert first == second
    assert first_stats["output_sha256"] == second_stats["output_sha256"]
    assert replacements[-1][1] == output
    assert replacements[-1][0].name.startswith(f".{output.name}.")
    assert not list(tmp_path.glob(f".{output.name}.*.tmp"))
