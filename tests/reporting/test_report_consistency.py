"""Test consistency across generated MITRE ATT&CK coverage reports."""

import json
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from tools.reports import coverage_report


def sample_registry() -> dict[str, Any]:
    """Return a sample registry containing nine detection rules."""
    return {
        "rules": [
            {
                "id": "DET-SIGMA-LSASS-ACCESS",
                "name": "LSASS Process Access Detection",
                "format": "sigma",
            },
            {
                "id": "DET-SIGMA-POWERSHELL-EXEC",
                "name": "Suspicious PowerShell Execution",
                "format": "sigma",
            },
            {
                "id": "DET-SIGMA-SUSPICIOUS-LOGIN",
                "name": "Suspicious Login Activity",
                "format": "sigma",
            },
            {
                "id": "DET-YARA-MALWARE-SAMPLE",
                "name": "Malware Sample Detection",
                "format": "yara",
            },
            {
                "id": "DET-YARA-OBFUSCATED-POWERSHELL",
                "name": "Obfuscated PowerShell Payload",
                "format": "yara",
            },
            {
                "id": "DET-YARA-POWERSHELL-PAYLOAD",
                "name": "PowerShell Payload Detection",
                "format": "yara",
            },
            {
                "id": "DET-SURI-C2-COMMUNICATION",
                "name": "C2 Communication Detection",
                "format": "suricata",
            },
            {
                "id": "DET-SURI-NETWORK-ALERT",
                "name": "Suspicious Network Traffic",
                "format": "suricata",
            },
            {
                "id": "DET-SURI-POWERSHELL-ALERT",
                "name": "PowerShell Network Activity",
                "format": "suricata",
            },
        ]
    }


def sample_mitre_mapping() -> dict[str, Any]:
    """Return the authoritative three-rule MITRE mapping."""
    return {
        "rules": [
            {
                "registry_id": "DET-SIGMA-LSASS-ACCESS",
                "techniques": ["T1003.001"],
            },
            {
                "registry_id": "DET-SIGMA-POWERSHELL-EXEC",
                "techniques": ["T1059.001"],
            },
            {
                "registry_id": "DET-YARA-OBFUSCATED-POWERSHELL",
                "techniques": ["T1027"],
            },
        ]
    }


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    """Write YAML test data to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(data, file, sort_keys=False)


def read_json(path: Path) -> dict[str, Any]:
    """Read a JSON report from disk and validate its root structure."""
    with path.open("r", encoding="utf-8") as file:
        data: Any = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object: {path}")

    return cast(dict[str, Any], data)


def generate_test_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Generate reports using isolated temporary files."""
    output_dir = tmp_path / "reports"

    paths = {
        "REGISTRY_FILE": tmp_path / "registry.yaml",
        "MITRE_MAPPING": tmp_path / "mitre-mapping.yaml",
        "COVERAGE_REPORT": output_dir / "coverage_report.json",
        "ATTACK_COVERAGE": output_dir / "attack-coverage.json",
        "RULE_COVERAGE_MAP": output_dir / "rule_coverage_map.json",
    }

    write_yaml(paths["REGISTRY_FILE"], sample_registry())
    write_yaml(paths["MITRE_MAPPING"], sample_mitre_mapping())

    for attribute, path in paths.items():
        monkeypatch.setattr(coverage_report, attribute, path)

    coverage_report.generate_reports()

    return (
        read_json(paths["COVERAGE_REPORT"]),
        read_json(paths["ATTACK_COVERAGE"]),
        read_json(paths["RULE_COVERAGE_MAP"]),
    )


def assert_rule_summary(coverage: dict[str, Any]) -> None:
    """Verify rule totals and ATT&CK coverage scope."""
    assert coverage["summary"] == {
        "total_rules": 9,
        "mapped_rules": 3,
        "unmapped_rules": 6,
        "total_mapped_techniques": 3,
    }

    assert len(coverage["rules"]) == 9

    assert coverage["coverage_scope"] == (
        "Repository mapping dataset only. "
        "This report does not represent full ATT&CK Enterprise coverage."
    )


def assert_rule_mapping(
    coverage: dict[str, Any],
    rule_coverage: dict[str, Any],
) -> None:
    """Verify all rules and their mappings are consistent."""
    expected_mappings = {
        "DET-SIGMA-LSASS-ACCESS": ["T1003.001"],
        "DET-SIGMA-POWERSHELL-EXEC": ["T1059.001"],
        "DET-YARA-OBFUSCATED-POWERSHELL": ["T1027"],
    }

    expected_ids = {
        rule["id"] for rule in sample_registry()["rules"]
    }

    assert set(rule_coverage) == expected_ids

    report_ids = {
        rule["registry_id"] for rule in coverage["rules"]
    }

    assert report_ids == expected_ids

    for registry_id, rule_data in rule_coverage.items():
        expected = expected_mappings.get(registry_id, [])

        assert rule_data["techniques"] == expected
        assert rule_data["technique_count"] == len(expected)

    for rule in coverage["rules"]:
        expected = expected_mappings.get(rule["registry_id"], [])

        assert rule["techniques"] == expected
        assert rule["mapped"] is bool(expected)
        assert rule["technique_count"] == len(expected)


def assert_technique_mapping(
    coverage: dict[str, Any],
    attack_coverage: dict[str, Any],
) -> None:
    """Verify technique coverage consistency across reports."""
    expected_techniques = {
        "T1003.001": ["DET-SIGMA-LSASS-ACCESS"],
        "T1027": ["DET-YARA-OBFUSCATED-POWERSHELL"],
        "T1059.001": ["DET-SIGMA-POWERSHELL-EXEC"],
    }

    expected_coverage = {
        technique: {
            "rule_count": len(registry_ids),
            "rules": registry_ids,
        }
        for technique, registry_ids in expected_techniques.items()
    }

    assert coverage["techniques"] == expected_coverage

    assert attack_coverage["summary"] == {
        "mapped_techniques": 3,
        "coverage_scope": "repository_mapping_dataset",
    }

    actual_techniques = {
        entry["technique_id"]: entry
        for entry in attack_coverage["techniques"]
    }

    assert set(actual_techniques) == set(expected_techniques)

    for technique, registry_ids in expected_techniques.items():
        entry = actual_techniques[technique]

        assert entry["covered"] is True
        assert entry["rules"] == registry_ids
        assert entry["rule_count"] == len(registry_ids)


def test_generate_reports_writes_consistent_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify all generated coverage reports are mutually consistent."""
    coverage, attack_coverage, rule_coverage = generate_test_reports(
        tmp_path,
        monkeypatch,
    )

    assert_rule_summary(coverage)
    assert_rule_mapping(coverage, rule_coverage)
    assert_technique_mapping(coverage, attack_coverage)


def test_save_json_creates_parent_directories(
    tmp_path: Path,
) -> None:
    """Verify JSON output creates missing parent directories."""
    output_file = tmp_path / "nested" / "reports" / "output.json"

    expected_data = {
        "status": "success",
        "count": 3,
    }

    coverage_report.save_json(output_file, expected_data)

    assert output_file.exists()
    assert read_json(output_file) == expected_data


def test_build_rule_coverage_output_preserves_unmapped_rules() -> None:
    """Verify rule coverage output retains unmapped rules."""
    rule_map = {
        "DET-SIGMA-LSASS-ACCESS": ["T1003.001"],
        "DET-SIGMA-SUSPICIOUS-LOGIN": [],
        "DET-YARA-MALWARE-SAMPLE": [],
    }

    result = coverage_report.build_rule_coverage_output(rule_map)

    assert result == {
        "DET-SIGMA-LSASS-ACCESS": {
            "techniques": ["T1003.001"],
            "technique_count": 1,
        },
        "DET-SIGMA-SUSPICIOUS-LOGIN": {
            "techniques": [],
            "technique_count": 0,
        },
        "DET-YARA-MALWARE-SAMPLE": {
            "techniques": [],
            "technique_count": 0,
        },
    }
