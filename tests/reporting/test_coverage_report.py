"""Tests for MITRE ATT&CK coverage report calculations."""

import pytest

from tools.reports import coverage_report


def sample_rules() -> list[dict[str, str]]:
    """Return sample detection rules for coverage tests."""
    return [
        {
            "registry_id": "DET-SIGMA-LSASS-ACCESS",
            "rule_name": "Suspicious LSASS Process Access",
            "format": "sigma",
        },
        {
            "registry_id": "DET-SIGMA-POWERSHELL-EXEC",
            "rule_name": "PowerShell Encoded Command Execution",
            "format": "sigma",
        },
        {
            "registry_id": "DET-YARA-OBFUSCATED-POWERSHELL",
            "rule_name": "Obfuscated PowerShell Payload",
            "format": "yara",
        },
        {
            "registry_id": "DET-SIGMA-RULE-004",
            "rule_name": "Suspicious Login Activity",
            "format": "sigma",
        },
        {
            "registry_id": "DET-YARA-RULE-005",
            "rule_name": "Malware Detection",
            "format": "yara",
        },
        {
            "registry_id": "DET-SIGMA-RULE-006",
            "rule_name": "PowerShell Payload Detection",
            "format": "sigma",
        },
        {
            "registry_id": "DET-SURICATA-RULE-007",
            "rule_name": "C2 Communication Detection",
            "format": "suricata",
        },
        {
            "registry_id": "DET-SURICATA-RULE-008",
            "rule_name": "Network Alert Detection",
            "format": "suricata",
        },
        {
            "registry_id": "DET-SURICATA-RULE-009",
            "rule_name": "Suricata PowerShell Detection",
            "format": "suricata",
        },
    ]


def sample_mapping() -> dict[str, list[str]]:
    """Return sample MITRE mappings using actual registry IDs."""
    return {
        "DET-SIGMA-LSASS-ACCESS": ["T1003.001"],
        "DET-SIGMA-POWERSHELL-EXEC": ["T1059.001"],
        "DET-YARA-OBFUSCATED-POWERSHELL": ["T1027"],
    }


def test_build_rule_coverage_map_includes_all_rules() -> None:
    """Verify mapped and unmapped rules are included."""
    rules = sample_rules()
    mapping = sample_mapping()

    result = coverage_report.build_rule_coverage_map(
        rules,
        mapping,
    )

    assert len(result) == 9

    assert result["DET-SIGMA-LSASS-ACCESS"] == ["T1003.001"]
    assert result["DET-SIGMA-POWERSHELL-EXEC"] == ["T1059.001"]
    assert result["DET-YARA-OBFUSCATED-POWERSHELL"] == ["T1027"]

    for registry_id in (
        "DET-SIGMA-RULE-004",
        "DET-YARA-RULE-005",
        "DET-SIGMA-RULE-006",
        "DET-SURICATA-RULE-007",
        "DET-SURICATA-RULE-008",
        "DET-SURICATA-RULE-009",
    ):
        assert result[registry_id] == []


def test_build_rule_coverage_map_rejects_unknown_registry_ids() -> None:
    """Verify unknown registry IDs are rejected."""
    rules = sample_rules()
    mapping = {
        "DET-UNKNOWN": ["T1003.001"],
    }

    with pytest.raises(
        ValueError,
        match="unknown registry IDs",
    ):
        coverage_report.build_rule_coverage_map(
            rules,
            mapping,
        )


def test_build_technique_coverage() -> None:
    """Verify technique-to-rule relationships are generated."""
    rules = sample_rules()
    mapping = sample_mapping()

    rule_map = coverage_report.build_rule_coverage_map(
        rules,
        mapping,
    )

    result = coverage_report.build_technique_coverage(
        rule_map
    )

    assert len(result) == 3

    assert result == {
    "T1003.001": ["DET-SIGMA-LSASS-ACCESS"],
    "T1027": ["DET-YARA-OBFUSCATED-POWERSHELL"],
    "T1059.001": ["DET-SIGMA-POWERSHELL-EXEC"],
}


def test_build_coverage_report_summary() -> None:
    """Verify total, mapped, and unmapped rule counts."""
    rules = sample_rules()
    mapping = sample_mapping()

    rule_map = coverage_report.build_rule_coverage_map(
        rules,
        mapping,
    )

    technique_map = coverage_report.build_technique_coverage(
        rule_map
    )

    result = coverage_report.build_coverage_report(
        rules,
        rule_map,
        technique_map,
    )

    assert result["summary"] == {
        "total_rules": 9,
        "mapped_rules": 3,
        "unmapped_rules": 6,
        "total_mapped_techniques": 3,
    }


def test_build_coverage_report_preserves_unmapped_rules() -> None:
    """Verify unmapped rules remain visible in the report."""
    rules = sample_rules()
    mapping = sample_mapping()

    rule_map = coverage_report.build_rule_coverage_map(
        rules,
        mapping,
    )

    technique_map = coverage_report.build_technique_coverage(
        rule_map
    )

    result = coverage_report.build_coverage_report(
        rules,
        rule_map,
        technique_map,
    )

    assert len(result["rules"]) == 9

    unmapped_rules = [
        rule
        for rule in result["rules"]
        if not rule["mapped"]
    ]

    assert len(unmapped_rules) == 6

    for rule in unmapped_rules:
        assert rule["techniques"] == []
        assert rule["technique_count"] == 0


def test_coverage_report_does_not_claim_full_attack_coverage() -> None:
    """Verify the report explicitly limits its coverage scope."""
    rules = sample_rules()
    mapping = sample_mapping()

    rule_map = coverage_report.build_rule_coverage_map(
        rules,
        mapping,
    )

    technique_map = coverage_report.build_technique_coverage(
        rule_map
    )

    result = coverage_report.build_coverage_report(
        rules,
        rule_map,
        technique_map,
    )

    assert (
        "does not represent full ATT&CK Enterprise coverage"
        in result["coverage_scope"]
    )


def test_load_registry_rules_rejects_duplicate_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify duplicate registry IDs cause validation failure."""
    registry = {
        "rules": [
            {
                "id": "DET-DUPLICATE",
                "name": "First Rule",
                "format": "sigma",
            },
            {
                "id": "DET-DUPLICATE",
                "name": "Second Rule",
                "format": "yara",
            },
        ]
    }

    monkeypatch.setattr(
        coverage_report,
        "load_yaml",
        lambda path: registry,
    )

    with pytest.raises(
        ValueError,
        match="Duplicate registry ID",
    ):
        coverage_report.load_registry_rules()


def test_load_mitre_mapping_rejects_duplicate_registry_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify duplicate mapping registry IDs are rejected."""
    mapping = {
        "rules": [
            {
                "registry_id": "DET-RULE-1",
                "techniques": ["T1003.001"],
            },
            {
                "registry_id": "DET-RULE-1",
                "techniques": ["T1027"],
            },
        ]
    }

    monkeypatch.setattr(
        coverage_report,
        "load_yaml",
        lambda path: mapping,
    )

    with pytest.raises(
        ValueError,
        match="Duplicate mapping registry_id",
    ):
        coverage_report.load_mitre_mapping()


def test_load_mitre_mapping_normalizes_technique_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify technique IDs are normalized and deduplicated."""
    mapping = {
        "rules": [
            {
                "registry_id": "DET-RULE-1",
                "techniques": [
                    "t1003.001",
                    "T1027",
                    "T1003.001",
                ],
            }
        ]
    }

    monkeypatch.setattr(
        coverage_report,
        "load_yaml",
        lambda path: mapping,
    )

    result = coverage_report.load_mitre_mapping()

    assert result == {
        "DET-RULE-1": [
            "T1003.001",
            "T1027",
        ]
    }


def test_build_attack_coverage_contains_mapped_techniques_only() -> None:
    """Verify ATT&CK output contains only mapped techniques."""
    rules = sample_rules()
    mapping = sample_mapping()

    rule_map = coverage_report.build_rule_coverage_map(
        rules,
        mapping,
    )

    technique_map = coverage_report.build_technique_coverage(
        rule_map
    )

    result = coverage_report.build_attack_coverage(
        technique_map
    )

    assert result["summary"]["mapped_techniques"] == 3

    technique_ids = {
        item["technique_id"]
        for item in result["techniques"]
    }

    assert technique_ids == {
        "T1003.001",
        "T1027",
        "T1059.001",
    }
