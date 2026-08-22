from __future__ import annotations

from pathlib import Path

import pytest

from tools.parsers.sigma_parser import (
    extract_mitre_attack,
    load_sigma_rule,
    load_schema,
    normalize_logsource,
    normalize_severity,
    normalize_sigma_rule,
    normalize_status,
    parse_datetime,
    validate_rule,
)


def get_schema_path() -> Path:
    """Return the path to detection_rule.schema.json."""
    return (
        Path(__file__).resolve().parents[2]
        / "schemas"
        / "detection_rule.schema.json"
    )


def test_parse_datetime_date_only() -> None:
    result = parse_datetime("2026-08-22")

    assert result == "2026-08-22T00:00:00+00:00"


def test_parse_datetime_iso8601() -> None:
    result = parse_datetime(
        "2026-08-22T12:00:00Z"
    )

    assert result == "2026-08-22T12:00:00+00:00"


def test_parse_datetime_invalid_value() -> None:
    result = parse_datetime("invalid-date")

    assert "T" in result
    assert result.endswith("+00:00")


def test_parse_datetime_missing_value() -> None:
    result = parse_datetime(None)

    assert "T" in result
    assert result.endswith("+00:00")


def test_normalize_status() -> None:
    assert normalize_status("experimental") == "experimental"
    assert normalize_status("test") == "testing"
    assert normalize_status("testing") == "testing"
    assert normalize_status("stable") == "stable"
    assert normalize_status("production") == "stable"
    assert normalize_status("deprecated") == "deprecated"
    assert normalize_status("unsupported") == "deprecated"


def test_normalize_status_missing_or_unknown() -> None:
    assert normalize_status(None) == "testing"
    assert normalize_status("") == "testing"
    assert normalize_status("unknown") == "testing"


def test_normalize_severity() -> None:
    assert normalize_severity("informational") == "informational"
    assert normalize_severity("low") == "low"
    assert normalize_severity("medium") == "medium"
    assert normalize_severity("high") == "high"
    assert normalize_severity("critical") == "critical"


def test_normalize_severity_missing_or_unknown() -> None:
    assert normalize_severity(None) == "informational"
    assert normalize_severity("") == "informational"
    assert normalize_severity("unknown") == "informational"


def test_extract_mitre_attack() -> None:
    tags = [
        "attack.execution",
        "attack.t1059",
        "attack.t1059.001",
        "attack.t1059.001",
        "windows",
    ]

    result = extract_mitre_attack(tags)

    assert result == [
        "T1059",
        "T1059.001",
    ]


def test_extract_mitre_attack_accepts_current_parser_behavior() -> None:
    tags = [
        "attack.execution",
        "attack.t123",
        "attack.t12345",
        "attack.t1234.01",
        "attack.t1234.0001",
        "windows",
    ]

    result = extract_mitre_attack(tags)

    assert result == [
        "T123",
        "T1234.0001",
        "T1234.01",
        "T12345",
    ]


def test_extract_mitre_attack_case_insensitive() -> None:
    tags = [
        "ATTACK.T1059",
        "Attack.T1059.001",
    ]

    result = extract_mitre_attack(tags)

    assert result == [
        "T1059",
        "T1059.001",
    ]


def test_normalize_logsource() -> None:
    logsource = {
        "category": "process_creation",
        "product": "windows",
        "service": "sysmon",
    }

    result = normalize_logsource(logsource)

    assert result == [
        {
            "category": "process_creation",
            "product": "windows",
            "service": "sysmon",
        }
    ]


def test_normalize_logsource_partial() -> None:
    result = normalize_logsource(
        {
            "product": "windows",
        }
    )

    assert result == [
        {
            "product": "windows",
        }
    ]


def test_normalize_logsource_empty() -> None:
    assert normalize_logsource(None) == []
    assert normalize_logsource({}) == []
    assert normalize_logsource("invalid") == []


def test_load_sigma_rule(tmp_path: Path) -> None:
    rule_path = tmp_path / "test_rule.yml"

    rule_path.write_text(
        """
title: Test Rule
id: test-001
status: experimental
level: high
description: Test Sigma rule
author: Secwexen
date: 2026-08-22
tags:
  - attack.t1059.001
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
      - powershell.exe
  condition: selection
falsepositives:
  - Administrative activity
""".strip(),
        encoding="utf-8",
    )

    rule = load_sigma_rule(rule_path)

    assert rule["title"] == "Test Rule"
    assert rule["id"] == "test-001"
    assert rule["status"] == "experimental"
    assert rule["level"] == "high"
    assert rule["logsource"]["category"] == "process_creation"


def test_load_sigma_rule_rejects_non_dict(
    tmp_path: Path,
) -> None:
    rule_path = tmp_path / "invalid.yml"

    rule_path.write_text(
        "- item1\n- item2\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_sigma_rule(rule_path)


def test_normalize_sigma_rule() -> None:
    sigma_rule = {
        "title": "Suspicious PowerShell",
        "id": "sigma-test-001",
        "status": "stable",
        "level": "high",
        "description": "Detects suspicious PowerShell activity.",
        "author": "Secwexen",
        "date": "2026-08-22",
        "tags": [
            "attack.execution",
            "attack.t1059",
            "attack.t1059.001",
        ],
        "logsource": {
            "category": "process_creation",
            "product": "windows",
            "service": "sysmon",
        },
        "detection": {
            "selection": {
                "Image|endswith": [
                    "powershell.exe",
                ]
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Administrative scripts",
        ],
        "references": [
            "https://example.com/reference",
        ],
    }

    result = normalize_sigma_rule(
        sigma_rule,
        Path("sigma-test-001.yml"),
    )

    assert result["id"] == "sigma-test-001"
    assert result["name"] == "Suspicious PowerShell"
    assert result["type"] == "sigma"
    assert result["version"] == "1.0.0"
    assert result["status"] == "stable"
    assert result["severity"] == "high"
    assert result["description"] == (
        "Detects suspicious PowerShell activity."
    )
    assert result["author"] == "Secwexen"

    assert result["tags"] == [
        "attack.execution",
        "attack.t1059",
        "attack.t1059.001",
    ]

    assert result["mitre_attack"] == [
        "T1059",
        "T1059.001",
    ]

    assert result["log_sources"] == [
        {
            "category": "process_creation",
            "product": "windows",
            "service": "sysmon",
        }
    ]

    assert result["detection_logic"] == {
        "selection": {
            "Image|endswith": [
                "powershell.exe",
            ]
        },
        "condition": "selection",
    }

    assert result["false_positives"] == [
        "Administrative scripts",
    ]

    assert result["references"] == [
        "https://example.com/reference",
    ]

    assert result["references_attack"] == [
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1059.001/",
    ]

    assert result["created_at"] == (
        "2026-08-22T00:00:00+00:00"
    )

    assert result["updated_at"] == (
        "2026-08-22T00:00:00+00:00"
    )


def test_normalize_sigma_rule_missing_optional_fields() -> None:
    sigma_rule = {
        "id": "minimal-rule",
        "title": "Minimal Rule",
    }

    result = normalize_sigma_rule(
        sigma_rule,
        Path("minimal-rule.yml"),
    )

    assert result["id"] == "minimal-rule"
    assert result["name"] == "Minimal Rule"
    assert result["type"] == "sigma"
    assert result["version"] == "1.0.0"
    assert result["status"] == "testing"
    assert result["severity"] == "informational"
    assert result["description"] == (
        "Normalized Sigma detection rule: Minimal Rule"
    )
    assert result["author"] == "Secwexen"
    assert result["tags"] == []
    assert result["mitre_attack"] == []
    assert result["log_sources"] == []
    assert result["detection_logic"] == {}
    assert result["false_positives"] == []
    assert "references" not in result
    assert "references_attack" not in result


def test_load_schema() -> None:
    schema = load_schema(get_schema_path())

    assert schema["title"] == (
        "Security Playbooks Detection Rule"
    )
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False

    required = set(schema["required"])

    assert {
        "id",
        "name",
        "type",
        "status",
        "severity",
        "description",
        "author",
        "created_at",
        "updated_at",
    }.issubset(required)


def test_normalized_rule_passes_schema() -> None:
    schema = load_schema(get_schema_path())

    sigma_rule = {
        "id": "schema-test-001",
        "title": "Schema Validation Test",
        "status": "stable",
        "level": "medium",
        "description": "Test normalized detection rule.",
        "author": "Secwexen",
        "date": "2026-08-22",
        "tags": [
            "attack.t1059.001",
        ],
        "logsource": {
            "category": "process_creation",
        },
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "powershell",
                ]
            },
            "condition": "selection",
        },
    }

    normalized = normalize_sigma_rule(
        sigma_rule,
        Path("schema-test-001.yml"),
    )

    assert validate_rule(
        normalized,
        schema,
    ) is True


def test_invalid_normalized_rule_fails_schema() -> None:
    schema = load_schema(get_schema_path())

    invalid_rule = {
        "id": "invalid-rule",
        "name": "Invalid Rule",
        "type": "invalid-type",
        "status": "stable",
        "severity": "high",
        "description": "Invalid test rule.",
        "author": "Secwexen",
        "created_at": "2026-08-22T00:00:00+00:00",
        "updated_at": "2026-08-22T00:00:00+00:00",
    }

    assert validate_rule(
        invalid_rule,
        schema,
    ) is False


def test_normalized_rule_rejects_extra_property() -> None:
    schema = load_schema(get_schema_path())

    invalid_rule = {
        "id": "extra-property-test",
        "name": "Extra Property Test",
        "type": "sigma",
        "status": "stable",
        "severity": "medium",
        "description": "Test extra property.",
        "author": "Secwexen",
        "created_at": "2026-08-22T00:00:00+00:00",
        "updated_at": "2026-08-22T00:00:00+00:00",
        "unexpected_field": True,
    }

    assert validate_rule(
        invalid_rule,
        schema,
    ) is False
