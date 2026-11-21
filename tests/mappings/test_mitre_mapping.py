"""Tests for the MITRE ATT&CK mapping configuration."""

from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MAPPING_FILE = PROJECT_ROOT / "detection-rules" / "mappings" / "mitre-mapping.yaml"


def load_mapping() -> dict[str, Any]:
    """Load and validate the MITRE ATT&CK mapping YAML file."""
    with MAPPING_FILE.open("r", encoding="utf-8") as handle:
        data: Any = yaml.safe_load(handle)

    assert isinstance(data, dict), "Mapping file must contain a YAML object."

    return data


def test_mapping_file_exists() -> None:
    """Verify that the MITRE mapping file exists."""
    assert MAPPING_FILE.exists()


def test_rules_section_exists() -> None:
    """Verify that the mapping contains a valid rules section."""
    data = load_mapping()

    assert "rules" in data
    assert isinstance(data["rules"], list)


def test_rule_ids_are_unique() -> None:
    """Verify that all defined rule IDs are unique."""
    data = load_mapping()

    rule_ids = [rule["rule_id"] for rule in data["rules"] if isinstance(rule, dict) and "rule_id" in rule]

    assert len(rule_ids) == len(set(rule_ids))


def test_rules_have_required_fields() -> None:
    """Verify that every rule contains the required fields."""
    data = load_mapping()

    for rule in data["rules"]:
        assert isinstance(rule, dict)
        assert rule.get("rule_id")
        assert rule.get("rule_name")
        assert isinstance(rule.get("techniques"), list)
        assert isinstance(rule.get("source"), list)


def test_technique_ids_are_valid_format() -> None:
    """Verify that technique IDs follow the expected MITRE format."""
    data = load_mapping()

    for rule in data["rules"]:
        for technique_id in rule.get("techniques", []):
            assert isinstance(technique_id, str)
            assert technique_id.startswith("T")
            assert technique_id[1:].replace(".", "").isdigit()
