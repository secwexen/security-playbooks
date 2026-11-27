"""Tests for consistency between MITRE ATT&CK mappings and coverage matrix."""

import json
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MAPPING_FILE = PROJECT_ROOT / "detection-rules" / "mappings" / "mitre-mapping.yaml"

MATRIX_FILE = PROJECT_ROOT / "reports" / "attack-matrix.json"


def load_mapping() -> dict[str, Any]:
    """Load and validate the MITRE ATT&CK mapping YAML file."""
    with MAPPING_FILE.open("r", encoding="utf-8") as handle:
        data: Any = yaml.safe_load(handle)

    assert isinstance(data, dict), "MITRE mapping must contain a YAML object."

    return data


def load_matrix() -> dict[str, Any]:
    """Load and validate the generated ATT&CK matrix JSON file."""
    assert MATRIX_FILE.exists(), f"ATT&CK matrix file does not exist: {MATRIX_FILE}"

    with MATRIX_FILE.open("r", encoding="utf-8") as handle:
        data: Any = json.load(handle)

    assert isinstance(data, dict), "ATT&CK matrix must contain a JSON object."

    return data


def test_mapping_and_matrix_rule_count_match() -> None:
    """Verify that mapping rule IDs match matrix rule IDs."""
    mapping = load_mapping()
    matrix = load_matrix()

    mapping_rules = mapping.get("rules", [])
    matrix_rules: set[str] = set()

    for technique in matrix.get("techniques", []):
        for rule in technique.get("rules", []):
            matrix_rules.add(rule["rule_id"])

    mapping_rule_ids = {
    rule["rule_id"]
    for rule in mapping_rules
    if isinstance(rule, dict)
    and rule.get("rule_id")
    and rule.get("techniques")
}

    assert matrix_rules == mapping_rule_ids


def test_mapping_and_matrix_techniques_match() -> None:
    """Verify that mapped techniques match matrix technique IDs."""
    mapping = load_mapping()
    matrix = load_matrix()

    mapping_techniques = {technique for rule in mapping.get("rules", []) for technique in rule.get("techniques", [])}

    matrix_techniques = {technique["technique_id"] for technique in matrix.get("techniques", [])}

    assert matrix_techniques == mapping_techniques


def test_matrix_rule_counts_are_correct() -> None:
    """Verify that matrix rule counts match the mapping definitions."""
    mapping = load_mapping()
    matrix = load_matrix()

    expected_counts: dict[str, int] = {}

    for rule in mapping.get("rules", []):
        for technique in rule.get("techniques", []):
            expected_counts[technique] = expected_counts.get(technique, 0) + 1

    for technique in matrix.get("techniques", []):
        technique_id = technique["technique_id"]

        assert technique["rule_count"] == expected_counts[technique_id]
