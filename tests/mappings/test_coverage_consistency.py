import json
from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MAPPING_FILE = (
    PROJECT_ROOT
    / "detection-rules"
    / "mappings"
    / "mitre-mapping.yaml"
)

MATRIX_FILE = (
    PROJECT_ROOT
    / "reports"
    / "attack-matrix.json"
)


def load_mapping() -> dict:
    with MAPPING_FILE.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    assert isinstance(data, dict)
    return data


def load_matrix() -> dict:
    assert MATRIX_FILE.exists()

    with MATRIX_FILE.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    assert isinstance(data, dict)
    return data


def test_mapping_and_matrix_rule_count_match():
    mapping = load_mapping()
    matrix = load_matrix()

    mapping_rules = mapping.get("rules", [])
    matrix_rules = set()

    for technique in matrix.get("techniques", []):
        for rule in technique.get("rules", []):
            matrix_rules.add(rule["rule_id"])

    mapping_rule_ids = {
        rule["rule_id"]
        for rule in mapping_rules
        if isinstance(rule, dict) and rule.get("rule_id")
    }

    assert matrix_rules == mapping_rule_ids


def test_mapping_and_matrix_techniques_match():
    mapping = load_mapping()
    matrix = load_matrix()

    mapping_techniques = {
        technique
        for rule in mapping.get("rules", [])
        for technique in rule.get("techniques", [])
    }

    matrix_techniques = {
        technique["technique_id"]
        for technique in matrix.get("techniques", [])
    }

    assert matrix_techniques == mapping_techniques


def test_matrix_rule_counts_are_correct():
    mapping = load_mapping()
    matrix = load_matrix()

    expected_counts = {}

    for rule in mapping.get("rules", []):
        for technique in rule.get("techniques", []):
            expected_counts[technique] = (
                expected_counts.get(technique, 0) + 1
            )

    for technique in matrix.get("techniques", []):
        technique_id = technique["technique_id"]

        assert technique["rule_count"] == expected_counts[technique_id]
