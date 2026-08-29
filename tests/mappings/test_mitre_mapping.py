from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MAPPING_FILE = (
    PROJECT_ROOT
    / "detection-rules"
    / "mappings"
    / "mitre-mapping.yaml"
)


def load_mapping() -> dict:
    with MAPPING_FILE.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    assert isinstance(data, dict)
    return data


def test_mapping_file_exists():
    assert MAPPING_FILE.exists()


def test_rules_section_exists():
    data = load_mapping()

    assert "rules" in data
    assert isinstance(data["rules"], list)


def test_rule_ids_are_unique():
    data = load_mapping()

    rule_ids = [
        rule["rule_id"]
        for rule in data["rules"]
        if isinstance(rule, dict) and "rule_id" in rule
    ]

    assert len(rule_ids) == len(set(rule_ids))


def test_rules_have_required_fields():
    data = load_mapping()

    for rule in data["rules"]:
        assert isinstance(rule, dict)
        assert rule.get("rule_id")
        assert rule.get("rule_name")
        assert isinstance(rule.get("techniques"), list)
        assert isinstance(rule.get("source"), list)


def test_technique_ids_are_valid_format():
    data = load_mapping()

    for rule in data["rules"]:
        for technique_id in rule.get("techniques", []):
            assert isinstance(technique_id, str)
            assert technique_id.startswith("T")
            assert technique_id[1:].replace(".", "").isdigit()
