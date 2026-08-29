import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_FILE = (
    PROJECT_ROOT
    / "schemas"
    / "detection_rule.schema.json"
)


def load_schema():
    assert SCHEMA_FILE.exists()

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def build_valid_detection_rule():
    return {
        "id": "rule-001",
        "name": "Suspicious PowerShell Execution",
        "type": "sigma",
        "description": "Detects suspicious PowerShell execution.",
        "author": "Secwexen",
        "created_at": "2026-01-01T00:00:00Z"
    }


def test_detection_rule_schema_exists():
    assert SCHEMA_FILE.exists()


def test_detection_rule_schema_is_valid():
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_detection_rule_is_valid():
    schema = load_schema()
    instance = build_valid_detection_rule()

    Draft202012Validator(schema).validate(instance)


def test_detection_rule_rejects_invalid_type():
    schema = load_schema()
    instance = build_valid_detection_rule()
    instance["type"] = "invalid"

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_detection_rule_schema_rejects_unknown_property():
    schema = load_schema()
    instance = build_valid_detection_rule()

    instance["__unexpected_property__"] = True

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)
