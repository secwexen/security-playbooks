import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_FILE = (
    PROJECT_ROOT
    / "schemas"
    / "alert_schema.json"
)


def load_schema():
    assert SCHEMA_FILE.exists()

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def build_valid_alert():
    return {
        "id": "alert-001",
        "rule_id": "rule-001",
        "rule_type": "sigma",
        "severity": "medium"
    }


def test_alert_schema_exists():
    assert SCHEMA_FILE.exists()


def test_alert_schema_is_valid():
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_alert_instance_is_valid():
    schema = load_schema()
    instance = build_valid_alert()

    Draft202012Validator(schema).validate(instance)


def test_alert_schema_rejects_invalid_rule_type():
    schema = load_schema()
    instance = build_valid_alert()
    instance["rule_type"] = "invalid"

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_alert_schema_rejects_unknown_property():
    schema = load_schema()
    instance = build_valid_alert()

    instance["__unexpected_property__"] = True

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)
