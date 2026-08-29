import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_FILE = (
    PROJECT_ROOT
    / "schemas"
    / "incident.schema.json"
)


def load_schema():
    assert SCHEMA_FILE.exists()

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def build_valid_incident():
    return {
        "id": "incident-001",
        "title": "Suspicious PowerShell Activity",
        "severity": "medium",
        "status": "open",
        "created_at": "2026-01-01T00:00:00Z"
    }


def test_incident_schema_exists():
    assert SCHEMA_FILE.exists()


def test_incident_schema_is_valid():
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_incident_instance_is_valid():
    schema = load_schema()
    instance = build_valid_incident()

    Draft202012Validator(schema).validate(instance)


def test_incident_rejects_invalid_severity():
    schema = load_schema()
    instance = build_valid_incident()
    instance["severity"] = "invalid"

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_incident_schema_rejects_unknown_property():
    schema = load_schema()
    instance = build_valid_incident()

    instance["__unexpected_property__"] = True

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)
