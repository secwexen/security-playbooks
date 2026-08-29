import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_FILE = (
    PROJECT_ROOT
    / "schemas"
    / "playbook.schema.json"
)


def load_schema():
    assert SCHEMA_FILE.exists()

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def build_valid_playbook():
    return {
        "id": "playbook-001",
        "name": "Security Investigation Playbook",
        "category": "custom",
        "status": "draft",
        "description": "A defensive security investigation playbook.",
        "steps": [
            {
                "id": "step-001",
                "order": 1,
                "name": "Initial Investigation",
                "action": "investigate",
                "description": "Review the alert and associated telemetry.",
                "expected_result": "Relevant evidence is identified."
            }
        ]
    }


def test_playbook_schema_exists():
    assert SCHEMA_FILE.exists()


def test_playbook_schema_is_valid():
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_playbook_instance_is_valid():
    schema = load_schema()
    instance = build_valid_playbook()

    Draft202012Validator(schema).validate(instance)


def test_playbook_rejects_invalid_category():
    schema = load_schema()
    instance = build_valid_playbook()
    instance["category"] = "invalid"

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_playbook_schema_rejects_unknown_property():
    schema = load_schema()
    instance = build_valid_playbook()

    instance["__unexpected_property__"] = True

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)
