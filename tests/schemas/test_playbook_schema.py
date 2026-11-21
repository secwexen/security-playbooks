"""Unit tests for the playbook JSON schema."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_FILE = PROJECT_ROOT / "schemas" / "playbook.schema.json"


def load_schema() -> dict[str, Any]:
    """Load and validate the playbook JSON schema."""
    assert SCHEMA_FILE.exists(), f"Schema file not found: {SCHEMA_FILE}"

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema: dict[str, Any] = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def build_valid_playbook() -> dict[str, Any]:
    """Build a minimal valid playbook for schema tests."""
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
                "expected_result": "Relevant evidence is identified.",
            }
        ],
    }


def test_playbook_schema_exists() -> None:
    """Verify that the playbook schema file exists."""
    assert SCHEMA_FILE.exists()


def test_playbook_schema_is_valid() -> None:
    """Verify that the playbook schema is a valid JSON Schema document."""
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_playbook_instance_is_valid() -> None:
    """Verify that a minimal playbook passes schema validation."""
    schema = load_schema()
    instance = build_valid_playbook()

    Draft202012Validator(schema).validate(instance)


def test_playbook_rejects_invalid_category() -> None:
    """Verify that an unsupported playbook category is rejected."""
    schema = load_schema()
    instance = build_valid_playbook()
    instance["category"] = "invalid"

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_playbook_schema_rejects_unknown_property() -> None:
    """Verify that unknown top-level properties are rejected."""
    schema = load_schema()
    instance = build_valid_playbook()

    instance["__unexpected_property__"] = True

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)
