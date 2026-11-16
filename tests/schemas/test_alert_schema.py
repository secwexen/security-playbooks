"""Tests for the alert JSON schema."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_FILE = PROJECT_ROOT / "schemas" / "alert_schema.json"


def load_schema() -> dict[str, Any]:
    """Load and validate the alert JSON schema."""
    assert SCHEMA_FILE.exists()

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema: dict[str, Any] = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def build_valid_alert() -> dict[str, Any]:
    """Build a valid alert test instance."""
    return {
        "id": "alert-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "rule_id": "rule-001",
        "rule_type": "sigma",
        "severity": "medium",
        "status": "new",
    }


def test_alert_schema_exists():
    """Verify that the alert schema file exists."""
    assert SCHEMA_FILE.exists()


def test_alert_schema_is_valid():
    """Verify that the alert schema is valid."""
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_alert_instance_is_valid():
    """Verify that a minimal alert instance passes validation."""
    schema = load_schema()
    instance = build_valid_alert()

    Draft202012Validator(schema).validate(instance)


def test_alert_schema_rejects_invalid_rule_type():
    """Verify that invalid rule types are rejected."""
    schema = load_schema()
    instance = build_valid_alert()

    instance["rule_type"] = "invalid"

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_alert_schema_rejects_unknown_property():
    """Verify that unknown alert properties are rejected."""
    schema = load_schema()
    instance = build_valid_alert()

    instance["__unexpected_property__"] = True

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)
