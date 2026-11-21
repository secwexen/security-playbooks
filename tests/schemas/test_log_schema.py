"""Unit tests for the log JSON schema."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_FILE = PROJECT_ROOT / "schemas" / "log_schema.json"


def load_schema() -> dict[str, Any]:
    """Load and validate the log JSON schema."""
    assert SCHEMA_FILE.exists(), f"Schema file not found: {SCHEMA_FILE}"

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema: dict[str, Any] = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def build_valid_log() -> dict[str, Any]:
    """Build a minimal valid log event for schema tests."""
    return {
        "event_type": "authentication",
        "timestamp": "2026-01-01T00:00:00Z",
        "source": {
            "type": "windows",
        },
    }


def test_log_schema_exists() -> None:
    """Verify that the log schema file exists."""
    assert SCHEMA_FILE.exists()


def test_log_schema_is_valid() -> None:
    """Verify that the log schema is a valid JSON Schema document."""
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_log_instance_is_valid() -> None:
    """Verify that a minimal log event passes schema validation."""
    schema = load_schema()
    instance = build_valid_log()

    Draft202012Validator(schema).validate(instance)


def test_log_schema_rejects_invalid_source_type() -> None:
    """Verify that an unsupported source type is rejected."""
    schema = load_schema()
    instance = build_valid_log()
    instance["source"]["type"] = "invalid"

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_log_schema_rejects_unknown_property() -> None:
    """Verify that unknown top-level properties are rejected."""
    schema = load_schema()
    instance = build_valid_log()

    instance["__unexpected_property__"] = True

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)
