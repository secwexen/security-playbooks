"""Tests for the IOC JSON schema."""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_FILE = PROJECT_ROOT / "schemas" / "ioc.schema.json"


def load_schema() -> dict[str, Any]:
    """Load and validate the IOC JSON schema."""
    assert SCHEMA_FILE.exists(), f"Schema file not found: {SCHEMA_FILE}"

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema: dict[str, Any] = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def build_valid_ioc() -> dict[str, Any]:
    """Build a valid IOC test instance."""
    return {
        "id": "ioc-001",
        "type": "ipv4",
        "value": "192.0.2.10",
    }


def test_ioc_schema_exists() -> None:
    """Verify that the IOC schema file exists."""
    assert SCHEMA_FILE.exists()


def test_ioc_schema_is_valid() -> None:
    """Verify that the IOC schema is valid."""
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_ioc_instance_is_valid() -> None:
    """Verify that a minimal IOC instance passes validation."""
    schema = load_schema()
    instance = build_valid_ioc()

    Draft202012Validator(schema).validate(instance)


def test_ioc_rejects_invalid_type() -> None:
    """Verify that invalid IOC types are rejected."""
    schema = load_schema()
    instance = build_valid_ioc()

    instance["type"] = "invalid"

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_ioc_schema_rejects_unknown_property() -> None:
    """Verify that unknown IOC properties are rejected."""
    schema = load_schema()
    instance = build_valid_ioc()

    instance["__unexpected_property__"] = True

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)
