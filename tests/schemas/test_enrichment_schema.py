import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_FILE = (
    PROJECT_ROOT
    / "schemas"
    / "enrichment.schema.json"
)


def load_schema():
    assert SCHEMA_FILE.exists()

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def build_valid_enrichment():
    return {
        "ioc_id": "ioc-001",
        "status": "success",
        "timestamp": "2026-01-01T00:00:00Z"
    }


def test_enrichment_schema_exists():
    assert SCHEMA_FILE.exists()


def test_enrichment_schema_is_valid():
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_enrichment_instance_is_valid():
    schema = load_schema()
    instance = build_valid_enrichment()

    Draft202012Validator(schema).validate(instance)


def test_enrichment_rejects_invalid_status():
    schema = load_schema()
    instance = build_valid_enrichment()
    instance["status"] = "invalid"

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_enrichment_schema_rejects_unknown_property():
    schema = load_schema()
    instance = build_valid_enrichment()

    instance["__unexpected_property__"] = True

    validator = Draft202012Validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)
