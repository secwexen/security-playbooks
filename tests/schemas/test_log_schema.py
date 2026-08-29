import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_FILE = PROJECT_ROOT / "schemas" / "log_schema.json"


def load_schema():
    assert SCHEMA_FILE.exists()

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)

    Draft202012Validator.check_schema(schema)
    return schema


def build_minimal_instance(schema):
    instance = {}

    for field in schema.get("required", []):
        definition = schema.get("properties", {}).get(field, {})

        if definition.get("type") == "string":
            instance[field] = "test"

        elif definition.get("type") == "integer":
            instance[field] = 1

        elif definition.get("type") == "number":
            instance[field] = 1

        elif definition.get("type") == "boolean":
            instance[field] = True

        elif definition.get("type") == "array":
            instance[field] = []

        elif definition.get("type") == "object":
            instance[field] = {}

        else:
            instance[field] = "test"

    return instance


def test_log_schema_exists():
    assert SCHEMA_FILE.exists()


def test_log_schema_is_valid():
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_log_instance_is_valid():
    schema = load_schema()
    instance = build_minimal_instance(schema)

    Draft202012Validator(schema).validate(instance)


def test_log_schema_rejects_unknown_property():
    schema = load_schema()
    instance = build_minimal_instance(schema)

    if schema.get("additionalProperties") is False:
        instance["__unexpected_property__"] = True

        validator = Draft202012Validator(schema)

        try:
            validator.validate(instance)
        except ValidationError:
            return

        raise AssertionError(
            "Schema accepted an unexpected property."
        )
