import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from tests.schemas.conftest import build_minimal_instance


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


def test_alert_schema_exists():
    assert SCHEMA_FILE.exists()


def test_alert_schema_is_valid():
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_minimal_alert_instance_is_valid():
    schema = load_schema()
    instance = build_minimal_instance(schema)

    Draft202012Validator(schema).validate(instance)


def test_alert_schema_rejects_unknown_property():
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
