"""Tests for shared schema validation helpers."""

# pylint: disable=missing-function-docstring

import importlib.util
from pathlib import Path

import pytest


# Load the existing conftest.py helper module.
CONFTEST_PATH = Path(__file__).resolve().parents[1] / "conftest.py"

SPEC = importlib.util.spec_from_file_location(
    "project_conftest_helpers",
    CONFTEST_PATH,
)

assert SPEC is not None
assert SPEC.loader is not None

conftest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(conftest)


def test_example_value_constants():
    assert conftest.example_value({"const": "test"}) == "test"
    assert conftest.example_value({"examples": ["one"]}) == "one"
    assert conftest.example_value({"default": "value"}) == "value"


def test_example_value_types():
    assert conftest.example_value(
        {"type": "string"}, "name"
    ) == "test-name"

    assert conftest.example_value({"type": "integer"}) == 0
    assert conftest.example_value({"type": "number"}) == 0
    assert conftest.example_value({"type": "boolean"}) is True
    assert conftest.example_value({"type": "null"}) is None


def test_example_value_enum():
    assert conftest.example_value(
        {"enum": ["low", "high"]}
    ) == "low"

    assert conftest.example_value(
        {"enum": ["unknown", "unmapped"]}
    ) == "unknown"

    assert conftest.example_from_enum([]) is None


def test_example_value_references():
    schema = {
        "definitions": {
            "name": {"type": "string", "default": "admin"}
        }
    }

    assert conftest.example_value(
        {"$ref": "#/definitions/name"},
        root_schema=schema,
    ) == "admin"


def test_example_value_union():
    schema = {
        "oneOf": [
            {"type": "string", "default": "first"},
            {"type": "integer"},
        ]
    }

    assert conftest.example_value(schema) == "first"

    schema = {
        "anyOf": [
            {"type": "string", "default": "second"},
        ]
    }

    assert conftest.example_value(schema) == "second"


def test_example_value_nullable_types():
    assert conftest.example_value(
        {"type": ["null"]}
    ) is None

    assert conftest.example_value(
        {"type": ["null", "string"]}
    ) == "test-value"


def test_example_from_all_of():
    schema = [
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "required": ["name"],
        },
        {
            "type": "object",
            "properties": {
                "age": {"type": "integer"}
            },
            "required": ["age"],
        },
    ]

    result = conftest.example_from_all_of(
        schema,
        "example",
        {},
    )

    assert "name" in result
    assert "age" in result


def test_example_from_all_of_scalar():
    assert conftest.example_from_all_of(
        [{"const": "test"}],
        "value",
        {},
    ) == "test"


def test_example_from_union():
    assert conftest.example_from_union(
        [{"type": "string", "default": "valid"}],
        "value",
        {},
    ) == "valid"


def test_example_string_formats():
    assert conftest.example_string(
        {"format": "email"},
        "email",
    ) == "test@example.com"

    assert conftest.example_string(
        {"format": "hostname"},
        "host",
    ) == "example.com"


def test_example_string_length():
    result = conftest.example_string(
        {
            "type": "string",
            "minLength": 10,
            "maxLength": 15,
        },
        "name",
    )

    assert 10 <= len(result) <= 15


def test_example_string_pattern_technique_id():
    result = conftest.example_string(
        {"pattern": r"^T\d{4}$"},
        "technique",
    )

    assert result == "T1059"


def test_example_integer():
    assert conftest.example_integer(
        {"minimum": 10}
    ) == 10

    assert conftest.example_integer(
        {"minimum": 10, "maximum": 20}
    ) == 10

    assert conftest.example_integer(
        {"exclusiveMinimum": 10}
    ) == 11


def test_example_number():
    assert conftest.example_number(
        {"minimum": 5}
    ) == 5

    assert conftest.example_number(
        {"exclusiveMinimum": 5}
    ) == pytest.approx(5.1)


def test_example_array():
    result = conftest.example_array(
        {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 2,
        },
        "items",
        {},
    )

    assert len(result) == 2


def test_example_array_prefix_items():
    result = conftest.example_array(
        {
            "type": "array",
            "prefixItems": [
                {"type": "string"},
                {"type": "integer"},
            ],
        },
        "items",
        {},
    )

    assert len(result) == 2


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (r"TA\d{4}", "TA0002"),
        (r"T\d{4}", "T1059"),
        ("CVE", "CVE-2024-1234"),
        (r"\d+\.\d+\.\d+", "1.0.0"),
        ("25[0-5]", "192.168.1.1"),
    ],
)
def test_example_string_pattern(pattern, expected):
    result = conftest.example_string(
        {"type": "string", "pattern": pattern},
        "value",
    )

    assert result == expected


def test_example_string_valid_pattern():
    result = conftest.example_string(
        {"type": "string", "pattern": r"^test$"},
        "value",
    )

    assert result == "test"


def test_example_string_invalid_pattern():
    result = conftest.example_string(
        {"type": "string", "pattern": "["},
        "value",
    )

    assert result == "test"


def test_resolve_ref():
    schema = {
        "definitions": {
            "example": {"type": "string"}
        }
    }

    assert conftest.resolve_ref(
        "#/definitions/example",
        schema,
    ) == {"type": "string"}


def test_resolve_ref_invalid():
    assert conftest.resolve_ref(
        "https://example.com/schema",
        {},
    ) is None

    assert conftest.resolve_ref(
        "#/missing",
        {},
    ) is None


def test_build_valid_object():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
        },
        "required": ["name", "age"],
    }

    result = conftest.build_valid_object(schema)

    assert "name" in result
    assert "age" in result


def test_build_valid_object_dependent_required():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "email": {"type": "string"},
        },
        "required": ["name"],
        "dependentRequired": {
            "name": ["email"]
        },
    }

    result = conftest.build_valid_object(schema)

    assert "name" in result
    assert "email" in result


def test_build_minimal_instance():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
        },
        "required": ["name"],
    }

    result = conftest.build_minimal_instance(schema)

    assert "name" in result
