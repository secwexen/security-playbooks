"""Shared pytest fixtures and schema validation helpers."""

from __future__ import annotations

from collections.abc import Callable

import re
from datetime import datetime, timezone
from typing import Any

# pylint: disable=missing-function-docstring

ENUM_DEFAULTS = {
    "sigma": "sigma",
    "suricata": "suricata",
    "yara": "yara",
    "custom": "custom",
    "success": "success",
    "partial": "partial",
    "not_found": "not_found",
    "failed": "failed",
    "informational": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "ipv4": "192.168.1.1",
    "ipv6": "2001:0db8:0000:0000:0000:0000:0000:0001",
    "domain": "example.com",
    "url": "https://example.com",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": ("e3b0c44298fc1c149afbf4c8996fb924" "27ae41e4649b934ca495991b7852b855"),
    "email": "test@example.com",
    "hostname": "example-host",
    "cve": "CVE-2024-1234",
    "user_agent": "Mozilla/5.0",
    "registry_key": r"HKLM\Software\Example",
    "mutex": r"Global\ExampleMutex",
    "other": "other",
    "windows": "windows",
    "sysmon": "sysmon",
    "linux": "linux",
    "syslog": "syslog",
    "network": "network",
    "application": "application",
    "cloud": "cloud",
    "edr": "edr",
}


def _resolve_schema(
    schema: dict[str, Any],
    root_schema: dict[str, Any],
) -> dict[str, Any]:
    """Resolve a local schema reference when possible."""
    if "$ref" not in schema:
        return schema

    resolved = resolve_ref(schema["$ref"], root_schema)
    return resolved if resolved is not None else schema


def _example_from_composition(
    schema: dict[str, Any],
    field_name: str,
    root_schema: dict[str, Any],
) -> tuple[bool, Any]:
    """Generate an example from allOf, oneOf, or anyOf."""
    if "allOf" in schema:
        return True, example_from_all_of(
            schema["allOf"],
            field_name,
            root_schema,
        )

    union_key = "oneOf" if "oneOf" in schema else "anyOf"

    if union_key in schema:
        return True, example_from_union(
            schema[union_key],
            field_name,
            root_schema,
        )

    return False, None


def _example_from_type(
    schema: dict[str, Any],
    field_name: str,
    root_schema: dict[str, Any],
) -> Any:
    """Generate an example based on the resolved schema type."""
    schema_type = schema.get("type")

    if isinstance(schema_type, list):
        non_null_types = [item for item in schema_type if item != "null"]

        if not non_null_types:
            return None

        schema_copy = dict(schema)
        schema_copy["type"] = non_null_types[0]

        return example_value(
            schema_copy,
            field_name,
            root_schema,
        )

    type_generators: dict[str, Callable[[], Any]] = {
        "string": lambda: example_string(schema, field_name),
        "integer": lambda: example_integer(schema),
        "number": lambda: example_number(schema),
        "boolean": lambda: True,
        "null": lambda: None,
        "array": lambda: example_array(
            schema,
            field_name,
            root_schema,
        ),
        "object": lambda: build_valid_object(
            schema,
            root_schema=root_schema,
        ),
    }

    if isinstance(schema_type, str):
        generator = type_generators.get(schema_type)

        if generator is not None:
            return generator()

    if "properties" in schema:
        return build_valid_object(
            schema,
            root_schema=root_schema,
        )

    return None


def example_value(
    schema: dict[str, Any],
    field_name: str = "value",
    root_schema: dict[str, Any] | None = None,
) -> Any:
    """Generate an example value compatible with a JSON Schema."""
    if root_schema is None:
        root_schema = schema

    schema = _resolve_schema(schema, root_schema)

    if "const" in schema:
        return schema["const"]

    examples = schema.get("examples")
    if examples:
        return examples[0]

    if "default" in schema:
        return schema["default"]

    if "enum" in schema:
        return example_from_enum(schema["enum"])

    handled, value = _example_from_composition(
        schema,
        field_name,
        root_schema,
    )

    if handled:
        return value

    return _example_from_type(
        schema,
        field_name,
        root_schema,
    )


def example_from_enum(enum_values: list[Any]) -> Any:
    """Select a representative value from an enum."""
    if not enum_values:
        return None

    for value in enum_values:
        if isinstance(value, str) and value in ENUM_DEFAULTS:
            return ENUM_DEFAULTS[value]

    return enum_values[0]


def example_from_all_of(
    schemas: list[dict[str, Any]],
    field_name: str,
    root_schema: dict[str, Any],
) -> Any:
    """Generate an example by combining allOf object schemas."""
    merged: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    for schema in schemas:
        resolved = _resolve_schema(schema, root_schema)

        properties = resolved.get("properties", {})
        merged["properties"].update(properties)

        for required_field in resolved.get("required", []):
            if required_field not in merged["required"]:
                merged["required"].append(required_field)

    if merged["properties"]:
        return build_valid_object(
            merged,
            root_schema=root_schema,
        )

    for schema in schemas:
        value = example_value(
            schema,
            field_name,
            root_schema,
        )

        if value is not None:
            return value

    return None


def example_from_union(
    schemas: list[dict[str, Any]],
    field_name: str,
    root_schema: dict[str, Any],
) -> Any:
    """Generate an example from oneOf or anyOf alternatives."""
    for schema in schemas:
        try:
            value = example_value(
                schema,
                field_name,
                root_schema,
            )

            if value is not None:
                return value

        except (ValueError, TypeError):
            continue

    return None


def example_string(
    schema: dict[str, Any],
    field_name: str,
) -> str:
    """Generate a string satisfying common schema constraints."""
    now = datetime.now(timezone.utc)

    format_examples = {
        "date-time": now.isoformat(),
        "date": now.date().isoformat(),
        "time": "12:00:00Z",
        "uri": "https://example.com",
        "uri-reference": "/example",
        "email": "test@example.com",
        "hostname": "example.com",
        "ipv4": "192.168.1.1",
        "ipv6": "2001:0db8:0000:0000:0000:0000:0000:0001",
        "uuid": "123e4567-e89b-12d3-a456-426614174000",
    }

    fmt = schema.get("format")
    pattern = schema.get("pattern")

    if fmt in format_examples:
        value = format_examples[fmt]
    elif pattern:
        value = _example_for_pattern(pattern)
    else:
        value = f"test-{field_name}"

    min_length = schema.get("minLength", 0)
    max_length = schema.get("maxLength")

    if len(value) < min_length:
        value += "x" * (min_length - len(value))

    if max_length is not None:
        value = value[:max_length]

    if pattern and not _matches_pattern(value, pattern):
        value = _example_for_pattern(pattern)

        if len(value) < min_length:
            value += "x" * (min_length - len(value))

        if max_length is not None:
            value = value[:max_length]

    return value


def example_integer(
    schema: dict[str, Any],
) -> int:
    """Generate an integer satisfying common numeric constraints."""
    if "minimum" in schema:
        value = int(schema["minimum"])
    elif "exclusiveMinimum" in schema:
        value = int(schema["exclusiveMinimum"]) + 1
    else:
        value = 0

    if "maximum" in schema:
        value = min(value, int(schema["maximum"]))

    if "exclusiveMaximum" in schema:
        value = min(
            value,
            int(schema["exclusiveMaximum"]) - 1,
        )

    multiple_of = schema.get("multipleOf")

    if multiple_of:
        multiple_of = int(multiple_of)

        if multiple_of:
            value = ((value + multiple_of - 1) // multiple_of) * multiple_of

    return value


def example_number(
    schema: dict[str, Any],
) -> float | int:
    """Generate a numeric example satisfying common constraints."""
    if "minimum" in schema:
        value = schema["minimum"]
    elif "exclusiveMinimum" in schema:
        value = schema["exclusiveMinimum"] + 0.1
    else:
        value = 0

    if "maximum" in schema:
        value = min(value, schema["maximum"])

    if "exclusiveMaximum" in schema:
        value = min(
            value,
            schema["exclusiveMaximum"] - 0.1,
        )

    multiple_of = schema.get("multipleOf")

    if multiple_of:
        multiplier = int(value / multiple_of)
        value = multiplier * multiple_of

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("Numeric schema constraints must contain integer or float values.")

    if isinstance(value, float):
        return value

    return int(value)


def _example_array_items(
    schema: dict[str, Any],
    field_name: str,
    root_schema: dict[str, Any],
) -> list[Any]:
    """Generate initial array items from items or prefixItems."""
    if "prefixItems" in schema:
        return [example_value(item_schema, field_name, root_schema) for item_schema in schema["prefixItems"]]

    item_schema = schema.get("items")

    if item_schema:
        return [
            example_value(
                item_schema,
                field_name,
                root_schema,
            )
        ]

    return []


def example_array(
    schema: dict[str, Any],
    field_name: str,
    root_schema: dict[str, Any],
) -> list[Any]:
    """Generate an array satisfying common JSON Schema constraints."""
    result = _example_array_items(
        schema,
        field_name,
        root_schema,
    )

    min_items = schema.get("minItems", 0)
    max_items = schema.get("maxItems")
    item_schema = schema.get("items")

    while len(result) < min_items:
        if item_schema:
            result.append(
                example_value(
                    item_schema,
                    field_name,
                    root_schema,
                )
            )
        else:
            result.append(None)

    if max_items is not None:
        result = result[:max_items]

    if "contains" in schema and not result:
        result.append(
            example_value(
                schema["contains"],
                field_name,
                root_schema,
            )
        )

    return result


def _example_for_pattern(pattern: str) -> str:
    """Return a representative string for common regular expressions."""
    pattern_examples = [
        (r"TA\d{4}", "TA0002"),
        (r"T\d{4}", "T1059"),
        ("CVE", "CVE-2024-1234"),
        (r"\d+\.\d+\.\d+", "1.0.0"),
        ("25[0-5]", "192.168.1.1"),
        (r"\d{1,3}\.", "192.168.1.1"),
        ("[0-9a-fA-F]{8}", "123e4567-e89b-12d3-a456-426614174000"),
        (r"^\[a-z0-9\]", "testvalue"),
        (r"^\[A-Z0-9\]", "TESTVALUE"),
    ]

    for expression, example in pattern_examples:
        if expression in pattern:
            return example

    return "test"


def _matches_pattern(
    value: str,
    pattern: str,
) -> bool:
    """Check whether a value matches a regular expression."""
    try:
        return re.search(pattern, value) is not None
    except re.error:
        return True


def _decode_json_pointer_part(part: str) -> str:
    """Decode an escaped JSON Pointer path component."""
    return part.replace("~1", "/").replace("~0", "~")


def resolve_ref(
    ref: str,
    root_schema: dict[str, Any],
) -> dict[str, Any] | None:
    """Resolve a local JSON Schema reference."""
    if not ref.startswith("#/"):
        return None

    current: Any = root_schema

    for part in ref[2:].split("/"):
        if not isinstance(current, dict):
            return None

        current = current.get(_decode_json_pointer_part(part))

        if current is None:
            return None

    return current if isinstance(current, dict) else None


def _resolve_object_schema(
    schema: dict[str, Any],
    root_schema: dict[str, Any],
) -> dict[str, Any]:
    """Resolve a referenced object schema."""
    return _resolve_schema(schema, root_schema)


def _add_required_properties(
    result: dict[str, Any],
    properties: dict[str, Any],
    required: list[str],
    root_schema: dict[str, Any],
) -> None:
    """Populate required object properties with generated examples."""
    for field_name in required:
        field_schema = properties.get(field_name, {})

        result[field_name] = example_value(
            field_schema,
            field_name,
            root_schema,
        )


def _add_dependent_properties(
    result: dict[str, Any],
    properties: dict[str, Any],
    dependent_required: dict[str, Any],
    root_schema: dict[str, Any],
) -> None:
    """Populate properties required by dependentRequired constraints."""
    for field_name, dependencies in dependent_required.items():
        if field_name not in result:
            continue

        for dependency in dependencies:
            if dependency in result:
                continue

            dependency_schema = properties.get(dependency, {})

            result[dependency] = example_value(
                dependency_schema,
                dependency,
                root_schema,
            )


def build_valid_object(
    schema: dict[str, Any],
    root_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an object containing required and dependent properties."""
    if root_schema is None:
        root_schema = schema

    schema = _resolve_object_schema(schema, root_schema)

    properties = schema.get("properties", {})
    required = schema.get("required", [])
    dependent_required = schema.get("dependentRequired", {})

    result: dict[str, Any] = {}

    _add_required_properties(
        result,
        properties,
        required,
        root_schema,
    )

    _add_dependent_properties(
        result,
        properties,
        dependent_required,
        root_schema,
    )

    return result


def build_minimal_instance(
    schema: dict[str, Any],
) -> dict[str, Any]:
    """Build a minimal example instance from a JSON Schema."""
    return build_valid_object(
        schema,
        root_schema=schema,
    )
