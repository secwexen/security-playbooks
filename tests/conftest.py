from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


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
    "ipv6": "2001:db8::1",
    "domain": "example.com",
    "url": "https://example.com",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    ),
    "email": "test@example.com",
    "hostname": "example-host",
    "cve": "CVE-2024-1234",
    "user_agent": "Mozilla/5.0",
    "registry_key": r"HKLM\Software\Example",
    "mutex": "Global\\ExampleMutex",
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


def example_value(
    schema: dict[str, Any],
    field_name: str = "value",
    root_schema: dict[str, Any] | None = None,
) -> Any:
    if root_schema is None:
        root_schema = schema

    if "$ref" in schema:
        resolved = resolve_ref(schema["$ref"], root_schema)

        if resolved is not None:
            return example_value(
                resolved,
                field_name,
                root_schema,
            )

    if "const" in schema:
        return schema["const"]

    examples = schema.get("examples")

    if examples:
        return examples[0]

    if "default" in schema:
        return schema["default"]

    if "enum" in schema:
        return example_from_enum(schema["enum"])

    if "allOf" in schema:
        return example_from_all_of(
            schema["allOf"],
            field_name,
            root_schema,
        )

    if "oneOf" in schema:
        return example_from_union(
            schema["oneOf"],
            field_name,
            root_schema,
        )

    if "anyOf" in schema:
        return example_from_union(
            schema["anyOf"],
            field_name,
            root_schema,
        )

    schema_type = schema.get("type")

    if isinstance(schema_type, list):
        non_null_types = [
            item for item in schema_type
            if item != "null"
        ]

        if not non_null_types:
            return None

        schema_copy = dict(schema)
        schema_copy["type"] = non_null_types[0]

        return example_value(
            schema_copy,
            field_name,
            root_schema,
        )

    if schema_type == "string":
        return example_string(schema, field_name)

    if schema_type == "integer":
        return example_integer(schema)

    if schema_type == "number":
        return example_number(schema)

    if schema_type == "boolean":
        return True

    if schema_type == "null":
        return None

    if schema_type == "array":
        return example_array(
            schema,
            field_name,
            root_schema,
        )

    if schema_type == "object" or "properties" in schema:
        return build_valid_object(
            schema,
            root_schema=root_schema,
        )

    return None


def example_from_enum(enum_values: list[Any]) -> Any:
    if not enum_values:
        return None

    for value in enum_values:
        if value in ENUM_DEFAULTS:
            return ENUM_DEFAULTS[value]

    return enum_values[0]


def example_from_all_of(
    schemas: list[dict[str, Any]],
    field_name: str,
    root_schema: dict[str, Any],
) -> Any:
    merged: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    for schema in schemas:
        resolved = schema

        if "$ref" in schema:
            resolved = resolve_ref(
                schema["$ref"],
                root_schema,
            ) or schema

        if resolved.get("properties"):
            merged["properties"].update(
                resolved["properties"]
            )

        for required_field in resolved.get(
            "required",
            [],
        ):
            if required_field not in merged["required"]:
                merged["required"].append(
                    required_field
                )

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
    fmt = schema.get("format")

    format_examples = {
        "date-time": datetime.now(
            timezone.utc
        ).isoformat(),
        "date": datetime.now(
            timezone.utc
        ).date().isoformat(),
        "time": "12:00:00Z",
        "uri": "https://example.com",
        "uri-reference": "/example",
        "email": "test@example.com",
        "hostname": "example.com",
        "ipv4": "192.168.1.1",
        "ipv6": "2001:db8::1",
        "uuid": "123e4567-e89b-12d3-a456-426614174000",
    }

    if fmt in format_examples:
        value = format_examples[fmt]
    elif schema.get("pattern"):
        value = _example_for_pattern(schema["pattern"])
    else:
        value = f"test-{field_name}"

    min_length = schema.get("minLength", 0)

    if len(value) < min_length:
        value += "x" * (min_length - len(value))

    max_length = schema.get("maxLength")

    if max_length is not None:
        if max_length == 0:
            return ""

        value = value[:max_length]

        if len(value) < min_length:
            value += "x" * (min_length - len(value))

    pattern = schema.get("pattern")

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
    if "minimum" in schema:
        value = int(schema["minimum"])
    elif "exclusiveMinimum" in schema:
        value = int(schema["exclusiveMinimum"]) + 1
    else:
        value = 0

    if "maximum" in schema:
        value = min(
            value,
            int(schema["maximum"]),
        )

    if "exclusiveMaximum" in schema:
        value = min(
            value,
            int(schema["exclusiveMaximum"]) - 1,
        )

    multiple_of = schema.get("multipleOf")

    if multiple_of:
        multiple_of = int(multiple_of)

        if multiple_of:
            value = (
                (value + multiple_of - 1)
                // multiple_of
            ) * multiple_of

    return value


def example_number(
    schema: dict[str, Any],
) -> float | int:
    if "minimum" in schema:
        value = schema["minimum"]
    elif "exclusiveMinimum" in schema:
        value = schema["exclusiveMinimum"] + 0.1
    else:
        value = 0

    if "maximum" in schema:
        value = min(
            value,
            schema["maximum"],
        )

    if "exclusiveMaximum" in schema:
        value = min(
            value,
            schema["exclusiveMaximum"] - 0.1,
        )

    multiple_of = schema.get("multipleOf")

    if multiple_of:
        multiplier = int(value / multiple_of)
        value = multiplier * multiple_of

    return value


def example_array(
    schema: dict[str, Any],
    field_name: str,
    root_schema: dict[str, Any],
) -> list[Any]:
    min_items = schema.get("minItems", 0)
    max_items = schema.get("maxItems")

    item_schema = schema.get("items")

    if "prefixItems" in schema:
        result = [
            example_value(
                item_schema,
                field_name,
                root_schema,
            )
            for item_schema in schema["prefixItems"]
        ]
    elif item_schema:
        result = [
            example_value(
                item_schema,
                field_name,
                root_schema,
            )
        ]
    else:
        result = []

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
    if r"TA\d{4}" in pattern:
        return "TA0002"

    if r"T\d{4}" in pattern:
        return "T1059"

    if "CVE" in pattern:
        return "CVE-2024-1234"

    if r"\d+\.\d+\.\d+" in pattern:
        return "1.0.0"

    if (
        "25[0-5]" in pattern
        or r"\d{1,3}\." in pattern
    ):
        return "192.168.1.1"

    if "[0-9a-fA-F]{8}" in pattern:
        return "123e4567-e89b-12d3-a456-426614174000"

    if re.search(
        r"\^\[a-z0-9\]",
        pattern,
    ):
        return "testvalue"

    if re.search(
        r"\^\[A-Z0-9\]",
        pattern,
    ):
        return "TESTVALUE"

    return "test"


def _matches_pattern(
    value: str,
    pattern: str,
) -> bool:
    try:
        return re.search(
            pattern,
            value,
        ) is not None
    except re.error:
        return True


def resolve_ref(
    ref: str,
    root_schema: dict[str, Any],
) -> dict[str, Any] | None:
    if not ref.startswith("#/"):
        return None

    current: Any = root_schema

    for part in ref[2:].split("/"):
        part = (
            part
            .replace("~1", "/")
            .replace("~0", "~")
        )

        if not isinstance(current, dict):
            return None

        current = current.get(part)

        if current is None:
            return None

    if isinstance(current, dict):
        return current

    return None


def build_valid_object(
    schema: dict[str, Any],
    root_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if root_schema is None:
        root_schema = schema

    if "$ref" in schema:
        resolved = resolve_ref(
            schema["$ref"],
            root_schema,
        )

        if resolved is not None:
            schema = resolved

    properties = schema.get(
        "properties",
        {},
    )

    required = schema.get(
        "required",
        [],
    )

    result: dict[str, Any] = {}

    for field_name in required:
        field_schema = properties.get(
            field_name,
            {},
        )

        result[field_name] = example_value(
            field_schema,
            field_name,
            root_schema,
        )

    dependent_required = schema.get(
        "dependentRequired",
        {},
    )

    for field_name, dependencies in dependent_required.items():
        if field_name in result:
            for dependency in dependencies:
                if dependency not in result:
                    dependency_schema = properties.get(
                        dependency,
                        {},
                    )

                    result[dependency] = example_value(
                        dependency_schema,
                        dependency,
                        root_schema,
                    )

    return result


def build_minimal_instance(
    schema: dict[str, Any],
) -> dict[str, Any]:
    return build_valid_object(
        schema,
        root_schema=schema,
    )
