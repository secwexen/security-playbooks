from __future__ import annotations

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
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email": "email",
    "hostname": "hostname",
    "cve": "cve",
    "user_agent": "user_agent",
    "registry_key": "registry_key",
    "mutex": "mutex",
    "other": "other",
    "windows": "windows",
    "sysmon": "sysmon",
    "linux": "linux",
    "syslog": "syslog",
    "network": "network",
    "suricata": "suricata",
    "application": "application",
    "cloud": "cloud",
    "edr": "edr",
}


def example_value(schema: dict[str, Any], field_name: str) -> Any:
    """Build a valid example value from a JSON Schema property."""
    if "enum" in schema:
        enum_values = schema["enum"]

        if not enum_values:
            return None

        return enum_values[0]

    if "const" in schema:
        return schema["const"]

    schema_type = schema.get("type")

    if schema_type == "string":
        if "format" == schema.get("format"):
            return "test"

        if schema.get("format") == "date-time":
            return "2026-01-01T00:00:00Z"

        if schema.get("format") == "date":
            return "2026-01-01"

        if schema.get("format") == "uri":
            return "https://example.com"

        if schema.get("pattern"):
            return _example_for_pattern(schema["pattern"])

        return f"test-{field_name}"

    if schema_type == "integer":
        return schema.get("minimum", 0)

    if schema_type == "number":
        return schema.get("minimum", 0)

    if schema_type == "boolean":
        return True

    if schema_type == "array":
        item_schema = schema.get("items")

        if not item_schema:
            return []

        return [example_value(item_schema, field_name)]

    if schema_type == "object":
        return build_valid_object(schema)

    return None


def _example_for_pattern(pattern: str) -> str:
    """Return a safe example for common JSON Schema patterns."""
    if "T\\d{4}" in pattern:
        return "T1059"

    if "TA\\d{4}" in pattern:
        return "TA0002"

    if "\\d+\\.\\d+\\.\\d+" in pattern:
        return "1.0.0"

    if "^[a-z0-9]+" in pattern:
        return "test-value"

    return "test"


def build_valid_object(schema: dict[str, Any]) -> dict[str, Any]:
    """Build an object containing all required fields."""
    properties = schema.get("properties", {})
    required = schema.get("required", [])

    result: dict[str, Any] = {}

    for field_name in required:
        field_schema = properties.get(field_name, {})

        result[field_name] = example_value(
            field_schema,
            field_name,
        )

    return result


def build_minimal_instance(
    schema: dict[str, Any],
) -> dict[str, Any]:
    """Build a minimally valid instance from a JSON Schema."""
    return build_valid_object(schema)
