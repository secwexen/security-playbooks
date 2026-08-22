from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from jsonschema import ValidationError, validate

from tools.utils.logger import get_logger


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RULES_DIR = PROJECT_ROOT / "detection-rules" / "sigma"
SCHEMA_PATH = PROJECT_ROOT / "schemas" / "detection_rule.schema.json"

logger = get_logger(__name__)


def load_sigma_rule(path: Path) -> dict[str, Any]:
    """Load a Sigma YAML rule."""
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid Sigma YAML structure: {path}")

    return data


def load_schema(path: Path) -> dict[str, Any]:
    """Load the normalized detection rule JSON schema."""
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid JSON schema: {path}")

    return data


def parse_datetime(value: Any) -> str:
    """
    Convert a Sigma date value into ISO 8601 date-time.

    Sigma rules may contain YYYY-MM-DD. The normalized schema requires date-time.
    """
    if not value:
        return datetime.now(timezone.utc).isoformat()

    value = str(value)

    try:
        if len(value) == 10:
            parsed = datetime.strptime(value, "%Y-%m-%d")
            parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.isoformat()

        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.isoformat()

    except ValueError:
        logger.warning(
            "Invalid date '%s'. Using current UTC time.",
            value,
        )
        return datetime.now(timezone.utc).isoformat()


def normalize_status(status: Any) -> str:
    """
    Normalize Sigma status into the project's detection status model.
    """
    if not status:
        return "testing"

    value = str(status).lower().strip()

    mapping = {
        "experimental": "experimental",
        "test": "testing",
        "testing": "testing",
        "stable": "stable",
        "production": "stable",
        "deprecated": "deprecated",
        "unsupported": "deprecated",
    }

    return mapping.get(value, "testing")


def normalize_severity(level: Any) -> str:
    """
    Normalize Sigma levels into the project's severity model.
    """
    if not level:
        return "informational"

    value = str(level).lower().strip()

    allowed = {
        "informational",
        "low",
        "medium",
        "high",
        "critical",
    }

    if value in allowed:
        return value

    return "informational"


def extract_mitre_attack(tags: list[str]) -> list[str]:
    """
    Extract MITRE ATT&CK technique IDs from Sigma tags.
    """
    mitre_attack: set[str] = set()

    for tag in tags:
        value = str(tag).lower().strip()

        if value.startswith("attack.t"):
            technique = value.replace("attack.", "").upper()

            if technique.startswith("T"):
                mitre_attack.add(technique)

    return sorted(mitre_attack)


def normalize_logsource(logsource: Any) -> list[dict[str, str]]:
    """
    Normalize Sigma logsource into the project's log_sources structure.
    """
    if not isinstance(logsource, dict):
        return []

    normalized: dict[str, str] = {}

    for field in ("category", "product", "service"):
        value = logsource.get(field)

        if value is not None:
            normalized[field] = str(value)

    if not normalized:
        return []

    return [normalized]


def normalize_sigma_rule(
    sigma_rule: dict[str, Any],
    source_path: Path,
) -> dict[str, Any]:
    """
    Convert a Sigma rule into the project's normalized detection rule.
    """

    now = datetime.now(timezone.utc).isoformat()

    rule_id = str(
        sigma_rule.get("id")
        or source_path.stem
    )

    name = str(
        sigma_rule.get("title")
        or source_path.stem
    )

    description = str(
        sigma_rule.get("description")
        or f"Normalized Sigma detection rule: {name}"
    )

    author = str(
        sigma_rule.get("author")
        or "Secwexen"
    )

    tags = sigma_rule.get("tags") or []

    if not isinstance(tags, list):
        tags = [str(tags)]

    tags = [str(tag) for tag in tags]

    created_at = parse_datetime(
        sigma_rule.get("date")
    )

    updated_at = parse_datetime(
        sigma_rule.get("modified")
        or sigma_rule.get("modified_date")
        or sigma_rule.get("date")
    )

    normalized_rule: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "type": "sigma",
        "version": "1.0.0",
        "status": normalize_status(
            sigma_rule.get("status")
        ),
        "severity": normalize_severity(
            sigma_rule.get("level")
        ),
        "description": description,
        "author": author,
        "tags": sorted(set(tags)),
        "mitre_attack": extract_mitre_attack(tags),
        "log_sources": normalize_logsource(
            sigma_rule.get("logsource")
        ),
        "detection_logic": sigma_rule.get("detection") or {},
        "false_positives": [
            str(value)
            for value in (sigma_rule.get("falsepositives") or [])
        ],
        "created_at": created_at,
        "updated_at": updated_at,
    }

    references = sigma_rule.get("references")

    if isinstance(references, list):
        normalized_rule["references"] = [
            str(value) for value in references
        ]

    if normalized_rule["mitre_attack"]:
        normalized_rule["references_attack"] = [
            f"https://attack.mitre.org/techniques/{technique}/"
            for technique in normalized_rule["mitre_attack"]
        ]

    return normalized_rule


def validate_rule(
    rule: dict[str, Any],
    schema: dict[str, Any],
) -> bool:
    """Validate normalized detection rule against JSON Schema."""
    try:
        validate(
            instance=rule,
            schema=schema,
        )

        return True

    except ValidationError as exc:
        logger.error(
            "Normalized rule validation failed: %s",
            exc.message,
        )

        return False


def load_and_normalize_rule(
    path: Path,
    schema: dict[str, Any],
) -> dict[str, Any] | None:

    try:
        sigma_rule = load_sigma_rule(path)

        normalized_rule = normalize_sigma_rule(
            sigma_rule,
            path,
        )

    except (
        OSError,
        ValueError,
        yaml.YAMLError,
    ) as exc:

        logger.error(
            "Failed to process %s: %s",
            path,
            exc,
        )

        return None

    if not validate_rule(
        normalized_rule,
        schema,
    ):
        return None

    return normalized_rule


def main() -> None:

    if not RULES_DIR.exists():
        logger.error(
            "Sigma rules directory not found: %s",
            RULES_DIR,
        )
        return

    if not SCHEMA_PATH.exists():
        logger.error(
            "Detection rule schema not found: %s",
            SCHEMA_PATH,
        )
        return

    try:
        schema = load_schema(SCHEMA_PATH)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:

        logger.error(
            "Failed to load schema: %s",
            exc,
        )

        return

    rule_files = sorted(
        RULES_DIR.glob("*.yml")
    )

    if not rule_files:
        logger.warning(
            "No Sigma rules found in %s",
            RULES_DIR,
        )
        return

    valid_rules = 0
    invalid_rules = 0

    for rule_file in rule_files:

        logger.info(
            "Processing Sigma rule: %s",
            rule_file.name,
        )

        rule = load_and_normalize_rule(
            rule_file,
            schema,
        )

        if rule is None:

            invalid_rules += 1

            print(
                f"[FAIL] {rule_file.name}"
            )

            continue

        valid_rules += 1

        print(
            f"\n=== {rule_file.name} ==="
        )

        print(
            f"Name     : {rule['name']}"
        )

        print(
            f"ID       : {rule['id']}"
        )

        print(
            f"Type     : {rule['type']}"
        )

        print(
            f"Status   : {rule['status']}"
        )

        print(
            f"Severity : {rule['severity']}"
        )

        print(
            f"Author   : {rule['author']}"
        )

        print(
            f"MITRE    : {rule.get('mitre_attack', [])}"
        )

        print(
            "Schema    : VALID"
        )

    print("\n=== Summary ===")

    print(
        f"Valid   : {valid_rules}"
    )

    print(
        f"Invalid : {invalid_rules}"
    )

    print(
        f"Total   : {len(rule_files)}"
    )


if __name__ == "__main__":
    main()
