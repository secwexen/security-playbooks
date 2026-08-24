from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import ValidationError, validate

from tools.parsers.sigma_parser import (
    load_schema,
    load_sigma_rule,
    normalize_sigma_rule,
)
from tools.utils.logger import get_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DETECTION_SCHEMA = (
    PROJECT_ROOT
    / "schemas"
    / "detection_rule.schema.json"
)

SIGMA_RULES_DIR = (
    PROJECT_ROOT
    / "detection-rules"
    / "sigma"
)

logger = get_logger(__name__)


def validate_detection_rule(
    rule: dict[str, Any],
    schema: dict[str, Any],
) -> tuple[bool, str | None]:
    """Validate a normalized detection rule."""
    try:
        validate(
            instance=rule,
            schema=schema,
        )
        return True, None

    except ValidationError as exc:
        return False, exc.message


def process_sigma_rule(
    path: Path,
    schema: dict[str, Any],
) -> bool:
    """Load, normalize and validate one Sigma rule."""

    try:
        sigma_rule = load_sigma_rule(path)

        normalized_rule = normalize_sigma_rule(
            sigma_rule,
            path,
        )

    except (
        OSError,
        ValueError,
    ) as exc:
        logger.error(
            "Failed to process %s: %s",
            path,
            exc,
        )
        return False

    valid, error = validate_detection_rule(
        normalized_rule,
        schema,
    )

    if not valid:
        logger.error(
            "Validation failed: %s | %s",
            path.name,
            error,
        )
        return False

    logger.info(
        "Validation passed: %s",
        path.name,
    )

    return True


def validate_all_sigma_rules() -> tuple[int, int]:
    """
    Validate every Sigma rule in detection-rules/sigma.

    Returns:
        (valid_count, invalid_count)
    """
    if not DETECTION_SCHEMA.exists():
        logger.error(
            "Detection schema not found: %s",
            DETECTION_SCHEMA,
        )
        return 0, 0

    if not SIGMA_RULES_DIR.exists():
        logger.error(
            "Sigma rules directory not found: %s",
            SIGMA_RULES_DIR,
        )
        return 0, 0

    try:
        schema = load_schema(
            DETECTION_SCHEMA
        )
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        logger.error(
            "Failed to load detection schema: %s",
            exc,
        )
        return 0, 0

    rule_files = sorted(
        SIGMA_RULES_DIR.glob("*.yml")
    )

    if not rule_files:
        logger.warning(
            "No Sigma rules found in: %s",
            SIGMA_RULES_DIR,
        )
        return 0, 0

    valid_count = 0
    invalid_count = 0

    for rule_file in rule_files:
        if process_sigma_rule(
            rule_file,
            schema,
        ):
            valid_count += 1
        else:
            invalid_count += 1

    return valid_count, invalid_count


def main() -> int:
    """Run validation for all Sigma rules."""
    logger.info(
        "Starting validation of all detection rules."
    )

    valid_count, invalid_count = (
        validate_all_sigma_rules()
    )

    total = (
        valid_count
        + invalid_count
    )

    logger.info(
        "Rule validation completed. "
        "Valid=%d Invalid=%d Total=%d",
        valid_count,
        invalid_count,
        total,
    )

    if invalid_count > 0:
        logger.error(
            "Rule validation: FAIL"
        )
        return 1

    if total == 0:
        logger.warning(
            "No detection rules were validated."
        )
        return 1

    logger.info(
        "Rule validation: PASS"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
