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


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMAS_DIR = PROJECT_ROOT / "schemas"

DETECTION_RULE_SCHEMA = (
    SCHEMAS_DIR / "detection_rule.schema.json"
)

IOC_SCHEMA = SCHEMAS_DIR / "ioc.schema.json"

SIGMA_RULES_DIR = (
    PROJECT_ROOT / "detection-rules" / "sigma"
)

IOC_STORE = (
    PROJECT_ROOT / "iocs" / "iocs.json"
)

logger = get_logger(__name__)


def load_json(path: Path) -> Any:
    """Load JSON from disk."""
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def validate_instance(
    instance: Any,
    schema: dict[str, Any],
) -> tuple[bool, str | None]:
    """Validate an object against JSON Schema."""
    try:
        validate(
            instance=instance,
            schema=schema,
        )

        return True, None

    except ValidationError as exc:
        return False, exc.message


def validate_sigma_rules(
    schema: dict[str, Any],
) -> tuple[int, int]:
    """
    Parse, normalize and validate all Sigma rules.
    """
    valid = 0
    invalid = 0

    if not SIGMA_RULES_DIR.exists():
        logger.warning(
            "Sigma rules directory not found: %s",
            SIGMA_RULES_DIR,
        )
        return valid, invalid

    rule_files = sorted(
        SIGMA_RULES_DIR.glob("*.yml")
    )

    if not rule_files:
        logger.warning(
            "No Sigma rules found: %s",
            SIGMA_RULES_DIR,
        )
        return valid, invalid

    for rule_file in rule_files:
        try:
            sigma_rule = load_sigma_rule(
                rule_file
            )

            normalized_rule = normalize_sigma_rule(
                sigma_rule,
                rule_file,
            )

        except (
            OSError,
            ValueError,
        ) as exc:
            logger.error(
                "Unable to process Sigma rule %s: %s",
                rule_file,
                exc,
            )
            invalid += 1
            continue

        is_valid, error = validate_instance(
            normalized_rule,
            schema,
        )

        if is_valid:
            logger.info(
                "Sigma rule valid: %s",
                rule_file.name,
            )
            valid += 1
        else:
            logger.error(
                "Sigma rule invalid: %s | %s",
                rule_file.name,
                error,
            )
            invalid += 1

    return valid, invalid


def load_iocs() -> list[dict[str, Any]]:
    """Load normalized IOC records."""
    if not IOC_STORE.exists():
        return []

    try:
        raw = IOC_STORE.read_text(
            encoding="utf-8"
        ).strip()

        if not raw:
            return []

        data = json.loads(raw)

    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        logger.error(
            "Unable to load IOC store %s: %s",
            IOC_STORE,
            exc,
        )
        return []

    if not isinstance(data, list):
        logger.error(
            "IOC store must contain a JSON array: %s",
            IOC_STORE,
        )
        return []

    return [
        item
        for item in data
        if isinstance(item, dict)
    ]


def validate_iocs(
    schema: dict[str, Any],
) -> tuple[int, int]:
    """Validate normalized IOC records."""
    valid = 0
    invalid = 0

    iocs = load_iocs()

    if not iocs:
        logger.info(
            "No normalized IOC records found. "
            "IOC validation skipped."
        )
        return valid, invalid

    for index, ioc in enumerate(iocs):
        is_valid, error = validate_instance(
            ioc,
            schema,
        )

        if is_valid:
            logger.info(
                "IOC valid: index=%d id=%s",
                index,
                ioc.get("id"),
            )
            valid += 1
        else:
            logger.error(
                "IOC invalid: index=%d id=%s | %s",
                index,
                ioc.get("id"),
                error,
            )
            invalid += 1

    return valid, invalid


def validate_pipeline() -> bool:
    """Run the detection and IOC validation pipeline."""
    logger.info(
        "Starting pipeline validation."
    )

    if not DETECTION_RULE_SCHEMA.exists():
        logger.error(
            "Detection rule schema not found: %s",
            DETECTION_RULE_SCHEMA,
        )
        return False

    if not IOC_SCHEMA.exists():
        logger.error(
            "IOC schema not found: %s",
            IOC_SCHEMA,
        )
        return False

    try:
        detection_rule_schema = load_schema(
            DETECTION_RULE_SCHEMA
        )

        ioc_schema = load_schema(
            IOC_SCHEMA
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        logger.error(
            "Unable to load validation schemas: %s",
            exc,
        )
        return False

    sigma_valid, sigma_invalid = (
        validate_sigma_rules(
            detection_rule_schema
        )
    )

    ioc_valid, ioc_invalid = validate_iocs(
        ioc_schema
    )

    total_valid = (
        sigma_valid
        + ioc_valid
    )

    total_invalid = (
        sigma_invalid
        + ioc_invalid
    )

    logger.info(
        "Pipeline validation completed. "
        "Valid=%d Invalid=%d",
        total_valid,
        total_invalid,
    )

    return total_invalid == 0


def main() -> None:
    """Run pipeline validation."""
    success = validate_pipeline()

    if success:
        logger.info(
            "Pipeline validation: PASS"
        )
        return

    logger.error(
        "Pipeline validation: FAIL"
    )


if __name__ == "__main__":
    main()
