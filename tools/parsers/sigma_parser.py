from pathlib import Path
from typing import Any

import yaml
from jsonschema import ValidationError, validate

from tools.utils.logger import get_logger


RULES_DIR = Path("detection-rules/sigma")
SCHEMA_PATH = Path("schemas/detection_rule.schema.json")

logger = get_logger(__name__)


def load_yaml_rule(path: Path) -> dict[str, Any]:
    """Load a Sigma YAML rule from disk."""
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML structure: {path}")

    return data


def load_schema(path: Path) -> dict[str, Any]:
    """Load the detection rule JSON schema."""
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid schema structure: {path}")

    return data


def validate_rule(
    rule: dict[str, Any],
    schema: dict[str, Any],
) -> bool:
    """Validate a rule against the project detection rule schema."""
    try:
        validate(instance=rule, schema=schema)
        return True
    except ValidationError as exc:
        logger.error("Rule validation failed: %s", exc.message)
        return False


def load_sigma_rule(path: Path, schema: dict[str, Any]) -> dict[str, Any] | None:
    """Load and validate a Sigma rule."""
    try:
        rule = load_yaml_rule(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logger.error("Failed to load %s: %s", path, exc)
        return None

    if not validate_rule(rule, schema):
        return None

    return rule


def main() -> None:
    if not RULES_DIR.exists():
        logger.error("Sigma rules directory not found: %s", RULES_DIR)
        return

    if not SCHEMA_PATH.exists():
        logger.error("Schema not found: %s", SCHEMA_PATH)
        return

    logger.info("Loading detection rule schema: %s", SCHEMA_PATH)

    try:
        schema = load_schema(SCHEMA_PATH)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logger.error("Failed to load schema: %s", exc)
        return

    logger.info("Loading Sigma rules from: %s", RULES_DIR)

    rule_files = sorted(RULES_DIR.glob("*.yml"))

    if not rule_files:
        logger.warning("No Sigma rules found in %s", RULES_DIR)
        return

    valid_rules = 0
    invalid_rules = 0

    for rule_file in rule_files:
        rule = load_sigma_rule(rule_file, schema)

        if rule is None:
            invalid_rules += 1
            print(f"[FAIL] {rule_file.name}")
            continue

        valid_rules += 1

        print(f"\n=== {rule_file.name} ===")
        print(f"Title   : {rule.get('title')}")
        print(f"ID      : {rule.get('id')}")
        print(f"Status  : {rule.get('status')}")
        print(f"Level   : {rule.get('level')}")
        print(f"Tags    : {rule.get('tags')}")
        print("Schema  : VALID")

    print("\n=== Summary ===")
    print(f"Valid   : {valid_rules}")
    print(f"Invalid : {invalid_rules}")
    print(f"Total   : {len(rule_files)}")


if __name__ == "__main__":
    main()
