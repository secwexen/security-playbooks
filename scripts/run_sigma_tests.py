from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from tools.parsers.sigma_parser import (
    load_schema,
    load_sigma_rule,
    normalize_sigma_rule,
    validate_rule,
)
from tools.utils.logger import get_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SIGMA_RULES_DIR = PROJECT_ROOT / "detection-rules" / "sigma"
SIGMA_TEST_DIR = PROJECT_ROOT / "tests" / "sigma"
FIXTURES_DIR = SIGMA_TEST_DIR / "fixtures"
TEST_CASES_FILE = SIGMA_TEST_DIR / "test-cases.yaml"
EXPECTED_RESULTS_FILE = FIXTURES_DIR / "expected_results.json"
DETECTION_SCHEMA = PROJECT_ROOT / "schemas" / "detection_rule.schema.json"

logger = get_logger(__name__)

LOAD_ERRORS = (
    OSError,
    ValueError,
    json.JSONDecodeError,
    yaml.YAMLError,
)


def load_json(path: Path) -> Any:
    """Load JSON from disk."""
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_yaml(path: Path) -> Any:
    """Load YAML from disk."""
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def _matches_value(
    actual: Any,
    expected: Any,
    operator: str | None,
) -> bool:
    """Compare one event value against one expected Sigma value."""
    expected_string = str(expected).lower()
    actual_string = str(actual).lower()

    if operator == "contains":
        return expected_string in actual_string

    if operator == "startswith":
        return actual_string.startswith(expected_string)

    if operator == "endswith":
        return actual_string.endswith(expected_string)

    return actual == expected or actual_string == expected_string


def _matches_expected_values(
    actual: Any,
    expected: Any,
    operator: str | None,
) -> bool:
    """Return whether an event value matches any expected value."""
    values = expected if isinstance(expected, list) else [expected]
    return any(
        _matches_value(
            actual,
            value,
            operator,
        )
        for value in values
    )


def event_matches_selection(
    event: dict[str, Any],
    selection: dict[str, Any],
) -> bool:
    """
    Evaluate a basic Sigma selection against one event.

    Supported operators:
    - exact field matching
    - |contains
    - |startswith
    - |endswith

    This runner intentionally implements only the operators
    needed by the current project rules.
    """
    for field, expected in selection.items():
        actual_field, operator = _parse_field_operator(field)

        if actual_field not in event:
            return False

        if not _matches_expected_values(
            event[actual_field],
            expected,
            operator,
        ):
            return False

    return True


def _parse_field_operator(
    field: str,
) -> tuple[str, str | None]:
    """Split a Sigma field name from its supported operator."""
    if "|" not in field:
        return field, None

    return tuple(field.split("|", 1))  # type: ignore[return-value]


def evaluate_detection(
    rule: dict[str, Any],
    event: dict[str, Any],
) -> bool:
    """
    Evaluate Sigma conditions supported by the current rules.

    Supported condition patterns:
    - selection
    - selection and not filter_name
    - selection and not filter_a and not filter_b
    """
    detection = rule.get("detection", {})

    if not isinstance(detection, dict):
        return False

    condition = str(
        detection.get("condition", "selection")
    ).strip()

    positive_parts, negative_parts = _split_conditions(condition)

    if not positive_parts:
        return False

    if not _positive_conditions_match(
        detection,
        positive_parts,
        event,
    ):
        return False

    return not _negative_condition_matches(
        detection,
        negative_parts,
        event,
    )


def _split_conditions(
    condition: str,
) -> tuple[list[str], list[str]]:
    """Split a basic Sigma condition into positive and negative parts."""
    positive_parts: list[str] = []
    negative_parts: list[str] = []

    for part in condition.split(" and "):
        name = part.strip()

        if name.startswith("not "):
            negative_parts.append(name[4:].strip())
        elif name:
            positive_parts.append(name)

    return positive_parts, negative_parts


def _positive_conditions_match(
    detection: dict[str, Any],
    selections: list[str],
    event: dict[str, Any],
) -> bool:
    """Check that all positive Sigma selections match."""
    for selection_name in selections:
        selection = detection.get(selection_name)

        if not isinstance(selection, dict):
            return False

        if not event_matches_selection(event, selection):
            return False

    return True


def _negative_condition_matches(
    detection: dict[str, Any],
    filters: list[str],
    event: dict[str, Any],
) -> bool:
    """Check whether any negative Sigma filter matches."""
    for filter_name in filters:
        selection = detection.get(filter_name)

        if not isinstance(selection, dict):
            return False

        if event_matches_selection(event, selection):
            return True

    return False


def load_events(
    fixture_name: str,
) -> list[dict[str, Any]]:
    """Load events from a JSON fixture file."""
    path = FIXTURES_DIR / fixture_name

    if not path.exists():
        raise FileNotFoundError(f"Fixture not found: {path}")

    data = load_json(path)

    if not isinstance(data, list):
        raise ValueError(
            f"Fixture must contain a JSON array: {path}"
        )

    return [
        event
        for event in data
        if isinstance(event, dict)
    ]


def load_test_cases() -> list[dict[str, Any]]:
    """Load Sigma test cases from YAML."""
    if not TEST_CASES_FILE.exists():
        raise FileNotFoundError(
            f"Test case file not found: {TEST_CASES_FILE}"
        )

    data = load_yaml(TEST_CASES_FILE)

    if not isinstance(data, dict):
        raise ValueError(
            "test-cases.yaml must contain a YAML object."
        )

    tests = data.get("tests", [])

    if not isinstance(tests, list):
        raise ValueError("'tests' must be a YAML list.")

    return [
        test
        for test in tests
        if isinstance(test, dict)
    ]


def load_expected_results() -> dict[str, Any]:
    """Load expected Sigma test results."""
    if not EXPECTED_RESULTS_FILE.exists():
        raise FileNotFoundError(
            f"Expected results file not found: {EXPECTED_RESULTS_FILE}"
        )

    data = load_json(EXPECTED_RESULTS_FILE)

    if not isinstance(data, dict):
        raise ValueError(
            "expected_results.json must contain an object."
        )

    return data


def load_and_validate_rule(
    rule_file: str,
) -> dict[str, Any]:
    """Load, normalize, and schema-validate one Sigma rule."""
    rule_path = SIGMA_RULES_DIR / rule_file

    if not rule_path.exists():
        raise FileNotFoundError(
            f"Sigma rule not found: {rule_path}"
        )

    sigma_rule = load_sigma_rule(rule_path)
    normalized = normalize_sigma_rule(
        sigma_rule,
        rule_path,
    )
    schema = load_schema(DETECTION_SCHEMA)

    if not validate_rule(normalized, schema):
        raise ValueError(
            f"Schema validation failed: {rule_file}"
        )

    return sigma_rule


def _get_expected_case(
    test_case: dict[str, Any],
    expected_results: dict[str, Any],
) -> tuple[str, str, str, list[Any]] | None:
    """Extract and validate test-case metadata."""
    name = str(test_case.get("name", "unnamed"))
    rule_file = str(test_case.get("rule", ""))
    fixture_file = str(test_case.get("fixture", ""))
    default_expected = str(
        test_case.get("expected", "")
    ).lower()

    if not rule_file or not fixture_file:
        logger.error(
            "Test case %s is missing rule or fixture.",
            name,
        )
        return None

    expected_entry = expected_results.get(name)

    if not isinstance(expected_entry, dict):
        logger.error(
            "No expected result found for test: %s",
            name,
        )
        return None

    expected_result = str(
        expected_entry.get(
            "expected",
            default_expected,
        )
    ).lower()

    expected_indexes = expected_entry.get(
        "matched_event_indexes",
        [],
    )

    if not isinstance(expected_indexes, list):
        expected_indexes = []

    return (
        name,
        rule_file,
        fixture_file,
        expected_indexes,
    ), expected_result  # type: ignore[return-value]


def _execute_test(
    sigma_rule: dict[str, Any],
    events: list[dict[str, Any]],
) -> list[int]:
    """Evaluate all fixture events against one Sigma rule."""
    return [
        index
        for index, event in enumerate(events)
        if evaluate_detection(sigma_rule, event)
    ]


def run_test_case(
    test_case: dict[str, Any],
    expected_results: dict[str, Any],
) -> bool:
    """Execute one Sigma test case."""
    case_data = _get_expected_case(
        test_case,
        expected_results,
    )

    if case_data is None:
        return False

    case_info, expected_result = case_data
    name, rule_file, fixture_file, expected_indexes = case_info

    try:
        sigma_rule = load_and_validate_rule(rule_file)
        events = load_events(fixture_file)
    except LOAD_ERRORS as exc:
        logger.error(
            "Test %s could not be loaded: %s",
            name,
            exc,
        )
        return False

    matched_indexes = _execute_test(
        sigma_rule,
        events,
    )

    actual_result = (
        "match"
        if matched_indexes
        else "no_match"
    )
    passed = (
        actual_result == expected_result
        and matched_indexes == expected_indexes
    )

    _log_test_result(
        name,
        expected_result,
        expected_indexes,
        actual_result,
        matched_indexes,
        passed,
    )

    return passed


def _log_test_result(
    name: str,
    expected_result: str,
    expected_indexes: list[Any],
    actual_result: str,
    matched_indexes: list[int],
    passed: bool,
) -> None:
    """Log one Sigma test result."""
    if passed:
        logger.info(
            "Sigma test PASS: %s | expected=%s matched=%s",
            name,
            expected_result,
            matched_indexes,
        )
        return

    logger.error(
        "Sigma test FAIL: %s | "
        "expected=%s/%s actual=%s/%s",
        name,
        expected_result,
        expected_indexes,
        actual_result,
        matched_indexes,
    )


def _load_test_configuration() -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
] | None:
    """Load the configured Sigma test cases and expectations."""
    try:
        test_cases = load_test_cases()
        expected_results = load_expected_results()
    except LOAD_ERRORS as exc:
        logger.error(
            "Failed to load Sigma test configuration: %s",
            exc,
        )
        return None

    if not test_cases:
        logger.error("No Sigma test cases found.")
        return None

    return test_cases, expected_results


def main() -> int:
    """Run all configured Sigma tests."""
    logger.info("Starting Sigma test runner.")

    configuration = _load_test_configuration()

    if configuration is None:
        return 1

    test_cases, expected_results = configuration

    results = [
        run_test_case(
            test_case,
            expected_results,
        )
        for test_case in test_cases
    ]

    passed = sum(results)
    failed = len(results) - passed

    logger.info(
        "Sigma tests completed. PASS=%d FAIL=%d TOTAL=%d",
        passed,
        failed,
        len(results),
    )

    if failed:
        logger.error("Sigma test runner: FAIL")
        return 1

    logger.info("Sigma test runner: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
