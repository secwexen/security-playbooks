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

SIGMA_RULES_DIR = (
    PROJECT_ROOT
    / "detection-rules"
    / "sigma"
)

SIGMA_TEST_DIR = (
    PROJECT_ROOT
    / "tests"
    / "sigma"
)

FIXTURES_DIR = (
    SIGMA_TEST_DIR
    / "fixtures"
)

TEST_CASES_FILE = (
    SIGMA_TEST_DIR
    / "test-cases.yaml"
)

EXPECTED_RESULTS_FILE = (
    FIXTURES_DIR
    / "expected_results.json"
)

DETECTION_SCHEMA = (
    PROJECT_ROOT
    / "schemas"
    / "detection_rule.schema.json"
)

logger = get_logger(__name__)


def load_json(path: Path) -> Any:
    """Load JSON from disk."""
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def load_yaml(path: Path) -> Any:
    """Load YAML from disk."""
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return yaml.safe_load(file)


def event_matches_selection(
    event: dict[str, Any],
    selection: dict[str, Any],
) -> bool:
    """
    Evaluate a basic Sigma selection against one event.

    Supported:
    - exact field matching
    - |contains
    - |startswith
    - |endswith

    This runner intentionally implements only the operators
    needed by the current project rules.
    """
    for field, expected in selection.items():
        operator = None
        actual_field = field

        if "|" in field:
            actual_field, operator = field.split(
                "|",
                1,
            )

        if actual_field not in event:
            return False

        actual = event[actual_field]

        if isinstance(
            expected,
            list,
        ):
            expected_values = expected
        else:
            expected_values = [expected]

        matched = False

        for expected_value in expected_values:
            expected_string = str(
                expected_value
            )
            actual_string = str(
                actual
            )

            if operator == "contains":
                if expected_string.lower() in (
                    actual_string.lower()
                ):
                    matched = True

            elif operator == "startswith":
                if actual_string.lower().startswith(
                    expected_string.lower()
                ):
                    matched = True

            elif operator == "endswith":
                if actual_string.lower().endswith(
                    expected_string.lower()
                ):
                    matched = True

            else:
                if actual == expected_value:
                    matched = True
                elif actual_string.lower() == (
                    expected_string.lower()
                ):
                    matched = True

        if not matched:
            return False

    return True


def evaluate_detection(
    rule: dict[str, Any],
    event: dict[str, Any],
) -> bool:
    """
    Evaluate Sigma conditions used by the current rules.

    Supported:
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

    parts = [
        part.strip()
        for part in condition.split(" and ")
    ]

    if not parts:
        return False

    positive_parts: list[str] = []
    negative_parts: list[str] = []

    for part in parts:
        if part.startswith("not "):
            negative_parts.append(part[4:].strip())
        else:
            positive_parts.append(part)

    for selection_name in positive_parts:
        selection = detection.get(selection_name)

        if not isinstance(selection, dict):
            return False

        if not event_matches_selection(
            event,
            selection,
        ):
            return False

    for filter_name in negative_parts:
        filter_selection = detection.get(filter_name)

        if not isinstance(filter_selection, dict):
            return False

        if event_matches_selection(
            event,
            filter_selection,
        ):
            return False

    return True
    

def load_events(
    fixture_name: str,
) -> list[dict[str, Any]]:
    """Load events from a fixture file."""
    path = FIXTURES_DIR / fixture_name

    if not path.exists():
        raise FileNotFoundError(
            f"Fixture not found: {path}"
        )

    data = load_json(path)

    if not isinstance(
        data,
        list,
    ):
        raise ValueError(
            f"Fixture must contain a JSON array: {path}"
        )

    events = []

    for event in data:
        if isinstance(
            event,
            dict,
        ):
            events.append(event)

    return events


def load_test_cases() -> list[dict[str, Any]]:
    """Load test cases from YAML."""
    if not TEST_CASES_FILE.exists():
        raise FileNotFoundError(
            f"Test case file not found: "
            f"{TEST_CASES_FILE}"
        )

    data = load_yaml(
        TEST_CASES_FILE
    )

    if not isinstance(
        data,
        dict,
    ):
        raise ValueError(
            "test-cases.yaml must contain a YAML object."
        )

    tests = data.get(
        "tests",
        [],
    )

    if not isinstance(
        tests,
        list,
    ):
        raise ValueError(
            "'tests' must be a YAML list."
        )

    return [
        test
        for test in tests
        if isinstance(
            test,
            dict,
        )
    ]


def load_expected_results() -> dict[str, Any]:
    """Load expected Sigma test results."""
    if not EXPECTED_RESULTS_FILE.exists():
        raise FileNotFoundError(
            f"Expected results file not found: "
            f"{EXPECTED_RESULTS_FILE}"
        )

    data = load_json(
        EXPECTED_RESULTS_FILE
    )

    if not isinstance(
        data,
        dict,
    ):
        raise ValueError(
            "expected_results.json must contain an object."
        )

    return data


def load_and_validate_rule(
    rule_file: str,
) -> dict[str, Any]:
    """Load, normalize and schema-validate one Sigma rule."""
    rule_path = (
        SIGMA_RULES_DIR
        / rule_file
    )

    if not rule_path.exists():
        raise FileNotFoundError(
            f"Sigma rule not found: {rule_path}"
        )

    sigma_rule = load_sigma_rule(
        rule_path
    )

    normalized = normalize_sigma_rule(
        sigma_rule,
        rule_path,
    )

    schema = load_schema(
        DETECTION_SCHEMA
    )

    if not validate_rule(
        normalized,
        schema,
    ):
        raise ValueError(
            f"Schema validation failed: {rule_file}"
        )

    return sigma_rule


def run_test_case(
    test_case: dict[str, Any],
    expected_results: dict[str, Any],
) -> bool:
    """Execute one Sigma test case."""
    name = str(
        test_case.get(
            "name",
            "unnamed",
        )
    )

    rule_file = str(
        test_case.get(
            "rule",
            "",
        )
    )

    fixture_file = str(
        test_case.get(
            "fixture",
            "",
        )
    )

    expected = str(
        test_case.get(
            "expected",
            "",
        )
    ).lower()

    if not rule_file or not fixture_file:
        logger.error(
            "Test case %s is missing rule or fixture.",
            name,
        )
        return False

    expected_entry = expected_results.get(
        name
    )

    if not isinstance(
        expected_entry,
        dict,
    ):
        logger.error(
            "No expected result found for test: %s",
            name,
        )
        return False

    expected_result = str(
        expected_entry.get(
            "expected",
            expected,
        )
    ).lower()

    expected_indexes = expected_entry.get(
        "matched_event_indexes",
        [],
    )

    if not isinstance(
        expected_indexes,
        list,
    ):
        expected_indexes = []

    try:
        sigma_rule = load_and_validate_rule(
            rule_file
        )

        events = load_events(
            fixture_file
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        logger.error(
            "Test %s could not be loaded: %s",
            name,
            exc,
        )
        return False

    matched_indexes: list[int] = []

    for index, event in enumerate(
        events
    ):
        if evaluate_detection(
            sigma_rule,
            event,
        ):
            matched_indexes.append(
                index
            )

    actual_result = (
        "match"
        if matched_indexes
        else "no_match"
    )

    passed = (
        actual_result == expected_result
        and matched_indexes
        == expected_indexes
    )

    if passed:
        logger.info(
            "Sigma test PASS: %s | "
            "expected=%s matched=%s",
            name,
            expected_result,
            matched_indexes,
        )
    else:
        logger.error(
            "Sigma test FAIL: %s | "
            "expected=%s/%s actual=%s/%s",
            name,
            expected_result,
            expected_indexes,
            actual_result,
            matched_indexes,
        )

    return passed


def main() -> int:
    """Run all configured Sigma tests."""
    logger.info(
        "Starting Sigma test runner."
    )

    try:
        test_cases = load_test_cases()
        expected_results = (
            load_expected_results()
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        logger.error(
            "Failed to load Sigma test configuration: %s",
            exc,
        )
        return 1

    if not test_cases:
        logger.error(
            "No Sigma test cases found."
        )
        return 1

    passed = 0
    failed = 0

    for test_case in test_cases:
        if run_test_case(
            test_case,
            expected_results,
        ):
            passed += 1
        else:
            failed += 1

    total = passed + failed

    logger.info(
        "Sigma tests completed. "
        "PASS=%d FAIL=%d TOTAL=%d",
        passed,
        failed,
        total,
    )

    if failed:
        logger.error(
            "Sigma test runner: FAIL"
        )
        return 1

    logger.info(
        "Sigma test runner: PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
