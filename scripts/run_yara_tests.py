from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

try:
    import yara
except ImportError as exc:
    yara = None
    YARA_IMPORT_ERROR = exc
else:
    YARA_IMPORT_ERROR = None

from tools.utils.logger import get_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]

YARA_RULES_DIR = (
    PROJECT_ROOT
    / "detection-rules"
    / "yara"
)

YARA_TEST_DIR = (
    PROJECT_ROOT
    / "tests"
    / "yara"
)

FIXTURES_DIR = (
    YARA_TEST_DIR
    / "fixtures"
)

TEST_CASES_FILE = (
    YARA_TEST_DIR
    / "test-samples.yaml"
)

EXPECTED_RESULTS_FILE = (
    FIXTURES_DIR
    / "expected_matches.json"
)

logger = get_logger(__name__)


def load_yaml(path: Path) -> Any:
    """Load YAML from disk."""
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return yaml.safe_load(file)


def load_json(path: Path) -> Any:
    """Load JSON from disk."""
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def normalize_test_cases(
    data: Any,
) -> list[dict[str, Any]]:
    """
    Normalize supported test-sample YAML layouts.

    Supported top-level keys:
    - tests
    - test_cases
    - test-cases
    - samples
    """
    if isinstance(data, list):
        return [
            item
            for item in data
            if isinstance(item, dict)
        ]

    if isinstance(data, dict):
        for key in (
            "tests",
            "test_cases",
            "test-cases",
            "samples",
        ):
            value = data.get(key)

            if isinstance(value, list):
                return [
                    item
                    for item in value
                    if isinstance(item, dict)
                ]

    return []


def load_test_cases() -> list[dict[str, Any]]:
    """Load YARA test definitions."""
    if not TEST_CASES_FILE.exists():
        raise FileNotFoundError(
            f"YARA test file not found: "
            f"{TEST_CASES_FILE}"
        )

    data = load_yaml(
        TEST_CASES_FILE
    )

    return normalize_test_cases(
        data
    )


def load_expected_results() -> dict[str, Any]:
    """Load expected YARA match results."""
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
            "expected_matches.json must contain "
            "a JSON object."
        )

    return data


def resolve_rule_path(
    rule_name: str,
) -> Path:
    """Resolve a YARA rule filename."""
    path = (
        YARA_RULES_DIR
        / rule_name
    )

    if path.exists():
        return path

    raise FileNotFoundError(
        f"YARA rule not found: {path}"
    )


def resolve_sample_path(
    sample_name: str,
) -> Path:
    """
    Resolve a sample fixture.

    Test cases normally reference:
        benign_sample.txt
        malicious_sample.txt
    """
    candidates = (
        FIXTURES_DIR / sample_name,
        YARA_TEST_DIR / sample_name,
    )

    for path in candidates:
        if path.exists():
            return path

    raise FileNotFoundError(
        f"YARA sample not found: {sample_name}"
    )


def compile_rule(
    rule_path: Path,
) -> Any:
    """Compile one YARA rule file."""
    if yara is None:
        raise RuntimeError(
            "yara-python is not installed."
        ) from YARA_IMPORT_ERROR

    return yara.compile(
        filepath=str(rule_path)
    )


def normalize_expected_matches(
    value: Any,
) -> list[str]:
    """
    Normalize expected match names.

    Supports:
    - ["rule_name"]
    - {"matches": ["rule_name"]}
    - {"matched_rules": ["rule_name"]}
    - string
    """
    if value is None:
        return []

    if isinstance(
        value,
        str,
    ):
        return [value]

    if isinstance(
        value,
        list,
    ):
        return [
            str(item)
            for item in value
        ]

    if isinstance(
        value,
        dict,
    ):
        for key in (
            "matches",
            "matched_rules",
            "expected_matches",
            "rules",
        ):
            nested = value.get(key)

            if isinstance(
                nested,
                list,
            ):
                return [
                    str(item)
                    for item in nested
                ]

            if isinstance(
                nested,
                str,
            ):
                return [nested]

    return []


def extract_rule_names(
    matches: Any,
) -> list[str]:
    """Extract matched YARA rule names."""
    names: list[str] = []

    for match in matches:
        name = getattr(
            match,
            "rule",
            None,
        )

        if name:
            names.append(
                str(name)
            )

    return sorted(
        set(names)
    )


def run_test_case(
    test_case: dict[str, Any],
    expected_results: dict[str, Any],
) -> bool:
    """Execute one YARA test case."""

    name = str(
        test_case.get(
            "name",
            "unnamed",
        )
    )

    rule_name = (
        test_case.get("rule")
        or test_case.get("rule_file")
    )

    sample_name = (
        test_case.get("sample")
        or test_case.get("fixture")
        or test_case.get("sample_file")
    )

    if not rule_name:
        logger.error(
            "YARA test %s is missing rule.",
            name,
        )
        return False

    if not sample_name:
        logger.error(
            "YARA test %s is missing sample.",
            name,
        )
        return False

    expected_entry = expected_results.get(
        name
    )

    if expected_entry is None:
        logger.error(
            "No expected result found for YARA test: %s",
            name,
        )
        return False

    if isinstance(
        expected_entry,
        dict,
    ):
        expected_matches = (
            expected_entry.get(
                "matches",
                expected_entry.get(
                    "matched_rules",
                    expected_entry.get(
                        "expected_matches",
                        [],
                    ),
                ),
            )
        )
    else:
        expected_matches = expected_entry

    expected_rules = normalize_expected_matches(
        expected_matches
    )

    try:
        rule_path = resolve_rule_path(
            str(rule_name)
        )

        sample_path = resolve_sample_path(
            str(sample_name)
        )

        compiled_rule = compile_rule(
            rule_path
        )

        matches = compiled_rule.match(
            str(sample_path)
        )

    except (
        OSError,
        FileNotFoundError,
        RuntimeError,
        ValueError,
    ) as exc:
        logger.error(
            "YARA test %s could not be loaded: %s",
            name,
            exc,
        )
        return False

    actual_rules = extract_rule_names(
        matches
    )

    passed = (
        actual_rules
        == sorted(
            set(expected_rules)
        )
    )

    if passed:
        logger.info(
            "YARA test PASS: %s | "
            "expected=%s matched=%s",
            name,
            expected_rules,
            actual_rules,
        )
    else:
        logger.error(
            "YARA test FAIL: %s | "
            "expected=%s matched=%s",
            name,
            expected_rules,
            actual_rules,
        )

    return passed


def main() -> int:
    """Run all configured YARA tests."""
    logger.info(
        "Starting YARA test runner."
    )

    if yara is None:
        logger.error(
            "yara-python is not installed. "
            "Install the dependency before running YARA tests."
        )
        return 1

    if not YARA_RULES_DIR.exists():
        logger.error(
            "YARA rules directory not found: %s",
            YARA_RULES_DIR,
        )
        return 1

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
            "Failed to load YARA test configuration: %s",
            exc,
        )
        return 1

    if not test_cases:
        logger.error(
            "No YARA test cases found."
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

    total = (
        passed
        + failed
    )

    logger.info(
        "YARA tests completed. "
        "PASS=%d FAIL=%d TOTAL=%d",
        passed,
        failed,
        total,
    )

    if failed:
        logger.error(
            "YARA test runner: FAIL"
        )
        return 1

    logger.info(
        "YARA test runner: PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
