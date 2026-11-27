"""Tests for YARA detection rules."""

from __future__ import annotations

from typing import Any

import pytest

# Pytest fixture parameters intentionally share fixture function names.
# pylint: disable=redefined-outer-name

from scripts.run_yara_tests import (
    load_expected_results,
    load_test_cases,
    run_test_case,
)


@pytest.fixture(scope="module")
def expected_results() -> Any:
    """Load expected YARA match results."""
    return load_expected_results()


@pytest.fixture(scope="module")
def test_cases() -> Any:
    """Load YARA test definitions."""
    return load_test_cases()


@pytest.mark.parametrize(
    "test_name",
    [
        "malware_sample_match",
        "powershell_payload_match",
        "obfuscated_powershell_match",
    ],
)
def test_yara_rule(
    test_name: str,
    test_cases: Any,
    expected_results: Any,
) -> None:
    """Validate each configured YARA test case."""
    test_case = next(
        (
            case
            for case in test_cases
            if case.get("name") == test_name
        ),
        None,
    )

    assert test_case is not None, (
        f"YARA test case not found: {test_name}"
    )

    assert run_test_case(
        test_case,
        expected_results,
    )
