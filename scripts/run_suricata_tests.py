from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from tools.utils.logger import get_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SURICATA_RULES_DIR = (
    PROJECT_ROOT
    / "detection-rules"
    / "suricata"
)

SURICATA_TEST_DIR = (
    PROJECT_ROOT
    / "tests"
    / "suricata"
)

FIXTURES_DIR = (
    SURICATA_TEST_DIR
    / "fixtures"
)

TEST_CASES_FILE = (
    SURICATA_TEST_DIR
    / "test-pcaps.yaml"
)

EXPECTED_ALERTS_FILE = (
    FIXTURES_DIR
    / "expected_alerts.json"
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
    Normalize common Suricata test-case layouts.

    Supported top-level keys:
    - tests
    - test_cases
    - test-cases
    - cases
    - pcaps
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
            "cases",
            "pcaps",
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
    """Load Suricata PCAP test definitions."""
    if not TEST_CASES_FILE.exists():
        raise FileNotFoundError(
            f"Suricata test file not found: "
            f"{TEST_CASES_FILE}"
        )

    data = load_yaml(
        TEST_CASES_FILE
    )

    return normalize_test_cases(
        data
    )


def load_expected_alerts() -> dict[str, Any]:
    """Load expected Suricata alerts."""
    if not EXPECTED_ALERTS_FILE.exists():
        raise FileNotFoundError(
            "Expected Suricata alerts file not found: "
            f"{EXPECTED_ALERTS_FILE}"
        )

    data = load_json(
        EXPECTED_ALERTS_FILE
    )

    if not isinstance(
        data,
        dict,
    ):
        raise ValueError(
            "expected_alerts.json must contain "
            "a JSON object."
        )

    return data


def find_suricata() -> str | None:
    """Return the Suricata executable path."""
    return shutil.which(
        "suricata"
    )


def collect_rule_files() -> list[Path]:
    """Collect all Suricata rule files."""
    if not SURICATA_RULES_DIR.exists():
        return []

    return sorted(
        SURICATA_RULES_DIR.glob("*.rules")
    )


def build_rule_arguments() -> list[str]:
    """
    Build Suricata rule arguments.

    Each .rules file is supplied with -S so the runner
    can use the repository's local detection rules.
    """
    arguments: list[str] = []

    for rule_file in collect_rule_files():
        arguments.extend(
            [
                "-S",
                str(rule_file),
            ]
        )

    return arguments


def resolve_pcap(
    value: str,
) -> Path:
    """Resolve a PCAP path from a test case."""
    candidates = (
        FIXTURES_DIR / value,
        SURICATA_TEST_DIR / value,
        PROJECT_ROOT / value,
    )

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        f"PCAP not found: {value}"
    )


def normalize_expected_signatures(
    value: Any,
) -> list[str]:
    """
    Normalize expected alert signatures.

    Supported forms:
    - ["Signature A"]
    - {"signatures": ["Signature A"]}
    - {"expected_alerts": ["Signature A"]}
    - {"alerts": ["Signature A"]}
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
            "signatures",
            "expected_alerts",
            "alerts",
            "matches",
            "rules",
        ):
            nested = value.get(
                key
            )

            if isinstance(
                nested,
                str,
            ):
                return [nested]

            if isinstance(
                nested,
                list,
            ):
                return [
                    str(item)
                    for item in nested
                ]

    return []


def collect_alert_signatures(
    output_dir: Path,
) -> list[str]:
    """
    Read Suricata eve.json alert events and extract signatures.
    """
    eve_path = (
        output_dir
        / "eve.json"
    )

    if not eve_path.exists():
        return []

    signatures: list[str] = []

    with eve_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(
                    line
                )
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get(
                "alert",
                {},
            )

            if not isinstance(
                alert,
                dict,
            ):
                continue

            signature = alert.get(
                "signature"
            )

            if signature:
                signatures.append(
                    str(signature)
                )

    return sorted(
        set(signatures)
    )


def run_suricata(
    pcap_path: Path,
) -> tuple[list[str], str | None]:
    """Run Suricata against one PCAP."""
    suricata = find_suricata()

    if not suricata:
        return (
            [],
            "suricata executable not found",
        )

    rule_arguments = build_rule_arguments()

    if not rule_arguments:
        return (
            [],
            "no repository Suricata rule files found",
        )

    with tempfile.TemporaryDirectory(
        prefix="security_playbooks_suricata_"
    ) as temporary_directory:
        output_dir = Path(
            temporary_directory
        )

        command = [
            suricata,
            "-r",
            str(pcap_path),
            "-l",
            str(output_dir),
            *rule_arguments,
        ]

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )

        except OSError as exc:
            return (
                [],
                str(exc),
            )

        if process.returncode != 0:
            stderr = (
                process.stderr.strip()
                or process.stdout.strip()
                or "Suricata exited with an error."
            )

            return (
                [],
                stderr,
            )

        signatures = collect_alert_signatures(
            output_dir
        )

        return (
            signatures,
            None,
        )


def run_test_case(
    test_case: dict[str, Any],
    expected_alerts: dict[str, Any],
) -> bool:
    """Execute one Suricata PCAP test case."""
    name = str(
        test_case.get(
            "name",
            "unnamed",
        )
    )

    pcap_value = (
        test_case.get("pcap")
        or test_case.get("pcap_file")
        or test_case.get("fixture")
        or test_case.get("sample")
    )

    if not pcap_value:
        logger.error(
            "Suricata test %s is missing a PCAP.",
            name,
        )
        return False

    expected_entry = (
        expected_alerts.get(name)
    )

    if expected_entry is None:
        logger.error(
            "No expected alert result found for test: %s",
            name,
        )
        return False

    if isinstance(
        expected_entry,
        dict,
    ):
        raw_expected = (
            expected_entry.get(
                "signatures",
                expected_entry.get(
                    "expected_alerts",
                    expected_entry.get(
                        "alerts",
                        expected_entry.get(
                            "matches",
                            [],
                        ),
                    ),
                ),
            )
        )
    else:
        raw_expected = expected_entry

    expected_signatures = (
        normalize_expected_signatures(
            raw_expected
        )
    )

    try:
        pcap_path = resolve_pcap(
            str(pcap_value)
        )

    except (
        OSError,
        FileNotFoundError,
    ) as exc:
        logger.error(
            "Suricata test %s could not load PCAP: %s",
            name,
            exc,
        )
        return False

    actual_signatures, error = run_suricata(
        pcap_path
    )

    if error:
        logger.error(
            "Suricata test %s failed: %s",
            name,
            error,
        )
        return False

    expected_normalized = sorted(
        set(expected_signatures)
    )

    actual_normalized = sorted(
        set(actual_signatures)
    )

    passed = (
        expected_normalized
        == actual_normalized
    )

    if passed:
        logger.info(
            "Suricata test PASS: %s | "
            "expected=%s matched=%s",
            name,
            expected_normalized,
            actual_normalized,
        )
    else:
        logger.error(
            "Suricata test FAIL: %s | "
            "expected=%s matched=%s",
            name,
            expected_normalized,
            actual_normalized,
        )

    return passed


def main() -> int:
    """Run all configured Suricata tests."""
    logger.info(
        "Starting Suricata test runner."
    )

    if not find_suricata():
        logger.error(
            "Suricata is not installed or not "
            "available in PATH."
        )
        return 1

    if not SURICATA_RULES_DIR.exists():
        logger.error(
            "Suricata rules directory not found: %s",
            SURICATA_RULES_DIR,
        )
        return 1

    try:
        test_cases = load_test_cases()
        expected_alerts = load_expected_alerts()

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        logger.error(
            "Failed to load Suricata test configuration: %s",
            exc,
        )
        return 1

    if not test_cases:
        logger.error(
            "No Suricata test cases found."
        )
        return 1

    passed = 0
    failed = 0

    for test_case in test_cases:
        if run_test_case(
            test_case,
            expected_alerts,
        ):
            passed += 1
        else:
            failed += 1

    total = (
        passed
        + failed
    )

    logger.info(
        "Suricata tests completed. "
        "PASS=%d FAIL=%d TOTAL=%d",
        passed,
        failed,
        total,
    )

    if failed:
        logger.error(
            "Suricata test runner: FAIL"
        )
        return 1

    logger.info(
        "Suricata test runner: PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
