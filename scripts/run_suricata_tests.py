"""Validate repository Suricata rules against network traffic fixtures."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from tools.utils.logger import get_logger

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SURICATA_RULES_DIR = PROJECT_ROOT / "detection-rules" / "suricata"
SURICATA_TEST_DIR = PROJECT_ROOT / "tests" / "suricata"
FIXTURES_DIR = SURICATA_TEST_DIR / "fixtures"
TEST_CASES_FILE = SURICATA_TEST_DIR / "test-pcaps.yaml"
EXPECTED_ALERTS_FILE = FIXTURES_DIR / "expected_alerts.json"

logger = get_logger(__name__)

CONFIG_ERRORS = (
    OSError,
    ValueError,
    yaml.YAMLError,
)


def load_yaml(path: Path) -> Any:
    """Load YAML from disk."""
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_json(path: Path) -> Any:
    """Load JSON from disk."""
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def normalize_test_cases(
    data: Any,
) -> list[dict[str, Any]]:
    """Normalize supported Suricata test-case layouts."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

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
                return [item for item in value if isinstance(item, dict)]

    return []


def load_test_cases() -> list[dict[str, Any]]:
    """Load Suricata PCAP test definitions."""
    if not TEST_CASES_FILE.exists():
        raise FileNotFoundError(f"Suricata test file not found: {TEST_CASES_FILE}")

    return normalize_test_cases(load_yaml(TEST_CASES_FILE))


def load_expected_alerts() -> dict[str, Any]:
    """Load expected Suricata alerts."""
    if not EXPECTED_ALERTS_FILE.exists():
        raise FileNotFoundError(f"Expected Suricata alerts file not found: " f"{EXPECTED_ALERTS_FILE}")

    data = load_json(EXPECTED_ALERTS_FILE)

    if not isinstance(data, dict):
        raise ValueError("expected_alerts.json must contain a JSON object.")

    return data


def find_suricata() -> str | None:
    """Return the Suricata executable path."""
    return shutil.which("suricata")


def collect_rule_files() -> list[Path]:
    """Collect repository Suricata rule files."""
    if not SURICATA_RULES_DIR.exists():
        return []

    return sorted(SURICATA_RULES_DIR.glob("*.rules"))


def normalize_suricata_rule(raw_rule: str) -> str:
    """
    Normalize one multiline Suricata rule into one line.

    Source rule files may remain readable and multiline.
    The generated rules file is normalized for the target parser.
    """
    rule = raw_rule.strip()

    if not rule:
        return ""

    return re.sub(r"\s+", " ", rule).strip()


def extract_suricata_rules(content: str) -> list[str]:
    """
    Extract complete Suricata signatures from a rule file.

    A signature starts with alert/pass/drop/reject and ends at
    the matching closing parenthesis. Comments and empty lines
    are ignored.
    """
    rules: list[str] = []
    current: list[str] = []
    depth = 0

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if not current and not re.match(
            r"^(alert|pass|drop|reject)\b",
            line,
            flags=re.IGNORECASE,
        ):
            continue

        current.append(line)
        depth += line.count("(")
        depth -= line.count(")")

        if depth == 0:
            normalized = normalize_suricata_rule(" ".join(current))

            if normalized:
                rules.append(normalized)

            current = []

    if current:
        normalized = normalize_suricata_rule(" ".join(current))

        if normalized:
            rules.append(normalized)

    return rules


def build_combined_rules_file(
    destination: Path,
) -> tuple[Path | None, int]:
    """
    Combine and normalize all repository rules.

    Returns:
        A tuple containing the generated rules path and rule count.
    """
    rule_files = collect_rule_files()

    if not rule_files:
        return None, 0

    generated_rules: list[str] = []

    for rule_file in rule_files:
        try:
            content = rule_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Unable to read rule file {rule_file}: {exc}") from exc

        generated_rules.extend(extract_suricata_rules(content))

    if not generated_rules:
        return None, 0

    destination.write_text(
        "\n".join(generated_rules) + "\n",
        encoding="utf-8",
    )

    return destination, len(generated_rules)


def resolve_pcap(value: str) -> Path:
    """Resolve a PCAP path against supported repository locations."""
    candidates = (
        FIXTURES_DIR / value,
        SURICATA_TEST_DIR / value,
        PROJECT_ROOT / value,
    )

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(f"PCAP not found: {value}")


def normalize_expected_signatures(value: Any) -> list[str]:
    """Normalize expected alert signatures."""
    if value is None:
        return []

    if isinstance(value, str):
        return [value]

    if isinstance(value, list):
        return [str(item) for item in value]

    if isinstance(value, dict):
        for key in (
            "signatures",
            "expected_alerts",
            "alerts",
            "matches",
            "rules",
        ):
            nested = value.get(key)

            if isinstance(nested, str):
                return [nested]

            if isinstance(nested, list):
                return [str(item) for item in nested]

    return []


def collect_alert_signatures(output_dir: Path) -> list[str]:
    """Collect unique alert signatures from eve.json."""
    eve_path = output_dir / "eve.json"

    if not eve_path.exists():
        return []

    signatures: list[str] = []

    with eve_path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(event, dict):
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {})

            if not isinstance(alert, dict):
                continue

            signature = alert.get("signature")

            if signature:
                signatures.append(str(signature))

    return sorted(set(signatures))


def collect_engine_stats(
    output_dir: Path,
) -> tuple[int | None, int | None]:
    """Extract rules_loaded and alert count from eve.json."""
    eve_path = output_dir / "eve.json"

    if not eve_path.is_file():
        return None, None

    rules_loaded: int | None = None
    alerts: int | None = None

    with eve_path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(event, dict):
                continue

            if event.get("event_type") != "stats":
                continue

            stats = event.get("stats")

            if not isinstance(stats, dict):
                continue

            detect = stats.get("detect")

            if not isinstance(detect, dict):
                continue

            engines = detect.get("engines", [])

            if isinstance(engines, list):
                loaded_values = [
                    engine["rules_loaded"]
                    for engine in engines
                    if (
                        isinstance(engine, dict)
                        and isinstance(engine.get("rules_loaded"), int)
                        and not isinstance(engine.get("rules_loaded"), bool)
                    )
                ]

                if loaded_values:
                    rules_loaded = sum(loaded_values)

            alert_value = detect.get("alert")

            if isinstance(alert_value, int) and not isinstance(alert_value, bool):
                alerts = alert_value

    return rules_loaded, alerts


def _execute_suricata_command(
    command: list[str],
) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    """Execute Suricata and return its process result or an error."""
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return None, str(exc)

    return process, None


def _validate_suricata_output(
    process: subprocess.CompletedProcess[str],
    output_dir: Path,
    rule_count: int,
) -> str | None:
    """Validate Suricata output, exit status, and loaded rule count."""
    combined_output = f"{process.stdout.strip()}\n{process.stderr.strip()}"

    fatal_markers = (
        "Signature missing required value",
        "error parsing signature",
        "no rules were loaded",
        "unknown file format",
        "pcap file reader thread failed",
        "Failed to init pcap file",
    )

    for marker in fatal_markers:
        if marker in combined_output:
            return f"Suricata validation failed: {marker}"

    if process.returncode != 0:
        return process.stderr.strip() or process.stdout.strip() or "Suricata exited with an error."

    rules_loaded, _alerts = collect_engine_stats(output_dir)

    if rules_loaded is not None and rules_loaded < rule_count:
        return "Suricata loaded fewer rules than generated: " f"loaded={rules_loaded} generated={rule_count}"

    return None


def run_suricata(
    pcap_path: Path,
) -> tuple[list[str], str | None]:
    """Run Suricata against one PCAP."""
    signatures: list[str] = []
    error: str | None = None
    suricata = find_suricata()

    if not suricata:
        error = "suricata executable not found"
    elif not pcap_path.is_file():
        error = f"PCAP is not a file: {pcap_path}"
    else:
        with tempfile.TemporaryDirectory(prefix="security_playbooks_suricata_") as temporary_directory:
            temporary_path = Path(temporary_directory)
            output_dir = temporary_path / "output"
            output_dir.mkdir(parents=True, exist_ok=True)

            rules_path = temporary_path / "security_playbooks.rules"

            try:
                combined_rules, rule_count = build_combined_rules_file(rules_path)
            except (OSError, RuntimeError) as exc:
                error = str(exc)
            else:
                if combined_rules is None:
                    error = "no valid repository Suricata rules found"
                else:
                    command = [
                        suricata,
                        "-r",
                        str(pcap_path),
                        "-S",
                        str(combined_rules),
                        "-k",
                        "none",
                        "-l",
                        str(output_dir),
                    ]

                    process, execution_error = _execute_suricata_command(command)

                    if execution_error is not None or process is None:
                        error = execution_error or "Suricata execution failed."
                    else:
                        error = _validate_suricata_output(
                            process,
                            output_dir,
                            rule_count,
                        )

                        if error is None:
                            signatures = collect_alert_signatures(output_dir)

    return signatures, error


def _get_test_name(test_case: dict[str, Any]) -> str:
    """Return the configured test-case name."""
    return str(test_case.get("name", "unnamed"))


def _get_pcap_value(test_case: dict[str, Any]) -> Any:
    """Return the first configured PCAP fixture field."""
    return test_case.get("pcap") or test_case.get("pcap_file") or test_case.get("fixture") or test_case.get("sample")


def _get_expected_signatures(
    name: str,
    expected_alerts: dict[str, Any],
) -> list[str] | None:
    """Retrieve and normalize expected signatures for one test."""
    expected_entry = expected_alerts.get(name)

    if expected_entry is None:
        logger.error(
            "No expected alert result found for test: %s",
            name,
        )
        return None

    if isinstance(expected_entry, dict):
        raw_expected = expected_entry.get(
            "signatures",
            expected_entry.get(
                "expected_alerts",
                expected_entry.get(
                    "alerts",
                    expected_entry.get("matches", []),
                ),
            ),
        )
    else:
        raw_expected = expected_entry

    return normalize_expected_signatures(raw_expected)


def _resolve_test_pcap(
    name: str,
    pcap_value: Any,
) -> Path | None:
    """Resolve a test PCAP and log failures."""
    try:
        return resolve_pcap(str(pcap_value))
    except OSError as exc:
        logger.error(
            "Suricata test %s could not load PCAP: %s",
            name,
            exc,
        )
        return None


def _compare_and_log_signatures(
    name: str,
    expected_signatures: list[str],
    actual_signatures: list[str],
) -> bool:
    """Compare expected and actual signatures and log the result."""
    expected_normalized = sorted(set(expected_signatures))
    actual_normalized = sorted(set(actual_signatures))

    passed = expected_normalized == actual_normalized

    if passed:
        logger.info(
            "Suricata test PASS: %s | expected=%s matched=%s",
            name,
            expected_normalized,
            actual_normalized,
        )
    else:
        logger.error(
            "Suricata test FAIL: %s | expected=%s matched=%s",
            name,
            expected_normalized,
            actual_normalized,
        )

    return passed


def run_test_case(
    test_case: dict[str, Any],
    expected_alerts: dict[str, Any],
) -> bool:
    """Execute one Suricata PCAP test case."""
    name = _get_test_name(test_case)
    pcap_value = _get_pcap_value(test_case)

    if not pcap_value:
        logger.error(
            "Suricata test %s is missing a PCAP.",
            name,
        )
        return False

    expected_signatures = _get_expected_signatures(
        name,
        expected_alerts,
    )

    if expected_signatures is None:
        return False

    pcap_path = _resolve_test_pcap(name, pcap_value)

    if pcap_path is None:
        return False

    actual_signatures, error = run_suricata(pcap_path)

    if error is not None:
        logger.error(
            "Suricata test %s failed: %s",
            name,
            error,
        )
        return False

    return _compare_and_log_signatures(
        name,
        expected_signatures,
        actual_signatures,
    )


def _load_test_configuration() -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
    """Load Suricata test cases and expected alerts."""
    try:
        test_cases = load_test_cases()
        expected_alerts = load_expected_alerts()
    except CONFIG_ERRORS as exc:
        logger.error(
            "Failed to load Suricata test configuration: %s",
            exc,
        )
        return None

    if not test_cases:
        logger.error("No Suricata test cases found.")
        return None

    return test_cases, expected_alerts


def _run_all_test_cases(
    test_cases: list[dict[str, Any]],
    expected_alerts: dict[str, Any],
) -> tuple[int, int]:
    """Execute all test cases and return passed and failed counts."""
    passed = 0
    failed = 0

    for test_case in test_cases:
        if run_test_case(test_case, expected_alerts):
            passed += 1
        else:
            failed += 1

    return passed, failed


def main() -> int:
    """Run all configured Suricata tests."""
    logger.info("Starting Suricata test runner.")

    if not find_suricata():
        logger.error("Suricata is not installed or not available in PATH.")
        return 1

    if not SURICATA_RULES_DIR.exists():
        logger.error(
            "Suricata rules directory not found: %s",
            SURICATA_RULES_DIR,
        )
        return 1

    configuration = _load_test_configuration()

    if configuration is None:
        return 1

    test_cases, expected_alerts = configuration

    passed, failed = _run_all_test_cases(
        test_cases,
        expected_alerts,
    )
    total = passed + failed

    logger.info(
        "Suricata tests completed. PASS=%d FAIL=%d TOTAL=%d",
        passed,
        failed,
        total,
    )

    if failed:
        logger.error("Suricata test runner: FAIL")
        return 1

    logger.info("Suricata test runner: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
