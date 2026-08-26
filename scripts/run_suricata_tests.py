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
    """Normalize supported Suricata test-case layouts."""
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
            f"Suricata test file not found: {TEST_CASES_FILE}"
        )

    data = load_yaml(TEST_CASES_FILE)

    return normalize_test_cases(data)


def load_expected_alerts() -> dict[str, Any]:
    """Load expected Suricata alerts."""
    if not EXPECTED_ALERTS_FILE.exists():
        raise FileNotFoundError(
            f"Expected Suricata alerts file not found: "
            f"{EXPECTED_ALERTS_FILE}"
        )

    data = load_json(EXPECTED_ALERTS_FILE)

    if not isinstance(data, dict):
        raise ValueError(
            "expected_alerts.json must contain a JSON object."
        )

    return data


def find_suricata() -> str | None:
    """Return the Suricata executable path."""
    return shutil.which("suricata")


def collect_rule_files() -> list[Path]:
    """Collect repository Suricata rule files."""
    if not SURICATA_RULES_DIR.exists():
        return []

    return sorted(
        SURICATA_RULES_DIR.glob("*.rules")
    )


def normalize_suricata_rule(
    raw_rule: str,
) -> str:
    """
    Normalize one multiline Suricata rule into one line.

    Source rule files may stay readable/multiline.
    The generated rules file is normalized for the
    target Suricata parser.
    """
    rule = raw_rule.strip()

    if not rule:
        return ""

    # Collapse all whitespace while preserving quoted strings.
    rule = re.sub(
        r"\s+",
        " ",
        rule,
    ).strip()

    return rule


def extract_suricata_rules(
    content: str,
) -> list[str]:
    """
    Extract complete Suricata signatures from a rule file.

    A signature starts with alert/pass/drop/reject and
    ends at the matching closing parenthesis.
    Comments and empty lines are ignored.
    """
    rules: list[str] = []
    current: list[str] = []
    depth = 0

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if not current:
            if not re.match(
                r"^(alert|pass|drop|reject)\b",
                line,
                flags=re.IGNORECASE,
            ):
                continue

        current.append(line)

        depth += line.count("(")
        depth -= line.count(")")

        if current and depth == 0:
            normalized = normalize_suricata_rule(
                " ".join(current)
            )

            if normalized:
                rules.append(normalized)

            current = []

    if current:
        normalized = normalize_suricata_rule(
            " ".join(current)
        )

        if normalized:
            rules.append(normalized)

    return rules


def build_combined_rules_file(
    destination: Path,
) -> tuple[Path | None, int]:
    """
    Combine and normalize all repository rules.

    Returns:
        (generated_rules_path, rule_count)
    """
    rule_files = collect_rule_files()

    if not rule_files:
        return None, 0

    generated_rules: list[str] = []

    for rule_file in rule_files:
        try:
            content = rule_file.read_text(
                encoding="utf-8"
            )
        except OSError as exc:
            raise RuntimeError(
                f"Unable to read rule file "
                f"{rule_file}: {exc}"
            ) from exc

        generated_rules.extend(
            extract_suricata_rules(content)
        )

    if not generated_rules:
        return None, 0

    destination.write_text(
        "\n".join(generated_rules) + "\n",
        encoding="utf-8",
    )

    return destination, len(generated_rules)


def resolve_pcap(
    value: str,
) -> Path:
    """Resolve a PCAP path."""
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
    """Normalize expected alert signatures."""
    if value is None:
        return []

    if isinstance(value, str):
        return [value]

    if isinstance(value, list):
        return [
            str(item)
            for item in value
        ]

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
                return [
                    str(item)
                    for item in nested
                ]

    return []


def collect_alert_signatures(
    output_dir: Path,
) -> list[str]:
    """Collect unique alert signatures from eve.json."""
    eve_path = output_dir / "eve.json"

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
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get(
                "alert",
                {},
            )

            if not isinstance(alert, dict):
                continue

            signature = alert.get("signature")

            if signature:
                signatures.append(
                    str(signature)
                )

    return sorted(set(signatures))


def collect_engine_stats(
    output_dir: Path,
) -> tuple[int | None, int | None]:
    """
    Extract rules_loaded and alert count from eve.json.
    """
    eve_path = output_dir / "eve.json"

    if not eve_path.exists():
        return None, None

    rules_loaded: int | None = None
    alerts: int | None = None

    with eve_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "stats":
                continue

            stats = event.get(
                "stats",
                {},
            )

            if not isinstance(stats, dict):
                continue

            detect = stats.get(
                "detect",
                {},
            )

            if isinstance(detect, dict):
                engines = detect.get(
                    "engines",
                    [],
                )

                if isinstance(engines, list):
                    loaded_values = [
                        engine.get("rules_loaded")
                        for engine in engines
                        if isinstance(engine, dict)
                        and isinstance(
                            engine.get("rules_loaded"),
                            int,
                        )
                    ]

                    if loaded_values:
                        rules_loaded = sum(
                            loaded_values
                        )

                alert_value = detect.get("alert")

                if isinstance(
                    alert_value,
                    int,
                ):
                    alerts = alert_value

    return rules_loaded, alerts


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

    if not pcap_path.is_file():
        return (
            [],
            f"PCAP is not a file: {pcap_path}",
        )

    with tempfile.TemporaryDirectory(
        prefix="security_playbooks_suricata_"
    ) as temporary_directory:

        temporary_path = Path(
            temporary_directory
        )

        output_dir = (
            temporary_path / "output"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        rules_path = (
            temporary_path
            / "security_playbooks.rules"
        )

        try:
            combined_rules, rule_count = (
                build_combined_rules_file(
                    rules_path
                )
            )
        except (
            OSError,
            RuntimeError,
        ) as exc:
            return (
                [],
                str(exc),
            )

        if combined_rules is None:
            return (
                [],
                "no valid repository Suricata rules found",
            )

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

        stderr = process.stderr.strip()
        stdout = process.stdout.strip()

        # Suricata can emit warnings/errors while still
        # returning success. Treat rule parser failures as
        # test-runner failures explicitly.
        combined_output = (
            f"{stdout}\n{stderr}"
        )

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
                return (
                    [],
                    (
                        f"Suricata validation failed: {marker}"
                    ),
                )

        if process.returncode != 0:
            return (
                [],
                (
                    stderr
                    or stdout
                    or "Suricata exited with an error."
                ),
            )

        rules_loaded, _alerts = (
            collect_engine_stats(
                output_dir
            )
        )

        if rules_loaded is not None and rules_loaded < rule_count:
            return (
                [],
                (
                    "Suricata loaded fewer rules than "
                    f"generated: loaded={rules_loaded} "
                    f"generated={rule_count}"
                ),
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

    expected_entry = expected_alerts.get(
        name
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

    total = passed + failed

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
