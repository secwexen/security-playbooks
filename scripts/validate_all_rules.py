"""Run detection-rule validation and generate a JSON validation report."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from jsonschema import (
    Draft202012Validator,
    FormatChecker,
    SchemaError,
    ValidationError,
    validate,
)

from tools.parsers.sigma_parser import (
    load_schema,
    load_sigma_rule,
    normalize_sigma_rule,
)
from tools.utils.logger import get_logger

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DETECTION_SCHEMA = PROJECT_ROOT / "schemas" / "detection_rule.schema.json"

SIGMA_RULES_DIR = PROJECT_ROOT / "detection-rules" / "sigma"

REPORTS_DIR = PROJECT_ROOT / "reports" / "validation"

JSON_REPORT = REPORTS_DIR / "validation-summary.json"

logger = get_logger(__name__)

RUNNERS = {
    "Sigma": "scripts.run_sigma_tests",
    "YARA": "scripts.run_yara_tests",
    "Suricata": "scripts.run_suricata_tests",
}


def validate_detection_rule(
    rule: dict[str, Any],
    schema: dict[str, Any],
) -> tuple[bool, str | None]:
    """Validate a normalized detection rule."""
    try:
        validate(
            instance=rule,
            schema=schema,
            format_checker=FormatChecker(),
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
        yaml.YAMLError,
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
    """Return the number of valid and invalid Sigma rules."""
    if not DETECTION_SCHEMA.is_file():
        logger.error(
            "Detection schema not found: %s",
            DETECTION_SCHEMA,
        )

        return 0, 0

    if not SIGMA_RULES_DIR.is_dir():
        logger.error(
            "Sigma rules directory not found: %s",
            SIGMA_RULES_DIR,
        )

        return 0, 0

    try:
        schema = load_schema(DETECTION_SCHEMA)

        Draft202012Validator.check_schema(schema)

    except (
        OSError,
        ValueError,
        SchemaError,
    ) as exc:
        logger.error(
            "Failed to load or validate detection schema: %s",
            exc,
        )

        return 0, 0

    rule_files = sorted(
        path for path in SIGMA_RULES_DIR.iterdir() if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
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
        if process_sigma_rule(rule_file, schema):
            valid_count += 1
        else:
            invalid_count += 1

    return valid_count, invalid_count


def run_test_runner(
    engine: str,
    module: str,
) -> dict[str, Any]:
    """Execute one test runner and validate its reported results."""
    logger.info(
        "Starting %s test runner.",
        engine,
    )

    started = time.perf_counter()

    try:
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                module,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        return_code = process.returncode
        stdout = process.stdout or ""
        stderr = process.stderr or ""

    except OSError as exc:
        return_code = 1
        stdout = ""
        stderr = str(exc)

    duration = round(
        time.perf_counter() - started,
        3,
    )

    output = "\n".join(part for part in (stdout, stderr) if part)

    test_results = []

    test_pattern = re.compile(
        rf"{re.escape(engine)} test (PASS|FAIL):\s*([^|]+)",
        re.IGNORECASE,
    )

    summary_pattern = re.compile(
        rf"{re.escape(engine)} tests completed\.\s*" r"PASS=(\d+)\s+FAIL=(\d+)\s+TOTAL=(\d+)",
        re.IGNORECASE,
    )

    reported_summary = None

    for line in output.splitlines():
        test_match = test_pattern.search(line)

        if test_match:
            test_results.append(
                {
                    "name": test_match.group(2).strip(),
                    "status": test_match.group(1).upper(),
                    "details": line.strip(),
                }
            )

        summary_match = summary_pattern.search(line)

        if summary_match:
            reported_summary = {
                "passed": int(summary_match.group(1)),
                "failed": int(summary_match.group(2)),
                "total": int(summary_match.group(3)),
            }

    passed = sum(result["status"] == "PASS" for result in test_results)

    failed = sum(result["status"] == "FAIL" for result in test_results)

    total = len(test_results)

    validation_error = None

    if return_code != 0:
        validation_error = f"Runner exited with code {return_code}."

    elif reported_summary is None:
        validation_error = "Runner summary line not found."

    elif reported_summary["total"] == 0:
        validation_error = "Runner reported zero tests."

    elif (
        reported_summary["passed"] != passed
        or reported_summary["failed"] != failed
        or reported_summary["total"] != total
    ):
        validation_error = "Runner summary does not match individual test results."

    runner_passed = validation_error is None

    result = {
        "engine": engine,
        "module": module,
        "status": "PASS" if runner_passed else "FAIL",
        "exit_code": return_code,
        "duration_seconds": duration,
        "passed": passed,
        "failed": failed,
        "total": total,
        "tests": test_results,
        "reported_summary": reported_summary,
        "validation_error": validation_error,
        "output": output,
    }

    logger.info(
        "%s runner completed: status=%s PASS=%d FAIL=%d TOTAL=%d",
        engine,
        result["status"],
        passed,
        failed,
        total,
    )

    if validation_error:
        logger.error(
            "%s runner validation error: %s",
            engine,
            validation_error,
        )

    return result


def write_reports(
    report: dict[str, Any],
) -> None:
    """Write the JSON validation report."""
    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    JSON_REPORT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    logger.info(
        "JSON report generated: %s",
        JSON_REPORT,
    )


def main() -> int:
    """Run all validation stages and generate the JSON report."""
    started = time.perf_counter()

    logger.info("Starting complete detection-rule validation.")

    # Stage 1: Sigma schema validation.
    valid_count, invalid_count = validate_all_sigma_rules()

    schema_total = valid_count + invalid_count

    schema_status = "PASS" if schema_total > 0 and invalid_count == 0 else "FAIL"

    sigma_schema = {
        "status": schema_status,
        "valid": valid_count,
        "invalid": invalid_count,
        "total": schema_total,
    }

    logger.info(
        "Sigma schema validation: %s | Valid=%d Invalid=%d Total=%d",
        schema_status,
        valid_count,
        invalid_count,
        schema_total,
    )

    # Stage 2: Detection engine test runners.
    runner_results = []

    for engine, module in RUNNERS.items():
        runner_results.append(run_test_runner(engine, module))

    # Stage 3: Aggregate results.
    all_passed = schema_status == "PASS" and all(runner["status"] == "PASS" for runner in runner_results)

    duration = round(
        time.perf_counter() - started,
        3,
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if all_passed else "FAIL",
        "duration_seconds": duration,
        "sigma_schema": sigma_schema,
        "runners": runner_results,
        "summary": {
            "sigma_rules_valid": valid_count,
            "sigma_rules_invalid": invalid_count,
            "test_passed": sum(runner["passed"] for runner in runner_results),
            "test_failed": sum(runner["failed"] for runner in runner_results),
            "test_total": sum(runner["total"] for runner in runner_results),
            "runner_count": len(runner_results),
            "runner_failures": sum(runner["status"] == "FAIL" for runner in runner_results),
        },
    }

    # Stage 4: Generate JSON report even when validation fails.
    try:
        write_reports(report)

    except OSError:
        logger.exception("Failed to write validation report.")

        return 1

    logger.info(
        "Complete validation finished: %s | Duration=%.3fs",
        report["status"],
        duration,
    )

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
