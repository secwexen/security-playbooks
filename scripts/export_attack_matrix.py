from __future__ import annotations

import json
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None


PROJECT_ROOT = Path(__file__).resolve().parent.parent

MAPPING_FILE = (
    PROJECT_ROOT
    / "detection-rules"
    / "mappings"
    / "mitre-mapping.yaml"
)

OUTPUT_FILE = PROJECT_ROOT / "reports" / "attack-matrix.json"

LOGGER = logging.getLogger("export_attack_matrix")


def configure_logging() -> None:
    """Configure logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def load_mapping() -> dict[str, Any]:
    """Load the MITRE mapping YAML file."""
    if yaml is None:
        raise RuntimeError(
            "PyYAML is not installed. "
            "Install it with: pip install PyYAML"
        )

    if not MAPPING_FILE.exists():
        raise FileNotFoundError(
            f"MITRE mapping file not found: {MAPPING_FILE}"
        )

    with MAPPING_FILE.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        raise ValueError("MITRE mapping must contain a YAML object.")

    return data


def validate_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate and return the rules section."""
    rules = data.get("rules", [])

    if not isinstance(rules, list):
        raise ValueError("'rules' must be a YAML list.")

    validated: list[dict[str, Any]] = []

    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            LOGGER.warning("Skipping invalid rule at index %d.", index)
            continue

        rule_id = rule.get("rule_id")
        rule_name = rule.get("rule_name")
        techniques = rule.get("techniques", [])
        sources = rule.get("source", [])

        if not rule_id:
            LOGGER.warning(
                "Skipping rule %d: missing rule_id.",
                index,
            )
            continue

        if not rule_name:
            LOGGER.warning(
                "Rule %s has no rule_name.",
                rule_id,
            )

        if not isinstance(techniques, list):
            techniques = [techniques]

        if not isinstance(sources, list):
            sources = [sources]

        validated.append(
            {
                "rule_id": str(rule_id),
                "rule_name": str(rule_name or ""),
                "techniques": [
                    str(technique)
                    for technique in techniques
                    if technique
                ],
                "source": [
                    str(source)
                    for source in sources
                    if source
                ],
            }
        )

    return validated


def build_matrix(
    rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a technique-centric ATT&CK matrix."""
    techniques: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "technique_id": "",
            "rules": [],
            "sources": [],
        }
    )

    for rule in rules:
        for technique_id in rule["techniques"]:
            entry = techniques[technique_id]

            entry["technique_id"] = technique_id

            entry["rules"].append(
                {
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["rule_name"],
                }
            )

            for source in rule["source"]:
                if source not in entry["sources"]:
                    entry["sources"].append(source)

    matrix = []

    for technique_id, entry in techniques.items():
        matrix.append(
            {
                "technique_id": technique_id,
                "covered": bool(entry["rules"]),
                "rule_count": len(entry["rules"]),
                "rules": entry["rules"],
                "sources": sorted(entry["sources"]),
            }
        )

    return sorted(
        matrix,
        key=lambda item: item["technique_id"],
    )


def build_summary(
    matrix: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build coverage statistics."""
    total = len(matrix)

    covered = sum(
        1
        for technique in matrix
        if technique["covered"]
    )

    uncovered = total - covered

    coverage_percent = (
        round((covered / total) * 100, 2)
        if total
        else 0.0
    )

    total_rules = sum(
        technique["rule_count"]
        for technique in matrix
    )

    return {
        "total_techniques": total,
        "covered_techniques": covered,
        "uncovered_techniques": uncovered,
        "coverage_percent": coverage_percent,
        "total_rule_mappings": total_rules,
    }


def write_report(
    matrix: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    """Write the attack matrix report."""
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = {
        "schema_version": "1.0",
        "project": "security-playbooks",
        "source": str(
            MAPPING_FILE.relative_to(PROJECT_ROOT)
        ),
        "summary": summary,
        "techniques": matrix,
    }

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            report,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")

    LOGGER.info(
        "Attack matrix written to: %s",
        OUTPUT_FILE,
    )


def main() -> int:
    """Run the export."""
    configure_logging()

    LOGGER.info(
        "Starting ATT&CK attack matrix export."
    )

    try:
        data = load_mapping()
        rules = validate_rules(data)
        matrix = build_matrix(rules)
        summary = build_summary(matrix)

        write_report(matrix, summary)

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        OSError,
    ) as exc:
        LOGGER.error("%s", exc)
        return 1

    LOGGER.info(
        "Export complete: %d techniques, "
        "%d covered, %d uncovered.",
        summary["total_techniques"],
        summary["covered_techniques"],
        summary["uncovered_techniques"],
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
