"""Export MITRE ATT&CK detection coverage as a JSON matrix."""

from __future__ import annotations

import importlib
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MAPPING_FILE = PROJECT_ROOT / "detection-rules" / "mappings" / "mitre-mapping.yaml"

OUTPUT_FILE = PROJECT_ROOT / "reports" / "attack-matrix.json"

LOGGER = logging.getLogger("export_attack_matrix")

try:
    YAML_MODULE: Any = importlib.import_module("yaml")
except ImportError:
    YAML_MODULE = None


def configure_logging() -> None:
    """Configure application logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def load_mapping() -> dict[str, Any]:
    """Load the authoritative MITRE ATT&CK mapping YAML file."""
    if YAML_MODULE is None:
        raise RuntimeError("PyYAML is not installed. Install it with: pip install PyYAML")

    if not MAPPING_FILE.exists():
        raise FileNotFoundError(f"MITRE mapping file not found: {MAPPING_FILE}")

    with MAPPING_FILE.open("r", encoding="utf-8") as handle:
        data: Any = YAML_MODULE.safe_load(handle)

    if not isinstance(data, dict):
        raise ValueError("MITRE mapping must contain a YAML object.")

    return data


def validate_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate mapping entries and normalize their ATT&CK techniques."""
    rules = data.get("rules", [])

    if not isinstance(rules, list):
        raise ValueError("'rules' must be a YAML list.")

    validated: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()

    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"Invalid mapping entry at index {index}: " "expected an object.")

        rule_id = rule.get("rule_id")
        rule_name = rule.get("rule_name")
        techniques = rule.get("techniques", [])
        sources = rule.get("source", [])

        if not rule_id:
            raise ValueError(f"Mapping entry {index} is missing rule_id.")

        rule_id = str(rule_id).strip()

        if not rule_id:
            raise ValueError(f"Mapping entry {index} has an empty rule_id.")

        if rule_id in seen_rule_ids:
            raise ValueError(f"Duplicate mapping rule_id: {rule_id}")

        seen_rule_ids.add(rule_id)

        if not isinstance(techniques, list):
            raise ValueError(f"Techniques for {rule_id} must be a YAML list.")

        if not isinstance(sources, list):
            sources = [sources]

        normalized_techniques = sorted(
            {str(technique).strip().upper() for technique in techniques if technique and str(technique).strip()}
        )

        normalized_sources = sorted({str(source).strip() for source in sources if source and str(source).strip()})

        validated.append(
            {
                "rule_id": rule_id,
                "rule_name": str(rule_name or ""),
                "techniques": normalized_techniques,
                "source": normalized_sources,
            }
        )

    return validated


def build_matrix(
    rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build a technique-centric ATT&CK coverage matrix."""
    techniques: defaultdict[str, dict[str, Any]] = defaultdict(
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

            rule_entry = {
                "rule_id": rule["rule_id"],
                "rule_name": rule["rule_name"],
            }

            if rule_entry not in entry["rules"]:
                entry["rules"].append(rule_entry)

            for source in rule["source"]:
                if source not in entry["sources"]:
                    entry["sources"].append(source)

    matrix: list[dict[str, Any]] = []

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
    """Build ATT&CK coverage statistics."""
    total = len(matrix)

    covered = sum(1 for technique in matrix if technique["covered"])

    uncovered = total - covered

    coverage_percent = round((covered / total) * 100, 2) if total else 0.0

    total_rules = sum(technique["rule_count"] for technique in matrix)

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
    """Write the ATT&CK coverage report as JSON."""
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = {
        "schema_version": "1.0",
        "project": "security-playbooks",
        "source": str(MAPPING_FILE.relative_to(PROJECT_ROOT)),
        "summary": summary,
        "techniques": matrix,
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as handle:
        json.dump(
            report,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")

    LOGGER.info(
        "ATT&CK matrix written to: %s",
        OUTPUT_FILE,
    )


def main() -> int:
    """Run the ATT&CK matrix export process."""
    configure_logging()

    LOGGER.info("Starting ATT&CK attack matrix export.")

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
        "Export complete: %d techniques, %d covered, %d uncovered.",
        summary["total_techniques"],
        summary["covered_techniques"],
        summary["uncovered_techniques"],
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
