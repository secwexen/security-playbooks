"""Generate MITRE ATT&CK coverage reports from the detection registry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from tools.utils.logger import get_logger

PROJECT_ROOT = Path(__file__).resolve().parents[2]

REGISTRY_FILE = PROJECT_ROOT / "detection-rules" / "registry.yaml"
MITRE_MAPPING = (
    PROJECT_ROOT
    / "detection-rules"
    / "mappings"
    / "mitre-mapping.yaml"
)

MAPPINGS_DIR = PROJECT_ROOT / "detection-rules" / "mappings"

COVERAGE_REPORT = MAPPINGS_DIR / "coverage-report.json"
ATTACK_COVERAGE = MAPPINGS_DIR / "attack-coverage.json"
RULE_COVERAGE_MAP = MAPPINGS_DIR / "rule-coverage-map.json"

logger = get_logger(__name__)


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file and validate its root structure."""
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError(f"Expected a YAML object: {path}")

    return data


def save_json(path: Path, data: Any) -> None:
    """Save JSON data and create parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)
        file.write("\n")


def load_registry_rules() -> list[dict[str, str]]:
    """Load all detection rules from the authoritative registry."""
    registry = load_yaml(REGISTRY_FILE)
    entries = registry.get("rules")

    if not isinstance(entries, list):
        raise ValueError("Registry 'rules' must be a list.")

    rules: list[dict[str, str]] = []
    seen_ids: set[str] = set()

    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Registry contains an invalid rule entry.")

        registry_id = str(entry.get("id", "")).strip()
        name = str(entry.get("name", "")).strip()
        rule_format = str(entry.get("format", "")).strip().lower()

        if not registry_id:
            raise ValueError("Registry rule has an empty ID.")

        if registry_id in seen_ids:
            raise ValueError(f"Duplicate registry ID: {registry_id}")

        if not name or not rule_format:
            raise ValueError(
                f"Registry rule has missing name or format: {registry_id}"
            )

        seen_ids.add(registry_id)

        rules.append(
            {
                "registry_id": registry_id,
                "rule_name": name,
                "format": rule_format,
            }
        )

    return rules


def load_mitre_mapping() -> dict[str, list[str]]:
    """Load ATT&CK mappings indexed by registry_id."""
    data = load_yaml(MITRE_MAPPING)
    entries = data.get("rules")

    if not isinstance(entries, list):
        raise ValueError("MITRE mapping 'rules' must be a list.")

    mapping: dict[str, list[str]] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("MITRE mapping contains an invalid entry.")

        registry_id = str(entry.get("registry_id", "")).strip()

        if not registry_id:
            raise ValueError("MITRE mapping entry has no registry_id.")

        if registry_id in mapping:
            raise ValueError(
                f"Duplicate mapping registry_id: {registry_id}"
            )

        techniques = entry.get("techniques", [])

        if not isinstance(techniques, list):
            raise ValueError(
                f"Techniques must be a list: {registry_id}"
            )

        normalized = []

        for technique in techniques:
            technique_id = str(technique).strip().upper()

            if technique_id:
                normalized.append(technique_id)

        mapping[registry_id] = sorted(set(normalized))

    return mapping


def build_rule_coverage_map(
    rules: list[dict[str, str]],
    mitre_mapping: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Create a complete registry rule-to-techniques mapping."""
    registry_ids = {
        rule["registry_id"]
        for rule in rules
    }

    unknown_ids = set(mitre_mapping) - registry_ids

    if unknown_ids:
        raise ValueError(
            "MITRE mapping contains unknown registry IDs: "
            + ", ".join(sorted(unknown_ids))
        )

    return {
        rule["registry_id"]: mitre_mapping.get(
            rule["registry_id"],
            [],
        )
        for rule in rules
    }


def build_technique_coverage(
    rule_map: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Create a technique-to-registry-rules mapping."""
    technique_map: dict[str, list[str]] = {}

    for registry_id, techniques in rule_map.items():
        for technique in techniques:
            technique_map.setdefault(technique, [])
            technique_map[technique].append(registry_id)

    return {
        technique: sorted(registry_ids)
        for technique, registry_ids in sorted(technique_map.items())
    }


def build_coverage_report(
    rules: list[dict[str, str]],
    rule_map: dict[str, list[str]],
    technique_map: dict[str, list[str]],
) -> dict[str, Any]:
    """Build the complete repository coverage report."""
    report_rules = []

    for rule in rules:
        registry_id = rule["registry_id"]
        techniques = rule_map[registry_id]

        report_rules.append(
            {
                "registry_id": registry_id,
                "rule_name": rule["rule_name"],
                "format": rule["format"],
                "mapped": bool(techniques),
                "techniques": techniques,
                "technique_count": len(techniques),
            }
        )

    mapped_rules = sum(
        bool(techniques)
        for techniques in rule_map.values()
    )

    return {
        "schema_version": "1.0.0",
        "project": "Security Playbooks",
        "coverage_scope": (
            "Repository mapping dataset only. "
            "This report does not represent full ATT&CK Enterprise coverage."
        ),
        "summary": {
            "total_rules": len(rules),
            "mapped_rules": mapped_rules,
            "unmapped_rules": len(rules) - mapped_rules,
            "total_mapped_techniques": len(technique_map),
        },
        "rules": report_rules,
        "techniques": {
            technique: {
                "rule_count": len(registry_ids),
                "rules": registry_ids,
            }
            for technique, registry_ids in technique_map.items()
        },
    }


def build_attack_coverage(
    technique_map: dict[str, list[str]],
) -> dict[str, Any]:
    """Build the ATT&CK coverage output for mapped techniques."""
    return {
        "summary": {
            "mapped_techniques": len(technique_map),
            "coverage_scope": "repository_mapping_dataset",
        },
        "techniques": [
            {
                "technique_id": technique,
                "covered": True,
                "rule_count": len(registry_ids),
                "rules": registry_ids,
            }
            for technique, registry_ids in technique_map.items()
        ],
    }


def build_rule_coverage_output(
    rule_map: dict[str, list[str]],
) -> dict[str, Any]:
    """Build rule coverage output including unmapped rules."""
    return {
        registry_id: {
            "techniques": techniques,
            "technique_count": len(techniques),
        }
        for registry_id, techniques in rule_map.items()
    }


def generate_reports() -> None:
    """Generate all coverage reports from registry and mapping sources."""
    rules = load_registry_rules()
    mitre_mapping = load_mitre_mapping()

    rule_map = build_rule_coverage_map(
        rules,
        mitre_mapping,
    )

    technique_map = build_technique_coverage(rule_map)

    report = build_coverage_report(
        rules,
        rule_map,
        technique_map,
    )

    attack_coverage = build_attack_coverage(technique_map)

    rule_coverage = build_rule_coverage_output(rule_map)

    save_json(COVERAGE_REPORT, report)
    save_json(ATTACK_COVERAGE, attack_coverage)
    save_json(RULE_COVERAGE_MAP, rule_coverage)

    summary = report["summary"]

    logger.info(
    "Coverage reports generated. Rules=%d Mapped=%d Unmapped=%d Techniques=%d",
    summary["total_rules"],
    summary["mapped_rules"],
    summary["unmapped_rules"],
    summary["total_mapped_techniques"],
)


def main() -> None:
    """Run coverage report generation."""
    logger.info("Starting coverage report generation.")

    try:
        generate_reports()
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logger.error("Coverage report generation failed: %s", exc)
        return

    logger.info("Coverage report generation completed.")


if __name__ == "__main__":
    main()
