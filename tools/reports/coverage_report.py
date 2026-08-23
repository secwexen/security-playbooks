from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from jsonschema import validate

from tools.parsers.sigma_parser import (
    load_schema,
    load_sigma_rule,
    normalize_sigma_rule,
)
from tools.utils.logger import get_logger


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SIGMA_RULES_DIR = (
    PROJECT_ROOT
    / "detection-rules"
    / "sigma"
)

DETECTION_SCHEMA = (
    PROJECT_ROOT
    / "schemas"
    / "detection_rule.schema.json"
)

MAPPINGS_DIR = (
    PROJECT_ROOT
    / "detection-rules"
    / "mappings"
)

MITRE_MAPPING = (
    MAPPINGS_DIR
    / "mitre-mapping.yaml"
)

COVERAGE_REPORT = (
    MAPPINGS_DIR
    / "coverage_report.json"
)

ATTACK_COVERAGE = (
    MAPPINGS_DIR
    / "attack-coverage.json"
)

RULE_COVERAGE_MAP = (
    MAPPINGS_DIR
    / "rule_coverage_map.json"
)

logger = get_logger(__name__)


def load_json(path: Path) -> Any:
    """Load JSON from disk."""
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def save_json(
    path: Path,
    data: Any,
) -> None:
    """Save JSON to disk."""
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")


def load_mitre_mapping() -> dict[str, list[str]]:
    """
    Load MITRE rule mappings.

    Expected YAML structure:

    rules:
      - rule_id: ...
        rule_name: ...
        techniques:
          - T1059
        source:
          - ...
    """
    if not MITRE_MAPPING.exists():
        logger.warning(
            "MITRE mapping file not found: %s",
            MITRE_MAPPING,
        )
        return {}

    with MITRE_MAPPING.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError(
            "MITRE mapping must be a YAML object."
        )

    rules = data.get(
        "rules",
        [],
    )

    if not isinstance(rules, list):
        raise ValueError(
            "MITRE mapping 'rules' must be a list."
        )

    mapping: dict[str, list[str]] = {}

    for entry in rules:
        if not isinstance(
            entry,
            dict,
        ):
            continue

        rule_id = str(
            entry.get("rule_id", "")
        ).strip()

        if not rule_id:
            continue

        techniques = entry.get(
            "techniques",
            [],
        )

        if not isinstance(
            techniques,
            list,
        ):
            continue

        normalized_techniques = sorted(
            {
                str(technique)
                .strip()
                .upper()
                for technique in techniques
                if str(technique).strip()
            }
        )

        mapping[rule_id] = (
            normalized_techniques
        )

    return mapping


def collect_sigma_rules() -> list[dict[str, Any]]:
    """Load and normalize all Sigma rules."""
    if not SIGMA_RULES_DIR.exists():
        logger.warning(
            "Sigma rules directory not found: %s",
            SIGMA_RULES_DIR,
        )
        return []

    if not DETECTION_SCHEMA.exists():
        logger.error(
            "Detection schema not found: %s",
            DETECTION_SCHEMA,
        )
        return []

    schema = load_schema(
        DETECTION_SCHEMA
    )

    rules: list[dict[str, Any]] = []

    for rule_file in sorted(
        SIGMA_RULES_DIR.glob("*.yml")
    ):
        try:
            sigma_rule = load_sigma_rule(
                rule_file
            )

            normalized = normalize_sigma_rule(
                sigma_rule,
                rule_file,
            )

            validate(
                instance=normalized,
                schema=schema,
            )

        except (
            OSError,
            ValueError,
        ) as exc:
            logger.error(
                "Unable to process %s: %s",
                rule_file,
                exc,
            )
            continue

        except Exception as exc:
            logger.error(
                "Invalid normalized rule %s: %s",
                rule_file,
                exc,
            )
            continue

        rules.append(
            normalized
        )

    return rules


def build_rule_coverage_map(
    rules: list[dict[str, Any]],
    mitre_mapping: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Map MITRE techniques to detection rule IDs."""
    mapping: dict[str, list[str]] = {}

    for rule in rules:
        rule_id = str(
            rule.get("id", "")
        ).strip()

        if not rule_id:
            continue

        techniques = mitre_mapping.get(
            rule_id,
            rule.get(
                "mitre_attack",
                [],
            ),
        )

        if not isinstance(
            techniques,
            list,
        ):
            continue

        for technique in techniques:
            normalized = (
                str(technique)
                .strip()
                .upper()
            )

            if not normalized:
                continue

            mapping.setdefault(
                normalized,
                [],
            )

            if rule_id not in mapping[
                normalized
            ]:
                mapping[
                    normalized
                ].append(rule_id)

    for technique in mapping:
        mapping[technique].sort()

    return dict(
        sorted(
            mapping.items()
        )
    )


def build_coverage_report(
    rules: list[dict[str, Any]],
    mitre_mapping: dict[str, list[str]],
) -> dict[str, Any]:
    """Build an ATT&CK detection coverage report."""
    rule_map = build_rule_coverage_map(
        rules,
        mitre_mapping,
    )

    technique_counter = Counter()

    for technique, rule_ids in rule_map.items():
        technique_counter[
            technique
        ] = len(rule_ids)

    mapped_rule_ids = {
        rule_id
        for rule_ids in rule_map.values()
        for rule_id in rule_ids
    }

    covered_techniques = sorted(
        rule_map.keys()
    )

    report = {
        "total_rules": len(rules),
        "total_mapped_rules": len(
            mapped_rule_ids
        ),
        "total_unmapped_rules": max(
            0,
            len(rules)
            - len(mapped_rule_ids),
        ),
        "total_techniques_covered": len(
            covered_techniques
        ),
        "techniques": {
            technique: {
                "detection_count": (
                    technique_counter[
                        technique
                    ]
                ),
                "rules": rule_map[
                    technique
                ],
            }
            for technique in covered_techniques
        },
    }

    return report


def generate_reports(
    rules: list[dict[str, Any]],
    mitre_mapping: dict[str, list[str]],
) -> None:
    """Generate all coverage JSON outputs."""
    rule_map = build_rule_coverage_map(
        rules,
        mitre_mapping,
    )

    report = build_coverage_report(
        rules,
        mitre_mapping,
    )

    attack_coverage = {
        "covered_techniques": sorted(
            rule_map.keys()
        ),
        "total_techniques": len(
            rule_map
        ),
    }

    rule_coverage = {
        rule_id: {
            "techniques": sorted(
                techniques
            ),
            "technique_count": len(
                techniques
            ),
        }
        for rule_id, techniques
        in _build_rule_to_techniques(
            rule_map
        ).items()
    }

    save_json(
        RULE_COVERAGE_MAP,
        rule_coverage,
    )

    save_json(
        ATTACK_COVERAGE,
        attack_coverage,
    )

    save_json(
        COVERAGE_REPORT,
        report,
    )

    logger.info(
        "Coverage reports generated. "
        "Rules=%d Mapped=%d Techniques=%d",
        report["total_rules"],
        report["total_mapped_rules"],
        report[
            "total_techniques_covered"
        ],
    )


def _build_rule_to_techniques(
    rule_map: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Invert technique -> rules into rule -> techniques."""
    result: dict[str, list[str]] = {}

    for technique, rule_ids in rule_map.items():
        for rule_id in rule_ids:
            result.setdefault(
                rule_id,
                [],
            )
            result[
                rule_id
            ].append(technique)

    for rule_id in result:
        result[rule_id] = sorted(
            set(
                result[rule_id]
            )
        )

    return dict(
        sorted(
            result.items()
        )
    )


def main() -> None:
    """Generate MITRE ATT&CK coverage reports."""
    logger.info(
        "Starting coverage report generation."
    )

    try:
        mitre_mapping = (
            load_mitre_mapping()
        )

        rules = collect_sigma_rules()

    except (
        OSError,
        ValueError,
        yaml.YAMLError,
    ) as exc:
        logger.error(
            "Coverage generation failed: %s",
            exc,
        )
        return

    if not rules:
        logger.warning(
            "No valid Sigma rules available "
            "for coverage analysis."
        )
        return

    if not mitre_mapping:
        logger.warning(
            "MITRE mapping is empty. "
            "Coverage will contain zero mapped techniques."
        )

    generate_reports(
        rules,
        mitre_mapping,
    )

    logger.info(
        "Coverage report generation completed."
    )


if __name__ == "__main__":
    main()
