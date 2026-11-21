"""Validate Security Playbooks Markdown files and catalog entries."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS_DIR = PROJECT_ROOT / "playbooks"
CATALOG_FILE = PLAYBOOKS_DIR / "catalog.yaml"

REQUIRED_FIELDS = {
    "name",
    "id",
    "description",
    "severity",
    "tactic",
}

VALID_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}

VALID_STATUSES = {
    "draft",
    "active",
    "deprecated",
}

VALID_TACTICS = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
    "response",
    "triage",
    "stealth",
}

FRONTMATTER_PATTERN = re.compile(
    r"\A---\s*\n(.*?)\n---(?:\s*\n|\Z)",
    re.DOTALL,
)


class PlaybookValidationError(Exception):
    """Represent a playbook validation failure."""


def load_yaml_file(path: Path) -> Any:
    """Load YAML data from a file."""
    try:
        with path.open("r", encoding="utf-8") as file:
            return yaml.safe_load(file)
    except (OSError, yaml.YAMLError) as exc:
        raise PlaybookValidationError(f"Unable to load YAML file '{path}': {exc}") from exc


def discover_playbooks() -> list[Path]:
    """Discover Markdown playbooks recursively."""
    if not PLAYBOOKS_DIR.is_dir():
        raise PlaybookValidationError(f"Playbooks directory does not exist: {PLAYBOOKS_DIR}")

    return sorted(
        path
        for path in PLAYBOOKS_DIR.rglob("*.md")
        if path.name.lower() != "readme.md" and path.name.lower() != "index.md"
    )


def extract_frontmatter(path: Path) -> dict[str, Any]:
    """Extract YAML frontmatter from a Markdown playbook."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlaybookValidationError(f"Unable to read playbook '{path}': {exc}") from exc

    match = FRONTMATTER_PATTERN.search(content)

    if match is None:
        raise PlaybookValidationError("Missing YAML frontmatter.")

    try:
        metadata = yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:
        raise PlaybookValidationError(f"Invalid YAML frontmatter: {exc}") from exc

    if not isinstance(metadata, dict):
        raise PlaybookValidationError("Frontmatter must contain a YAML mapping.")

    return metadata


def validate_required_fields(
    metadata: dict[str, Any],
) -> list[str]:
    """Validate required metadata fields."""
    errors: list[str] = []

    missing_fields = REQUIRED_FIELDS - metadata.keys()

    if missing_fields:
        errors.append(f"Missing required fields: {', '.join(sorted(missing_fields))}")

    for field in REQUIRED_FIELDS.intersection(metadata):
        value = metadata[field]

        if value is None or not str(value).strip():
            errors.append(f"Required field '{field}' cannot be empty.")

    return errors


def validate_severity(metadata: dict[str, Any]) -> list[str]:
    """Validate playbook severity."""
    severity = metadata.get("severity")

    if severity is None:
        return []

    if not isinstance(severity, str):
        return ["Severity must be a string."]

    if severity.lower() not in VALID_SEVERITIES:
        return [f"Invalid severity '{severity}'. " f"Allowed values: {', '.join(sorted(VALID_SEVERITIES))}"]

    return []


def validate_tactic(metadata: dict[str, Any]) -> list[str]:
    """Validate the MITRE ATT&CK tactic."""
    tactic = metadata.get("tactic")

    if tactic is None:
        return []

    if not isinstance(tactic, str):
        return ["Tactic must be a string."]

    if tactic.lower() not in VALID_TACTICS:
        return [f"Unknown tactic '{tactic}'. " "Check the project's supported tactic definitions."]

    return []


def validate_status(metadata: dict[str, Any]) -> list[str]:
    """Validate optional playbook status."""
    status = metadata.get("status")

    if status is None:
        return []

    if not isinstance(status, str):
        return ["Status must be a string."]

    if status.lower() not in VALID_STATUSES:
        return [f"Invalid status '{status}'. " f"Allowed values: {', '.join(sorted(VALID_STATUSES))}"]

    return []


def validate_playbook(path: Path) -> list[str]:
    """Validate an individual Markdown playbook."""
    errors: list[str] = []

    try:
        metadata = extract_frontmatter(path)

        errors.extend(validate_required_fields(metadata))
        errors.extend(validate_severity(metadata))
        errors.extend(validate_tactic(metadata))
        errors.extend(validate_status(metadata))

    except PlaybookValidationError as exc:
        errors.append(str(exc))

    return errors


def load_catalog() -> list[dict[str, Any]]:
    """Load and validate the playbook catalog structure."""
    if not CATALOG_FILE.is_file():
        raise PlaybookValidationError(f"Playbook catalog does not exist: {CATALOG_FILE}")

    catalog = load_yaml_file(CATALOG_FILE)

    entries: Any

    if isinstance(catalog, list):
        entries = catalog

    elif isinstance(catalog, dict):
        entries = catalog.get("playbooks")

        if entries is None:
            raise PlaybookValidationError("Catalog must contain a 'playbooks' list.")

    else:
        raise PlaybookValidationError("Catalog must be a YAML list or mapping.")

    if not isinstance(entries, list):
        raise PlaybookValidationError("Catalog 'playbooks' field must be a list.")

    if not all(isinstance(entry, dict) for entry in entries):
        raise PlaybookValidationError("Every catalog entry must be a YAML mapping.")

    return entries


def validate_catalog(
    playbook_files: list[Path],
) -> list[str]:
    """Validate catalog entries and their Markdown references."""
    errors: list[str] = []

    try:
        entries = load_catalog()
    except PlaybookValidationError as exc:
        return [str(exc)]

    known_ids: set[str] = set()
    known_paths = {path.resolve() for path in playbook_files}

    for index, entry in enumerate(entries, start=1):
        playbook_id = entry.get("id")

        if not isinstance(playbook_id, str) or not playbook_id.strip():
            errors.append(f"Catalog entry #{index}: missing or invalid ID.")
            continue

        if playbook_id in known_ids:
            errors.append(f"Catalog entry #{index}: duplicate ID '{playbook_id}'.")

        known_ids.add(playbook_id)

        reference = entry.get("path")

        if not isinstance(reference, str) or not reference.strip():
            errors.append(f"Catalog entry '{playbook_id}': missing path.")
            continue

        resolved_path = (PLAYBOOKS_DIR / reference).resolve()

        if not resolved_path.is_relative_to(PLAYBOOKS_DIR.resolve()):
            errors.append(f"Catalog entry '{playbook_id}': path escapes playbooks directory.")
            continue

        if resolved_path not in known_paths:
            errors.append(f"Catalog entry '{playbook_id}': " f"playbook file not found: {reference}")

    return errors


def main() -> int:
    """Run playbook validation and return an exit status."""
    print("Starting playbook validation...")

    try:
        playbook_files = discover_playbooks()
    except PlaybookValidationError as exc:
        print(f"[ERROR] {exc}")
        return 1

    if not playbook_files:
        print("[WARNING] No Markdown playbooks found.")
        return 0

    valid_count = 0
    invalid_count = 0

    for path in playbook_files:
        errors = validate_playbook(path)
        relative_path = path.relative_to(PROJECT_ROOT)

        if errors:
            invalid_count += 1
            print(f"[FAIL] {relative_path}")

            for error in errors:
                print(f"       - {error}")
        else:
            valid_count += 1
            print(f"[PASS] {relative_path}")

    catalog_errors = validate_catalog(playbook_files)

    if catalog_errors:
        print("\nCatalog validation failed:")

        for error in catalog_errors:
            print(f"[FAIL] {error}")

    else:
        print("[PASS] Playbook catalog validation")

    print("\nValidation summary")
    print("------------------")
    print(f"Total playbooks: {len(playbook_files)}")
    print(f"Valid playbooks: {valid_count}")
    print(f"Invalid playbooks: {invalid_count}")
    print(f"Catalog errors: {len(catalog_errors)}")

    if invalid_count or catalog_errors:
        print("\n[FAIL] Playbook validation failed.")
        return 1

    print("\n[SUCCESS] All playbooks passed validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
