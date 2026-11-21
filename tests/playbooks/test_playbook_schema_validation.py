"""Validate playbook JSON Schema and Markdown metadata."""

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
SCHEMA_FILE: Path = PROJECT_ROOT / "schemas" / "playbook.schema.json"
PLAYBOOKS_DIR: Path = PROJECT_ROOT / "playbooks"


def load_schema() -> dict[str, Any]:
    """Load the playbook JSON Schema and validate its structure."""
    assert SCHEMA_FILE.exists(), f"Schema file not found: {SCHEMA_FILE}"

    with SCHEMA_FILE.open("r", encoding="utf-8") as handle:
        schema: dict[str, Any] = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def extract_front_matter(content: str) -> str | None:
    """Extract YAML front matter from a Markdown document."""
    content = content.strip()

    if not content.startswith("---"):
        return None

    parts = content.split("---", 2)

    if len(parts) != 3:
        return None

    front_matter = parts[1].strip()

    return front_matter or None


def test_playbook_schema_exists() -> None:
    """Verify that the playbook JSON Schema file exists."""
    assert SCHEMA_FILE.exists(), f"Schema file not found: {SCHEMA_FILE}"


def test_playbook_schema_is_valid() -> None:
    """Verify that the playbook JSON Schema is valid."""
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_playbook_files_have_machine_readable_metadata() -> None:
    """Verify that playbook Markdown files contain YAML front matter."""
    excluded_files = {
        "README.md",
        "playbook-guide.md",
    }

    playbook_files: list[Path] = [path for path in PLAYBOOKS_DIR.rglob("*.md") if path.name not in excluded_files]

    assert playbook_files, "No playbook Markdown files were found."

    missing_metadata: list[str] = []

    for playbook_file in playbook_files:
        content = playbook_file.read_text(encoding="utf-8")
        front_matter = extract_front_matter(content)

        if front_matter is None:
            missing_metadata.append(str(playbook_file))

    assert not missing_metadata, "Playbooks without front matter:\n" + "\n".join(missing_metadata)
