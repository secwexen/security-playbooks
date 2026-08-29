import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_FILE = (
    PROJECT_ROOT
    / "schemas"
    / "playbook.schema.json"
)

PLAYBOOKS_DIR = PROJECT_ROOT / "playbooks"


def load_schema():
    assert SCHEMA_FILE.exists()

    with SCHEMA_FILE.open(
        "r",
        encoding="utf-8",
    ) as handle:
        schema = json.load(handle)

    Draft202012Validator.check_schema(schema)

    return schema


def extract_front_matter(content):
    content = content.strip()

    if not content.startswith("---"):
        return None

    parts = content.split("---", 2)

    if len(parts) != 3:
        return None

    return parts[1].strip()


def test_playbook_schema_exists():
    assert SCHEMA_FILE.exists()


def test_playbook_schema_is_valid():
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema.get("$schema")


def test_playbook_files_have_machine_readable_metadata():
    playbook_files = [
        path
        for path in PLAYBOOKS_DIR.rglob("*.md")
        if path.name not in {
            "README.md",
            "playbook-guide.md",
        }
    ]

    assert playbook_files

    missing_metadata = []

    for playbook_file in playbook_files:
        content = playbook_file.read_text(
            encoding="utf-8"
        )

        front_matter = extract_front_matter(content)

        if not front_matter:
            missing_metadata.append(
                str(playbook_file)
            )

    assert not missing_metadata, (
        "Playbooks without front matter:\n"
        + "\n".join(missing_metadata)
    )
