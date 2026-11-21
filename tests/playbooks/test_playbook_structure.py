"""Tests for the structure and organization of playbook files."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOKS_DIR = PROJECT_ROOT / "playbooks"
DOCS_DIR = PROJECT_ROOT / "docs"

EXPECTED_DIRECTORIES = [
    "cloud",
    "collection",
    "command-and-control",
    "credential-access",
    "defense-impairment",
    "discovery",
    "execution",
    "exfiltration",
    "impact",
    "initial-access",
    "lateral-movement",
    "persistence",
    "privilege-escalation",
    "reconnaissance",
    "resource-development",
    "response",
    "stealth",
    "triage",
]

EXPECTED_FILES = [
    "README.md",
]


def test_playbooks_directory_exists() -> None:
    """Verify that the main playbooks directory exists."""
    assert PLAYBOOKS_DIR.exists()
    assert PLAYBOOKS_DIR.is_dir()


def test_playbook_guide_exists() -> None:
    """Verify that the playbook guide exists in the documentation directory."""
    guide = DOCS_DIR / "playbooks" / "playbook-guide.md"

    assert guide.exists(), f"Missing playbook guide: {guide}"
    assert guide.is_file(), f"Not a file: {guide}"


def test_expected_playbook_directories_exist() -> None:
    """Verify that all expected playbook category directories exist."""
    for directory in EXPECTED_DIRECTORIES:
        path = PLAYBOOKS_DIR / directory

        assert path.exists(), f"Missing playbook directory: {path}"
        assert path.is_dir(), f"Not a directory: {path}"


def test_expected_root_files_exist() -> None:
    """Verify that all expected root-level playbook files exist."""
    for filename in EXPECTED_FILES:
        path = PLAYBOOKS_DIR / filename

        assert path.exists(), f"Missing playbook file: {path}"
        assert path.is_file(), f"Not a file: {path}"


def test_playbook_categories_contain_markdown_files() -> None:
    """Verify that each expected category contains Markdown files."""
    for directory in EXPECTED_DIRECTORIES:
        category_dir = PLAYBOOKS_DIR / directory
        markdown_files = list(category_dir.glob("*.md"))

        assert markdown_files, f"No Markdown playbooks found in {category_dir}"


def test_all_playbook_markdown_files_are_non_empty() -> None:
    """Verify that all Markdown playbook files contain content."""
    playbook_files = list(PLAYBOOKS_DIR.rglob("*.md"))

    assert playbook_files

    for playbook_file in playbook_files:
        content = playbook_file.read_text(encoding="utf-8").strip()

        assert content, f"Playbook file is empty: {playbook_file}"
