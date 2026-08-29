from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOKS_DIR = PROJECT_ROOT / "playbooks"

EXPECTED_DIRECTORIES = [
    "collection",
    "command-and-control",
    "credential-access",
    "defense-evasion",
    "discovery",
    "execution",
    "exfiltration",
    "impact",
    "initial-access",
    "lateral-movement",
    "persistence",
    "privilege-escalation",
    "response",
    "triage",
]

EXPECTED_FILES = [
    "README.md",
    "playbook-guide.md",
]


def test_playbooks_directory_exists():
    assert PLAYBOOKS_DIR.exists()
    assert PLAYBOOKS_DIR.is_dir()


def test_expected_playbook_directories_exist():
    for directory in EXPECTED_DIRECTORIES:
        path = PLAYBOOKS_DIR / directory

        assert path.exists(), f"Missing playbook directory: {path}"
        assert path.is_dir(), f"Not a directory: {path}"


def test_expected_root_files_exist():
    for filename in EXPECTED_FILES:
        path = PLAYBOOKS_DIR / filename

        assert path.exists(), f"Missing playbook file: {path}"
        assert path.is_file(), f"Not a file: {path}"


def test_playbook_categories_contain_markdown_files():
    for directory in EXPECTED_DIRECTORIES:
        category_dir = PLAYBOOKS_DIR / directory

        markdown_files = list(category_dir.glob("*.md"))

        assert markdown_files, (
            f"No Markdown playbooks found in {category_dir}"
        )


def test_all_playbook_markdown_files_are_non_empty():
    playbook_files = list(
        PLAYBOOKS_DIR.rglob("*.md")
    )

    assert playbook_files

    for playbook_file in playbook_files:
        content = playbook_file.read_text(
            encoding="utf-8"
        ).strip()

        assert content, (
            f"Playbook file is empty: {playbook_file}"
        )
