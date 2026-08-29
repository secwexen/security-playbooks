from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOKS_DIR = PROJECT_ROOT / "playbooks"

REQUIRED_METADATA_TERMS = [
    "MITRE ATT&CK",
]


def get_playbook_files():
    return [
        path
        for path in PLAYBOOKS_DIR.rglob("*.md")
        if path.name not in {
            "README.md",
            "playbook-guide.md",
        }
    ]


def test_playbook_files_exist():
    playbook_files = get_playbook_files()

    assert playbook_files


def test_playbooks_contain_title():
    for playbook_file in get_playbook_files():
        content = playbook_file.read_text(
            encoding="utf-8"
        ).strip()

        assert content.startswith("#"), (
            f"Playbook has no Markdown title: {playbook_file}"
        )


def test_playbooks_contain_mitre_reference():
    missing = []

    for playbook_file in get_playbook_files():
        content = playbook_file.read_text(
            encoding="utf-8"
        )

        if "MITRE ATT&CK" not in content:
            missing.append(
                str(playbook_file)
            )

    assert not missing, (
        "Playbooks without MITRE ATT&CK reference:\n"
        + "\n".join(missing)
    )


def test_playbooks_do_not_contain_empty_front_matter():
    for playbook_file in get_playbook_files():
        content = playbook_file.read_text(
            encoding="utf-8"
        )

        if content.startswith("---"):
            sections = content.split("---", 2)

            assert len(sections) == 3, (
                f"Invalid front matter in {playbook_file}"
            )

            assert sections[1].strip(), (
                f"Empty front matter in {playbook_file}"
            )
