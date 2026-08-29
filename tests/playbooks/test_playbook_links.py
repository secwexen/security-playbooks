import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOKS_DIR = PROJECT_ROOT / "playbooks"

MARKDOWN_LINK_PATTERN = re.compile(
    r"\[[^\]]+\]\(([^)]+)\)"
)


def get_playbook_files():
    return list(PLAYBOOKS_DIR.rglob("*.md"))


def extract_local_links(content):
    links = []

    for target in MARKDOWN_LINK_PATTERN.findall(content):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue

        clean_target = target.split("#", 1)[0].strip()

        if clean_target:
            links.append(clean_target)

    return links


def test_all_local_playbook_links_resolve():
    playbook_files = get_playbook_files()

    assert playbook_files

    broken_links = []

    for playbook_file in playbook_files:
        content = playbook_file.read_text(
            encoding="utf-8"
        )

        for link in extract_local_links(content):
            target = (
                playbook_file.parent / link
            ).resolve()

            try:
                target.relative_to(
                    PROJECT_ROOT.resolve()
                )
            except ValueError:
                broken_links.append(
                    f"{playbook_file}: {link}"
                )
                continue

            if not target.exists():
                broken_links.append(
                    f"{playbook_file}: {link}"
                )

    assert not broken_links, (
        "Broken local playbook links:\n"
        + "\n".join(broken_links)
    )
