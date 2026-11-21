"""Tests for local Markdown links in security playbooks."""

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOKS_DIR = PROJECT_ROOT / "playbooks"

MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def get_playbook_files() -> list[Path]:
    """Return all Markdown playbook files recursively."""
    return list(PLAYBOOKS_DIR.rglob("*.md"))


def extract_local_links(content: str) -> list[str]:
    """Extract local Markdown links while excluding external links."""
    links: list[str] = []

    for target in MARKDOWN_LINK_PATTERN.findall(content):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue

        clean_target = target.split("#", 1)[0].strip()

        if clean_target:
            links.append(clean_target)

    return links


def test_all_local_playbook_links_resolve() -> None:
    """Verify that all local playbook links resolve inside the project."""
    playbook_files = get_playbook_files()

    assert playbook_files, "No Markdown playbook files were found."

    broken_links: list[str] = []
    project_root = PROJECT_ROOT.resolve()

    for playbook_file in playbook_files:
        content = playbook_file.read_text(encoding="utf-8")

        for link in extract_local_links(content):
            target = (playbook_file.parent / link).resolve()

            try:
                target.relative_to(project_root)
            except ValueError:
                broken_links.append(f"{playbook_file}: {link}")
                continue

            if not target.exists():
                broken_links.append(f"{playbook_file}: {link}")

    assert not broken_links, "Broken local playbook links:\n" + "\n".join(broken_links)
