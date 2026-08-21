from pathlib import Path

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def detection_rules_dir(project_root: Path) -> Path:
    return project_root / "detection-rules"


@pytest.fixture(scope="session")
def playbooks_dir(project_root: Path) -> Path:
    return project_root / "playbooks"


@pytest.fixture(scope="session")
def schemas_dir(project_root: Path) -> Path:
    return project_root / "schemas"


@pytest.fixture
def load_yaml():
    def _load_yaml(path: Path):
        with path.open("r", encoding="utf-8") as file:
            return yaml.safe_load(file)

    return _load_yaml
