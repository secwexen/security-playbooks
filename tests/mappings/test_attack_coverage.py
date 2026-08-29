import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCRIPT_FILE = PROJECT_ROOT / "scripts" / "export_attack_matrix.py"

OUTPUT_FILE = PROJECT_ROOT / "reports" / "attack-matrix.json"


def run_export():
    result = subprocess.run(
        [sys.executable, str(SCRIPT_FILE)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, (
        f"Export script failed.\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )


def load_report() -> dict:
    assert OUTPUT_FILE.exists()

    with OUTPUT_FILE.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    assert isinstance(data, dict)
    return data


def test_attack_matrix_export():
    run_export()

    report = load_report()

    assert report["schema_version"] == "1.0"
    assert report["project"] == "security-playbooks"


def test_attack_matrix_summary():
    run_export()

    report = load_report()
    summary = report["summary"]

    assert summary["total_techniques"] == 3
    assert summary["covered_techniques"] == 3
    assert summary["uncovered_techniques"] == 0
    assert summary["coverage_percent"] == 100.0


def test_attack_matrix_contains_techniques():
    run_export()

    report = load_report()

    technique_ids = {
        item["technique_id"]
        for item in report["techniques"]
    }

    assert "T1059.001" in technique_ids
    assert "T1027" in technique_ids
    assert "T1110" in technique_ids


def test_attack_matrix_entries_are_consistent():
    run_export()

    report = load_report()

    for technique in report["techniques"]:
        assert technique["technique_id"]
        assert technique["covered"] is True
        assert technique["rule_count"] >= 1
        assert isinstance(technique["rules"], list)
        assert isinstance(technique["sources"], list)
