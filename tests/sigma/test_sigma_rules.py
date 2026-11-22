"""Tests for Sigma rule parsing and MITRE ATT&CK URL generation."""

import pytest

from tools.parsers.sigma_parser import build_mitre_attack_url


@pytest.mark.parametrize(
    ("technique_id", "expected_url"),
    [
        (
            "T1059",
            "https://attack.mitre.org/techniques/T1059/",
        ),
        (
            "T1059.001",
            "https://attack.mitre.org/techniques/T1059/001/",
        ),
        (
            "T1003.008",
            "https://attack.mitre.org/techniques/T1003/008/",
        ),
    ],
)
def test_build_mitre_attack_url(
    technique_id: str,
    expected_url: str,
) -> None:
    """Verify canonical MITRE ATT&CK URLs for valid technique IDs."""
    assert build_mitre_attack_url(technique_id) == expected_url


@pytest.mark.parametrize(
    "technique_id",
    [
        "",
        "T1059.001.002",
        "1059",
        "T1059.invalid",
    ],
)
def test_build_mitre_attack_url_rejects_invalid_ids(
    technique_id: str,
) -> None:
    """Verify invalid MITRE ATT&CK technique IDs raise ValueError."""
    with pytest.raises(ValueError):
        build_mitre_attack_url(technique_id)
