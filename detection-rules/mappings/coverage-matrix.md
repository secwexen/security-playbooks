# MITRE ATT&CK Coverage Matrix

> This document describes the current detection coverage maintained by
> Security Playbooks.

## Summary

| Metric | Value |
|--------|------:|
| Total Detection Rules | 2 |
| Mapped Detection Rules | 2 |
| Unmapped Detection Rules | 0 |
| Total Techniques | 3 |
| Covered Techniques | 3 |
| Uncovered Techniques | 0 |
| Coverage | 100% |

## Detection Rules

| Rule ID | Rule Name | Techniques |
|---------|-----------|------------|
| `f1a2b3c4-d5e6-7890-1234-56789abcdef0` | PowerShell Encoded Command Execution | T1059.001, T1027 |
| `example-sigma-001` | Suspicious Login Attempt | T1110 |

## Technique Coverage

| Technique ID | Technique Name | Covered | Rule Count |
|--------------|----------------|--------:|-----------:|
| `T1027` | Obfuscated Files or Information | Yes | 1 |
| `T1059.001` | PowerShell | Yes | 1 |
| `T1110` | Brute Force | Yes | 1 |

## Coverage Details

### T1027 — Obfuscated Files or Information

Covered by:

- `f1a2b3c4-d5e6-7890-1234-56789abcdef0`

### T1059.001 — PowerShell

Covered by:

- `f1a2b3c4-d5e6-7890-1234-56789abcdef0`

### T1110 — Brute Force

Covered by:

- `example-sigma-001`

## Gaps

No uncovered techniques are currently defined in this mapping dataset.

> Coverage reflects the techniques declared in the repository mapping dataset.
> It does not represent complete coverage of the entire MITRE ATT&CK framework.
