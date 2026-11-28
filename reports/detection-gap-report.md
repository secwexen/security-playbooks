# Detection Gap Analysis Report

## 1. Overview

This report documents the current detection coverage gaps identified in the Security Playbooks repository.

The analysis is based on the authoritative detection rule registry and the MITRE ATT&CK mapping dataset.

The purpose is to identify unmapped detection rules, document coverage limitations, and establish investigation priorities.

## 2. Coverage Summary

| Metric                           | Value |
| -------------------------------- | ----- |
| Total registered detection rules | 9     |
| Rules with ATT&CK mappings       | 3     |
| Rules without ATT&CK mappings    | 6     |
| Unique mapped techniques         | 3     |
| Mapping coverage                 | 33.3% |

Mapping coverage represents the percentage of registered rules with at least one documented ATT&CK technique. It does not represent full ATT&CK Enterprise coverage.

## 3. Identified Detection Mapping Gaps

The following rules currently have no documented ATT&CK technique mapping.

| Registry ID                 | Detection Rule                                | Format   | Status   |
| --------------------------- | --------------------------------------------- | -------- | -------- |
| DET-SIGMA-SUSPICIOUS-LOGIN  | Windows Failed Logon Event                    | Sigma    | Unmapped |
| DET-YARA-MALWARE-SAMPLE     | Example Malware Pattern                       | YARA     | Unmapped |
| DET-YARA-POWERSHELL-PAYLOAD | PowerShell Encoded Command                    | YARA     | Unmapped |
| DET-SURI-C2-COMMUNICATION   | Potential C2 Communication and DNS Indicators | Suricata | Unmapped |
| DET-SURI-NETWORK-ALERT      | Potential Suspicious HTTP User-Agent          | Suricata | Unmapped |
| DET-SURI-POWERSHELL-ALERT   | Potential PowerShell Encoded Command Activity | Suricata | Unmapped |

These entries represent documented mapping gaps. They must not automatically be interpreted as confirmed detection capability gaps.

## 4. Existing ATT&CK Coverage

The current mapping dataset contains three evidence-supported technique mappings:

| Registry ID                    | ATT&CK Technique |
| ------------------------------ | ---------------- |
| DET-SIGMA-LSASS-ACCESS         | T1003.001        |
| DET-SIGMA-POWERSHELL-EXEC      | T1059.001        |
| DET-YARA-OBFUSCATED-POWERSHELL | T1027            |

No additional technique mappings are inferred in this report.

## 5. Metadata Consistency Finding

The following metadata discrepancy requires investigation:

- Registry ID: DET-SIGMA-SUSPICIOUS-LOGIN
- Mapping rule name: Windows Failed Logon Event
- Previously documented registry name: Suspicious Login Activity

The authoritative rule name should be verified against the actual detection rule before changing either file.

## 6. Gap Investigation Priorities

| Priority       | Area                             | Required Investigation                                                                        |
| -------------- | -------------------------------- | --------------------------------------------------------------------------------------------- |
| High           | Sigma suspicious login           | Verify detection behavior, event sources, and appropriate ATT&CK mapping evidence.            |
| High           | Suricata C2 communication        | Review network indicators, telemetry availability, and detection capabilities.                |
| Medium         | Suricata suspicious HTTP traffic | Verify detection conditions and available network telemetry.                                  |
| Medium         | YARA PowerShell payload          | Review matching conditions and determine whether an evidence-supported ATT&CK mapping exists. |
| Medium         | Suricata PowerShell activity     | Verify the detected network behavior and its relationship to the registered rule.             |
| To be assessed | YARA malware sample              | Review the actual rule implementation and sample evidence before assigning a mapping.         |

Priorities indicate investigation order, not confirmed severity or missing detection capability.

## 7. Recommended Actions

1. Review all six unmapped detection rules.
2. Verify each rule's actual detection logic and supporting telemetry.
3. Identify evidence-supported ATT&CK technique mappings where applicable.
4. Investigate the identified registry and mapping metadata discrepancy.
5. Update the authoritative mapping file only after validation.
6. Regenerate coverage reports after approved mapping changes.
7. Record confirmed detection gaps separately from mapping gaps.

## 8. Scope and Limitations

This analysis uses the repository's current detection registry and MITRE ATT&CK mapping dataset.

It does not claim complete MITRE ATT&CK Enterprise coverage.

An unmapped rule does not necessarily indicate that the corresponding behavior is undetected.

No unsupported ATT&CK techniques have been assigned.

## 9. Conclusion

The repository currently contains nine registered detection rules, of which three have documented ATT&CK mappings and six remain unmapped.

The six unmapped rules and one metadata discrepancy have been identified for further investigation.

This report establishes the initial detection mapping gap baseline for milestone v0.3.0.

## 10. Technical Validation Findings

The six unmapped detection rules were reviewed based on their detection logic and available metadata.

### 10.1 Confirmed Findings

| Registry ID                 | Finding                                                      | Assessment                                            |
| --------------------------- | ------------------------------------------------------------ | ----------------------------------------------------- |
| DET-SIGMA-SUSPICIOUS-LOGIN  | Event ID 4625 detection without event correlation            | Brute-force detection capability is limited.          |
| DET-YARA-MALWARE-SAMPLE     | Training-only static string matching                         | Not a production malware detection rule.              |
| DET-YARA-POWERSHELL-PAYLOAD | PowerShell and encoded-command string matching               | Does not confirm command execution.                   |
| DET-SURI-C2-COMMUNICATION   | Generic HTTP User-Agent and example DNS TXT indicators       | Does not independently establish C2 activity.         |
| DET-SURI-NETWORK-ALERT      | Detection based on curl User-Agent                           | Potential false positives from legitimate automation. |
| DET-SURI-POWERSHELL-ALERT   | PowerShell and encoded-command indicators in network traffic | Does not confirm endpoint execution.                  |

### 10.2 Detection Capability Limitations

The current failed-logon Sigma rule detects individual Windows Security Event ID 4625 events. It does not implement threshold-based correlation or repeated authentication failure analysis.

The YARA malware sample rule is explicitly intended for training and must not be considered production detection coverage.

The PowerShell YARA and Suricata rules identify suspicious content patterns. Their matches do not independently establish successful command execution.

The Suricata C2 and HTTP rules use generic network indicators. Additional evidence would be required to establish malicious communication.

### 10.3 ATT&CK Mapping Review

The PowerShell encoded-command rules contain indicators relevant to ATT&CK technique T1059.001.

However, their current detection logic does not establish actual execution. T1059.001 is therefore recorded as a candidate for further mapping review rather than automatically added to the authoritative mapping dataset.

No unsupported ATT&CK mappings were introduced.

### 10.4 Metadata Consistency

A naming discrepancy remains under investigation:

- Registry name: Suspicious Login Activity
- Sigma title: Windows Failed Logon Event
- Mapping rule name: Windows Failed Logon Event

The registry and mapping metadata should be reconciled after confirming the intended canonical rule name.

### 10.5 Validation Conclusion

The review identified limitations in authentication correlation, production malware detection, PowerShell execution visibility, and network-based C2 identification.

These findings distinguish confirmed rule limitations from unverified detection coverage gaps.

Further investigation and evidence are required before assigning additional ATT&CK techniques or declaring specific attack behaviors completely undetected.
