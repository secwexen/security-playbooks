# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - Initial Release

### Added

- Initial project structure
- Detection rules (Sigma-based)
- MITRE ATT&CK-aligned mappings
- Incident response playbooks
- Lab scenarios for hands-on practice
- Sample logs and datasets

### Notes

- Established baseline project structure
- Prepared foundation for future detection and automation features

# Release v0.2.0 – 2026-03-31

## [0.2.0] - 2026-03-31

### Added

#### Detection Testing Framework

- Introduced a detection testing framework under `testing/`
- Automated testing for Sigma, YARA, and Suricata rules
- MITRE ATT&CK coverage calculation
- False-positive / false-negative tracking
- Atomic Red Team integration (simulation-ready)
- Structured JSON outputs and HTML coverage reporting

#### SOAR-lite Automation Engine

- Added modular SOAR-like execution framework under `src/security_playbooks/soar/`
- YAML-based playbook parsing
- Step-by-step execution engine
- Modular action loading system
- Built-in response actions:
  - IOC enrichment
  - Host isolation
  - Slack notifications
  - IP blocking
  - User disabling
- Enables consistent and repeatable incident response execution

#### Metrics & Reporting

- Added automated metrics generation under `metrics/auto_reports/`
- Detection quality scoring
- MITRE ATT&CK coverage reporting
- False-positive / false-negative statistics

#### Playbook Execution

- Structured playbook execution outputs under `output/playbook_runs/`
- Includes logs and execution artifacts for reproducibility and auditing

### Updated

#### Detection Rules

- Expanded Sigma rules
- Added new YARA rules
- Added new Suricata rules
- Updated MITRE ATT&CK mappings
- Improved coverage matrices

#### ATT&CK Scenarios

- Expanded scenarios including PowerShell execution (T1059), phishing simulation (T1566), malware analysis, lateral movement, credential access, and data exfiltration

#### Documentation

- Improved architecture documentation
- Added playbook format specification
- Added detection rule format guide
- Enhanced Quick Start guide
- Expanded API documentation

### Integrations & Tools

- Sysmon log parser
- Sigma rule parser
- AbuseIPDB integration
- VirusTotal integration

### Dependencies

- Updated `orjson` from 3.10.7 to 3.11.6
- Updated `black` from 24.4.2 to 26.3.1
- Updated `requests` from 2.32.4 to 2.33.0
