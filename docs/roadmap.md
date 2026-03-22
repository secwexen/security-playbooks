# Security Playbooks – Roadmap

This document outlines the planned development path for the **Security Playbooks** repository, including short‑term improvements, medium‑term expansions, and long‑term strategic goals.

## 1. Short‑Term Goals

### Playbook Expansion

- Add at least 10 new attack scenarios mapped to MITRE ATT&CK.
- Enrich existing playbooks with detailed log sources, detection notes, and response steps.
- Introduce IOC/IOA sections for all current and future playbooks.

### Detection Engineering Improvements

- Reorganize Sigma rules by category and ATT&CK technique.
- Expand YARA rules with additional malware families.
- Align Suricata rules with network‑centric ATT&CK techniques.

### Documentation Enhancements

- Update [OVERVIEW](docs/overview.md) and create a clear [RUN_COMMANDS](docs/RUN_COMMANDS.md).
- Add step‑by‑step walkthroughs for lab environments.
- Establish a versioning and naming standard for all playbooks and detection rules.

## 2. Mid‑Term Goals

### SOC & Incident Response Playbooks

- Develop structured playbooks for common incident types:
  - Phishing
  - Ransomware
  - Lateral movement
  - Privilege escalation
  - Data exfiltration
- Add decision trees and escalation paths for each playbook.

### Automation & Integration

- Provide example SOAR workflows (e.g., Cortex XSOAR, Shuffle, Splunk SOAR).
- Add API‑ready JSON/YAML versions of playbooks for automation pipelines.
- Introduce a standardized schema for machine‑readable playbooks.

### Lab & Simulation Content

- Build reproducible lab scenarios using:
  - Atomic Red Team
  - Caldera
  - Infection Monkey
- Provide sample datasets for SIEM testing.

## 3. Long‑Term Goals

### Framework Coverage Expansion

- Map all playbooks to:
  - MITRE ATT&CK
  - NIST 800‑61
  - CIS Controls
  - ISO 27035

### Threat Intelligence Integration

- Add threat‑actor‑specific playbooks.
- Include TTP evolution notes and historical context.
- Provide enrichment templates for TI platforms.

### Community & Contribution Model

- Create contribution guidelines and templates.
- Introduce a review workflow for new playbooks.
- Build a tagging system for complexity, required tools, and environment type.
