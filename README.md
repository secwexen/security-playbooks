# Security Playbooks

<p align="center">
<img src="assets/images/security-playbooks-logo.png" width="700" alt="Security Playbooks Logo" loading="lazy" decoding="async">
</p>

[![CI](https://github.com/secwexen/security-playbooks/actions/workflows/ci.yml/badge.svg)](https://github.com/secwexen/security-playbooks/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/secwexen/security-playbooks?include_prereleases)](https://github.com/secwexen/security-playbooks/releases)
[![License](https://img.shields.io/github/license/secwexen/security-playbooks)](https://github.com/secwexen/security-playbooks/blob/main/LICENSE)

## About

Security Playbooks is a defensive security repository designed for cybersecurity professionals and SOC analysts.

It brings together blue-team resources such as MITRE ATT&CK mappings, detection rules, incident-response and threat-hunting playbooks, validation tests, coverage reports, and lab materials. The repository also includes selected threat-intelligence, IOC-enrichment, automation, and integration resources; their scope and functionality vary by component.

The project is intended to support learning and defensive workflows, including detection engineering, threat hunting, incident response, and security-content validation in controlled environments.

## Why Security Playbooks?

Security Playbooks organizes detection engineering, threat hunting, incident response, ATT&CK mapping, validation tests, and lab materials in one repository. Its workflows and reports are intended to help users investigate alerts, test supported detection content, review mapped coverage, and identify areas for further improvement.

By keeping detection content, validation tests, and coverage mappings together, the repository makes it easier to review how supported rules are tested and mapped.

## Use Cases

- Alert Investigation & Triage
- Threat Hunting Operations
- Detection Engineering & Validation
- Incident Response Simulation
- Adversary Emulation (Lab Only)
- Training & Skill Development
- Security Awareness Training
- Detection Gap Analysis
- MITRE ATT&CK Alignment

## Legal & Authorized Use

This Security Playbooks repository is intended strictly for educational, research, and authorized security testing purposes only. Users are solely responsible for ensuring their activities comply with all applicable laws and regulations.

The maintainers assume no liability for misuse or any damages resulting from the use of this project.

See [Ethics & Responsible Use Guidelines](docs/legal/ethics.md) for details.

## Who Is This For

- SOC Analysts
- Threat Hunters
- Blue Teamers
- Cybersecurity professionals
- Red Teamers (Lab Use Only)
- Detection Engineers
- Threat Intelligence Analysts
- Security Operations Managers

## Features

- **Detection Rules** - Sigma, YARA, Suricata (tested & validated)
- **Security Playbooks** - IR & threat hunting workflows
- **MITRE ATT&CK Mapping** - Full technique coverage
- **Automated Testing** - Pytest suite with fixtures
- **Coverage Reporting** - ATT&CK Navigator integration
- **Hands-on Labs** - Adversary emulation scenarios
- **Platform Integrations** - Splunk, Elastic, Sentinel, CrowdStrike
- **SOC Automation** - Python scripts for rule validation & enrichment

For full details, refer to the [Features](docs/product/features.md) file.

## MITRE ATT&CK Coverage

> Coverage reflects the ATT&CK techniques mapped in this repository; it does not represent coverage of all MITRE ATT&CK techniques.

Coverage mappings are maintained in:

- [MITRE Mapping](detection-rules/mappings/mitre-mapping.yaml) - MITRE ATT&CK techniques mapping
- [Coverage Matrix](detection-rules/mappings/coverage-matrix.md) - Detection coverage matrix
- [Coverage Report](reports/coverage-summary.md) - Detection coverage summary and analysis
- [Attack Navigator Layer](detection-rules/mappings/attack-navigator-layer.json) - ATT&CK Navigator layer
- [Rule Coverage Map](detection-rules/mappings/rule-coverage-map.json) - Rule-to-technique coverage mapping

## Supported Integrations

Security Playbooks includes integrations for common security platforms and collaboration tools:

- Microsoft Defender
- CrowdStrike Falcon
- Microsoft Sentinel
- Splunk
- Elastic
- Slack

See [Integrations](integrations/) for implementation details.

## Security Workflow

This workflow shows how security behaviors are mapped, detected, investigated, enriched, validated, tested, and measured across the repository.

```text
Threat / Attack Behavior
        ↓
MITRE ATT&CK Mapping
        ↓
Detection Rules (Sigma / YARA / Suricata)
        ↓
Alert / Event Generated
        ↓
Triage & Prioritization (Playbooks)
        ↓
Alert Investigation
        ↓
Threat Hunting & Enrichment
        ↓
IOC / Threat Intelligence
        ↓
Incident Response
        ↓
Detection Validation (Labs & Tests)
        ↓
Automated Tests & Coverage Metrics
        ↓
Coverage / Reporting / Improvement
```

## Installation

### Supported Operating Systems

- **Linux**: Recommended for development, testing, automation, and deployment
- **Windows**: Supported for development and testing with Visual Studio Code and WSL2
- **macOS**: Supported for local development and testing

### Requirements

- Python 3.13+
- pip for Python dependency installation
- Make for repository automation and common development tasks
- Git for repository management
- PyYAML for YAML configuration and metadata processing
- JSON support for schemas, datasets, reports, and machine-readable security data
- Sigma rule support
- YARA rule support
- Suricata rule support
- Pytest for automated testing and validation

### Optional Components

- Docker: Used for containerized labs, testing, and integration workflows
- Scapy: Used for generating and working with Suricata PCAP fixtures

For full details, refer to the [Installation Guide](docs/getting-started/installation.md) file.

## Quick Start

### 1. Clone & Setup

```bash
# Clone repository
git clone https://github.com/secwexen/security-playbooks.git
cd security-playbooks

# Create virtual environment
python -m venv .venv

# Activate virtual environment
source .venv/bin/activate     # Linux/Mac
.\.venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt
```

### 2. Run Detection Tests

The project includes automated tests for Sigma, YARA, and Suricata detection rules.

```python
# Run Sigma detection tests
python -m scripts.run_sigma_tests

# Run YARA tests
python -m scripts.run_yara_tests

# Run Suricata tests
python -m scripts.run_suricata_tests

# Run the full pytest suite
python -m pytest -v
```

The Suricata fixtures are real PCAP files generated with Scapy. Scapy is included as a project dependency. [Development Requirements](requirements-dev.txt).

If the PCAP fixtures need to be regenerated:

```python
python tests/suricata/generate_fixtures.py
```

For complete setup instructions and troubleshooting, see the [Quick Start](docs/getting-started/quickstart.md) guide.

## How to Use a Playbook

1. **Identify the event or behavior** you are investigating, such as a phishing alert, suspicious login, or malware detection.
2. **Choose a matching playbook** from the catalog below. Start with a triage playbook for initial alert review; use a response playbook when an incident requires coordinated response.
3. **Review the playbook before taking action.** Check its purpose, scope, trigger conditions, required telemetry, and safety guidance.
4. **Follow the investigation steps** using your organization's approved tools and procedures. Collect and document relevant evidence, timestamps, and decisions.
5. **Apply the decision and escalation criteria.** Escalate or perform response actions only in accordance with your organization's authority and incident-response procedures.
6. **Record the outcome** and review any linked detection rules, related playbooks, or validation guidance.
7. **Document findings and actions.** Record the investigation steps, evidence collected, decisions made, and any related detections or follow-up tasks.

Playbooks are analyst-guidance documents; they do not automatically execute actions. Adapt them to your environment and verify that each step is appropriate for your tooling, policies, and authorization.

## Playbook Catalog

The playbooks are organized by their primary purpose. Browse a category or open the linked playbook to review its scope and procedures.

| Category                                          | Typical Use                                         | Example playbooks                                                                                                                                                                                                    |
| ------------------------------------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Triage](playbooks/triage/)                       | Initial alert validation and prioritization         | [Phishing Alert Triage](playbooks/triage/phishing-alert-triage.md), [Suspicious Login Triage](playbooks/triage/suspicious-login-triage.md), [Malware Detection Triage](playbooks/triage/malware-detection-triage.md) |
| [Incident Response](playbooks/response/)          | Containment, remediation, and recovery              | [Phishing Response](playbooks/response/phishing-response.md), [Malware Response](playbooks/response/malware-response.md), [Ransomware Response](playbooks/response/ransomware-response.md)                           |
| [Cloud](playbooks/cloud/)                         | Cloud account, identity, and service incidents      | [Cloud Account Compromise](playbooks/cloud/cloud-account-compromise.md), [Cloud Credential Access](playbooks/cloud/cloud-credential-access.md)                                                                       |
| [Credential Access](playbooks/credential-access/) | Credential theft and credential abuse investigation | [Credential Dumping](playbooks/credential-access/credential-dumping.md), [Password Spraying](playbooks/credential-access/password-spraying.md)                                                                       |
| [Exfiltration](playbooks/exfiltration/)           | Data theft and outbound transfer investigation      | [Data Exfiltration](playbooks/exfiltration/data-exfiltration.md), [Cloud Exfiltration](playbooks/exfiltration/cloud-exfiltration.md)                                                                                 |

For the complete list of playbooks, see the [playbook catalog](playbooks/catalog.yaml). For category descriptions and playbook structure, see the [Playbooks README](playbooks/README.md) and [Playbook Guide](docs/playbooks/playbook-guide.md).

## Documentation

- [Architecture](docs/architecture/architecture.md)
- [Security Playbooks](playbooks/)
- [Playbook Guide](docs/playbooks/playbook-guide.md)
- [Testing Guide](docs/testing/testing.md)
- [FAQ](docs/FAQ.md)

## License

Copyright © 2026 secwexen.

This project is licensed under the **MIT License**.    
See the [LICENSE](LICENSE) file for full details.

## Contributing

Contributions and suggestions are welcome!

- Fork the repository and create a feature or fix branch (e.g. `feature/feature-name`, `fix/bug-name`, `docs/update-readme`, `chore/dependency-update`).
- Make your changes and update the relevant documentation, playbooks, or detection rules as needed.
- Use clear commit messages (e.g. Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`).
- Open a pull request referencing related issues/discussion when possible.
- All PRs must pass CI checks before merging.

Please open an issue before submitting major changes or new features.

See [CONTRIBUTING](CONTRIBUTING.md) for detailed contribution guidelines.

## Roadmap

Planned improvements include:

- Expanded ATT&CK-mapped playbooks and lab scenarios
- Enhanced and validated detection rules (Sigma, YARA, and Suricata)
- Structured SOC workflows and incident response playbooks
- Standardized, machine-readable playbook formats
- Alignment with security frameworks (NIST, CIS, ISO)

For the full roadmap and upcoming features, see [ROADMAP](ROADMAP.md).

## Community & Support

- **GitHub Issues** - Report bugs or request features
- **GitHub Discussions** - Ask questions and share ideas
- **Contributing** - Submit improvements and new playbooks

## Security

If you discover a security vulnerability, please follow our responsible disclosure process.

See [SECURITY](SECURITY.md) for detailed information.
