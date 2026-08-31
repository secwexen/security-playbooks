# Security Playbooks

<p align="center">
<img src="assets/images/security-playbooks-logo.png" width="650" alt="Security Playbooks Logo" loading="lazy" decoding="async">
</p>

[![CI](https://github.com/secwexen/security-playbooks/actions/workflows/ci.yml/badge.svg)](https://github.com/secwexen/security-playbooks/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/secwexen/security-playbooks?include_prereleases)](https://github.com/secwexen/security-playbooks/releases)
[![License](https://img.shields.io/github/license/secwexen/security-playbooks)](https://github.com/secwexen/security-playbooks/blob/main/LICENSE)

## About

Security Playbooks is a defensive cybersecurity and blue team repository designed for cybersecurity professionals, SOC analysts, threat hunters, detection engineers, incident responders, and security practitioners.

It focuses on delivering realistic, MITRE ATT&CK mapping, detection engineering, detection rules, detection validation, threat hunting, incident response playbooks, security playbooks, SOC workflows, adversary emulation, threat intelligence, IOC enrichment, security validation, automated testing, security automation, security integrations, coverage analysis, and hands-on labs to help users build practical skills in threat hunting, incident response, detection engineering, and adversary simulation within controlled environments.

The project aims to bridge the gap between the oretical knowledge and real-world security operations by providing structured, reproducible, practical cybersecurity workflows, threat intelligence, detection engineering, incident response, security validation, automated testing, machine-readable security content, and coverage analysis capabilities.

## Use Cases

- Alert Investigation & Triage  
- Threat Hunting Operations  
- Detection Engineering & Validation  
- Incident Response Simulation  
- Adversary Emulation (Lab Only)  
- Training & Skill Development

## Legal & Authorized Use Only

This Security Playbooks repository is intended strictly for educational, research, and authorized security testing purposes only.

Users are solely responsible for ensuring their activities comply with all applicable laws and regulations.

The maintainers assume no liability for misuse or any damages resulting from the use of this project.

## Legal Disclaimer

The contents of this repository, including scripts, scenarios, and detection rules, are provided for educational, research purposes only. No responsibility for any damage, misuse, or legal consequences resulting from the use of this material.

This software is provided “as is” without warranty of any kind, express or implied.

## Who Is This For

- SOC Analysts  
- Threat Hunters  
- Blue Team Engineers  
- Cybersecurity professionals  
- Red Teamers (Lab Use Only)  
- Detection Engineers  
- Threat Intelligence Analysts

## Features

- Detection Rules  
- Attack Scenarios  
- Hands-on Labs  
- Log Analysis Examples  
- Documentation & Tools  
- Sigma, YARA & Suricata Rules  
- IOC Enrichment & Threat Feeds

## MITRE ATT&CK Coverage

Coverage mappings are maintained in:

- [Mitre Mapping](detection-rules/mappings/mitre-mapping.yaml) – MITRE ATT&CK techniques mapping  
- [Coverage Matrix](detection-rules/mappings/coverage-matrix.md) – Detection coverage matrix  
- [Coverage Report](reports/coverage-summary.md) – Detection coverage summary and analysis  
- [Attack Navigator Layer](detection-rules/mappings/attack-navigator-layer.json) — ATT&CK Navigator layer  
- [Rule Coverage Map](detection-rules/mappings/rule-coverage-map.json) — Rule-to-technique coverage mapping

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
MITRE ATT&CK
        ↓
Detection Rules (Sigma / YARA / Suricata)
        ↓
Alert / Event
        ↓
Triage
        ↓
Investigation
        ↓
Threat Hunting
        ↓
IOC / Threat Intelligence
        ↓
Incident Response
        ↓
Validation
        ↓
Automated Tests
        ↓
Coverage / Reporting
```

## Installation

### Supported Operating Systems

- Linux — Recommended for development, testing, automation, and deployment  
- Windows — Supported for development and testing with Visual Studio Code and WSL2  
- macOS — Supported for local development and testing

### Requirements

- Python 3.11+
- pip for Python dependency installation
- Make for repository automation and common development tasks
- Git for repository management
- PyYAML for YAML configuration and metadata processing
- JSON support for schemas, datasets, reports, and machine-readable security data
- Sigma rule support
- YARA rule support
- Suricata rule support
- pytest for automated testing and validation

### Optional Components

- Docker: Used for containerized labs, testing, and integration workflows
- Scapy: Used for generating and working with Suricata PCAP fixtures

## Quick Start

```bash
# Clone repository
git clone https://github.com/secwexen/security-playbooks.git
cd security-playbooks

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install -r requirements-dev.txt

# Run the full pytest suite
python -m pytest -v
```

For full details, refer to the [Quick Start](docs/getting-started/quickstart.md) file.

## Run Detection Tests

The project includes automated tests for YARA and Suricata detection rules.

```bash
# Run Sigma detection tests
python -m scripts.run_sigma_tests

# Run YARA tests
python -m scripts.run_yara_tests

# Run Suricata tests
python -m scripts.run_suricata_tests
```

The Suricata fixtures are real PCAP files generated with Scapy. Scapy is included in `requirements-dev.txt`.

If the PCAP fixtures need to be regenerated:

```bash
python tests/suricata/generate_fixtures.py
```

For complete setup instructions and troubleshooting, see the [Quick Start](docs/getting-started/quickstart.md) guide.

## Documentation

- [Project Index](docs/INDEX.md)
- [Quick Start](docs/getting-started/quickstart.md)  
- [Roadmap](ROADMAP.md)  
- [Contributing Guidelines](CONTRIBUTING.md)  
- [Changelog](CHANGELOG.md)  
- [Security Policy](SECURITY.md)

## License

Copyright © 2026 secwexen.

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for full details.

## Contributing

Contributions and suggestions are welcome!

- Fork the repository and create a feature or fix branch (e.g. `feature/your-feature`, `fix/bug-name`, `docs/update-readme`, `chore/dependency-update`).
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

## Security

If you discover a security vulnerability, please follow our responsible disclosure process.

See [SECURITY](SECURITY.md) for detailed information.
