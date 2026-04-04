# Security Playbooks

<p align="center">
<img src="assets/images/security-playbooks-logo.png" width="600" alt="Security Playbooks Logo" loading="lazy" decoding="async">
</p>

**Security Playbooks | MITRE ATT&CK Red & Blue Team Labs for SOC Analysts**  
**Open‑source ATT&CK scenarios, detection rules, and practical blue‑team labs.**

**Official Website:** [https://secwexen.github.io/security-playbooks/](https://secwexen.github.io/security-playbooks/)

[![CI](https://github.com/secwexen/security-playbooks/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/secwexen/security-playbooks/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/secwexen/security-playbooks/branch/main/graph/badge.svg?branch=main&event=pull_request)](https://codecov.io/gh/secwexen/security-playbooks)
[![Release](https://img.shields.io/github/v/release/secwexen/security-playbooks?include_prereleases)](https://github.com/secwexen/security-playbooks/releases)
[![License](https://img.shields.io/github/license/secwexen/security-playbooks)](https://github.com/secwexen/security-playbooks/blob/main/LICENSE)

**Security Playbooks** is an open‑source, high‑quality cybersecurity repository featuring **MITRE ATT&CK attack simulations**, **detection engineering rules** (Sigma, YARA, Suricata), **incident response labs**, **log analysis workflows**, and **threat‑hunting playbooks**.  
This project is designed for SOC analysts, blue teamers, threat hunters, and cybersecurity professionals who want to build real-world skills.

## About

Security Playbooks is an open-source, educational, and portfolio-focused repository designed for cybersecurity professionals.

It focuses on delivering realistic, MITRE ATT&CK–aligned attack scenarios, detection engineering content, and hands-on labs to help users build practical skills in threat hunting, incident response, and adversary simulation within controlled environments.

The project aims to bridge the gap between theoretical knowledge and real-world security operations by providing structured, reproducible, and practical cybersecurity workflows.

## Features

- **Detection Rules** – Ready-to-use Sigma, YARA, and Suricata rules for threat detection  
- **Attack Scenarios** – MITRE ATT&CK–based simulations (phishing, malware, lateral movement)  
- **Hands-on Labs** – Practical exercises with PoC scripts for controlled environments  
- **Log Analysis Examples** – Sample logs, outputs, and visual artifacts  
- **Documentation & Tools** – Quick Start guides, architecture docs, and helper scripts

## Threat Model

This playbook assumes a realistic enterprise environment and adversary behavior. It is designed for educational and lab purposes only.

- **Target Environment:** Windows Active Directory (Enterprise Network)
- **Log Sources:** 
  - Windows Event Logs (Security, Sysmon)
  - Network Traffic (PCAP)
  - Endpoint Detection & Response (EDR) telemetry
- **Adversary Profile:** APT-like actor executing common enterprise attacks
- **Attack Surface:** Endpoints, domain controllers, user workstations
- **Attack Vectors Covered:** 
  - Command & scripting interpreter execution (T1059)
  - Phishing and social engineering (T1566)
  - Malware execution and lateral movement
- **Assumptions:**
  - Logging and monitoring are enabled (Sysmon, Security Logs)
  - SIEM or log aggregation is available
  - Scenarios run in isolated lab environments only
- **Goals:** 
  - Demonstrate detection engineering and threat hunting workflows
  - Provide hands-on lab exercises for portfolio and learning purposes

## Scenarios

This repository contains multiple playbook-style scenarios:

| Scenario | Type | MITRE ATT&CK | Playbook File |
|----------|------|--------------|---------------|
| PowerShell Execution | T1059 | Command & Scripting Interpreter | [T1059_PowerShell_Execution.md](scenarios/T1059_PowerShell_Execution.md) |
| Malware Analysis | Malware | Various | [malware_analysis/README.md](scenarios/malware_analysis/README.md) |
| Phishing Simulation | Social Engineering | T1566 | [phishing_simulation/README.md](scenarios/phishing_simulation/README.md) |

## Who Is This Playbook For

Security Playbooks is intended for cybersecurity professionals who want to practice, analyze, and understand real-world cyber threats in a structured and controlled environment.

- **SOC Analysts** – Perform alert triage, log analysis, and incident investigation  
- **Threat Hunters** – Conduct hypothesis-driven hunts and analyze adversary behavior  
- **Blue Team Engineers** – Build, test, and optimize detection rules (Sigma, YARA, Suricata)  
- **Cybersecurity Professionals** – Gain hands-on experience and develop practical expertise  
- **Red Teamers (Lab Use Only)** – Emulate adversary techniques in controlled, isolated environments  

## Use Cases

Security Playbooks supports a range of practical cybersecurity workflows and real-world scenarios:

- **Alert Investigation & Triage** – Analyze and validate alerts generated by SIEM and EDR platforms  
- **Threat Hunting Operations** – Execute structured hunts based on known tactics, techniques, and procedures (TTPs)  
- **Detection Engineering & Validation** – Develop, test, and refine detection logic against simulated threats  
- **Incident Response Simulation** – Follow structured procedures to investigate and respond to security incidents  
- **Adversary Emulation (Lab Only)** – Reproduce attacker techniques to validate defensive capabilities  
- **Training & Skill Development** – Strengthen technical skills through hands-on, scenario-based exercises  

## Installation

Security Playbooks requires a minimal and modern environment to run detection rules, labs, and analysis tools.

### Supported Operating Systems

- Windows 10 / 11  
- Linux (Ubuntu 20.04+, Debian-based distros)  
- macOS (Intel & Apple Silicon)

### Python Requirements

- Python **3.11+**  
- pip 23+  
- Virtual environment recommended

### Required Tools (Depending on Scenario)

- **Sysmon** (Windows logging)  
- **Suricata** (Network IDS)  
- **YARA** (Malware pattern matching)  
- **Sigma CLI** (Rule conversion)  
- **Wireshark / tcpdump** (PCAP analysis)  
- **Python libraries** (installed via [requirements.txt](requirements.txt) and [dev-requirements.txt](dev-requirements.txt))

## Quick Start

```bash
# Clone repo
git clone https://github.com/secwexen/security-playbooks.git
cd security-playbooks

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install -r dev-requirements.txt

# To quickly test the project, run:
python labs/lab2_log_analysis/parser.py examples/malware_log_example.txt
```

For full details, refer to the [Quick Start](docs/quickstart.md) file.  
For complete command information, refer to the [RUN COMMANDS](docs/RUN_COMMANDS.md) file.

## Ethical Use

All tools in this repository are developed **strictly for educational and ethical purposes**.  
They are intended to be used for:

- Research and learning  
- Lab experiments in isolated environments

I do **not** endorse or support illegal activity of any kind.

## Docs & Resources

Detailed guides and references are also available in the repository:

- [Wiki — Full Documentation](https://github.com/secwexen/security-playbooks/wiki)
- [Repository Structure](docs/architecture.md)
- [Quick Start](docs/quickstart.md)
- [Examples](docs/examples.md)
- [Roadmap & Milestones](ROADMAP.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)

## License

Copyright © 2026 secwexen.

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for full details.

## Disclaimer

The contents of this repository are for educational and research purposes. The repository owner assumes no responsibility for misuse or legal consequences. 

For full details, see [DISCLAIMER.md](/DISCLAIMER.md).

## Community & Support

- Check out [Issues](https://github.com/secwexen/security-playbooks/issues) for tasks and ideas.  
- Join [Discussions](https://github.com/secwexen/security-playbooks/discussions) to share feedback and proposals.  
- Contribute code, documentation, or testing — see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security

For guidance on safe usage and reporting vulnerabilities, see [SECURITY.md](/SECURITY.md).

## Contributing

Contributions are welcome!

- Fork the repository and create a feature or fix branch (e.g. `feature/your-feature` or `fix/bug-name`).
- Make your changes and add relevant tests.
- Ensure all tests pass (`pytest`) and code style checks (e.g. `make lint`).
- Open a pull request referencing related issues/discussion when possible.
- All PRs must pass CI checks before merging.

Please open an issue before submitting major changes or new features.

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

## Roadmap

This document outlines the planned development path for the **Security Playbooks** repository, including short‑term improvements, medium‑term expansions, and long‑term strategic goals.

Planned improvements include:

- expanded ATT&CK-mapped playbooks
- enhanced detection rules (Sigma, YARA, Suricata)
- structured SOC and incident response workflows
- automation-ready playbooks (SOAR integration)
- lab and simulation scenarios
- standardized schemas for machine-readable playbooks
- alignment with security frameworks (NIST, CIS, ISO)

For the full roadmap and upcoming features, see [ROADMAP.md](docs/roadmap.md).

The roadmap evolves based on community feedback, operational needs, and contributor input. Contributions and suggestions are welcome.

## Development Status

**Security Playbooks** is currently in **Active Development** stage.

## External References

- **MITRE ATT&CK Framework** — [https://attack.mitre.org](https://attack.mitre.org)  
- **NIST Cybersecurity Framework** — [https://www.nist.gov/cyberframework](https://www.nist.gov/cyberframework)  
- **OWASP Security Projects** — [https://owasp.org](https://owasp.org)  
- **Microsoft Security Research** — [https://www.microsoft.com/en-us/security/blog/](https://www.microsoft.com/en-us/security/blog/)  
- **Google Red Team** — [https://redteam.google/](https://redteam.google/)  
- **Elastic Security Labs** — [https://www.elastic.co/security-labs](https://www.elastic.co/security-labs)  
- **Sigma HQ** — [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)  
