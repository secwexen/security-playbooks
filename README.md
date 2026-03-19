# Security Playbooks

**Official Website:** [https://secwexen.github.io/security-playbooks/](https://secwexen.github.io/security-playbooks/)

[![CodeQL](https://github.com/secwexen/security-playbooks/actions/workflows/github-code-scanning/codeql/badge.svg?branch=main&event=push)](https://github.com/secwexen/security-playbooks/actions/workflows/github-code-scanning/codeql)
[![Release](https://img.shields.io/github/v/release/secwexen/security-playbooks)](https://github.com/secwexen/security-playbooks/releases)
[![License](https://img.shields.io/github/license/secwexen/security-playbooks)](https://github.com/secwexen/security-playbooks/blob/main/LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen)](https://github.com/secwexen/security-playbook)

**Security Playbooks** is an open‑source, high‑quality cybersecurity repository featuring **MITRE ATT&CK attack simulations**, **detection engineering rules** (Sigma, YARA, Suricata), **incident response labs**, **log analysis workflows**, and **threat‑hunting playbooks**.  
This project is designed for SOC analysts, blue teamers, threat hunters, and cybersecurity who want to build real‑world skills through hands‑on examples.

## About

The **Security Playbooks** is an open-source, educational, and portfolio-focused repository for cybersecurity professionals.  
It provides a structured collection of:

- MITRE ATT&CK-based attack scenarios  
- Sigma, YARA, and Suricata detection rules  
- Proof-of-Concept (PoC) scripts  
- Lab walkthroughs and practical exercises  

This repository is designed to **demonstrate professional cybersecurity skills**, including threat hunting, incident response, and pentesting workflows, in a safe and controlled environment.

## Overview

**Security Playbooks** is organized to give users a clear and practical view of real-world cybersecurity workflows:

- **Detection Rules:** Ready-to-use Sigma/YARA/Suricata rules for threat detection and analysis.  
- **Scenarios:** Simulated attacks based on MITRE ATT&CK, including phishing, malware, and lateral movement exercises.  
- **Labs:** Hands-on lab exercises with PoC scripts for testing and research in isolated environments.  
- **Examples:** Sample outputs, screenshots, and logs to visualize results.  
- **Docs & Tools:** Quick Start guides, architecture explanations, and optional helper scripts to support learning and experimentation.  

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

## Features

- MITRE ATT&CK–based attack scenarios
- Sigma / YARA / Suricata detection rules
- PoC examples for isolated lab environments
- Log analysis samples
- Threat hunting practice workflows

## Who Is This Playbook For

The Security Playbooks is intended for cybersecurity expert who want to practice, analyze, and understand real-world cyber threats in a structured and controlled environment:

- **SOC Analysts** – for detection engineering, alert analysis, and log investigation  
- **Threat Hunters** – for hypothesis-driven hunting and adversary behavior analysis  
- **Blue Team Engineers** – for building and testing detection rules (Sigma, YARA, Suricata)  
- **Cybersecurity Students** – for hands-on learning and portfolio development  
- **Red Teamers (lab-only)** – for adversary emulation and controlled attack simulations  

## Repository Structure

```
security-playbooks/
├─ detection-rules/    # Sigma, YARA, Suricata rules for threat detection
├─ scenarios/          # MITRE ATT&CK-based attack simulations
├─ labs/               # PoC scripts and lab walkthroughs
├─ examples/           # Sample outputs, logs, and screenshots
├─ docs/               # Documentation and guides
└─ tools/              # Helper scripts and parsers
```

## Quick Start

```bash
git clone https://github.com/secwexen/security-playbooks.git
cd security-playbooks
```

See the [quick_start.md](docs/quick_start.md) file for full details.

## Running the Examples

This repository includes several educational scripts and detection rules.  
Below are the commands used to run each component.

See the [RUN_COMMANDS.md](docs/RUN_COMMANDS.md) file for full details.

### Quick Start (Single Command)

To quickly test the project, run:
```
python labs/lab2_log_analysis/parser.py examples/malware_log_example.txt
```

## Ethical Use

All tools in this repository are developed **strictly for educational and ethical purposes**.  
They are intended to be used for:

- Research and learning  
- Lab experiments in isolated environments

I do **not** endorse or support illegal activity of any kind.

## Docs & Resources

Detailed guides and references are also available in the repository:

- [Quick Start](docs/quickstart.md)
- [Roadmap & Milestones](docs/roadmap.md)
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

## Community & Contribution

- Check out [Issues](https://github.com/secwexen/security-playbooks/issues) for tasks and ideas.  
- Join [Discussions](https://github.com/secwexen/security-playbooks/discussions) to share feedback and proposals.  
- **Found Security Playbooks Repository useful? Give us a star and help grow the community!**  
- Contribute code, documentation, or testing — see [CONTRIBUTING.md](CONTRIBUTING.md) for details.  
- Visit the [Official Website](https://secwexen.github.io/security-playbooks/) for documentation, updates, and project information.
- Visit the [Security Playbooks Wiki — Full Documentation](https://github.com/secwexen/security-playbooks/wiki) for detailed guides, architecture, agent behavior models, and project updates.

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

## Development Status

**Security Playbooks** is currently in **Active Development** stage.

## Note

Scripts, scenarios, and detection rules are for **educational and lab use only**.

## External References

- **MITRE ATT&CK Framework** — [https://attack.mitre.org](https://attack.mitre.org)  
- **NIST Cybersecurity Framework (CSF)** — [https://www.nist.gov/cyberframework](https://www.nist.gov/cyberframework)  
- **OWASP Security Projects** — [https://owasp.org](https://owasp.org)  
- **Microsoft Security Research & Threat Intelligence** — [https://www.microsoft.com/en-us/security/blog/](https://www.microsoft.com/en-us/security/blog/)  
- **Google Red Team** — [https://redteam.google/](https://redteam.google/)  
- **Elastic Security Labs** — [https://www.elastic.co/security-labs](https://www.elastic.co/security-labs)  
- **Sigma HQ** — [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)  
