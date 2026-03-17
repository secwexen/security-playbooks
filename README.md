# Cyber Threat Playbook

[![License](https://img.shields.io/github/license/secwexen/cyber-threat-playbook)](https://github.com/secwexen/cyber-threat-playbook/blob/main/LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen)](https://github.com/secwexen/cyber-threat-playbook)

Cyber Threat Playbook is an open-source, comprehensive cybersecurity playbook featuring MITRE ATT&CK attack simulations, detection engineering rules (Sigma, YARA, Suricata), PoC labs, and threat hunting workflows.

## About

The **Cyber Threat Playbook** is an open-source, educational, and portfolio-focused repository for cybersecurity professionals.  
It provides a structured collection of:

- MITRE ATT&CK-based attack scenarios  
- Sigma, YARA, and Suricata detection rules  
- Proof-of-Concept (PoC) scripts  
- Lab walkthroughs and practical exercises  

This repository is designed to **demonstrate professional cybersecurity skills**, including threat hunting, incident response, and pentesting workflows, in a safe and controlled environment.

## Overview

**Cyber Threat Playbook** is organized to give users a clear and practical view of real-world cybersecurity workflows:

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

The Cyber Threat Playbook is intended for cybersecurity expert who want to practice, analyze, and understand real-world cyber threats in a structured and controlled environment:

- **SOC Analysts** – for detection engineering, alert analysis, and log investigation  
- **Threat Hunters** – for hypothesis-driven hunting and adversary behavior analysis  
- **Blue Team Engineers** – for building and testing detection rules (Sigma, YARA, Suricata)  
- **Cybersecurity Students** – for hands-on learning and portfolio development  
- **Red Teamers (lab-only)** – for adversary emulation and controlled attack simulations  

## Repository Structure

```
cyber-threat-playbook/
├─ detection-rules/    # Sigma, YARA, Suricata rules for threat detection
├─ scenarios/          # MITRE ATT&CK-based attack simulations
├─ labs/               # PoC scripts and lab walkthroughs
├─ examples/           # Sample outputs, logs, and screenshots
├─ docs/               # Documentation and guides
└─ tools/              # Helper scripts and parsers
```

## Quick Start

```bash
git clone https://github.com/secwexen/cyber-threat-playbook.git
cd cyber-threat-playbook
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

## License

Copyright © 2026 secwexen.

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for full details.

## Disclaimer

The contents of this repository are for educational and research purposes. The repository owner assumes no responsibility for misuse or legal consequences. 

For full details, see [DISCLAIMER.md](/DISCLAIMER.md).

## Security

For guidance on safe usage and reporting vulnerabilities, see [SECURITY.md](/SECURITY.md).

## Note

Scripts, scenarios, and detection rules are for **educational and lab use only**.

## Author

**Secwexen** – Project Author, Lead & Maintainer    
**GitHub:** [github.com/secwexen](https://github.com/secwexen)
