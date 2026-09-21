# Getting Started

This guide will help you quickly set up and start using the Security Playbooks repository.

## 1. Clone the Repository

Clone the repository and move into the project directory:

```bash
git clone https://github.com/secwexen/security-playbooks.git
cd security-playbooks
```

## 2. Review the Repository Structure

The main project components are organized as follows:

```text
playbooks/            # Security investigation and response playbooks
detection-rules/      # Sigma, YARA, and Suricata detection rules
docs/                 # Project documentation
labs/                 # Training datasets, logs, PCAPs, and scenarios
integrations/         # SIEM and security-tool integrations
scripts/              # Automation and utility scripts
reports/              # Validation and test reports
tests/                # Automated tests
```

Review the relevant documentation before using playbooks, detection rules, or lab materials.

## 3. Install Python

The project requires Python 3.11 or later.

Check the installed version:

```bash
python --version
```

or:

```bash
python3 --version
```

Install Python 3.11+ if the required version is not available.

## 4. Install Dependencies

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install the project dependencies:

```bash
pip install -r requirements.txt
```

Install the project development dependencies:

```bash
pip install -r requirements-dev.txt
```

## 5. Run the Test Suite

Run the automated tests before making changes:

```bash
pytest
```

Use the test results to identify validation, metadata, schema, detection-rule, or playbook issues before contributing changes.

## 6. Explore the Playbooks

Playbooks are organized by security function and MITRE ATT&CK-related activity.

For example:

```text
playbooks/
├── initial-access/
├── execution/
├── persistence/
├── privilege-escalation/
├── credential-access/
├── defense-evasion/
├── lateral-movement/
├── discovery/
├── collection/
├── command-and-control/
├── exfiltration/
├── impact/
├── cloud/
├── triage/
└── response/
```

Start with the playbook that matches the observed security event or investigation objective.

Each playbook defines its purpose, ATT&CK mapping, triggers, investigation procedure, evidence requirements, decision criteria, escalation guidance, related detection rules, and validation requirements.

## 7. Review Detection Rules

Detection rules are located under:

```text
detection-rules/
├── sigma/
├── yara/
└── suricata/
```

Review the applicable rule before using or modifying a playbook.

Detection rules should be validated against approved datasets and test scenarios before being deployed into production security monitoring.
