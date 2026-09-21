# Development Guide

This document describes the development workflow and standards for Security Playbooks.

## 1. Development Environment

Security Playbooks uses Python 3.11 or later.

Create and activate a virtual environment:

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## 2. Repository Structure

Main development areas include:

```text
playbooks/         # Security playbooks
detection-rules/   # Sigma, YARA, and Suricata rules
docs/              # Documentation
labs/              # Controlled labs and test data
scripts/           # Automation and utilities
tests/             # Automated tests
integrations/      # Security platform integrations
reports/           # Validation reports
```

## 3. Development Standards

Changes should:

- follow the existing repository structure and naming conventions;
- preserve YAML and Markdown formatting;
- use valid MITRE ATT&CK mappings;
- reference only existing playbooks and detection rules;
- avoid duplicate or unnecessary content;
- preserve defensive and authorized-use requirements.

## 4. Playbook Development

New or modified playbooks should include:

- YAML front matter;
- MITRE ATT&CK mapping;
- trigger conditions;
- investigation procedure;
- evidence requirements;
- decision criteria;
- escalation guidance;
- response guidance;
- related detection rules;
- related playbooks;
- validation;
- safety guidance.

Detection-rule references must point to files that actually exist in [Detection Rules](/detection-rules/).

## 5. Detection Rule Development

Detection rules must use the appropriate repository format:

- Sigma
- YARA
- Suricata

New or modified rules should include appropriate metadata, valid syntax, and supported ATT&CK mappings where applicable.

## 6. Testing

Run the test suite before submitting changes:

```bash
python -m pytest -v
```

Tests should pass for changes to playbooks, detection rules, schemas, scripts, and related documentation.

## 7. Validation

Detection rules and playbooks should be validated using approved fixtures, datasets, or controlled laboratory scenarios.

Do not validate security content against unauthorized systems or production environments.

## 8. Makefile

The root `Makefile` provides common development and validation commands.

Run commands from the repository root:

```bash
make install
make lint
make validate
make test
make check
```

Use `make check` to run the complete development pipeline.
