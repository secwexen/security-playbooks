# Usage

This document describes how to use Security Playbooks for security investigation, detection validation, threat hunting, and authorized security testing.

## 1. Playbooks

Playbooks are located in:

```text
playbooks/
```

Select the playbook that matches the security event, investigation objective, or MITRE ATT&CK technique being investigated.

Each playbook provides investigation steps, evidence requirements, decision criteria, escalation guidance, and related detection rules.

## 2. Detection Rules

Detection rules are located in:

```text
detection-rules/
├── sigma/
├── yara/
└── suricata/
```

Use the appropriate rule format for the target detection platform and validate rules against approved test data before production deployment.

## 3. Labs and Test Data

Controlled datasets, logs, PCAP samples, and attack scenarios are located in:

```text
labs/
```

Use lab materials only in authorized and controlled environments.

## 4. Validation

Run the project test suite with:

```bash
python -m pytest -v
```

Use the relevant validation procedures when testing playbooks, detection rules, scripts, or integrations.

## 5. Integrations

Integration content is located in:

```text
integrations/
```

Review the applicable integration documentation before deploying queries, rules, or configurations to a security platform.
