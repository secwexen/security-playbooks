# Playbooks Guide

## Overview

Security Playbooks is a defensive security repository designed to support
SOC operations, threat hunting, detection engineering, incident response,
security validation, and authorized security testing.

This guide defines the structure, metadata requirements, writing standards,
MITRE ATT&CK mapping conventions, validation expectations, and maintenance
rules for all playbooks stored under the `playbooks/` directory.

All playbooks must remain consistent with the repository schemas, detection
rules, validation workflows, and authorized-use requirements.

## Playbook Organization

Playbooks are organized into directories based on their primary security function, investigation purpose, or MITRE ATT&CK-related activity.

The main categories include:

- `cloud/` — Cloud security and cloud account activities
- `collection/` — Data and information collection activities
- `command-and-control/` — C2 communication and remote control activities
- `credential-access/` — Credential theft and credential access investigations
- `defense-evasion/` — Techniques used to evade security controls
- `discovery/` — System, network, account, and environment discovery
- `execution/` — Command, script, and program execution
- `exfiltration/` — Data exfiltration activities
- `impact/` — Destructive and disruptive activities
- `initial-access/` — Initial access techniques and investigations
- `lateral-movement/` — Movement between systems
- `persistence/` — Persistence mechanisms
- `privilege-escalation/` — Privilege escalation techniques
- `response/` — Incident response procedures
- `triage/` — Initial alert and event investigation

Each playbook should belong to the category that best represents its primary purpose.

When a playbook involves multiple ATT&CK techniques or security functions, place it according to its primary behavior and document additional relationships in the `MITRE ATT&CK` and `Related Playbooks` sections.

Avoid duplicate playbooks and avoid creating new categories unless the existing structure cannot accurately represent the playbook.

## Playbook Structure

Every playbook should follow a consistent structure.

Recommended sections:

- Purpose
- MITRE ATT&CK
- Trigger Conditions
- Scope
- Investigation Procedure
- Evidence to Collect
- Decision Criteria
- Escalation
- Response Guidance
- Related Detection Rules
- Related Playbooks
- Validation
- Safety
