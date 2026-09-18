# Playbooks README

This directory contains a structured collection of **MITRE ATT&CK-aligned defensive security playbooks** designed for SOC operations, threat hunting, detection engineering, incident response, security validation, and authorized security testing.

The playbooks provide practical and reproducible workflows for investigating security alerts, analyzing adversary behavior, validating detections, conducting threat hunts, and responding to security incidents in controlled and authorized environments.

## Playbook Categories

Playbooks are organized into security-focused categories based on their primary purpose and operational workflow.

| Category                | Description                                            |
| ----------------------- | ------------------------------------------------------ |
| `cloud/`                | Cloud security and cloud account activities            |
| `collection/`           | Collection of data and information                     |
| `command-and-control/`  | Command-and-control communication                      |
| `credential-access/`    | Credential access and credential theft                 |
| `defense-evasion/`      | Evasion of security controls                           |
| `discovery/`            | Discovery of systems, accounts, services, and networks |
| `execution/`            | Command, script, and program execution                 |
| `exfiltration/`         | Data exfiltration activities                           |
| `impact/`               | Destructive or disruptive activities                   |
| `initial-access/`       | Initial access techniques and scenarios                |
| `lateral-movement/`     | Movement between systems                               |
| `persistence/`          | Persistence mechanisms                                 |
| `privilege-escalation/` | Privilege escalation activities                        |
| `response/`             | Incident response procedures                           |
| `triage/`               | Initial alert and event investigation                  |

## How to Use

Select the playbook that best matches the observed security event or behavior.

Each playbook provides:

- Investigation scope and objectives
- Trigger conditions
- Step-by-step investigation procedures
- Evidence to collect
- Decision and escalation criteria
- Related detection rules and playbooks
- Validation requirements
- Safety guidance

Playbooks should be adapted to the organization's available telemetry, security tooling, and documented incident-response procedures.

All activities must be performed in authorized environments.

For playbook structure, metadata, naming conventions, and maintenance requirements, see the [Playbook Guide](../docs/playbook-guide.md).
