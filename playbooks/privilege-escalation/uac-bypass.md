---
id: "uac-bypass"
name: "UAC Bypass"
category: "privilege-escalation"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-24T17:58:00Z"
updated_at: "2026-09-24T17:58:00Z"
description: "UAC Bypass occurs when an attacker attempts to circumvent Windows User Account Control to execute a process with elevated privileges without following the expected elevation workflow."
objective: "Identify, investigate, and validate suspicious UAC bypass activity and determine whether unauthorized privilege escalation occurred."
severity: "high"
mitre_attack:
  - "T1548.002"
triggers:
  - "Unexpected high-integrity process execution"
  - "Suspicious execution of an auto-elevated Windows component"
  - "Unexpected process elevation from a non-elevated context"
  - "Suspicious UAC-related Registry activity"
  - "Abnormal parent-child process relationship associated with elevated execution"
  - "EDR or SIEM alert indicating possible UAC bypass activity"
prerequisites:
  - "Access to Windows process creation telemetry"
  - "Access to endpoint security or EDR telemetry"
  - "Access to Windows Registry activity telemetry"
  - "Access to account and privilege telemetry"
tags:
  - "uac-bypass"
  - "privilege-escalation"
  - "uac"
  - "windows"
  - "endpoint-security"
  - "mitre-attack"
references:
  - "https://attack.mitre.org/techniques/T1548/002/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify UAC Bypass Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, user account, process, timestamp, integrity level, and alert context."
  expected_result: "The suspicious UAC-related activity and affected asset are identified."
- id: "identify-user-context"
  order: 2
  name: "Identify User and Privilege Context"
  action: "analyze"
  description: "Review the initiating account, group membership, privilege state, and expected administrative role associated with the activity."
  expected_result: "The initiating user's privilege context and expected elevation behavior are documented."
- id: "review-process-lineage"
  order: 3
  name: "Review Process Lineage"
  action: "analyze"
  description: "Review the suspicious process, parent process, ancestor processes, command line, execution path, and child processes to identify abnormal elevation behavior."
  expected_result: "The process execution chain and potential elevation point are identified."
- id: "review-uac-indicators"
  order: 4
  name: "Review UAC Bypass Indicators"
  action: "analyze"
  description: "Investigate the use of auto-elevated Windows components, unusual execution paths, abnormal process relationships, and other indicators associated with UAC bypass activity."
  expected_result: "Relevant UAC bypass indicators are identified or ruled out."
- id: "review-registry-activity"
  order: 5
  name: "Review Registry Activity"
  action: "analyze"
  description: "Review Registry creation and modification events that occurred before, during, or after the suspected UAC bypass activity."
  expected_result: "Relevant Registry modifications are correlated with the suspicious process activity or determined to be unrelated."
- id: "validate-elevation"
  order: 6
  name: "Validate Privilege Elevation"
  action: "analyze"
  description: "Determine whether the suspicious process actually executed with elevated privileges by correlating integrity level, token information, account context, and endpoint telemetry."
  expected_result: "Privilege elevation is confirmed, ruled out, or remains inconclusive."
- id: "determine-scope"
  order: 7
  name: "Determine UAC Bypass Scope"
  action: "hunt"
  description: "Search for the same process, account, execution pattern, Registry activity, hash, or related indicators across the affected environment."
  expected_result: "The prevalence and scope of the suspected UAC bypass activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the UAC bypass activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "uac-bypass"
---

# UAC Bypass

## Purpose

This playbook provides a structured workflow for investigating suspected UAC bypass activity on Windows endpoints.

Windows User Account Control (UAC) is designed to limit unauthorized elevation of privileges. UAC bypass activity attempts to circumvent the expected elevation workflow and obtain elevated execution without normal user interaction.

The objective is to determine whether the observed behavior represents legitimate administrative activity, suspicious execution, or confirmed unauthorized privilege escalation.

## MITRE ATT&CK

| Technique | Name                                                           | Relevance                                                                                 |
| --------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Relevant when an actor bypasses Windows UAC to execute a process with elevated privileges |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An unexpected high-integrity process is created.
- A non-elevated process launches an unexpectedly elevated child process.
- An auto-elevated Windows component is executed from an unusual context.
- Suspicious Registry activity is associated with process elevation.
- Process lineage indicates abnormal elevation behavior.
- An endpoint security product reports possible UAC bypass activity.
- Threat hunting identifies suspicious UAC-related execution.

## Scope

The investigation should consider:

- affected host;
- username;
- user privilege state;
- process name;
- process path;
- command line;
- parent process;
- child processes;
- process integrity level;
- process token information;
- executable hash;
- digital signature;
- Registry activity;
- security events;
- EDR telemetry;
- related alerts;
- additional affected hosts.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- username;
- suspicious process;
- process path;
- parent process;
- integrity level;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify User and Privilege Context

Collect:

- username;
- account type;
- group membership;
- administrative status;
- assigned privileges;
- logon context;
- expected administrative activity.

Determine whether the user was expected to perform an elevated operation on the affected host.

### Step 3 — Review Process Lineage

Review:

- suspicious process;
- parent process;
- ancestor processes;
- child processes;
- command line;
- executable path;
- process creation timestamps;
- process integrity level;
- execution account.

Determine whether the process tree contains an unexpected transition from a non-elevated context to an elevated context.

### Step 4 — Review UAC Bypass Indicators

Review:

- use of auto-elevated Windows components;
- unusual execution paths;
- abnormal parent-child relationships;
- unexpected elevated processes;
- process execution inconsistent with the endpoint baseline;
- repeated elevation attempts.

A known Windows component alone should not be treated as proof of malicious behavior. Correlate process identity, path, parent, user, integrity level, and timing.

### Step 5 — Review Registry Activity

Review:

- Registry creation;
- Registry modification;
- UAC-related configuration changes;
- Registry activity immediately preceding elevation;
- Registry activity performed by unexpected accounts or processes.

Determine whether Registry activity is associated with the suspected elevation event.

Do not modify Registry keys during investigation before required evidence has been preserved and authorization has been established.

### Step 6 — Validate Privilege Elevation

Determine:

- process integrity level;
- process token information;
- execution account;
- privilege state;
- elevated child processes;
- security or EDR events associated with the elevation.

Determine whether elevated execution actually occurred and whether it was expected.

### Step 7 — Determine Activity Scope

Search the environment for:

- same username;
- same host;
- same process path;
- same file hash;
- same command-line pattern;
- same Registry activity;
- same process lineage;
- related alerts.

Determine:

- number of affected hosts;
- number of affected accounts;
- first observed activity;
- latest observed activity;
- whether the behavior is isolated;
- whether additional post-elevation activity occurred.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence        | Description                                                 |
| --------------- | ----------------------------------------------------------- |
| Alert           | Detection source, ID, severity, timestamp                   |
| Host            | Hostname, IP address, operating system                      |
| User            | Username, account type, privilege context                   |
| Process         | Process name, path, command line                            |
| Process Tree    | Parent, ancestor, and child processes                       |
| Integrity       | Process integrity level and elevation state                 |
| Token           | Security token and privilege information                    |
| Registry        | Relevant Registry creation or modification events           |
| Executable      | Path, hash, signature, metadata                             |
| EDR Telemetry   | Endpoint process and behavioral data                        |
| Security Events | Relevant Windows security events                            |
| Timeline        | Process, Registry, authentication, and elevation timestamps |
| Scope           | Other affected hosts and accounts                           |
| Detections      | Related security alerts                                     |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the elevation is authorized;
- the initiating account is expected to perform administrative operations;
- process lineage matches known administrative behavior;
- the executable and path are expected;
- Registry activity is legitimate;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the elevation behavior is unexpected;
- process lineage deviates from the normal endpoint baseline;
- Registry activity is unexplained;
- the user or application cannot be immediately validated;
- elevated execution is observed but malicious intent is not established;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized privilege elevation;
- UAC bypass behavior associated with an untrusted or unauthorized process;
- suspicious process lineage supporting privilege escalation;
- unauthorized Registry activity associated with the elevation;
- post-elevation activity consistent with compromise;
- broader malicious activity associated with the same account or host.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the observed elevation was legitimate or unauthorized.

Document:

- evidence collected;
- evidence unavailable;
- telemetry limitations;
- additional data required.

## Escalation

Escalate the investigation when:

- unauthorized privilege elevation is confirmed;
- suspicious execution continues after elevation;
- persistence is identified;
- credential access is observed;
- lateral movement is identified;
- command-and-control activity is detected;
- multiple hosts show the same UAC bypass pattern;
- the affected account or endpoint may be compromised.

## Response Guidance

For confirmed malicious UAC bypass activity:

1. Preserve process, Registry, account, and endpoint telemetry.
2. Identify all affected hosts, accounts, and processes.
3. Follow the organization's endpoint containment procedure.
4. Determine whether elevated processes are still active.
5. Investigate post-elevation activity before removing relevant artifacts.
6. Review the affected account for additional suspicious activity.
7. Remediate unauthorized Registry or configuration changes according to approved procedures.
8. Investigate persistence, credential access, and lateral movement.
9. Review endpoint security controls and UAC configuration.
10. Escalate confirmed compromise to incident response.
11. Document the investigation timeline and remediation actions.

Do not terminate processes, modify Registry entries, or change endpoint configuration before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

No dedicated UAC bypass detection rule is currently available in the repository.

## Related Playbooks

- `playbooks/privilege-escalation/token-manipulation.md`
- `playbooks/privilege-escalation/scheduled-task-abuse.md`
- `playbooks/privilege-escalation/privileged-service-abuse.md`
- `playbooks/privilege-escalation/weak-service-permissions.md`

## Validation

The playbook should be validated against approved Windows endpoint telemetry, process creation events, Registry activity, privilege metadata, and controlled laboratory scenarios.

Validation should confirm that:

- suspicious elevated processes can be identified;
- process lineage can be reconstructed;
- user privilege context can be established;
- relevant Registry activity can be correlated;
- privilege elevation can be validated;
- legitimate administrative elevation can be distinguished from suspicious activity;
- environmental scope can be determined;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

UAC bypass techniques should only be evaluated in isolated and explicitly authorized environments. Do not intentionally bypass UAC, modify security controls, or perform privilege-escalation testing on production systems or systems without explicit authorization.
