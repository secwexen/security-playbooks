---
id: "lateral-movement-triage"
name: "Lateral Movement Triage"
category: "triage"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-04T00:00:00Z"
updated_at: "2026-09-04T00:00:00Z"
description: "Investigate suspected lateral movement activity and determine whether unauthorized access or remote execution occurred between systems."
objective: "Determine the source, destination, technique, scope, and legitimacy of suspected lateral movement and identify whether containment or incident response is required."
severity: "high"
mitre_attack:
  - "T1021"
  - "T1047"
  - "T1078"
triggers:
  - "Lateral movement alert"
  - "Unexpected remote authentication"
  - "Unusual remote service activity"
  - "Suspicious administrative protocol usage"
  - "Unexpected access between internal systems"
  - "Threat hunting identifies anomalous remote execution or authentication"
prerequisites:
  - "Access to authentication telemetry"
  - "Access to endpoint process telemetry"
  - "Access to network telemetry"
  - "Access to remote service logs where available"
tags:
  - "lateral-movement"
  - "triage"
  - "remote-access"
  - "authentication"
  - "endpoint"
references:
  - "https://attack.mitre.org/techniques/T1021/"
  - "https://attack.mitre.org/techniques/T1047/"
  - "https://attack.mitre.org/techniques/T1078/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Lateral Movement Alert"
  action: "investigate"
  description: "Identify the detection source, source system, destination system, account, timestamp, and suspected lateral movement technique."
  expected_result: "The suspected lateral movement event and involved systems are identified."
- id: "identify-source-destination"
  order: 2
  name: "Identify Source and Destination"
  action: "analyze"
  description: "Determine which system initiated the activity and which system received or was accessed by the activity."
  expected_result: "The source and destination systems are clearly documented."
- id: "review-authentication"
  order: 3
  name: "Review Authentication Activity"
  action: "analyze"
  description: "Review authentication events, account context, logon type, and authentication method associated with the activity."
  expected_result: "The authentication context is understood and assessed."
- id: "review-remote-service"
  order: 4
  name: "Review Remote Service Activity"
  action: "analyze"
  description: "Determine which remote service or protocol was used and review associated activity."
  expected_result: "The remote access or execution mechanism is identified."
- id: "review-process-activity"
  order: 5
  name: "Review Process Activity"
  action: "analyze"
  description: "Review process creation, parent-child relationships, command lines, and remote execution artifacts on the source and destination systems."
  expected_result: "Relevant process activity is documented and correlated."
- id: "correlate-related-activity"
  order: 6
  name: "Correlate Related Activity"
  action: "hunt"
  description: "Search for credential access, privilege escalation, persistence, discovery, and additional remote access activity."
  expected_result: "Related attack activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Movement Scope"
  action: "hunt"
  description: "Search the environment for additional source systems, destination systems, accounts, and repeated lateral movement patterns."
  expected_result: "The scope of the suspected lateral movement is determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "lateral-movement"
---

# Lateral Movement Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspected lateral movement between systems.

The objective is to determine whether remote authentication, remote execution, or remote service activity represents legitimate administrative behavior, suspicious activity, or confirmed unauthorized access.

## MITRE ATT&CK

| Technique | Name                               | Relevance                                                                         |
| --------- | ---------------------------------- | --------------------------------------------------------------------------------- |
| T1021     | Remote Services                    | Relevant when an adversary uses remote services to access or move between systems |
| T1047     | Windows Management Instrumentation | Relevant when WMI is used for remote execution                                    |
| T1078     | Valid Accounts                     | Relevant when legitimate credentials are used for unauthorized access             |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A lateral movement detection is generated.
- Unexpected remote authentication is observed.
- An unusual administrative protocol is used between internal systems.
- A user authenticates to systems they do not normally access.
- Remote execution is observed from an unexpected source.
- Multiple systems show related remote access activity.
- Threat hunting identifies anomalous internal authentication or execution.

## Scope

The investigation should consider:

- source host;
- destination host;
- source IP;
- destination IP;
- associated user or service account;
- authentication method;
- logon type;
- remote service or protocol;
- process ID;
- parent process;
- child processes;
- command line;
- timestamps;
- network connections;
- privilege level;
- related credentials;
- persistence;
- additional affected hosts.

## Triage Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- source host;
- destination host;
- associated account;
- suspected technique;
- detection severity.

Preserve the original alert context before making containment or remediation changes.

### Step 2 — Identify Source and Destination

Determine:

- which system initiated the connection;
- which system received the connection;
- whether both systems are expected to communicate;
- whether the source and destination are in the same security boundary;
- whether the connection is normal for the account or application.

Pay particular attention to unexpected access to:

- servers;
- administrative systems;
- domain controllers;
- security infrastructure;
- other privileged systems.

### Step 3 — Review Authentication Activity

Review:

- successful authentication;
- failed authentication;
- account name;
- logon type;
- authentication protocol or method;
- authentication timestamp;
- source workstation;
- target system.

Determine whether the account normally accesses the destination system.

Investigate unusual activity such as:

- a standard user accessing administrative systems;
- a service account performing interactive activity;
- an account accessing multiple hosts in a short period;
- successful authentication following suspicious failures.

### Step 4 — Review Remote Service Activity

Identify the remote access mechanism.

Examples include:

- SMB;
- RDP;
- WinRM;
- WMI;
- SSH;
- other authorized remote administration services.

Review:

- connection time;
- source;
- destination;
- protocol;
- authentication context;
- associated process;
- remote execution events where available.

A legitimate remote administration protocol should not be classified as malicious without additional evidence.

### Step 5 — Review Process Activity

On the source and destination systems, review:

- process creation;
- parent process;
- child processes;
- command line;
- process account;
- integrity level;
- executable path;
- process timestamps.

Pay attention to unexpected remote execution patterns and processes that are inconsistent with normal administrative activity.

### Step 6 — Correlate Related Activity

Search for related:

- credential access;
- privilege escalation;
- discovery;
- persistence;
- process execution;
- authentication;
- network connections;
- security alerts.

Determine whether the lateral movement occurred before or after another suspicious event.

### Step 7 — Determine Environmental Scope

Search across the environment for:

- the same source host;
- the same destination host;
- the same account;
- the same remote service;
- the same process;
- the same command line;
- the same authentication pattern.

Determine:

- number of source systems;
- number of destination systems;
- number of affected accounts;
- first observed activity;
- most recent observed activity;
- whether movement is still active.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence       | Description                                   |
| -------------- | --------------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp     |
| Source         | Source hostname and IP address                |
| Destination    | Destination hostname and IP address           |
| User           | Associated user or service account            |
| Authentication | Logon type and authentication method          |
| Remote Service | RDP, SMB, WinRM, WMI, SSH, or other service   |
| Process        | Process metadata                              |
| Process Tree   | Parent and child processes                    |
| Command Line   | Complete command line                         |
| Network        | Related network connections                   |
| Privilege      | Account and process privilege context         |
| Timeline       | Related authentication and process timestamps |
| Scope          | Other affected systems and accounts           |
| Detections     | Related alerts and rule IDs                   |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the account is authorized;
- the source and destination are expected;
- the remote service is approved;
- the activity matches documented administration;
- no additional suspicious indicators are identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the source or destination is unusual;
- the account does not normally access the destination;
- remote execution is unexpected;
- multiple internal systems are accessed in an unusual pattern;
- suspicious process or authentication activity is present;
- additional investigation is required.

Continue investigation and correlate additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized remote access;
- confirmed credential misuse;
- confirmed unauthorized remote execution;
- lateral movement associated with malware;
- lateral movement associated with credential theft;
- coordinated access across multiple systems as part of a confirmed compromise.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the remote activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- a privileged account is involved unexpectedly;
- a domain controller or other critical system is accessed unexpectedly;
- multiple systems are affected;
- credential compromise is suspected;
- unauthorized remote execution is confirmed;
- persistence is identified;
- the activity is associated with malware or command-and-control behavior.

## Response Guidance

For confirmed malicious lateral movement:

1. Preserve relevant authentication, endpoint, and network evidence.
2. Follow the organization's containment procedure.
3. Identify compromised accounts and systems.
4. Search for additional lateral movement indicators across the environment.
5. Review credential exposure and privilege changes.
6. Contain affected accounts or hosts according to authorized procedures.
7. Investigate persistence and additional compromise.
8. Escalate to incident response.
9. Document the investigation timeline and actions taken.

Do not terminate sessions, disable accounts, or isolate systems before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/lsass-access.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/suricata/network-alert.rules`

## Related Playbooks

- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-powershell-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/lateral-movement/rdp-lateral-movement.md`
- `playbooks/lateral-movement/smb-lateral-movement.md`
- `playbooks/lateral-movement/winrm-lateral-movement.md`
- `playbooks/lateral-movement/wmi-lateral-movement.md`
- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/lateral-movement/pass-the-ticket.md`
- `playbooks/response/lateral-movement-response.md`
- `playbooks/response/account-compromise-response.md`

## Validation

The playbook should be validated against approved lateral movement test data, authentication telemetry, endpoint events, and controlled network scenarios.

Validation should confirm that:

- source and destination systems can be identified;
- suspicious authentication can be correlated;
- remote services can be identified;
- process and network activity can be correlated;
- environmental scope can be determined;
- legitimate administration can be distinguished from suspicious movement;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Remote access, account containment, endpoint isolation, and other response actions must follow applicable authorization, evidence-preservation, and change-management procedures.
