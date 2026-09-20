---
id: "service-persistence"
name: "Windows Service Persistence"
category: "persistence"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-14T16:15:00Z"
updated_at: "2026-09-20T19:19:00Z"
description: "Windows services can be configured to start automatically and may be abused to establish persistence on Windows systems."
objective: "Identify, investigate, and validate suspicious Windows service persistence and determine whether the service configuration or associated executable is legitimate, suspicious, or malicious."
severity: "high"
mitre_attack:
  - "T1543.003"
triggers:
  - "Unexpected Windows service creation"
  - "Unexpected service modification"
  - "Unknown executable configured as a service"
  - "Service configured for automatic startup without an approved reason"
  - "Service created by an unexpected account or process"
  - "Threat hunting identifies anomalous service persistence"
prerequisites:
  - "Access to Windows service telemetry"
  - "Access to process creation telemetry"
  - "Access to command-line telemetry"
  - "Access to endpoint, file, and authentication telemetry where available"
tags:
  - "windows-service"
  - "service"
  - "persistence"
  - "windows"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1543/003/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Service Persistence Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, service name, account, creation or modification event, and timestamp."
  expected_result: "The suspicious service persistence event and affected asset are identified."
- id: "identify-service"
  order: 2
  name: "Identify Windows Service"
  action: "analyze"
  description: "Determine the service name, display name, service type, startup mode, executable path, service account, and configuration."
  expected_result: "The service configuration is documented."
- id: "review-service-lifecycle"
  order: 3
  name: "Review Service Lifecycle"
  action: "analyze"
  description: "Review service creation, modification, startup, stop, and deletion events and correlate them with administrative activity."
  expected_result: "The service lifecycle and relevant changes are established."
- id: "review-payload"
  order: 4
  name: "Review Service Payload"
  action: "analyze"
  description: "Review the executable path, command line, arguments, file hash, signature, and associated files referenced by the service."
  expected_result: "The service payload and execution context are assessed."
- id: "review-account-context"
  order: 5
  name: "Review Service Account"
  action: "analyze"
  description: "Determine which account runs the service and whether the configured identity and privileges are expected."
  expected_result: "The service account and privilege context are documented."
- id: "review-execution"
  order: 6
  name: "Review Service Execution"
  action: "analyze"
  description: "Correlate service startup with process creation, parent-child relationships, file activity, and network activity."
  expected_result: "Service execution and resulting activity are correlated."
- id: "determine-scope"
  order: 7
  name: "Determine Persistence Scope"
  action: "hunt"
  description: "Search for the same service name, executable, hash, command line, account, or persistence pattern across the environment."
  expected_result: "The prevalence and scope of the service persistence are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the service persistence activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "service-persistence"
---

# Windows Service Persistence

## Purpose

This playbook provides a structured workflow for investigating suspicious Windows service persistence.

Windows services are legitimate operating system and application mechanisms used for background and automatic execution. They can also be abused to establish persistence by configuring a service to launch an unauthorized program.

The objective is to determine whether a service configuration is legitimate, suspicious, or malicious and whether it is associated with additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name                                             | Relevance                                                                                   |
| --------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| T1543.003 | Create or Modify System Process: Windows Service | Relevant when a Windows service is created or modified to establish or maintain persistence |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An unexpected Windows service is created.
- An existing service is unexpectedly modified.
- A service references an unknown executable or script.
- A service is configured for automatic startup without an approved reason.
- A service runs under an unexpected account or privilege context.
- A service executable is stored in an unusual location.
- A known suspicious or malicious file is configured as a service payload.
- Threat hunting identifies anomalous service persistence.

## Scope

The investigation should consider:

- affected host;
- service name;
- display name;
- service type;
- startup mode;
- service state;
- executable path;
- command line;
- arguments;
- service account;
- privilege context;
- creation time;
- modification time;
- service start time;
- process tree;
- file activity;
- network activity;
- authentication activity;
- related alerts;
- additional affected hosts.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- service name;
- associated account;
- detection severity;
- detection reason.

Preserve the original alert context before modifying or removing the service.

### Step 2 — Identify the Windows Service

Collect:

- service name;
- display name;
- service type;
- startup mode;
- current state;
- executable path;
- command line;
- service account;
- dependencies.

Determine whether the service belongs to known and approved software.

### Step 3 — Review Service Lifecycle

Determine:

- when the service was created;
- which account created it;
- when it was modified;
- which account modified it;
- when it started;
- whether its configuration changed before the alert.

Correlate service creation or modification with:

- software installation;
- system administration;
- patching;
- application updates;
- security events;
- process creation.

### Step 4 — Review Service Payload

Review the executable or script referenced by the service.

Collect:

- executable path;
- filename;
- command line;
- arguments;
- file hash;
- file type;
- file timestamps;
- digital signature where applicable.

Pay particular attention to payloads located in:

- user-writable directories;
- temporary directories;
- unusual application data paths;
- hidden directories;
- unexpected system locations.

A legitimate service executable should be evaluated in the context of its publisher, installation source, expected path, and normal system behavior.

### Step 5 — Review Service Account

Determine:

- service account;
- privilege level;
- logon context;
- whether the account is expected;
- whether the account has excessive privileges for the service.

An elevated service account is not inherently malicious. Assess it against the normal requirements of the associated service.

### Step 6 — Review Service Execution

Correlate the service with:

- service start events;
- process creation;
- parent-child relationships;
- command-line telemetry;
- file activity;
- network connections;
- DNS activity.

Determine whether service startup resulted in unexpected or suspicious activity.

### Step 7 — Determine Persistence Scope

Search the environment for:

- same service name;
- same display name;
- same executable;
- same file hash;
- same command line;
- same service account;
- same configuration pattern.

Determine:

- number of affected hosts;
- number of affected accounts;
- first observed service creation;
- latest observed service start;
- whether the suspicious service remains active.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence       | Description                                          |
| -------------- | ---------------------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp            |
| Host           | Hostname, IP address, operating system               |
| Service        | Service name, display name, type, state              |
| Startup Mode   | Automatic, manual, or other configuration            |
| Payload        | Executable path, command line, arguments             |
| Account        | Service account and privilege context                |
| Lifecycle      | Creation, modification, startup, and deletion events |
| Process        | Service-related process activity                     |
| Process Tree   | Parent and child processes                           |
| Hash           | SHA-256 or available file hash                       |
| Signature      | Digital signature information where available        |
| Files          | Created, modified, downloaded, or executed files     |
| Network        | Related network connections                          |
| DNS            | Related DNS activity                                 |
| Authentication | Relevant authentication events                       |
| Scope          | Other affected hosts and services                    |
| Detections     | Related security alerts                              |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the service belongs to approved software;
- creation or modification was expected;
- the executable is known and trusted;
- the executable path is appropriate;
- the service account is expected;
- startup behavior is consistent with normal operations;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the service origin is unclear;
- the service was unexpectedly created or modified;
- the executable path is unusual;
- the payload is unknown;
- the service account is unexpected;
- the command line is abnormal;
- related process, file, or network activity is suspicious;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized service persistence;
- confirmed malicious executable or script;
- service configuration associated with malware;
- confirmed command-and-control activity;
- credential access;
- lateral movement;
- other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the service persistence is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious service persistence is confirmed;
- multiple hosts contain the same suspicious service;
- a privileged service account is unexpectedly involved;
- the service payload is associated with known malware;
- credential compromise is suspected;
- lateral movement is identified;
- command-and-control activity is observed;
- a business-critical system is affected.

## Response Guidance

For confirmed malicious service persistence:

1. Preserve service, process, file, authentication, and network evidence.
2. Identify all affected hosts and service accounts.
3. Determine whether the service is currently running.
4. Follow the organization's endpoint containment procedure.
5. Search for related service names, payloads, hashes, command lines, and process relationships.
6. Investigate additional persistence mechanisms.
7. Follow authorized service remediation procedures.
8. Review possible credential exposure.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Do not immediately delete or modify the suspicious service before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/obfuscated-powershell.yar`
- `detection-rules/yara/yara-powershell-payload.yar`

## Related Playbooks

- `playbooks/persistence/scheduled-task-persistence.md`
- `playbooks/persistence/registry-run-keys.md`
- `playbooks/persistence/startup-folder.md`
- `playbooks/privilege-escalation/privileged-service-abuse.md`
- `playbooks/privilege-escalation/service-permission-abuse.md`
- `playbooks/privilege-escalation/weak-service-permissions.md`
- `playbooks/privilege-escalation/unquoted-service-path.md`
- `playbooks/triage/persistence-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/response/persistence-removal-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved Windows service telemetry, service metadata, process creation events, endpoint telemetry, and controlled persistence scenarios.

Validation should confirm that:

- service creation can be identified;
- service modification can be investigated;
- service configuration can be analyzed;
- service accounts and privileges can be assessed;
- service startup can be correlated with process activity;
- payload files can be analyzed;
- related file and network activity can be investigated;
- persistence scope can be determined;
- legitimate services can be distinguished from malicious persistence;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Service creation, modification, startup, or removal should only be performed in approved testing or administrative environments. Do not modify or remove production services outside authorized procedures.
