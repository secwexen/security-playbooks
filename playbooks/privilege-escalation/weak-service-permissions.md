---
id: "weak-service-permissions"
name: "Weak Service Permissions"
category: "privilege-escalation"
status: "active"
version: "1.0.1"
author: "Secwexen"
created_at: "2026-09-24T15:19:00Z"
updated_at: "2026-09-26T21:59:00Z"
description: "Weak Service Permissions occur when a Windows service executable or its containing directory can be modified by an unauthorized user, allowing replacement or modification of the service binary."
objective: "Identify, investigate, and validate suspicious service file or directory permissions and determine whether weak permissions enabled unauthorized execution, privilege escalation, persistence, or related malicious activity."
severity: "high"
mitre_attack:
  - "T1574.010"
triggers:
  - "Suspicious permissions on a Windows service executable"
  - "Unexpected user or group can modify a service binary"
  - "Unexpected modification or replacement of a service executable"
  - "Service executable located in a writable directory"
  - "Service starts an executable that was recently modified or replaced"
  - "Threat hunting identifies weak service file or directory permissions"
prerequisites:
  - "Access to Windows service configuration telemetry"
  - "Access to file and directory permission telemetry"
  - "Access to process creation telemetry"
  - "Access to account and privilege telemetry"
tags:
  - "weak-service-permissions"
  - "privilege-escalation"
  - "service"
  - "windows"
  - "file-permissions"
  - "directory-permissions"
  - "persistence"
references:
  - "https://attack.mitre.org/techniques/T1574/010/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify Weak Service Permission Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, service, executable, account, permissions, timestamp, and alert context."
    expected_result: "The suspicious service permission condition and affected asset are identified."
  - id: "identify-service"
    order: 2
    name: "Identify Service Configuration"
    action: "analyze"
    description: "Review the service name, executable path, service account, startup configuration, and expected ownership."
    expected_result: "The affected service and its execution context are documented."
  - id: "review-permissions"
    order: 3
    name: "Review File and Directory Permissions"
    action: "analyze"
    description: "Review permissions and ownership on the service executable and its parent directories to determine whether unauthorized users can modify or replace the executable."
    expected_result: "Potential unauthorized write or modification rights are identified or ruled out."
  - id: "review-file-activity"
    order: 4
    name: "Review File Activity"
    action: "analyze"
    description: "Review creation, modification, replacement, ownership, hashes, signatures, and timestamps for the service executable and related files."
    expected_result: "Suspicious service-file activity is identified or ruled out."
  - id: "review-process-activity"
    order: 5
    name: "Review Process Activity"
    action: "analyze"
    description: "Correlate service execution with process creation, executable paths, parent-child relationships, command lines, and execution timestamps."
    expected_result: "Service-related process activity is documented and correlated."
  - id: "review-privilege-context"
    order: 6
    name: "Review Privilege Context"
    action: "analyze"
    description: "Determine the security context under which the service executes and assess the privilege impact of unauthorized service binary modification."
    expected_result: "The potential privilege-escalation impact is established."
  - id: "determine-scope"
    order: 7
    name: "Determine Weak Permission Scope"
    action: "hunt"
    description: "Search for the same service executable, permission pattern, file hash, directory configuration, or affected account across the environment."
    expected_result: "The prevalence and scope of the weak service permission condition are determined."
  - id: "determine-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the service permission activity and document the evidence supporting the final assessment."
    expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "weak-service-permissions"
---

# Weak Service Permissions

## Purpose

This playbook provides a structured workflow for investigating weak permissions on Windows service executables and their associated directories.

A service executable or its containing directory with overly permissive write access may allow an unauthorized user to modify or replace the binary. When the service later executes under a more privileged security context, the modified executable may execute with those privileges.

The objective is to determine whether weak permissions represent an exploitable condition, whether unauthorized modification occurred, and whether the activity resulted in privilege escalation, persistence, or broader compromise.

## MITRE ATT&CK

| Technique | Name                                                      | Relevance                                                                                                                       |
| --------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| T1574.010 | Hijack Execution Flow: Services File Permissions Weakness | Relevant when weak file or directory permissions allow unauthorized modification or replacement of a Windows service executable |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A service executable has unexpected write permissions.
- A non-administrative user or group can modify a service binary.
- A service executable is located in a writable directory.
- A service binary is unexpectedly modified or replaced.
- A service starts an executable that was recently changed.
- Service execution is associated with suspicious file activity.
- Threat hunting identifies weak service permissions.

## Scope

The investigation should consider:

- affected host;
- service name;
- service executable path;
- service account;
- startup type;
- file owner;
- directory owner;
- file permissions;
- directory permissions;
- effective access;
- affected users and groups;
- executable hash;
- file signature;
- file creation time;
- file modification time;
- service configuration changes;
- process activity;
- authentication activity;
- related alerts;
- additional affected hosts.

## Investigation Procedure

### Step 1 — Identify Weak Service Permission Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- service name;
- executable path;
- affected account;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify Service Configuration

Collect:

- service name;
- display name;
- executable path;
- command line;
- startup type;
- service account;
- service state;
- service configuration timestamps where available.

Determine whether the service and executable are expected on the affected host.

### Step 3 — Review File and Directory Permissions

Review permissions on:

- service executable;
- executable parent directory;
- relevant parent directories;
- related service files.

Determine:

- file owner;
- directory owner;
- granted permissions;
- effective permissions;
- users and groups with write access;
- whether non-administrative identities can modify or replace the executable.

Pay particular attention to write or modify permissions granted to unexpected users or groups.

Do not change permissions during investigation before required evidence has been preserved and authorization has been established.

### Step 4 — Review File Activity

Review:

- file creation;
- file modification;
- file replacement;
- ownership changes;
- permission changes;
- file hashes;
- digital signatures;
- file timestamps.

Determine whether service-file changes align with expected maintenance or deployment activity.

Pay particular attention to newly created or recently modified executables associated with the service.

### Step 5 — Review Process Activity

Correlate the service with:

- service start events;
- process creation;
- executable path;
- parent process;
- child processes;
- command line;
- process timestamps;
- account context;
- integrity level where available.

Determine whether the service executed the expected binary or an unauthorized replacement.

### Step 6 — Review Privilege Context

Determine:

- service execution account;
- account type;
- group membership;
- assigned privileges;
- integrity level;
- expected service security context.

Assess whether unauthorized modification of the service executable could result in execution under a more privileged context.

### Step 7 — Determine Weak Permission Scope

Search the environment for:

- same service name;
- same executable path;
- same file hash;
- same permission pattern;
- same writable directory;
- same affected account;
- same service configuration.

Determine:

- number of affected hosts;
- number of affected services;
- number of affected accounts;
- first observed weak-permission condition;
- latest observed modification;
- whether unauthorized access is ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence              | Description                                      |
| --------------------- | ------------------------------------------------ |
| Alert                 | Detection source, ID, severity, timestamp        |
| Host                  | Hostname, IP address, operating system           |
| Service               | Name, path, state, startup type                  |
| Service Account       | Account and privilege context                    |
| File Permissions      | Service executable permissions and ownership     |
| Directory Permissions | Parent directory permissions and ownership       |
| Effective Access      | Users and groups able to modify the service      |
| Executable            | Path, hash, signature, metadata                  |
| File Activity         | Creation, modification, replacement, ownership   |
| Process               | Related process activity                         |
| Process Tree          | Parent and child processes                       |
| Configuration         | Service configuration and change history         |
| Authentication        | Relevant account and logon events                |
| Timeline              | File, service, process, and authentication times |
| Scope                 | Other affected hosts and services                |
| Detections            | Related security alerts                          |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the service permissions are intentional;
- only authorized administrators or service-management identities can modify the executable;
- the executable and directory ownership are expected;
- file modifications are associated with approved maintenance or software deployment;
- the service executes the expected binary;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- unexpected users or groups can modify the service executable;
- the service directory is writable by an inappropriate identity;
- file modifications are unexplained;
- the executable hash or signature changes unexpectedly;
- service execution follows suspicious file activity;
- related process or authentication activity is abnormal;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized modification or replacement of a service executable;
- an unauthorized user successfully changes a service binary;
- the modified executable is executed by the service;
- execution occurs under an elevated security context;
- service abuse is used for confirmed privilege escalation or persistence;
- the activity is part of a broader confirmed compromise.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the weak permission condition was benign or abused.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- unauthorized service-file modification is confirmed;
- an unexpected account can modify a privileged service executable;
- privilege escalation is confirmed;
- persistence is identified;
- multiple hosts contain the same weak permission condition;
- credential access or lateral movement is observed;
- command-and-control activity is identified.

## Response Guidance

For confirmed malicious weak service permission abuse:

1. Preserve service, file, process, permission, and account evidence.
2. Identify all affected hosts, services, and accounts.
3. Follow the organization's endpoint containment procedure.
4. Determine whether the service executable was modified or replaced.
5. Search for the same executable, hash, service, and permission pattern across the environment.
6. Investigate persistence, privilege escalation, credential access, and lateral movement.
7. Remediate excessive service file and directory permissions according to approved change procedures.
8. Remove unauthorized service artifacts only after required evidence preservation.
9. Review potentially exposed privileged accounts.
10. Escalate confirmed compromise to incident response.
11. Document the investigation timeline and remediation actions.

Do not modify service files, permissions, or configuration before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

## Related Playbooks

- `playbooks/privilege-escalation/privileged-service-abuse.md`
- `playbooks/privilege-escalation/unquoted-service-path.md`
- `playbooks/privilege-escalation/service-permission-abuse.md`
- `playbooks/persistence/service-persistence.md`
- `playbooks/execution/scheduled-task-execution.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/persistence-triage.md`
- `playbooks/response/persistence-removal-response.md`

## Validation

The playbook should be validated against approved Windows service configurations, file and directory permission datasets, service telemetry, process creation events, and controlled laboratory scenarios.

Validation should confirm that:

- service executable permissions can be identified;
- directory permissions can be investigated;
- effective write access can be determined;
- service-file modifications can be correlated with process execution;
- service privilege context can be established;
- legitimate service maintenance can be distinguished from unauthorized modification;
- environmental scope can be determined;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Service files, permissions, and configurations should be investigated using approved telemetry and controlled environments. Do not intentionally weaken service permissions, replace service binaries, or perform unauthorized privilege-escalation testing on production systems.
