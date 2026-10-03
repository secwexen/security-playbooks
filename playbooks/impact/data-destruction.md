---
id: "data-destruction"
name: "Data Destruction"
category: "impact"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-03T15:25:00Z"
updated_at: "2026-10-03T15:25:00Z"
description: "Data Destruction involves the unauthorized deletion, overwriting, or deliberate destruction of files and stored data to impair availability or render information irrecoverable."
objective: "Identify, investigate, and scope suspected data destruction activity, determine the affected data and assets, assess recoverability, and support containment and recovery actions."
severity: "high"
mitre_attack:
  - "T1485"
triggers:
  - "Mass deletion or overwrite of files or directories"
  - "Wiper or destructive malware activity"
  - "Abnormal file destruction across multiple systems"
  - "Unexpected deletion of critical business data"
  - "Unauthorized deletion of cloud storage objects or infrastructure data"
  - "Threat hunting identifies destructive file activity"
prerequisites:
  - "Access to endpoint file and process telemetry"
  - "Access to authentication and account telemetry"
  - "Access to storage and backup telemetry where available"
  - "Access to network and cloud activity logs where applicable"
tags:
  - "data-destruction"
  - "impact"
  - "wiper"
  - "file-deletion"
  - "availability"
  - "windows"
  - "linux"
references:
  - "https://attack.mitre.org/techniques/T1485/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Data Destruction Alert"
  action: "investigate"
  description: "Identify the detection source, affected asset, timestamp, account, process, and alert context associated with the suspected destructive activity."
  expected_result: "The suspected data destruction activity and initial affected asset are identified."
- id: "identify-affected-data"
  order: 2
  name: "Identify Affected Data and Assets"
  action: "investigate"
  description: "Determine which files, directories, storage locations, systems, or cloud resources were affected by the destructive activity."
  expected_result: "The affected data, storage locations, and assets are documented."
- id: "review-destruction-activity"
  order: 3
  name: "Review Destruction Activity"
  action: "analyze"
  description: "Review file deletion, overwrite, truncation, corruption, or destructive storage operations and determine the mechanism used."
  expected_result: "The observed destruction mechanism and affected data are characterized."
- id: "review-execution-context"
  order: 4
  name: "Review Execution Context"
  action: "analyze"
  description: "Review the initiating account, process, command line, executable path, parent-child relationships, authentication activity, and security context associated with the destructive operation."
  expected_result: "The execution context and initiating activity are documented."
- id: "assess-data-recoverability"
  order: 5
  name: "Assess Data Recoverability"
  action: "analyze"
  description: "Determine whether affected data remains recoverable through available backups, snapshots, replicas, forensic techniques, or other approved recovery mechanisms."
  expected_result: "The current recoverability of affected data is assessed."
- id: "correlate-related-activity"
  order: 6
  name: "Correlate Related Activity"
  action: "analyze"
  description: "Correlate the destructive activity with authentication, privilege escalation, lateral movement, malware execution, persistence, command-and-control, and other related events."
  expected_result: "Related attack activity and potential compromise context are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Destruction Scope"
  action: "hunt"
  description: "Search across the environment for the same process, command line, executable, file pattern, account, hash, storage operation, or destructive behavior."
  expected_result: "The prevalence, affected assets, affected data, and temporal scope of the destruction are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the activity and document the evidence supporting the final investigation outcome."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "data-destruction"
---

# Data Destruction

## Purpose

This playbook provides a structured SOC workflow for investigating suspected data destruction activity intended to impair data availability or render stored information irrecoverable.

Data destruction may involve deletion, overwriting, truncation, corruption, or other destructive operations affecting individual files or stored data. The investigation should distinguish data destruction from disk-level wiping activity and from routine file deletion performed as part of legitimate administration.

The objective is to determine whether the observed activity is legitimate, suspicious, or malicious, identify the affected data and assets, assess recoverability, and establish the operational scope of the event.

## MITRE ATT&CK

| Technique | Name             | Relevance                                                                                    |
| --------- | ---------------- | -------------------------------------------------------------------------------------------- |
| T1485     | Data Destruction | Primary technique for intentional destruction of files or stored data to impair availability |

T1485 is categorized by MITRE ATT&CK under the **Impact** tactic. Its current Enterprise scope includes Windows, Linux, macOS, IaaS, ESXi, and container environments.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Large-scale deletion or overwrite of files or directories.
- Unexpected destruction of business-critical data.
- Wiper malware or destructive tooling is identified.
- Destructive file operations occur across multiple systems.
- Cloud storage objects or infrastructure resources are unexpectedly deleted.
- Threat hunting identifies coordinated destructive activity.
- Recovery assets or stored data are altered in a manner consistent with deliberate destruction.

Common file deletion commands do not necessarily make data irrecoverable; investigation should determine whether data was merely unlinked or was actually overwritten or otherwise destroyed.

## Scope

The investigation should consider:

- affected hosts;
- affected users;
- affected files and directories;
- file systems;
- network shares;
- databases and application data;
- cloud storage resources;
- virtual machines and storage resources where applicable;
- destructive process and command line;
- parent process;
- executable path;
- account and privilege context;
- authentication activity;
- backup and snapshot availability;
- related malware or tooling;
- related network activity;
- other affected systems;
- data recoverability.

## Investigation Procedure

### Step 1 — Identify Data Destruction Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host or storage resource;
- associated account;
- process or service;
- detection severity;
- detection reason.

Preserve the original alert context before performing remediation or recovery actions.

### Step 2 — Identify Affected Data and Assets

Determine:

- affected files;
- affected directories;
- file extensions;
- storage locations;
- network shares;
- databases;
- cloud objects;
- affected hosts;
- affected applications;
- first observed destruction time;
- latest observed destruction time.

Prioritize business-critical, security-sensitive, and operationally essential data.

### Step 3 — Review Destruction Activity

Review:

- deletion events;
- overwrite operations;
- file truncation;
- corruption indicators;
- destructive utilities;
- scripts;
- command lines;
- file-system activity;
- storage API activity where applicable.

Determine whether the activity represents routine file management or deliberate destruction.

Data destruction involving file deletion or overwrite should be distinguished from disk-level destruction techniques that target disk content or disk structure.

### Step 4 — Review Execution Context

Determine:

- initiating account;
- account type;
- privilege level;
- process name;
- executable path;
- command line;
- parent process;
- child processes;
- execution time;
- process hash;
- digital signature where available;
- related authentication activity.

Assess whether the execution context is consistent with approved administrative or operational activity.

### Step 5 — Assess Data Recoverability

Determine:

- backup availability;
- backup integrity;
- snapshot availability;
- replication status;
- unaffected copies;
- file recoverability;
- forensic recovery options;
- affected recovery infrastructure.

Do not modify affected storage or recovery sources before required evidence preservation and authorization have been considered.

Backups should be protected from the same destructive activity and maintained in a manner that supports restoration after compromise.

### Step 6 — Correlate Related Activity

Correlate the destruction timeline with:

- authentication events;
- privilege escalation;
- lateral movement;
- malware execution;
- persistence;
- command-and-control activity;
- security control modification;
- backup-related activity;
- activity on other hosts.

Determine whether the destruction is an isolated event or part of a broader attack chain.

### Step 7 — Determine Destruction Scope

Search the environment for:

- same process;
- same executable;
- same command line;
- same file hash;
- same account;
- same file or directory pattern;
- same storage operation;
- same destructive behavior.

Determine:

- number of affected hosts;
- number of affected accounts;
- amount and type of affected data;
- first observed destruction;
- latest observed destruction;
- whether destructive activity remains active;
- whether recovery resources are also affected.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence       | Description                                         |
| -------------- | --------------------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp           |
| Host           | Hostname, IP address, operating system              |
| Account        | Initiating account and privilege context            |
| Process        | Process name, PID, path, hash                       |
| Command Line   | Complete destructive command line                   |
| Parent Process | Parent process and execution chain                  |
| File Activity  | Deleted, overwritten, truncated, or corrupted files |
| Storage        | Affected local, remote, or cloud storage            |
| Authentication | Related logon and account activity                  |
| Network        | Related network connections                         |
| Malware        | Associated malware or destructive tooling           |
| Backup         | Backup, snapshot, and replication status            |
| Timeline       | Destruction and related event timestamps            |
| Scope          | Other affected assets and data                      |
| Recovery       | Recoverability and restoration options              |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the operation is authorized;
- the initiating account is expected;
- the affected data is non-sensitive or intentionally removed;
- the process and command line are consistent with approved administration;
- no abnormal related activity is identified;
- the observed deletion is part of a documented retention or maintenance process.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the operation is unexpected;
- the initiating account is unusual;
- the command line is abnormal;
- large numbers of files are affected;
- destructive utilities or scripts are involved;
- the activity targets unusual or sensitive data;
- related telemetry indicates possible compromise;
- the full impact or intent cannot yet be established.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized destruction of organizational data;
- deliberate file overwrite or destructive modification;
- confirmed wiper or destructive malware activity;
- coordinated destruction across multiple systems;
- destruction performed as part of a broader compromise;
- intentional destruction of critical operational data;
- destructive activity targeting recovery resources.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the destruction was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- affected data that could not be assessed;
- additional telemetry required;
- recovery information that remains unknown.

## Escalation

Escalate the investigation when:

- unauthorized data destruction is confirmed;
- critical business data is affected;
- multiple hosts or systems are impacted;
- destructive activity is ongoing;
- recovery resources are affected;
- destructive malware or wiper functionality is identified;
- privilege escalation or lateral movement is observed;
- command-and-control activity is identified;
- data recoverability is uncertain or significantly impaired.

## Response Guidance

For confirmed malicious data destruction:

1. Preserve relevant process, file, account, storage, and network evidence.
2. Identify all affected hosts, users, applications, and storage resources.
3. Follow the organization's approved containment procedure.
4. Determine whether destructive activity remains active.
5. Protect unaffected backups, replicas, and recovery infrastructure.
6. Preserve affected systems and storage according to forensic requirements.
7. Investigate the broader attack chain and identify the initial access or execution context where possible.
8. Restore affected data only through authorized recovery procedures.
9. Validate restored data and system integrity before returning affected services to operation.
10. Document the investigation timeline, affected data, recovery actions, and final disposition.

Do not delete suspicious artifacts or immediately rebuild affected systems before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

## Related Playbooks

- `playbooks/impact/ransomware.md`
- `playbooks/response/malware-response.md`

## Validation

The playbook should be validated against approved file-system telemetry, process creation data, storage activity, backup and recovery datasets, and controlled destructive-activity scenarios.

Validation should confirm that:

- destructive file activity can be identified;
- affected data and assets can be determined;
- execution context can be established;
- destructive operations can be distinguished from routine administration;
- data recoverability can be assessed;
- related attack-chain activity can be correlated;
- environmental scope can be determined;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Destructive actions must not be intentionally performed against production systems. Investigation and validation activities should use approved telemetry, isolated test environments, controlled datasets, and established evidence-preservation and recovery procedures.
