---
id: "disk-wipe"
name: "Disk Wipe"
category: "impact"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-02T18:41:00Z"
updated_at: "2026-10-02T18:41:00Z"
description: "Disk Wipe involves corrupting or wiping disk data or disk structures to disrupt system availability and prevent normal system boot or operation."
objective: "Identify, investigate, and scope suspected disk wiping activity and determine whether disk data or critical disk structures were intentionally corrupted or removed."
severity: "critical"
mitre_attack:
  - "T1561.002"
triggers:
  - "Detection of suspicious direct disk access"
  - "Unexpected modification of the master boot record or partition structures"
  - "Unexpected disk formatting or destructive disk operations"
  - "System becomes unable to boot following suspicious activity"
  - "Destructive malware or wiper activity is identified"
  - "Threat hunting identifies anomalous disk modification activity"
prerequisites:
  - "Access to endpoint process and command-line telemetry"
  - "Access to disk and system event telemetry"
  - "Access to file and artifact telemetry"
  - "Access to authentication and account telemetry"
  - "Access to backup and recovery status information"
tags:
  - "disk-wipe"
  - "disk-structure-wipe"
  - "impact"
  - "destructive"
  - "availability"
  - "windows"
  - "endpoint"
references:
  - "https://attack.mitre.org/techniques/T1561/002/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify Disk Wipe Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, timestamp, account, process, command line, and reason for the alert."
    expected_result: "The suspected disk wiping activity and affected asset are identified."
  - id: "identify-host"
    order: 2
    name: "Identify Affected Host"
    action: "investigate"
    description: "Determine the affected host, operating system, system role, asset criticality, and current availability state."
    expected_result: "The affected host and its operational importance are documented."
  - id: "review-disk-state"
    order: 3
    name: "Review Disk and System State"
    action: "analyze"
    description: "Review available disk, partition, boot, storage, and system state information to determine whether critical disk structures or storage contents were altered."
    expected_result: "The observed disk and system state is characterized and relevant structural changes are identified."
  - id: "review-process-activity"
    order: 4
    name: "Review Process and Command Activity"
    action: "analyze"
    description: "Review processes, parent-child relationships, command lines, execution paths, accounts, and privileges associated with the suspected disk modification activity."
    expected_result: "The execution context and processes associated with the suspected disk wipe are identified."
  - id: "review-file-artifacts"
    order: 5
    name: "Review File and Artifact Activity"
    action: "analyze"
    description: "Review relevant files, scripts, executables, drivers, temporary artifacts, hashes, and recently created or modified content associated with the activity."
    expected_result: "Relevant destructive tooling and associated artifacts are identified and preserved where available."
  - id: "review-network-activity"
    order: 6
    name: "Review Network Activity"
    action: "analyze"
    description: "Review network connections and remote activity associated with the suspected disk wipe, including related administrative access, payload delivery, and communication with other affected systems."
    expected_result: "Related network activity and potential propagation or remote access are identified."
  - id: "determine-scope"
    order: 7
    name: "Determine Disk Wipe Scope"
    action: "hunt"
    description: "Search the environment for matching processes, commands, hashes, disk modification indicators, affected hosts, and related destructive activity."
    expected_result: "The prevalence, affected assets, and environmental scope of the disk wipe are determined."
  - id: "determine-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity based on the available evidence and document the impact, scope, and supporting investigation findings."
    expected_result: "The investigation receives a documented outcome and escalation decision."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "disk-wipe"
---

# Disk Wipe

## Purpose

This playbook provides a structured workflow for investigating suspected disk wiping activity that may disrupt system availability, prevent normal boot, or render stored data inaccessible.

The investigation focuses on identifying unauthorized disk modification, determining whether critical disk structures or storage contents were affected, and establishing the scope and operational impact of the activity.

Disk wiping activity may involve direct modification of disk structures such as the master boot record or partition information. MITRE ATT&CK classifies Disk Structure Wipe as `T1561.002` under the Impact tactic.

### Disk Structure Context

Disk Structure Wipe may target structures required for system startup, including the master boot record or partition information. Damage to these structures may prevent the operating system from loading and can therefore result in loss of system availability.

The presence of direct disk access alone does not establish malicious activity. Administrative, recovery, imaging, storage-management, and other legitimate operations may also access disks directly.

## MITRE ATT&CK

| Technique | Name                | Relevance                                                                                |
| --------- | ------------------- | ---------------------------------------------------------------------------------------- |
| T1561.002 | Disk Structure Wipe | Primary technique for activity targeting disk structures required for normal system boot |

Disk Structure Wipe is specifically concerned with corrupting or wiping disk structures such as the MBR or partition information. It is distinct from `T1561.001 Disk Content Wipe`, which targets storage contents rather than disk structures.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Suspicious direct disk access is detected.
- Critical disk structures are unexpectedly modified.
- A system becomes unable to boot following suspicious activity.
- Destructive commands or disk manipulation tools are observed.
- Wiper malware is detected.
- Multiple systems exhibit similar disk corruption or boot failure.
- Threat hunting identifies anomalous disk modification activity.

## Scope

The investigation should consider:

- affected host;
- operating system;
- system role;
- asset criticality;
- disk and partition state;
- boot configuration;
- disk access activity;
- process execution;
- process parent-child relationships;
- command line;
- executing account;
- privilege context;
- files and scripts;
- executable hashes;
- drivers;
- authentication activity;
- network activity;
- backup availability;
- recovery infrastructure;
- additional affected hosts;
- operational availability impact.

## Investigation Procedure

### Step 1 — Identify Disk Wipe Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated account;
- process;
- command line;
- detection reason;
- current host availability.

Preserve the original alert context before performing remediation or recovery actions.

### Step 2 — Identify Affected Host

Collect:

- hostname;
- IP address;
- operating system;
- system role;
- asset owner;
- business criticality;
- current availability state;
- current recovery state.

Determine whether the affected system is:

- a workstation;
- an application server;
- a database server;
- a domain controller;
- a virtualization host;
- a security-sensitive infrastructure system;
- another critical asset.

### Step 3 — Review Disk and System State

Review available telemetry describing:

- disk configuration;
- partition configuration;
- boot configuration;
- system startup state;
- disk initialization events;
- storage errors;
- unexpected formatting activity;
- disk access anomalies;
- system recovery status.

Determine whether critical disk structures or storage components were modified.

Where the system remains operational, preserve relevant telemetry before performing recovery operations.

### Step 4 — Review Process and Command Activity

Review:

- process name;
- process ID;
- parent process;
- child processes;
- executable path;
- command line;
- execution time;
- executing account;
- integrity level;
- loaded modules where available;
- digital signature;
- process hash.

Pay particular attention to:

- unknown administrative utilities;
- unexpected disk-management tools;
- scripts performing destructive operations;
- unsigned binaries;
- recently introduced executables;
- execution from temporary or user-writable locations;
- suspicious process chains.

A legitimate disk-management tool does not by itself establish malicious activity. Correlate process activity with account, host role, change records, and operational context.

### Step 5 — Review File and Artifact Activity

Identify:

- destructive tools;
- scripts;
- executables;
- drivers;
- temporary files;
- configuration files;
- recently created or modified artifacts;
- file hashes;
- digital signatures;
- malware indicators.

Preserve relevant artifacts according to evidence-handling requirements.

Do not execute unknown binaries or intentionally reproduce destructive disk activity on production systems.

### Step 6 — Review Network Activity

Review network activity associated with:

- the affected host;
- the executing account;
- the suspicious process;
- remote administration;
- payload delivery;
- lateral movement;
- related hosts.

Determine whether the disk modification was preceded or followed by:

- remote authentication;
- suspicious file transfer;
- administrative access;
- command-and-control activity;
- similar activity on additional systems.

### Step 7 — Determine Disk Wipe Scope

Search the environment for:

- matching command lines;
- matching executable hashes;
- matching process names;
- matching scripts;
- matching disk modification behavior;
- common accounts;
- common source hosts;
- additional systems with boot or storage failures.

Determine:

- number of affected hosts;
- number of unavailable systems;
- first observed activity;
- latest observed activity;
- whether activity remains active;
- whether backups or recovery infrastructure are affected.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification and the resulting operational impact.

## Evidence to Collect

| Evidence       | Description                                             |
| -------------- | ------------------------------------------------------- |
| Alert          | Detection source, identifier, severity, and timestamp   |
| Host           | Hostname, IP address, operating system, and criticality |
| Disk           | Disk, partition, boot, and storage state                |
| Process        | Process metadata and execution context                  |
| Process Tree   | Parent and child processes                              |
| Command Line   | Complete observed command line                          |
| Account        | Executing account and privilege context                 |
| Files          | Related scripts, executables, and artifacts             |
| Hashes         | SHA-256 or other available hashes                       |
| Network        | Related connections and remote activity                 |
| Authentication | Relevant account activity                               |
| Recovery       | Backup, recovery, and availability status               |
| Scope          | Additional affected hosts and systems                   |
| Timeline       | Disk, process, file, authentication, and network events |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the disk operation is authorized;
- the activity corresponds to approved administration or recovery;
- the executing account is expected;
- the process and executable are known and trusted;
- the operation is documented through approved change procedures;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the investigation.

### Suspicious

Classify the activity as **suspicious** when:

- disk modification activity is unexpected;
- the executing account is unusual;
- the process or executable is unknown;
- the command line is abnormal;
- disk access occurs outside an approved maintenance window;
- related network or authentication activity is anomalous;
- additional evidence is required to determine intent.

Continue investigation and correlate additional telemetry.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized destructive disk modification;
- confirmed corruption of critical disk structures;
- execution of confirmed destructive malware;
- coordinated disk wiping across multiple systems;
- destructive activity following unauthorized access;
- confirmed compromise associated with the disk wipe;
- deliberate disruption of system availability.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the disk activity was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- affected systems;
- recovery status;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- critical disk structures are confirmed to have been modified;
- a system becomes unavailable or unable to boot;
- destructive activity is unauthorized;
- destructive malware is identified;
- multiple systems are affected;
- backup or recovery infrastructure is also impacted;
- lateral movement or remote administration is identified;
- credential compromise is suspected;
- command-and-control activity is observed.

## Response Guidance

For confirmed malicious disk-wiping activity:

1. Preserve available disk, process, account, file, and network evidence.
2. Identify all affected and potentially affected systems.
3. Follow the organization's approved endpoint containment procedure.
4. Prevent further propagation where authorized.
5. Protect unaffected backup and recovery infrastructure.
6. Determine whether recovery images, backups, or alternate recovery mechanisms remain available.
7. Coordinate system recovery through approved incident-response and disaster-recovery procedures.
8. Investigate the initial access and attack chain associated with the destructive activity.
9. Review potentially compromised accounts and credentials.
10. Document the incident timeline, affected assets, availability impact, and recovery actions.

Do not perform disk repair, reformatting, imaging, or other recovery actions that could alter relevant evidence before required evidence preservation has been completed or appropriate authorization has been obtained.

## Related Detection Rules

## Related Playbooks

- `playbooks/impact/data-destruction.md`
- `playbooks/impact/ransomware.md`
- `playbooks/impact/inhibit-system-recovery.md`
- `playbooks/response/malware-response.md`
- `playbooks/triage/suspicious-process-triage.md`

## Validation

The playbook should be validated against approved endpoint disk telemetry, process creation data, disk and storage events, recovery-state information, and controlled destructive-activity simulations.

Validation should confirm that:

- suspicious disk activity can be identified;
- affected hosts can be determined;
- disk and boot state can be assessed;
- associated processes and accounts can be investigated;
- related artifacts can be preserved;
- environmental scope can be determined;
- availability impact can be established;
- recovery status can be assessed;
- escalation criteria produce consistent investigation outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not intentionally wipe, corrupt, format, or modify production disks for testing purposes. Destructive validation must use isolated systems, approved test data, and established evidence-preservation and recovery procedures.
