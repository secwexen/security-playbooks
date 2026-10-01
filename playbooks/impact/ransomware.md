---
id: "ransomware"
name: "Ransomware"
category: "impact"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-01T18:59:00Z"
updated_at: "2026-10-01T18:59:00Z"
description: "Investigate suspected ransomware activity involving unauthorized data encryption and determine the affected scope, operational impact, and required response actions."
objective: "Identify, investigate, contain, and scope ransomware activity while preserving evidence and supporting coordinated incident response."
severity: "critical"
mitre_attack:
  - "T1486"
triggers:
  - "Ransomware detection alert"
  - "Large-scale file encryption activity"
  - "Rapid modification of files with unusual or previously unseen extensions"
  - "Ransom note creation"
  - "Unexpected encryption process execution"
  - "Multiple systems showing correlated encryption activity"
  - "Threat hunting identifies ransomware-like behavior"
prerequisites:
  - "Access to endpoint process telemetry"
  - "Access to file and filesystem telemetry"
  - "Access to authentication telemetry"
  - "Access to network telemetry"
  - "Access to backup and recovery telemetry where available"
tags:
  - "ransomware"
  - "impact"
  - "data-encrypted"
  - "encryption"
  - "windows"
  - "incident-response"
  - "critical"
references:
  - "https://attack.mitre.org/techniques/T1486/"
steps:
  - id: "identify-ransomware-alert"
    order: 1
    name: "Identify Ransomware Alert"
    action: "investigate"
    description: "Identify the detection source, affected assets, timestamps, encryption indicators, and original alert context."
    expected_result: "The ransomware alert, associated assets, and initial encryption indicators are identified."
  - id: "identify-affected-host"
    order: 2
    name: "Identify Affected Host"
    action: "investigate"
    description: "Determine which hosts, servers, or endpoints are affected and identify their ownership, criticality, and current operational status."
    expected_result: "Affected hosts and their operational context are documented."
  - id: "identify-encryption-activity"
    order: 3
    name: "Identify Encryption Activity"
    action: "analyze"
    description: "Review file modification patterns, renamed or encrypted files, unusual extensions, encryption-related processes, and affected storage locations."
    expected_result: "The observed encryption behavior and affected data locations are characterized."
  - id: "review-execution-context"
    order: 4
    name: "Review Execution Context"
    action: "analyze"
    description: "Review the process, command line, parent process, user account, execution path, and related process activity associated with the encryption behavior."
    expected_result: "The ransomware execution context and associated activity are documented."
  - id: "review-ransom-artifacts"
    order: 5
    name: "Review Ransomware Artifacts"
    action: "analyze"
    description: "Review ransom notes, suspicious files, executable artifacts, hashes, file extensions, and other indicators associated with the ransomware activity."
    expected_result: "Ransomware artifacts and supporting indicators are identified and preserved."
  - id: "assess-recovery-impact"
    order: 6
    name: "Assess Recovery and Backup Impact"
    action: "analyze"
    description: "Determine whether backup systems, recovery mechanisms, snapshots, or other restoration resources are affected or remain available."
    expected_result: "The availability and integrity of recovery resources are assessed."
  - id: "determine-ransomware-scope"
    order: 7
    name: "Determine Ransomware Scope"
    action: "hunt"
    description: "Search the environment for related encryption activity, ransomware artifacts, affected hosts, accounts, file shares, and common indicators."
    expected_result: "The number and scope of affected assets, accounts, and data locations are determined."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity and document the evidence supporting the final assessment and required response actions."
    expected_result: "The ransomware investigation receives a documented outcome and response disposition."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "ransomware"
---

# Ransomware

## Purpose

This playbook provides a structured workflow for investigating suspected ransomware activity involving unauthorized encryption of data and disruption of access to systems or stored information.

The objective is to determine whether observed encryption activity is legitimate or malicious, identify the affected scope, preserve evidence, and support coordinated containment and incident response.

Ransomware activity commonly involves large-scale encryption of files or data to interrupt availability. MITRE ATT&CK maps this behavior to **T1486 — Data Encrypted for Impact**.

## MITRE ATT&CK

| Technique | Name                      | Relevance                                                                     |
| --------- | ------------------------- | ----------------------------------------------------------------------------- |
| T1486     | Data Encrypted for Impact | Primary technique for unauthorized encryption of data to disrupt availability |

Recovery-disruption behavior such as deleting shadow copies or disabling recovery mechanisms is represented separately by **T1490 — Inhibit System Recovery**.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A ransomware detection alert is generated.
- Large-scale file encryption or rapid file modification is observed.
- Previously unseen or suspicious file extensions appear across multiple files.
- A ransom note is created.
- An unexpected encryption-related process executes.
- Multiple endpoints or servers exhibit correlated encryption activity.
- Threat hunting identifies ransomware-like file or process behavior.

## Scope

The investigation should consider:

- affected host;
- affected user account;
- endpoint or server role;
- encrypted files;
- encrypted directories;
- network shares;
- mounted drives;
- file extensions;
- ransom notes;
- encryption-related processes;
- parent and child processes;
- command line;
- executable path;
- file hashes;
- process execution timestamps;
- authentication activity;
- network activity;
- affected hosts;
- backup infrastructure;
- recovery resources;
- related security alerts;
- environmental prevalence.

## Investigation Procedure

### Step 1 — Identify Ransomware Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected asset;
- associated account;
- detection severity;
- detection reason;
- observed encryption indicators.

Preserve the original alert context before modifying affected systems.

### Step 2 — Identify Affected Host

Determine:

- hostname;
- IP address;
- operating system;
- asset owner;
- host criticality;
- server or workstation role;
- current operational status;
- current isolation status.

Determine whether the affected system contains:

- business-critical data;
- shared storage;
- database systems;
- backup-related resources;
- administrative infrastructure.

Prioritize systems based on organizational response procedures and business impact.

### Step 3 — Identify Encryption Activity

Review:

- file creation and modification activity;
- file rename activity;
- unusual file extensions;
- large numbers of modified files;
- affected directories;
- local drives;
- mounted volumes;
- network shares;
- encryption-related process activity.

Identify whether file modifications are:

- localized to a single directory;
- distributed across multiple directories;
- present on multiple volumes;
- present across network-accessible shares; or
- occurring across multiple hosts.

High-volume file modification alone does not establish ransomware activity. Correlate file activity with process, user, host, and artifact context.

### Step 4 — Review Execution Context

Review the encryption-related process:

- process name;
- process ID;
- parent process;
- child processes;
- executable path;
- command line;
- execution timestamp;
- user account;
- integrity level;
- digital signature;
- file hash.

Assess whether the process:

- originated from an unusual location;
- was recently created;
- was executed by an unexpected account;
- launched additional processes;
- accessed large numbers of files;
- interacted with network shares;
- exhibited behavior consistent with unauthorized encryption.

Do not execute suspected ransomware binaries for analysis on production systems.

### Step 5 — Review Ransomware Artifacts

Collect and review:

- ransom notes;
- suspicious executables;
- scripts;
- dropped files;
- modified files;
- unusual file extensions;
- file hashes;
- digital signatures;
- file metadata;
- creation and modification timestamps;
- related process artifacts.

Preserve representative encrypted files and ransom-note samples where permitted by evidence-preservation procedures.

Correlate artifacts across affected systems to determine whether the same ransomware activity is present elsewhere.

### Step 6 — Assess Recovery and Backup Impact

Determine whether:

- backup systems remain available;
- backup repositories were accessed;
- snapshots remain available;
- recovery services remain operational;
- recovery data was modified or deleted;
- affected systems can be restored through approved procedures.

Document:

- available recovery sources;
- affected recovery sources;
- unavailable recovery sources;
- integrity status of available backups;
- additional restoration requirements.

Do not modify or delete backup evidence during investigation unless authorized containment or recovery procedures require it.

### Step 7 — Determine Ransomware Scope

Search the environment for:

- same ransomware artifacts;
- same file extensions;
- same ransom-note content;
- same hashes;
- same executable paths;
- same command lines;
- same process behavior;
- similar file modification patterns;
- related authentication activity;
- related network activity;
- affected file shares;
- additional affected hosts.

Determine:

- number of affected hosts;
- number of affected accounts;
- affected servers;
- affected workstations;
- affected shares;
- first observed encryption activity;
- latest observed activity;
- whether encryption remains active;
- whether additional systems show precursor activity.

## Evidence to Collect

| Evidence       | Description                                                   |
| -------------- | ------------------------------------------------------------- |
| Alert          | Detection source, identifier, severity, and timestamp         |
| Host           | Hostname, IP address, operating system, role, and criticality |
| User           | Account associated with ransomware execution                  |
| Process        | Encryption process metadata                                   |
| Process Tree   | Parent and child process relationships                        |
| Command Line   | Complete observed command line                                |
| Files          | Encrypted, renamed, created, or modified files                |
| Extensions     | Original and observed file extensions                         |
| Ransom Note    | Ransom note name, path, and content metadata                  |
| Hashes         | SHA-256 and other available artifact hashes                   |
| Network        | Related network connections and destinations                  |
| Authentication | Related account and authentication events                     |
| Shares         | Affected network shares and storage locations                 |
| Backups        | Backup and recovery resource status                           |
| Timeline       | Process, file, authentication, and network timestamps         |
| Scope          | Affected hosts, accounts, shares, and data locations          |
| Detections     | Related alerts and detection identifiers                      |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- file encryption is attributable to an approved application or administrative process;
- the process is known and trusted;
- the user and host context are expected;
- file modification behavior matches documented business activity;
- no ransom note or malicious artifact is identified;
- no additional suspicious activity is observed.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- large-scale file modification is observed;
- unusual file extensions are present;
- encryption behavior is not attributable to an approved process;
- the execution context is unexpected;
- ransomware artifacts are suspected but not confirmed;
- telemetry is incomplete;
- environmental scope cannot yet be established.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized encryption of files or data;
- confirmed ransomware execution;
- ransom note creation associated with unauthorized encryption;
- confirmed ransomware artifacts;
- coordinated encryption activity across multiple systems;
- malicious encryption activity affecting network shares or critical data;
- additional confirmed malicious activity associated with the ransomware event.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the encryption activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- affected systems not yet fully scoped;
- additional telemetry required;
- unresolved investigation questions.

## Escalation

Escalate the investigation immediately when:

- unauthorized encryption is confirmed;
- ransomware execution is confirmed;
- multiple hosts are affected;
- critical servers or business-critical data are affected;
- network shares are being encrypted;
- privileged accounts are involved;
- backup or recovery infrastructure is affected;
- encryption activity remains active;
- lateral movement or additional compromise is identified;
- widespread environmental impact is suspected.

Coordinate escalation with the organization's incident-response and business-continuity procedures.

## Response Guidance

For confirmed ransomware activity:

1. Preserve relevant process, file, authentication, network, and alert evidence.
2. Identify all affected hosts, accounts, file shares, and storage locations.
3. Contain affected systems according to the organization's incident-response procedures.
4. Prevent further unauthorized access to affected network resources where authorized.
5. Protect available backups and recovery resources from further modification or destruction.
6. Identify the ransomware artifacts, hashes, extensions, and execution indicators.
7. Search the environment for related ransomware activity and secondary affected systems.
8. Assess whether credential compromise, lateral movement, persistence, or additional malicious activity occurred.
9. Follow approved eradication, recovery, and restoration procedures.
10. Validate restored systems and data before returning them to normal operations.
11. Document the investigation timeline, containment actions, recovery actions, and lessons learned.

Do not modify, delete, or execute suspicious ransomware artifacts before required evidence preservation and appropriate authorization have been considered.

Ransom payment decisions must follow the organization's legal, regulatory, executive, insurance, and incident-response requirements.

## Related Detection Rules

## Related Playbooks

- `playbooks/impact/data-destruction.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against controlled ransomware simulation scenarios, approved endpoint telemetry, file activity telemetry, process creation data, authentication events, network telemetry, and backup-status data.

Validation should confirm that:

- ransomware-like file encryption activity can be identified;
- affected hosts and accounts can be determined;
- encryption processes can be investigated;
- ransomware artifacts can be collected and correlated;
- affected files and storage locations can be scoped;
- backup and recovery availability can be assessed;
- related systems can be identified;
- malicious ransomware activity can be distinguished from legitimate encryption activity;
- escalation criteria produce consistent investigation outcomes.

## Safety

This playbook is intended for defensive security operations, controlled security validation, authorized incident response, and approved laboratory environments.

Do not deploy, execute, or intentionally propagate ransomware in production environments.

Ransomware artifacts should be handled according to approved malware-analysis and evidence-preservation procedures. Recovery and containment actions must follow authorized organizational processes.
