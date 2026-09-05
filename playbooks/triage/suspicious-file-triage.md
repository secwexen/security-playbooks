---
id: "suspicious-file-triage"
name: "Suspicious File Triage"
category: "triage"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-05T16:48:00Z"
updated_at: "2026-09-05T16:48:00Z"
description: "Investigate suspicious files and determine whether an identified file is legitimate, suspicious, or malicious."
objective: "Determine the origin, characteristics, execution context, prevalence, and potential impact of a suspicious file and identify whether further investigation or incident response is required."
severity: "high"
mitre_attack:
  - "T1027"
  - "T1105"
triggers:
  - "Suspicious file detection"
  - "Unknown executable detected"
  - "Unsigned file detected"
  - "Suspicious file hash detection"
  - "File detected in a user-writable or temporary directory"
  - "Threat hunting identifies an anomalous file"
prerequisites:
  - "Access to endpoint file telemetry"
  - "Access to process telemetry"
  - "Access to file hash and metadata"
  - "Access to network telemetry where available"
tags:
  - "file"
  - "triage"
  - "malware"
  - "endpoint"
  - "investigation"
references:
  - "https://attack.mitre.org/techniques/T1027/"
  - "https://attack.mitre.org/techniques/T1105/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify File Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, file path, timestamp, and alert context."
  expected_result: "The suspicious file alert and affected asset are clearly identified."
- id: "collect-file-metadata"
  order: 2
  name: "Collect File Metadata"
  action: "analyze"
  description: "Collect the file name, type, size, timestamps, hash, signature, and path."
  expected_result: "The file's core metadata is documented."
- id: "review-file-location"
  order: 3
  name: "Review File Location"
  action: "analyze"
  description: "Assess whether the file location is expected for the associated application, user, or operating system."
  expected_result: "The legitimacy of the file location is assessed."
- id: "review-origin"
  order: 4
  name: "Review File Origin"
  action: "investigate"
  description: "Determine how and when the file was created, downloaded, copied, or introduced to the host."
  expected_result: "The file provenance and introduction path are identified where possible."
- id: "review-execution"
  order: 5
  name: "Review Execution Context"
  action: "analyze"
  description: "Determine whether the file was executed and review associated process, parent process, command line, and user context."
  expected_result: "The file's execution context is documented or ruled out."
- id: "review-network-activity"
  order: 6
  name: "Review Related Network Activity"
  action: "analyze"
  description: "Review network connections associated with the file or related process."
  expected_result: "Relevant network activity is identified or ruled out."
- id: "determine-prevalence"
  order: 7
  name: "Determine File Prevalence"
  action: "hunt"
  description: "Search the environment for the same hash, filename, path, or related file characteristics."
  expected_result: "The file's environmental prevalence and potential scope are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the file and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "suspicious-file"
---

# Suspicious File Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspicious files identified on endpoint systems.

The objective is to determine whether the file is:

- legitimate;
- suspicious;
- malicious; or
- inconclusive due to insufficient evidence.

## MITRE ATT&CK

| Technique | Name                            | Relevance                                                                        |
| --------- | ------------------------------- | -------------------------------------------------------------------------------- |
| T1027     | Obfuscated Files or Information | Relevant when suspicious files contain obfuscated or otherwise concealed content |
| T1105     | Ingress Tool Transfer           | Relevant when a suspicious file is retrieved or transferred from another system  |

Additional ATT&CK techniques should only be mapped when supported by the observed file or execution behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint detects a suspicious file.
- An unknown executable is identified.
- An unsigned or unexpectedly signed file is detected.
- A suspicious file hash is identified.
- A file is created in a temporary, download, or user-writable directory.
- A YARA or endpoint detection matches the file.
- Threat hunting identifies an anomalous file.
- Multiple hosts contain the same suspicious artifact.

## Scope

The investigation should consider:

- affected host;
- associated user or service account;
- file name;
- file path;
- file type;
- file size;
- SHA-256 hash;
- creation time;
- modification time;
- digital signature;
- signer;
- file origin;
- parent process;
- child processes;
- command line;
- network activity;
- related detections;
- file prevalence;
- additional affected hosts.

## Triage Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- detection severity;
- reason for detection.

Preserve the original alert context before making remediation changes.

### Step 2 — Collect File Metadata

Collect:

- filename;
- full path;
- file type;
- file size;
- SHA-256 hash;
- creation time;
- modification time;
- digital signature;
- signer information.

Use available file metadata to establish an initial assessment of the artifact.

### Step 3 — Review File Location

Assess whether the file path is expected.

Pay particular attention to files located in:

- temporary directories;
- user-writable directories;
- download directories;
- application data directories;
- unusual system locations;
- locations inconsistent with the expected application.

An unusual file location is an indicator for further investigation but does not by itself establish malicious intent.

### Step 4 — Review File Origin

Determine how the file entered the system.

Investigate:

- file creation events;
- browser downloads;
- email attachments;
- removable media activity;
- software installation;
- administrative deployment;
- file copies from other systems;
- network transfers.

Establish the earliest known appearance of the file where telemetry permits.

### Step 5 — Review Execution Context

Determine whether the file was executed.

Review:

- process ID;
- parent process;
- child processes;
- command line;
- execution timestamp;
- user context;
- integrity level;
- associated application.

Pay particular attention to unexpected process relationships and execution from user-writable or temporary locations.

### Step 6 — Review Related Network Activity

If the file or associated process executed, review:

- destination IP;
- destination domain;
- destination port;
- protocol;
- DNS activity;
- connection timestamps;
- repeated connections.

Investigate suspicious external communication or network behavior that is not consistent with the file's expected purpose.

### Step 7 — Determine File Prevalence

Search the environment for:

- SHA-256 hash;
- filename;
- file path;
- related file names;
- associated command line;
- related process activity.

Determine:

- number of affected hosts;
- number of affected users;
- first observed time;
- latest observed time;
- whether the file remains present or active.

### Step 8 — Determine Investigation Outcome

Classify the file as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence     | Description                               |
| ------------ | ----------------------------------------- |
| Alert        | Detection source, ID, severity, timestamp |
| Host         | Hostname, IP address, operating system    |
| User         | Associated user or service account        |
| File         | Filename and file type                    |
| Path         | Full file path                            |
| Hash         | SHA-256 or available file hash            |
| Metadata     | Size and timestamps                       |
| Signature    | Digital signature and signer              |
| Origin       | File creation or delivery source          |
| Process      | Related process metadata                  |
| Process Tree | Parent and child processes                |
| Command Line | Complete command line                     |
| Network      | Related network activity                  |
| Prevalence   | Other systems containing the file         |
| Detections   | Related security alerts                   |

## Decision Criteria

### Benign

Classify the file as **benign** when:

- the file is known and approved;
- the file is associated with legitimate software;
- the file location is expected;
- the signature or provenance is trustworthy;
- execution behavior is normal;
- no additional suspicious indicators are identified.

Document the justification before closing the alert.

### Suspicious

Classify the file as **suspicious** when:

- the file cannot be confidently attributed;
- the file is unsigned or unexpected;
- the file originates from an unusual location;
- the provenance is unclear;
- the execution context is unusual;
- related process or network activity is suspicious;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the file as **malicious** when sufficient evidence indicates:

- confirmed malicious content;
- confirmed unauthorized execution;
- malicious process activity;
- confirmed command-and-control communication;
- persistence or other malicious behavior associated with the file;
- the same artifact is confirmed malicious across multiple systems.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when the available evidence is insufficient to determine whether the file is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- confirmed malware is identified;
- the file executed on a critical host;
- multiple hosts contain the artifact;
- a privileged account is associated with the activity;
- suspicious network activity is identified;
- persistence is associated with the file;
- credential access or lateral movement is suspected.

## Response Guidance

For confirmed malicious files:

1. Preserve relevant file, process, and network evidence.
2. Follow the organization's endpoint containment procedure.
3. Identify all systems and accounts associated with the artifact.
4. Search for the file hash and related indicators across the environment.
5. Review related process, persistence, authentication, and network activity.
6. Follow authorized quarantine or remediation procedures.
7. Assess possible credential exposure.
8. Escalate to incident response.
9. Document the investigation timeline and actions taken.

Do not delete or modify relevant evidence before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/obfuscated-powershell.yar`
- `detection-rules/yara/yara-powershell-payload.yar`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/sigma/lsass-access.yml`

## Related Playbooks

- `playbooks/triage/malware-detection-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-powershell-triage.md`
- `playbooks/triage/persistence-triage.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`
- `playbooks/response/persistence-removal-response.md`

## Validation

The playbook should be validated against approved suspicious-file fixtures, endpoint telemetry, and controlled security datasets.

Validation should confirm that:

- suspicious files can be identified;
- file metadata and provenance can be investigated;
- file execution can be correlated with process activity;
- related network activity can be investigated;
- file prevalence can be determined;
- legitimate files can be distinguished from malicious artifacts;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Suspicious files should be handled through approved analysis and evidence-preservation procedures. Do not execute unknown files on production systems.
