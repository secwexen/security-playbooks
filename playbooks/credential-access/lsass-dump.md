---
id: "lsass-dump"
name: "LSASS Credential Access"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-15T14:51:00Z"
updated_at: "2026-09-20T18:52:00Z"
description: "LSASS credential access involves attempts to access the Local Security Authority Subsystem Service for authentication material."
objective: "Identify, investigate, and validate suspicious access to LSASS and determine whether credential material may have been targeted or exposed."
severity: "critical"
mitre_attack:
  - "T1003.001"
triggers:
  - "Suspicious LSASS process access alert"
  - "Unexpected access to lsass.exe"
  - "Credential access behavior targeting LSASS"
  - "LSASS access from an unusual or unsigned process"
  - "LSASS access associated with privilege escalation or lateral movement"
  - "Threat hunting identifies anomalous LSASS access"
prerequisites:
  - "Access to process creation telemetry"
  - "Access to process access telemetry where available"
  - "Access to endpoint security telemetry"
  - "Access to authentication telemetry"
tags:
  - "lsass"
  - "credential-access"
  - "credential-dumping"
  - "windows"
  - "authentication"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1003/001/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify LSASS Access Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, account, initiating process, target process, and timestamp."
  expected_result: "The suspicious LSASS access event and affected asset are identified."
- id: "identify-accessing-process"
  order: 2
  name: "Identify Accessing Process"
  action: "analyze"
  description: "Determine which process accessed lsass.exe and review its executable path, hash, signer, parent process, and account context."
  expected_result: "The initiating process and execution context are documented."
- id: "review-access-context"
  order: 3
  name: "Review Process Access Context"
  action: "analyze"
  description: "Review available process-access telemetry, access characteristics, integrity level, privileges, and surrounding execution events."
  expected_result: "The LSASS access context is assessed."
- id: "review-process-tree"
  order: 4
  name: "Review Process Tree"
  action: "analyze"
  description: "Correlate the accessing process with its parent and child processes and determine whether the process chain is expected."
  expected_result: "The process execution chain is documented and correlated."
- id: "review-file-and-network-activity"
  order: 5
  name: "Review File and Network Activity"
  action: "analyze"
  description: "Review file activity, downloads, DNS requests, and network connections associated with the accessing process."
  expected_result: "Related file and network activity is identified or ruled out."
- id: "assess-account-exposure"
  order: 6
  name: "Assess Potential Credential Exposure"
  action: "analyze"
  description: "Identify accounts that may have been exposed and correlate subsequent authentication activity."
  expected_result: "Potentially affected accounts and related activity are documented."
- id: "determine-scope"
  order: 7
  name: "Determine LSASS Access Scope"
  action: "hunt"
  description: "Search for the same process, hash, command line, account, host, or LSASS access pattern across the environment."
  expected_result: "The prevalence and scope of the LSASS access activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the LSASS access activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "lsass-dump"
---

# LSASS Credential Access

## Purpose

This playbook provides a structured workflow for investigating suspicious access to the Windows Local Security Authority Subsystem Service (`lsass.exe`).

LSASS is a legitimate Windows security process involved in authentication and security operations. Because of its role, unauthorized access to LSASS can be an indicator of credential-access activity.

The objective is to determine whether the observed LSASS access is legitimate, suspicious, or malicious and whether authentication material may have been targeted or exposed.

## MITRE ATT&CK

| Technique | Name                                | Relevance                                                      |
| --------- | ----------------------------------- | -------------------------------------------------------------- |
| T1003.001 | OS Credential Dumping: LSASS Memory | Relevant when LSASS is targeted for credential-access activity |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An LSASS access detection is generated.
- An unexpected process accesses `lsass.exe`.
- A non-standard or unsigned process targets LSASS.
- LSASS access is associated with suspicious privilege escalation.
- LSASS access is followed by anomalous authentication activity.
- Threat hunting identifies unusual LSASS process access.

## Scope

The investigation should consider:

- affected host;
- initiating account;
- potentially affected accounts;
- accessing process;
- process path;
- file hash;
- digital signature;
- parent process;
- child processes;
- command line;
- process integrity level;
- process privileges;
- LSASS process;
- process-access telemetry;
- authentication events;
- file activity;
- network activity;
- DNS activity;
- related detections;
- other affected hosts.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated account;
- accessing process;
- target process;
- detection severity;
- detection reason.

Preserve the original alert context before taking remediation actions.

### Step 2 — Identify the Accessing Process

Collect:

- process name;
- executable path;
- file hash;
- digital signature;
- process owner;
- parent process;
- command line;
- execution timestamp;
- integrity level;
- available privileges.

Determine whether the process belongs to approved security software, administrative tooling, endpoint protection, or another legitimate workload.

### Step 3 — Review Process Access Context

Review available process-access telemetry associated with `lsass.exe`.

Determine:

- which process initiated the access;
- when the access occurred;
- whether the access was expected;
- whether the initiating process had an unusual privilege context;
- whether related security detections were generated.

A single access event should be evaluated in context rather than treated as conclusive evidence of credential theft.

### Step 4 — Review Process Tree

Correlate the accessing process with:

- parent process;
- child processes;
- command-line activity;
- process creation timestamps;
- preceding execution events.

Investigate unusual process chains, especially when LSASS access follows unexpected execution or suspicious user activity.

### Step 5 — Review File and Network Activity

Review activity associated with the accessing process, including:

- file creation;
- file modification;
- downloads;
- temporary artifacts;
- DNS requests;
- network connections;
- external destinations.

Determine whether the LSASS access was followed by additional suspicious behavior.

### Step 6 — Assess Potential Credential Exposure

Identify accounts that may have been present or active on the affected system.

Consider:

- privileged accounts;
- administrative accounts;
- service accounts;
- recently authenticated users;
- accounts associated with subsequent suspicious logons.

Correlate the LSASS event with later authentication activity to identify possible credential misuse.

### Step 7 — Determine LSASS Access Scope

Search the environment for:

- same accessing process;
- same file hash;
- same command line;
- same account;
- same host;
- similar LSASS access events;
- related authentication activity.

Determine:

- number of affected hosts;
- number of affected accounts;
- first observed event;
- latest observed event;
- whether suspicious activity is ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence          | Description                                      |
| ----------------- | ------------------------------------------------ |
| Alert             | Detection source, ID, severity, timestamp        |
| Host              | Hostname, IP address, operating system           |
| Account           | Initiating and potentially affected accounts     |
| Target Process    | `lsass.exe` and process metadata                 |
| Accessing Process | Process name, path, hash, signer                 |
| Parent Process    | Process responsible for launching the accessor   |
| Child Processes   | Processes created after or around LSASS access   |
| Command Line      | Available command-line information               |
| Process Access    | Available LSASS process-access telemetry         |
| Privileges        | Integrity level and privilege context            |
| Authentication    | Related logon and authentication events          |
| Files             | Created, modified, downloaded, or executed files |
| Network           | Related network connections                      |
| DNS               | Related DNS activity                             |
| Timeline          | Correlated process and authentication events     |
| Scope             | Other affected hosts and accounts                |
| Detections        | Related security alerts                          |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the accessing process is approved security or administrative software;
- the behavior is expected for the software;
- the account and host context are authorized;
- the process is trusted;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- an unusual process accesses LSASS;
- process ownership or purpose is unclear;
- the process path or signer is unexpected;
- the access occurs in an abnormal execution chain;
- related authentication or network activity is anomalous;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized LSASS access;
- confirmed credential-access behavior;
- LSASS access associated with malware;
- subsequent use of potentially compromised credentials;
- lateral movement involving affected accounts;
- persistence or privilege escalation linked to the activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the LSASS access was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious LSASS access is confirmed;
- privileged credentials may have been exposed;
- service-account credentials may have been exposed;
- suspicious authentication follows the LSASS access;
- lateral movement is identified;
- multiple hosts or accounts are affected;
- the accessing process is associated with confirmed malware.

## Response Guidance

For confirmed malicious LSASS access:

1. Preserve process, endpoint, authentication, and network evidence.
2. Identify potentially affected hosts and accounts.
3. Follow the organization's credential-compromise response procedure.
4. Review and contain potentially compromised accounts according to policy.
5. Investigate subsequent authentication activity.
6. Search for lateral movement and persistence.
7. Follow authorized endpoint containment procedures.
8. Review possible exposure of privileged credentials.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, session invalidation, and account containment should follow approved organizational response procedures.

Do not perform credential extraction or attempt to reproduce credential theft on production systems.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`

## Related Playbooks

- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/credential-access.md`
- `playbooks/credential-access/sam-dump.md`
- `playbooks/credential-access/ntds-dump.md`
- `playbooks/credential-access/dpapi-credential-access.md`
- `playbooks/credential-access/credentials-from-password-stores.md`
- `playbooks/credential-access/password-manager-credential-theft.md`
- `playbooks/credential-access/browser-credential-theft.md`
- `playbooks/credential-access/password-spraying.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/lateral-movement-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved endpoint telemetry, process-access events, authentication events, and controlled credential-access detection scenarios.

Validation should confirm that:

- suspicious LSASS access can be identified;
- the accessing process can be determined;
- process ownership and execution context can be assessed;
- parent and child processes can be correlated;
- account exposure can be assessed;
- authentication activity can be correlated;
- related file and network activity can be investigated;
- environmental scope can be determined;
- legitimate security tooling can be distinguished from suspicious LSASS access;
- escalation criteria produce consistent outcomes.

Validation should use controlled telemetry and synthetic scenarios rather than real credential extraction from production systems.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not extract, disclose, or handle real user credentials during validation. Use synthetic credentials, sanitized telemetry, and isolated laboratory systems.

Credential-compromise response actions must follow approved organizational procedures and applicable access-control requirements.
