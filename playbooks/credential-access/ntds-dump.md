---
id: "ntds-dump"
name: "NTDS Credential Access"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-15T20:06:00Z"
updated_at: "2026-09-15T20:06:00Z"
description: "NTDS credential access involves attempts to obtain Active Directory account authentication material from the domain controller database."
objective: "Identify, investigate, and validate suspicious access to the NTDS database and determine whether domain credentials may have been exposed."
severity: "critical"
mitre_attack:
  - "T1003.003"
triggers:
  - "Suspicious NTDS credential access alert"
  - "Unexpected access to the domain controller credential database"
  - "Unexpected creation or access of an NTDS-related copy"
  - "Credential access activity involving a domain controller"
  - "NTDS access associated with privilege escalation or lateral movement"
  - "Threat hunting identifies anomalous domain credential access"
prerequisites:
  - "Access to domain controller telemetry"
  - "Access to process creation telemetry"
  - "Access to file and authentication telemetry"
  - "Access to endpoint and directory-service telemetry where available"
tags:
  - "ntds"
  - "credential-access"
  - "credential-dumping"
  - "active-directory"
  - "domain-controller"
  - "windows"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1003/003/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify NTDS Access Alert"
  action: "investigate"
  description: "Identify the detection source, affected domain controller, account, initiating process, timestamp, and alert context."
  expected_result: "The suspicious NTDS access event and affected domain controller are identified."
- id: "identify-access-target"
  order: 2
  name: "Identify NTDS Access Target"
  action: "analyze"
  description: "Determine which NTDS-related database, copy, shadow-copy artifact, or associated resource was accessed."
  expected_result: "The credential access target and context are documented."
- id: "review-process-context"
  order: 3
  name: "Review Process Context"
  action: "analyze"
  description: "Review the initiating process, parent process, command line, account context, privileges, and execution timeline."
  expected_result: "The process execution context is assessed."
- id: "review-file-activity"
  order: 4
  name: "Review File Activity"
  action: "analyze"
  description: "Review creation, access, copying, or modification of NTDS-related files and supporting artifacts."
  expected_result: "Relevant file activity and artifacts are documented."
- id: "review-domain-activity"
  order: 5
  name: "Review Domain Activity"
  action: "analyze"
  description: "Correlate NTDS access with directory-service events, authentication activity, privileged operations, and changes involving domain accounts."
  expected_result: "Related domain activity and account context are correlated."
- id: "assess-account-impact"
  order: 6
  name: "Assess Potential Domain Credential Exposure"
  action: "analyze"
  description: "Identify domain accounts that may have been exposed and assess privilege, scope, and business impact."
  expected_result: "Potentially affected accounts and their risk are documented."
- id: "determine-scope"
  order: 7
  name: "Determine NTDS Access Scope"
  action: "hunt"
  description: "Search for related processes, accounts, domain controllers, file artifacts, hashes, and credential access indicators across the environment."
  expected_result: "The prevalence and scope of the NTDS access activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the NTDS access activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "ntds-dump"
---

# NTDS Credential Access

## Purpose

This playbook provides a structured workflow for investigating suspicious access to the Active Directory credential database on Windows domain controllers.

The NTDS database is a core Active Directory data store. Unauthorized access to NTDS-related data can expose authentication material for domain accounts and may enable subsequent account compromise, privilege escalation, or lateral movement.

The objective is to determine whether the activity is legitimate, suspicious, or malicious and whether domain credentials may have been exposed.

## MITRE ATT&CK

| Technique | Name                        | Relevance                                                                   |
| --------- | --------------------------- | --------------------------------------------------------------------------- |
| T1003.003 | OS Credential Dumping: NTDS | Relevant when Active Directory credential material is targeted through NTDS |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An NTDS credential-access detection is generated.
- Unexpected access to NTDS-related data is observed.
- An NTDS-related copy or artifact is unexpectedly created or accessed.
- Credential-access activity occurs on a domain controller.
- NTDS access is associated with suspicious privilege escalation.
- NTDS access is followed by anomalous domain authentication activity.
- Threat hunting identifies suspicious domain credential access behavior.

## Scope

The investigation should consider:

- affected domain controller;
- initiating host;
- initiating account;
- potentially affected domain accounts;
- initiating process;
- process path;
- parent process;
- command line;
- privileges;
- NTDS-related files or artifacts;
- file creation and access activity;
- directory-service events;
- authentication events;
- privileged operations;
- lateral movement;
- persistence;
- network activity;
- related alerts;
- other affected domain controllers.

## NTDS Context

The NTDS database is associated with Active Directory domain controllers and contains sensitive directory information.

Investigations should focus on the **observed access behavior and supporting telemetry** rather than attempting to reproduce credential extraction.

Do not copy, extract, disclose, or process real domain credential material as part of routine investigation or validation.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected domain controller;
- initiating host;
- associated account;
- initiating process;
- detection severity;
- detection reason.

Preserve the original alert context before taking remediation actions.

### Step 2 — Identify NTDS Access Target

Determine what NTDS-related resource was accessed.

Investigate available evidence for:

- database access;
- suspicious copies;
- unexpected file access;
- shadow-copy-related activity;
- supporting artifacts.

Document the access target and context without attempting credential extraction.

### Step 3 — Review Process Context

Review:

- process name;
- executable path;
- file hash;
- digital signature;
- parent process;
- command line;
- user context;
- integrity level;
- available privileges;
- execution timestamp.

Determine whether the process belongs to approved domain-management, backup, recovery, security, or administrative software.

### Step 4 — Review File Activity

Investigate:

- NTDS-related file access;
- file creation;
- file copying;
- unexpected archive creation;
- unusual temporary files;
- related cleanup or deletion activity.

Collect:

- filename;
- path;
- hash;
- timestamps;
- creating process;
- modifying account.

Unexpected NTDS-related artifacts should be correlated with the initiating process and broader event timeline.

### Step 5 — Review Domain Activity

Correlate the event with:

- directory-service events;
- authentication events;
- privileged logons;
- account changes;
- group membership changes;
- remote administration;
- lateral movement indicators.

Pay particular attention to suspicious domain activity occurring immediately before or after the NTDS access event.

### Step 6 — Assess Potential Domain Credential Exposure

Identify accounts that may have been exposed based on available evidence.

Prioritize:

- domain administrators;
- privileged groups;
- service accounts;
- administrative accounts;
- accounts with broad access;
- accounts associated with suspicious subsequent authentication.

Determine whether potentially exposed credentials could affect additional systems or services.

### Step 7 — Determine NTDS Access Scope

Search the environment for:

- same initiating process;
- same file hash;
- same command line;
- same account;
- same host;
- same NTDS-related artifact;
- same domain controller;
- related authentication activity.

Determine:

- number of affected domain controllers;
- number of potentially affected accounts;
- first observed activity;
- latest observed activity;
- whether suspicious activity is ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence          | Description                                                     |
| ----------------- | --------------------------------------------------------------- |
| Alert             | Detection source, ID, severity, timestamp                       |
| Domain Controller | Hostname, IP address, role                                      |
| Initiating Host   | Source system associated with the activity                      |
| Account           | Initiating and potentially affected accounts                    |
| Process           | Process name, path, hash                                        |
| Parent Process    | Process responsible for launching the activity                  |
| Command Line      | Available command-line information                              |
| NTDS Target       | Database, copy, or related artifact accessed                    |
| File Activity     | Creation, access, copy, modification, or deletion               |
| Privileges        | Account and process privilege context                           |
| Directory Service | Relevant directory-service events                               |
| Authentication    | Related authentication and logon events                         |
| Lateral Movement  | Related remote access activity                                  |
| Network           | Related network connections                                     |
| Timeline          | Correlated credential, process, file, and authentication events |
| Scope             | Other affected hosts and accounts                               |
| Detections        | Related security alerts                                         |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the access is performed by approved administrative, backup, recovery, or security software;
- the account is authorized;
- the operation is documented or expected;
- file activity matches an approved workflow;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the initiating process is unusual;
- the account context is unexpected;
- NTDS-related files or artifacts are accessed unexpectedly;
- the activity occurs outside approved maintenance windows;
- related authentication or administrative activity is anomalous;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized NTDS credential access;
- confirmed credential collection activity;
- malicious processes or tooling are associated with the access;
- potentially compromised domain credentials are subsequently used;
- lateral movement follows the credential access;
- the activity is associated with confirmed domain compromise.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the NTDS access was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate immediately when:

- domain credential exposure is confirmed or strongly suspected;
- privileged domain accounts may have been exposed;
- domain administrator activity is involved;
- suspicious authentication follows the access;
- lateral movement is identified;
- multiple domain controllers or accounts are affected;
- the activity is associated with confirmed malware.

## Response Guidance

For confirmed malicious NTDS credential access:

1. Preserve process, file, domain, authentication, and network evidence.
2. Identify affected domain controllers and potentially exposed accounts.
3. Follow the organization's credential-compromise response procedure.
4. Review and contain potentially compromised privileged accounts according to policy.
5. Investigate authentication activity for evidence of credential reuse.
6. Search for lateral movement and persistence.
7. Follow authorized endpoint and identity containment procedures.
8. Review possible exposure of service and administrative credentials.
9. Escalate confirmed domain compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, session invalidation, privileged-account containment, and other identity-response actions must follow approved organizational procedures.

Do not extract or disclose real domain credential material during response or validation.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`

## Related Playbooks

- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/sam-dump.md`
- `playbooks/credential-access/kerberoasting.md`
- `playbooks/credential-access/asrep-roasting.md`
- `playbooks/credential-access/password-spraying.md`
- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/lateral-movement/pass-the-ticket.md`
- `playbooks/lateral-movement/wmi-lateral-movement.md`
- `playbooks/lateral-movement/smb-lateral-movement.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/lateral-movement-response.md`
- `playbooks/response/isolate-host-response.md`
- `playbooks/response/malware-response.md`

## Validation

The playbook should be validated against approved domain-controller telemetry, NTDS-access detection fixtures, file activity, directory-service events, and controlled credential-access scenarios.

Validation should confirm that:

- suspicious NTDS access can be identified;
- the affected domain controller can be determined;
- the initiating process and account can be correlated;
- NTDS-related file activity can be investigated;
- directory-service and authentication events can be correlated;
- potentially exposed accounts can be identified;
- related lateral movement can be investigated;
- legitimate administrative or backup activity can be distinguished from suspicious credential access;
- escalation criteria produce consistent outcomes.

Validation should use synthetic telemetry and controlled laboratory scenarios rather than real credential extraction.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not extract, copy, disclose, or handle real domain credentials during testing or investigation.

Credential-access validation should use synthetic accounts, sanitized telemetry, and isolated laboratory domain controllers.
