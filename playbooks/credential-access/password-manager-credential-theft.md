---
id: "password-manager-credential-theft"
name: "Password Manager Credential Theft"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-19T11:34:00Z"
updated_at: "2026-09-20T18:54:00Z"
description: "Unauthorized access to password-manager data can expose stored credentials, secrets, and other authentication material."
objective: "Identify, investigate, and validate suspicious access to password-manager data and determine whether stored credentials may have been exposed."
severity: "critical"
mitre_attack:
  - "T1555.005"
triggers:
  - "Unexpected access to password-manager data"
  - "Unknown process accessing a password-manager database or profile"
  - "Password-manager files copied or staged by an unusual process"
  - "Credential-store access associated with suspicious process execution"
  - "Password-manager access followed by anomalous authentication activity"
  - "Threat hunting identifies unusual password-manager data access"
prerequisites:
  - "Access to endpoint telemetry"
  - "Access to process creation telemetry"
  - "Access to file access telemetry"
  - "Access to authentication telemetry where available"
  - "Access to approved password-manager application metadata"
tags:
  - "password-manager"
  - "credential-theft"
  - "credential-access"
  - "credentials"
  - "authentication"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1555/005/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Password Manager Access Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, user, password manager, accessing process, and relevant timestamps."
  expected_result: "The suspicious password-manager access event and affected asset are identified."
- id: "identify-target-store"
  order: 2
  name: "Identify Target Store"
  action: "analyze"
  description: "Determine which password manager, user profile, database, vault, or related credential artifact was accessed."
  expected_result: "The targeted password-manager resource is documented."
- id: "review-process-context"
  order: 3
  name: "Review Process Context"
  action: "analyze"
  description: "Review the accessing process, executable path, hash, signer, parent process, command line, account context, and execution timeline."
  expected_result: "The accessing process and execution context are assessed."
- id: "review-store-activity"
  order: 4
  name: "Review Store Access Activity"
  action: "analyze"
  description: "Review file, database, application, or endpoint telemetry associated with password-manager access, copying, staging, or archival."
  expected_result: "Relevant credential-store access activity is identified or ruled out."
- id: "assess-credential-exposure"
  order: 5
  name: "Assess Potential Credential Exposure"
  action: "analyze"
  description: "Identify accounts and services potentially represented in the accessed password store and assess their privilege and business impact."
  expected_result: "Potentially affected accounts and services are documented."
- id: "review-follow-on-activity"
  order: 6
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Correlate password-manager access with authentication, persistence, privilege escalation, lateral movement, and suspicious network activity."
  expected_result: "Potential credential misuse and follow-on activity are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Password Manager Access Scope"
  action: "hunt"
  description: "Search for the same accessing process, file hash, account, store, access pattern, or related activity across the environment."
  expected_result: "The prevalence and scope of the password-manager access are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the password-manager access activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "password-manager-credential-theft"
---

# Password Manager Credential Theft

## Purpose

This playbook provides a structured workflow for investigating suspicious access to password-manager applications, vaults, profiles, databases, and related credential stores.

Password managers are designed to protect and organize authentication secrets. Unauthorized access to their data can expose credentials and other sensitive authentication material and may lead to account compromise.

The objective is to determine whether the observed password-manager access is legitimate, suspicious, or malicious and whether stored credentials may have been exposed.

## MITRE ATT&CK

| Technique | Name                                                | Relevance                                                                     |
| --------- | --------------------------------------------------- | ----------------------------------------------------------------------------- |
| T1555.005 | Credentials from Password Stores: Password Managers | Relevant when credentials stored by password-management software are targeted |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint detection identifies suspicious access to a password manager.
- An unexpected process accesses password-manager data.
- Password-manager files or databases are copied or staged unexpectedly.
- An unknown executable accesses a password-manager profile.
- Password-manager access is associated with suspected malware.
- Authentication activity changes unexpectedly after password-manager access.
- Threat hunting identifies unusual credential-store access.

## Scope

The investigation should consider:

- affected host;
- associated user;
- password manager;
- password-manager profile;
- vault or database;
- accessing process;
- executable path;
- file hash;
- parent process;
- command line;
- account context;
- file activity;
- process activity;
- authentication events;
- network activity;
- persistence;
- privilege escalation;
- lateral movement;
- related alerts;
- other affected hosts and accounts.

## Password Manager Context

Password managers may maintain encrypted vaults, profile data, configuration files, session information, or other application-specific artifacts.

Legitimate access may be generated by:

- the password-manager application itself;
- approved synchronization services;
- endpoint backup software;
- approved security tooling;
- authorized administrative workflows.

The presence of a password-manager file or database on a system is not itself evidence of malicious activity.

The investigation should focus on the **accessing process, account context, targeted resource, timing, and surrounding behavior**.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- password manager;
- accessing process;
- targeted resource;
- detection severity;
- detection reason.

Preserve the original alert context before taking remediation actions.

### Step 2 — Identify Target Store

Determine:

- password-manager application;
- user profile;
- vault or database;
- relevant file path;
- access timestamp;
- access type where available.

Document the targeted resource without extracting or displaying real credentials.

### Step 3 — Review Process Context

Review:

- process name;
- executable path;
- file hash;
- digital signature;
- parent process;
- child processes;
- command line;
- user context;
- integrity level;
- execution timestamp.

Determine whether the process is:

- the legitimate password-manager application;
- approved security software;
- approved backup or synchronization software;
- an unknown or suspicious executable.

### Step 4 — Review Store Access Activity

Review available:

- file access telemetry;
- database access events;
- process behavior;
- application telemetry;
- endpoint security alerts.

Determine:

- which process accessed the store;
- when the access occurred;
- whether data was copied;
- whether data was staged or archived;
- whether cleanup activity followed.

Unexpected access from processes unrelated to the password manager requires additional investigation.

### Step 5 — Assess Potential Credential Exposure

Identify potentially affected accounts or services represented in the password-manager store, based on available evidence.

Consider:

- corporate accounts;
- cloud accounts;
- administrative accounts;
- privileged accounts;
- service accounts;
- sensitive business applications.

Do not extract or display real credentials during routine investigation.

### Step 6 — Review Follow-on Activity

Correlate password-manager access with:

- successful authentication;
- failed authentication;
- new sessions;
- suspicious sign-ins;
- privilege escalation;
- lateral movement;
- persistence;
- suspicious network activity;
- additional credential-access activity.

Pay particular attention to suspicious authentication shortly after the password-manager access.

### Step 7 — Determine Password Manager Access Scope

Search the environment for:

- same accessing process;
- same file hash;
- same command line;
- same user account;
- same password manager;
- same access pattern;
- related authentication activity.

Determine:

- number of affected hosts;
- number of affected users;
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

| Evidence         | Description                                          |
| ---------------- | ---------------------------------------------------- |
| Alert            | Detection source, ID, severity, timestamp            |
| Host             | Hostname, IP address, operating system               |
| User             | Associated user or account                           |
| Password Manager | Application and version where available              |
| Store            | Vault, database, profile, or related resource        |
| Process          | Process name, path, hash                             |
| Parent Process   | Process responsible for launching the accessor       |
| Command Line     | Available command-line information                   |
| File Activity    | Accessed, copied, staged, archived, or deleted files |
| Account Context  | User and process privilege context                   |
| Authentication   | Related authentication events                        |
| Network          | Related network connections                          |
| Persistence      | Related persistence indicators                       |
| Lateral Movement | Related remote-access activity                       |
| Timeline         | Correlated process, file, and authentication events  |
| Scope            | Other affected hosts and accounts                    |
| Detections       | Related security alerts                              |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the accessing process is the legitimate password-manager application;
- the operation is expected;
- the user and host context are authorized;
- access is associated with approved backup or synchronization;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- an unrelated process accesses password-manager data;
- the process is unusual or unknown;
- the file path or signer is unexpected;
- credential-store data is copied or staged unexpectedly;
- related endpoint or network activity is abnormal;
- suspicious authentication follows the access;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized access to password-manager data;
- confirmed credential-theft behavior;
- password-manager access associated with malware;
- subsequent misuse of potentially exposed credentials;
- lateral movement using affected accounts;
- persistence or privilege escalation linked to the activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the password-manager access was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- credential exposure is confirmed or strongly suspected;
- privileged or administrative credentials may be affected;
- cloud or corporate credentials may have been exposed;
- suspicious authentication follows the access;
- lateral movement is identified;
- multiple hosts or users are affected;
- the accessing process is associated with confirmed malware.

## Response Guidance

For confirmed malicious password-manager credential theft:

1. Preserve endpoint, file, process, authentication, and network evidence.
2. Identify affected hosts, users, accounts, and services.
3. Determine whether potentially exposed accounts were subsequently used.
4. Follow the organization's credential-compromise response procedure.
5. Review suspicious authentication and session activity.
6. Follow authorized account-containment and credential-remediation procedures.
7. Investigate additional persistence and credential-access mechanisms.
8. Review related applications, extensions, and downloaded files where applicable.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, session invalidation, account containment, and vault remediation should follow approved organizational procedures.

Do not extract, display, or disclose real password-manager credentials during investigation or validation.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`

## Related Playbooks

- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/browser-credential-theft.md`
- `playbooks/credential-access/credentials-from-password-stores.md`
- `playbooks/credential-access/windows-credential-manager.md`
- `playbooks/credential-access/dpapi-credential-access.md`
- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/sam-dump.md`
- `playbooks/credential-access/ntds-dump.md`
- `playbooks/credential-access/password-spraying.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved endpoint telemetry, synthetic password-manager fixtures, file-access events, process telemetry, authentication events, and controlled credential-access scenarios.

Validation should confirm that:

- password-manager access can be identified;
- the targeted application and store can be determined;
- accessing processes can be identified;
- process relationships can be correlated;
- file copying and staging can be investigated;
- potential credential exposure can be assessed;
- subsequent authentication can be correlated;
- legitimate password-manager and security-tool activity can be distinguished from suspicious access;
- escalation criteria produce consistent outcomes.

Validation should use synthetic credentials, sanitized fixtures, and isolated laboratory systems.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not extract, recover, display, or disclose real credentials during investigation or validation.

Use synthetic credentials, sanitized password-manager data, and isolated systems for testing.
