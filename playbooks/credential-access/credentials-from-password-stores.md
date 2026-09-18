---
id: "credentials-from-password-stores"
name: "Credentials from Password Stores"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-18T19:05:00Z"
updated_at: "2026-09-18T19:05:00Z"
description: "Unauthorized access to password stores can expose saved credentials, authentication secrets, and other sensitive account information."
objective: "Identify, investigate, and validate suspicious access to password stores and determine whether stored authentication material may have been exposed."
severity: "high"
mitre_attack:
  - "T1555"
triggers:
  - "Unexpected access to a password store"
  - "Unknown process accessing stored credentials"
  - "Password-store files or databases accessed by an unusual process"
  - "Credential-store access associated with suspicious execution"
  - "Password-store activity followed by anomalous authentication"
  - "Threat hunting identifies unusual access to stored credentials"
prerequisites:
  - "Access to endpoint telemetry"
  - "Access to process creation telemetry"
  - "Access to file and application telemetry"
  - "Access to authentication telemetry where available"
tags:
  - "password-stores"
  - "credential-access"
  - "credentials"
  - "authentication"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1555/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Password Store Access Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, user, accessing process, targeted application or store, and relevant timestamps."
  expected_result: "The suspicious password-store access event and affected asset are identified."
- id: "identify-password-store"
  order: 2
  name: "Identify Password Store"
  action: "analyze"
  description: "Determine which password manager, operating-system credential store, application store, or protected credential repository was accessed."
  expected_result: "The targeted password store and application context are documented."
- id: "review-process-context"
  order: 3
  name: "Review Process Context"
  action: "analyze"
  description: "Review the accessing process, executable path, hash, signer, parent process, command line, account context, and execution timeline."
  expected_result: "The accessing process and execution context are assessed."
- id: "review-file-activity"
  order: 4
  name: "Review Store Access Activity"
  action: "analyze"
  description: "Review file, database, registry, or application telemetry associated with access to the password store."
  expected_result: "Relevant password-store access activity is identified or ruled out."
- id: "assess-credential-exposure"
  order: 5
  name: "Assess Potential Credential Exposure"
  action: "analyze"
  description: "Identify accounts or services potentially associated with the accessed store and assess their privilege and business impact."
  expected_result: "Potentially affected accounts and services are documented."
- id: "review-follow-on-activity"
  order: 6
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Correlate password-store access with authentication, privilege escalation, persistence, lateral movement, and suspicious network activity."
  expected_result: "Potential credential misuse and follow-on activity are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Password Store Access Scope"
  action: "hunt"
  description: "Search for the same process, file hash, account, store, access pattern, or related activity across the environment."
  expected_result: "The prevalence and scope of the password-store access are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the password-store access activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "credentials-from-password-stores"
---

# Credentials from Password Stores

## Purpose

This playbook provides a structured workflow for investigating suspicious access to password stores and other repositories containing saved authentication material.

Password stores may be implemented by operating systems, password managers, browsers, enterprise applications, or other software. Unauthorized access to these stores can expose credentials and other authentication information.

The objective is to determine whether the observed access is legitimate, suspicious, or malicious and whether stored credentials may have been exposed.

## MITRE ATT&CK

| Technique | Name                             | Relevance                                                                |
| --------- | -------------------------------- | ------------------------------------------------------------------------ |
| T1555     | Credentials from Password Stores | Relevant when stored credentials or authentication material are targeted |

More specific T1555 sub-techniques should be used when the exact credential store is known and supported by the available evidence.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint detection identifies suspicious password-store access.
- An unknown process accesses stored credentials.
- Password-store databases or files are accessed unexpectedly.
- Credential-store access is associated with suspicious execution.
- Stored-credential access is followed by anomalous authentication.
- Threat hunting identifies unusual access to saved credentials.

## Scope

The investigation should consider:

- affected host;
- associated user;
- password-store application;
- credential store;
- accessing process;
- executable path;
- file hash;
- parent process;
- command line;
- account context;
- file or database access;
- registry activity where applicable;
- authentication events;
- network activity;
- persistence;
- privilege escalation;
- lateral movement;
- related alerts;
- other affected hosts and accounts.

## Password Store Context

Password stores can include:

- operating-system credential stores;
- password-manager databases;
- application-specific credential stores;
- browser-related credential repositories;
- enterprise authentication applications.

Access by the owning application or approved administrative/security software may be legitimate.

The investigation should therefore evaluate the **accessing process, account context, targeted store, timing, and surrounding behavior**.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- accessing process;
- targeted store;
- detection severity;
- detection reason.

Preserve the original alert context before taking remediation actions.

### Step 2 — Identify Password Store

Determine:

- application or service name;
- credential-store type;
- store or database path where available;
- user profile;
- access timestamp;
- access method where available.

Document the targeted store without extracting or displaying real credentials.

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

Determine whether the process belongs to the expected application, security tooling, backup software, or another approved workflow.

### Step 4 — Review Store Access Activity

Review available:

- file access telemetry;
- database access;
- registry access;
- application telemetry;
- endpoint security detections.

Determine:

- which process accessed the store;
- when access occurred;
- whether access was expected;
- whether related files were copied or staged.

Investigate unexpected access by processes unrelated to the password-store application.

### Step 5 — Assess Potential Credential Exposure

Identify potentially affected accounts and services based on the available evidence.

Consider:

- corporate accounts;
- cloud accounts;
- administrative accounts;
- privileged accounts;
- service accounts;
- sensitive applications.

Do not recover or display actual credentials as part of routine investigation.

### Step 6 — Review Follow-on Activity

Correlate password-store access with:

- successful authentication;
- failed authentication;
- new sessions;
- privilege escalation;
- lateral movement;
- persistence;
- suspicious network activity;
- additional credential-access events.

Pay particular attention to authentication activity occurring shortly after the suspicious store access.

### Step 7 — Determine Password Store Access Scope

Search the environment for:

- same accessing process;
- same file hash;
- same account;
- same store;
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

| Evidence          | Description                                                  |
| ----------------- | ------------------------------------------------------------ |
| Alert             | Detection source, ID, severity, timestamp                    |
| Host              | Hostname, IP address, operating system                       |
| User              | Associated user or account                                   |
| Application       | Password manager, operating-system component, or application |
| Store             | Targeted credential store or database                        |
| Process           | Process name, path, hash                                     |
| Parent Process    | Process responsible for launching the accessor               |
| Command Line      | Available command-line information                           |
| File Activity     | Accessed, copied, staged, archived, or deleted files         |
| Registry Activity | Relevant registry access where applicable                    |
| Account Context   | User and process privilege context                           |
| Authentication    | Related authentication events                                |
| Network           | Related network connections                                  |
| Persistence       | Related persistence indicators                               |
| Lateral Movement  | Related remote-access activity                               |
| Timeline          | Correlated process, file, and authentication events          |
| Scope             | Other affected hosts and accounts                            |
| Detections        | Related security alerts                                      |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the accessing process is the legitimate password-store application;
- the operation is expected;
- the account and host context are authorized;
- access is associated with approved backup, security, or administration;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- an unrelated process accesses the password store;
- the accessing process is unusual or unknown;
- the file path or signer is unexpected;
- credential-store data is copied or staged unexpectedly;
- related endpoint or network activity is abnormal;
- subsequent authentication activity is suspicious;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized access to stored credentials;
- confirmed credential-theft behavior;
- password-store access associated with malware;
- subsequent misuse of potentially exposed credentials;
- lateral movement using affected accounts;
- persistence or privilege escalation linked to the activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the password-store access was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- credential exposure is confirmed or strongly suspected;
- privileged or administrative accounts may be affected;
- cloud or corporate accounts may have been exposed;
- suspicious authentication follows the store access;
- lateral movement is identified;
- multiple hosts or users are affected;
- the accessing process is associated with confirmed malware.

## Response Guidance

For confirmed malicious password-store access:

1. Preserve endpoint, file, process, authentication, and network evidence.
2. Identify affected hosts, users, accounts, and services.
3. Determine whether potentially exposed accounts were subsequently used.
4. Follow the organization's credential-compromise response procedure.
5. Review suspicious authentication and session activity.
6. Follow authorized account-containment and credential-remediation procedures.
7. Investigate additional persistence and credential-access mechanisms.
8. Review related applications and downloaded files where applicable.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, session invalidation, and account containment must follow approved organizational procedures.

Do not extract, display, or disclose real credentials during investigation or validation.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/lsass-access.yml`
- `detection-rules/yara/malware-sample.yar`

## Related Playbooks

- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/sam-dump.md`
- `playbooks/credential-access/ntds-dump.md`
- `playbooks/credential-access/browser-credential-theft.md`
- `playbooks/credential-access/password-manager-credential-theft.md`
- `playbooks/credential-access/windows-credential-manager.md`
- `playbooks/credential-access/credential-access.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved endpoint telemetry, synthetic password-store fixtures, file-access events, application telemetry, authentication events, and controlled credential-access scenarios.

Validation should confirm that:

- password-store access can be identified;
- the targeted credential store can be determined;
- accessing processes can be identified;
- process relationships can be correlated;
- file and database access can be investigated;
- potential credential exposure can be assessed;
- subsequent authentication can be correlated;
- legitimate application and security-tool access can be distinguished from suspicious access;
- escalation criteria produce consistent outcomes.

Validation should use synthetic credentials, sanitized password-store fixtures, and isolated laboratory systems.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not extract, recover, display, or disclose real credentials during investigation or validation.

Use synthetic credentials, sanitized fixtures, and isolated systems for testing.
