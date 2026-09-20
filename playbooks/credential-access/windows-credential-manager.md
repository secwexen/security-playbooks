---
id: "windows-credential-manager"
name: "Windows Credential Manager"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-19T17:58:00Z"
updated_at: "2026-09-20T18:39:00Z"
description: "Unauthorized access to Windows Credential Manager data can expose stored credentials and other authentication material."
objective: "Identify, investigate, and validate suspicious access to Windows Credential Manager data and determine whether stored credentials may have been exposed."
severity: "high"
mitre_attack:
  - "T1555.004"
triggers:
  - "Unexpected access to Windows Credential Manager data"
  - "Unknown process accessing Credential Manager or related credential data"
  - "Suspicious credential enumeration activity"
  - "Credential Manager access associated with suspicious process execution"
  - "Credential-store access followed by anomalous authentication activity"
  - "Threat hunting identifies unusual Windows Credential Manager activity"
prerequisites:
  - "Access to endpoint telemetry"
  - "Access to process creation telemetry"
  - "Access to file access telemetry"
  - "Access to authentication telemetry where available"
  - "Access to approved Windows Credential Manager application metadata"
tags:
  - "windows"
  - "credential-manager"
  - "credential-access"
  - "credential-theft"
  - "credentials"
  - "authentication"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1555/004/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Credential Manager Access Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, user, accessing process, targeted resource, and relevant timestamps."
  expected_result: "The suspicious Windows Credential Manager access event and affected asset are identified."
- id: "identify-target-store"
  order: 2
  name: "Identify Target Credential Store"
  action: "analyze"
  description: "Determine which Windows Credential Manager resource, credential store, user profile, or related artifact was accessed."
  expected_result: "The targeted credential resource is documented."
- id: "review-process-context"
  order: 3
  name: "Review Process Context"
  action: "analyze"
  description: "Review the accessing process, executable path, hash, signer, parent process, command line, account context, and execution timeline."
  expected_result: "The accessing process and execution context are assessed."
- id: "review-store-activity"
  order: 4
  name: "Review Credential Store Activity"
  action: "analyze"
  description: "Review file, process, application, and endpoint telemetry associated with Credential Manager access, enumeration, copying, or staging."
  expected_result: "Relevant credential-store activity is identified or ruled out."
- id: "assess-credential-exposure"
  order: 5
  name: "Assess Potential Credential Exposure"
  action: "analyze"
  description: "Identify accounts and services potentially represented in the affected credential store and assess their privilege and business impact."
  expected_result: "Potentially affected accounts and services are documented."
- id: "review-follow-on-activity"
  order: 6
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Correlate Credential Manager access with authentication, persistence, privilege escalation, lateral movement, and suspicious network activity."
  expected_result: "Potential credential misuse and related activity are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Credential Manager Access Scope"
  action: "hunt"
  description: "Search for the same accessing process, file hash, account, credential store, access pattern, or related activity across the environment."
  expected_result: "The prevalence and scope of the Credential Manager access are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the Credential Manager access activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "windows-credential-manager"
---

# Windows Credential Manager

## Purpose

This playbook provides a structured workflow for investigating suspicious access to Windows Credential Manager and related credential stores.

Windows Credential Manager is used to store credentials and authentication information for applications, services, network resources, and other supported Windows functionality. Unauthorized access to this data may expose authentication material and contribute to account compromise.

The objective is to determine whether the observed Credential Manager access is legitimate, suspicious, or malicious and whether stored credentials may have been exposed.

## MITRE ATT&CK

| Technique | Name                                                         | Relevance                                                                       |
| --------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| T1555.004 | Credentials from Password Stores: Windows Credential Manager | Relevant when Windows Credential Manager data is targeted for credential access |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint detection identifies suspicious access to Windows Credential Manager.
- An unexpected process accesses Credential Manager data.
- A process enumerates or interacts with credential-store data unexpectedly.
- An unknown executable accesses a credential-related Windows resource.
- Credential Manager access is associated with suspected malware.
- Authentication activity changes unexpectedly after Credential Manager access.
- Threat hunting identifies unusual credential-store access.

## Scope

The investigation should consider:

- affected host;
- associated user;
- Windows Credential Manager;
- credential store;
- affected user profile;
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

## Windows Credential Manager Context

Windows Credential Manager can contain authentication information used by supported applications, network resources, and other Windows components.

Legitimate access may be generated by:

- Windows system components;
- approved applications;
- authorized administrative workflows;
- endpoint management software;
- approved security tooling;
- authorized troubleshooting or maintenance activity.

The presence of Credential Manager data on a Windows system is not itself evidence of malicious activity.

The investigation should focus on the **accessing process, account context, targeted resource, timing, and surrounding behavior**.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- accessing process;
- targeted resource;
- detection severity;
- detection reason.

Preserve the original alert context before taking remediation actions.

### Step 2 — Identify Target Credential Store

Determine:

- affected Windows Credential Manager resource;
- user profile;
- relevant credential-related artifact;
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

- a legitimate Windows component;
- an approved application;
- approved security or management software;
- an unknown or suspicious executable.

### Step 4 — Review Credential Store Activity

Review available:

- file access telemetry;
- process activity;
- application telemetry;
- endpoint security alerts;
- credential-store access events.

Determine:

- which process accessed the credential store;
- when the access occurred;
- whether credential-related data was copied;
- whether data was staged or archived;
- whether cleanup activity followed.

Unexpected access from processes unrelated to normal Windows or application activity requires additional investigation.

### Step 5 — Assess Potential Credential Exposure

Identify potentially affected accounts or services represented in the credential context, based on available evidence.

Consider:

- corporate accounts;
- cloud accounts;
- administrative accounts;
- privileged accounts;
- service accounts;
- sensitive business applications.

Do not extract or display real credentials during routine investigation.

### Step 6 — Review Follow-on Activity

Correlate Credential Manager access with:

- successful authentication;
- failed authentication;
- new sessions;
- suspicious sign-ins;
- privilege escalation;
- lateral movement;
- persistence;
- suspicious network activity;
- additional credential-access activity.

Pay particular attention to suspicious authentication shortly after the Credential Manager access.

### Step 7 — Determine Credential Manager Access Scope

Search the environment for:

- same accessing process;
- same file hash;
- same command line;
- same user account;
- same credential-store access pattern;
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
| Credential Store | Windows Credential Manager resource or artifact      |
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

- the accessing process is a legitimate Windows component or approved application;
- the operation is expected;
- the user and host context are authorized;
- access is associated with approved administrative or management activity;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- an unrelated process accesses Credential Manager data;
- the process is unusual or unknown;
- the file path or signer is unexpected;
- credential-store access occurs together with other suspicious activity;
- related endpoint or network activity is abnormal;
- suspicious authentication follows the access;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized access to Windows Credential Manager data;
- confirmed credential-theft behavior;
- Credential Manager access associated with malware;
- subsequent misuse of potentially exposed credentials;
- lateral movement using affected accounts;
- persistence or privilege escalation linked to the activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the Credential Manager access was legitimate or malicious.

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

For confirmed malicious Windows Credential Manager credential theft:

1. Preserve endpoint, file, process, authentication, and network evidence.
2. Identify affected hosts, users, accounts, and services.
3. Determine whether potentially exposed accounts were subsequently used.
4. Follow the organization's credential-compromise response procedure.
5. Review suspicious authentication and session activity.
6. Follow authorized account-containment and credential-remediation procedures.
7. Investigate additional persistence and credential-access mechanisms.
8. Search for related activity across other endpoints.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, session invalidation, account containment, and credential remediation should follow approved organizational procedures.

Do not extract, display, or disclose real credentials during investigation or validation.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`

## Related Playbooks

- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/browser-credential-theft.md`
- `playbooks/credential-access/credentials-from-password-stores.md`
- `playbooks/credential-access/password-manager-credential-theft.md`
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

The playbook should be validated against approved endpoint telemetry, synthetic Credential Manager fixtures, file-access events, process telemetry, authentication events, and controlled credential-access scenarios.

Validation should confirm that:

- Windows Credential Manager access can be identified;
- the targeted credential resource can be determined;
- accessing processes can be identified;
- process relationships can be correlated;
- credential-store activity can be investigated;
- potential credential exposure can be assessed;
- subsequent authentication can be correlated;
- legitimate Windows and administrative activity can be distinguished from suspicious access;
- escalation criteria produce consistent outcomes.

Validation should use synthetic credentials, sanitized fixtures, and isolated laboratory systems.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not extract, recover, display, or disclose real credentials during investigation or validation.

Use synthetic credentials, sanitized test data, and isolated systems for testing.
