---
id: "credential-access"
name: "Credential Access"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-20T12:58:00Z"
updated_at: "2026-09-20T18:43:00Z"
description: "Credential access activity may expose passwords, authentication material, tokens, hashes, tickets, or other secrets used to access systems and services."
objective: "Identify, investigate, and validate suspicious credential-access activity, determine the affected credentials and scope, and support appropriate containment and credential-compromise response actions."
severity: "critical"
mitre_attack:
  - "T1003"
  - "T1110"
  - "T1555"
  - "T1558"
triggers:
  - "Unexpected credential-access activity"
  - "Suspicious credential dumping or credential-store access"
  - "Repeated authentication failures or password-spraying indicators"
  - "Suspicious access to password stores or authentication material"
  - "Credential-access activity associated with suspicious process execution"
  - "Credential access followed by anomalous authentication or lateral movement"
  - "Threat hunting identifies unusual credential-access behavior"
prerequisites:
  - "Access to endpoint telemetry"
  - "Access to process creation telemetry"
  - "Access to authentication telemetry"
  - "Access to file and network telemetry where available"
  - "Access to approved identity and asset context"
tags:
  - "credential-access"
  - "credential-theft"
  - "credentials"
  - "authentication"
  - "windows"
  - "identity"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1003/"
  - "https://attack.mitre.org/techniques/T1110/"
  - "https://attack.mitre.org/techniques/T1555/"
  - "https://attack.mitre.org/techniques/T1558/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Credential Access Alert"
  action: "investigate"
  description: "Identify the detection source, affected host or identity, associated user or account, observed credential-access behavior, and relevant timestamps."
  expected_result: "The suspicious credential-access event and affected asset or identity are identified."
- id: "identify-credential-access-type"
  order: 2
  name: "Identify Credential Access Type"
  action: "analyze"
  description: "Determine whether the activity involves credential dumping, password-store access, password spraying, Kerberos credential access, or another credential-access mechanism."
  expected_result: "The credential-access mechanism and targeted authentication material are documented."
- id: "review-process-and-account-context"
  order: 3
  name: "Review Process and Account Context"
  action: "analyze"
  description: "Review the accessing process, executable path, hash, signer, parent process, command line, user context, account privileges, and execution timeline."
  expected_result: "The process and account context are assessed."
- id: "review-credential-access-activity"
  order: 4
  name: "Review Credential Access Activity"
  action: "analyze"
  description: "Review endpoint, identity, file, authentication, and security telemetry associated with credential-access activity, collection, enumeration, copying, or attempted use."
  expected_result: "Relevant credential-access activity is identified or ruled out."
- id: "assess-credential-exposure"
  order: 5
  name: "Assess Potential Credential Exposure"
  action: "analyze"
  description: "Identify accounts, credentials, tokens, hashes, tickets, or authentication material potentially affected and assess their privilege and business impact."
  expected_result: "Potentially affected authentication material and associated risk are documented."
- id: "review-follow-on-activity"
  order: 6
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Correlate credential-access activity with authentication, persistence, privilege escalation, lateral movement, network activity, and additional credential-access behavior."
  expected_result: "Potential credential misuse and related attack activity are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Credential Access Scope"
  action: "hunt"
  description: "Search for the same process, file hash, account, command line, credential-access pattern, authentication activity, or related indicators across the environment."
  expected_result: "The prevalence and scope of the credential-access activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the credential-access activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "credential-access"
---

# Credential Access

## Purpose

This playbook provides a structured workflow for investigating suspicious **credential-access activity** across endpoints, identities, authentication systems, and protected credential stores.

Credential-access activity can target passwords, hashes, tokens, tickets, browser credentials, password-manager data, Windows credential stores, or other authentication material.

The objective is to determine whether the observed activity is legitimate, suspicious, or malicious, identify potentially exposed credentials, and determine the scope of the activity.

## MITRE ATT&CK

| Technique | Name                             | Relevance                                                                                    |
| --------- | -------------------------------- | -------------------------------------------------------------------------------------------- |
| T1003     | OS Credential Dumping            | Relevant when credentials are obtained from operating-system authentication stores or memory |
| T1110     | Brute Force                      | Relevant when repeated authentication attempts are used to obtain valid credentials          |
| T1555     | Credentials from Password Stores | Relevant when stored passwords or other authentication material are targeted                 |
| T1558     | Steal or Forge Kerberos Tickets  | Relevant when Kerberos tickets or related authentication material are targeted               |

MITRE ATT&CK organizes credential-access techniques around obtaining authentication material such as passwords, hashes, tokens, and tickets. The specific technique and sub-technique should be selected according to the observed behavior.

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint detection identifies suspicious credential-access behavior.
- Credential dumping or credential-store access is detected.
- Repeated authentication failures indicate possible password spraying or brute-force activity.
- An unexpected process accesses protected credential data.
- Browser, password-manager, Windows Credential Manager, SAM, LSASS, or other credential-related data is accessed unexpectedly.
- Credential-access activity is associated with suspected malware.
- Credential access is followed by suspicious authentication or lateral movement.
- Threat hunting identifies unusual credential-access behavior.

## Scope

The investigation should consider:

- affected host;
- associated user;
- affected account;
- credential-access mechanism;
- targeted credential store;
- accessing process;
- executable path;
- file hash;
- parent process;
- command line;
- account privileges;
- authentication events;
- file activity;
- network activity;
- persistence;
- privilege escalation;
- lateral movement;
- related alerts;
- other affected hosts and accounts.

## Credential Access Context

Credential-access activity can target multiple sources of authentication material.

Examples include:

- operating-system credential stores;
- LSASS memory;
- SAM and other local credential databases;
- Active Directory credential material;
- browser credential stores;
- password managers;
- Windows Credential Manager;
- DPAPI-protected data;
- password authentication attempts;
- Kerberos tickets.

Legitimate activity may be generated by:

- operating-system components;
- approved security tooling;
- identity-management systems;
- authorized administrative workflows;
- approved endpoint management software;
- authorized security testing.

The presence of credential-related data or normal authentication activity is not itself evidence of malicious behavior.

The investigation should focus on the **accessing process, account context, targeted resource, timing, authorization, and surrounding behavior**.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- affected account;
- credential-access type;
- detection severity;
- detection reason.

Preserve the original alert context before taking remediation actions.

### Step 2 — Identify Credential Access Type

Determine whether the activity involves:

- credential dumping;
- LSASS access;
- SAM access;
- NTDS access;
- browser credential access;
- password-manager access;
- Windows Credential Manager access;
- DPAPI-related access;
- password spraying;
- Kerberos ticket access;
- another credential-access mechanism.

Document the targeted authentication material without extracting or displaying real credentials.

### Step 3 — Review Process and Account Context

Review:

- process name;
- executable path;
- file hash;
- digital signature;
- parent process;
- child processes;
- command line;
- user context;
- account privilege;
- integrity level;
- execution timestamp.

Determine whether the activity is associated with:

- a legitimate system process;
- an approved security application;
- authorized administrative activity;
- an unknown or suspicious executable;
- a known malicious process.

### Step 4 — Review Credential Access Activity

Review available:

- process telemetry;
- file access telemetry;
- authentication logs;
- identity telemetry;
- EDR alerts;
- security events;
- network telemetry.

Determine:

- which credential resource was targeted;
- which process performed the access;
- when the activity occurred;
- whether credential material was copied or staged;
- whether multiple credential sources were targeted;
- whether cleanup activity followed.

Unexpected access from unrelated or untrusted processes requires additional investigation.

### Step 5 — Assess Potential Credential Exposure

Identify potentially affected:

- user accounts;
- administrative accounts;
- privileged accounts;
- service accounts;
- cloud identities;
- application accounts;
- authentication tokens;
- password hashes;
- Kerberos tickets.

Assess:

- privilege level;
- business importance;
- authentication scope;
- systems accessible by the affected identity.

Do not extract, display, or reuse real credentials during routine investigation.

### Step 6 — Review Follow-on Activity

Correlate credential-access activity with:

- successful authentication;
- failed authentication;
- new sessions;
- suspicious sign-ins;
- persistence;
- privilege escalation;
- lateral movement;
- remote access;
- suspicious network activity;
- additional credential-access events.

Pay particular attention to authentication or lateral movement shortly after credential access.

### Step 7 — Determine Credential Access Scope

Search the environment for:

- same accessing process;
- same file hash;
- same command line;
- same user or account;
- same credential-access behavior;
- related authentication activity;
- related network activity.

Determine:

- number of affected hosts;
- number of affected users;
- number of affected accounts;
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
| Credential Type  | Credential source or access mechanism                |
| Credential Store | Targeted store, resource, or authentication source   |
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

- the activity is generated by a legitimate system or approved security process;
- the operation is expected;
- the user and host context are authorized;
- the credential-access behavior has a documented operational purpose;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- credential-access behavior is unexpected;
- an unrelated process accesses credential material;
- the process is unusual, unsigned, or unknown;
- multiple credential sources are targeted unexpectedly;
- related endpoint or network activity is abnormal;
- suspicious authentication follows the credential-access event;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized credential access;
- confirmed credential-theft behavior;
- credential access associated with malware;
- subsequent misuse of affected credentials;
- lateral movement using potentially exposed credentials;
- persistence or privilege escalation linked to credential access;
- multiple independent indicators confirm compromise.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the credential-access activity was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- credential exposure is confirmed or strongly suspected;
- privileged or administrative credentials may be affected;
- cloud or corporate identities may have been exposed;
- suspicious authentication follows the credential-access activity;
- lateral movement is identified;
- multiple hosts or accounts are affected;
- the accessing process is associated with confirmed malware.

## Response Guidance

For confirmed malicious credential-access activity:

1. Preserve endpoint, identity, authentication, file, and network evidence.
2. Identify affected hosts, users, accounts, credentials, and services.
3. Determine whether potentially exposed credentials were subsequently used.
4. Follow the organization's credential-compromise response procedure.
5. Review suspicious authentication and session activity.
6. Follow authorized account-containment and credential-remediation procedures.
7. Investigate additional persistence and credential-access mechanisms.
8. Search for related activity across the environment.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, token or session invalidation, account containment, and credential remediation should follow approved organizational procedures.

Do not extract, display, or disclose real credentials during investigation or validation.

## Related Detection Rules

- `detection-rules/sigma/lsass-access.yml`
- `detection-rules/sigma/suspicious-login.yml`

## Related Playbooks

- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/ntds-dump.md`
- `playbooks/credential-access/sam-dump.md`
- `playbooks/credential-access/kerberoasting.md`
- `playbooks/credential-access/password-spraying.md`
- `playbooks/credential-access/asrep-roasting.md`
- `playbooks/credential-access/browser-credential-theft.md`
- `playbooks/credential-access/credentials-from-password-stores.md`
- `playbooks/credential-access/password-manager-credential-theft.md`
- `playbooks/credential-access/windows-credential-manager.md`
- `playbooks/credential-access/dpapi-credential-access.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved endpoint telemetry, synthetic credential data, authentication events, process telemetry, file-access events, identity telemetry, and controlled credential-access scenarios.

Validation should confirm that:

- credential-access activity can be identified;
- the credential-access mechanism can be determined;
- the affected credential source can be identified;
- accessing processes can be identified;
- process and account context can be correlated;
- potential credential exposure can be assessed;
- subsequent authentication can be correlated;
- legitimate administrative and security activity can be distinguished from suspicious behavior;
- environmental scope can be determined;
- escalation criteria produce consistent outcomes.

Validation should use synthetic credentials, sanitized test data, and isolated laboratory systems.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not extract, recover, display, or disclose real credentials during investigation or validation.

Use synthetic credentials, sanitized test data, and isolated systems for testing.
