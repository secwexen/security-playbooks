---
id: "browser-credential-theft"
name: "Browser Credential Theft"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-18T14:47:00Z"
updated_at: "2026-09-20T18:42:00Z"
description: "Browser credential theft involves attempts to access stored authentication material from web browsers and related browser profile data."
objective: "Identify, investigate, and validate suspicious access to browser credential stores and determine whether authentication material may have been exposed."
severity: "high"
mitre_attack:
  - "T1555.003"
triggers:
  - "Unexpected access to browser credential stores"
  - "Suspicious process accessing browser profile data"
  - "Unknown executable reading browser credential artifacts"
  - "Browser credential access associated with malware or suspicious execution"
  - "Browser data access followed by anomalous authentication activity"
  - "Threat hunting identifies unusual browser credential access"
prerequisites:
  - "Access to endpoint telemetry"
  - "Access to process creation telemetry"
  - "Access to file access telemetry"
  - "Access to authentication telemetry where available"
tags:
  - "browser-credential-theft"
  - "credential-access"
  - "credentials"
  - "browser"
  - "windows"
  - "endpoint"
  - "authentication"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1555/003/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Browser Credential Access Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, account, accessing process, browser profile, and relevant timestamps."
  expected_result: "The suspicious browser credential-access event and affected asset are identified."
- id: "identify-browser-data"
  order: 2
  name: "Identify Browser Data Target"
  action: "analyze"
  description: "Determine which browser, profile, credential-related data store, or browser artifact was accessed."
  expected_result: "The browser and targeted data source are documented."
- id: "review-process-context"
  order: 3
  name: "Review Process Context"
  action: "analyze"
  description: "Review the accessing process, executable path, hash, parent process, command line, account context, and execution time."
  expected_result: "The accessing process and execution context are assessed."
- id: "review-file-activity"
  order: 4
  name: "Review File Activity"
  action: "analyze"
  description: "Review file access, creation, copying, staging, archiving, or deletion associated with the browser profile."
  expected_result: "Relevant browser-profile file activity is identified or ruled out."
- id: "review-follow-on-activity"
  order: 5
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Correlate browser credential access with authentication events, suspicious network activity, persistence, privilege escalation, and lateral movement."
  expected_result: "Potential credential misuse and follow-on activity are identified or ruled out."
- id: "assess-account-impact"
  order: 6
  name: "Assess Potential Credential Exposure"
  action: "analyze"
  description: "Identify accounts or web services potentially associated with exposed browser credentials and assess their privilege and business impact."
  expected_result: "Potentially affected accounts and services are documented."
- id: "determine-scope"
  order: 7
  name: "Determine Browser Credential Access Scope"
  action: "hunt"
  description: "Search for the same accessing process, file hash, browser profile access pattern, account, or host activity across the environment."
  expected_result: "The prevalence and scope of the browser credential-access activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the browser credential-access activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "browser-credential-theft"
---

# Browser Credential Theft

## Purpose

This playbook provides a structured workflow for investigating suspicious access to credentials and authentication material stored by web browsers.

Modern browsers may store authentication-related data within user profiles. Unauthorized access to browser credential stores can expose credentials or other authentication material and may lead to account compromise.

The objective is to determine whether the observed browser-data access is legitimate, suspicious, or malicious and whether credential exposure may have occurred.

## MITRE ATT&CK

| Technique | Name                          | Relevance                                                                                |
| --------- | ----------------------------- | ---------------------------------------------------------------------------------------- |
| T1555.003 | Credentials from Web Browsers | Relevant when browser-stored credentials or related authentication material are targeted |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint detection identifies suspicious browser credential access.
- An unexpected process accesses browser profile data.
- An unknown executable reads browser credential-related artifacts.
- Browser data access is associated with known or suspected malware.
- Browser credential access is followed by anomalous authentication activity.
- Threat hunting identifies unusual browser profile or credential-store access.

## Scope

The investigation should consider:

- affected host;
- associated user;
- browser;
- browser profile;
- accessing process;
- executable path;
- file hash;
- parent process;
- command line;
- account context;
- file access;
- credential-related browser artifacts;
- authentication events;
- network activity;
- DNS activity;
- persistence;
- privilege escalation;
- lateral movement;
- related alerts;
- other affected hosts and accounts.

## Browser Credential Context

Browser profiles can contain authentication-related data used by websites and applications.

Depending on the browser and platform, relevant artifacts may include:

- credential stores;
- profile databases;
- cookies;
- saved login metadata;
- browser configuration files;
- session-related data.

Not every access to a browser profile is malicious. Browsers, extensions, backup tools, endpoint-management software, and approved security tools may legitimately access profile data.

The investigation should therefore focus on the **accessing process, user context, targeted artifacts, timing, and surrounding activity**.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- accessing process;
- browser;
- profile;
- detection severity;
- detection reason.

Preserve the original alert context before taking remediation actions.

### Step 2 — Identify Browser Data Target

Determine:

- browser name;
- browser version where available;
- user profile;
- profile path;
- browser-related artifact accessed;
- access timestamp;
- access type where available.

Document the target without extracting or disclosing real credentials.

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
- execution timestamp;
- integrity level;
- available privileges.

Determine whether the accessing process belongs to the browser itself, approved administration, backup, endpoint security, or another legitimate application.

### Step 4 — Review File Activity

Investigate:

- browser profile file access;
- file creation;
- file copying;
- archive creation;
- temporary files;
- staging activity;
- deletion or cleanup.

Correlate file activity with the initiating process and account.

Pay particular attention to unusual access from:

- temporary directories;
- user-writable paths;
- scripting environments;
- unsigned executables;
- unexpected administrative tools.

### Step 5 — Review Follow-on Activity

Correlate browser credential access with:

- authentication events;
- successful and failed logons;
- new sessions;
- suspicious network connections;
- DNS activity;
- privilege escalation;
- persistence;
- lateral movement.

Pay particular attention to suspicious authentication shortly after the browser credential-access event.

### Step 6 — Assess Potential Credential Exposure

Identify potentially affected accounts and services based on available evidence.

Consider:

- corporate accounts;
- cloud services;
- email accounts;
- privileged accounts;
- administrative accounts;
- sensitive business applications.

Do not attempt to recover or display real credentials as part of routine investigation.

### Step 7 — Determine Browser Credential Access Scope

Search the environment for:

- same accessing process;
- same file hash;
- same command line;
- same browser;
- same artifact-access pattern;
- same account;
- same affected host;
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

| Evidence         | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| Alert            | Detection source, ID, severity, timestamp                    |
| Host             | Hostname, IP address, operating system                       |
| User             | Associated user or account                                   |
| Browser          | Browser name and profile                                     |
| Artifact         | Browser credential-related data accessed                     |
| Process          | Process name, path, hash                                     |
| Parent Process   | Process responsible for launching the accessor               |
| Command Line     | Available command-line information                           |
| File Activity    | Accessed, copied, staged, archived, or deleted files         |
| Account Context  | User and process privilege context                           |
| Authentication   | Related authentication events                                |
| Network          | Related network connections                                  |
| DNS              | Related DNS activity                                         |
| Persistence      | Related persistence indicators                               |
| Lateral Movement | Related remote access activity                               |
| Timeline         | Correlated browser, process, file, and authentication events |
| Scope            | Other affected hosts and accounts                            |
| Detections       | Related security alerts                                      |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the accessing process is an approved application;
- the browser or endpoint software is expected to access its own profile;
- the operation is part of an approved backup, security, or administrative workflow;
- the account and host context are authorized;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- an unusual process accesses browser credential-related data;
- the process path or signer is unexpected;
- the accessing account is unusual;
- browser data is copied or staged unexpectedly;
- related file or network activity is abnormal;
- subsequent authentication activity is suspicious;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized browser credential access;
- confirmed credential-theft behavior;
- browser-data access associated with malware;
- subsequent misuse of potentially exposed credentials;
- lateral movement using affected accounts;
- persistence or privilege escalation linked to the activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the browser credential access was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- credential exposure is confirmed or strongly suspected;
- privileged or administrative accounts may be affected;
- cloud or corporate accounts may have been exposed;
- suspicious authentication follows the browser access;
- lateral movement is identified;
- multiple hosts or users are affected;
- the accessing process is associated with confirmed malware.

## Response Guidance

For confirmed malicious browser credential theft:

1. Preserve endpoint, file, process, authentication, and network evidence.
2. Identify affected hosts, users, accounts, and services.
3. Determine whether potentially exposed accounts were subsequently used.
4. Follow the organization's credential-compromise response procedure.
5. Review suspicious authentication and session activity.
6. Follow authorized account-containment and credential-remediation procedures.
7. Investigate additional persistence and credential-access mechanisms.
8. Review related browser extensions, applications, and downloaded files where applicable.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, session invalidation, and account containment must follow approved organizational procedures.

Do not extract, display, or disclose real browser credentials during investigation or validation.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`

## Related Playbooks

- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/sam-dump.md`
- `playbooks/credential-access/credentials-from-password-stores.md`
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

The playbook should be validated against approved endpoint telemetry, synthetic browser-profile fixtures, file-access events, authentication telemetry, and controlled credential-access scenarios.

Validation should confirm that:

- browser profile access can be identified;
- credential-related artifact access can be distinguished;
- accessing processes can be identified;
- parent-child process relationships can be correlated;
- file copying and staging activity can be investigated;
- related authentication activity can be correlated;
- potential credential exposure can be assessed;
- legitimate browser and security-tool activity can be distinguished from suspicious access;
- escalation criteria produce consistent outcomes.

Validation should use synthetic accounts, sanitized browser data, and isolated laboratory systems.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not extract, recover, display, or handle real browser credentials during validation.

Use synthetic credentials, sanitized browser profiles, and isolated systems for testing.
