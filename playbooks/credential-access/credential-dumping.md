---
id: "credential-dumping"
name: "Credential Dumping"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-14T21:55:00Z"
updated_at: "2026-09-20T18:47:00Z"
description: "Credential dumping involves attempts to obtain authentication material such as password hashes, cached credentials, or authentication secrets from systems."
objective: "Identify, investigate, and validate suspicious credential dumping activity and determine whether authentication material may have been exposed."
severity: "critical"
mitre_attack:
  - "T1003"
triggers:
  - "Suspicious credential dumping alert"
  - "Unexpected access to credential stores"
  - "Suspicious access to LSASS or other authentication processes"
  - "Unexpected access to SAM or related registry data"
  - "Credential access behavior associated with privilege escalation"
  - "Threat hunting identifies anomalous credential access activity"
prerequisites:
  - "Access to endpoint telemetry"
  - "Access to process creation telemetry"
  - "Access to authentication telemetry"
  - "Access to registry and file telemetry where available"
tags:
  - "credential-dumping"
  - "credential-access"
  - "credentials"
  - "windows"
  - "authentication"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1003/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Credential Access Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, account, process, timestamp, and alert context."
  expected_result: "The suspicious credential access event and affected asset are identified."
- id: "identify-access-target"
  order: 2
  name: "Identify Credential Access Target"
  action: "analyze"
  description: "Determine which authentication process, credential store, registry location, file, or other source was accessed."
  expected_result: "The credential access target and context are documented."
- id: "review-process-context"
  order: 3
  name: "Review Process Context"
  action: "analyze"
  description: "Review the process, parent process, command line, user context, integrity level, and available execution telemetry."
  expected_result: "The process execution chain and access context are assessed."
- id: "review-access-method"
  order: 4
  name: "Review Access Method"
  action: "analyze"
  description: "Determine how the credential material was accessed and whether the observed behavior matches an approved administrative or security workflow."
  expected_result: "The access method is understood without executing or reproducing credential extraction."
- id: "review-account-impact"
  order: 5
  name: "Assess Potential Account Exposure"
  action: "analyze"
  description: "Identify accounts that may have been exposed and determine their privilege, authentication scope, and business impact."
  expected_result: "Potentially affected accounts and their risk are documented."
- id: "review-follow-on-activity"
  order: 6
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Correlate credential access with authentication events, lateral movement, persistence, privilege escalation, and suspicious network activity."
  expected_result: "Post-access activity and possible credential misuse are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Credential Access Scope"
  action: "hunt"
  description: "Search for related processes, accounts, hosts, hashes, command lines, and credential access indicators across the environment."
  expected_result: "The prevalence and scope of the credential access activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the credential access activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "credential-dumping"
---

# Credential Dumping

## Purpose

This playbook provides a structured workflow for investigating suspected credential dumping activity.

Credential dumping refers to attempts to obtain authentication material from a system, including password hashes, cached credentials, authentication secrets, or other credential artifacts.

Credential access can have significant impact because exposed credentials may enable account compromise, privilege escalation, lateral movement, or persistence.

## MITRE ATT&CK

| Technique | Name                  | Relevance                                                                                          |
| --------- | --------------------- | -------------------------------------------------------------------------------------------------- |
| T1003     | OS Credential Dumping | Relevant when credential material is accessed or collected from operating system credential stores |

More specific T1003 sub-techniques should be mapped when the observed activity provides sufficient evidence to identify the specific credential source.

Do not assign a sub-technique solely from an alert title.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A credential dumping detection is generated.
- An unexpected process accesses a protected authentication process.
- A process accesses a sensitive credential store.
- Credential-related files or registry data are accessed unexpectedly.
- Credential access occurs in association with suspicious privilege escalation.
- Credential access is followed by unexpected authentication activity.
- Threat hunting identifies anomalous credential access behavior.

## Scope

The investigation should consider:

- affected host;
- affected user;
- initiating account;
- process name;
- process path;
- parent process;
- command line;
- execution time;
- target authentication process;
- target credential store;
- file or registry access;
- process integrity level;
- privileges;
- authentication events;
- lateral movement;
- persistence;
- network activity;
- related alerts;
- other affected hosts and accounts.

## Credential Sources

Potential credential sources may include:

- protected authentication processes;
- local account databases;
- registry-backed credential stores;
- cached authentication material;
- browser or application credential stores;
- password-management software;
- memory-resident authentication material.

The exact source should be determined from telemetry and evidence rather than assumed from the alert category.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated account;
- initiating process;
- target credential source;
- detection severity;
- detection reason.

Preserve the original alert context before taking remediation actions.

### Step 2 — Identify Credential Access Target

Determine which credential source was accessed.

Examples include:

- an authentication process;
- a local account database;
- sensitive registry data;
- cached credentials;
- application-specific credential storage.

Document the target without attempting to reproduce unauthorized credential extraction.

### Step 3 — Review Process Context

Review:

- process name;
- executable path;
- file hash;
- parent process;
- child processes;
- command line;
- user context;
- integrity level;
- process privileges;
- execution timestamp.

Determine whether the process belongs to approved security software, administrative tooling, endpoint management, or normal operating-system behavior.

### Step 4 — Review Access Method

Determine the observed access method from available telemetry.

Investigate:

- process access events;
- protected-process access;
- registry access;
- file access;
- security product alerts;
- endpoint behavioral detections.

Do not execute credential extraction tools or reproduce credential theft on production systems.

### Step 5 — Assess Potential Account Exposure

Identify:

- accounts present on the affected system;
- privileged accounts;
- service accounts;
- administrative accounts;
- accounts that authenticated recently;
- accounts that may have had authentication material exposed.

Determine whether additional systems may be affected by the potential exposure.

### Step 6 — Review Follow-on Activity

Correlate the credential access event with:

- successful and failed authentication;
- new logons;
- privileged logons;
- lateral movement;
- remote service activity;
- persistence;
- privilege escalation;
- suspicious network connections;
- additional credential access events.

Pay particular attention to activity that occurs shortly after the suspected credential access.

### Step 7 — Determine Credential Access Scope

Search the environment for:

- same initiating process;
- same executable hash;
- same command line;
- same user account;
- same host;
- same credential access indicator;
- same source and target relationship.

Determine:

- number of affected hosts;
- number of affected accounts;
- first observed activity;
- latest observed activity;
- whether credential access is ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence          | Description                                                 |
| ----------------- | ----------------------------------------------------------- |
| Alert             | Detection source, ID, severity, timestamp                   |
| Host              | Hostname, IP address, operating system                      |
| Account           | Initiating and potentially affected accounts                |
| Process           | Process name, path, hash                                    |
| Parent Process    | Process responsible for launching the activity              |
| Command Line      | Available command-line information                          |
| Credential Target | Authentication process, file, registry, or credential store |
| Access Telemetry  | Relevant process, registry, and file access events          |
| Privileges        | Process integrity level and privilege context               |
| Authentication    | Related logon and authentication events                     |
| Lateral Movement  | Related remote access activity                              |
| Persistence       | Related persistence indicators                              |
| Network           | Related network connections                                 |
| Timeline          | Correlated credential, process, and authentication events   |
| Scope             | Other affected hosts and accounts                           |
| Detections        | Related security alerts                                     |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the process belongs to approved security or administration tooling;
- the access is expected;
- the account and host context are authorized;
- the observed behavior matches documented operational activity;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the credential access source is unclear;
- a non-standard process accesses sensitive credential material;
- the initiating account is unexpected;
- the process context is unusual;
- related authentication activity is anomalous;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized credential collection;
- malicious access to credential stores;
- credential access associated with a confirmed compromise;
- subsequent use of compromised credentials;
- lateral movement using exposed credentials;
- persistence or privilege escalation linked to the credential access.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the credential access was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate immediately when:

- credential compromise is confirmed;
- privileged credentials may have been exposed;
- service-account credentials may have been exposed;
- compromised credentials appear to have been used;
- lateral movement is identified;
- multiple hosts or accounts are affected;
- credential access is associated with confirmed malware.

## Response Guidance

For confirmed malicious credential dumping:

1. Preserve process, authentication, registry, file, and network evidence.
2. Identify potentially exposed accounts and affected hosts.
3. Follow the organization's credential-compromise response procedure.
4. Review and contain suspected compromised accounts according to policy.
5. Investigate authentication activity for evidence of credential reuse.
6. Search for lateral movement and additional persistence.
7. Follow authorized endpoint containment procedures.
8. Review possible exposure of privileged or service credentials.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, session invalidation, or account containment should follow the organization's approved incident-response procedures.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`

## Related Playbooks

- `playbooks/credential-access/credential-access.md`
- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/ntds-dump.md`
- `playbooks/credential-access/sam-dump.md`
- `playbooks/credential-access/dpapi-credential-access.md`
- `playbooks/credential-access/credentials-from-password-stores.md`
- `playbooks/credential-access/password-manager-credential-theft.md`
- `playbooks/credential-access/browser-credential-theft.md`
- `playbooks/credential-access/password-spraying.md`
- `playbooks/privilege-escalation/token-manipulation.md`
- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/lateral-movement/pass-the-ticket.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/lateral-movement-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved endpoint telemetry, credential-access detection fixtures, authentication events, process telemetry, and controlled security-validation scenarios.

Validation should confirm that:

- suspicious credential access can be identified;
- the credential source can be determined;
- initiating processes and accounts can be correlated;
- privileged and non-privileged contexts can be distinguished;
- authentication activity can be correlated;
- potential account exposure can be assessed;
- lateral movement can be identified;
- benign administrative and security tooling can be distinguished from malicious credential access;
- escalation criteria produce consistent outcomes.

Validation should use controlled fixtures and telemetry rather than real credential extraction from production systems.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not extract, disclose, or handle real user credentials during validation. Use synthetic credentials, sanitized fixtures, and isolated laboratory systems for testing.

Credential-compromise response actions must follow approved organizational procedures and applicable access-control requirements.
