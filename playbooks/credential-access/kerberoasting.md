---
id: "kerberoasting"
name: "Kerberoasting"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-16T18:45:00Z"
updated_at: "2026-09-20T18:50:00Z"
description: "Kerberoasting involves requesting Kerberos service tickets for service accounts and attempting to recover account credentials from the captured ticket material."
objective: "Identify, investigate, and validate suspicious Kerberoasting activity and determine whether service-account credentials may have been targeted or exposed."
severity: "high"
mitre_attack:
  - "T1558.003"
triggers:
  - "Unexpected Kerberos service ticket requests"
  - "Abnormal volume of service ticket requests from a single account or host"
  - "Service ticket activity involving unusual user accounts"
  - "Kerberos ticket requests targeting unexpected service accounts"
  - "Service ticket activity associated with privilege escalation or lateral movement"
  - "Threat hunting identifies anomalous Kerberos service-ticket activity"
prerequisites:
  - "Access to Kerberos authentication telemetry"
  - "Access to domain-controller security logs"
  - "Access to process and endpoint telemetry"
  - "Access to account and directory-service information"
tags:
  - "kerberoasting"
  - "credential-access"
  - "kerberos"
  - "active-directory"
  - "service-account"
  - "domain"
  - "windows"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1558/003/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Kerberoasting Alert"
  action: "investigate"
  description: "Identify the detection source, initiating account, source host, service account, ticket activity, and timestamps."
  expected_result: "The suspicious Kerberos service-ticket activity and affected entities are identified."
- id: "identify-service-ticket"
  order: 2
  name: "Identify Service Ticket Activity"
  action: "analyze"
  description: "Determine which service accounts and service principal names were targeted and characterize the associated ticket requests."
  expected_result: "The targeted service accounts and ticket request context are documented."
- id: "review-source-context"
  order: 3
  name: "Review Source Context"
  action: "analyze"
  description: "Review the source host, initiating account, process activity, authentication context, and whether the activity matches expected administrative behavior."
  expected_result: "The source system and initiating account context are assessed."
- id: "review-account-context"
  order: 4
  name: "Review Service Account Context"
  action: "analyze"
  description: "Review the targeted service accounts, service principal names, privilege level, ownership, usage, and expected authentication patterns."
  expected_result: "The targeted service-account context and potential impact are documented."
- id: "review-authentication-activity"
  order: 5
  name: "Review Authentication Activity"
  action: "analyze"
  description: "Correlate service-ticket requests with logon events, authentication anomalies, privilege changes, and subsequent account activity."
  expected_result: "Related authentication activity is correlated and assessed."
- id: "review-follow-on-activity"
  order: 6
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Investigate subsequent lateral movement, privileged access, persistence, suspicious network activity, or use of affected service accounts."
  expected_result: "Potential credential misuse and follow-on activity are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Kerberoasting Scope"
  action: "hunt"
  description: "Search for similar ticket-request patterns, source hosts, initiating accounts, targeted service accounts, and related authentication activity across the environment."
  expected_result: "The prevalence and scope of the Kerberoasting activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "kerberoasting"
---

# Kerberoasting

## Purpose

This playbook provides a structured workflow for investigating suspicious Kerberos service-ticket activity associated with potential Kerberoasting.

Kerberoasting targets service accounts by requesting Kerberos service tickets for service principal names (SPNs). The resulting ticket material may then be subjected to offline credential-recovery attempts.

The objective is to determine whether the observed ticket activity is legitimate, suspicious, or malicious and whether service-account credentials may have been targeted or exposed.

## MITRE ATT&CK

| Technique | Name                                           | Relevance                                                                                                           |
| --------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Relevant when Kerberos service tickets are requested or used in a manner consistent with credential-access activity |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An unusual volume of service-ticket requests is detected.
- A single user or host requests tickets for an unusual number of service accounts.
- Service tickets are requested for unexpected or high-value service accounts.
- Kerberos activity differs significantly from the account's normal behavior.
- Service-ticket requests are associated with suspicious process execution.
- Subsequent authentication or lateral-movement activity is observed.
- Threat hunting identifies anomalous service-ticket request patterns.

## Scope

The investigation should consider:

- initiating host;
- initiating account;
- targeted service account;
- service principal name;
- domain controller;
- ticket request timestamp;
- ticket request volume;
- source IP;
- process information;
- authentication context;
- service-account privileges;
- service-account ownership;
- account usage history;
- subsequent authentication;
- lateral movement;
- privilege escalation;
- persistence;
- network activity;
- related alerts;
- additional affected accounts and hosts.

## Kerberos Context

Kerberos is a primary authentication protocol used by Windows Active Directory environments.

Service accounts may have associated service principal names that allow clients to request service tickets for services operating under those accounts.

Not every service-ticket request is suspicious. Applications, users, administrators, and automated services may legitimately request multiple tickets during normal operations.

The investigation should therefore focus on the request pattern, initiating identity, targeted service accounts, and surrounding telemetry.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- initiating account;
- source host;
- source IP;
- targeted service account;
- targeted SPN;
- domain controller;
- detection severity;
- detection reason.

Preserve the original alert context before taking response actions.

### Step 2 — Identify Service Ticket Activity

Determine:

- requested service principal names;
- targeted service accounts;
- number of ticket requests;
- request frequency;
- request timestamps;
- source systems;
- whether requests are concentrated on a small number of accounts.

Look for patterns that differ from the normal behavior of the initiating account or host.

### Step 3 — Review Source Context

Review:

- initiating user;
- source host;
- process activity;
- command-line telemetry;
- authentication context;
- endpoint security alerts.

Determine whether the source account or system normally performs administrative, application, or service-related authentication.

### Step 4 — Review Service Account Context

For each targeted service account, determine:

- account name;
- SPN;
- account owner;
- associated service;
- privilege level;
- group memberships;
- expected hosts;
- password-management process;
- recent changes.

Prioritize service accounts with elevated privileges or access to sensitive systems for further investigation.

### Step 5 — Review Authentication Activity

Correlate service-ticket requests with:

- logon events;
- Kerberos authentication;
- privilege changes;
- account changes;
- remote service access;
- domain-controller events.

Determine whether the activity is part of an expected application or administrative workflow.

### Step 6 — Review Follow-on Activity

Investigate activity occurring after the suspicious ticket requests, including:

- authentication using targeted accounts;
- lateral movement;
- remote-service access;
- privilege escalation;
- persistence;
- suspicious process execution;
- unusual network connections.

A suspicious ticket-request pattern combined with later account misuse should be treated as a higher-priority investigation.

### Step 7 — Determine Kerberoasting Scope

Search the environment for:

- same initiating account;
- same source host;
- same service accounts;
- same SPNs;
- similar ticket-request patterns;
- related authentication events;
- subsequent lateral movement.

Determine:

- number of affected hosts;
- number of targeted service accounts;
- number of initiating accounts;
- first observed activity;
- latest observed activity;
- whether activity is ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence           | Description                                           |
| ------------------ | ----------------------------------------------------- |
| Alert              | Detection source, ID, severity, timestamp             |
| Source Host        | Host initiating the ticket requests                   |
| Source Account     | Account requesting service tickets                    |
| Service Account    | Targeted service account                              |
| SPN                | Targeted service principal name                       |
| Ticket Activity    | Request timestamps and request volume                 |
| Domain Controller  | Domain controller processing the requests             |
| Process            | Related process and endpoint activity                 |
| Command Line       | Available command-line information                    |
| Account Privileges | Privilege level and group memberships                 |
| Authentication     | Related Kerberos and logon events                     |
| Lateral Movement   | Related remote-access activity                        |
| Persistence        | Related persistence indicators                        |
| Network            | Related network connections                           |
| Timeline           | Correlated ticket, process, and authentication events |
| Scope              | Other affected accounts and hosts                     |
| Detections         | Related security alerts                               |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- ticket requests are consistent with normal application behavior;
- the initiating account is expected to request the tickets;
- targeted service accounts are known and operationally justified;
- request volume is consistent with normal activity;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- request volume is unusual for the initiating account;
- many service accounts are targeted unexpectedly;
- the initiating host is unusual;
- targeted service accounts are high-value or unexpected;
- the activity does not match known application behavior;
- related authentication or endpoint activity is anomalous;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized Kerberos ticket harvesting behavior;
- confirmed credential-access activity targeting service accounts;
- subsequent misuse of affected service-account credentials;
- lateral movement using compromised service accounts;
- privilege escalation associated with compromised credentials;
- other confirmed malicious activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the ticket-request activity was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- privileged service accounts are targeted;
- multiple service accounts are targeted unexpectedly;
- suspicious ticket activity is followed by account misuse;
- lateral movement is identified;
- domain or enterprise-level privileges may be affected;
- multiple hosts or accounts are involved;
- confirmed credential compromise is suspected.

## Response Guidance

For confirmed malicious Kerberoasting activity:

1. Preserve Kerberos, process, endpoint, and authentication evidence.
2. Identify all affected service accounts and source systems.
3. Determine the privileges and resources associated with affected accounts.
4. Follow the organization's credential-compromise response procedure.
5. Review authentication activity for evidence of credential reuse.
6. Investigate lateral movement and privilege escalation.
7. Follow authorized account-containment and credential-remediation procedures.
8. Review service-account password-management practices.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, session invalidation, and service-account containment should follow approved organizational procedures.

Do not attempt to recover real service-account passwords during routine investigation or validation.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`

## Related Playbooks

- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/ntds-dump.md`
- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/asrep-roasting.md`
- `playbooks/credential-access/password-spraying.md`
- `playbooks/credential-access/credential-access.md`
- `playbooks/lateral-movement/pass-the-ticket.md`
- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/lateral-movement/wmi-lateral-movement.md`
- `playbooks/lateral-movement/smb-lateral-movement.md`
- `playbooks/privilege-escalation/token-manipulation.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/triage/lateral-movement-triage.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/lateral-movement-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved Kerberos authentication telemetry, service-ticket detection fixtures, account metadata, endpoint telemetry, and controlled Active Directory scenarios.

Validation should confirm that:

- abnormal service-ticket request patterns can be identified;
- initiating hosts and accounts can be determined;
- targeted service accounts and SPNs can be identified;
- service-account privilege context can be assessed;
- Kerberos and logon activity can be correlated;
- subsequent credential misuse can be investigated;
- lateral movement can be identified;
- legitimate application behavior can be distinguished from suspicious ticket-request activity;
- escalation criteria produce consistent outcomes.

Validation should use synthetic accounts, sanitized telemetry, and isolated laboratory environments.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not request, extract, recover, or disclose real service-account credentials during investigation or validation.

Use synthetic service accounts and isolated Active Directory environments for security testing.
