---
id: "asrep-roasting"
name: "AS-REP Roasting"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-17T20:17:00Z"
updated_at: "2026-09-20T18:40:00Z"
description: "AS-REP Roasting targets Active Directory accounts that do not require Kerberos pre-authentication and may expose material that can be subjected to offline credential-recovery attempts."
objective: "Identify, investigate, and validate suspicious AS-REP activity and determine whether domain accounts may have been targeted or exposed."
severity: "high"
mitre_attack:
  - "T1558.004"
triggers:
  - "Unexpected Kerberos AS-REQ activity involving accounts without pre-authentication"
  - "Unusual authentication requests targeting multiple user accounts"
  - "AS-REP activity originating from an unexpected host or account"
  - "AS-REP activity associated with credential-access, privilege escalation, or lateral movement indicators"
  - "Threat hunting identifies anomalous Kerberos pre-authentication patterns"
prerequisites:
  - "Access to Kerberos authentication telemetry"
  - "Access to domain-controller security logs"
  - "Access to Active Directory account metadata"
  - "Access to endpoint and process telemetry where available"
tags:
  - "asrep-roasting"
  - "credential-access"
  - "kerberos"
  - "active-directory"
  - "domain"
  - "authentication"
  - "windows"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1558/004/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify AS-REP Roasting Alert"
  action: "investigate"
  description: "Identify the detection source, source host, initiating account, targeted account, domain controller, and relevant timestamps."
  expected_result: "The suspicious AS-REP activity and affected entities are identified."
- id: "identify-target-accounts"
  order: 2
  name: "Identify Target Accounts"
  action: "analyze"
  description: "Determine which accounts were targeted and whether Kerberos pre-authentication is disabled for those accounts."
  expected_result: "Targeted accounts and their authentication configuration are documented."
- id: "review-source-context"
  order: 3
  name: "Review Source Context"
  action: "analyze"
  description: "Review the source host, initiating account, process activity, network context, and whether the activity is expected."
  expected_result: "The source system and initiating identity are assessed."
- id: "review-authentication-pattern"
  order: 4
  name: "Review Authentication Pattern"
  action: "analyze"
  description: "Review request frequency, targeted account count, timestamps, source distribution, and related Kerberos authentication events."
  expected_result: "The authentication pattern is characterized and compared with expected behavior."
- id: "review-account-risk"
  order: 5
  name: "Review Account Risk"
  action: "analyze"
  description: "Review account privileges, group memberships, service usage, ownership, password-management practices, and business importance."
  expected_result: "Potentially high-impact accounts are identified."
- id: "review-follow-on-activity"
  order: 6
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Correlate the activity with successful authentication, lateral movement, privilege escalation, persistence, and suspicious endpoint or network behavior."
  expected_result: "Potential credential misuse and follow-on activity are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine AS-REP Activity Scope"
  action: "hunt"
  description: "Search for similar AS-REP activity, source hosts, initiating accounts, targeted accounts, and related authentication events across the environment."
  expected_result: "The prevalence and scope of the activity are determined."
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
  scenario: "asrep-roasting"
---

# AS-REP Roasting

## Purpose

This playbook provides a structured workflow for investigating suspicious Kerberos AS-REP activity associated with potential AS-REP Roasting.

AS-REP Roasting targets accounts that do not require Kerberos pre-authentication. Authentication material returned by the domain controller may then be targeted for offline credential-recovery attempts.

The objective is to determine whether the observed activity is legitimate, suspicious, or malicious and whether domain accounts may have been targeted or exposed.

## MITRE ATT&CK

| Technique | Name                                             | Relevance                                                                                                          |
| --------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | Relevant when accounts that do not require Kerberos pre-authentication are targeted for credential-access activity |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Suspicious AS-REQ activity is detected.
- Kerberos activity targets accounts that do not require pre-authentication.
- Multiple accounts are targeted from an unexpected source.
- AS-REP activity originates from an unusual host or account.
- The activity is associated with suspicious credential-access behavior.
- Subsequent authentication or lateral-movement activity is observed.
- Threat hunting identifies anomalous Kerberos authentication patterns.

## Scope

The investigation should consider:

- source host;
- source IP;
- initiating account;
- targeted account;
- domain controller;
- Kerberos request timestamps;
- request volume;
- account configuration;
- pre-authentication requirement;
- account privileges;
- group memberships;
- service usage;
- authentication history;
- endpoint activity;
- lateral movement;
- privilege escalation;
- persistence;
- network activity;
- related alerts;
- additional affected accounts and hosts.

## Kerberos Context

Kerberos authentication in Active Directory commonly uses pre-authentication as part of the authentication process.

Accounts configured without the expected pre-authentication requirement can become targets for AS-REP Roasting.

The presence of such an account or an AS-REQ event is **not by itself evidence of malicious activity**. Application behavior, administrative activity, account configuration, and authentication context must be considered.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- source IP;
- source host;
- initiating account;
- targeted account;
- domain controller;
- detection severity;
- detection reason.

Preserve the original alert context before taking response actions.

### Step 2 — Identify Target Accounts

For each targeted account, determine:

- account name;
- account type;
- whether Kerberos pre-authentication is required;
- account status;
- group memberships;
- privilege level;
- account owner;
- associated service or application;
- recent configuration changes.

Pay particular attention to privileged or high-value domain accounts.

### Step 3 — Review Source Context

Review:

- source IP;
- source hostname;
- initiating account;
- process activity;
- command-line telemetry;
- endpoint security alerts;
- internal or external network context.

Determine whether the source normally performs administrative, application, or authentication-related activities.

### Step 4 — Review Authentication Pattern

Review:

- number of targeted accounts;
- number of requests;
- request timestamps;
- source distribution;
- destination domain controllers;
- related Kerberos events.

Look for patterns that differ from the normal behavior of the initiating account or host.

### Step 5 — Review Account Risk

For targeted accounts, determine:

- privilege level;
- group memberships;
- service dependencies;
- ownership;
- normal login behavior;
- recent password changes;
- account configuration changes;
- sensitivity of accessible systems and services.

Prioritize accounts with elevated access or broad domain privileges.

### Step 6 — Review Follow-on Activity

Correlate the AS-REP activity with:

- successful authentication;
- privileged logons;
- remote access;
- lateral movement;
- privilege escalation;
- persistence;
- suspicious process execution;
- suspicious network connections.

Pay particular attention to suspicious authentication involving targeted accounts after the AS-REP activity.

### Step 7 — Determine AS-REP Activity Scope

Search the environment for:

- same source host;
- same source IP;
- same initiating account;
- same targeted accounts;
- similar AS-REQ patterns;
- other accounts without pre-authentication;
- related authentication activity.

Determine:

- number of affected accounts;
- number of affected hosts;
- number of involved domain controllers;
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

| Evidence              | Description                                      |
| --------------------- | ------------------------------------------------ |
| Alert                 | Detection source, ID, severity, timestamp        |
| Source Host           | Host initiating the activity                     |
| Source IP             | Origin of authentication requests                |
| Source Account        | Account associated with the requests             |
| Target Account        | Account targeted by AS-REP activity              |
| Domain Controller     | Domain controller processing the request         |
| Kerberos Activity     | Relevant AS-REQ and authentication events        |
| Account Configuration | Pre-authentication and account-state information |
| Account Privileges    | Privilege level and group memberships            |
| Process               | Related endpoint process activity                |
| Command Line          | Available command-line information               |
| Authentication        | Related successful and failed authentication     |
| Lateral Movement      | Related remote-access activity                   |
| Persistence           | Related persistence indicators                   |
| Network               | Related network connections                      |
| Timeline              | Correlated authentication and endpoint events    |
| Scope                 | Other affected hosts and accounts                |
| Detections            | Related security alerts                          |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the authentication pattern is consistent with normal application behavior;
- the source account and host are expected;
- the targeted account configuration is operationally justified;
- the observed activity is associated with approved administration or service operations;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- multiple accounts are targeted unexpectedly;
- the source host or account is unusual;
- the targeted accounts have unexpected or sensitive privileges;
- the activity does not match normal authentication behavior;
- account configuration is inconsistent with organizational policy;
- related authentication or endpoint activity is anomalous;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized targeting of accounts without Kerberos pre-authentication;
- confirmed credential-access behavior;
- subsequent misuse of affected accounts;
- lateral movement using affected credentials;
- privilege escalation associated with compromised accounts;
- other confirmed malicious activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the AS-REP activity was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- privileged accounts are targeted;
- multiple accounts are targeted unexpectedly;
- suspicious authentication follows the AS-REP activity;
- account compromise is suspected or confirmed;
- lateral movement is identified;
- multiple hosts or domain controllers are involved;
- the activity is associated with confirmed malicious infrastructure.

## Response Guidance

For confirmed malicious AS-REP Roasting activity:

1. Preserve Kerberos, authentication, endpoint, and network evidence.
2. Identify all targeted accounts and source systems.
3. Determine account privilege and resource access.
4. Follow the organization's credential-compromise response procedure.
5. Review authentication activity for evidence of credential reuse.
6. Investigate lateral movement and privilege escalation.
7. Review account configuration and approved password-management procedures.
8. Follow authorized account-containment and credential-remediation procedures.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, account containment, session invalidation, and configuration changes should follow approved organizational procedures.

Do not attempt to recover real account credentials during routine investigation or validation.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`

## Related Playbooks

- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/ntds-dump.md`
- `playbooks/credential-access/sam-dump.md`
- `playbooks/credential-access/kerberoasting.md`
- `playbooks/credential-access/password-spraying.md`
- `playbooks/credential-access/credential-access.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/lateral-movement/pass-the-ticket.md`
- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/lateral-movement/rdp-lateral-movement.md`
- `playbooks/lateral-movement/smb-lateral-movement.md`
- `playbooks/lateral-movement/winrm-lateral-movement.md`
- `playbooks/lateral-movement/wmi-lateral-movement.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/triage/lateral-movement-triage.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/lateral-movement-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved Kerberos authentication telemetry, Active Directory account metadata, synthetic authentication events, endpoint telemetry, and controlled identity-security scenarios.

Validation should confirm that:

- suspicious AS-REP activity can be identified;
- targeted accounts can be determined;
- account pre-authentication configuration can be assessed;
- initiating hosts and accounts can be identified;
- account privilege context can be determined;
- authentication activity can be correlated;
- subsequent credential misuse can be investigated;
- lateral movement can be identified;
- legitimate authentication behavior can be distinguished from suspicious AS-REP activity;
- escalation criteria produce consistent outcomes.

Validation should use synthetic accounts, sanitized telemetry, and isolated Active Directory environments.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not attempt credential recovery or handle real user credentials during validation.

Use synthetic accounts, sanitized authentication telemetry, and isolated laboratory environments for testing.
