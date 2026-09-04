---
id: "suspicious-login-triage"
name: "Suspicious Login Triage"
category: "triage"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-08-31T11:45:00Z"
updated_at: "2026-08-04T23:43:00Z"
description: "Investigate suspicious authentication activity and determine whether observed login behavior is legitimate, suspicious, or indicative of account compromise."
objective: "Determine the legitimacy, scope, and potential impact of suspicious login activity and identify whether additional account or incident response actions are required."
severity: "high"
mitre_attack:
  - "T1078"
triggers:
  - "Suspicious login alert"
  - "Multiple failed authentication attempts"
  - "Successful login following repeated failures"
  - "Login from an unusual source or location"
  - "Unexpected privileged account authentication"
  - "Threat hunting identifies anomalous authentication activity"
prerequisites:
  - "Access to authentication logs"
  - "Access to identity provider telemetry"
  - "Access to endpoint telemetry"
  - "Access to network or source IP telemetry"
tags:
  - "authentication"
  - "login"
  - "account"
  - "triage"
  - "identity"
  - "windows"
references:
  - "https://attack.mitre.org/techniques/T1078/"
steps:
  - id: "identify-account"
    order: 1
    name: "Identify Account"
    action: "investigate"
    description: "Identify the account associated with the suspicious authentication event."
    expected_result: "The account, account type, and privilege level are identified."
  - id: "review-authentication-event"
    order: 2
    name: "Review Authentication Event"
    action: "analyze"
    description: "Review the authentication timestamp, result, logon type, authentication method, and target resource."
    expected_result: "The authentication event is fully characterized."
  - id: "review-source-context"
    order: 3
    name: "Review Source Context"
    action: "analyze"
    description: "Review the source IP, hostname, network context, and geographic information when available."
    expected_result: "The source of the authentication attempt is identified and assessed."
  - id: "review-account-history"
    order: 4
    name: "Review Account History"
    action: "analyze"
    description: "Compare the activity with the account's normal authentication behavior and recent login history."
    expected_result: "The activity is compared with the account's expected behavior."
  - id: "review-related-events"
    order: 5
    name: "Review Related Events"
    action: "hunt"
    description: "Search for related failed logons, successful logons, MFA events, password changes, privilege changes, and endpoint activity."
    expected_result: "Related authentication and account activity is identified or ruled out."
  - id: "assess-compromise"
    order: 6
    name: "Assess Account Compromise"
    action: "analyze"
    description: "Determine whether the authentication activity is consistent with credential misuse or account compromise."
    expected_result: "The likelihood of account compromise is documented."
  - id: "determine-outcome"
    order: 7
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the authentication activity and document supporting evidence."
    expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "suspicious-login"
---

# Suspicious Login Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspicious authentication and login activity.

The objective is to determine whether observed authentication behavior is:

- expected and legitimate;
- suspicious and requiring additional investigation; or
- indicative of credential misuse or account compromise.

## MITRE ATT&CK

| Technique | Name           | Relevance                                                                                   |
| --------- | -------------- | ------------------------------------------------------------------------------------------- |
| T1078     | Valid Accounts | Relevant when legitimate credentials are suspected of being misused for unauthorized access |

Additional techniques should only be mapped when the observed authentication activity supports them.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious login detection is generated.
- Multiple failed authentication attempts are observed.
- A successful login occurs after repeated failures.
- An account authenticates from an unusual source.
- An account authenticates from an unusual geographic location.
- A privileged account performs an unexpected authentication.
- Authentication activity occurs outside expected operational patterns.
- Threat hunting identifies anomalous login behavior.

## Scope

The investigation should consider:

- username;
- account type;
- account privilege level;
- source IP;
- source hostname;
- destination host or service;
- authentication method;
- logon type;
- timestamp;
- geographic context;
- MFA status;
- previous authentication activity;
- failed authentication attempts;
- successful authentication attempts;
- password changes;
- account changes;
- endpoint activity;
- network activity;
- related detections.

## Triage Procedure

### Step 1 — Identify the Account

Determine which account is associated with the authentication event.

Collect:

- username;
- domain;
- account type;
- privilege level;
- service-account status where applicable;
- account owner;
- expected operating environment.

Determine whether the account is:

- a standard user;
- an administrator;
- a privileged account;
- a service account;
- a shared account; or
- an account not normally expected to access the target resource.

### Step 2 — Review the Authentication Event

Review the authentication details:

- timestamp;
- authentication result;
- logon type;
- authentication protocol or method;
- target host;
- target service;
- source host;
- source IP;
- session information;
- MFA result where available.

Determine whether the authentication was:

- successful;
- failed;
- denied;
- challenged;
- approved after additional authentication.

### Step 3 — Review Source Context

Investigate the source of the authentication attempt.

Collect:

- source IP address;
- source hostname;
- network segment;
- VPN status;
- proxy or gateway context;
- geographic information where available;
- device identity where available.

Pay particular attention to:

- previously unseen source addresses;
- unusual network locations;
- unexpected external access;
- source systems not normally associated with the account;
- authentication from infrastructure unrelated to the user's normal activity.

### Step 4 — Review Authentication History

Compare the observed activity with normal account behavior.

Review:

- recent successful logins;
- recent failed logins;
- normal working hours;
- normal source locations;
- normal source devices;
- normal target systems;
- previous authentication patterns.

A deviation from the normal baseline should increase investigation priority, but should not by itself establish account compromise.

### Step 5 — Review Failed Authentication Activity

Investigate surrounding failed authentication attempts.

Determine:

- number of failures;
- time period;
- source distribution;
- targeted accounts;
- targeted services;
- whether a successful authentication followed the failures.

A large volume of failures across multiple accounts may indicate password spraying or brute-force activity and should be correlated with the relevant detection and hunting workflows.

### Step 6 — Review MFA and Identity Events

When available, review:

- MFA prompts;
- MFA approvals;
- MFA failures;
- MFA method changes;
- password resets;
- password changes;
- recovery-method changes;
- account lockouts;
- identity-provider events.

Investigate unexpected authentication-factor changes or unexpected MFA approvals in conjunction with the login event.

### Step 7 — Correlate Endpoint and Network Activity

Search for endpoint and network activity associated with the account or source.

Review:

- process creation;
- remote sessions;
- network connections;
- file access;
- privilege changes;
- persistence indicators;
- lateral movement;
- other security alerts.

Determine whether suspicious authentication was followed by additional activity on the same host or account.

### Step 8 — Assess Account Compromise

Assess whether the evidence is consistent with credential misuse.

Increase concern when multiple indicators are present, such as:

- unusual source;
- unexpected device;
- abnormal time;
- suspicious authentication sequence;
- unexpected MFA behavior;
- privileged account involvement;
- successful login following suspicious failures;
- suspicious endpoint activity;
- suspicious network activity.

Do not classify an event as compromised solely because a login originated from an unusual location.

### Step 9 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious / Compromised**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence              | Description                                |
| --------------------- | ------------------------------------------ |
| Account               | Username, domain, account type, privilege  |
| Timestamp             | Authentication event time                  |
| Result                | Success, failure, denial, challenge        |
| Source IP             | Source network address                     |
| Source Host           | Device or system generating authentication |
| Destination           | Target host or service                     |
| Logon Type            | Authentication or session type             |
| Authentication Method | Protocol or identity method                |
| MFA                   | MFA result and relevant context            |
| Geo Context           | Geographic information where available     |
| Login History         | Recent authentication activity             |
| Endpoint Activity     | Related process and system events          |
| Network Activity      | Related network connections                |
| Related Alerts        | Associated detections and incidents        |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the account is authorized to access the resource;
- the source device is expected;
- the authentication pattern is consistent with normal behavior;
- MFA or other authentication controls behave as expected;
- no additional suspicious activity is identified.

Document the reason for the classification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the source is unusual;
- the authentication time is anomalous;
- the device is unexpected;
- multiple failed attempts surround a successful login;
- account activity differs significantly from the normal baseline;
- related telemetry is incomplete;
- account compromise cannot yet be ruled out.

Continue investigation and correlate additional evidence.

### Malicious / Compromised

Classify the activity as **malicious or compromised** when evidence supports unauthorized account use, such as:

- confirmed credential misuse;
- unauthorized privileged access;
- confirmed compromised credentials;
- suspicious post-authentication activity;
- confirmed attacker activity associated with the account.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the activity is legitimate or malicious.

Document:

- evidence collected;
- evidence that is unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- a privileged account is involved unexpectedly;
- suspicious authentication affects multiple systems;
- confirmed credential compromise is suspected;
- suspicious authentication is followed by lateral movement;
- suspicious authentication is followed by persistence or credential access;
- unexpected MFA activity is observed;
- the affected account has access to sensitive systems or data.

## Response Guidance

For confirmed account compromise:

1. Preserve relevant authentication and endpoint evidence.
2. Follow the organization's account-containment procedure.
3. Reset or otherwise remediate compromised credentials according to policy.
4. Review active sessions and authentication tokens where applicable.
5. Identify other systems and services accessed by the account.
6. Search for related activity across the environment.
7. Escalate to incident response.
8. Document the investigation timeline and actions taken.

Response actions involving account disablement, credential reset, session revocation, or access changes must follow organizational authorization and change-management procedures.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/lsass-access.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`

## Related Playbooks

- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-powershell-triage.md`
- `playbooks/triage/lateral-movement-triage.md`
- `playbooks/credential-access/password-spraying.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`

## Validation

The playbook should be validated against approved authentication and security event datasets.

Validation should confirm that:

- suspicious login activity can be identified;
- failed and successful authentication events can be correlated;
- unusual source context can be investigated;
- privileged-account activity receives appropriate priority;
- related endpoint and network activity can be correlated;
- benign authentication behavior can be distinguished from suspicious activity;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Account containment, credential changes, session termination, and access-control changes must follow applicable authorization, evidence-preservation, and change-management procedures.
