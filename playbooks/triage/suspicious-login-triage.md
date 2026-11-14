---
id: "suspicious-login-triage"
name: "Suspicious Login Triage"
category: "triage"
status: "active"
version: "1.0.3"
author: "Secwexen"
created_at: "2026-08-31T11:45:00Z"
updated_at: "2026-11-14T08:34:00Z"
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
    description: "Identify the account associated with the suspicious authentication event, including its account type, owner, privilege level, and expected access context."
    expected_result: "The affected account, account type, privilege level, and ownership are identified."
  - id: "review-authentication-event"
    order: 2
    name: "Review Authentication Event"
    action: "analyze"
    description: "Review the authentication timestamp, result, logon type, authentication method, target resource, and associated session information."
    expected_result: "The authentication event and its relevant details are fully characterized."
  - id: "review-source-context"
    order: 3
    name: "Review Source Context"
    action: "analyze"
    description: "Review the source IP, hostname, network context, device identity, VPN or proxy usage, and geographic information where available."
    expected_result: "The authentication source and its consistency with expected account activity are assessed."
  - id: "review-account-history"
    order: 4
    name: "Review Account History"
    action: "analyze"
    description: "Compare the activity with the account's normal authentication behavior, previous login history, expected devices, locations, and operational patterns."
    expected_result: "The observed authentication activity is compared with the account's expected behavior."
  - id: "review-related-events"
    order: 5
    name: "Review Related Events"
    action: "hunt"
    description: "Search for related failed logons, successful logons, MFA events, password changes, privilege changes, session activity, and associated endpoint or network events."
    expected_result: "Related authentication, identity, endpoint, and network activity is identified or reasonably ruled out."
  - id: "assess-compromise"
    order: 6
    name: "Assess Account Compromise"
    action: "analyze"
    description: "Determine whether the authentication activity is consistent with credential misuse, unauthorized account access, or other malicious authentication behavior."
    expected_result: "The likelihood and available evidence of account compromise are documented."
  - id: "determine-scope"
    order: 7
    name: "Determine Investigation Scope"
    action: "hunt"
    description: "Search for related authentication activity, source addresses, devices, target systems, accounts, and security indicators across the environment."
    expected_result: "The scope of the suspicious authentication activity, including potentially affected accounts, hosts, and services, is identified or reasonably ruled out."
  - id: "determine-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the authentication activity, document supporting evidence, establish the account compromise status, and record affected resources and remaining investigative or escalation requirements."
    expected_result: "The suspicious login investigation receives a documented outcome with its classification, compromise assessment, scope, and follow-up requirements recorded."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "suspicious-login"
---

# Suspicious Login Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspicious authentication and login activity.

It guides analysts in evaluating account context, authentication methods, source devices, network origins, and deviations from established login patterns.

The investigation aims to determine whether unauthorized access occurred, identify affected accounts and resources, assess potential compromise, and establish whether containment or incident response is required.

## MITRE ATT&CK

| Technique | Name           | Relevance                                                                                   |
| --------- | -------------- | ------------------------------------------------------------------------------------------- |
| T1078     | Valid Accounts | Relevant when legitimate credentials are suspected of being misused for unauthorized access |

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

## Investigation Procedure

### Step 1 - Identify Account

Identify the account associated with the suspicious authentication event.

Collect:

- username;
- domain;
- account type;
- privilege level;
- service-account status where applicable;
- account owner;
- expected operating environment;
- expected access permissions.

Determine whether the account is:

- a standard user;
- an administrator;
- a privileged account;
- a service account;
- a shared account;
- an account not normally expected to access the target resource.

Preserve the original detection context and associated authentication evidence.

### Step 2 - Review Authentication Event

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

Correlate authentication events with relevant identity-provider and directory-service telemetry.

Determine whether the authentication sequence indicates unusual or potentially unauthorized access.

### Step 3 - Review Source Context

Investigate the source of the authentication attempt.

Collect:

- source IP address;
- source hostname;
- source device;
- network segment;
- VPN status;
- proxy or gateway context;
- geographic information where available;
- device identity where available;
- network reputation where available.

Pay particular attention to:

- previously unseen source addresses;
- unusual network locations;
- unexpected external access;
- source systems not normally associated with the account;
- authentication from suspicious infrastructure;
- unexpected remote-access activity;
- abnormal device characteristics.

Determine whether the source context is consistent with the account's normal access patterns.

### Step 4 - Review Account History

Compare the observed activity with normal account behavior.

Review:

- recent successful logins;
- recent failed logins;
- normal working hours;
- normal source locations;
- normal source devices;
- normal target systems;
- previous authentication patterns;
- typical authentication methods;
- expected remote-access behavior.

Identify deviations from the established account baseline.

A deviation from normal behavior should increase investigation priority but should not independently establish account compromise.

### Step 5 - Review Related Events

Search for related authentication, identity, endpoint, and network activity.

Review:

- failed authentication attempts;
- successful authentication attempts;
- MFA prompts;
- MFA approvals;
- MFA failures;
- MFA method changes;
- password resets;
- password changes;
- recovery-method changes;
- account lockouts;
- identity-provider events;
- session creation and termination;
- process creation;
- remote sessions;
- network connections;
- file access;
- privilege changes;
- persistence indicators;
- lateral movement;
- other security alerts.

Determine:

- number of failed authentication attempts;
- relevant time period;
- source distribution;
- targeted accounts;
- targeted services;
- whether a successful authentication followed suspicious failures;
- whether unexpected MFA or identity changes occurred;
- whether suspicious authentication was followed by additional endpoint or network activity.

A large volume of authentication failures across multiple accounts may indicate password spraying or brute-force activity. Correlate these findings with the relevant detection and hunting workflows.

### Step 6 - Assess Account Compromise

Assess whether the available evidence is consistent with credential misuse or unauthorized account access.

Increase investigation priority when multiple indicators are present, such as:

- unusual source;
- unexpected device;
- abnormal authentication time;
- suspicious authentication sequence;
- unexpected MFA behavior;
- privileged account involvement;
- successful login following suspicious failures;
- unauthorized authentication;
- suspicious post-authentication activity;
- suspicious endpoint activity;
- suspicious network activity.

Determine whether:

- credentials may have been exposed;
- unauthorized authentication occurred;
- an unauthorized session was established;
- privileged access was obtained;
- additional account activity followed authentication;
- other systems or services may have been accessed.

Do not classify an event as compromised solely because a login originated from an unusual location.

Document the evidence supporting the compromise assessment and distinguish confirmed unauthorized access from suspected credential misuse.

### Step 7 - Determine Investigation Scope

Search across the environment for related authentication and account activity.

Investigate:

- the affected account;
- associated source IP addresses;
- associated devices;
- related authentication events;
- repeated failed authentication attempts;
- successful authentication following failures;
- related privileged account activity;
- additional target systems;
- accessed services;
- related security alerts;
- associated endpoint activity;
- related network indicators.

Determine:

- number of affected accounts;
- number of affected hosts;
- number of affected services;
- number of suspicious source addresses;
- number of successful suspicious authentications;
- earliest observed activity;
- most recent observed activity;
- whether unauthorized access is ongoing;
- whether additional accounts may be affected;
- whether the activity is isolated or part of a broader attack.

Document the identified scope and any telemetry limitations that prevent the full extent of the activity from being established.

### Step 8 - Determine Investigation Outcome

Classify the authentication activity as:

- **Benign**
- **Suspicious**
- **Malicious**
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

### Malicious

Classify the activity as **malicious** when sufficient evidence supports unauthorized account use, such as:

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
- additional telemetry required;
- unverified source device and network context;
- unresolved session establishment and post-authentication activity.

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
