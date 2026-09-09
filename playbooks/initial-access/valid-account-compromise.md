---
id: "valid-account-compromise"
name: "Valid Account Compromise"
category: "initial-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-09T17:15:00Z"
updated_at: "2026-09-09T17:15:00Z"
description: "Investigate suspected unauthorized use of valid credentials to access systems, applications, or cloud resources."
objective: "Determine whether valid credentials were used without authorization, identify affected accounts and systems, establish scope, and determine whether containment or incident response is required."
severity: "high"
mitre_attack:
  - "T1078"
triggers:
  - "Suspicious successful authentication"
  - "Unexpected login from an unfamiliar source"
  - "Authentication following credential exposure"
  - "Unusual account activity"
  - "Unexpected access to sensitive systems"
  - "Threat intelligence identifies compromised credentials"
prerequisites:
  - "Access to identity and authentication logs"
  - "Access to endpoint and network telemetry"
  - "Access to account and privilege information"
  - "Access to cloud or application audit logs where available"
tags:
  - "valid-accounts"
  - "account-compromise"
  - "initial-access"
  - "authentication"
  - "identity"
  - "credential-abuse"
references:
  - "https://attack.mitre.org/techniques/T1078/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Authentication Alert"
  action: "investigate"
  description: "Identify the detection source, affected account, source system, destination, timestamp, and alert context."
  expected_result: "The suspicious authentication event and affected account are identified."
- id: "review-authentication"
  order: 2
  name: "Review Authentication Context"
  action: "analyze"
  description: "Review sign-in method, source IP, device, location, authentication protocol, and MFA activity."
  expected_result: "The authentication context and anomalies are documented."
- id: "review-account-context"
  order: 3
  name: "Review Account Context"
  action: "analyze"
  description: "Review account type, privileges, normal usage patterns, group membership, and expected access."
  expected_result: "The account's normal and sensitive access context is understood."
- id: "review-target-activity"
  order: 4
  name: "Review Target Activity"
  action: "analyze"
  description: "Review activity performed after authentication, including resource access, process execution, mailbox activity, and configuration changes."
  expected_result: "Post-authentication activity is identified or ruled out."
- id: "review-endpoint-network"
  order: 5
  name: "Review Endpoint and Network Activity"
  action: "analyze"
  description: "Correlate endpoint processes, network connections, browser activity, and other telemetry associated with the account activity."
  expected_result: "Related endpoint and network activity is documented."
- id: "review-account-changes"
  order: 6
  name: "Review Account Changes"
  action: "investigate"
  description: "Review password changes, MFA changes, group membership changes, application access, and other account modifications."
  expected_result: "Unauthorized account changes are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Compromise Scope"
  action: "hunt"
  description: "Search for the same account, source infrastructure, authentication pattern, and related activity across the environment."
  expected_result: "Affected systems, applications, and accounts are identified."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the activity and document the evidence supporting the final assessment."
  expected_result: "The authentication event receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "valid-account-compromise"
---

# Valid Account Compromise

## Purpose

This playbook provides a structured workflow for investigating suspected unauthorized use of valid credentials.

The objective is to determine whether legitimate credentials were used by an unauthorized party, identify the affected systems and resources, establish scope, and determine whether incident response is required.

## MITRE ATT&CK

| Technique | Name           | Relevance                                                                                  |
| --------- | -------------- | ------------------------------------------------------------------------------------------ |
| T1078     | Valid Accounts | Relevant when an adversary uses legitimate account credentials to gain unauthorized access |

Additional ATT&CK sub-techniques should only be mapped when supported by the observed account and authentication behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious successful authentication is detected.
- An account logs in from an unfamiliar source or device.
- Authentication follows known or suspected credential exposure.
- An account performs unusual or high-risk activity.
- A user accesses systems they do not normally access.
- Threat intelligence indicates that credentials may be compromised.
- Multiple authentication events suggest credential misuse.

## Scope

The investigation should consider:

- affected account;
- account type;
- account privileges;
- source IP;
- source device;
- destination system;
- application;
- geographic context;
- authentication method;
- authentication protocol;
- MFA activity;
- sign-in timestamps;
- password changes;
- account changes;
- accessed resources;
- endpoint activity;
- network activity;
- related accounts;
- related alerts.

## Investigation Procedure

### Step 1 — Identify the Authentication Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected account;
- source IP;
- source device;
- destination;
- suspected reason for detection;
- alert severity.

Preserve the original authentication and alert context before making account changes.

### Step 2 — Review Authentication Context

Review:

- successful sign-ins;
- failed sign-ins;
- source addresses;
- source devices;
- geographic location;
- authentication method;
- authentication protocol;
- MFA results;
- session information where available.

Compare the activity with the account's normal authentication pattern.

Pay particular attention to:

- previously unseen devices;
- unusual source locations;
- impossible or highly unusual travel patterns;
- authentication outside normal operating periods;
- repeated failed attempts followed by success;
- abnormal MFA activity.

### Step 3 — Review Account Context

Determine:

- account type;
- account owner;
- normal access pattern;
- group membership;
- privileges;
- administrative roles;
- service-account status;
- systems normally accessed.

Assess whether the authentication was consistent with the account's normal responsibilities.

### Step 4 — Review Target Activity

Review activity performed after successful authentication, including:

- resource access;
- file access;
- mailbox activity;
- administrative actions;
- process execution;
- remote access;
- application activity;
- configuration changes.

Determine whether the account performed actions inconsistent with its normal behavior.

### Step 5 — Review Endpoint and Network Activity

Correlate the authentication event with:

- process creation;
- browser activity;
- downloaded files;
- endpoint detections;
- network connections;
- remote service activity;
- DNS activity.

Determine whether the account activity is associated with a compromised endpoint or suspicious network infrastructure.

### Step 6 — Review Account Changes

Review:

- password changes;
- password resets;
- MFA enrollment;
- MFA method changes;
- recovery-method changes;
- group membership changes;
- privilege changes;
- application consent;
- new sessions or access tokens where available.

Determine whether the account was modified as part of the suspected compromise.

### Step 7 — Determine Compromise Scope

Search across the environment for:

- the same account;
- the same source IP;
- the same device;
- the same authentication pattern;
- related applications;
- related destination systems;
- related account changes.

Determine:

- number of affected systems;
- number of affected applications;
- number of affected accounts;
- first observed activity;
- most recent observed activity;
- whether unauthorized access is ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Compromised**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence        | Description                                           |
| --------------- | ----------------------------------------------------- |
| Alert           | Detection source, ID, severity, timestamp             |
| Account         | User or service account                               |
| Account Type    | Standard, privileged, service, or other account type  |
| Source          | IP address, device, and geographic context            |
| Authentication  | Method, protocol, success/failure, MFA                |
| Destination     | Accessed system or application                        |
| Activity        | Actions performed after authentication                |
| Endpoint        | Related process, file, browser, and security activity |
| Network         | Related network connections                           |
| Account Changes | Password, MFA, group, privilege, and access changes   |
| Timeline        | Relevant authentication and activity timestamps       |
| Scope           | Other affected systems and accounts                   |
| Detections      | Related security alerts                               |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the authentication source is authorized;
- the device is expected;
- the location is consistent with normal activity;
- the account activity matches expected behavior;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the source device or location is unusual;
- authentication behavior is abnormal;
- the account accesses unexpected systems;
- follow-on activity is unusual;
- the activity cannot yet be attributed to compromise;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Compromised

Classify the account as **compromised** when sufficient evidence indicates:

- unauthorized use of valid credentials;
- confirmed credential misuse;
- unauthorized access to systems or applications;
- suspicious activity clearly associated with the account;
- account activity consistent with a broader confirmed compromise.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the account was compromised.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- compromise is confirmed;
- a privileged account is affected;
- sensitive or critical systems were accessed;
- multiple systems are affected;
- credentials may have been exposed;
- suspicious persistence or lateral movement follows the authentication;
- malicious endpoint or network activity is identified.

## Response Guidance

For confirmed valid-account compromise:

1. Preserve authentication, endpoint, and network evidence.
2. Identify all systems and applications accessed by the account.
3. Follow the organization's account-containment procedure.
4. Review and remediate compromised credentials according to policy.
5. Review MFA and recovery settings.
6. Review active sessions and access tokens where applicable.
7. Search for additional activity associated with the account.
8. Investigate persistence, lateral movement, and other follow-on activity.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Do not disable accounts, terminate sessions, or modify authentication settings before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/lsass-access.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`

## Related Playbooks

- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/triage/email-compromise-triage.md`
- `playbooks/initial-access/phishing.md`
- `playbooks/initial-access/application-consent-abuse.md`
- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/lateral-movement/pass-the-ticket.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`

## Validation

The playbook should be validated against approved identity, authentication, endpoint, and cloud-audit datasets.

Validation should confirm that:

- suspicious authentication can be identified;
- account and device context can be investigated;
- MFA and authentication activity can be correlated;
- post-authentication activity can be identified;
- account changes can be investigated;
- affected systems and accounts can be determined;
- legitimate authentication can be distinguished from account compromise;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Account containment, credential changes, session termination, and access revocation must follow applicable authorization, evidence-preservation, privacy, and change-management procedures.
