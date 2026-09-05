---
id: "email-compromise-triage"
name: "Email Compromise Triage"
category: "triage"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-05T13:33:00Z"
updated_at: "2026-09-05T13:33:00Z"
description: "Investigate suspected email account compromise and determine whether unauthorized access, mailbox manipulation, or malicious activity occurred."
objective: "Determine the legitimacy, scope, and impact of suspected email account compromise and identify whether containment or incident response is required."
severity: "high"
mitre_attack:
  - "T1078"
  - "T1098"
triggers:
  - "Suspected email account compromise alert"
  - "Unexpected mailbox sign-in"
  - "Suspicious mailbox rule or forwarding configuration"
  - "Unexpected password or authentication-factor change"
  - "Suspicious outbound email activity"
  - "Threat intelligence identifies compromised email infrastructure"
prerequisites:
  - "Access to email security telemetry"
  - "Access to identity provider and authentication logs"
  - "Access to mailbox audit logs"
  - "Access to endpoint and network telemetry where available"
tags:
  - "email"
  - "account-compromise"
  - "triage"
  - "identity"
  - "authentication"
  - "mailbox"
references:
  - "https://attack.mitre.org/techniques/T1078/"
  - "https://attack.mitre.org/techniques/T1098/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Compromise Alert"
  action: "investigate"
  description: "Identify the detection source, affected mailbox, account, timestamp, and alert context."
  expected_result: "The suspected compromise and affected account are clearly identified."
- id: "review-authentication"
  order: 2
  name: "Review Authentication Activity"
  action: "analyze"
  description: "Review recent successful and failed sign-ins, source locations, devices, authentication methods, and MFA activity."
  expected_result: "The account authentication history and anomalous activity are documented."
- id: "review-mailbox-activity"
  order: 3
  name: "Review Mailbox Activity"
  action: "analyze"
  description: "Review mailbox access, message activity, forwarding, inbox rules, delegates, and other mailbox changes."
  expected_result: "Suspicious or unauthorized mailbox activity is identified or ruled out."
- id: "review-account-changes"
  order: 4
  name: "Review Account Changes"
  action: "analyze"
  description: "Review password changes, MFA changes, recovery methods, application access, and other identity changes."
  expected_result: "Unauthorized account or authentication changes are identified or ruled out."
- id: "review-endpoint-activity"
  order: 5
  name: "Review Endpoint Activity"
  action: "analyze"
  description: "Review endpoint and browser activity associated with suspicious authentication or mailbox access."
  expected_result: "Relevant endpoint activity is correlated with the suspected compromise."
- id: "review-outbound-mail"
  order: 6
  name: "Review Outbound Email Activity"
  action: "analyze"
  description: "Review recent sent messages, recipients, message volume, and suspicious content associated with the affected account."
  expected_result: "Potential malicious outbound email activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Compromise Scope"
  action: "hunt"
  description: "Search for related authentication, mailbox, account, and endpoint activity across the environment."
  expected_result: "The scope of the suspected compromise is determined."
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
  scenario: "email-compromise"
---

# Email Compromise Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspected email account compromise.

The objective is to determine whether unauthorized access or mailbox manipulation occurred and whether the account was used for additional malicious activity.

## MITRE ATT&CK

| Technique | Name                 | Relevance                                                                                                        |
| --------- | -------------------- | ---------------------------------------------------------------------------------------------------------------- |
| T1078     | Valid Accounts       | Relevant when legitimate account credentials are used for unauthorized access                                    |
| T1098     | Account Manipulation | Relevant when account settings, authentication factors, or access permissions are modified without authorization |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An email account compromise detection is generated.
- An unexpected mailbox sign-in is observed.
- A mailbox rule or forwarding configuration is unexpectedly created or changed.
- A password or authentication-factor change occurs unexpectedly.
- Suspicious outbound email activity is detected.
- An account performs unusual mailbox access.
- Threat intelligence indicates that account credentials or mailbox access may be compromised.

## Scope

The investigation should consider:

- affected account;
- mailbox;
- source IP;
- source device;
- geographic context;
- authentication method;
- MFA activity;
- sign-in history;
- password changes;
- authentication-factor changes;
- mailbox rules;
- forwarding;
- delegates;
- sent messages;
- deleted messages;
- message access;
- application access;
- endpoint activity;
- related accounts;
- related alerts.

## Triage Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected account;
- mailbox;
- alert severity;
- detection reason.

Preserve the original alert context before making account or mailbox changes.

### Step 2 — Review Authentication Activity

Review:

- successful sign-ins;
- failed sign-ins;
- source IP addresses;
- source devices;
- geographic context;
- sign-in timestamps;
- authentication methods;
- MFA results.

Compare the activity with the account's normal authentication behavior.

Pay particular attention to:

- previously unseen devices;
- unusual source locations;
- unexpected external access;
- authentication outside expected operating periods;
- suspicious MFA activity.

### Step 3 — Review Mailbox Activity

Review:

- mailbox access;
- inbox rules;
- forwarding rules;
- delegates;
- permissions;
- message creation;
- message deletion;
- unusual folder activity;
- mailbox configuration changes.

Investigate unexpected rules or forwarding destinations, especially when they redirect messages outside the organization's expected environment.

### Step 4 — Review Account and Authentication Changes

Review:

- password changes;
- password resets;
- MFA enrollment changes;
- MFA method changes;
- recovery-method changes;
- application registrations;
- application access;
- permission changes.

Determine whether these changes were expected and authorized.

### Step 5 — Review Outbound Email Activity

Review recently sent messages for:

- unusual recipients;
- unusual message volume;
- suspicious links;
- suspicious attachments;
- credential requests;
- financial requests;
- impersonation;
- messages inconsistent with normal account activity.

Determine whether the account may have been used to conduct phishing, business email compromise, or other malicious activity.

### Step 6 — Review Endpoint and Browser Activity

When relevant, investigate:

- browser activity;
- authentication activity;
- process execution;
- downloaded files;
- suspicious extensions;
- endpoint alerts;
- network connections.

Correlate endpoint events with suspicious sign-ins and mailbox access.

### Step 7 — Determine Compromise Scope

Search across the environment for:

- the same source IP;
- the same device;
- related authentication activity;
- other affected accounts;
- similar mailbox rules;
- shared forwarding destinations;
- suspicious outbound messages;
- related endpoint activity.

Determine:

- number of affected accounts;
- number of affected mailboxes;
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

| Evidence        | Description                                          |
| --------------- | ---------------------------------------------------- |
| Alert           | Detection source, ID, severity, timestamp            |
| Account         | User account and mailbox                             |
| Authentication  | Sign-ins, failures, methods, MFA                     |
| Source          | IP address, device, geographic context               |
| Mailbox         | Access and configuration activity                    |
| Rules           | Inbox and forwarding rules                           |
| Delegates       | Mailbox delegation and permissions                   |
| Account Changes | Password, MFA, recovery, and access changes          |
| Outbound Mail   | Sent messages and recipients                         |
| Endpoint        | Related browser, process, file, and network activity |
| Timeline        | Relevant authentication and mailbox timestamps       |
| Scope           | Other affected accounts and mailboxes                |
| Detections      | Related security alerts                              |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the sign-in is expected;
- the source device is authorized;
- mailbox changes are documented and approved;
- account changes are legitimate;
- outbound email activity is consistent with normal behavior;
- no additional suspicious activity is identified.

Document the business or operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the source or device is unusual;
- mailbox configuration changes are unexpected;
- authentication behavior is abnormal;
- account changes cannot be immediately attributed;
- suspicious outbound email activity is observed;
- additional investigation is required.

Continue investigation and correlate additional evidence.

### Compromised

Classify the account as **compromised** when sufficient evidence indicates:

- unauthorized account access;
- confirmed credential misuse;
- unauthorized mailbox manipulation;
- unauthorized forwarding or delegation;
- suspicious outbound mail originating from the account;
- confirmed attacker activity associated with the mailbox.

Escalate to the appropriate account-compromise or incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the account was compromised.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- account compromise is confirmed;
- a privileged account is affected;
- suspicious forwarding or mailbox rules are identified;
- credentials or authentication factors may have been compromised;
- malicious outbound email was sent;
- multiple accounts or mailboxes are affected;
- sensitive information may have been accessed.

## Response Guidance

For confirmed email account compromise:

1. Preserve authentication, mailbox, endpoint, and message evidence.
2. Follow the organization's account-containment procedure.
3. Review and remediate unauthorized mailbox rules and forwarding.
4. Review active sessions and authentication tokens where applicable.
5. Reset or otherwise remediate compromised credentials according to policy.
6. Review MFA and recovery settings.
7. Identify affected recipients and related accounts.
8. Search for additional compromise indicators across the environment.
9. Escalate to incident response.
10. Document the investigation timeline and actions taken.

Do not delete relevant mailbox or authentication evidence before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`

## Related Playbooks

- `playbooks/triage/phishing-alert-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/triage/account-compromise-triage.md`
- `playbooks/initial-access/phishing.md`
- `playbooks/initial-access/application-consent-abuse.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`

## Validation

The playbook should be validated against approved identity, mailbox, endpoint, and email-security datasets.

Validation should confirm that:

- suspicious authentication can be identified;
- mailbox activity can be investigated;
- unauthorized forwarding and rules can be identified;
- account and MFA changes can be correlated;
- suspicious outbound email activity can be investigated;
- affected accounts and mailboxes can be identified;
- legitimate administrative activity can be distinguished from compromise;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Account containment, credential changes, mailbox configuration changes, and session termination must follow applicable authorization, evidence-preservation, privacy, and change-management procedures.
