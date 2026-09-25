---
id: "account-compromise-response"
name: "Account Compromise Response"
category: "response"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-25T18:50:00Z"
updated_at: "2026-09-25T18:50:00Z"
description: "Account compromise occurs when an unauthorized party gains access to a legitimate user account or abuses compromised credentials to access organizational resources."
objective: "Identify, investigate, contain, and remediate confirmed or suspected account compromise and determine whether compromised credentials were used to access additional systems or services."
severity: "high"
mitre_attack:
  - "T1078"
  - "T1110"
triggers:
  - "Suspicious authentication activity associated with a user account"
  - "Confirmed or suspected credential exposure"
  - "Unexpected successful authentication from an unusual source"
  - "Multiple failed authentication attempts followed by a successful login"
  - "Unexpected remote access or privileged account usage"
  - "Identity provider, VPN, or endpoint detection indicating account compromise"
  - "Threat hunting identifies anomalous account activity"
prerequisites:
  - "Access to authentication and identity telemetry"
  - "Access to identity provider or directory services"
  - "Access to VPN and remote-access telemetry where applicable"
  - "Access to endpoint and process telemetry"
  - "Authorized access to account-management and session-control capabilities"
tags:
  - "account-compromise"
  - "valid-accounts"
  - "credential-access"
  - "authentication"
  - "incident-response"
  - "identity-security"
  - "windows"
  - "mitre-attack"
references:
  - "https://attack.mitre.org/techniques/T1078/"
  - "https://attack.mitre.org/techniques/T1110/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Account Compromise Alert"
  action: "investigate"
  description: "Identify the detection source, affected account, host or service, authentication method, timestamp, source, and initial alert context."
  expected_result: "The suspected account compromise event and affected identity are identified."
- id: "validate-account-activity"
  order: 2
  name: "Validate Account Activity"
  action: "analyze"
  description: "Determine whether the observed authentication and account activity is consistent with the user's expected behavior, access pattern, location, device, and operational role."
  expected_result: "The legitimacy of the observed account activity is assessed."
- id: "review-authentication-events"
  order: 3
  name: "Review Authentication Events"
  action: "analyze"
  description: "Review successful and failed authentication events, logon types, source addresses, devices, timestamps, authentication methods, and related identity-provider activity."
  expected_result: "A complete authentication timeline is established."
- id: "review-post-authentication-activity"
  order: 4
  name: "Review Post-Authentication Activity"
  action: "analyze"
  description: "Correlate the account with endpoint, network, application, and administrative activity following successful authentication."
  expected_result: "Potential actions performed using the affected account are identified."
- id: "determine-scope"
  order: 5
  name: "Determine Compromise Scope"
  action: "hunt"
  description: "Search for additional hosts, applications, services, sessions, source addresses, authentication methods, and accounts associated with the compromised credentials."
  expected_result: "The scope and potential lateral impact of the account compromise are determined."
- id: "contain-account"
  order: 6
  name: "Contain Account Access"
  action: "contain"
  description: "Apply approved account-containment controls such as credential reset, session revocation, token invalidation, access restriction, or temporary account suspension based on the organization's incident-response procedures."
  expected_result: "Unauthorized access is contained and active sessions or authentication paths are addressed."
- id: "eradicate-and-recover"
  order: 7
  name: "Eradicate and Recover"
  action: "respond"
  description: "Remove unauthorized access mechanisms, restore the account to a trusted state, verify authentication controls, and address the underlying source of credential exposure or compromise."
  expected_result: "The affected account is restored to an authorized and controlled state."
- id: "determine-outcome"
  order: 8
  name: "Determine Response Outcome"
  action: "document"
  description: "Classify the incident, document evidence and response actions, identify affected resources, and record remaining risks or follow-up requirements."
  expected_result: "The account compromise receives a documented response outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "account-compromise-response"
---

# Account Compromise Response

## Purpose

This playbook provides a structured response workflow for suspected or confirmed compromise of user, administrative, service, or cloud identities.

Account compromise may allow an unauthorized party to use legitimate credentials to access systems, applications, remote services, or other protected resources. MITRE ATT&CK maps abuse of legitimate credentials to **T1078 – Valid Accounts** and credential-guessing activity to **T1110 – Brute Force**.

The objective is to establish whether the account was compromised, determine the extent of unauthorized access, contain active access paths, restore the account to a trusted state, and identify related compromise activity.

## MITRE ATT&CK

| Technique | Name           | Relevance                                                                                                     |
| --------- | -------------- | ------------------------------------------------------------------------------------------------------------- |
| T1078     | Valid Accounts | Relevant when compromised or otherwise unauthorized credentials are used to access organizational resources   |
| T1110     | Brute Force    | Relevant when repeated credential-guessing or related authentication attacks contribute to account compromise |

Additional ATT&CK techniques should only be mapped when supported by observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Suspicious authentication activity is associated with a user or administrative account.
- A credential is confirmed or suspected to have been exposed.
- A successful login originates from an unexpected source, device, or access location.
- Multiple authentication failures are followed by a successful authentication.
- A privileged account is used outside its expected operational context.
- Identity provider, VPN, EDR, SIEM, or other security telemetry indicates possible account compromise.
- Threat hunting identifies anomalous account activity.

## Scope

The investigation should consider:

- affected account;
- account type;
- account privilege level;
- authentication method;
- authentication timestamp;
- source IP address;
- source device;
- destination system;
- logon type;
- identity provider;
- VPN or remote-access service;
- MFA activity;
- active sessions;
- access tokens;
- endpoint activity;
- process activity;
- administrative actions;
- application activity;
- related accounts;
- related hosts;
- related alerts.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected account;
- account type;
- affected host or service;
- source IP address;
- authentication method;
- detection reason.

Preserve the original alert context before account-containment actions are performed.

### Step 2 — Validate Account Activity

Determine whether the observed activity is consistent with the account's expected behavior.

Review:

- normal working hours;
- expected source locations;
- known devices;
- expected applications;
- typical authentication methods;
- account role;
- administrative responsibilities;
- recent operational changes.

A single unusual login should not automatically be treated as confirmed compromise. Correlate multiple authentication and endpoint signals before assigning the final classification.

### Step 3 — Review Authentication Events

Review:

- successful authentication events;
- failed authentication events;
- logon types;
- source IP addresses;
- destination systems;
- authentication protocols;
- MFA events;
- identity-provider events;
- VPN events;
- remote-access activity;
- password-reset activity;
- session creation and termination.

Construct a timeline covering the period immediately before and after the suspected compromise.

MITRE's current Valid Accounts detection strategy includes anomalous logon patterns, abnormal logon types, and inconsistent geographic or time-based activity as detection signals.

### Step 4 — Review Post-Authentication Activity

Correlate successful authentication with:

- process creation;
- endpoint activity;
- administrative actions;
- remote-service usage;
- application access;
- file access;
- security configuration changes;
- account-management changes;
- privilege changes;
- additional authentication events.

Determine what actions were performed using the affected identity after authentication.

### Step 5 — Determine Compromise Scope

Search the environment for:

- the affected account;
- associated source IP addresses;
- associated devices;
- successful and failed authentications;
- remote sessions;
- administrative actions;
- related accounts;
- related hosts;
- repeated credential failures;
- unusual application access.

Determine:

- number of affected hosts;
- number of affected services;
- number of affected applications;
- number of affected accounts;
- earliest suspicious activity;
- latest suspicious activity;
- whether unauthorized access is ongoing.

### Step 6 — Contain Account Access

Based on incident severity and organizational procedures, consider:

- resetting the affected credentials;
- revoking active sessions;
- invalidating authentication tokens where supported;
- temporarily restricting or suspending the account;
- removing unauthorized authentication methods;
- reviewing and re-establishing MFA;
- restricting suspicious source access;
- protecting dependent privileged credentials.

Containment actions should be coordinated with identity-management and incident-response procedures to avoid unnecessary operational impact.

### Step 7 — Eradicate and Recover

Determine and address the likely source of compromise.

Review for:

- exposed credentials;
- phishing-related credential theft;
- credential dumping;
- password spraying;
- brute-force activity;
- malware-associated credential theft;
- unauthorized authentication factors;
- persistence mechanisms;
- compromised endpoints.

Restore the affected account to a trusted state and verify:

- credentials were successfully reset;
- active sessions were addressed;
- MFA configuration is trusted;
- unauthorized account changes were removed;
- access permissions remain appropriate;
- dependent systems accept the restored authentication state.

### Step 8 — Determine Response Outcome

Classify the incident as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification and record all containment, eradication, recovery, and follow-up actions.

## Evidence to Collect

| Evidence                | Description                                      |
| ----------------------- | ------------------------------------------------ |
| Alert                   | Detection source, ID, severity, timestamp        |
| Account                 | Username, account type, privilege level          |
| Authentication          | Successful and failed authentication events      |
| Source                  | Source IP, device, geographic or network context |
| Destination             | Accessed hosts, services, and applications       |
| Logon Type              | Authentication or remote-access type             |
| MFA                     | MFA prompts, approvals, failures, and changes    |
| Sessions                | Active and historical sessions                   |
| Identity Provider       | Directory or cloud identity telemetry            |
| VPN                     | Remote-access authentication and session data    |
| Endpoint                | Related process and endpoint telemetry           |
| Administrative Activity | Configuration, privilege, or account changes     |
| Timeline                | Authentication and post-authentication activity  |
| Scope                   | Other affected hosts, accounts, and services     |
| Detections              | Related SIEM, EDR, identity, and security alerts |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the account activity is verified as authorized;
- the source device and authentication context are expected;
- administrative or operational activity is documented;
- no evidence of unauthorized access is identified;
- no suspicious post-authentication activity is observed.

Document the operational justification before closing the incident.

### Suspicious

Classify the activity as **suspicious** when:

- authentication behavior is anomalous;
- the account activity cannot immediately be attributed to the legitimate user;
- unusual source or device activity is observed;
- authentication failures indicate possible credential attacks;
- post-authentication activity requires additional investigation;
- compromise cannot yet be confirmed.

Continue investigation and maintain appropriate containment controls.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized access to the affected account;
- confirmed credential compromise;
- unauthorized use of valid credentials;
- confirmed brute-force or password-spraying activity resulting in unauthorized access;
- unauthorized administrative or privileged actions;
- broader compromise associated with the affected identity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to establish whether the account activity was authorized or unauthorized.

Document:

- evidence collected;
- evidence unavailable;
- telemetry limitations;
- additional data required;
- containment status.

## Escalation

Escalate the incident when:

- account compromise is confirmed;
- privileged credentials are affected;
- multiple accounts or systems are involved;
- unauthorized administrative actions occurred;
- persistence is identified;
- credential access activity is observed;
- lateral movement is identified;
- command-and-control activity is detected;
- the source of credential compromise remains active.

## Response Guidance

For confirmed account compromise:

1. Preserve authentication, endpoint, identity-provider, VPN, and application telemetry.
2. Identify all affected accounts, systems, sessions, and services.
3. Follow the organization's identity-containment procedure.
4. Reset or rotate compromised credentials using approved processes.
5. Revoke active sessions and invalidate applicable authentication tokens.
6. Verify MFA configuration and remove unauthorized authentication methods.
7. Investigate the source of credential exposure or theft.
8. Review privileged access and permissions associated with the account.
9. Search for additional use of the compromised credentials across the environment.
10. Investigate persistence, credential access, lateral movement, and additional compromise activity.
11. Restore the account only after required containment and validation actions are complete.
12. Document the incident timeline, evidence, response actions, and recovery state.

Do not delete authentication evidence or immediately remove compromised-account artifacts before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`

## Related Playbooks

- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/credential-access/password-spraying.md`

## Validation

The playbook should be validated against controlled authentication datasets, identity-provider events, VPN telemetry, Windows authentication logs, endpoint telemetry, and authorized account-compromise laboratory scenarios.

Validation should confirm that:

- suspicious authentication activity can be identified;
- legitimate account activity can be distinguished from anomalous behavior;
- authentication timelines can be reconstructed;
- post-authentication activity can be correlated;
- compromised accounts can be scoped across the environment;
- containment actions are documented and reproducible;
- credential and session recovery can be validated;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, incident response, security validation, controlled laboratory environments, and authorized testing only.

Account-containment, credential-reset, session-revocation, and access-restriction actions should be performed only by authorized personnel and according to approved organizational procedures. Avoid destructive remediation until required forensic and authentication evidence has been preserved.
