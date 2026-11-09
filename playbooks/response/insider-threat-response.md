---
id: "insider-threat-response"
name: "Insider Threat Response"
category: "response"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-11-09T14:31:00Z"
updated_at: "2026-11-09T14:31:00Z"
description: "Insider threats occur when employees, contractors, administrators, or other trusted individuals misuse authorized access, intentionally or unintentionally exposing organizational systems, sensitive information, or business operations to security risks."
objective: "Identify, investigate, contain, and mitigate insider threats, determine affected users, accounts, systems, and information assets, preserve relevant evidence, and prevent further unauthorized or harmful activity."
severity: "high"
mitre_attack:
  - "T1078"
  - "T1098"
  - "T1213"
  - "T1530"
  - "T1567.002"
triggers:
  - "Unusual user account activity or access patterns"
  - "Unauthorized access to sensitive organizational information"
  - "Abnormal data downloads, transfers, or exfiltration activity"
  - "Suspicious privilege escalation or permission changes"
  - "Unauthorized use of privileged accounts"
  - "DLP, UEBA, EDR, or SIEM insider-threat alerts"
  - "Unexpected deletion, modification, or disclosure of organizational data"
  - "Reports of potential data theft or policy violations"
prerequisites:
  - "Access to identity and access management logs"
  - "Access to SIEM, EDR, DLP, and security monitoring telemetry"
  - "Access to cloud audit and application activity logs"
  - "Access to privileged access management records"
  - "Access to relevant file access and data transfer logs"
  - "Authorized access to account suspension and access revocation capabilities"
  - "Established incident escalation and HR coordination procedures"
  - "Evidence preservation and chain-of-custody procedures"
tags:
  - "insider-threat"
  - "insider-risk"
  - "data-exfiltration"
  - "unauthorized-access"
  - "privileged-access"
  - "identity-security"
  - "data-protection"
  - "incident-response"
  - "mitre-attack"
references:
  - "https://attack.mitre.org/techniques/T1078/"
  - "https://attack.mitre.org/techniques/T1098/"
  - "https://attack.mitre.org/techniques/T1213/"
  - "https://attack.mitre.org/techniques/T1530/"
  - "https://attack.mitre.org/techniques/T1567/002/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify Insider Threat Alert"
    action: "investigate"
    description: "Identify the detection source, affected user accounts, involved systems, suspicious activities, detection timestamp, and initial alert context."
    expected_result: "The suspected insider threat activity and potentially affected accounts or resources are identified."
  - id: "validate-user-activity"
    order: 2
    name: "Validate User Activity"
    action: "analyze"
    description: "Determine whether the observed user activity is consistent with authorized business operations, established access patterns, and assigned responsibilities."
    expected_result: "The legitimacy of the observed user activity is assessed."
  - id: "analyze-threat-behavior"
    order: 3
    name: "Analyze Threat Behavior"
    action: "analyze"
    description: "Examine authentication events, access patterns, privilege changes, data access, endpoint activity, and transfer behavior to identify malicious, negligent, or compromised-user activity."
    expected_result: "The suspected insider threat behavior and associated security risks are identified."
  - id: "determine-scope"
    order: 4
    name: "Determine Incident Scope"
    action: "hunt"
    description: "Identify affected users, accounts, endpoints, applications, sensitive information, cloud resources, and related infrastructure to establish the incident scope and potential business impact."
    expected_result: "The affected organizational resources and potential data exposure are determined."
  - id: "contain-threat"
    order: 5
    name: "Contain Insider Threat"
    action: "contain"
    description: "Apply approved account restrictions, session revocation, privilege removal, endpoint isolation, access policy enforcement, and data protection controls while preserving relevant evidence."
    expected_result: "Suspicious activity is contained and further unauthorized access or data exposure is prevented."
  - id: "remediate-exposure"
    order: 6
    name: "Remediate Security Exposure"
    action: "respond"
    description: "Address compromised credentials, excessive permissions, unauthorized access paths, exposed information, and affected systems, and restore secure operational conditions."
    expected_result: "Identified security weaknesses and unauthorized access conditions are remediated."
  - id: "verify-security-recovery"
    order: 7
    name: "Verify Security Recovery"
    action: "validate"
    description: "Verify account security, access permissions, endpoint integrity, data protection controls, and monitoring effectiveness, and check for recurring suspicious activity."
    expected_result: "Security recovery and containment effectiveness are verified."
  - id: "determine-outcome"
    order: 8
    name: "Determine Response Outcome"
    action: "document"
    description: "Classify the incident and document involved accounts, observed behavior, affected information, collected evidence, containment actions, business impact, and remaining risks."
    expected_result: "The insider threat incident receives a documented response outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "insider-threat-response"
---

# Insider Threat Response

## Purpose

This playbook provides a structured response workflow for suspected or confirmed insider threats involving employees, contractors, administrators, and other individuals with authorized organizational access.

Insider threats may involve intentional or accidental misuse of privileges, unauthorized data access, intellectual property theft, data exfiltration, account manipulation, information disclosure, or data destruction. Compromised legitimate accounts may also be used to carry out insider-related attacks.

The objective is to identify suspicious activity, assess its scope and impact, contain threats, preserve forensic evidence, and restore secure operational conditions.

## MITRE ATT&CK

| Technique | Name                               | Relevance                                                     |
| --------- | ---------------------------------- | ------------------------------------------------------------- |
| T1078     | Valid Accounts                     | Misuse of legitimate organizational accounts                  |
| T1098     | Account Manipulation               | Unauthorized account and permission modifications             |
| T1213     | Data from Information Repositories | Unauthorized collection of organizational information         |
| T1530     | Data from Cloud Storage            | Unauthorized access to sensitive cloud-stored information     |
| T1567.002 | Exfiltration to Cloud Storage      | Exfiltration of organizational data to cloud storage services |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Unusual user account activity or authentication patterns.
- Unauthorized access to confidential or restricted information.
- Unexpected downloads or transfers of sensitive organizational data.
- Suspicious privilege escalation or permission modifications.
- DLP systems detect suspicious data movement.
- UEBA systems identify abnormal user behavior.
- EDR or SIEM platforms detect suspicious endpoint or account activity.
- Unauthorized forwarding or downloading of organizational emails.
- Unexpected deletion or modification of critical information.
- Reports of potential intellectual property theft or information disclosure.
- Suspicious activity following employee termination or role changes.

## Scope

The investigation should consider:

- affected user accounts;
- privileged accounts;
- authentication events;
- affected endpoints;
- domain controllers;
- cloud environments;
- file servers and repositories;
- email accounts and mailboxes;
- sensitive organizational information;
- intellectual property;
- data access permissions;
- file downloads and transfers;
- removable storage devices;
- external storage services;
- network connections;
- application activity;
- privilege modifications;
- access policy changes;
- account lifecycle events;
- business and operational impact;
- potential data exposure.

## Investigation Procedure

### Step 1 — Identify Insider Threat Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected user account;
- user identity and organizational role;
- account privileges;
- affected systems;
- suspicious activity type;
- source IP address;
- device identifier;
- reported business impact;
- initial incident severity.

Identify whether the suspected activity involves:

- an employee;
- a contractor;
- a privileged administrator;
- a third-party service provider;
- a compromised legitimate account;
- an unidentified internal identity.

Preserve the original alert context and relevant identity, endpoint, network, application, and data access telemetry.

Do not assume that unusual user behavior automatically indicates malicious intent.

### Step 2 — Validate User Activity

Determine whether the observed activity is consistent with legitimate business operations.

Review:

- normal user activity baselines;
- assigned job responsibilities;
- authorized access permissions;
- expected working hours;
- approved remote access activity;
- recent role or department changes;
- approved data transfer operations;
- authorized administrative activities;
- access requests and approvals;
- recent security policy changes;
- account lifecycle information.

Correlate suspicious activity with identity, endpoint, application, and data access logs.

Determine whether the activity could be explained by:

- legitimate business operations;
- approved administrative tasks;
- authorized security testing;
- temporary access requirements;
- scheduled data migration;
- compromised credentials;
- accidental user actions;
- intentional misuse of authorized access.

A deviation from normal behavior should not automatically be classified as an insider attack.

Validate the activity using objective technical evidence and established organizational procedures.

### Step 3 — Analyze Threat Behavior

Analyze the observed behavior to identify the suspected insider threat category.

Review:

- authentication logs;
- identity provider events;
- privileged access records;
- file access logs;
- cloud audit logs;
- endpoint telemetry;
- email activity;
- DLP alerts;
- network traffic;
- removable media events;
- application access records;
- data transfer activity.

Determine whether the behavior indicates intentional misuse, accidental exposure, or external compromise of a legitimate account.

### Step 4 — Determine Incident Scope

Search for:

- additional affected user accounts;
- suspicious privilege modifications;
- unauthorized file access;
- sensitive information downloads;
- external data transfer activity;
- affected endpoints;
- related cloud applications;
- suspicious email forwarding rules;
- unauthorized mailbox access;
- removable storage activity;
- affected file repositories;
- previous similar user activity;
- unauthorized access to shared resources.

Determine:

- number of affected accounts;
- number of affected systems;
- affected organizational departments;
- categories of exposed information;
- volume of accessed or transferred data;
- potential data exfiltration;
- duration of suspicious activity;
- privileges involved;
- access paths used;
- whether external parties received organizational information;
- potential regulatory implications;
- business and operational impact;
- whether suspicious activity is ongoing.

Identify whether the incident is isolated to one identity or involves multiple users and systems.

### Step 5 — Contain Insider Threat

Apply appropriate containment controls based on the identified threat behavior.

Consider:

- temporarily suspending affected accounts;
- revoking active authentication sessions;
- invalidating access tokens;
- resetting compromised credentials;
- enforcing multifactor authentication;
- removing unauthorized privileges;
- restricting access to sensitive repositories;
- disabling suspicious application integrations;
- blocking unauthorized data transfer paths;
- isolating affected endpoints where justified;
- disabling unauthorized email forwarding rules;
- applying additional DLP restrictions;
- restricting external sharing permissions.

For suspected account compromise, prioritize credential protection, session revocation, and identity security controls.

For confirmed malicious insider activity, coordinate containment with the incident-response team, identity administrators, data owners, and authorized organizational stakeholders.

### Step 6 — Remediate Security Exposure

Review affected organizational resources and restore secure access conditions.

Consider:

- removing unauthorized account permissions;
- correcting excessive privileges;
- removing unauthorized access tokens;
- reviewing application integrations;
- correcting file-sharing permissions;
- disabling unauthorized external sharing;
- securing affected cloud storage;
- reviewing mailbox forwarding rules;
- restoring modified organizational information;
- recovering deleted files where appropriate;
- reviewing endpoint integrity;
- updating access control policies;
- addressing identified security weaknesses;
- reviewing third-party access;
- implementing additional monitoring controls.

Coordinate remediation with identity, infrastructure, endpoint, application, data protection, and business teams.

Ensure that all remediation actions are authorized, documented, and supported by appropriate evidence.

### Step 7 — Verify Security Recovery

Verify:

- authentication integrity;
- active session status;
- privileged access assignments;
- access permissions;
- endpoint integrity;
- cloud application security;
- data repository permissions;
- email forwarding configurations;
- DLP protection status;
- external sharing restrictions;
- suspicious data transfer activity;
- audit logging;
- application functionality;
- business operations.

Confirm that unauthorized access has been removed and legitimate users retain their required access.

Verify that compromised credentials, sessions, tokens, and unauthorized permissions cannot be reused.

### Step 8 — Determine Response Outcome

Classify the incident as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification and record affected accounts, user activity, accessed information, potential data exposure, containment actions, business impact, and recovery status.

## Evidence to Collect

| Evidence          | Description                                                               |
| ----------------- | ------------------------------------------------------------------------- |
| Alert             | Detection source, alert ID, severity, timestamp                           |
| Identity          | User identity, account information, and organizational role               |
| Authentication    | Login events, MFA activity, session information, and source IP addresses  |
| Privileged Access | Administrative permissions, privilege changes, and PAM records            |
| Endpoint          | Device information, EDR alerts, and endpoint activity                     |
| File Access       | File access, modification, deletion, and download events                  |
| Data Transfer     | Transfer volume, destination, protocols, and timestamps                   |
| DLP               | Data protection alerts and policy violations                              |
| Cloud             | Cloud audit logs, storage access, and sharing activity                    |
| Email             | Mailbox access, forwarding rules, and message transfer activity           |
| Network           | Source and destination addresses, connections, and traffic patterns       |
| Applications      | Application activity, access records, and configuration changes           |
| Removable Media   | USB device connections and file transfer activity                         |
| Timeline          | Detection, investigation, containment, and recovery timestamps            |
| Chain of Custody  | Evidence collection details, integrity verification, and handling records |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- activity is associated with legitimate business operations;
- access is consistent with assigned job responsibilities;
- data transfers are properly authorized;
- administrative actions have valid approvals;
- no unauthorized access is identified;
- no evidence of data exfiltration exists;
- observed anomalies have a verified operational explanation.

Document the operational justification before closing the incident.

### Suspicious

Classify the activity as **suspicious** when:

- access patterns deviate from established baselines;
- sensitive information is accessed unexpectedly;
- unusual downloads or transfers are identified;
- privilege changes cannot be immediately verified;
- external sharing activity appears abnormal;
- suspicious email or cloud application activity is detected;
- potential security policy violations are observed;
- available evidence indicates possible insider misuse.

Continue investigation and maintain appropriate monitoring and containment controls.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- intentional unauthorized access to organizational information;
- deliberate data theft or exfiltration;
- intentional disclosure of confidential information;
- unauthorized abuse of privileged accounts;
- deliberate bypass of established security controls;
- intentional deletion or destruction of organizational data;
- unauthorized modification of account permissions;
- unauthorized transfer of intellectual property;
- coordinated malicious activity involving internal identities.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to establish whether the observed activity represents malicious insider behavior, negligent activity, or legitimate business operations.

Document:

- evidence collected;
- evidence unavailable;
- telemetry limitations;
- affected accounts;
- potentially exposed information;
- containment status;
- additional investigation requirements;
- unresolved authorization questions;
- attribution limitations;
- unverified data transfer activity.

## Escalation

Escalate the incident when:

- malicious insider activity is confirmed;
- sensitive organizational information is exposed;
- intellectual property theft is suspected;
- privileged accounts are involved;
- unauthorized data exfiltration is identified;
- critical systems or business operations are compromised;
- regulatory or contractual data protection obligations may be affected;
- unauthorized access continues despite containment;
- employee-related investigation requires HR or Legal involvement;
- third-party access or external data recipients are involved.

## Response Guidance

For confirmed insider threat activity:

1. Preserve identity, authentication, endpoint, network, application, and data access telemetry.
2. Identify affected user accounts, devices, applications, and organizational information.
3. Determine whether the activity involves malicious intent, negligence, or compromised credentials.
4. Assess the scope of unauthorized access and potential data exposure.
5. Coordinate with security, identity, infrastructure, HR, Legal, and Privacy teams as appropriate.
6. Apply proportionate containment controls.
7. Revoke unauthorized sessions, credentials, tokens, and permissions.
8. Protect affected information repositories and external sharing channels.
9. Review related accounts and systems for additional suspicious activity.
10. Remediate identified security weaknesses and unauthorized access paths.
11. Verify account security and restore legitimate business access.
12. Document the incident timeline, evidence, containment actions, and recovery status.
13. Preserve forensic evidence and maintain chain-of-custody records.

Do not assume that every unusual employee activity represents malicious intent.

## Related Detection Rules

## Related Playbooks

- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/data-exfiltration-response.md`
- `playbooks/response/cloud-incident-response.md`
- `playbooks/response/business-email-compromise-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against controlled insider-threat scenarios, authorized user activity datasets, identity logs, endpoint telemetry, DLP alerts, cloud audit records, and data access monitoring reports.

Validation should confirm that:

- suspicious user behavior can be identified;
- legitimate business activity can be distinguished from unauthorized behavior;
- malicious, negligent, and compromised-user scenarios can be differentiated;
- affected accounts and organizational resources can be identified;
- unauthorized access and privilege misuse can be detected;
- potential data exfiltration can be investigated;
- incident scope and business impact can be determined;
- containment controls can be applied;
- relevant forensic evidence can be preserved;
- account security and access permissions can be restored;
- HR, Legal, and Privacy escalation procedures can be initiated where required;
- response actions are documented and reproducible;
- legitimate business operations can be maintained during investigation.

## Safety

This playbook is intended for authorized defensive security operations and incident response activities.

All investigation, monitoring, access control, and evidence collection activities must comply with organizational policies and applicable privacy and data protection requirements.

Preserve forensic evidence and coordinate response activities with relevant security, HR, and Legal teams.
