---
id: "password-spraying"
name: "Password Spraying"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-17T15:17:00Z"
updated_at: "2026-09-17T15:17:00Z"
description: "Password spraying is an authentication attack pattern in which a limited number of common or compromised passwords are attempted against multiple accounts."
objective: "Identify, investigate, and validate suspicious password-spraying activity and determine whether accounts may have been targeted or compromised."
severity: "high"
mitre_attack:
  - "T1110.003"
triggers:
  - "Multiple failed authentication attempts across several accounts"
  - "Repeated authentication failures originating from a common source"
  - "Authentication attempts against many accounts within a short period"
  - "Successful authentication following a password-spraying pattern"
  - "Password-spraying activity targeting privileged or high-value accounts"
  - "Threat hunting identifies anomalous authentication patterns"
prerequisites:
  - "Access to authentication telemetry"
  - "Access to identity-provider or domain-controller logs"
  - "Access to endpoint and network telemetry where available"
  - "Access to account and group information"
tags:
  - "password-spraying"
  - "credential-access"
  - "authentication"
  - "active-directory"
  - "identity"
  - "windows"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1110/003/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Password Spraying Alert"
  action: "investigate"
  description: "Identify the detection source, source addresses, targeted accounts, authentication provider, timestamps, and alert context."
  expected_result: "The suspicious authentication pattern and affected entities are identified."
- id: "identify-authentication-pattern"
  order: 2
  name: "Identify Authentication Pattern"
  action: "analyze"
  description: "Determine the number of targeted accounts, failure volume, time window, source distribution, and authentication services involved."
  expected_result: "The authentication pattern is documented and assessed."
- id: "review-source-context"
  order: 3
  name: "Review Source Context"
  action: "analyze"
  description: "Review source IP addresses, hosts, geographic or network context, user agents where available, and known organizational infrastructure."
  expected_result: "The origin and context of the authentication attempts are assessed."
- id: "review-target-accounts"
  order: 4
  name: "Review Target Accounts"
  action: "analyze"
  description: "Identify targeted accounts, privileges, account type, ownership, normal usage patterns, and business importance."
  expected_result: "Potentially targeted accounts and their risk are documented."
- id: "review-successful-authentication"
  order: 5
  name: "Review Successful Authentication"
  action: "analyze"
  description: "Identify successful authentications occurring during or immediately after the suspicious failure pattern and correlate them with source, account, and destination context."
  expected_result: "Potentially compromised authentications are identified or ruled out."
- id: "review-follow-on-activity"
  order: 6
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Correlate authentication activity with privilege escalation, lateral movement, persistence, endpoint activity, and suspicious network behavior."
  expected_result: "Post-authentication activity and possible account misuse are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Password Spraying Scope"
  action: "hunt"
  description: "Search for related authentication failures, source addresses, targeted accounts, successful logons, and repeated patterns across the environment."
  expected_result: "The prevalence and scope of the password-spraying activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the authentication activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "password-spraying"
---

# Password Spraying

## Purpose

This playbook provides a structured workflow for investigating suspected password-spraying activity.

Password spraying is an authentication attack pattern in which a limited number of passwords are attempted against multiple accounts. Unlike attacks focused on repeatedly guessing a single account's password, password spraying typically distributes authentication attempts across multiple accounts to avoid account-specific lockout thresholds.

The objective is to determine whether the observed authentication activity is legitimate, suspicious, or malicious and whether any accounts may have been targeted or compromised.

## MITRE ATT&CK

| Technique | Name                           | Relevance                                                                                                       |
| --------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| T1110.003 | Brute Force: Password Spraying | Relevant when authentication attempts are distributed across multiple accounts using a limited set of passwords |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Multiple authentication failures affect several accounts in a short period.
- A common source generates repeated authentication failures against multiple users.
- Authentication attempts are distributed across many accounts.
- A successful authentication follows a suspicious failure pattern.
- Privileged or high-value accounts are included among the targets.
- Authentication activity originates from an unusual external or internal source.
- Threat hunting identifies an anomalous multi-account authentication pattern.

## Scope

The investigation should consider:

- source IP address;
- source host;
- destination service;
- authentication protocol;
- identity provider;
- domain controller where applicable;
- targeted accounts;
- account type;
- privileged accounts;
- failed authentication count;
- successful authentication count;
- time window;
- source distribution;
- destination distribution;
- geographic or network context;
- user agent where available;
- endpoint activity;
- lateral movement;
- persistence;
- related alerts;
- other affected accounts and hosts.

## Authentication Context

Password-spraying indicators can appear across multiple authentication services and identity platforms.

Relevant telemetry may include:

- Active Directory authentication;
- Windows logon events;
- VPN authentication;
- remote-access services;
- cloud identity-provider sign-ins;
- web application authentication;
- email or collaboration platform authentication;
- other centralized identity services.

Authentication failures should always be evaluated in context. Legitimate systems, applications, synchronization services, misconfigured clients, and network infrastructure can also generate repeated failed authentications.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- source IP;
- source host;
- targeted accounts;
- authentication service;
- domain or identity provider;
- detection severity;
- detection reason.

Preserve the original alert context before taking response actions.

### Step 2 — Identify Authentication Pattern

Determine:

- number of authentication failures;
- number of targeted accounts;
- number of successful authentications;
- time window;
- source count;
- destination count;
- request frequency;
- authentication protocol;
- account distribution.

Look for a pattern involving repeated authentication attempts against multiple accounts rather than repeated failures against a single account.

### Step 3 — Review Source Context

Review:

- source IP address;
- source hostname;
- internal or external network location;
- ASN or provider information where relevant;
- VPN or proxy context;
- known organizational infrastructure;
- user agent where available;
- associated endpoint telemetry.

Determine whether the source is:

- approved infrastructure;
- an expected authentication service;
- a known security scanner;
- a misconfigured application;
- an unknown or suspicious host.

### Step 4 — Review Target Accounts

For targeted accounts, determine:

- username;
- account type;
- privilege level;
- group memberships;
- service-account status;
- administrative role;
- account ownership;
- normal login pattern;
- recent password changes;
- recent account changes.

Prioritize accounts with elevated privileges or access to sensitive systems.

### Step 5 — Review Successful Authentication

Identify any successful authentication that occurs:

- during the suspicious activity;
- immediately after the failure pattern;
- from the same source;
- against one of the targeted accounts;
- against another system using the same account.

Review:

- source;
- destination;
- account;
- timestamp;
- authentication method;
- location or network context;
- device context where available.

A successful authentication following a suspicious multi-account failure pattern requires further investigation.

### Step 6 — Review Follow-on Activity

Correlate successful authentications with:

- privileged logons;
- remote access;
- lateral movement;
- process creation;
- persistence;
- mailbox or cloud activity;
- file access;
- network connections;
- additional credential-access activity.

Determine whether potentially compromised accounts were subsequently used for unauthorized activity.

### Step 7 — Determine Password Spraying Scope

Search the environment for:

- same source IP;
- same source host;
- same targeted accounts;
- similar authentication failure patterns;
- successful logons following failures;
- related identity-provider events;
- repeated activity against other services.

Determine:

- number of affected accounts;
- number of affected hosts;
- number of affected services;
- number of successful authentications;
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

| Evidence               | Description                                             |
| ---------------------- | ------------------------------------------------------- |
| Alert                  | Detection source, ID, severity, timestamp               |
| Source IP              | Origin of authentication attempts                       |
| Source Host            | Host associated with the attempts                       |
| Target Accounts        | Accounts targeted by the activity                       |
| Authentication Service | VPN, AD, cloud identity, web service, or other provider |
| Protocol               | Authentication protocol where available                 |
| Failed Attempts        | Number and timestamps of failures                       |
| Successful Attempts    | Number and timestamps of successful authentications     |
| Account Privileges     | Privilege level and group memberships                   |
| Location               | Network or geographic context where available           |
| Device                 | Device information where available                      |
| User Agent             | Client information where available                      |
| Endpoint               | Related endpoint activity                               |
| Lateral Movement       | Related remote access activity                          |
| Persistence            | Related persistence indicators                          |
| Network                | Related network connections                             |
| Timeline               | Correlated authentication and endpoint events           |
| Scope                  | Other affected accounts, services, and hosts            |
| Detections             | Related security alerts                                 |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- failures are explained by a known application or service;
- the source is approved infrastructure;
- authentication behavior is consistent with normal operations;
- affected accounts belong to an expected automated workflow;
- there is no suspicious successful authentication;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- multiple unrelated accounts are targeted;
- authentication failures originate from an unusual source;
- the activity differs from normal authentication patterns;
- privileged accounts are included;
- a successful authentication occurs during the suspicious pattern;
- account or endpoint context is unclear;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized distributed authentication attempts;
- confirmed password-spraying behavior;
- successful authentication of a targeted account associated with suspicious activity;
- subsequent account misuse;
- lateral movement using an affected account;
- privilege escalation or persistence involving a potentially compromised account.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the authentication pattern was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- a privileged account successfully authenticates during the suspicious activity;
- account compromise is suspected or confirmed;
- multiple services or identity platforms are targeted;
- multiple hosts or users are affected;
- suspicious authentication is followed by lateral movement;
- persistence is identified;
- the activity is associated with confirmed malicious infrastructure.

## Response Guidance

For confirmed malicious password-spraying activity:

1. Preserve authentication, identity-provider, endpoint, and network evidence.
2. Identify all targeted accounts and affected services.
3. Determine whether any authentication attempts were successful.
4. Follow the organization's account-compromise response procedure.
5. Review potentially compromised accounts and privileged identities.
6. Investigate subsequent authentication and lateral-movement activity.
7. Follow authorized account containment and credential-remediation procedures.
8. Review source infrastructure and related indicators across the environment.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Account disablement, credential resets, session invalidation, and other identity response actions must follow approved organizational procedures.

Do not test passwords against real user accounts as part of routine investigation or validation.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`

## Related Playbooks

- `playbooks/credential-access/credential-access.md`
- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/kerberoasting.md`
- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/ntds-dump.md`
- `playbooks/credential-access/sam-dump.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/lateral-movement/pass-the-ticket.md`
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

The playbook should be validated against approved authentication telemetry, identity-provider logs, synthetic account activity, endpoint telemetry, and controlled authentication-security scenarios.

Validation should confirm that:

- distributed authentication failures can be identified;
- targeted accounts can be determined;
- source systems can be identified;
- successful authentications can be correlated with failure patterns;
- privileged accounts can be identified;
- related endpoint and network activity can be investigated;
- potential account compromise can be assessed;
- benign authentication failures can be distinguished from suspicious multi-account activity;
- escalation criteria produce consistent outcomes.

Validation should use synthetic accounts, test identities, sanitized telemetry, and isolated environments.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not perform password-spraying tests against real user accounts, production identity systems, or third-party services.

Use synthetic accounts and isolated authentication infrastructure when validating detection logic.
