---
id: "pass-the-hash"
name: "Pass the Hash"
category: "lateral-movement"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-10T06:23:00Z"
updated_at: "2026-10-10T06:23:00Z"
description: "Investigate suspected pass-the-hash activity involving the unauthorized use of captured password hashes to authenticate to remote Windows systems."
objective: "Determine whether suspicious authentication and remote access activity indicate pass-the-hash, identify affected accounts and systems, establish the extent of lateral movement, and support appropriate incident response."
severity: "high"
mitre_attack:
  - "T1550.002"
triggers:
  - "Unusual NTLM network authentication associated with privileged accounts"
  - "Unexpected authentication from a previously unseen source host"
  - "Suspicious authentication followed by remote process or service activity"
  - "Anomalous use of administrative accounts across multiple systems"
  - "Detection of potential credential reuse associated with lateral movement"
  - "Threat hunting identifies suspicious NTLM authentication patterns"
prerequisites:
  - "Access to Windows Security event logs"
  - "Access to authentication and identity telemetry"
  - "Access to endpoint process creation telemetry"
  - "Access to network connection and remote access telemetry where available"
  - "Access to account ownership, privilege, and baseline information"
tags:
  - "pass-the-hash"
  - "lateral-movement"
  - "credential-access"
  - "authentication"
  - "ntlm"
  - "windows"
  - "incident-response"
references:
  - "https://attack.mitre.org/techniques/T1550/002/"
steps:
  - id: "identify-pth-alert"
    order: 1
    name: "Identify Pass-the-Hash Alert"
    action: "investigate"
    description: "Identify the detection source, alert timestamp, affected account, source host, destination host, authentication protocol, and available evidence of suspicious credential reuse."
    expected_result: "The alert context and initial indicators associated with suspected pass-the-hash activity are documented."
  - id: "identify-source-destination"
    order: 2
    name: "Identify Source and Destination"
    action: "investigate"
    description: "Identify the originating host, destination system, associated IP addresses, host roles, and relevant network relationships."
    expected_result: "The source and destination systems and their relationship to the observed authentication are established."
  - id: "review-authentication"
    order: 3
    name: "Review Authentication Activity"
    action: "analyze"
    description: "Review Windows authentication events, including logon type, authentication package, account identity, source workstation, timestamp, and authentication outcome."
    expected_result: "The authentication sequence and deviations from expected account and host behavior are documented."
  - id: "review-account-credential-context"
    order: 4
    name: "Review Account and Credential Context"
    action: "analyze"
    description: "Assess the account's privileges, normal access patterns, recent authentication history, credential exposure indicators, and whether the observed access was authorized."
    expected_result: "The account context and available evidence of possible credential compromise are assessed."
  - id: "review-remote-execution"
    order: 5
    name: "Review Remote Execution Activity"
    action: "analyze"
    description: "Correlate authentication activity with process creation, remote service activity, administrative shares, remote management, and other relevant execution events on the destination system."
    expected_result: "Related remote access and execution activity is identified and assessed."
  - id: "correlate-related-events"
    order: 6
    name: "Correlate Related Events"
    action: "hunt"
    description: "Correlate authentication, process, network, and endpoint telemetry to determine whether the activity is associated with credential theft, additional lateral movement, persistence, or other suspicious behavior."
    expected_result: "Related activity and supporting or contradicting evidence are documented."
  - id: "determine-movement-scope"
    order: 7
    name: "Determine Lateral Movement Scope"
    action: "hunt"
    description: "Search for related authentication patterns involving the same account, source host, destination hosts, and time period to identify additional potentially affected systems."
    expected_result: "The scope of potentially affected accounts and systems is established."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity using the available evidence, document the investigation findings, and determine whether escalation or containment is required."
    expected_result: "A documented investigation outcome and recommended next actions are available."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "pass-the-hash"
---

# Pass the Hash

## Purpose

This playbook provides a structured workflow for investigating suspected pass-the-hash activity in Windows environments.

Pass-the-hash is a technique in which an adversary uses a captured password hash to authenticate as an account without knowing its plaintext password. The technique may enable unauthorized access to remote systems and facilitate lateral movement.

The objective is to determine whether observed authentication activity is legitimate, suspicious, or malicious; identify potentially compromised accounts and systems; and establish the extent of any associated lateral movement.

A successful NTLM authentication or an unusual network logon does not, by itself, establish that a pass-the-hash attack occurred. Findings must be evaluated using authentication context, endpoint telemetry, account behavior, and corroborating evidence.

## MITRE ATT&CK

| Technique | Name          | Relevance                                                                                                |
| --------- | ------------- | -------------------------------------------------------------------------------------------------------- |
| T1550.002 | Pass the Hash | Primary technique involving the use of captured password hashes for authentication and lateral movement. |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Unusual NTLM authentication involving a privileged or sensitive account.
- Network logons from a source host that is not normally associated with the account.
- Authentication to multiple systems within an unusual time window.
- Unexpected remote service or process activity following successful authentication.
- Account usage inconsistent with established authentication and access patterns.
- Correlated endpoint or identity detections indicating potential credential compromise.
- Threat hunting identifies suspicious authentication and lateral movement behavior.

A single failed or successful authentication event should not automatically be classified as pass-the-hash. Investigate the complete activity sequence and its surrounding context.

## Scope

The investigation should consider:

- originating host;
- destination host;
- source and destination IP addresses;
- associated user account;
- account type and privilege level;
- authentication protocol and package;
- Windows logon type;
- authentication outcome;
- source workstation;
- authentication timestamps;
- process creation activity;
- remote service activity;
- administrative share access;
- remote management activity;
- network connections;
- credential exposure indicators;
- related authentication events;
- other potentially affected systems;
- associated security alerts.

## Investigation Procedure

### Step 1 — Identify Pass-the-Hash Alert

Review the original alert and preserve its context.

Collect:

- detection source and alert identifier;
- detection timestamp;
- account associated with the authentication;
- source and destination systems;
- source and destination IP addresses;
- authentication package;
- logon type;
- detection rationale;
- related alerts and event identifiers.

Determine which indicators triggered the investigation and whether they are sufficient to justify further analysis.

Do not classify the activity as pass-the-hash solely because NTLM authentication was observed.

### Step 2 — Identify Source and Destination

Identify the system originating the authentication and the system receiving it.

Collect:

- hostname and IP address of each system;
- operating system and host role;
- asset owner and criticality;
- relevant network segment;
- expected administrative relationships;
- whether the source system normally accesses the destination;
- whether the destination is sensitive or privileged.

Determine whether the observed connection is consistent with documented administration, approved management tooling, or established application behavior.

Investigate unexpected source-to-destination relationships and access to systems that the account does not normally use.

### Step 3 — Review Authentication Activity

Examine the authentication sequence on the destination system and, where available, the relevant domain controllers and identity infrastructure.

Review applicable telemetry, including:

- Windows Security event 4624 for successful logons;
- Windows Security event 4648 for logons using explicit credentials;
- Windows Security event 4768 for Kerberos authentication ticket requests;
- available process creation and network connection telemetry;
- relevant authentication failures and surrounding successful logons.

For each relevant event, examine:

- account name and domain;
- source workstation and source network address;
- destination host;
- logon type;
- authentication package;
- timestamp;
- logon identifier where available;
- associated process or service activity.

Pay particular attention to unusual network logons, especially when the authentication context is inconsistent with the account's normal behavior.

Event 4768 and Kerberos-related activity should be interpreted in context. They may help establish the wider authentication sequence but do not independently confirm pass-the-hash.

### Step 4 — Review Account and Credential Context

Determine whether the account's observed behavior is consistent with its normal use.

Review:

- account type and privilege level;
- normal source systems;
- typical destination systems;
- expected working hours and authentication patterns;
- recent account changes;
- recent suspicious authentication;
- evidence of credential dumping or other credential exposure;
- reported or confirmed account compromise;
- whether the activity was authorized by the account owner or system administrator.

Assess whether the account has privileges that could enable access to additional systems.

A privileged account or an NTLM authentication event alone does not demonstrate credential theft. Look for corroborating evidence of unauthorized credential use.

### Step 5 — Review Remote Execution Activity

Review activity on the destination host following the suspicious authentication.

Investigate available evidence of:

- remote process creation;
- service creation or modification;
- administrative share access;
- remote management activity;
- unexpected command execution;
- file creation or modification;
- changes to scheduled tasks or other persistence mechanisms;
- outbound network connections;
- subsequent access to additional systems.

Correlate the timestamps and available account, process, and logon identifiers.

Determine whether remote activity is consistent with authorized administration or indicates potentially unauthorized access.

Do not execute suspicious binaries or modify affected systems merely to reproduce the observed behavior.

### Step 6 — Correlate Related Events

Build a timeline combining authentication, process, network, and endpoint activity.

Correlate:

- authentication events across source and destination systems;
- account activity preceding the suspected incident;
- process creation following successful authentication;
- network connections associated with the relevant processes;
- potential credential access activity;
- remote service and management events;
- related security alerts;
- activity involving the same account on other systems.

Where available, compare the observed behavior with established administrative activity and known access patterns.

Determine whether the evidence supports suspected pass-the-hash, another authentication-related technique, legitimate administration, or an alternative explanation.

### Step 7 — Determine Lateral Movement Scope

Search the environment for related activity involving:

- the same account;
- the same originating host;
- the same destination host;
- the same source or destination addresses;
- similar authentication patterns;
- related process activity;
- related remote service activity;
- similar timestamps and access sequences.

Establish:

- the number of potentially affected systems;
- the accounts involved;
- the earliest and latest relevant events;
- whether access continued after the initial activity;
- whether privileged systems were accessed;
- whether additional credential access or persistence was observed;
- whether the activity remains ongoing.

Document gaps in telemetry and distinguish confirmed affected systems from systems requiring further investigation.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the selected classification.

Identify whether incident escalation, credential remediation, endpoint containment, or further investigation is required.

## Evidence to Collect

| Evidence            | Description                                                                  |
| ------------------- | ---------------------------------------------------------------------------- |
| Alert               | Detection source, alert identifier, severity, and timestamp                  |
| Authentication      | Relevant Windows authentication events and associated fields                 |
| Source Host         | Hostname, IP address, operating system, and asset role                       |
| Destination Host    | Hostname, IP address, operating system, and asset criticality                |
| Account             | Account identity, domain, account type, and privilege context                |
| Logon Context       | Logon type, authentication package, and available logon identifiers          |
| Process Activity    | Relevant process creation events, command lines, and process relationships   |
| Remote Access       | Remote service, administrative share, and management activity                |
| Network             | Relevant connections, endpoints, timestamps, and available protocol metadata |
| Credential Exposure | Evidence supporting possible credential compromise                           |
| Timeline            | Chronological sequence of authentication and related activity                |
| Scope               | Other affected accounts, hosts, and systems                                  |
| Detections          | Related alerts and supporting investigation findings                         |

Preserve evidence according to organizational evidence-handling and retention requirements.

## Decision Criteria

### Benign

Classify the activity as **benign** when the available evidence establishes that:

- the authentication was authorized;
- the account's access is consistent with its assigned responsibilities;
- the source and destination relationship is expected;
- related remote activity corresponds to approved administrative or application operations;
- the observed authentication pattern has a credible operational explanation;
- no corroborating evidence of unauthorized credential use is identified.

Document the justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when one or more indicators require additional investigation, including:

- unusual NTLM network authentication;
- access from an unexpected source system;
- authentication involving an account outside its normal usage pattern;
- unexpected access to privileged systems;
- remote activity that is not adequately explained;
- related events suggesting potential credential exposure;
- insufficient telemetry to rule out unauthorized credential use.

Continue the investigation and seek corroborating evidence.

### Malicious

Classify the activity as **malicious** when sufficient corroborating evidence establishes unauthorized use of captured authentication material or other malicious lateral movement activity.

Supporting evidence may include:

- confirmed unauthorized use of a compromised account;
- authentication activity correlated with established credential compromise;
- unauthorized remote execution following suspicious authentication;
- confirmed lateral movement to additional systems;
- related credential access or persistence;
- evidence of continuing unauthorized access.

Escalate to the appropriate incident-response process and establish the full scope of the compromise.

### Inconclusive

Use **inconclusive** when the available evidence is insufficient to determine whether the activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- unresolved authentication patterns;
- limitations in event and endpoint coverage;
- additional telemetry required;
- investigative actions needed to reach a defensible conclusion.

Do not classify activity as benign solely because evidence is unavailable.

## Escalation

Escalate the investigation when:

- unauthorized use of a privileged account is confirmed or strongly suspected;
- authentication activity indicates possible use of compromised credentials;
- remote execution on an unauthorized system is identified;
- multiple hosts exhibit related suspicious authentication;
- credential access or additional persistence is observed;
- sensitive systems or domain infrastructure may be affected;
- unauthorized activity remains ongoing;
- the investigation indicates broader account or environment compromise.

Notify the incident-response and identity-security teams according to organizational procedures.

## Response Guidance

For confirmed or strongly suspected malicious activity:

1. Preserve relevant authentication, endpoint, process, and network evidence.
2. Identify affected accounts, source systems, destination systems, and related activity.
3. Determine whether the originating endpoint or another system may contain exposed credentials.
4. Coordinate account containment and credential remediation with the identity and incident-response teams.
5. Evaluate whether password changes, session revocation, or other credential invalidation measures are required.
6. Isolate affected endpoints when justified by the incident's severity and authorized response procedures.
7. Restrict unauthorized remote access and review relevant administrative privileges.
8. Investigate related credential access, persistence, and lateral movement.
9. Search for continued use of the affected accounts and related activity across the environment.
10. Restore affected systems and access only after the incident-response team has established that remediation requirements have been met.
11. Document the incident timeline, affected assets, evidence, containment actions, and recovery decisions.

Credential remediation should account for the authentication mechanisms and credential material involved. Changing a password should not be assumed to resolve every form of active unauthorized access.

Do not delete artifacts, reset systems, or perform disruptive containment actions before considering evidence preservation and the appropriate authorization process.

## Related Detection Rules

## Related Playbooks

- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/credential-dumping.md`
- `playbooks/lateral-movement/pass-the-ticket.md`
- `playbooks/lateral-movement/smb-lateral-movement.md`
- `playbooks/lateral-movement/rdp-lateral-movement.md`
- `playbooks/lateral-movement/winrm-lateral-movement.md`
- `playbooks/lateral-movement/wmi-lateral-movement.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/response/account-compromise-response.md`

## Validation

The playbook should be validated against approved Windows authentication telemetry, endpoint process events, network connection records, and controlled defensive test scenarios.

Validation should confirm that:

- authentication events can be collected and correlated;
- source and destination systems can be identified;
- account and privilege context can be established;
- suspicious NTLM authentication patterns can be investigated;
- remote execution activity can be correlated with authentication;
- legitimate administration can be distinguished from unauthorized access;
- related credential access and lateral movement can be investigated;
- the scope of potentially affected systems can be established;
- escalation and response criteria produce consistent outcomes.

A validation scenario should include both legitimate administrative activity and suspicious authentication activity to assess investigative accuracy and avoid classifying isolated indicators as proof of compromise.

## Safety

This playbook is intended for defensive security operations, incident response, security validation, and authorized testing.

Investigations should use approved telemetry and authorized access to affected systems. Credential material must be handled securely and must not be included in ordinary logs, tickets, or reports.

Do not attempt to use captured hashes to access remote systems, perform unauthorized authentication tests, or execute unapproved lateral movement actions. Any controlled validation must be conducted in an authorized test environment under established security procedures.
