---
id: "keylogging"
name: "Keylogging"
category: "collection"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-29T19:54:00Z"
updated_at: "2026-10-29T19:54:00Z"
description: "Investigate suspected keylogging activity to determine whether unauthorized keyboard input capture, credential collection, or sensitive data collection has occurred."
objective: "Identify and investigate suspicious keylogging behavior, establish the affected systems and accounts, assess potential credential exposure, and determine appropriate containment and response actions."
severity: "high"
mitre_attack:
  - "T1056.001"
triggers:
  - "An endpoint detection alert identifies suspected keylogging or unauthorized input capture."
  - "An unexpected process exhibits suspicious keyboard monitoring or input interception behavior."
  - "Unauthorized modifications to input-related registry settings, drivers, or system components are detected."
  - "An unknown process creates suspicious files potentially associated with captured input."
  - "Suspicious collection activity is correlated with credential misuse or anomalous outbound network communication."
prerequisites:
  - "Access to endpoint detection and response telemetry."
  - "Access to process creation, process lineage, and command-line telemetry."
  - "Access to relevant file, registry, driver, and system modification events."
  - "Access to network and authentication telemetry where available."
  - "An approved evidence preservation and incident escalation procedure."
tags:
  - "keylogging"
  - "input-capture"
  - "collection"
  - "credential-access"
  - "endpoint"
  - "malware-analysis"
references:
  - "https://attack.mitre.org/techniques/T1056/001/"
steps:
  - id: "identify-keylogging-alert"
    order: 1
    name: "Identify Keylogging Alert"
    action: "investigate"
    description: "Identify the detection source, alert timestamp, affected asset, suspected process, and reported input-capture behavior."
    expected_result: "The alert context, suspected behavior, and affected asset are documented."
  - id: "identify-affected-host-user"
    order: 2
    name: "Identify Affected Host and User"
    action: "investigate"
    description: "Determine which endpoint and user accounts may have been exposed to unauthorized input capture."
    expected_result: "Affected assets, associated users, account privileges, and relevant exposure context are identified."
  - id: "review-process-execution"
    order: 3
    name: "Review Process Execution"
    action: "analyze"
    description: "Review the suspected process, executable path, command line, process lineage, signature, hash, execution privileges, and related child processes."
    expected_result: "The process execution context and indicators of legitimate or suspicious activity are documented."
  - id: "assess-input-capture-indicators"
    order: 4
    name: "Assess Input-Capture Indicators"
    action: "analyze"
    description: "Investigate available telemetry for suspicious keyboard event monitoring, input interception, unexpected access to raw input interfaces, or unauthorized input-monitoring components."
    expected_result: "Input-capture indicators are identified and assessed against expected software behavior."
  - id: "review-persistence-modifications"
    order: 5
    name: "Review Persistence and System Modifications"
    action: "analyze"
    description: "Review relevant registry changes, driver installation, startup configuration, scheduled execution, services, and other persistence indicators associated with the suspected process."
    expected_result: "Relevant system modifications and potential persistence mechanisms are documented."
  - id: "review-artifacts-network-activity"
    order: 6
    name: "Review Collected Artifacts and Network Activity"
    action: "analyze"
    description: "Investigate suspicious files, logs, temporary artifacts, file access patterns, and network connections that may indicate storage or transfer of captured input."
    expected_result: "Potentially collected data, related artifacts, and associated network activity are identified."
  - id: "determine-credential-exposure"
    order: 7
    name: "Determine Credential Exposure and Scope"
    action: "hunt"
    description: "Correlate the suspected activity with authentication events, account usage, related alerts, and other affected endpoints to establish the potential extent of exposure."
    expected_result: "Potentially exposed credentials, affected accounts, related systems, and the investigation scope are documented."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity using the available evidence and document the findings, confidence, unresolved questions, and required response actions."
    expected_result: "The investigation outcome, supporting evidence, and recommended next actions are recorded."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "keylogging"
---

# Keylogging

## Purpose

This playbook provides a structured workflow for investigating suspected keylogging activity on endpoints and other supported systems.

Keylogging involves capturing and recording keyboard input. Unauthorized keylogging may expose authentication credentials, confidential information, and other sensitive user data.

The objective is to determine whether the observed behavior is legitimate, suspicious, or malicious; identify potentially affected users and systems; assess credential exposure; and support appropriate incident response actions.

## MITRE ATT&CK

| Technique | Name                      | Relevance                                                                                                  |
| --------- | ------------------------- | ---------------------------------------------------------------------------------------------------------- |
| T1056.001 | Input Capture: Keylogging | Primary technique associated with unauthorized keyboard input capture and potential credential collection. |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint security alert identifies suspected keylogging activity.
- An unknown or unauthorized process exhibits suspicious keyboard input monitoring.
- Process telemetry identifies unexpected input-interception behavior.
- Unauthorized driver, registry, or system modifications coincide with suspicious input monitoring.
- An unknown process creates files potentially associated with captured input.
- Suspicious input-capture activity is associated with unusual outbound network connections.
- Authentication anomalies suggest that credentials may have been exposed on an affected endpoint.
- Threat hunting identifies related behavior across multiple systems.

A single API call, process name, or system modification does not establish malicious keylogging. Findings must be evaluated in the context of the complete process, user, host, and system activity.

## Scope

The investigation should consider:

- affected endpoint or system;
- hostname and IP address;
- operating system and version;
- associated user accounts;
- privileged and service accounts;
- suspected process and executable path;
- command line and process lineage;
- process creation and execution timestamps;
- process signature and hash;
- input-monitoring behavior;
- relevant API or system-call telemetry;
- file creation and modification activity;
- registry modifications;
- driver installation or modification;
- scheduled tasks, services, and startup configuration;
- authentication activity;
- network connections and destinations;
- potentially exposed credentials or confidential information;
- related alerts and additional affected systems.

Investigation coverage should reflect the operating systems and telemetry sources available in the environment.

## Investigation Procedure

### Step 1 — Identify Keylogging Alert

Review the original alert and determine:

- detection source;
- alert identifier;
- alert severity;
- detection timestamp;
- affected host;
- suspected process;
- associated user;
- reported input-capture behavior;
- related detection events.

Preserve the original alert details and relevant timestamps.

Determine whether the detection is based on behavioral telemetry, a known artifact, endpoint protection, or analyst observation.

### Step 2 — Identify Affected Host and User

Identify the affected system and the accounts active during the suspected activity.

Collect:

- hostname and IP address;
- operating system;
- asset owner and criticality;
- logged-on user;
- account type and privilege level;
- interactive and remote logon activity;
- relevant authentication timestamps;
- endpoint isolation status;
- other alerts associated with the host or account.

Determine whether privileged users, administrators, service accounts, or other sensitive identities may have been exposed.

Do not assume that the account which generated the alert is necessarily the account whose input was captured.

### Step 3 — Review Process Execution

Examine the suspected process and its execution context.

Collect:

- process name and identifier;
- executable path;
- complete command line;
- parent and child processes;
- process creation time;
- user and security context;
- file hash;
- digital signature and publisher;
- file creation and modification timestamps;
- process network connections;
- related file and registry activity.

Review whether the process originated from an expected installation directory and whether its behavior is consistent with its documented purpose.

### Step 4 — Assess Input-Capture Indicators

Review available telemetry for behavior consistent with unauthorized keyboard input capture.

Depending on the operating system and available monitoring, relevant indicators may include:

- suspicious keyboard event monitoring;
- unexpected use of input interception APIs;
- repeated input-state polling by an unrelated process;
- unusual access to raw keyboard input interfaces;
- installation of unexpected input-related drivers;
- suspicious modifications to input-handling components;
- input-monitoring behavior occurring outside the expected operation of the application.

Differentiate authorized accessibility tools, input-method software, remote administration products, and approved endpoint utilities from unexplained or unauthorized behavior.

Do not classify a process as malicious solely because it accesses keyboard-related functionality. Validate the behavior against the software's expected purpose and the organization's approved software inventory.

### Step 5 — Review Persistence and System Modifications

Investigate whether the suspected process is associated with unauthorized persistence or changes to system configuration.

Review available evidence for:

- unexpected driver installation;
- suspicious registry modifications;
- unauthorized startup entries;
- newly created or modified scheduled tasks;
- unexpected service creation or modification;
- changes to system components;
- suspicious file placement;
- unusual privilege assignments;
- related WMI or other persistence activity.

Establish which account or process performed each modification and whether the activity corresponds to an approved installation, update, or administrative operation.

Correlate the modification timestamps with the suspected input-capture activity.

### Step 6 — Review Collected Artifacts and Network Activity

Investigate artifacts that may indicate the storage or transfer of captured input.

Review:

- files created or modified by the suspected process;
- unexpected logs or data files;
- unusual writes to temporary or user-writable directories;
- file sizes and modification patterns;
- access to sensitive application data;
- suspicious network connections;
- destination IP addresses and domains;
- DNS requests;
- connection timestamps and frequency;
- relevant endpoint or network security alerts.

Where evidence suggests possible data collection, preserve relevant artifacts using approved forensic procedures.

### Step 7 — Determine Credential Exposure and Scope

Correlate the suspected keylogging activity with authentication and endpoint telemetry.

Determine:

- whether the process was active during user authentication;
- which accounts were logged on to the affected system;
- whether privileged accounts were used;
- whether suspicious authentication occurred during or after the suspected exposure period;
- whether access originated from unusual locations or devices;
- whether the same process, file hash, or behavior exists on other systems;
- whether related malware, persistence, or data-transfer activity was identified.

Establish the earliest known activity, latest observed activity, and potential exposure window.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification, the affected assets and accounts, the potential exposure window, and any required containment or escalation actions.

## Evidence to Collect

| Evidence         | Description                                                                       |
| ---------------- | --------------------------------------------------------------------------------- |
| Alert            | Detection source, identifier, severity, and timestamp                             |
| Host             | Hostname, IP address, operating system, and asset criticality                     |
| User             | Associated accounts, account types, privileges, and logon context                 |
| Process          | Process identifiers, executable paths, command line, and lineage                  |
| File             | File hashes, signatures, paths, and timestamps                                    |
| Input Monitoring | Relevant input-capture and system API telemetry                                   |
| System Changes   | Registry modifications, driver activity, and configuration changes                |
| Persistence      | Startup entries, tasks, services, and other relevant mechanisms                   |
| File Activity    | Files created, modified, accessed, or potentially associated with collected input |
| Network          | Connection metadata, DNS activity, destinations, and timestamps                   |
| Authentication   | Relevant successful and failed authentication events                              |
| Scope            | Other affected systems, processes, and accounts                                   |
| Timeline         | Chronology of execution, collection indicators, and related events                |
| Findings         | Classification, evidence gaps, confidence, and response recommendations           |

## Decision Criteria

### Benign

Classify the activity as **benign** when sufficient evidence establishes that:

- the software is approved and its purpose is documented;
- observed input-monitoring behavior is expected for the application;
- the execution path and publisher are consistent with the approved installation;
- relevant system modifications are authorized;
- no unexplained collection or transfer activity is identified;
- no additional suspicious behavior is observed.

Document the operational justification before closing the investigation.

### Suspicious

Classify the activity as **suspicious** when one or more of the following conditions are present:

- unexpected keyboard monitoring is observed;
- an unknown process exhibits input-interception behavior;
- input-monitoring activity is inconsistent with the process's purpose;
- unexplained registry or driver modifications are identified;
- suspicious artifacts may contain captured input;
- outbound network activity is associated with the suspected process;
- relevant telemetry is incomplete;
- the possibility of credential exposure cannot be ruled out.

Continue investigation, preserve relevant evidence, and escalate according to organizational procedures where necessary.

### Malicious

Classify the activity as **malicious** when sufficient evidence confirms unauthorized input capture or establishes a malicious keylogging operation, such as:

- confirmed unauthorized recording of keyboard input;
- verified collection of credentials or sensitive user data;
- a malicious component performing input capture;
- unauthorized input-capture behavior associated with malware;
- confirmed transfer of collected information to an unauthorized destination;
- keylogging activity linked to broader compromise or malicious persistence.

Escalate to incident response and initiate approved containment, credential protection, and eradication procedures.

### Inconclusive

Use **inconclusive** when the available evidence is insufficient to determine whether the observed behavior is legitimate or malicious.

Document:

- evidence collected;
- unresolved indicators;
- unavailable telemetry;
- potentially affected users and systems;
- additional evidence required;
- recommended investigation actions.

Do not classify the activity as benign solely because malicious behavior could not be confirmed.

## Escalation

Escalate to incident response when:

- unauthorized input capture is confirmed;
- credential exposure is suspected or confirmed;
- privileged or administrative accounts may have been affected;
- suspicious driver installation or system modification is identified;
- collected information appears to have been transferred externally;
- multiple endpoints exhibit related behavior;
- the suspected process is associated with additional malware or persistence;
- the investigation cannot establish the extent of exposure within the required response timeframe.

Coordinate with identity security, endpoint security, threat hunting, and other relevant teams as required.

## Response Guidance

For confirmed or high-confidence malicious keylogging activity:

1. Preserve relevant endpoint, process, file, system modification, and network evidence.
2. Follow the organization's endpoint containment procedure when isolation is warranted.
3. Identify affected users, endpoints, privileged accounts, and the potential exposure window.
4. Coordinate password resets for potentially exposed credentials from a trusted device.
5. Revoke relevant sessions or tokens where exposure may have enabled unauthorized access.
6. Review multifactor authentication activity and investigate suspicious account use.
7. Identify related artifacts and behavior across the environment.
8. Remove unauthorized components and persistence mechanisms through approved eradication procedures after evidence preservation.
9. Validate endpoint integrity and confirm that the suspicious behavior has ceased.
10. Monitor affected accounts and systems for further suspicious activity.
11. Document containment, eradication, recovery, and follow-up actions.

Do not reset credentials, remove artifacts, terminate processes, or modify the affected system in a manner that unnecessarily destroys evidence or disrupts critical services before the response team has considered the operational and forensic requirements.

Credential protection measures should be prioritized according to the exposure risk.

## Related Detection Rules

## Related Playbooks

- `playbooks/collection/browser-data.md`
- `playbooks/collection/clipboard-theft.md`
- `playbooks/collection/screen-capture.md`
- `playbooks/credential-access/credential-access.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/triage/suspicious-process-triage.md`

## Validation

The playbook should be validated against approved endpoint telemetry, process execution records, input-monitoring indicators, system modification events, and controlled security test scenarios.

Validation should confirm that:

- keylogging-related alerts can be investigated using available telemetry;
- the affected host and user context can be established;
- suspicious input-capture behavior can be distinguished from approved software functionality;
- process lineage and relevant system changes can be correlated;
- potentially collected artifacts can be identified and preserved safely;
- related network and authentication activity can be investigated;
- potentially affected credentials and endpoints can be identified;
- investigation outcomes are consistently classified;
- escalation and response actions follow approved procedures.

Record the validation outcome and update the playbook when technical or operational changes affect its accuracy.

## Safety

This playbook is intended for defensive security operations, authorized incident response, security validation, and controlled laboratory environments.

Do not deploy keyloggers, capture real user keystrokes, collect actual passwords, or access sensitive user input for testing purposes.

Use synthetic data and approved test environments when validating detection and response capabilities.

Preserve evidence according to organizational procedures, restrict access to potentially captured sensitive information, and ensure that containment and remediation actions are properly authorized.
