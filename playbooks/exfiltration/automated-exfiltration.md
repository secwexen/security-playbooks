---
id: "automated-exfiltration"
name: "Automated Exfiltration"
category: "exfiltration"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-07T17:29:00Z"
updated_at: "2026-10-07T17:29:00Z"
description: "Automated Exfiltration involves the automated transfer of collected data from a compromised environment to an external destination."
objective: "Identify, investigate, and scope automated data exfiltration activity and determine whether collected data was transferred without authorization."
severity: "high"
mitre_attack:
  - "T1020"
triggers:
  - "Repeated automated outbound data transfers"
  - "Scheduled or background process transmitting data to an external destination"
  - "Script or utility repeatedly transferring collected files"
  - "Unexpected periodic connections associated with data transfer"
  - "Threat hunting identifies recurring outbound transfer behavior"
prerequisites:
  - "Access to process creation telemetry"
  - "Access to network connection telemetry"
  - "Access to file and data access telemetry"
  - "Access to authentication and account telemetry"
  - "Access to endpoint and network investigation capabilities"
tags:
  - "automated-exfiltration"
  - "exfiltration"
  - "data-transfer"
  - "network"
  - "collection"
  - "endpoint"
  - "threat-hunting"
references:
  - "https://attack.mitre.org/techniques/T1020/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify Automated Exfiltration Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, associated account, transfer mechanism, destination, timestamps, and alert context."
    expected_result: "The suspected automated exfiltration activity and affected asset are identified."
  - id: "identify-transfer-mechanism"
    order: 2
    name: "Identify Transfer Mechanism"
    action: "analyze"
    description: "Determine which process, script, scheduled task, background service, or application performed or initiated the recurring data transfer."
    expected_result: "The transfer mechanism and associated execution context are documented."
  - id: "identify-transferred-data"
    order: 3
    name: "Identify Transferred Data"
    action: "analyze"
    description: "Determine what files, records, archives, or other data may have been accessed, staged, and transferred."
    expected_result: "The potentially exfiltrated data and available evidence of data access are identified."
  - id: "review-transfer-pattern"
    order: 4
    name: "Review Transfer Pattern"
    action: "analyze"
    description: "Review transfer frequency, timing, volume, duration, protocol, destination, and recurrence to determine whether the activity is automated."
    expected_result: "The transfer pattern is characterized and recurring automated behavior is identified or ruled out."
  - id: "review-execution-context"
    order: 5
    name: "Review Execution Context"
    action: "analyze"
    description: "Review the associated account, process chain, command line, script, scheduled execution, service context, and host role."
    expected_result: "The execution context and authorization of the automated transfer are assessed."
  - id: "review-destination"
    order: 6
    name: "Review Destination"
    action: "analyze"
    description: "Assess the transfer destination, ownership, reputation, network location, expected relationship, and observed communication history."
    expected_result: "The destination is characterized and its legitimacy is assessed."
  - id: "determine-exfiltration-scope"
    order: 7
    name: "Determine Exfiltration Scope"
    action: "hunt"
    description: "Search for the same transfer mechanism, destination, account, process, file pattern, command line, and recurring behavior across the environment."
    expected_result: "The prevalence, affected assets, accounts, destinations, and potential exfiltration scope are determined."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity and document the evidence supporting the final assessment."
    expected_result: "The activity receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "automated-exfiltration"
---

# Automated Exfiltration

## Purpose

This playbook provides a structured SOC workflow for investigating automated data exfiltration activity.

Automated exfiltration may involve scripts, scheduled tasks, background processes, services, or other mechanisms that repeatedly transfer collected data to an external destination. Automated and recurring transmission patterns should be investigated together with process, account, file, destination, and network context.

The objective is to determine whether the observed transfer is legitimate, suspicious, or malicious and whether unauthorized data was transferred from the environment.

## MITRE ATT&CK

| Technique | Name                   | Relevance                                                  |
| --------- | ---------------------- | ---------------------------------------------------------- |
| T1020     | Automated Exfiltration | Primary technique for automated transfer of collected data |

T1020 is an Enterprise ATT&CK technique under the Exfiltration tactic (TA0010).

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Repeated outbound data transfers to an external destination.
- A scheduled or background process periodically transmits data.
- A script or utility repeatedly uploads collected files.
- Automated transfer behavior is observed outside expected business operations.
- Threat hunting identifies recurring outbound communication associated with data transfer.

## Scope

The investigation should consider:

- affected host;
- associated account;
- process and process chain;
- command line;
- script or executable;
- scheduled task or background execution mechanism;
- source files or data;
- staging location;
- transfer frequency;
- transfer volume;
- transfer timestamps;
- protocol;
- destination IP address;
- destination domain;
- destination ownership;
- destination reputation;
- related authentication activity;
- related network activity;
- additional affected hosts;
- additional affected accounts.

## Investigation Procedure

### Step 1 — Identify Automated Exfiltration Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user or service account;
- process or application;
- destination;
- transfer protocol;
- observed recurrence;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify Transfer Mechanism

Determine which mechanism performed or initiated the transfer.

Review:

- process name;
- executable path;
- command line;
- parent process;
- child processes;
- script path;
- scheduled task;
- service;
- cron or equivalent background mechanism;
- application or synchronization component.

Determine whether the mechanism is:

- approved;
- expected on the host;
- associated with a known application;
- associated with administrative activity; or
- unexpected.

A legitimate transfer utility does not by itself establish benign activity.

### Step 3 — Identify Transferred Data

Determine what data may have been accessed, staged, or transmitted.

Review:

- file names;
- file paths;
- file extensions;
- archives;
- database records;
- configuration files;
- credentials or secrets;
- business-sensitive documents;
- staging directories;
- temporary files.

Correlate file access and creation activity with the observed transfer window.

Where technically and legally appropriate, preserve copies or hashes of relevant artifacts for investigation.

### Step 4 — Review Transfer Pattern

Analyze the transfer behavior for automation indicators.

Review:

- recurring time intervals;
- scheduled execution;
- transfer volume;
- transfer duration;
- transfer frequency;
- destination consistency;
- repeated process execution;
- repeated file access;
- background execution.

Pay particular attention to periodic behavior such as repeated transfers at regular intervals.

Current MITRE detection guidance specifically describes automated tools or scripts periodically transmitting data to external destinations through scheduled tasks or background processes.

### Step 5 — Review Execution Context

Determine:

- associated account;
- account type;
- privilege context;
- host role;
- process chain;
- command line;
- script content;
- execution time;
- scheduled execution context;
- related process activity.

Assess whether the observed transfer is consistent with an approved backup, synchronization, monitoring, or application workflow.

Do not classify recurring network communication as malicious solely because it is periodic.

### Step 6 — Review Destination

Assess the destination:

- IP address;
- domain;
- port;
- protocol;
- hosting provider;
- ownership;
- geographic context where relevant;
- reputation;
- historical communication;
- organizational allowlist status;
- relationship to the affected application or user.

Determine whether the destination is:

- internal;
- approved external;
- previously known;
- newly observed;
- uncommon;
- unauthorized; or
- associated with suspicious infrastructure.

### Step 7 — Determine Exfiltration Scope

Search the environment for:

- the same process or script;
- the same command line;
- the same destination;
- the same account;
- the same file path pattern;
- the same transfer schedule;
- the same archive names;
- the same file hashes;
- similar recurring transfer behavior.

Determine:

- number of affected hosts;
- number of affected accounts;
- volume of potentially transferred data;
- earliest observed transfer;
- latest observed transfer;
- number of external destinations;
- whether transfers are still occurring.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence       | Description                                                    |
| -------------- | -------------------------------------------------------------- |
| Alert          | Detection source, identifier, severity, timestamp              |
| Host           | Hostname, IP address, operating system, host role              |
| Account        | User or service account associated with the activity           |
| Process        | Process name, PID, path, parent and child processes            |
| Command Line   | Complete observed command line                                 |
| Script         | Relevant script or automation content                          |
| Schedule       | Scheduled task, cron, service, or background execution details |
| Files          | Files accessed, staged, created, or transferred                |
| Data           | Type and sensitivity of potentially transferred data           |
| Network        | Destination, port, protocol, timing, and transfer volume       |
| Destination    | Ownership, reputation, and organizational relationship         |
| Authentication | Related account activity                                       |
| Timeline       | Process, file, schedule, and network timestamps                |
| Scope          | Other affected hosts, accounts, and destinations               |
| Detections     | Related security alerts and telemetry                          |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the transfer mechanism is approved;
- the destination is authorized;
- the account and host context are expected;
- the transferred data is consistent with an approved business process;
- the recurring schedule is documented;
- no unauthorized access or suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the transfer mechanism is unexpected;
- the destination is unusual or previously unseen;
- recurring transfers cannot be explained;
- the account or execution context is abnormal;
- sensitive data appears to be involved;
- staging activity is observed;
- supporting telemetry is incomplete;
- malicious activity cannot yet be ruled out.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized automated data transfer;
- confirmed transfer of sensitive or restricted data to an unauthorized destination;
- malicious scripts or processes performing recurring transfers;
- exfiltration associated with confirmed compromise;
- unauthorized staging followed by outbound transfer;
- transfer activity associated with credential theft, persistence, lateral movement, or command-and-control;
- other confirmed malicious exfiltration behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the transfer is legitimate or unauthorized.

Document:

- evidence collected;
- evidence unavailable;
- telemetry limitations;
- additional data required.

## Escalation

Escalate the investigation when:

- unauthorized external data transfer is confirmed;
- sensitive or regulated information may have been transferred;
- the destination is confirmed malicious or unauthorized;
- automated transfers remain active;
- multiple hosts or accounts are affected;
- large volumes of data may have been transferred;
- malicious scripts or processes are involved;
- additional compromise activity is identified;
- the incident may require legal, regulatory, or privacy review.

## Response Guidance

For confirmed malicious automated exfiltration:

1. Preserve process, file, account, network, and transfer evidence.
2. Determine whether automated transfers are still active.
3. Identify all affected hosts, accounts, destinations, and data sets.
4. Follow the organization's approved containment procedure.
5. Disable or block the unauthorized transfer mechanism where authorized.
6. Investigate the origin and collection activity that preceded the transfer.
7. Search for related compromise activity across the environment.
8. Assess whether sensitive or regulated information was exposed.
9. Coordinate incident response, legal, privacy, and other required functions according to organizational policy.
10. Document the investigation timeline, containment actions, affected data, and final assessment.

Do not delete staging files, disable scheduled tasks, terminate suspicious processes, or block destinations before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

## Related Playbooks

- `playbooks/exfiltration/data-exfiltration.md`
- `playbooks/exfiltration/cloud-exfiltration.md`
- `playbooks/exfiltration/dns-exfiltration.md`
- `playbooks/triage/data-exfiltration-triage.md`

## Validation

The playbook should be validated against approved endpoint and network telemetry, scheduled execution scenarios, recurring transfer patterns, controlled data staging, and authorized automated transfer scenarios.

Validation should confirm that:

- automated transfer mechanisms can be identified;
- recurring transfer behavior can be characterized;
- transferred data can be scoped;
- process and account context can be determined;
- destination legitimacy can be assessed;
- affected hosts and accounts can be identified;
- benign automation can be distinguished from unauthorized exfiltration;
- escalation criteria produce consistent investigation outcomes.

MITRE's current Automated Exfiltration detection strategy includes process creation and network connection telemetry and uses recurring transfer behavior as a detection signal.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not intentionally exfiltrate production data or transmit sensitive information to unauthorized destinations. Controlled validation should use synthetic or approved test data and authorized test infrastructure.

Data preservation, containment, blocking, and removal actions must follow organizational authorization and evidence-preservation procedures.
