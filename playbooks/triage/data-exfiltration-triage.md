---
id: "data-exfiltration-triage"
name: "Data Exfiltration Triage"
category: "triage"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-03T17:10:00Z"
updated_at: "2026-09-04T23:51:00Z"
description: "Investigate suspected unauthorized data exfiltration and determine whether data was transferred outside the organization's authorized environment."
objective: "Determine whether data exfiltration occurred, identify the affected data and transfer path, establish scope, and determine whether incident response is required."
severity: "critical"
mitre_attack:
  - "T1041"
  - "T1567"
triggers:
  - "Suspected data exfiltration alert"
  - "Unexpected outbound data transfer"
  - "Unusual volume of outbound traffic"
  - "Sensitive data transfer to an external destination"
  - "Suspicious cloud storage upload"
  - "Threat hunting identifies anomalous outbound data activity"
prerequisites:
  - "Access to network telemetry"
  - "Access to endpoint telemetry"
  - "Access to proxy, firewall, or DNS telemetry where available"
  - "Access to data classification or file metadata"
tags:
  - "exfiltration"
  - "triage"
  - "network"
  - "data-loss"
  - "investigation"
references:
  - "https://attack.mitre.org/techniques/T1041/"
  - "https://attack.mitre.org/techniques/T1567/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Exfiltration Alert"
  action: "investigate"
  description: "Identify the detection source, affected host or account, timestamp, and suspected transfer activity."
  expected_result: "The suspected exfiltration event and affected assets are identified."
- id: "identify-data"
  order: 2
  name: "Identify Potentially Exfiltrated Data"
  action: "analyze"
  description: "Determine what data may have been transferred and assess its sensitivity and business relevance."
  expected_result: "The potentially affected data and its sensitivity are documented."
- id: "review-transfer"
  order: 3
  name: "Review Transfer Activity"
  action: "analyze"
  description: "Review destination, protocol, volume, timing, and transfer characteristics."
  expected_result: "The suspected transfer path and characteristics are documented."
- id: "review-source-context"
  order: 4
  name: "Review Source Context"
  action: "analyze"
  description: "Review the source host, user or service account, process, and application associated with the transfer."
  expected_result: "The source context and responsible identity are identified."
- id: "review-destination"
  order: 5
  name: "Review Destination"
  action: "analyze"
  description: "Assess the destination domain, IP address, cloud service, or external system and determine whether it is authorized."
  expected_result: "The destination is classified as authorized, suspicious, or unauthorized."
- id: "correlate-related-activity"
  order: 6
  name: "Correlate Related Activity"
  action: "hunt"
  description: "Search for related compression, staging, file access, authentication, process, and network activity."
  expected_result: "Related attack activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Exfiltration Scope"
  action: "hunt"
  description: "Search across the environment for related transfers, destinations, hosts, users, and indicators."
  expected_result: "The scope of the suspected exfiltration is determined."
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
  scenario: "data-exfiltration"
---

# Data Exfiltration Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspected unauthorized data exfiltration.

The objective is to determine whether data was transferred outside the organization's authorized environment, identify the affected data and transfer path, establish scope, and determine whether incident response is required.

## MITRE ATT&CK

| Technique | Name                          | Relevance                                                                            |
| --------- | ----------------------------- | ------------------------------------------------------------------------------------ |
| T1041     | Exfiltration Over C2 Channel  | Relevant when data is transferred through an established command-and-control channel |
| T1567     | Exfiltration Over Web Service | Relevant when data is transferred to an external web service or cloud service        |

Additional ATT&CK techniques should only be mapped when supported by the observed exfiltration behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An exfiltration detection is generated.
- Unexpected outbound data transfer is observed.
- An unusual volume of outbound traffic is identified.
- Sensitive or regulated data is transferred to an external destination.
- A suspicious upload to a cloud storage or web service is detected.
- Threat hunting identifies anomalous outbound data activity.
- Multiple related network events suggest possible data staging or transfer.

## Scope

The investigation should consider:

- affected host;
- associated user or service account;
- source IP;
- source process;
- source application;
- destination IP;
- destination domain;
- destination service;
- protocol;
- transfer volume;
- transfer time;
- file or dataset involved;
- data classification;
- staging activity;
- compression or archiving;
- encryption;
- DNS activity;
- proxy or firewall events;
- related detections;
- additional affected hosts or accounts.

## Triage Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- affected user or account;
- detection severity;
- reason for detection.

Preserve the original alert context before making containment or remediation changes.

### Step 2 — Identify Potentially Exfiltrated Data

Determine what data may have been transferred.

Identify:

- file names;
- directories;
- datasets;
- cloud objects;
- database records;
- document types;
- data classification;
- sensitivity;
- business owner where available.

Determine whether the data contains:

- credentials;
- personal information;
- financial information;
- intellectual property;
- confidential business information;
- regulated information.

Do not access sensitive content beyond what is necessary and authorized for the investigation.

### Step 3 — Review Transfer Activity

Review:

- transfer timestamp;
- source;
- destination;
- protocol;
- port;
- transfer volume;
- transfer frequency;
- session duration;
- connection pattern.

Determine whether the volume and timing are consistent with legitimate business activity.

Pay attention to:

- unusually large transfers;
- repeated uploads;
- transfer outside expected operating periods;
- transfers involving newly observed destinations;
- unexpected encrypted or tunneled traffic.

### Step 4 — Review Source Context

Identify the system and identity responsible for the transfer.

Collect:

- hostname;
- IP address;
- username;
- service account;
- process;
- parent process;
- application;
- command line where available.

Determine whether the transfer was initiated by:

- an approved business application;
- an administrator;
- an automated service;
- an unexpected process;
- an unauthorized user or process.

### Step 5 — Review Destination

Assess the destination:

- IP address;
- domain;
- URL where available;
- cloud service;
- hosting provider;
- geographic context;
- reputation;
- organizational ownership.

Determine whether the destination is:

- approved;
- known and legitimate;
- previously unseen;
- suspicious;
- explicitly unauthorized.

Consider whether the destination is commonly used for legitimate business transfers or whether it presents an unusual data-transfer path.

### Step 6 — Review Staging and Preparation Activity

Search for evidence that data was prepared before transfer.

Review:

- archive creation;
- compression;
- temporary staging directories;
- file collection;
- file copies;
- renaming;
- encryption;
- creation of large temporary files.

Correlate staging activity with subsequent outbound connections.

### Step 7 — Correlate Related Activity

Search for:

- process creation;
- file access;
- authentication;
- privilege changes;
- cloud activity;
- DNS activity;
- proxy logs;
- firewall logs;
- C2 activity;
- persistence;
- credential access.

Determine whether the suspected exfiltration is part of a larger attack chain.

### Step 8 — Determine Environmental Scope

Search across the environment for:

- the same destination;
- the same domain;
- the same IP address;
- the same process;
- the same command line;
- the same file or archive name;
- the same user activity;
- similar transfer volumes.

Determine:

- number of affected hosts;
- number of affected accounts;
- earliest observed activity;
- latest observed activity;
- whether the transfer is still active.

### Step 9 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence       | Description                                        |
| -------------- | -------------------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp          |
| Host           | Hostname, IP address, operating system             |
| User           | Associated user or service account                 |
| Source Process | Process or application responsible for transfer    |
| Data           | Potentially transferred files or datasets          |
| Classification | Sensitivity or data classification                 |
| Destination    | IP, domain, cloud service, or external system      |
| Protocol       | Network protocol and port                          |
| Volume         | Estimated transfer size                            |
| Timeline       | Start, end, and related timestamps                 |
| Staging        | Archive, compression, or temporary artifacts       |
| Network        | Proxy, firewall, DNS, and related network activity |
| Authentication | Related account activity                           |
| Detections     | Related security alerts                            |
| Scope          | Other affected hosts and accounts                  |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the transfer is approved;
- the destination is authorized;
- the application or process is legitimate;
- the data transfer is expected;
- the volume and timing are consistent with normal operations;
- no additional suspicious indicators are identified.

Document the business justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the destination is unusual or previously unseen;
- the transfer volume is anomalous;
- sensitive data may be involved;
- staging or compression activity is present;
- the responsible process or account is unexpected;
- related telemetry indicates possible compromise;
- additional investigation is required.

Continue investigation and correlate additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized data transfer;
- confirmed attacker-controlled destination;
- confirmed exfiltration of sensitive data;
- exfiltration associated with a known compromise;
- suspicious staging followed by unauthorized outbound transfer;
- coordinated exfiltration across multiple systems.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to establish whether the transfer was authorized or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- sensitive or regulated data may have been transferred;
- an unauthorized destination is identified;
- multiple systems or accounts are affected;
- exfiltration is associated with malware or C2 activity;
- privileged accounts are involved;
- the transfer is ongoing;
- business-critical data may be affected.

## Response Guidance

For confirmed unauthorized exfiltration:

1. Preserve relevant network, endpoint, and file evidence.
2. Follow the organization's containment procedure.
3. Stop or restrict ongoing unauthorized transfer when authorized.
4. Identify affected systems, accounts, and data.
5. Search for related exfiltration indicators across the environment.
6. Review credential and account compromise.
7. Determine the affected data scope and applicable reporting requirements.
8. Escalate to incident response.
9. Document the investigation timeline and actions taken.

Do not destroy staging files, logs, or other relevant evidence before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/suricata/network-alert.rules`
- `detection-rules/suricata/dns-exfiltration.rules`
- `detection-rules/suricata/powershell-alert.rules`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/sigma/suspicious-login.yml`

## Related Playbooks

- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/exfiltration/data-exfiltration.md`
- `playbooks/exfiltration/cloud-exfiltration.md`
- `playbooks/exfiltration/dns-exfiltration.md`
- `playbooks/response/data-exfiltration-response.md`
- `playbooks/response/isolate-host-response.md`
- `playbooks/response/account-compromise-response.md`

## Validation

The playbook should be validated against approved exfiltration test data, network telemetry, and controlled security scenarios.

Validation should confirm that:

- suspicious outbound transfers can be identified;
- affected data can be characterized;
- transfer sources and destinations can be investigated;
- staging activity can be correlated;
- environmental scope can be determined;
- authorized transfers can be distinguished from suspicious activity;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Handling of sensitive data, containment of network traffic, and interruption of active transfers must follow applicable authorization, evidence-preservation, privacy, and incident-response procedures.
