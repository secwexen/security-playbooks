---
id: "cloud-exfiltration"
name: "Cloud Storage Exfiltration"
category: "exfiltration"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-08T17:33:00Z"
updated_at: "2026-10-08T17:33:00Z"
description: "Cloud storage exfiltration involves transferring data from an affected environment to an external or unauthorized cloud storage service."
objective: "Identify, investigate, and scope suspicious transfers of sensitive or collected data to cloud storage services and determine whether unauthorized exfiltration occurred."
severity: "high"
mitre_attack:
  - "T1567.002"
triggers:
  - "Unexpected upload of files or data to a cloud storage service"
  - "Large outbound transfer to an unauthorized cloud storage service"
  - "Sensitive files accessed shortly before cloud upload activity"
  - "Unexpected use of cloud storage APIs, synchronization clients, or upload utilities"
  - "Cloud storage activity associated with a compromised or unexpected account"
  - "Threat hunting identifies anomalous data transfer to cloud storage"
prerequisites:
  - "Access to endpoint process and file telemetry"
  - "Access to network or proxy telemetry"
  - "Access to identity and authentication telemetry"
  - "Access to cloud audit or application activity logs when available"
tags:
  - "cloud"
  - "exfiltration"
  - "cloud-storage"
  - "data-transfer"
  - "data-loss"
  - "web-service"
references:
  - "https://attack.mitre.org/techniques/T1567/002/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify Exfiltration Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, associated account, timestamp, transfer activity, and original alert context."
    expected_result: "The suspicious cloud storage transfer and associated alert context are identified."
  - id: "identify-cloud-service"
    order: 2
    name: "Identify Cloud Storage Service"
    action: "investigate"
    description: "Identify the cloud storage provider, destination domain or API endpoint, storage account where available, and whether the service is approved for organizational use."
    expected_result: "The cloud storage service and its authorization status are documented."
  - id: "identify-source-context"
    order: 3
    name: "Identify Source Context"
    action: "analyze"
    description: "Determine the source host, user account, process, application, client, or script responsible for the transfer."
    expected_result: "The source system, account, and initiating execution context are identified."
  - id: "review-data-access"
    order: 4
    name: "Review Data Access"
    action: "analyze"
    description: "Review files, directories, databases, or other data sources accessed before the transfer and determine whether sensitive or security-relevant information was involved."
    expected_result: "The potentially accessed or collected data and its sensitivity are characterized."
  - id: "review-upload-activity"
    order: 5
    name: "Review Upload Activity"
    action: "analyze"
    description: "Review upload timestamps, transfer volume, request patterns, protocols, client applications, and available cloud or network telemetry associated with the transfer."
    expected_result: "The cloud upload activity and relevant transfer characteristics are documented."
  - id: "review-destination-context"
    order: 6
    name: "Review Destination Context"
    action: "analyze"
    description: "Determine whether the destination account, storage location, domain, application, or API endpoint is expected and whether the transfer is consistent with approved business activity."
    expected_result: "The destination context and legitimacy of the transfer are assessed."
  - id: "determine-exfiltration-scope"
    order: 7
    name: "Determine Exfiltration Scope"
    action: "hunt"
    description: "Search for related uploads involving the same account, host, files, hashes, destination service, destination account, or transfer pattern across the environment."
    expected_result: "The prevalence, duration, and scope of the cloud storage exfiltration activity are determined."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the observed cloud storage transfer and document the evidence supporting the final assessment."
    expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "cloud-storage-exfiltration"
---

# Cloud Storage Exfiltration

## Purpose

This playbook provides a structured SOC workflow for investigating suspicious data transfers to external or unauthorized cloud storage services.

Cloud storage services may be legitimately used for collaboration, backup, synchronization, file sharing, and business operations. The presence of a cloud storage transfer does not by itself establish malicious activity.

The objective is to determine whether the observed transfer is legitimate, suspicious, or malicious and whether unauthorized exfiltration of organizational data occurred.

## MITRE ATT&CK

| Technique | Name                          | Relevance                                                                          |
| --------- | ----------------------------- | ---------------------------------------------------------------------------------- |
| T1567.002 | Exfiltration to Cloud Storage | Primary technique for transferring data to cloud storage services for exfiltration |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint uploads unexpected files to a cloud storage service.
- A large or unusual outbound transfer is directed to a cloud storage provider.
- Sensitive files are accessed shortly before cloud upload activity.
- An unexpected process, script, or utility performs cloud uploads.
- A compromised or unusual account accesses a cloud storage service.
- Cloud audit logs identify anomalous file upload or creation activity.
- Threat hunting identifies abnormal cloud storage transfer behavior.

## Scope

The investigation should consider:

- affected host;
- associated user account;
- source IP address;
- process or application;
- cloud storage provider;
- destination domain;
- destination account;
- destination storage location;
- API endpoint;
- uploaded files;
- file paths;
- file hashes;
- data sensitivity;
- transfer size;
- transfer timestamps;
- upload frequency;
- network protocol;
- authentication context;
- cloud audit activity;
- related alerts;
- additional affected hosts or accounts.

## Investigation Procedure

### Step 1 — Identify Exfiltration Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated account;
- destination service;
- transfer details;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify Cloud Storage Service

Determine:

- cloud storage provider;
- destination domain;
- destination IP where available;
- API endpoint where available;
- storage account where available;
- client application;
- whether the service is organization-approved;
- whether the destination account is authorized.

Do not classify a cloud storage service as malicious solely because it is external. Evaluate whether its use is consistent with approved organizational activity.

### Step 3 — Identify Source Context

Determine:

- hostname;
- IP address;
- username;
- account type;
- authentication context;
- initiating process;
- parent process;
- executable path;
- command line;
- synchronization client or upload utility.

Assess whether the initiating account, process, and host are expected to perform the observed transfer.

### Step 4 — Review Data Access

Review activity immediately preceding the transfer.

Identify:

- accessed files;
- accessed directories;
- sensitive data repositories;
- recently collected files;
- archives;
- temporary files;
- database exports;
- credentials or secrets where authorized for investigation;
- file hashes.

Determine whether the accessed data contains confidential, regulated, proprietary, or security-sensitive information.

Do not assume that all uploaded data was successfully exfiltrated. Confirm transfer activity using available endpoint, network, or cloud telemetry.

### Step 5 — Review Upload Activity

Review:

- transfer timestamp;
- transfer duration;
- transferred volume;
- number of uploaded objects;
- upload frequency;
- source process;
- request method where available;
- destination domain;
- destination account;
- API activity;
- network connection metadata.

Look for:

- unusually large transfers;
- repeated uploads;
- transfers outside normal working patterns;
- uploads initiated by unusual processes;
- compressed archives followed by cloud uploads;
- sensitive files transferred to unauthorized destinations.

### Step 6 — Review Destination Context

Determine whether the destination is:

- an approved corporate cloud account;
- an approved business application;
- a personal account;
- an unknown account;
- an attacker-controlled or otherwise unauthorized location.

Review available:

- cloud audit logs;
- identity events;
- authentication history;
- sharing activity;
- object creation events;
- object modification events;
- account ownership information;
- application authorization records.

Correlate the destination activity with the user's normal business role and approved workflows.

### Step 7 — Determine Exfiltration Scope

Search the environment for:

- same destination domain;
- same destination account;
- same cloud application;
- same source account;
- same source host;
- same process or upload utility;
- same file hash;
- same file names or archive names;
- similar transfer volumes;
- similar upload patterns.

Determine:

- number of affected hosts;
- number of affected accounts;
- number of transferred objects;
- estimated data volume;
- earliest observed transfer;
- latest observed transfer;
- whether the activity remains active;
- whether other users or systems were involved.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence            | Description                                                   |
| ------------------- | ------------------------------------------------------------- |
| Alert               | Detection source, identifier, timestamp, severity             |
| Host                | Hostname, IP address, operating system                        |
| User                | Account and authentication context                            |
| Process             | Initiating process and execution metadata                     |
| Command Line        | Full observed command line where available                    |
| Cloud Service       | Provider, domain, application, API endpoint                   |
| Destination         | Destination account and storage location                      |
| Files               | Accessed and transferred files                                |
| Hashes              | SHA-256 or other available hashes                             |
| Data Classification | Sensitivity and business classification                       |
| Transfer            | Volume, duration, timestamps, frequency                       |
| Network             | Connections, domains, IPs, protocols                          |
| Cloud Audit         | Upload, create, share, and authentication events              |
| Scope               | Additional affected hosts and accounts                        |
| Detections          | Related security alerts                                       |
| Timeline            | Correlated file, process, identity, network, and cloud events |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the cloud storage service is approved;
- the destination account is authorized;
- the user and host are expected to perform the transfer;
- the transferred data is appropriate for the business process;
- the transfer volume and timing are consistent with normal activity;
- no suspicious related activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the destination service is unexpected;
- the destination account is unknown;
- the source process is unusual;
- the transfer volume is anomalous;
- sensitive data may have been involved;
- the transfer occurs outside expected operational patterns;
- related telemetry is incomplete;
- unauthorized activity cannot yet be confirmed or ruled out.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized transfer of sensitive or proprietary data;
- confirmed use of an unauthorized cloud storage destination;
- confirmed exfiltration associated with account compromise;
- malicious collection followed by cloud upload;
- repeated unauthorized transfers;
- cloud uploads associated with malware or a broader compromise;
- confirmed attacker-controlled destination activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the cloud storage activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- telemetry gaps;
- additional data required;
- follow-up investigation actions.

## Escalation

Escalate the investigation when:

- unauthorized exfiltration is confirmed;
- sensitive or regulated data is involved;
- a compromised account is associated with the transfer;
- an attacker-controlled destination is identified;
- multiple hosts or accounts are affected;
- large-scale transfer activity is observed;
- exfiltration is ongoing;
- credential access, persistence, lateral movement, or command-and-control activity is identified.

## Response Guidance

For confirmed malicious cloud storage exfiltration:

1. Preserve endpoint, network, identity, and cloud audit evidence.
2. Identify all affected hosts, accounts, destinations, and transferred data.
3. Follow the organization's approved containment procedure.
4. Terminate or restrict unauthorized sessions and cloud access according to approved response procedures.
5. Review potentially compromised user and service accounts.
6. Investigate related collection, credential access, persistence, lateral movement, and command-and-control activity.
7. Search for additional uploads using known files, hashes, domains, accounts, and behavioral indicators.
8. Coordinate with data owners, cloud administrators, legal, privacy, or compliance teams when required.
9. Assess whether the incident meets organizational data-loss or breach notification criteria.
10. Document the investigation timeline, scope, containment actions, and recovery activities.

Do not delete cloud objects, terminate accounts, or remove endpoint artifacts before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

## Related Playbooks

- `playbooks/cloud/cloud-storage-object-discovery.md`
- `playbooks/exfiltration/data-exfiltration.md`
- `playbooks/triage/data-exfiltration-triage.md`
- `playbooks/response/data-exfiltration-response.md`

## Validation

The playbook should be validated against approved cloud storage services, endpoint process telemetry, file-access telemetry, network or proxy logs, identity telemetry, and cloud audit data.

Validation should confirm that:

- approved and unauthorized cloud storage services can be distinguished;
- source accounts and hosts can be identified;
- initiating processes can be correlated with upload activity;
- accessed and transferred data can be identified where telemetry permits;
- transfer volume and timing can be evaluated;
- destination accounts and storage locations can be assessed;
- cloud audit events can be correlated with endpoint and network activity;
- environmental scope can be determined;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Investigation and containment actions must follow approved evidence-preservation, access-control, privacy, and change-management procedures. Do not intentionally upload sensitive data to external cloud services or perform unauthorized data-exfiltration testing on production systems.
