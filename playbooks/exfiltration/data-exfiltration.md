---
id: "data-exfiltration"
name: "Data Exfiltration"
category: "exfiltration"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-05T16:42:00Z"
updated_at: "2026-10-05T16:28:00Z"
description: "Investigate suspected unauthorized transfer of data from an affected environment to an external or attacker-controlled destination."
objective: "Determine whether data was exfiltrated, identify the transferred data and transfer mechanism, establish the affected scope, and support appropriate containment and response actions."
severity: "high"
mitre_attack:
  - "T1020"
  - "T1041"
triggers:
  - "Unexpected outbound transfer of sensitive data"
  - "Abnormal outbound traffic volume associated with file or data access"
  - "Suspicious transfer of archives or collected files"
  - "Known or suspicious command-and-control channel carrying unusually large outbound data"
  - "Data Loss Prevention alert indicating potential unauthorized data transfer"
  - "Threat hunting identifies anomalous data transfer activity"
prerequisites:
  - "Access to network traffic or network connection telemetry"
  - "Access to endpoint file and process telemetry"
  - "Access to authentication and account telemetry"
  - "Access to data classification or sensitivity information where available"
  - "Access to relevant proxy, firewall, DNS, or cloud service logs where applicable"
tags:
  - "exfiltration"
  - "data-transfer"
  - "collection"
  - "network"
  - "c2"
  - "incident-response"
  - "windows"
references:
  - "https://attack.mitre.org/techniques/T1020/"
  - "https://attack.mitre.org/techniques/T1041/"
steps:
  - id: "identify-exfiltration-alert"
    order: 1
    name: "Identify Exfiltration Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, associated account, timestamp, destination, observed transfer, and alert context."
    expected_result: "The suspected exfiltration activity and associated asset are identified."
  - id: "identify-transferred-data"
    order: 2
    name: "Identify Transferred Data"
    action: "analyze"
    description: "Determine what files, records, archives, credentials, or other information may have been transferred."
    expected_result: "The potentially exfiltrated data and its sensitivity are documented."
  - id: "review-transfer-activity"
    order: 3
    name: "Review Transfer Activity"
    action: "analyze"
    description: "Review network connections, transfer volume, timing, protocol, destination, process context, and file access associated with the suspected transfer."
    expected_result: "The transfer mechanism, timing, volume, and associated activity are characterized."
  - id: "review-source-context"
    order: 4
    name: "Review Source Context"
    action: "analyze"
    description: "Review the source host, user account, initiating process, command line, accessed files, and preceding collection or staging activity."
    expected_result: "The source system, account, process, and preceding data access activity are documented."
  - id: "review-destination"
    order: 5
    name: "Review Destination"
    action: "analyze"
    description: "Assess the destination domain, IP address, service, account, infrastructure relationship, and reputation using available telemetry and approved intelligence sources."
    expected_result: "The destination is assessed for legitimacy, ownership, and relevance to the suspected exfiltration."
  - id: "correlate-related-activity"
    order: 6
    name: "Correlate Related Activity"
    action: "hunt"
    description: "Correlate process, file access, archive creation, authentication, DNS, proxy, firewall, and command-and-control activity before and after the suspected transfer."
    expected_result: "Related collection, staging, execution, and network activity are identified and correlated."
  - id: "determine-exfiltration-scope"
    order: 7
    name: "Determine Exfiltration Scope"
    action: "hunt"
    description: "Search the environment for the same destination, source process, account, file hash, archive name, transfer pattern, or related activity across additional hosts."
    expected_result: "The number of affected hosts, accounts, destinations, and potentially exfiltrated datasets is determined."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity based on the available evidence and document the rationale, confirmed scope, and response requirements."
    expected_result: "The investigation receives a documented final outcome and escalation decision."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "data-exfiltration"
---

# Data Exfiltration

## Purpose

This playbook provides a structured workflow for investigating suspected unauthorized transfer of data from an affected environment to an external or attacker-controlled destination.

The objective is to determine:

- whether data was transferred outside the expected trust boundary;
- what information may have been transferred;
- which account, process, host, and destination were involved;
- whether the activity was authorized;
- whether related collection, staging, or command-and-control activity occurred; and
- whether additional systems or datasets were affected.

Data exfiltration may involve automated transfer, transfer over an existing command-and-control channel, alternate network protocols, web services, cloud storage, or other communication mechanisms. MITRE ATT&CK identifies `T1020` for Automated Exfiltration and `T1041` for Exfiltration Over C2 Channel.

### Data Exfiltration Context

Data transfer should not be classified as malicious solely because data moved to an external destination.

The investigation should establish:

- whether the transfer was authorized;
- whether the destination is approved;
- whether the transferred data was sensitive;
- whether the source process and account were expected;
- whether collection or staging occurred before transfer; and
- whether the transfer pattern is consistent with normal business operations.

Data staging may occur before exfiltration and can involve local or remote staging locations.

## MITRE ATT&CK

| Technique | Name                         | Relevance                                                                                   |
| --------- | ---------------------------- | ------------------------------------------------------------------------------------------- |
| T1020     | Automated Exfiltration       | Relevant when data is transferred using automated processing or scheduled transfer behavior |
| T1041     | Exfiltration Over C2 Channel | Relevant when data is transferred through an existing command-and-control channel           |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Unexpected outbound transfer of sensitive data.
- Abnormal outbound traffic volume associated with file or data access.
- Suspicious transfer of archives or collected files.
- A command-and-control channel carries unusually large or unexpected outbound data.
- A DLP control reports potential unauthorized data transfer.
- Threat hunting identifies anomalous data transfer activity.
- A suspicious process accesses sensitive files followed by outbound communication.

## Scope

The investigation should consider:

- affected host;
- associated user account;
- source process;
- parent and child processes;
- command line;
- accessed files and directories;
- file hashes;
- archive artifacts;
- data sensitivity;
- collection and staging activity;
- source IP address;
- destination IP address;
- destination domain;
- destination service;
- destination account;
- protocol;
- port;
- transfer volume;
- transfer timestamps;
- DNS activity;
- proxy activity;
- firewall activity;
- cloud service activity;
- related authentication events;
- additional affected hosts and accounts.

## Investigation Procedure

### Step 1 — Identify Exfiltration Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- source process;
- destination;
- observed transfer volume;
- detection reason.

Preserve the original alert context before making containment or remediation changes.

### Step 2 — Identify Transferred Data

Determine what information may have been transferred.

Review:

- file names;
- file paths;
- file types;
- archive names;
- database records;
- credentials or secrets;
- configuration data;
- intellectual property;
- regulated or sensitive information.

Determine the sensitivity and business ownership of the potentially transferred data.

Do not assume that all accessed files were successfully exfiltrated.

### Step 3 — Review Transfer Activity

Review:

- source IP;
- destination IP;
- destination domain;
- destination port;
- protocol;
- connection timestamps;
- connection duration;
- transfer volume;
- transfer direction;
- repeated connections;
- upload activity;
- process associated with the connection.

Compare the observed traffic with normal activity for the host, account, process, and destination.

Unexpected outbound volume following access to sensitive files should receive increased investigative priority. Detection guidance for `T1041` specifically considers anomalous outbound traffic associated with preceding file or data access.

### Step 4 — Review Source Context

Review the source endpoint and associated activity.

Collect:

- initiating process;
- parent process;
- child processes;
- complete command line;
- user account;
- logon context;
- accessed files;
- archive creation;
- temporary files;
- staging directories;
- relevant scheduled or automated tasks.

Determine whether collection or staging occurred before the transfer.

Data staging may be used to consolidate data before exfiltration and can reduce the number of connections made to an external destination.

### Step 5 — Review Destination

Assess:

- destination ownership;
- destination service;
- destination reputation;
- destination account where available;
- whether the destination is organization-approved;
- whether the destination was previously observed;
- whether the destination is associated with known infrastructure;
- whether the destination is consistent with the application or process performing the transfer.

Do not classify a destination as malicious solely because it is external or previously unseen.

### Step 6 — Correlate Related Activity

Correlate the suspected transfer with:

- sensitive file access;
- archive creation;
- compression activity;
- staging activity;
- process execution;
- authentication events;
- DNS requests;
- proxy requests;
- firewall connections;
- command-and-control activity;
- additional data transfers.

Construct a timeline covering relevant activity before, during, and after the suspected transfer.

### Step 7 — Determine Exfiltration Scope

Search across the environment for:

- the same destination;
- the same source process;
- the same account;
- the same command line;
- the same archive name;
- the same file hash;
- similar transfer volumes;
- similar timing patterns;
- the same collection or staging behavior.

Determine:

- affected hosts;
- affected accounts;
- affected destinations;
- estimated transferred volume;
- potentially exposed datasets;
- earliest observed activity;
- latest observed activity;
- whether the transfer is ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification, including the transferred data, source context, destination, transfer mechanism, and environmental scope.

## Evidence to Collect

| Evidence       | Description                                          |
| -------------- | ---------------------------------------------------- |
| Alert          | Detection source, alert ID, severity, timestamp      |
| Host           | Hostname, IP address, operating system               |
| User           | Associated account and authentication context        |
| Process        | Initiating process and process metadata              |
| Command Line   | Complete command line where available                |
| Files          | Accessed or potentially transferred files            |
| Archives       | Archive names, paths, and hashes                     |
| Data           | Data type, sensitivity, and ownership                |
| Network        | Source, destination, protocol, port, and timestamps  |
| DNS            | Related DNS queries and responses                    |
| Proxy          | Related web or proxy requests                        |
| Authentication | Related account and logon activity                   |
| Staging        | Local or remote staging artifacts                    |
| Timeline       | Collection, staging, execution, and transfer events  |
| Scope          | Affected hosts, accounts, destinations, and datasets |
| Detections     | Related alerts and detection identifiers             |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the transfer is authorized;
- the destination is approved;
- the source account and process are expected;
- the transferred data is consistent with the documented business purpose;
- the transfer volume and timing are normal;
- no suspicious collection, staging, or command-and-control activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the destination is unexpected or previously unseen;
- the transfer volume is abnormal;
- sensitive data was accessed before the transfer;
- collection or staging activity is present;
- the initiating process is unusual;
- the account or host context is inconsistent with the transfer;
- telemetry is incomplete and unauthorized exfiltration cannot yet be ruled out.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized transfer of sensitive or protected data;
- confirmed transfer to attacker-controlled infrastructure;
- exfiltration through a command-and-control channel;
- automated exfiltration associated with malicious activity;
- malicious collection or staging followed by external transfer;
- confirmed compromise of the source account or host;
- additional malicious activity associated with the transfer.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether unauthorized exfiltration occurred.

Document:

- evidence collected;
- evidence unavailable;
- estimated transfer scope;
- telemetry gaps;
- additional data sources required.

## Escalation

Escalate the investigation when:

- sensitive or regulated data may have been transferred;
- attacker-controlled infrastructure is identified;
- exfiltration remains active;
- multiple hosts or accounts are affected;
- command-and-control activity is associated with the transfer;
- collection or staging activity is confirmed;
- privileged or high-value accounts are involved;
- business-critical data may be exposed.

## Response Guidance

For confirmed malicious data exfiltration:

1. Preserve network, process, file, account, and authentication evidence.
2. Determine whether the transfer is still active.
3. Follow the organization's approved endpoint and network containment procedures.
4. Identify all affected hosts, accounts, destinations, and datasets.
5. Block or restrict confirmed malicious destinations according to approved response procedures.
6. Investigate the source of the data collection and any preceding staging activity.
7. Assess whether credentials, secrets, regulated data, or intellectual property were exposed.
8. Search the environment for additional instances of the same exfiltration pattern.
9. Investigate the broader compromise and associated persistence, lateral movement, or command-and-control activity.
10. Escalate according to the organization's incident-response and data-breach procedures.
11. Document the investigation timeline, scope, containment actions, and recovery activities.

Do not delete files, logs, network artifacts, or other relevant evidence before required evidence preservation has been completed.

## Related Detection Rules

## Related Playbooks

- `playbooks/triage/data-exfiltration-triage.md`
- `playbooks/exfiltration/cloud-exfiltration.md`
- `playbooks/exfiltration/dns-exfiltration.md`
- `playbooks/exfiltration/exfiltration-over-c2-channel.md`
- `playbooks/exfiltration/automated-exfiltration.md`
- `playbooks/collection/archive-collected-data.md`

## Validation

The playbook should be validated against approved network telemetry, endpoint process and file telemetry, proxy and firewall logs, DNS telemetry, DLP alerts, and controlled exfiltration scenarios.

Validation should confirm that:

- potentially transferred data can be identified;
- source processes and associated accounts can be determined;
- transfer destinations can be investigated;
- collection and staging activity can be correlated;
- transfer volume and timing can be assessed;
- environmental scope can be determined;
- benign business transfers can be distinguished from suspicious or malicious activity;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not intentionally transfer sensitive data to external systems for testing. Controlled validation should use synthetic or non-sensitive test data and approved destinations. Evidence collection and containment actions must follow applicable authorization, privacy, legal, and data-handling requirements.
