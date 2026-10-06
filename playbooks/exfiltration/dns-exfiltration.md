---
id: "dns-exfiltration"
name: "DNS Exfiltration"
category: "exfiltration"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-06T00:00:00Z"
updated_at: "2026-10-06T15:59:00Z"
description: "DNS Exfiltration involves transferring collected data through DNS queries or responses to an external destination in order to bypass or reduce the effectiveness of conventional network controls."
objective: "Identify, investigate, scope, and assess suspected DNS-based data exfiltration and determine whether unauthorized data transfer occurred."
severity: "high"
mitre_attack:
  - "T1048.003"
triggers:
  - "Unusual DNS query volume from an endpoint"
  - "High-entropy or encoded DNS query labels"
  - "Repeated queries to an uncommon external domain"
  - "Large or unusually frequent DNS requests"
  - "DNS traffic containing long or structured subdomains"
  - "Threat hunting identifies anomalous DNS-based transfer behavior"
prerequisites:
  - "Access to DNS query and response telemetry"
  - "Access to endpoint process and network telemetry"
  - "Access to asset and user context"
  - "Access to DNS and domain reputation data where available"
tags:
  - "dns"
  - "exfiltration"
  - "data-transfer"
  - "network"
  - "windows"
references:
  - "https://attack.mitre.org/techniques/T1048/003/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify DNS Exfiltration Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, associated account, queried domain, timestamp, and alert context."
    expected_result: "The suspicious DNS activity and affected asset are identified."
  - id: "review-dns-activity"
    order: 2
    name: "Review DNS Activity"
    action: "analyze"
    description: "Review DNS queries and responses associated with the affected host and identify unusual frequency, volume, query structure, and destination patterns."
    expected_result: "The observed DNS activity and relevant anomalies are documented."
  - id: "analyze-query-structure"
    order: 3
    name: "Analyze Query Structure"
    action: "analyze"
    description: "Inspect queried hostnames for unusually long labels, high-entropy values, encoding patterns, sequential identifiers, or repeated structured data."
    expected_result: "Potential data-encoding and transfer indicators within DNS queries are identified."
  - id: "identify-source-process"
    order: 4
    name: "Identify Source Process"
    action: "investigate"
    description: "Correlate DNS activity with the process, executable, command line, user account, and execution context responsible for generating the queries."
    expected_result: "The source process and associated execution context are identified."
  - id: "review-destination"
    order: 5
    name: "Review Destination"
    action: "analyze"
    description: "Review the queried domain, authoritative infrastructure, registration context, reputation, resolution behavior, and historical prevalence."
    expected_result: "The destination infrastructure and its relevance to the observed activity are assessed."
  - id: "correlate-related-activity"
    order: 6
    name: "Correlate Related Activity"
    action: "hunt"
    description: "Correlate DNS activity with process execution, file activity, authentication events, network connections, persistence, and other security alerts."
    expected_result: "Related activity is identified and correlated across the affected host and account."
  - id: "determine-exfiltration-scope"
    order: 7
    name: "Determine Exfiltration Scope"
    action: "hunt"
    description: "Search for the same queried domain, query pattern, source process, account, host, and behavioral indicators across the environment."
    expected_result: "The prevalence and potential scope of the DNS-based transfer are determined."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity based on the collected evidence and document the rationale for the final assessment."
    expected_result: "The DNS activity receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "dns-exfiltration"
---

# DNS Exfiltration

## Purpose

This playbook provides a structured SOC workflow for investigating suspected DNS-based data exfiltration.

DNS is commonly required for normal name resolution and application functionality. Suspicious activity may occur when DNS queries or responses are used to transfer encoded, fragmented, or otherwise structured data to infrastructure controlled or monitored by an unauthorized party.

The objective is to determine whether the observed DNS activity is legitimate, suspicious, malicious, or inconclusive and whether unauthorized data transfer occurred.

## MITRE ATT&CK

| Technique | Name                                               | Relevance                                         |
| --------- | -------------------------------------------------- | ------------------------------------------------- |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol: DNS | Primary technique for DNS-based data exfiltration |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint generates an unusual volume of DNS queries.
- DNS queries contain unusually long or high-entropy labels.
- Repeated queries are directed to an uncommon or previously unseen domain.
- Query names contain encoded, sequential, or structured values.
- DNS traffic occurs at unusual frequency or regular intervals.
- Threat hunting identifies behavior consistent with DNS-based data transfer.

A high DNS query volume or long hostname alone does not establish exfiltration. The activity must be evaluated in its application, process, destination, and environmental context.

## Scope

The investigation should consider:

- affected host;
- associated user account;
- source process;
- executable path;
- command line;
- queried domain;
- query type;
- query frequency;
- query volume;
- label length;
- label entropy;
- encoding patterns;
- repeated query structure;
- response behavior;
- destination infrastructure;
- DNS resolver;
- authoritative nameserver;
- network connections;
- related file activity;
- related authentication activity;
- additional affected hosts;
- potential data classification or sensitivity.

## Investigation Procedure

### Step 1 — Identify DNS Exfiltration Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- queried domain;
- query type;
- detection severity;
- detection reason.

Preserve the original DNS telemetry and alert context before making containment or remediation changes.

### Step 2 — Review DNS Activity

Review:

- DNS queries and responses;
- query frequency;
- query volume;
- query types;
- queried domains;
- resolver activity;
- timestamps;
- repeated query patterns.

Determine whether the activity is consistent with:

- normal application behavior;
- software updates;
- telemetry or monitoring;
- content delivery;
- service discovery; or
- potentially anomalous data transfer.

### Step 3 — Analyze Query Structure

Inspect queried hostnames for:

- unusually long labels;
- high-entropy strings;
- Base32, Base64, hexadecimal, or similar encoding indicators;
- sequential identifiers;
- fragmented values;
- repeated prefixes or suffixes;
- structured payload-like data;
- unusually regular query patterns.

Assess whether the observed structure could reasonably represent transferred data.

Do not classify encoded DNS labels as malicious solely because encoding is present. Some legitimate applications use encoded or structured identifiers.

### Step 4 — Identify Source Process

Correlate the DNS activity with endpoint telemetry.

Collect:

- process ID;
- process name;
- executable path;
- process creation time;
- parent process;
- child processes;
- command line;
- associated user;
- execution context;
- process hash where available.

Determine whether the generating process is:

- a known system component;
- a legitimate application;
- an administrative tool;
- an unexpected executable;
- an unsigned or unknown binary; or
- associated with previously identified malicious activity.

### Step 5 — Review Destination

Assess the queried domain and associated infrastructure.

Review:

- domain age where available;
- registration information;
- domain reputation;
- historical prevalence;
- authoritative nameservers;
- IP resolution history;
- hosting provider;
- geographic information where relevant;
- related domains;
- known threat intelligence;
- whether the domain is expected for the affected environment.

Determine whether the destination is associated with legitimate business activity or suspicious infrastructure.

### Step 6 — Correlate Related Activity

Correlate the DNS activity with:

- process creation;
- command-line activity;
- file creation and modification;
- archive creation;
- credential access;
- persistence;
- network connections;
- authentication events;
- other security detections;
- activity involving the same destination.

Review whether the DNS behavior forms part of a broader execution or exfiltration sequence.

### Step 7 — Determine Exfiltration Scope

Search the environment for:

- the same queried domain;
- the same query structure;
- the same source process;
- the same command line;
- the same executable hash;
- the same user account;
- similar DNS frequency;
- similar encoded query patterns.

Determine:

- number of affected hosts;
- number of affected accounts;
- first observed activity;
- latest observed activity;
- duration of the activity;
- estimated volume of transferred data where reliably measurable.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence            | Description                                         |
| ------------------- | --------------------------------------------------- |
| Alert               | Detection source, ID, severity, timestamp           |
| Host                | Hostname, IP address, operating system              |
| User                | Associated account and account type                 |
| DNS Queries         | Complete relevant query records                     |
| Query Structure     | Label length, entropy, encoding, sequencing         |
| Domain              | Queried domain and subdomain information            |
| Resolver            | DNS resolver and request path                       |
| Destination         | Authoritative infrastructure and resolved addresses |
| Process             | Source process metadata                             |
| Command Line        | Complete command line where available               |
| Files               | Related created or modified artifacts               |
| Network             | Related network connections                         |
| Authentication      | Related account activity                            |
| Timeline            | DNS, process, file, and authentication timestamps   |
| Scope               | Other affected hosts and accounts                   |
| Threat Intelligence | Domain and infrastructure reputation data           |
| Volume              | Estimated DNS request and transfer volume           |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the DNS queries are attributable to an approved application or service;
- the queried domain is known and expected;
- query structure is consistent with documented application behavior;
- frequency and volume are consistent with normal operations;
- no suspicious process or file activity is identified;
- no additional indicators of unauthorized data transfer are present.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the queried domain is unusual or previously unseen;
- query labels are unusually long or high entropy;
- encoded or structured values are repeatedly transmitted;
- DNS volume or frequency is abnormal;
- the source process is unexpected;
- related telemetry is incomplete;
- legitimate activity cannot yet be established.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- DNS queries are being used to transfer unauthorized data;
- encoded or fragmented data is repeatedly transmitted to suspicious infrastructure;
- the source process is confirmed malicious or unauthorized;
- the activity is associated with known compromise;
- additional malicious execution, persistence, credential access, or command-and-control activity is identified;
- unauthorized data exfiltration is confirmed.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the DNS activity represents legitimate application behavior or unauthorized data transfer.

Document:

- evidence collected;
- evidence unavailable;
- telemetry limitations;
- additional data required.

## Escalation

Escalate the investigation when:

- unauthorized DNS-based data transfer is confirmed;
- sensitive or regulated data may have been transferred;
- a malicious process is responsible for the activity;
- suspicious DNS activity is observed across multiple hosts;
- the destination is associated with known malicious infrastructure;
- credential access or persistence is identified;
- broader compromise indicators are present.

## Response Guidance

For confirmed malicious DNS exfiltration:

1. Preserve DNS, endpoint, process, file, account, and network evidence.
2. Identify all affected hosts, users, domains, and processes.
3. Follow the organization's endpoint containment procedure.
4. Investigate the source process and associated executable or script.
5. Determine the scope and potential sensitivity of transferred data.
6. Block or restrict confirmed malicious destinations according to approved procedures.
7. Search the environment for related domains, query patterns, hashes, and processes.
8. Investigate associated persistence, credential access, lateral movement, and command-and-control activity.
9. Remediate affected systems according to incident-response procedures.
10. Review potentially exposed accounts and data.
11. Document the investigation timeline, evidence, containment, and remediation actions.

Do not delete DNS, endpoint, or network evidence before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

## Related Playbooks

- `playbooks/command-and-control/dns-c2.md`
- `playbooks/command-and-control/application-layer-protocol.md`
- `playbooks/triage/data-exfiltration-triage.md`

## Validation

The playbook should be validated against approved DNS telemetry, endpoint process telemetry, controlled encoded-query scenarios, and representative legitimate DNS application traffic.

Validation should confirm that:

- anomalous DNS query frequency can be identified;
- unusually long or high-entropy labels can be investigated;
- potential encoding patterns can be identified;
- the responsible process can be correlated;
- destination infrastructure can be assessed;
- related endpoint and network activity can be correlated;
- environmental scope can be determined;
- legitimate DNS activity can be distinguished from suspected exfiltration;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

DNS traffic analysis and response actions should follow approved monitoring, evidence-preservation, and change-management procedures. Do not intentionally perform data exfiltration against production systems or external infrastructure outside authorized test environments.
