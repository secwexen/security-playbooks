---
id: "drive-by-download"
name: "Drive-by Compromise"
category: "initial-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-09T13:49:00Z"
updated_at: "2026-09-09T13:49:00Z"
description: "Investigate suspected drive-by compromise activity in which a user is exposed to malicious web content that may lead to unauthorized access or execution."
objective: "Determine whether malicious web content resulted in exploitation, unwanted downloads, code execution, or other compromise and establish the affected users, systems, and scope."
severity: "high"
mitre_attack:
  - "T1189"
triggers:
  - "Suspicious web content detection"
  - "Malicious website alert"
  - "Drive-by compromise detection"
  - "Unexpected browser download"
  - "Browser exploitation alert"
  - "Endpoint activity associated with suspicious web browsing"
prerequisites:
  - "Access to web proxy and DNS telemetry"
  - "Access to browser and endpoint telemetry"
  - "Access to URL and domain analysis"
  - "Access to network security telemetry where available"
tags:
  - "drive-by"
  - "initial-access"
  - "web"
  - "browser"
  - "exploit"
  - "malware"
references:
  - "https://attack.mitre.org/techniques/T1189/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Drive-by Alert"
  action: "investigate"
  description: "Identify the detection source, affected user or host, timestamp, and suspicious website or web activity."
  expected_result: "The suspected drive-by event and affected asset are identified."
- id: "identify-web-resource"
  order: 2
  name: "Identify Web Resource"
  action: "analyze"
  description: "Identify the URL, domain, IP address, page, redirect chain, and related web resources."
  expected_result: "The relevant web resource and infrastructure are documented."
- id: "review-browser-activity"
  order: 3
  name: "Review Browser Activity"
  action: "analyze"
  description: "Review browser history, navigation events, downloads, redirects, and associated browser processes."
  expected_result: "The user's interaction with the suspicious web resource is established."
- id: "review-downloads"
  order: 4
  name: "Review Download Activity"
  action: "analyze"
  description: "Determine whether files or other content were downloaded and collect relevant file metadata."
  expected_result: "Potentially downloaded artifacts are identified and documented."
- id: "review-endpoint-activity"
  order: 5
  name: "Review Endpoint Activity"
  action: "analyze"
  description: "Review process creation, child processes, file creation, command lines, and endpoint detections following the browsing event."
  expected_result: "Potential endpoint compromise activity is identified or ruled out."
- id: "review-network-activity"
  order: 6
  name: "Review Network Activity"
  action: "analyze"
  description: "Review DNS queries, outbound connections, redirects, and communication with suspicious infrastructure."
  expected_result: "Relevant network activity and destinations are documented."
- id: "determine-scope"
  order: 7
  name: "Determine Scope"
  action: "hunt"
  description: "Search for the same domain, URL, IP address, downloaded artifact, or browsing pattern across the environment."
  expected_result: "Affected users, hosts, and related activity are identified."
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
  scenario: "drive-by-download"
---

# Drive-by Compromise

## Purpose

This playbook provides a structured workflow for investigating suspected drive-by compromise activity resulting from interaction with malicious or compromised web content.

The objective is to determine whether the activity resulted in an exploit, unwanted download, code execution, or other endpoint compromise.

## MITRE ATT&CK

| Technique | Name                | Relevance                                                                                                      |
| --------- | ------------------- | -------------------------------------------------------------------------------------------------------------- |
| T1189     | Drive-by Compromise | Relevant when an adversary gains access through a user's interaction with malicious or compromised web content |

Additional ATT&CK techniques should only be mapped when supported by the observed activity.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A malicious website detection is generated.
- A browser visits a known malicious or suspicious domain.
- Unexpected downloads occur following web activity.
- Browser exploitation is suspected.
- An endpoint alert follows navigation to a suspicious website.
- Threat intelligence identifies malicious web infrastructure.
- Multiple users show similar suspicious browsing activity.

## Scope

The investigation should consider:

- affected user;
- affected host;
- browser;
- URL;
- domain;
- IP address;
- DNS queries;
- redirect chain;
- browser process;
- downloaded file;
- file hash;
- process execution;
- network connections;
- endpoint detections;
- related users;
- related hosts.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected user;
- affected host;
- suspicious URL or domain;
- detection severity.

Preserve the original alert and relevant telemetry before making remediation changes.

### Step 2 — Identify the Web Resource

Collect:

- full URL;
- domain;
- destination IP;
- URL path;
- request timestamp;
- referrer where available;
- redirect information where available.

Determine whether the destination is:

- known and legitimate;
- compromised;
- suspicious;
- malicious.

Do not actively browse suspicious infrastructure from production systems.

### Step 3 — Review Browser Activity

Review:

- browsing history;
- navigation events;
- redirects;
- downloads;
- browser process activity;
- browser extensions where relevant.

Determine whether the suspicious resource was accessed directly or through another page or redirect.

### Step 4 — Review Download Activity

Determine whether the browsing event resulted in:

- executable downloads;
- scripts;
- archives;
- documents;
- browser downloads;
- other files.

Collect:

- filename;
- file type;
- file size;
- SHA-256 hash;
- download path;
- download timestamp.

Do not execute downloaded artifacts outside an approved analysis environment.

### Step 5 — Review Endpoint Activity

Correlate the browsing event with:

- process creation;
- parent-child process relationships;
- command lines;
- file creation;
- script execution;
- persistence;
- endpoint detections.

Pay particular attention to processes launched immediately after suspicious browser activity.

### Step 6 — Review Network Activity

Review:

- DNS queries;
- destination IPs;
- destination domains;
- connection timestamps;
- outbound connections;
- repeated connections;
- communication with known malicious infrastructure.

Determine whether the browser or a spawned process established additional network connections.

### Step 7 — Determine Environmental Scope

Search across the environment for:

- same domain;
- same URL;
- same IP;
- same downloaded file hash;
- same browser activity;
- same endpoint behavior.

Determine:

- number of affected users;
- number of affected hosts;
- first observed activity;
- most recent observed activity;
- whether the activity is ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Exploit Attempt**
- **Confirmed Compromise**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence   | Description                               |
| ---------- | ----------------------------------------- |
| Alert      | Detection source, ID, severity, timestamp |
| User       | Affected user                             |
| Host       | Hostname, IP address, operating system    |
| Browser    | Browser and relevant activity             |
| URL        | Full URL and path                         |
| Domain     | Domain and destination infrastructure     |
| DNS        | Related DNS queries                       |
| Redirects  | Relevant redirect chain                   |
| Download   | Downloaded file and metadata              |
| Hash       | SHA-256 or available file hash            |
| Process    | Related process activity                  |
| Network    | Related network connections               |
| Detections | Related endpoint and network alerts       |
| Scope      | Other affected users and hosts            |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the website is legitimate;
- browsing activity is expected;
- downloads are authorized;
- no exploit indicators are identified;
- no suspicious endpoint or network activity is observed.

Document the justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the domain or URL is unusual;
- redirects are unexpected;
- suspicious content is present;
- unexpected downloads occur;
- endpoint telemetry is abnormal;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Exploit Attempt

Classify the event as an **exploit attempt** when:

- evidence indicates exploitation targeting the browser or related software;
- exploitation indicators are present;
- there is no sufficient evidence of successful compromise.

Continue monitoring and investigate potential follow-on activity.

### Confirmed Compromise

Classify the event as **confirmed compromise** when sufficient evidence indicates:

- successful exploitation;
- unauthorized code execution;
- malicious file execution;
- persistence;
- command-and-control activity;
- credential access;
- other confirmed post-compromise activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether exploitation or compromise occurred.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- successful exploitation is suspected or confirmed;
- malicious code execution is observed;
- downloaded malware is identified;
- credentials may have been exposed;
- multiple users or hosts are affected;
- command-and-control activity is identified;
- the affected system is business-critical.

## Response Guidance

For confirmed compromise:

1. Preserve browser, endpoint, DNS, and network evidence.
2. Identify all affected users and systems.
3. Follow the organization's endpoint containment procedure.
4. Investigate downloaded and executed artifacts.
5. Search for related indicators across the environment.
6. Review authentication and account activity.
7. Investigate persistence and post-compromise behavior.
8. Follow authorized remediation procedures.
9. Escalate to incident response.
10. Document the investigation timeline and remediation actions.

Do not delete browser history, downloaded artifacts, or relevant logs before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/suricata/network-alert.rules`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/yara/malware-sample.yar`

## Related Playbooks

- `playbooks/triage/phishing-alert-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/initial-access/phishing.md`
- `playbooks/initial-access/malicious-attachment.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`
- `playbooks/response/account-compromise-response.md`

## Validation

The playbook should be validated against approved web-security fixtures, browser telemetry, network telemetry, endpoint events, and controlled drive-by compromise scenarios.

Validation should confirm that:

- suspicious web resources can be identified;
- browser activity can be investigated;
- downloads can be identified and analyzed;
- endpoint activity can be correlated;
- network activity can be investigated;
- affected users and hosts can be identified;
- exploit attempts can be distinguished from confirmed compromise;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Suspicious websites and downloaded artifacts must be handled through approved analysis environments and procedures. Do not intentionally access or exploit malicious web infrastructure outside an authorized and controlled environment.
