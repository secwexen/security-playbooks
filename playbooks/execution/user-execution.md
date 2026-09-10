---
id: "user-execution"
name: "User Execution"
category: "execution"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-10T17:23:00Z"
updated_at: "2026-09-10T17:23:00Z"
description: "User Execution involves adversaries relying on users to execute malicious files, links, scripts, or other content to initiate or continue malicious activity."
objective: "Identify, investigate, and validate suspicious user-driven execution and determine whether user interaction resulted in unauthorized code execution or further compromise."
severity: "high"
mitre_attack:
  - "T1204"
triggers:
  - "Suspicious user execution alert"
  - "Malicious file opened by a user"
  - "User clicked a suspicious link"
  - "User-enabled active or executable content"
  - "Endpoint activity following suspicious user interaction"
  - "Threat intelligence identifies a user-execution campaign"
prerequisites:
  - "Access to endpoint process telemetry"
  - "Access to browser and email telemetry where available"
  - "Access to file and network telemetry"
  - "Access to authentication telemetry where relevant"
tags:
  - "user-execution"
  - "execution"
  - "phishing"
  - "endpoint"
  - "malware"
  - "initial-access"
references:
  - "https://attack.mitre.org/techniques/T1204/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify User Execution Alert"
  action: "investigate"
  description: "Identify the detection source, affected user, host, timestamp, and user action associated with the event."
  expected_result: "The suspicious user-execution event and affected asset are identified."
- id: "identify-user-action"
  order: 2
  name: "Identify User Action"
  action: "analyze"
  description: "Determine whether the user opened a file, clicked a link, executed a program, or enabled active content."
  expected_result: "The user action that initiated execution is established."
- id: "review-source-content"
  order: 3
  name: "Review Source Content"
  action: "analyze"
  description: "Review the file, message, link, document, or other content that prompted the user action."
  expected_result: "The source content and relevant indicators are documented."
- id: "review-process-activity"
  order: 4
  name: "Review Process Activity"
  action: "analyze"
  description: "Review process creation, parent-child relationships, command lines, and execution timestamps following the user action."
  expected_result: "The resulting process activity is documented and correlated."
- id: "review-file-network-activity"
  order: 5
  name: "Review File and Network Activity"
  action: "analyze"
  description: "Review file creation, downloads, DNS activity, and network connections associated with the execution."
  expected_result: "Related file and network activity is identified or ruled out."
- id: "review-follow-on-activity"
  order: 6
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Review persistence, credential access, privilege escalation, lateral movement, and other post-execution activity."
  expected_result: "Potential follow-on compromise activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Execution Scope"
  action: "hunt"
  description: "Search for the same file, link, hash, sender, command line, or execution pattern across the environment."
  expected_result: "Affected users, hosts, and related execution events are identified."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the user-execution activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "user-execution"
---

# User Execution

## Purpose

This playbook provides a structured workflow for investigating suspicious user-driven execution of files, links, scripts, documents, or other content.

The objective is to determine whether user interaction resulted in malicious execution, identify the resulting activity, establish scope, and determine whether incident response is required.

## MITRE ATT&CK

| Technique | Name           | Relevance                                                                |
| --------- | -------------- | ------------------------------------------------------------------------ |
| T1204     | User Execution | Relevant when an adversary relies on a user to execute malicious content |

Additional T1204 sub-techniques should only be mapped when supported by the observed user-execution behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious user-execution alert is generated.
- A user opens a suspicious file or document.
- A user clicks a suspicious link.
- A user executes an unexpected program or script.
- A user enables active or executable content.
- Endpoint activity follows a suspicious user interaction.
- Threat hunting identifies a repeated user-execution pattern.

## Scope

The investigation should consider:

- affected user;
- affected host;
- source content;
- file or URL;
- email message where applicable;
- sender;
- browser;
- file hash;
- execution timestamp;
- process tree;
- command line;
- child processes;
- file creation;
- downloaded content;
- network connections;
- DNS activity;
- authentication activity;
- persistence;
- related alerts;
- additional affected users or hosts.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected user;
- affected host;
- source content;
- detection severity.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify User Action

Determine exactly what the user did.

Examples include:

- opening a document;
- launching an executable;
- opening an archive;
- clicking a link;
- executing a script;
- enabling active content.

Establish the first known user interaction and its timestamp.

### Step 3 — Review Source Content

Review the content that prompted the action.

Collect:

- filename;
- file type;
- hash;
- URL;
- sender;
- message subject where applicable;
- source location;
- delivery method.

Assess whether the content was expected and whether it contains suspicious characteristics.

### Step 4 — Review Process Activity

Review:

- process creation;
- parent process;
- child processes;
- command line;
- execution time;
- user context;
- executable path.

Pay particular attention to unexpected processes launched by:

- office applications;
- email clients;
- browsers;
- archive utilities;
- document readers;
- other user-facing applications.

### Step 5 — Review File and Network Activity

Review:

- newly created files;
- downloaded files;
- extracted files;
- DNS requests;
- destination IPs;
- destination domains;
- outbound connections.

Correlate network and file activity with the user's execution timestamp.

### Step 6 — Review Follow-on Activity

Search for:

- persistence;
- credential access;
- privilege escalation;
- lateral movement;
- command-and-control;
- additional malware execution;
- account changes.

Determine whether user execution was an isolated event or the beginning of a broader attack chain.

### Step 7 — Determine Execution Scope

Search across the environment for:

- same file hash;
- same filename;
- same URL;
- same sender;
- same command line;
- same process pattern;
- same execution behavior.

Determine:

- number of affected users;
- number of affected hosts;
- first observed execution;
- latest observed execution;
- whether execution is still active.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence           | Description                                                        |
| ------------------ | ------------------------------------------------------------------ |
| Alert              | Detection source, ID, severity, timestamp                          |
| User               | Affected user                                                      |
| Host               | Hostname, IP address, operating system                             |
| Source Content     | File, link, document, or script                                    |
| Sender             | Sender information where applicable                                |
| Hash               | SHA-256 or available file hash                                     |
| User Action        | Action that initiated execution                                    |
| Process            | Process metadata                                                   |
| Process Tree       | Parent and child processes                                         |
| Command Line       | Complete command line                                              |
| Files              | Created, downloaded, or extracted files                            |
| Network            | Related network activity                                           |
| DNS                | Related DNS activity                                               |
| Follow-on Activity | Persistence, credential, privilege, or lateral movement indicators |
| Scope              | Other affected users and hosts                                     |
| Detections         | Related security alerts                                            |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the user action was expected;
- the content is legitimate;
- the process execution is normal;
- the source is trusted;
- no suspicious follow-on activity is identified.

Document the justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the content is unexpected;
- the user interaction is unusual;
- process execution is abnormal;
- files or network connections are suspicious;
- follow-on activity requires additional investigation.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- confirmed malicious content execution;
- unauthorized code execution;
- malicious child-process activity;
- confirmed malware execution;
- command-and-control communication;
- persistence;
- credential access;
- other confirmed post-execution malicious activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether user execution resulted in malicious activity.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious execution is confirmed;
- credentials may have been exposed;
- persistence is identified;
- command-and-control activity is observed;
- multiple users or hosts are affected;
- a privileged account is involved;
- a business-critical system is affected.

## Response Guidance

For confirmed malicious user execution:

1. Preserve relevant user, file, process, and network evidence.
2. Identify all affected users and hosts.
3. Follow the organization's endpoint containment procedure.
4. Search for related files, hashes, URLs, and execution patterns.
5. Review authentication and account activity.
6. Investigate persistence and post-compromise activity.
7. Follow authorized quarantine or remediation procedures.
8. Escalate confirmed compromise to incident response.
9. Document the investigation timeline and remediation actions.

Do not delete or modify relevant files, logs, or other evidence before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/obfuscated-powershell.yar`
- `detection-rules/yara/yara-powershell-payload.yar`

## Related Playbooks

- `playbooks/triage/phishing-alert-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/execution/scripting.md`
- `playbooks/execution/powershell.md`
- `playbooks/execution/command-shell.md`
- `playbooks/execution/python-execution.md`
- `playbooks/initial-access/phishing.md`
- `playbooks/initial-access/malicious-attachment.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved user-execution fixtures, phishing simulations, endpoint telemetry, and controlled execution scenarios.

Validation should confirm that:

- user actions can be identified;
- source content can be investigated;
- resulting process activity can be correlated;
- related file and network activity can be investigated;
- follow-on compromise activity can be identified;
- affected users and hosts can be determined;
- legitimate user execution can be distinguished from malicious execution;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Unknown files, links, documents, and scripts should be handled through approved analysis environments. Do not execute untrusted content on production systems.
