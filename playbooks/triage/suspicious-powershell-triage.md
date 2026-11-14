---
id: "suspicious-powershell-triage"
name: "Suspicious PowerShell Triage"
category: "triage"
status: "active"
version: "1.0.3"
author: "Secwexen"
created_at: "2026-08-30T16:45:00Z"
updated_at: "2026-11-14T08:38:00Z"
description: "Investigate suspicious PowerShell execution alerts and determine whether the observed activity is benign, suspicious, or malicious."
objective: "Determine the nature, scope, and impact of suspicious PowerShell activity and provide evidence for escalation or closure."
severity: "high"
mitre_attack:
  - "T1059.001"
  - "T1027"
triggers:
  - "Suspicious PowerShell execution alert"
  - "Encoded PowerShell command detection"
  - "Obfuscated PowerShell payload detection"
  - "Unexpected PowerShell network activity"
prerequisites:
  - "Access to endpoint process telemetry"
  - "Access to authentication telemetry"
  - "Access to network telemetry"
  - "Access to PowerShell logging when available"
tags:
  - "powershell"
  - "triage"
  - "execution"
  - "defense-evasion"
  - "windows"
references:
  - "https://attack.mitre.org/techniques/T1059/001/"
  - "https://attack.mitre.org/techniques/T1027/"
steps:
  - id: "identify-affected-host"
    order: 1
    name: "Identify the Affected Host"
    action: "investigate"
    description: "Identify the endpoint on which the suspicious PowerShell activity was observed, including its asset type, ownership, operating system, and criticality."
    expected_result: "The affected host, asset type, ownership, operating system, and criticality are identified."
  - id: "identify-user"
    order: 2
    name: "Identify the User"
    action: "investigate"
    description: "Identify the account associated with the PowerShell process and review its account type, privilege level, and relevant authentication context."
    expected_result: "The associated account, account type, privilege level, and authentication context are identified."
  - id: "review-process-execution"
    order: 3
    name: "Review Process Execution"
    action: "analyze"
    description: "Review the PowerShell process, parent and child processes, execution path, process identifiers, timestamps, and available process metadata."
    expected_result: "The PowerShell process execution context, process lineage, and related process activity are characterized."
  - id: "review-command-and-script-content"
    order: 4
    name: "Review Command Line and Script Content"
    action: "analyze"
    description: "Inspect the PowerShell command line and available script content for suspicious parameters, encoded commands, obfuscation, dynamic command construction, download behavior, and potential security-control evasion."
    expected_result: "The observed command line, script content, and relevant encoding, obfuscation, or execution indicators are documented and assessed."
  - id: "review-powershell-logging"
    order: 5
    name: "Review PowerShell Logging"
    action: "analyze"
    description: "Review available PowerShell and Windows logging sources, including operational events, script block logging, module logging, and transcription logs, and correlate them with endpoint activity."
    expected_result: "Relevant PowerShell logging and correlated endpoint events are identified and documented."
  - id: "review-network-and-file-activity"
    order: 6
    name: "Review Network and File Activity"
    action: "analyze"
    description: "Review network connections associated with PowerShell execution and identify files or artifacts created, modified, downloaded, or accessed around the execution time."
    expected_result: "Related network activity, potentially suspicious destinations, and relevant file artifacts are identified and documented."
  - id: "correlate-related-events"
    order: 7
    name: "Correlate Related Events and Determine Scope"
    action: "hunt"
    description: "Correlate related process, authentication, persistence, credential access, lateral movement, and PowerShell activity across the affected host and the wider environment."
    expected_result: "Related malicious or suspicious activity, additional affected hosts, accounts, and associated indicators are identified or reasonably ruled out."
  - id: "determine-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the PowerShell activity, document supporting evidence, establish its execution and impact status, and record affected resources and remaining investigative or escalation requirements."
    expected_result: "The investigation receives a documented outcome with its classification, execution assessment, affected resources, and follow-up requirements recorded."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "suspicious-powershell"
---

# Suspicious PowerShell Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspicious PowerShell execution on Windows systems.

It guides analysts in examining command lines, script content, process relationships, PowerShell logs, and associated network and file activity to identify potentially malicious execution.

The investigation aims to determine execution intent, identify related malicious behavior, assess affected systems, and establish whether containment or incident response is required.

## MITRE ATT&CK

| Technique | Name                            | Relevance                                                 |
| --------- | ------------------------------- | --------------------------------------------------------- |
| T1059.001 | PowerShell                      | Primary execution technique                               |
| T1027     | Obfuscated Files or Information | Relevant when encoded or obfuscated commands are observed |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A Sigma rule reports suspicious PowerShell execution.
- A YARA rule identifies suspicious PowerShell content.
- Suricata reports network activity associated with PowerShell execution.
- An analyst observes unusual PowerShell behavior during investigation.
- Threat hunting identifies anomalous PowerShell activity.

## Scope

The investigation should consider:

- affected host;
- associated user account;
- PowerShell process;
- parent process;
- child processes;
- command line;
- script content;
- loaded modules where available;
- created or modified files;
- network connections;
- related authentication events;
- related detections on other hosts.

## Investigation Procedure

### Step 1 - Identify the Affected Host

Identify the endpoint on which the suspicious PowerShell activity was observed.

Collect:

- hostname;
- IP address;
- operating system;
- asset owner;
- host criticality;
- endpoint type;
- current isolation status.

Determine whether the endpoint is:

- a user workstation;
- a server;
- an administrative workstation;
- a domain controller;
- a security-sensitive asset;
- another organizational endpoint.

Preserve the original alert and relevant endpoint telemetry before making investigation or remediation changes.

### Step 2 - Identify the User

Determine which account initiated or was associated with the PowerShell process.

Collect:

- username;
- domain;
- account type;
- privilege level;
- logon type;
- source workstation where available;
- authentication method;
- recent authentication activity.

Check whether the account is:

- a standard user;
- an administrator;
- a service account;
- a privileged account;
- an unexpected account for the affected host.

Determine whether the account's permissions and expected responsibilities are consistent with the observed PowerShell activity.

### Step 3 - Review Process Execution

Collect the PowerShell process details:

- process ID;
- parent process ID;
- process creation time;
- executable path;
- command line;
- integrity level;
- parent process;
- child processes;
- process lineage;
- execution account;
- digital signature where available.

Pay particular attention to unusual parent processes such as:

- Office applications;
- archive utilities;
- script interpreters;
- browser processes;
- temporary directory executables;
- unknown or unsigned binaries.

Determine whether PowerShell was started by an expected administrative tool, scheduled task, management platform, user application, or suspicious process.

Correlate the process execution timeline with the original detection.

### Step 4 - Review Command Line and Script Content

Inspect the PowerShell command line and available script content for:

- encoded commands;
- unusual parameters;
- hidden execution;
- execution policy changes;
- suspicious download behavior;
- unusual temporary paths;
- embedded scripts;
- dynamically generated content;
- string concatenation;
- excessive escaping;
- compressed or transformed content;
- attempts to bypass normal logging or security controls.

Investigate whether the content contains:

- Base64-encoded data;
- dynamically constructed commands;
- obfuscated strings;
- suspicious download or execution functions;
- unexpected external references;
- suspicious file or registry operations;
- commands associated with credential access or persistence.

Determine whether the encoding or obfuscation has a legitimate operational explanation.

Do not classify a command as malicious solely because it contains a suspicious-looking parameter or encoded content. Correlate the command with its execution context, user, host, script behavior, and related telemetry.

Do not execute unknown or suspicious scripts on production systems.

### Step 5 - Review PowerShell Logging

When available, review:

- PowerShell operational logs;
- Script Block Logging;
- module logging;
- transcription logs;
- associated Windows event records;
- process creation events;
- relevant security audit events.

Correlate timestamps with:

- process creation;
- authentication events;
- script execution;
- file creation;
- file modification;
- network activity;
- endpoint detections.

Determine whether the available logs provide visibility into the executed commands and scripts.

Identify relevant telemetry gaps, disabled logging sources, or missing events that limit the investigation.

### Step 6 - Review Network and File Activity

Investigate network connections associated with PowerShell execution.

Collect:

- destination IP;
- destination domain;
- destination port;
- protocol;
- connection time;
- connection duration;
- DNS lookups;
- HTTP/HTTPS metadata where available;
- proxy or firewall events.

Escalate investigation priority when PowerShell execution is followed by:

- unusual external communication;
- previously unseen destinations;
- suspicious domains;
- repeated periodic connections;
- payload retrieval;
- unexpected outbound connections;
- command-and-control-like behavior.

Identify files created, modified, downloaded, or accessed around the execution time.

Focus on:

- temporary files;
- scripts;
- executables;
- archives;
- downloaded payloads;
- suspicious files in user-writable directories;
- files associated with child processes;
- unexpected configuration changes.

Collect:

- filename;
- file path;
- file type;
- file size;
- creation timestamp;
- modification timestamp;
- SHA-256 hash;
- digital signature where available.

Correlate file and network activity with the PowerShell execution timeline.

### Step 7 - Correlate Related Events and Determine Scope

Search for related activity on the same host and account.

Review:

- process creation;
- parent-child process relationships;
- authentication activity;
- scheduled tasks;
- service creation;
- persistence mechanisms;
- credential access;
- lateral movement;
- suspicious remote sessions;
- additional PowerShell execution;
- related endpoint alerts;
- associated network connections.

Search across the environment for:

- the same command line;
- similar script content;
- matching file hashes;
- identical executable paths;
- related domains;
- suspicious IP addresses;
- similar process behavior;
- related authentication activity;
- additional affected hosts.

Determine:

- number of affected hosts;
- number of affected accounts;
- number of related PowerShell executions;
- related malicious or suspicious processes;
- associated network destinations;
- earliest observed activity;
- most recent observed activity;
- presence of persistence;
- evidence of credential access;
- evidence of lateral movement;
- whether malicious activity is ongoing.

Document the identified scope and any telemetry limitations that prevent the complete extent of the activity from being established.

### Step 8 - Determine Investigation Outcome

Classify the PowerShell activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

At minimum, collect:

| Evidence       | Description                          |
| -------------- | ------------------------------------ |
| Host           | Hostname, IP, operating system       |
| User           | Account associated with execution    |
| Process        | PowerShell process metadata          |
| Parent         | Parent process details               |
| Command line   | Full observed command line           |
| Script content | Relevant script block or content     |
| Timestamp      | Process and related event timestamps |
| Network        | Related connections and destinations |
| Files          | Created or modified artifacts        |
| Hashes         | SHA-256 or other available hashes    |
| Authentication | Related account activity             |
| Detections     | Related alerts and rule IDs          |

## Decision Criteria

### Benign

Classify as **benign** when:

- the execution is attributable to an approved administrator or service;
- the command is consistent with documented operational activity;
- the host and account are expected;
- related network and file activity are normal;
- no additional suspicious indicators are identified.

Document the justification before closing the alert.

### Suspicious

Classify as **suspicious** when:

- the execution context is unusual;
- encoded or obfuscated PowerShell is present;
- the parent process is unexpected;
- network activity is anomalous;
- the user or host context is inconsistent with the observed action;
- related telemetry is incomplete and malicious activity cannot yet be ruled out.

Continue investigation and correlate additional evidence.

### Malicious

Classify as **malicious** when evidence supports unauthorized activity, such as:

- confirmed malicious payload execution;
- unauthorized remote access;
- persistence;
- credential access;
- lateral movement;
- command-and-control activity;
- confirmed malware execution.

Escalate to the appropriate incident response workflow.

### Inconclusive

Use **inconclusive** when the available evidence is insufficient to determine whether the PowerShell activity is legitimate or malicious.

Document:

- evidence collected;
- evidence that is unavailable;
- additional telemetry required;
- unresolved command or script content analysis;
- undetermined execution outcome and potential follow-on activity.

Do not close the investigation as benign when material evidence remains unavailable.

## Escalation

Escalate the investigation when any of the following conditions are met:

- a privileged account is involved unexpectedly;
- multiple hosts show the same behavior;
- PowerShell retrieves or executes an unknown payload;
- malicious files are identified;
- command-and-control behavior is observed;
- credential access is suspected;
- lateral movement is suspected;
- persistence is identified;
- the host is business-critical.

## Response Guidance

For confirmed malicious activity:

1. Preserve relevant evidence.
2. Follow the organization's endpoint isolation procedure when required.
3. Identify related accounts and hosts.
4. Search for the same indicators across the environment.
5. Review persistence mechanisms.
6. Review credential exposure.
7. Escalate to incident response.
8. Record the investigation timeline and findings.

Do not remove artifacts before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/obfuscated-powershell.yar`
- `detection-rules/yara/yara-powershell-payload.yar`
- `detection-rules/suricata/powershell-alert.rules`

## Related Playbooks

- `playbooks/execution/powershell.md`
- `playbooks/defense-evasion/obfuscated-powershell.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/isolate-host-response.md`
- `playbooks/response/malware-response.md`

## Validation

The playbook should be validated against the repository's approved test data.

Validation should confirm that:

- suspicious PowerShell activity is detected;
- expected evidence is available;
- related detection rules trigger as expected;
- benign PowerShell activity can be distinguished from suspicious activity;
- escalation criteria are understandable and reproducible.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Investigation and response actions must follow the organization's authorization, evidence preservation, and change-management procedures.
