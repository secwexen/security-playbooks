---
id: "suspicious-powershell-triage"
name: "Suspicious PowerShell Triage"
category: "triage"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-08-29T00:00:00Z"
updated_at: "2026-08-29T00:00:00Z"
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
  validation:
  validated: false
  required: true
  last_validated: null
  scenario: "suspicious-powershell"
---

# Suspicious PowerShell Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspicious PowerShell execution on Windows systems.

The goal is to determine whether the observed activity is:

- expected administrative activity;
- suspicious activity requiring additional investigation; or
- confirmed malicious activity requiring incident response.

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
- loaded modules;
- created or modified files;
- network connections;
- related authentication events;
- related detections on other hosts.

## Triage Procedure

### Step 1 — Identify the Affected Host

Collect:

- hostname;
- IP address;
- operating system;
- asset owner;
- host criticality;
- current isolation status.

Determine whether the endpoint is:

- a user workstation;
- a server;
- an administrative workstation;
- a domain controller; or
- another security-sensitive asset.

### Step 2 — Identify the User

Determine which account initiated or was associated with the PowerShell process.

Collect:

- username;
- domain;
- account type;
- logon type;
- source workstation where available;
- recent authentication activity.

Check whether the account is:

- a standard user;
- an administrator;
- a service account;
- a privileged account; or
- an unexpected account for the affected host.

### Step 3 — Review Process Execution

Collect the PowerShell process details:

- process ID;
- parent process ID;
- process creation time;
- executable path;
- command line;
- integrity level;
- parent process;
- child processes.

Pay particular attention to unusual parent processes such as:

- Office applications;
- archive utilities;
- script interpreters;
- browser processes;
- temporary directory executables;
- unknown or unsigned binaries.

### Step 4 — Review the Command Line

Inspect the PowerShell command line for:

- encoded commands;
- unusual parameters;
- hidden execution;
- execution policy changes;
- suspicious download behavior;
- unusual temporary paths;
- embedded scripts;
- dynamically generated content;
- attempts to bypass normal logging or security controls.

Do not classify a command as malicious solely because it contains a suspicious-looking parameter. Correlate command-line evidence with process, user, host, and network context.

### Step 5 — Check for Encoding or Obfuscation

Investigate indicators such as:

- encoded PowerShell input;
- excessive escaping;
- string concatenation;
- dynamically constructed commands;
- compressed or transformed script content;
- unusually long command lines.

Determine whether the encoding or obfuscation has a legitimate operational explanation.

### Step 6 — Review PowerShell Logging

When available, review:

- PowerShell operational logs;
- Script Block Logging;
- module logging;
- transcription logs;
- associated Windows event records.

Correlate timestamps with:

- process creation;
- authentication events;
- file creation;
- network activity.

### Step 7 — Review Network Activity

Investigate network connections associated with the PowerShell process.

Collect:

- destination IP;
- destination domain;
- destination port;
- protocol;
- connection time;
- connection duration;
- DNS lookups;
- HTTP/HTTPS metadata where available.

Escalate investigation priority when PowerShell execution is followed by:

- unusual external communication;
- previously unseen destinations;
- suspicious domains;
- repeated periodic connections;
- payload retrieval;
- command-and-control-like behavior.

### Step 8 — Review File and Artifact Activity

Identify files created, modified, or accessed around the execution time.

Focus on:

- temporary files;
- scripts;
- executables;
- archives;
- downloaded payloads;
- suspicious files in user-writable directories.

Collect hashes where appropriate.

### Step 9 — Correlate Related Events

Search for related activity on the same host and account:

- process creation;
- authentication;
- scheduled tasks;
- service creation;
- persistence mechanisms;
- credential access;
- lateral movement;
- additional PowerShell execution.

Search across the environment for the same command line, hash, domain, or behavioral pattern.

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
