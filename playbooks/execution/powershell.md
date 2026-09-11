---
id: "powershell"
name: "PowerShell"
category: "execution"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-11T16:03:00Z"
updated_at: "2026-09-11T16:03:00Z"
description: "PowerShell is a command and scripting interpreter commonly used for Windows administration and automation and may also be abused to execute malicious commands and scripts."
objective: "Identify, investigate, and validate suspicious PowerShell activity and determine whether execution is legitimate, suspicious, or malicious."
severity: "high"
mitre_attack:
  - "T1059.001"
triggers:
  - "Suspicious PowerShell execution alert"
  - "Encoded PowerShell command"
  - "PowerShell executed from an unusual parent process"
  - "PowerShell launched from a user-facing application"
  - "PowerShell downloads or executes additional content"
  - "Threat hunting identifies anomalous PowerShell activity"
prerequisites:
  - "Access to PowerShell and process telemetry"
  - "Access to command-line logging"
  - "Access to endpoint security telemetry"
  - "Access to file and network telemetry where available"
tags:
  - "powershell"
  - "execution"
  - "command-line"
  - "windows"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1059/001/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify PowerShell Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, user, timestamp, PowerShell process, and alert context."
  expected_result: "The suspicious PowerShell event and affected asset are identified."
- id: "review-command-line"
  order: 2
  name: "Review PowerShell Command Line"
  action: "analyze"
  description: "Review the complete PowerShell command line, parameters, encoded content, execution options, and script path."
  expected_result: "The PowerShell command line and execution parameters are documented."
- id: "review-parent-process"
  order: 3
  name: "Review Parent Process"
  action: "analyze"
  description: "Determine which process launched PowerShell and assess whether the parent-child relationship is expected."
  expected_result: "The PowerShell parent process and execution chain are assessed."
- id: "review-script-content"
  order: 4
  name: "Review Script Content"
  action: "analyze"
  description: "Review available script content, file metadata, hashes, signatures, and indicators of obfuscation or malicious behavior."
  expected_result: "Relevant PowerShell script characteristics are identified."
- id: "review-child-processes"
  order: 5
  name: "Review Child Processes"
  action: "analyze"
  description: "Review child processes launched by PowerShell and correlate them with the execution timeline."
  expected_result: "PowerShell child-process activity is documented and correlated."
- id: "review-network-activity"
  order: 6
  name: "Review Network Activity"
  action: "analyze"
  description: "Review DNS requests, network connections, downloads, and external destinations associated with PowerShell."
  expected_result: "Related network activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine PowerShell Activity Scope"
  action: "hunt"
  description: "Search for the same command line, script hash, script path, encoded pattern, or parent-child process relationship across the environment."
  expected_result: "The prevalence and scope of the PowerShell activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the PowerShell activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "powershell"
---

# PowerShell

## Purpose

This playbook provides a structured workflow for investigating suspicious PowerShell execution on Windows systems.

The objective is to determine whether PowerShell activity is legitimate, suspicious, or malicious and whether it is associated with additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name                                          | Relevance                                                       |
| --------- | --------------------------------------------- | --------------------------------------------------------------- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Relevant when PowerShell is used to execute commands or scripts |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious PowerShell execution alert is generated.
- An encoded PowerShell command is observed.
- PowerShell is launched by an unusual parent process.
- PowerShell is started by a user-facing application.
- PowerShell downloads or executes additional content.
- PowerShell executes from an unusual location or context.
- Threat hunting identifies anomalous PowerShell behavior.

## Scope

The investigation should consider:

- affected host;
- associated user or service account;
- PowerShell executable;
- PowerShell version;
- command line;
- script path;
- script hash;
- parent process;
- child processes;
- execution timestamp;
- user context;
- encoded content;
- file activity;
- network activity;
- DNS activity;
- downloaded content;
- persistence;
- related alerts;
- additional affected hosts.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- PowerShell process;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Review PowerShell Command Line

Review the complete command line, including:

- PowerShell executable;
- parameters;
- script path;
- arguments;
- encoded commands;
- execution policy parameters;
- hidden or non-interactive options;
- download-related parameters.

Pay particular attention to:

- encoded commands;
- obfuscated content;
- unusual execution options;
- commands that retrieve additional content;
- commands executed from temporary or user-writable locations.

### Step 3 — Review Parent Process

Determine which process launched PowerShell.

Expected administrative relationships may include approved management or automation software.

Investigate unusual relationships such as PowerShell launched by:

- Office applications;
- email clients;
- browsers;
- archive utilities;
- document readers;
- unknown executables.

Parent-child relationships should be assessed in context and not classified as malicious solely because PowerShell was launched.

### Step 4 — Review Script Content

Where script content is available, review:

- filename;
- path;
- hash;
- digital signature;
- creation time;
- modification time;
- source;
- obfuscation;
- embedded commands;
- referenced files;
- external resources.

Do not execute unknown PowerShell scripts on production systems.

### Step 5 — Review Child Processes

Review:

- child process names;
- process paths;
- command lines;
- execution timestamps;
- account context.

Pay attention to PowerShell spawning:

- command shells;
- scripting interpreters;
- system utilities;
- archive tools;
- unexpected executables.

### Step 6 — Review Network Activity

Determine whether PowerShell or its child processes generated network activity.

Collect:

- destination IP;
- destination domain;
- destination port;
- protocol;
- DNS requests;
- connection timestamps;
- downloaded resources.

Investigate unexpected communication with suspicious or unapproved infrastructure.

### Step 7 — Determine Activity Scope

Search the environment for:

- command line;
- script hash;
- script path;
- encoded PowerShell pattern;
- parent-child process relationship;
- network destination;
- related file hash.

Determine:

- number of affected hosts;
- number of affected users;
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

| Evidence        | Description                               |
| --------------- | ----------------------------------------- |
| Alert           | Detection source, ID, severity, timestamp |
| Host            | Hostname, IP address, operating system    |
| User            | Associated user or service account        |
| PowerShell      | Executable and version                    |
| Command Line    | Complete PowerShell command line          |
| Script          | Filename, path, type, hash                |
| Parent Process  | Process that launched PowerShell          |
| Child Processes | Processes launched by PowerShell          |
| Script Metadata | Timestamps, signature, source             |
| Files           | Created, downloaded, or modified files    |
| Network         | Related network connections               |
| DNS             | Related DNS activity                      |
| Scope           | Other affected hosts and users            |
| Detections      | Related security alerts                   |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the PowerShell execution is authorized;
- the account is expected;
- the parent process is legitimate;
- the command line matches approved administration;
- the script is known and trusted;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the command line is unusual;
- encoded or obfuscated content is present;
- the script source is unclear;
- PowerShell is launched by an unexpected process;
- suspicious child processes are present;
- network activity is abnormal;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized PowerShell execution;
- malicious script content;
- confirmed payload retrieval;
- malicious child-process execution;
- command-and-control communication;
- credential access;
- persistence;
- other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the PowerShell activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious PowerShell execution is confirmed;
- credentials may have been accessed;
- persistence is identified;
- command-and-control activity is observed;
- multiple hosts are affected;
- a privileged account is involved;
- a business-critical system is affected.

## Response Guidance

For confirmed malicious PowerShell activity:

1. Preserve relevant process, command-line, script, and network evidence.
2. Identify all affected hosts and accounts.
3. Follow the organization's endpoint containment procedure.
4. Search for related PowerShell command lines, scripts, hashes, and indicators.
5. Investigate persistence, credential access, and lateral movement.
6. Follow authorized quarantine or remediation procedures.
7. Review possible credential exposure.
8. Escalate confirmed compromise to incident response.
9. Document the investigation timeline and remediation actions.

Do not delete or modify relevant scripts, logs, or other evidence before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/yara/obfuscated-powershell.yar`
- `detection-rules/yara/yara-powershell-payload.yar`

## Related Playbooks

- `playbooks/triage/suspicious-powershell-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/execution/scripting.md`
- `playbooks/execution/user-execution.md`
- `playbooks/execution/command-shell.md`
- `playbooks/defense-evasion/obfuscated-powershell.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved PowerShell fixtures, endpoint telemetry, command-line datasets, and controlled execution scenarios.

Validation should confirm that:

- PowerShell execution can be identified;
- command lines can be investigated;
- script metadata can be analyzed;
- parent and child processes can be correlated;
- encoded or obfuscated activity can be identified;
- related network activity can be investigated;
- environmental scope can be determined;
- legitimate PowerShell administration can be distinguished from malicious execution;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Unknown PowerShell scripts and commands should be analyzed in approved environments. Do not execute untrusted PowerShell content on production systems.
