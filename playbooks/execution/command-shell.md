---
id: "command-shell"
name: "Command Shell"
category: "execution"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-12T11:08:00Z"
updated_at: "2026-09-12T11:08:00Z"
description: "Command Shell execution involves using command-line interpreters to execute commands and programs on a system."
objective: "Identify, investigate, and validate suspicious command shell activity and determine whether command execution is legitimate, suspicious, or malicious."
severity: "high"
mitre_attack:
  - "T1059.003"
triggers:
  - "Suspicious command shell execution alert"
  - "Unexpected command shell process"
  - "Command shell launched by an unusual parent process"
  - "Encoded or obfuscated command execution"
  - "Command shell executing from an unusual location"
  - "Threat hunting identifies anomalous command shell activity"
prerequisites:
  - "Access to process creation telemetry"
  - "Access to command-line logging"
  - "Access to endpoint security telemetry"
  - "Access to file and network telemetry where available"
tags:
  - "command-shell"
  - "execution"
  - "command-line"
  - "windows"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1059/003/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Command Shell Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, user, timestamp, command shell process, and alert context."
  expected_result: "The suspicious command shell event and affected asset are identified."
- id: "review-command-line"
  order: 2
  name: "Review Command Line"
  action: "analyze"
  description: "Review the complete command line, arguments, execution options, and referenced files."
  expected_result: "The command line and execution parameters are documented."
- id: "review-parent-process"
  order: 3
  name: "Review Parent Process"
  action: "analyze"
  description: "Determine which process launched the command shell and assess whether the parent-child relationship is expected."
  expected_result: "The parent process and command shell execution chain are assessed."
- id: "review-child-processes"
  order: 4
  name: "Review Child Processes"
  action: "analyze"
  description: "Review child processes launched by the command shell and correlate them with the execution timeline."
  expected_result: "Command shell child-process activity is documented and correlated."
- id: "review-file-activity"
  order: 5
  name: "Review File Activity"
  action: "analyze"
  description: "Review files created, modified, downloaded, or executed by the command shell or its child processes."
  expected_result: "Related file activity is identified or ruled out."
- id: "review-network-activity"
  order: 6
  name: "Review Network Activity"
  action: "analyze"
  description: "Review DNS requests, network connections, and external destinations associated with the command shell or spawned processes."
  expected_result: "Related network activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Command Shell Activity Scope"
  action: "hunt"
  description: "Search for the same command line, process relationship, script, executable, or network destination across the environment."
  expected_result: "The prevalence and scope of the command shell activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the command shell activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "command-shell"
---

# Command Shell

## Purpose

This playbook provides a structured workflow for investigating suspicious command shell execution.

The objective is to determine whether command-line activity is legitimate, suspicious, or malicious and whether it is associated with additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name                                                     | Relevance                                                             |
| --------- | -------------------------------------------------------- | --------------------------------------------------------------------- |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Relevant when a command shell is used to execute commands or programs |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious command shell execution alert is generated.
- An unexpected command shell process is observed.
- A command shell is launched by an unusual parent process.
- Encoded or obfuscated command execution is detected.
- Command shell activity occurs from an unusual location or context.
- Suspicious child processes are launched by the command shell.
- Threat hunting identifies anomalous command shell activity.

## Scope

The investigation should consider:

- affected host;
- associated user or service account;
- command shell executable;
- command line;
- arguments;
- parent process;
- child processes;
- script or executable path;
- execution timestamp;
- user context;
- file activity;
- network activity;
- DNS activity;
- downloaded content;
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
- command shell process;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Review Command Line

Review the complete command line, including:

- command shell executable;
- switches;
- arguments;
- referenced scripts;
- referenced executables;
- redirection;
- piping;
- environment modifications.

Pay particular attention to:

- encoded or obfuscated commands;
- hidden execution;
- unusual arguments;
- commands that retrieve additional content;
- commands that execute tools from temporary or user-writable locations.

### Step 3 — Review Parent Process

Determine which process launched the command shell.

Investigate unusual parent processes such as:

- Office applications;
- email clients;
- browsers;
- document readers;
- archive utilities;
- unknown executables.

Assess the process relationship in context. A command shell launched by an administrative or automation tool is not inherently malicious.

### Step 4 — Review Child Processes

Review:

- child process names;
- executable paths;
- command lines;
- execution timestamps;
- account context.

Pay attention to command shells spawning:

- PowerShell;
- scripting interpreters;
- system utilities;
- archive tools;
- network utilities;
- unexpected executables.

Correlate child-process execution with the original command line.

### Step 5 — Review File Activity

Determine whether command shell activity resulted in:

- file creation;
- file modification;
- file download;
- archive extraction;
- executable launch;
- script creation.

Collect:

- filename;
- path;
- file type;
- hash;
- creation time;
- modification time.

Do not execute unknown files on production systems.

### Step 6 — Review Network Activity

Determine whether the command shell or its child processes generated network activity.

Collect:

- destination IP;
- destination domain;
- destination port;
- protocol;
- DNS requests;
- connection timestamps.

Investigate communication with unexpected or suspicious infrastructure.

### Step 7 — Determine Activity Scope

Search the environment for:

- same command line;
- same executable;
- same script;
- same parent-child process relationship;
- same file hash;
- same network destination.

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

| Evidence        | Description                                      |
| --------------- | ------------------------------------------------ |
| Alert           | Detection source, ID, severity, timestamp        |
| Host            | Hostname, IP address, operating system           |
| User            | Associated user or service account               |
| Command Shell   | Executable and execution context                 |
| Command Line    | Complete command line                            |
| Parent Process  | Process that launched the command shell          |
| Child Processes | Processes launched by the command shell          |
| Scripts         | Referenced scripts and metadata                  |
| Files           | Created, modified, downloaded, or executed files |
| Hashes          | SHA-256 or available file hashes                 |
| Network         | Related network connections                      |
| DNS             | Related DNS activity                             |
| Scope           | Other affected hosts and users                   |
| Detections      | Related security alerts                          |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the command is authorized;
- the account is expected;
- the parent process is legitimate;
- the command line matches approved administration;
- referenced files are trusted;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the command is unexpected;
- the source of execution is unclear;
- command-line arguments are unusual;
- encoded or obfuscated content is present;
- the parent-child relationship is abnormal;
- suspicious child processes or file activity are observed;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized command shell execution;
- malicious command or script content;
- malicious child-process execution;
- confirmed payload retrieval;
- command-and-control communication;
- credential access;
- persistence;
- other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the command shell activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious command execution is confirmed;
- credentials may have been accessed;
- persistence is identified;
- command-and-control activity is observed;
- multiple hosts are affected;
- a privileged account is involved;
- a business-critical system is affected.

## Response Guidance

For confirmed malicious command shell activity:

1. Preserve relevant process, command-line, file, and network evidence.
2. Identify all affected hosts and accounts.
3. Follow the organization's endpoint containment procedure.
4. Search for related command lines, scripts, hashes, and process patterns.
5. Investigate persistence, credential access, and lateral movement.
6. Follow authorized quarantine or remediation procedures.
7. Review possible credential exposure.
8. Escalate confirmed compromise to incident response.
9. Document the investigation timeline and remediation actions.

Do not delete or modify relevant scripts, files, logs, or other evidence before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/obfuscated-powershell.yar`

## Related Playbooks

- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/execution/scripting.md`
- `playbooks/execution/user-execution.md`
- `playbooks/execution/powershell.md`
- `playbooks/execution/python-execution.md`
- `playbooks/execution/wmi-execution.md`
- `playbooks/defense-evasion/obfuscated-powershell.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved command shell fixtures, endpoint telemetry, command-line datasets, and controlled execution scenarios.

Validation should confirm that:

- command shell execution can be identified;
- command lines can be investigated;
- parent and child processes can be correlated;
- file activity can be investigated;
- related network activity can be analyzed;
- environmental scope can be determined;
- legitimate administrative command execution can be distinguished from malicious execution;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Unknown commands, scripts, and executables should be analyzed in approved environments. Do not execute untrusted commands or scripts on production systems.
