---
id: "python-execution"
name: "Python Execution"
category: "execution"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-12T17:43:00Z"
updated_at: "2026-09-12T17:43:00Z"
description: "Python execution involves using the Python interpreter or Python-based tooling to execute scripts and code on a system."
objective: "Identify, investigate, and validate suspicious Python execution and determine whether the activity is legitimate, suspicious, or malicious."
severity: "high"
mitre_attack:
  - "T1059.006"
triggers:
  - "Suspicious Python execution alert"
  - "Unexpected Python interpreter activity"
  - "Python launched by an unusual parent process"
  - "Python executing code from an unusual location"
  - "Python downloading or executing additional content"
  - "Threat hunting identifies anomalous Python activity"
prerequisites:
  - "Access to process creation telemetry"
  - "Access to command-line telemetry"
  - "Access to endpoint security telemetry"
  - "Access to file and network telemetry where available"
tags:
  - "python"
  - "execution"
  - "command-line"
  - "scripting"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1059/006/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Python Execution Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, user, timestamp, Python process, and alert context."
  expected_result: "The suspicious Python execution event and affected asset are identified."
- id: "review-command-line"
  order: 2
  name: "Review Python Command Line"
  action: "analyze"
  description: "Review the complete Python command line, interpreter options, script path, module execution, and arguments."
  expected_result: "The Python command line and execution parameters are documented."
- id: "review-script"
  order: 3
  name: "Review Python Script Context"
  action: "analyze"
  description: "Review the script path, filename, hash, source, metadata, and available script content."
  expected_result: "The Python script context and relevant indicators are identified."
- id: "review-parent-process"
  order: 4
  name: "Review Parent Process"
  action: "analyze"
  description: "Determine which process launched Python and assess whether the parent-child relationship is expected."
  expected_result: "The Python parent process and execution chain are assessed."
- id: "review-child-processes"
  order: 5
  name: "Review Child Processes"
  action: "analyze"
  description: "Review child processes launched by Python and correlate them with the execution timeline."
  expected_result: "Python child-process activity is documented and correlated."
- id: "review-network-activity"
  order: 6
  name: "Review Network Activity"
  action: "analyze"
  description: "Review DNS requests, network connections, downloaded content, and external destinations associated with Python."
  expected_result: "Related network activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Python Activity Scope"
  action: "hunt"
  description: "Search for the same script hash, script path, command line, interpreter pattern, or process relationship across the environment."
  expected_result: "The prevalence and scope of the Python activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the Python execution activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "python-execution"
---

# Python Execution

## Purpose

This playbook provides a structured workflow for investigating suspicious Python execution on endpoint and server systems.

The objective is to determine whether Python execution is legitimate, suspicious, or malicious and whether it is associated with additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name                                      | Relevance                                                   |
| --------- | ----------------------------------------- | ----------------------------------------------------------- |
| T1059.006 | Command and Scripting Interpreter: Python | Relevant when Python is used to execute commands or scripts |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious Python execution alert is generated.
- An unexpected Python interpreter is executed.
- Python is launched by an unusual parent process.
- A Python script executes from an unusual location.
- Python downloads or executes additional content.
- Python spawns unexpected child processes.
- Threat hunting identifies anomalous Python activity.

## Scope

The investigation should consider:

- affected host;
- associated user or service account;
- Python executable;
- Python version;
- command line;
- script path;
- script filename;
- script hash;
- module execution;
- parent process;
- child processes;
- execution timestamp;
- user context;
- working directory;
- environment variables where relevant;
- file activity;
- network activity;
- DNS activity;
- downloaded content;
- package installation activity;
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
- Python process;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Review Python Command Line

Review the complete command line, including:

- Python executable;
- interpreter options;
- script path;
- module invocation;
- arguments;
- working directory;
- environment-specific parameters.

Pay particular attention to:

- scripts executed from temporary directories;
- scripts executed from user-writable locations;
- unexpected module execution;
- commands that retrieve additional content;
- unusual or obfuscated command arguments.

### Step 3 — Review Python Script Context

Determine:

- script filename;
- script path;
- file hash;
- creation time;
- modification time;
- source;
- digital signature where applicable;
- associated package or module.

Where authorized and safely available, review the script content for:

- suspicious imports;
- encoded content;
- external resource access;
- process execution;
- persistence-related behavior;
- unexpected file operations.

Do not execute unknown Python scripts on production systems.

### Step 4 — Review Parent Process

Determine which process launched Python.

Investigate unexpected relationships such as Python launched by:

- Office applications;
- email clients;
- browsers;
- document readers;
- archive utilities;
- unknown executables.

Assess the relationship in context. Python launched by an approved development, automation, or management tool is not inherently malicious.

### Step 5 — Review Child Processes

Review:

- child process names;
- executable paths;
- command lines;
- execution timestamps;
- account context.

Pay particular attention to Python spawning:

- command shells;
- PowerShell;
- system utilities;
- scripting interpreters;
- archive tools;
- unexpected executables.

Correlate child-process activity with the original Python execution.

### Step 6 — Review Network Activity

Determine whether Python or its child processes generated network activity.

Collect:

- destination IP;
- destination domain;
- destination port;
- protocol;
- DNS requests;
- connection timestamps;
- downloaded resources.

Investigate communication with unexpected or suspicious infrastructure.

Review package-management activity such as unexpected downloads or package installation when relevant to the event.

### Step 7 — Determine Activity Scope

Search the environment for:

- same script hash;
- same script path;
- same command line;
- same Python module;
- same parent-child process relationship;
- same network destination;
- related file hashes.

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

| Evidence         | Description                                      |
| ---------------- | ------------------------------------------------ |
| Alert            | Detection source, ID, severity, timestamp        |
| Host             | Hostname, IP address, operating system           |
| User             | Associated user or service account               |
| Python           | Interpreter executable and version               |
| Command Line     | Complete Python command line                     |
| Script           | Filename, path, type, hash                       |
| Module           | Module or package invoked                        |
| Parent Process   | Process that launched Python                     |
| Child Processes  | Processes launched by Python                     |
| Script Metadata  | Timestamps and available metadata                |
| Files            | Created, modified, downloaded, or executed files |
| Network          | Related network connections                      |
| DNS              | Related DNS activity                             |
| Package Activity | Relevant package downloads or installations      |
| Scope            | Other affected hosts and users                   |
| Detections       | Related security alerts                          |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- Python execution is authorized;
- the account is expected;
- the script is known and trusted;
- the parent process is legitimate;
- the command line matches approved development or automation;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the script or source is unexpected;
- the command line is unusual;
- the execution location is abnormal;
- suspicious child processes are present;
- unexpected network activity is observed;
- package activity is unusual;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized Python execution;
- malicious script content;
- confirmed payload retrieval;
- malicious child-process execution;
- command-and-control communication;
- credential access;
- persistence;
- other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the Python activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious Python execution is confirmed;
- credentials may have been accessed;
- persistence is identified;
- command-and-control activity is observed;
- multiple hosts are affected;
- a privileged account is involved;
- a business-critical system is affected.

## Response Guidance

For confirmed malicious Python activity:

1. Preserve relevant process, command-line, script, and network evidence.
2. Identify all affected hosts and accounts.
3. Follow the organization's endpoint containment procedure.
4. Search for related Python command lines, scripts, hashes, and process patterns.
5. Review package installation and downloaded content where relevant.
6. Investigate persistence, credential access, and lateral movement.
7. Follow authorized quarantine or remediation procedures.
8. Review possible credential exposure.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Do not delete or modify relevant scripts, files, package artifacts, logs, or other evidence before required evidence preservation has been completed.

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
- `playbooks/execution/command-shell.md`
- `playbooks/defense-evasion/obfuscated-powershell.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved Python execution fixtures, endpoint telemetry, command-line datasets, and controlled execution scenarios.

Validation should confirm that:

- Python execution can be identified;
- command lines can be investigated;
- Python scripts and metadata can be analyzed;
- parent and child processes can be correlated;
- related file and network activity can be investigated;
- Python package activity can be reviewed where relevant;
- environmental scope can be determined;
- legitimate Python development and automation can be distinguished from malicious execution;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Unknown Python scripts and packages should be analyzed in approved environments. Do not execute untrusted Python code on production systems.
