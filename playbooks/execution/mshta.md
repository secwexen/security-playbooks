---
id: "mshta"
name: "Mshta"
category: "execution"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-13T14:58:00Z"
updated_at: "2026-09-13T21:41:00Z"
description: "Mshta.exe is a Windows utility that can execute HTML Applications (HTA) and may be abused to execute scripts or other malicious content."
objective: "Identify, investigate, and validate suspicious mshta.exe execution and determine whether the activity is legitimate, suspicious, or malicious."
severity: "high"
mitre_attack:
  - "T1218.005"
triggers:
  - "Suspicious mshta.exe execution alert"
  - "Mshta launched by an unusual parent process"
  - "Mshta executing content from a remote location"
  - "Mshta launched by a user-facing application"
  - "Mshta executing suspicious script or HTA content"
  - "Threat hunting identifies anomalous mshta.exe activity"
prerequisites:
  - "Access to process creation telemetry"
  - "Access to command-line telemetry"
  - "Access to endpoint security telemetry"
  - "Access to file and network telemetry where available"
tags:
  - "mshta"
  - "execution"
  - "windows"
  - "signed-binary-proxy-execution"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1218/005/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Mshta Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, user, timestamp, mshta.exe process, and alert context."
  expected_result: "The suspicious mshta.exe event and affected asset are identified."
- id: "review-command-line"
  order: 2
  name: "Review Mshta Command Line"
  action: "analyze"
  description: "Review the complete mshta.exe command line, referenced HTA or script content, arguments, and execution options."
  expected_result: "The command line and referenced content are documented."
- id: "review-parent-process"
  order: 3
  name: "Review Parent Process"
  action: "analyze"
  description: "Determine which process launched mshta.exe and assess whether the parent-child relationship is expected."
  expected_result: "The parent process and execution chain are assessed."
- id: "review-content"
  order: 4
  name: "Review HTA or Script Content"
  action: "analyze"
  description: "Review available HTA, script, URL, file metadata, hashes, and indicators of obfuscation or malicious behavior."
  expected_result: "The referenced content and relevant indicators are identified."
- id: "review-child-processes"
  order: 5
  name: "Review Child Processes"
  action: "analyze"
  description: "Review child processes launched by mshta.exe and correlate them with the execution timeline."
  expected_result: "Mshta child-process activity is documented and correlated."
- id: "review-network-activity"
  order: 6
  name: "Review Network Activity"
  action: "analyze"
  description: "Review DNS requests, network connections, remote resources, and external destinations associated with mshta.exe."
  expected_result: "Related network activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Mshta Activity Scope"
  action: "hunt"
  description: "Search for the same command line, URL, file hash, HTA content, parent-child relationship, or execution pattern across the environment."
  expected_result: "The prevalence and scope of the mshta.exe activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the mshta.exe activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "mshta"
---

# Mshta

## Purpose

This playbook provides a structured workflow for investigating suspicious `mshta.exe` execution on Windows systems.

`mshta.exe` is a legitimate Windows utility used to execute HTML Applications (HTA). It can also be abused to execute scripts or malicious content.

The objective is to determine whether mshta execution is legitimate, suspicious, or malicious and whether it is associated with additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name                                 | Relevance                                                                             |
| --------- | ------------------------------------ | ------------------------------------------------------------------------------------- |
| T1218.005 | System Binary Proxy Execution: Mshta | Relevant when mshta.exe is used to execute content or scripts in a suspicious context |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious `mshta.exe` execution alert is generated.
- `mshta.exe` is launched by an unusual parent process.
- Mshta accesses or executes content from a remote location.
- Mshta is launched by a user-facing application.
- Mshta executes suspicious HTA or script content.
- Mshta spawns unexpected child processes.
- Threat hunting identifies anomalous `mshta.exe` activity.

## Scope

The investigation should consider:

- affected host;
- associated user or service account;
- `mshta.exe` path;
- command line;
- arguments;
- HTA file;
- script content;
- URL;
- parent process;
- child processes;
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
- `mshta.exe` process;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Review Mshta Command Line

Review the complete command line, including:

- `mshta.exe`;
- HTA file path;
- URL;
- script content where visible;
- arguments;
- referenced resources.

Pay particular attention to:

- remote URLs;
- unusual file paths;
- encoded or obfuscated content;
- commands that execute other interpreters;
- content hosted outside approved infrastructure.

### Step 3 — Review Parent Process

Determine which process launched `mshta.exe`.

Investigate unusual parent processes such as:

- Office applications;
- email clients;
- browsers;
- document readers;
- archive utilities;
- unknown executables.

Assess the relationship in context. Administrative or application workflows may legitimately invoke mshta in some environments.

### Step 4 — Review HTA or Script Content

Where content is available, review:

- filename;
- URL;
- file path;
- hash;
- source;
- creation time;
- modification time;
- digital signature where applicable;
- script behavior;
- obfuscation.

Look for:

- embedded scripts;
- process execution;
- file creation;
- external resource retrieval;
- persistence-related behavior;
- credential access attempts.

Do not execute unknown HTA or script content on production systems.

### Step 5 — Review Child Processes

Review:

- child process names;
- executable paths;
- command lines;
- execution timestamps;
- account context.

Pay particular attention to `mshta.exe` spawning:

- PowerShell;
- command shells;
- scripting interpreters;
- system utilities;
- unexpected executables.

Correlate child-process activity with the original mshta execution.

### Step 6 — Review Network Activity

Determine whether `mshta.exe` or its child processes generated network activity.

Collect:

- destination IP;
- destination domain;
- destination port;
- protocol;
- DNS requests;
- connection timestamps;
- remote content URLs.

Investigate unexpected communication with suspicious or unapproved infrastructure.

### Step 7 — Determine Activity Scope

Search the environment for:

- same command line;
- same URL;
- same HTA hash;
- same script content;
- same executable hash;
- same parent-child relationship;
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

| Evidence        | Description                               |
| --------------- | ----------------------------------------- |
| Alert           | Detection source, ID, severity, timestamp |
| Host            | Hostname, IP address, operating system    |
| User            | Associated user or service account        |
| Mshta           | Executable path and execution context     |
| Command Line    | Complete command line and arguments       |
| HTA             | File, URL, path, hash, and metadata       |
| Script          | Available script content and indicators   |
| Parent Process  | Process that launched mshta.exe           |
| Child Processes | Processes launched by mshta.exe           |
| Files           | Created, downloaded, or modified files    |
| Network         | Related network connections               |
| DNS             | Related DNS activity                      |
| Scope           | Other affected hosts and users            |
| Detections      | Related security alerts                   |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- mshta execution is authorized;
- the source is known and trusted;
- the parent process is legitimate;
- the referenced HTA or script is expected;
- the command line matches approved application behavior;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the source content is unexpected;
- mshta is launched by an unusual process;
- remote content is referenced unexpectedly;
- HTA or script content is obfuscated;
- suspicious child processes are present;
- abnormal network activity is observed;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized mshta execution;
- confirmed malicious HTA or script content;
- malicious child-process execution;
- confirmed payload retrieval;
- command-and-control communication;
- credential access;
- persistence;
- other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the mshta activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious mshta execution is confirmed;
- credentials may have been accessed;
- persistence is identified;
- command-and-control activity is observed;
- multiple hosts are affected;
- a privileged account is involved;
- a business-critical system is affected.

## Response Guidance

For confirmed malicious mshta activity:

1. Preserve relevant process, command-line, HTA, file, and network evidence.
2. Identify all affected hosts and accounts.
3. Follow the organization's endpoint containment procedure.
4. Search for related URLs, hashes, command lines, scripts, and process relationships.
5. Investigate persistence, credential access, and lateral movement.
6. Follow authorized quarantine or remediation procedures.
7. Review possible credential exposure.
8. Escalate confirmed compromise to incident response.
9. Document the investigation timeline and remediation actions.

Do not delete or modify relevant HTA files, scripts, logs, or other evidence before required evidence preservation has been completed.

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
- `playbooks/execution/python-execution.md`
- `playbooks/execution/wmi-execution.md`
- `playbooks/execution/scheduled-task-execution.md`
- `playbooks/defense-evasion/obfuscated-powershell.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved mshta telemetry, process creation events, HTA fixtures, network telemetry, and controlled execution scenarios.

Validation should confirm that:

- mshta.exe execution can be identified;
- command lines can be investigated;
- HTA and script metadata can be analyzed;
- parent and child processes can be correlated;
- remote content access can be identified;
- related network activity can be investigated;
- environmental scope can be determined;
- legitimate mshta usage can be distinguished from malicious execution;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Unknown HTA files, scripts, and remote resources should be analyzed in approved environments. Do not execute untrusted mshta content on production systems.
