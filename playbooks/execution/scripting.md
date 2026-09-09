---
id: "scripting"
name: "Scripting"
category: "execution"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-09T20:50:00Z"
updated_at: "2026-09-09T20:50:00Z"
description: "Scripting enables adversaries to execute commands and code through scripting engines and interpreters available on a system."
objective: "Identify, investigate, and validate suspicious scripting activity and determine whether script execution is associated with unauthorized or malicious behavior."
severity: "high"
mitre_attack:
  - "T1059"
triggers:
  - "Suspicious script execution alert"
  - "Unexpected scripting interpreter activity"
  - "Encoded or obfuscated script execution"
  - "Script executed from an unusual location"
  - "Suspicious child process spawned by a scripting engine"
  - "Threat hunting identifies anomalous script execution"
prerequisites:
  - "Access to process creation telemetry"
  - "Access to command-line telemetry"
  - "Access to endpoint security telemetry"
  - "Access to file and network telemetry where available"
tags:
  - "scripting"
  - "execution"
  - "command-line"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1059/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Script Execution Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, user, script interpreter, timestamp, and alert context."
  expected_result: "The suspicious script execution event and affected asset are identified."
- id: "identify-interpreter"
  order: 2
  name: "Identify Script Interpreter"
  action: "analyze"
  description: "Determine which scripting engine or interpreter executed the script."
  expected_result: "The scripting interpreter and execution context are identified."
- id: "review-command-line"
  order: 3
  name: "Review Command Line"
  action: "analyze"
  description: "Review the complete command line, parameters, encoded content, and execution options."
  expected_result: "The script execution command line is documented and assessed."
- id: "review-script"
  order: 4
  name: "Review Script Context"
  action: "analyze"
  description: "Review the script path, filename, source, content indicators, and related files where available."
  expected_result: "The script origin and relevant characteristics are identified."
- id: "review-process-tree"
  order: 5
  name: "Review Process Tree"
  action: "analyze"
  description: "Review the parent process, scripting interpreter, child processes, and related execution chain."
  expected_result: "The complete execution chain is documented."
- id: "review-network-activity"
  order: 6
  name: "Review Network Activity"
  action: "analyze"
  description: "Review network connections, DNS activity, and external destinations associated with the script or spawned processes."
  expected_result: "Relevant network activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Script Activity Scope"
  action: "hunt"
  description: "Search for the same command line, script hash, script path, interpreter pattern, or related activity across the environment."
  expected_result: "The prevalence and scope of the scripting activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the scripting activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "scripting"
---

# Scripting

## Purpose

This playbook provides a structured workflow for investigating suspicious scripting activity on endpoint systems.

The objective is to determine whether script execution is legitimate, suspicious, or malicious and whether it is associated with additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name                              | Relevance                                                                 |
| --------- | --------------------------------- | ------------------------------------------------------------------------- |
| T1059     | Command and Scripting Interpreter | Relevant when scripting interpreters are used to execute commands or code |

Additional T1059 sub-techniques should only be mapped when supported by the observed interpreter and execution behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious script execution alert is generated.
- An unexpected scripting interpreter is executed.
- A script contains encoded or obfuscated content.
- A script executes from an unusual location.
- A scripting engine launches an unexpected child process.
- Script execution is associated with suspicious network activity.
- Threat hunting identifies anomalous scripting behavior.

## Scope

The investigation should consider:

- affected host;
- associated user or service account;
- scripting interpreter;
- script path;
- script filename;
- command line;
- script hash;
- parent process;
- child processes;
- execution timestamp;
- user context;
- integrity level;
- network activity;
- DNS activity;
- related files;
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
- scripting interpreter;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify the Script Interpreter

Determine which interpreter or scripting engine was used.

Examples include:

- PowerShell;
- Windows Command Shell;
- Python;
- JavaScript or other supported scripting environments.

Identify the interpreter executable, version where available, and execution context.

### Step 3 — Review Command Line

Review the complete command line, including:

- interpreter options;
- script path;
- arguments;
- encoded content;
- download options;
- execution options;
- environment-specific parameters.

Pay particular attention to:

- encoded commands;
- hidden execution;
- unusual parameters;
- commands that download or execute additional content;
- commands executed from temporary or user-writable locations.

### Step 4 — Review Script Context

Determine:

- script path;
- filename;
- file type;
- hash;
- creation time;
- modification time;
- source;
- digital signature where applicable.

Assess whether the script was:

- locally created;
- downloaded;
- delivered by email;
- retrieved from a network location;
- deployed by an approved administrative process.

### Step 5 — Review Process Tree

Review:

- parent process;
- scripting interpreter;
- child processes;
- process creation times;
- user context;
- command lines.

Inspect the complete process chain rather than relying on the interpreter name alone.

Pay attention to interpreters spawning:

- command shells;
- system utilities;
- archive tools;
- credential-access tools;
- network utilities;
- unexpected executables.

### Step 6 — Review Network Activity

Determine whether the script or its child processes generated network activity.

Collect:

- destination IP;
- destination domain;
- destination port;
- protocol;
- DNS requests;
- connection timestamps;
- repeated connections.

Investigate communication with unexpected or suspicious infrastructure.

### Step 7 — Determine Activity Scope

Search the environment for:

- the same script hash;
- script filename;
- script path;
- command line;
- interpreter pattern;
- parent-child process relationship;
- network destination.

Determine:

- number of affected hosts;
- number of affected users;
- first observed time;
- latest observed time;
- whether execution is still active.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence     | Description                               |
| ------------ | ----------------------------------------- |
| Alert        | Detection source, ID, severity, timestamp |
| Host         | Hostname, IP address, operating system    |
| User         | Associated user or service account        |
| Interpreter  | Script engine or interpreter              |
| Script       | Filename, path, type, hash                |
| Command Line | Complete execution command line           |
| Process Tree | Parent and child processes                |
| Metadata     | Script timestamps and file metadata       |
| Signature    | Digital signature where applicable        |
| Network      | Related network activity                  |
| DNS          | Related DNS activity                      |
| Scope        | Other affected hosts and users            |
| Detections   | Related security alerts                   |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the interpreter is approved;
- the script is known and authorized;
- the execution context is expected;
- the command line matches documented administrative activity;
- no suspicious child processes or network activity are identified.

Document the justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the script is unexpected;
- the source is unclear;
- the command line is unusual;
- encoding or obfuscation is present;
- execution occurs from an unusual location;
- suspicious child processes are present;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized script execution;
- malicious script content;
- confirmed payload retrieval;
- malicious child-process execution;
- command-and-control activity;
- credential access;
- persistence or other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the scripting activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious script execution is confirmed;
- credentials may have been accessed;
- persistence is identified;
- command-and-control activity is observed;
- multiple hosts are affected;
- a privileged account is involved;
- a business-critical system is affected.

## Response Guidance

For confirmed malicious scripting activity:

1. Preserve relevant process, file, command-line, and network evidence.
2. Follow the organization's endpoint containment procedure.
3. Identify all affected hosts and accounts.
4. Search for the script hash, path, and command line across the environment.
5. Review related persistence, credential-access, and lateral-movement activity.
6. Follow authorized quarantine or remediation procedures.
7. Escalate confirmed compromise to incident response.
8. Document the investigation timeline and actions taken.

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
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/execution/powershell.md`
- `playbooks/execution/command-shell.md`
- `playbooks/execution/python-execution.md`
- `playbooks/defense-evasion/obfuscated-powershell.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved script fixtures, endpoint telemetry, command-line datasets, and controlled execution scenarios.

Validation should confirm that:

- script interpreters can be identified;
- suspicious command lines can be investigated;
- script files and metadata can be analyzed;
- process trees can be correlated;
- related network activity can be investigated;
- activity scope can be determined;
- legitimate scripting can be distinguished from malicious execution;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Suspicious scripts should be analyzed in approved environments. Do not execute unknown or untrusted scripts on production systems.
