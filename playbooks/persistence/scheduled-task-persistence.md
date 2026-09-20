---
id: "scheduled-task-persistence"
name: "Scheduled Task Persistence"
category: "persistence"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-13T18:41:00Z"
updated_at: "2026-09-20T19:18:00Z"
description: "Scheduled tasks can be configured to execute programs or scripts automatically and may be abused to maintain persistence on Windows systems."
objective: "Identify, investigate, and validate suspicious scheduled task persistence and determine whether the task is legitimate, suspicious, or malicious."
severity: "high"
mitre_attack:
  - "T1053.005"
triggers:
  - "Suspicious scheduled task creation"
  - "Unexpected scheduled task modification"
  - "Scheduled task configured for automatic execution"
  - "Unknown executable or script referenced by a scheduled task"
  - "Scheduled task using an unexpected account or privilege level"
  - "Threat hunting identifies anomalous scheduled task persistence"
prerequisites:
  - "Access to scheduled task telemetry"
  - "Access to process creation telemetry"
  - "Access to command-line logging"
  - "Access to endpoint, file, and authentication telemetry where available"
tags:
  - "scheduled-task"
  - "persistence"
  - "windows"
  - "task-scheduler"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1053/005/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Scheduled Task Persistence Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, account, task name, creation or modification event, and timestamp."
  expected_result: "The suspicious scheduled task persistence event and affected asset are identified."
- id: "identify-task"
  order: 2
  name: "Identify Scheduled Task"
  action: "analyze"
  description: "Identify the task name, task path, trigger, action, run-as account, and privilege configuration."
  expected_result: "The scheduled task configuration is documented."
- id: "review-task-lifecycle"
  order: 3
  name: "Review Task Lifecycle"
  action: "analyze"
  description: "Review task creation, modification, deletion, trigger changes, and related administrative activity."
  expected_result: "The task lifecycle and relevant changes are established."
- id: "review-payload"
  order: 4
  name: "Review Persistence Payload"
  action: "analyze"
  description: "Review the executable, script, command line, file path, hash, and working directory referenced by the task."
  expected_result: "The task payload and execution context are assessed."
- id: "review-account-context"
  order: 5
  name: "Review Account and Privilege Context"
  action: "analyze"
  description: "Determine which account executes the task and whether the configured privilege level is expected."
  expected_result: "The account and privilege context are documented and assessed."
- id: "review-execution"
  order: 6
  name: "Review Task Execution"
  action: "analyze"
  description: "Correlate scheduled task execution with process creation, child processes, file activity, and network activity."
  expected_result: "Task execution and resulting activity are correlated."
- id: "determine-scope"
  order: 7
  name: "Determine Persistence Scope"
  action: "hunt"
  description: "Search for the same task name, executable, script, command line, account, or persistence pattern across the environment."
  expected_result: "The prevalence and scope of the scheduled task persistence are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the scheduled task persistence and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "scheduled-task-persistence"
---

# Scheduled Task Persistence

## Purpose

This playbook provides a structured workflow for investigating suspicious scheduled task persistence on Windows systems.

Scheduled tasks are legitimate Windows automation mechanisms that can also be abused to execute malicious programs or scripts automatically and maintain persistence.

The objective is to determine whether a scheduled task is legitimate, suspicious, or malicious and whether it is associated with additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name                               | Relevance                                                                                      |
| --------- | ---------------------------------- | ---------------------------------------------------------------------------------------------- |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Relevant when Windows Task Scheduler is used to establish or maintain execution or persistence |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious scheduled task creation alert is generated.
- An existing scheduled task is unexpectedly modified.
- A task references an unknown executable or script.
- A task executes under an unexpected account.
- A task uses elevated privileges without an established operational reason.
- A task is configured to execute at startup, logon, or another recurring trigger unexpectedly.
- Threat hunting identifies anomalous scheduled task persistence.

## Scope

The investigation should consider:

- affected host;
- task name;
- task path;
- trigger;
- action;
- executable;
- script;
- command line;
- arguments;
- working directory;
- run-as account;
- privilege level;
- creation time;
- modification time;
- execution time;
- process tree;
- file activity;
- network activity;
- authentication activity;
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
- task name;
- task path;
- detection severity;
- detection reason.

Preserve the original alert context before making changes to the task.

### Step 2 — Identify the Scheduled Task

Collect:

- task name;
- task path;
- scheduler;
- trigger;
- action;
- run-as account;
- privilege configuration;
- execution conditions.

Determine whether the task is known and expected on the affected system.

### Step 3 — Review Task Lifecycle

Determine:

- when the task was created;
- when it was modified;
- which account created it;
- which account modified it;
- whether its trigger or action changed;
- whether related administrative activity occurred.

Look for unexpected creation or modification activity around the time of the alert.

### Step 4 — Review Persistence Payload

Review the task action, including:

- executable path;
- script path;
- command line;
- arguments;
- working directory;
- file hash;
- digital signature where applicable.

Pay particular attention to payloads located in:

- user-writable directories;
- temporary directories;
- hidden directories;
- unusual application data paths;
- locations not normally used by scheduled tasks.

### Step 5 — Review Account and Privilege Context

Determine:

- execution account;
- interactive or service context;
- privilege level;
- whether elevation is enabled;
- whether the account is expected to run the task.

An elevated task is not inherently malicious; assess it against normal administrative and application behavior.

### Step 6 — Review Task Execution

Correlate the task with:

- process creation;
- parent-child relationships;
- command-line telemetry;
- created or modified files;
- network connections;
- DNS activity;
- authentication events.

Determine whether the task produced unexpected activity after execution.

### Step 7 — Determine Persistence Scope

Search across the environment for:

- same task name;
- same task path;
- same executable;
- same script;
- same command line;
- same account;
- same trigger;
- same file hash.

Determine:

- number of affected hosts;
- number of affected accounts;
- first observed task creation;
- latest observed execution;
- whether the task remains active.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence       | Description                               |
| -------------- | ----------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp |
| Host           | Hostname, IP address, operating system    |
| Task           | Task name and path                        |
| Trigger        | Schedule or event condition               |
| Action         | Executable, script, arguments             |
| Account        | Run-as account and privilege context      |
| Lifecycle      | Creation and modification activity        |
| Process        | Task-related process activity             |
| Process Tree   | Parent and child processes                |
| Files          | Created, modified, or executed files      |
| Network        | Related network connections               |
| DNS            | Related DNS activity                      |
| Authentication | Relevant authentication events            |
| Scope          | Other affected hosts and tasks            |
| Detections     | Related security alerts                   |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the scheduled task is approved;
- its creation and modification are expected;
- the payload is known and trusted;
- the execution account is authorized;
- the trigger is operationally justified;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- task ownership or origin is unclear;
- the task is unexpectedly created or modified;
- the payload is unusual;
- the task executes from a user-writable or temporary location;
- the account or privilege level is unexpected;
- related process or network activity is abnormal;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized scheduled task persistence;
- malicious executable or script execution;
- confirmed malware persistence;
- task configuration associated with post-compromise activity;
- command-and-control communication;
- credential access;
- lateral movement;
- other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the scheduled task is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious scheduled task persistence is confirmed;
- privileged execution is unexpected;
- multiple hosts contain the same suspicious task;
- the task is associated with malware;
- credentials may have been accessed;
- lateral movement is suspected;
- command-and-control activity is observed;
- a business-critical system is affected.

## Response Guidance

For confirmed malicious scheduled task persistence:

1. Preserve task, process, file, authentication, and network evidence.
2. Identify all affected hosts and accounts.
3. Follow the organization's endpoint containment procedure.
4. Search for related task names, paths, payloads, hashes, and command lines.
5. Investigate associated persistence and post-compromise activity.
6. Follow authorized task remediation procedures.
7. Review possible credential exposure.
8. Escalate confirmed compromise to incident response.
9. Document the investigation timeline and remediation actions.

Do not immediately delete the task or referenced payload before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/obfuscated-powershell.yar`
- `detection-rules/yara/yara-powershell-payload.yar`

## Related Playbooks

- `playbooks/execution/scheduled-task-execution.md`
- `playbooks/execution/powershell.md`
- `playbooks/execution/command-shell.md`
- `playbooks/execution/wmi-execution.md`
- `playbooks/triage/persistence-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/response/persistence-removal-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved scheduled-task fixtures, task metadata, endpoint telemetry, process events, and controlled persistence scenarios.

Validation should confirm that:

- scheduled task creation can be identified;
- task configuration can be investigated;
- task lifecycle events can be correlated;
- payloads and execution accounts can be assessed;
- task execution can be correlated with process activity;
- related file and network activity can be investigated;
- persistence scope can be determined;
- legitimate scheduled task automation can be distinguished from malicious persistence;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Scheduled task creation or modification should only be performed in approved testing or administrative environments. Do not create, modify, or remove scheduled tasks on production systems outside authorized procedures.
