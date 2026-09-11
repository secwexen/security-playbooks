---
id: "scheduled-task-execution"
name: "Scheduled Task/Job Execution"
category: "execution"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-11T11:40:00Z"
updated_at: "2026-09-11T11:40:00Z"
description: "Scheduled Task/Job Execution enables commands or programs to run automatically at defined times or system events."
objective: "Identify, investigate, and validate scheduled task or job execution and determine whether the activity is legitimate, suspicious, or malicious."
severity: "high"
mitre_attack:
  - "T1053"
triggers:
  - "Suspicious scheduled task or job execution"
  - "Unexpected scheduled task creation"
  - "Unexpected task modification"
  - "Unknown program executed by a scheduled task"
  - "Scheduled task associated with suspicious process activity"
  - "Threat hunting identifies anomalous scheduled execution"
prerequisites:
  - "Access to task or job scheduling telemetry"
  - "Access to process creation logs"
  - "Access to command-line telemetry"
  - "Access to endpoint and file telemetry"
tags:
  - "scheduled-task"
  - "scheduled-job"
  - "execution"
  - "persistence"
  - "windows"
  - "endpoint"
references:
  - "https://attack.mitre.org/techniques/T1053/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Scheduled Execution Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, task or job, account, and execution timestamp."
  expected_result: "The scheduled execution event and affected asset are identified."
- id: "identify-task"
  order: 2
  name: "Identify Task or Job"
  action: "analyze"
  description: "Identify the task or job name, scheduler, trigger, action, account, and execution configuration."
  expected_result: "The scheduled task or job configuration is documented."
- id: "review-action"
  order: 3
  name: "Review Scheduled Action"
  action: "analyze"
  description: "Review the executable, script, command line, arguments, and working directory associated with the scheduled action."
  expected_result: "The scheduled action and its execution context are assessed."
- id: "review-task-context"
  order: 4
  name: "Review Task Context"
  action: "analyze"
  description: "Review task creation, modification, trigger conditions, run-as account, and privilege context."
  expected_result: "The task's lifecycle and execution context are documented."
- id: "review-process-activity"
  order: 5
  name: "Review Process Activity"
  action: "analyze"
  description: "Review process creation, parent-child relationships, command lines, and files created by the scheduled task."
  expected_result: "Associated process activity is identified and correlated."
- id: "review-network-activity"
  order: 6
  name: "Review Network Activity"
  action: "analyze"
  description: "Review network connections, DNS activity, and external destinations associated with the scheduled task or spawned processes."
  expected_result: "Related network activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Scheduled Execution Scope"
  action: "hunt"
  description: "Search for the same task name, command line, executable, script, or scheduling pattern across the environment."
  expected_result: "The prevalence and scope of the scheduled execution are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the scheduled execution activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "scheduled-task-execution"
---

# Scheduled Task/Job Execution

## Purpose

This playbook provides a structured workflow for investigating scheduled task or job execution.

The objective is to determine whether scheduled execution is legitimate, suspicious, or malicious and whether it is associated with additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name               | Relevance                                                                      |
| --------- | ------------------ | ------------------------------------------------------------------------------ |
| T1053     | Scheduled Task/Job | Relevant when scheduled tasks or jobs are used to execute commands or programs |

Additional T1053 sub-techniques should only be mapped when supported by the observed scheduler and platform.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious scheduled task or job execution alert is generated.
- An unexpected scheduled task is created.
- An existing task is unexpectedly modified.
- An unknown executable or script is launched by a scheduler.
- A scheduled task is associated with suspicious process activity.
- Scheduled execution occurs under an unexpected account.
- Threat hunting identifies anomalous scheduled execution.

## Scope

The investigation should consider:

- affected host;
- task or job name;
- scheduler;
- task path;
- trigger;
- action;
- executable;
- script;
- command line;
- arguments;
- working directory;
- run-as account;
- privilege context;
- creation time;
- modification time;
- execution time;
- parent process;
- child processes;
- created files;
- network activity;
- related alerts;
- additional affected hosts.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- affected account;
- task or job name;
- detection severity.

Preserve the original alert context before making configuration or remediation changes.

### Step 2 — Identify the Task or Job

Collect:

- task or job name;
- scheduler;
- task path;
- trigger;
- action;
- run-as account;
- execution privileges;
- task creation time;
- task modification time.

Determine whether the task or job is expected on the affected system.

### Step 3 — Review Scheduled Action

Review:

- executable path;
- script path;
- command line;
- arguments;
- working directory;
- environment where available.

Pay particular attention to actions that reference:

- temporary directories;
- user-writable locations;
- unusual scripts;
- unknown executables;
- encoded or obfuscated commands.

### Step 4 — Review Task Context

Determine:

- who created the task;
- when it was created;
- who modified it;
- whether the trigger is expected;
- whether elevated privileges are used;
- whether the run-as account is appropriate.

Compare task configuration with normal administrative or application behavior.

### Step 5 — Review Process Activity

Review:

- task scheduler process activity;
- parent-child relationships;
- command lines;
- child processes;
- process execution timestamps;
- created or modified files.

Determine whether the scheduled task launched unexpected processes.

### Step 6 — Review Network Activity

Review network activity associated with the scheduled task and spawned processes.

Collect:

- destination IP;
- destination domain;
- destination port;
- protocol;
- DNS requests;
- connection timestamps.

Investigate unexpected communication with external or suspicious infrastructure.

### Step 7 — Determine Scheduled Execution Scope

Search across the environment for:

- same task name;
- same task path;
- same executable;
- same script;
- same command line;
- same trigger;
- same run-as account.

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

| Evidence     | Description                                 |
| ------------ | ------------------------------------------- |
| Alert        | Detection source, ID, severity, timestamp   |
| Host         | Hostname, IP address, operating system      |
| Task/Job     | Name, path, scheduler                       |
| Trigger      | Schedule or event condition                 |
| Action       | Executable, script, arguments               |
| Account      | Run-as account and privilege context        |
| Timeline     | Creation, modification, and execution times |
| Process      | Related process activity                    |
| Process Tree | Parent and child processes                  |
| Files        | Created or modified files                   |
| Network      | Related network connections                 |
| DNS          | Related DNS activity                        |
| Scope        | Other affected hosts and tasks              |
| Detections   | Related security alerts                     |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the task or job is approved;
- the executable or script is known;
- the account is authorized;
- the schedule is expected;
- the execution behavior is normal;
- no additional suspicious indicators are identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the task is unexpected;
- the creator or modifier is unknown;
- the action references an unusual file;
- execution uses an unexpected privileged account;
- child processes or network activity are abnormal;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized scheduled execution;
- malicious executable or script execution;
- scheduled execution associated with confirmed malware;
- persistence or other confirmed malicious behavior;
- scheduled execution used as part of a broader compromise.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the scheduled execution is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious scheduled execution is confirmed;
- a privileged account is involved unexpectedly;
- persistence is suspected;
- multiple hosts contain the same suspicious task;
- credential access or lateral movement is identified;
- command-and-control activity is observed.

## Response Guidance

For confirmed malicious scheduled execution:

1. Preserve task, process, file, and network evidence.
2. Identify all affected hosts and accounts.
3. Follow the organization's endpoint containment procedure.
4. Search for the same task, executable, script, and command line across the environment.
5. Investigate associated persistence and post-compromise activity.
6. Follow authorized task or job remediation procedures.
7. Review possible credential exposure.
8. Escalate confirmed compromise to incident response.
9. Document the investigation timeline and remediation actions.

Do not delete or modify the scheduled task, referenced files, or relevant logs before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/yara/obfuscated-powershell.yar`

## Related Playbooks

- `playbooks/triage/persistence-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/execution/scripting.md`
- `playbooks/execution/powershell.md`
- `playbooks/execution/command-shell.md`
- `playbooks/persistence/scheduled-task-persistence.md`
- `playbooks/privilege-escalation/scheduled-task-abuse.md`
- `playbooks/response/persistence-removal-response.md`
- `playbooks/response/malware-response.md`

## Validation

The playbook should be validated against approved scheduled-task and job fixtures, endpoint telemetry, process events, and controlled execution scenarios.

Validation should confirm that:

- scheduled tasks and jobs can be identified;
- task configuration can be investigated;
- scheduled actions can be correlated with process activity;
- related files and network connections can be investigated;
- suspicious scheduled execution can be distinguished from legitimate administration;
- environmental scope can be determined;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Scheduled task and job modifications should follow approved authorization, evidence-preservation, and change-management procedures. Do not execute or modify suspicious scheduled tasks on production systems outside authorized response procedures.
