---
id: "wmi-execution"
name: "Windows Management Instrumentation"
category: "execution"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-13T12:10:00Z"
updated_at: "2026-09-13T12:10:00Z"
description: "Windows Management Instrumentation (WMI) can be used to manage Windows systems and execute commands or programs locally or remotely."
objective: "Identify, investigate, and validate suspicious WMI activity and determine whether the activity is legitimate, suspicious, or malicious."
severity: "high"
mitre_attack:
  - "T1047"
triggers:
  - "Suspicious WMI execution alert"
  - "Unexpected WMI process creation"
  - "WMI launched by an unusual parent process"
  - "Remote WMI activity from an unexpected host"
  - "WMI creating or executing an unexpected process"
  - "Threat hunting identifies anomalous WMI activity"
prerequisites:
  - "Access to WMI and process creation telemetry"
  - "Access to command-line telemetry"
  - "Access to endpoint security telemetry"
  - "Access to authentication and network telemetry where available"
tags:
  - "wmi"
  - "execution"
  - "windows"
  - "remote-execution"
  - "endpoint"
  - "lateral-movement"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1047/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify WMI Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, account, WMI activity, timestamp, and alert context."
  expected_result: "The suspicious WMI event and affected asset are identified."
- id: "identify-wmi-activity"
  order: 2
  name: "Identify WMI Activity"
  action: "analyze"
  description: "Determine whether WMI was used for local management, process creation, query execution, or remote activity."
  expected_result: "The WMI operation and execution context are identified."
- id: "review-command-line"
  order: 3
  name: "Review Command Line"
  action: "analyze"
  description: "Review available command-line data, referenced executables, scripts, parameters, and WMI-related tooling."
  expected_result: "The command line and relevant execution parameters are documented."
- id: "review-source-host"
  order: 4
  name: "Review Source and Target Hosts"
  action: "analyze"
  description: "Identify the initiating host, target host, user or service account, and authentication context."
  expected_result: "The WMI source, target, and account context are documented."
- id: "review-process-activity"
  order: 5
  name: "Review Process Activity"
  action: "analyze"
  description: "Review processes created through WMI and correlate their parent-child relationships, paths, command lines, and timestamps."
  expected_result: "WMI-related process activity is documented and correlated."
- id: "review-network-activity"
  order: 6
  name: "Review Network Activity"
  action: "analyze"
  description: "Review network connections and authentication activity associated with the WMI operation."
  expected_result: "Related network and authentication activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine WMI Activity Scope"
  action: "hunt"
  description: "Search for the same source host, target host, account, command line, process, or WMI execution pattern across the environment."
  expected_result: "The prevalence and scope of the WMI activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the WMI activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "wmi-execution"
---

# Windows Management Instrumentation

## Purpose

This playbook provides a structured workflow for investigating suspicious Windows Management Instrumentation (WMI) activity.

WMI is a legitimate Windows management technology that can also be abused to execute commands and programs locally or remotely.

The objective is to determine whether WMI activity is legitimate, suspicious, or malicious and whether it is associated with additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name                               | Relevance                                                 |
| --------- | ---------------------------------- | --------------------------------------------------------- |
| T1047     | Windows Management Instrumentation | Relevant when WMI is used to execute commands or programs |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious WMI execution alert is generated.
- Unexpected process creation is associated with WMI.
- WMI is initiated by an unusual process.
- Remote WMI activity originates from an unexpected system.
- WMI launches an unknown executable or script.
- WMI activity is associated with suspicious authentication or network activity.
- Threat hunting identifies anomalous WMI behavior.

## Scope

The investigation should consider:

- source host;
- target host;
- affected user;
- service account;
- authentication context;
- WMI provider or operation;
- command line;
- executable path;
- script path;
- parent process;
- child processes;
- process creation time;
- network connections;
- DNS activity;
- authentication events;
- file activity;
- related alerts;
- additional affected hosts.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- source host;
- target host;
- associated user or service account;
- WMI operation;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify WMI Activity

Determine how WMI was used.

Identify whether the activity involved:

- local WMI operations;
- remote WMI operations;
- process creation;
- command execution;
- script execution;
- administrative management.

Determine whether the observed activity is associated with an approved administrative or management workflow.

### Step 3 — Review Command Line

Review available command-line telemetry.

Identify:

- WMI-related tooling;
- executable path;
- script path;
- command arguments;
- referenced files;
- target host;
- execution account.

Pay particular attention to unexpected executables or scripts launched through WMI.

### Step 4 — Review Source and Target Hosts

Determine:

- initiating host;
- destination host;
- source IP;
- destination IP;
- initiating account;
- authentication mechanism;
- expected administrative relationship.

Investigate activity between hosts that do not normally communicate through remote management channels.

### Step 5 — Review Process Activity

Review:

- process creation;
- parent-child relationships;
- process paths;
- command lines;
- process execution timestamps;
- account context.

Determine whether WMI activity resulted in unexpected process execution.

Correlate the WMI event with the resulting process activity rather than evaluating WMI use in isolation.

### Step 6 — Review Network and Authentication Activity

Review:

- network connections;
- authentication events;
- source and destination systems;
- connection timestamps;
- relevant security events.

Investigate unexpected remote connections and authentication associated with the WMI operation.

### Step 7 — Determine Activity Scope

Search the environment for:

- same source host;
- same target host;
- same account;
- same command line;
- same executable;
- same process pattern;
- same WMI execution behavior.

Determine:

- number of affected hosts;
- number of affected accounts;
- first observed activity;
- latest observed activity;
- whether remote execution is still occurring.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence        | Description                                          |
| --------------- | ---------------------------------------------------- |
| Alert           | Detection source, ID, severity, timestamp            |
| Source Host     | Host initiating the WMI activity                     |
| Target Host     | Host receiving the WMI operation                     |
| User            | Associated user or service account                   |
| WMI Activity    | WMI operation and execution context                  |
| Command Line    | Relevant command-line information                    |
| Parent Process  | Process associated with the WMI operation            |
| Child Processes | Processes created or launched through WMI            |
| Authentication  | Related authentication events                        |
| Network         | Related network connections                          |
| Files           | Created, modified, or executed files                 |
| Timeline        | WMI, process, authentication, and network timestamps |
| Scope           | Other affected hosts and accounts                    |
| Detections      | Related security alerts                              |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- WMI usage is authorized;
- the source and target systems have an expected administrative relationship;
- the account is approved;
- the executed command or program is known;
- process activity is consistent with the expected operation;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the source or target host is unexpected;
- the account context is unusual;
- WMI launches an unexpected process;
- command-line activity is abnormal;
- remote WMI usage is inconsistent with normal administration;
- suspicious authentication or network activity is observed;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized WMI execution;
- malicious process or script execution;
- confirmed payload execution;
- command-and-control activity;
- credential access;
- lateral movement;
- persistence;
- other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the WMI activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- unauthorized WMI execution is confirmed;
- remote WMI activity affects multiple systems;
- privileged accounts are involved unexpectedly;
- lateral movement is suspected;
- credentials may have been accessed;
- command-and-control activity is observed;
- a business-critical system is affected.

## Response Guidance

For confirmed malicious WMI activity:

1. Preserve relevant WMI, process, authentication, and network evidence.
2. Identify all source and target hosts.
3. Identify all affected accounts.
4. Follow the organization's endpoint containment procedure.
5. Search for related WMI commands, processes, accounts, and network activity.
6. Investigate lateral movement and post-compromise activity.
7. Follow authorized quarantine or remediation procedures.
8. Review possible credential exposure.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Do not terminate, delete, or modify relevant processes, files, WMI configuration, or logs before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`

## Related Playbooks

- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/execution/scripting.md`
- `playbooks/execution/powershell.md`
- `playbooks/execution/command-shell.md`
- `playbooks/execution/python-execution.md`
- `playbooks/execution/scheduled-task-execution.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved WMI telemetry, process creation events, authentication events, and controlled execution scenarios.

Validation should confirm that:

- WMI activity can be identified;
- source and target hosts can be determined;
- relevant accounts can be identified;
- WMI-related process activity can be correlated;
- authentication and network activity can be investigated;
- legitimate administrative WMI activity can be distinguished from suspicious execution;
- environmental scope can be determined;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

WMI activity should be investigated using approved telemetry and controlled laboratory environments. Do not perform unauthorized remote execution or modify production systems outside approved response procedures.
