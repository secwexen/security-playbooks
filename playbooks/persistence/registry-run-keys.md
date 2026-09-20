---
id: "registry-run-keys"
name: "Registry Run Keys / Startup Folder"
category: "persistence"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-14T13:59:00Z"
updated_at: "2026-09-20T19:16:00Z"
description: "Registry Run Keys and related Windows startup mechanisms can be used to launch programs automatically when a user logs on."
objective: "Identify, investigate, and validate suspicious registry-based persistence and determine whether the configured startup entry is legitimate, suspicious, or malicious."
severity: "high"
mitre_attack:
  - "T1547.001"
triggers:
  - "Unexpected registry Run key modification"
  - "Unknown executable configured for startup"
  - "New startup entry created by an unexpected account"
  - "Registry persistence associated with suspicious process activity"
  - "Threat hunting identifies anomalous Run key activity"
prerequisites:
  - "Access to registry modification telemetry"
  - "Access to process creation telemetry"
  - "Access to endpoint security telemetry"
  - "Access to file and authentication telemetry where available"
tags:
  - "registry"
  - "run-keys"
  - "persistence"
  - "windows"
  - "startup"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1547/001/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Registry Persistence Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, user, registry path, modified value, and timestamp."
  expected_result: "The suspicious registry persistence event and affected asset are identified."
- id: "identify-registry-entry"
  order: 2
  name: "Identify Registry Entry"
  action: "analyze"
  description: "Determine the registry hive, key, value name, value data, and scope of the startup configuration."
  expected_result: "The registry persistence entry is documented."
- id: "review-modification-context"
  order: 3
  name: "Review Modification Context"
  action: "analyze"
  description: "Determine which process and account modified the registry entry and correlate the change with nearby events."
  expected_result: "The registry modification context is established."
- id: "review-payload"
  order: 4
  name: "Review Startup Payload"
  action: "analyze"
  description: "Review the executable, script, command line, file path, hash, and signature referenced by the registry entry."
  expected_result: "The startup payload and execution context are assessed."
- id: "review-execution"
  order: 5
  name: "Review Startup Execution"
  action: "analyze"
  description: "Correlate the registry entry with subsequent process creation and user logon activity."
  expected_result: "Startup execution and related process activity are correlated."
- id: "review-file-and-network-activity"
  order: 6
  name: "Review File and Network Activity"
  action: "analyze"
  description: "Review files created or accessed and network connections associated with the startup payload."
  expected_result: "Related file and network activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Persistence Scope"
  action: "hunt"
  description: "Search for the same registry path, value, payload, hash, command line, or persistence pattern across the environment."
  expected_result: "The prevalence and scope of the registry persistence are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the registry persistence activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "registry-run-keys"
---

# Registry Run Keys / Startup Folder

## Purpose

This playbook provides a structured workflow for investigating suspicious registry-based persistence on Windows systems.

Registry Run Keys and related startup mechanisms are legitimate Windows features that can also be abused to automatically launch programs when a user logs on.

The objective is to determine whether the startup configuration is legitimate, suspicious, or malicious and whether it is associated with additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name                               | Relevance                                                                      |
| --------- | ---------------------------------- | ------------------------------------------------------------------------------ |
| T1547.001 | Registry Run Keys / Startup Folder | Relevant when registry-based startup entries are used to establish persistence |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An unexpected registry Run key modification is detected.
- A new startup entry references an unknown executable or script.
- A registry startup entry is created by an unexpected account or process.
- A startup payload is associated with suspicious process activity.
- A known malicious file is referenced by a Run key.
- Threat hunting identifies anomalous registry persistence.

## Scope

The investigation should consider:

- affected host;
- associated user;
- registry hive;
- registry path;
- value name;
- value data;
- process that modified the key;
- modifying account;
- executable or script;
- command line;
- file path;
- file hash;
- digital signature;
- logon event;
- process execution;
- file activity;
- network activity;
- related alerts;
- additional affected hosts.

## Common Registry Locations

Common Windows startup locations include user and machine-level Run keys.

Examples include:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

Registry locations may vary by Windows architecture, user context, or environment configuration.

Do not treat the presence of a Run key as malicious by itself. Investigate the configured value and its execution context.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- registry path;
- value name;
- value data;
- detection severity;
- detection reason.

Preserve the original alert context before modifying the registry.

### Step 2 — Identify the Registry Entry

Collect:

- registry hive;
- key path;
- value name;
- value type;
- value data;
- scope;
- creation or modification time where available.

Determine whether the entry is user-specific or system-wide.

### Step 3 — Review Modification Context

Determine:

- process that modified the registry;
- parent process;
- account context;
- modification timestamp;
- related process creation;
- related file activity.

Investigate whether the registry modification occurred during a legitimate software installation, application update, administrative action, or system configuration change.

### Step 4 — Review Startup Payload

Review the program or script referenced by the registry value.

Collect:

- executable or script path;
- filename;
- command line;
- arguments;
- file hash;
- file type;
- file timestamps;
- digital signature where applicable.

Pay particular attention to payloads stored in:

- user-writable directories;
- temporary locations;
- unusual application data directories;
- hidden or unexpected paths.

### Step 5 — Review Startup Execution

Correlate the registry entry with:

- user logon;
- process creation;
- process tree;
- command-line telemetry;
- child processes.

Determine whether the configured payload actually executed and whether the execution resulted in additional suspicious activity.

### Step 6 — Review File and Network Activity

Investigate:

- files created or modified by the startup payload;
- downloaded content;
- DNS requests;
- network connections;
- external destinations.

Collect relevant hashes, timestamps, and destination information.

### Step 7 — Determine Persistence Scope

Search the environment for:

- same registry path;
- same value name;
- same value data;
- same payload;
- same file hash;
- same command line;
- same account.

Determine:

- number of affected hosts;
- number of affected users;
- first observed modification;
- latest observed execution;
- whether the persistence remains configured.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence       | Description                                          |
| -------------- | ---------------------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp            |
| Host           | Hostname, IP address, operating system               |
| User           | Associated user or account                           |
| Registry       | Hive, path, value name, value data                   |
| Modification   | Registry modification context and timestamp          |
| Process        | Process responsible for the registry change          |
| Parent Process | Process that initiated the modifying process         |
| Payload        | Executable or script referenced by the startup entry |
| Hash           | SHA-256 or available file hash                       |
| Signature      | Digital signature information where available        |
| Logon          | Relevant user logon events                           |
| Process Tree   | Startup process execution chain                      |
| Files          | Created, modified, downloaded, or executed files     |
| Network        | Related network connections                          |
| DNS            | Related DNS activity                                 |
| Scope          | Other affected hosts and users                       |
| Detections     | Related security alerts                              |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the registry entry belongs to approved software;
- the modification was expected;
- the modifying process is trusted;
- the payload is known and trusted;
- the startup behavior is consistent with normal application operation;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the startup entry is unexpected;
- the payload source is unclear;
- the modifying process is unusual;
- the payload resides in an abnormal location;
- the command line is suspicious;
- related process, file, or network activity is abnormal;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized registry persistence;
- confirmed malicious payload execution;
- startup execution associated with malware;
- command-and-control communication;
- credential access;
- lateral movement;
- other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the registry persistence is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- malicious registry persistence is confirmed;
- the payload is associated with known malware;
- multiple hosts contain the same suspicious persistence;
- privileged or service accounts are involved unexpectedly;
- credential compromise is suspected;
- lateral movement is identified;
- command-and-control activity is observed.

## Response Guidance

For confirmed malicious registry persistence:

1. Preserve registry, process, file, logon, and network evidence.
2. Identify all affected hosts and accounts.
3. Determine whether the startup payload is still present.
4. Follow the organization's endpoint containment procedure.
5. Search for related registry entries, payload hashes, command lines, and processes.
6. Investigate other persistence mechanisms that may have been established.
7. Follow authorized registry and payload remediation procedures.
8. Review possible credential exposure.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Do not immediately delete the registry entry or referenced payload before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/obfuscated-powershell.yar`
- `detection-rules/yara/yara-powershell-payload.yar`

## Related Playbooks

- `playbooks/persistence/scheduled-task-persistence.md`
- `playbooks/persistence/service-persistence.md`
- `playbooks/persistence/startup-folder.md`
- `playbooks/triage/persistence-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/execution/powershell.md`
- `playbooks/execution/command-shell.md`
- `playbooks/response/persistence-removal-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved registry telemetry, process creation events, logon events, endpoint telemetry, and controlled persistence scenarios.

Validation should confirm that:

- registry startup entries can be identified;
- registry modification events can be investigated;
- modifying processes and accounts can be correlated;
- startup payloads can be analyzed;
- logon and process execution can be correlated;
- related file and network activity can be investigated;
- persistence scope can be determined;
- legitimate startup entries can be distinguished from malicious persistence;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Registry modifications should only be performed in approved testing or administrative environments. Do not modify or remove registry persistence entries on production systems outside authorized procedures.
