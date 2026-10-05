---
id: "inhibit-system-recovery"
name: "Inhibit System Recovery"
category: "impact"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-29T16:04:00Z"
updated_at: "2026-10-05T16:45:00Z"
description: "Investigate activity that disables, deletes, or otherwise interferes with system recovery mechanisms, backups, snapshots, or recovery services."
objective: "Determine whether recovery mechanisms were intentionally inhibited, assess the affected recovery capabilities and environmental scope, and support containment and recovery actions."
severity: "critical"
mitre_attack:
  - "T1490"
triggers:
  - "Detection of shadow copy deletion or modification"
  - "Detection of backup catalog deletion or modification"
  - "Recovery configuration changes"
  - "Unexpected disabling of recovery services or features"
  - "Suspicious execution of recovery-related administrative utilities"
  - "Security monitoring identifies activity intended to prevent system restoration"
  - "Threat hunting identifies anomalous recovery-related activity"
prerequisites:
  - "Access to endpoint process telemetry"
  - "Access to backup and recovery telemetry"
  - "Access to system configuration and service telemetry"
  - "Access to file, process, and authentication telemetry"
  - "Access to backup, snapshot, or recovery administration records where available"
tags:
  - "inhibit-system-recovery"
  - "impact"
  - "backup"
  - "recovery"
  - "shadow-copy"
  - "windows"
  - "ransomware"
references:
  - "https://attack.mitre.org/techniques/T1490/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Recovery Inhibition Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, account, process, timestamp, recovery-related action, and original alert context."
  expected_result: "The suspicious recovery-related activity and affected asset are identified."
- id: "identify-recovery-mechanism"
  order: 2
  name: "Identify Recovery Mechanism"
  action: "analyze"
  description: "Determine which recovery mechanism was affected, including volume shadow copies, backup catalogs, recovery configuration, snapshots, or recovery services."
  expected_result: "The affected recovery mechanism and its operational purpose are documented."
- id: "review-process-execution"
  order: 3
  name: "Review Process Execution"
  action: "analyze"
  description: "Review the responsible process, command line, parent process, child processes, execution account, integrity level, and execution path."
  expected_result: "The process execution context and associated recovery-related activity are characterized."
- id: "review-recovery-changes"
  order: 4
  name: "Review Recovery Changes"
  action: "analyze"
  description: "Determine what recovery data, configuration, services, snapshots, or backup components were deleted, disabled, modified, or otherwise made unavailable."
  expected_result: "The specific recovery changes and resulting availability impact are documented."
- id: "review-related-activity"
  order: 5
  name: "Review Related Activity"
  action: "analyze"
  description: "Correlate the recovery-related activity with file operations, authentication events, process execution, security-control changes, encryption activity, data destruction, and other impact-related behavior."
  expected_result: "Related activity is identified and correlated with the recovery inhibition event."
- id: "determine-recovery-impact"
  order: 6
  name: "Determine Recovery Impact"
  action: "analyze"
  description: "Assess whether recovery capabilities remain available and determine which backup, snapshot, restore, or recovery options are affected."
  expected_result: "The operational impact on recovery capabilities is determined."
- id: "determine-environmental-scope"
  order: 7
  name: "Determine Environmental Scope"
  action: "hunt"
  description: "Search the environment for the same process, command line, recovery-related modification, backup deletion pattern, account, file hash, or affected recovery mechanism."
  expected_result: "The prevalence and scope of the recovery inhibition activity are determined."
- id: "determine-investigation-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the activity and document the evidence supporting the final investigation outcome."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "inhibit-system-recovery"
---

# Inhibit System Recovery

## Purpose

This playbook provides a structured workflow for investigating activity that disables, deletes, or otherwise interferes with system recovery mechanisms.

Recovery mechanisms may include volume shadow copies, backup catalogs, snapshots, recovery configuration, recovery services, or other capabilities required to restore affected systems and data.

The objective is to determine whether recovery capabilities were intentionally inhibited, identify the affected recovery mechanisms, assess operational impact and environmental scope, and support authorized containment and recovery procedures.

## MITRE ATT&CK

| Technique | Name                    | Relevance                                                                                              |
| --------- | ----------------------- | ------------------------------------------------------------------------------------------------------ |
| T1490     | Inhibit System Recovery | Primary impact technique when recovery mechanisms are disabled, deleted, or otherwise made unavailable |

MITRE ATT&CK identifies T1490 under the **Impact** tactic and describes activity intended to prevent or reduce the ability to recover affected systems or data.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Shadow copies are unexpectedly deleted or modified.
- Backup catalogs or recovery metadata are unexpectedly removed or changed.
- Recovery configuration is disabled or modified.
- Recovery services or features are unexpectedly disabled.
- Recovery-related administrative utilities are executed in an unusual context.
- Backup, snapshot, or recovery resources are deleted unexpectedly.
- Recovery inhibition activity is observed together with ransomware, data destruction, or other impact-related behavior.
- Threat hunting identifies anomalous recovery-related activity.

## Scope

The investigation should consider:

- affected host;
- affected account;
- responsible process;
- parent and child processes;
- command line;
- executable path;
- process integrity level;
- execution timestamp;
- recovery mechanism;
- shadow copies;
- backup catalogs;
- backup repositories;
- snapshots;
- recovery configuration;
- recovery services;
- modified files and system artifacts;
- authentication activity;
- security-control changes;
- encryption activity;
- data destruction;
- ransomware-related activity;
- additional affected hosts;
- affected backup or recovery infrastructure.

## Investigation Procedure

### Step 1 — Identify Recovery Inhibition Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated account;
- responsible process;
- recovery-related action;
- detection severity;
- original alert context.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify Recovery Mechanism

Determine which recovery mechanism was affected.

Review, where applicable:

- volume shadow copies;
- backup catalogs;
- backup jobs;
- snapshots;
- recovery configuration;
- recovery services;
- system restore functionality;
- other organizational recovery mechanisms.

Document the expected role of the affected mechanism and whether the change was authorized.

### Step 3 — Review Process Execution

Review:

- process name;
- process ID;
- parent process;
- child processes;
- command line;
- executable path;
- process creation time;
- execution account;
- integrity level;
- digital signature;
- file hash where available.

Determine whether the responsible process and execution context are consistent with expected administrative activity.

Pay particular attention to recovery-related activity originating from:

- unexpected user accounts;
- temporary or user-writable locations;
- scripting interpreters;
- recently created executables;
- unusual parent processes;
- processes associated with broader malicious activity.

Do not execute unknown binaries or intentionally alter recovery mechanisms during investigation.

### Step 4 — Review Recovery Changes

Determine:

- what recovery data was deleted;
- what recovery configuration was modified;
- which recovery services were disabled;
- which snapshots or backup artifacts were removed;
- whether recovery functionality remains available;
- whether the change affected local or centralized recovery infrastructure.

Establish the earliest known change and identify the responsible account and process where telemetry permits.

### Step 5 — Review Related Activity

Correlate the event with:

- process creation;
- authentication activity;
- privilege changes;
- security-control modification;
- file creation or deletion;
- backup administration activity;
- snapshot activity;
- encryption activity;
- data destruction;
- ransomware-related indicators;
- lateral movement;
- additional impact-related activity.

Recovery inhibition combined with encryption, destructive behavior, or unauthorized administrative activity should receive increased investigation priority.

### Step 6 — Determine Recovery Impact

Assess:

- whether shadow copies remain available;
- whether backups remain accessible;
- whether backup catalogs remain intact;
- whether restore points or snapshots remain usable;
- whether recovery services remain operational;
- whether recovery capabilities are limited to a single host or multiple systems;
- whether off-host or offline recovery copies remain available.

Document which recovery options remain functional and which have been affected.

### Step 7 — Determine Environmental Scope

Search for:

- the same process;
- the same command line;
- the same executable hash;
- the same account;
- the same recovery-related modification;
- the same backup deletion pattern;
- the same recovery configuration change;
- activity affecting other hosts;
- activity affecting backup or recovery infrastructure.

Determine:

- number of affected hosts;
- number of affected accounts;
- affected recovery systems;
- first observed occurrence;
- latest observed occurrence;
- whether the recovery inhibition activity remains active.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence           | Description                                                                |
| ------------------ | -------------------------------------------------------------------------- |
| Alert              | Detection source, ID, severity, timestamp                                  |
| Host               | Hostname, IP address, operating system                                     |
| Account            | User or service account associated with the activity                       |
| Process            | Process metadata and execution context                                     |
| Parent Process     | Parent process and process relationship                                    |
| Command Line       | Complete observed command line                                             |
| Executable         | Path, hash, file type, signature                                           |
| Recovery Mechanism | Shadow copy, backup, snapshot, recovery service, or configuration affected |
| Recovery Changes   | Deleted, modified, or disabled recovery components                         |
| Backup Status      | Availability and integrity of remaining backups                            |
| Authentication     | Related authentication events                                              |
| Files              | Relevant created, modified, or deleted artifacts                           |
| Network            | Related network connections                                                |
| Related Activity   | Encryption, destruction, ransomware, or other impact behavior              |
| Scope              | Other affected hosts and recovery systems                                  |
| Timeline           | Process, authentication, file, backup, and recovery events                 |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the recovery-related action is authorized;
- the account is authorized to administer recovery infrastructure;
- the process and executable are known and trusted;
- the change is consistent with documented maintenance or backup operations;
- the affected recovery mechanism was intentionally modified as part of approved activity;
- no additional suspicious or malicious activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the recovery-related change is unexpected;
- the responsible account is unusual;
- the execution context is inconsistent with normal administration;
- the executable or process is untrusted or unusual;
- recovery resources were modified without a confirmed operational reason;
- additional suspicious process, authentication, file, or network activity is present;
- environmental scope remains uncertain;
- additional telemetry is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized deletion or disabling of recovery mechanisms;
- malicious process execution associated with recovery inhibition;
- recovery inhibition performed as part of ransomware activity;
- recovery inhibition associated with data destruction;
- recovery inhibition associated with unauthorized privileged activity;
- coordinated recovery impairment across multiple affected systems;
- other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the recovery-related activity was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- recovery mechanisms that could not be assessed;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- unauthorized recovery inhibition is confirmed;
- recovery capabilities are materially degraded;
- multiple hosts are affected;
- backup or recovery infrastructure is affected;
- privileged accounts are involved unexpectedly;
- ransomware or encryption activity is identified;
- data destruction is observed;
- lateral movement is identified;
- additional impact-related activity is detected.

## Response Guidance

For confirmed malicious recovery inhibition:

1. Preserve process, account, file, configuration, backup, and recovery evidence.
2. Identify all affected hosts, accounts, backup systems, and recovery resources.
3. Follow the organization's approved endpoint and infrastructure containment procedures.
4. Prevent further unauthorized changes to recovery infrastructure.
5. Protect unaffected backup and recovery copies from additional modification or deletion.
6. Investigate related ransomware, encryption, data destruction, persistence, and lateral movement activity.
7. Determine whether clean and recoverable backup or snapshot copies remain available.
8. Follow authorized recovery procedures to restore affected recovery capabilities.
9. Review privileged accounts and administrative access associated with the activity.
10. Escalate confirmed compromise to incident response.
11. Document the investigation timeline, recovery impact, containment actions, and restoration status.

Do not delete, recreate, or modify recovery artifacts before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

## Related Playbooks

- `playbooks/impact/data-destruction.md`
- `playbooks/impact/ransomware.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/response/malware-response.md`

## Validation

The playbook should be validated against approved endpoint telemetry, backup and recovery events, shadow-copy activity, recovery configuration changes, process creation data, authentication events, and controlled laboratory scenarios.

Validation should confirm that:

- recovery-related activity can be identified;
- affected recovery mechanisms can be determined;
- process and account context can be investigated;
- recovery changes can be correlated with related activity;
- remaining recovery capabilities can be assessed;
- environmental scope can be determined;
- legitimate administrative activity can be distinguished from unauthorized recovery inhibition;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Recovery systems, backups, snapshots, and system configuration should be investigated through approved telemetry and controlled procedures. Do not intentionally delete backups, disable recovery mechanisms, or interfere with production recovery infrastructure outside authorized security response and change-management procedures.
