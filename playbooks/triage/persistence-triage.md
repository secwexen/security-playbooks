---
id: "persistence-triage"
name: "Persistence Triage"
category: "triage"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-01T14:33:00Z"
updated_at: "2026-09-04T23:47:00Z"
description: "Investigate suspected persistence mechanisms and determine whether unauthorized persistence is present on an endpoint."
objective: "Identify, validate, scope, and assess suspected persistence mechanisms and determine whether escalation or containment is required."
severity: "high"
mitre_attack:
  - "T1053"
  - "T1547"
triggers:
  - "Suspicious persistence alert"
  - "Unexpected scheduled task"
  - "Unexpected service or startup entry"
  - "Unexpected registry-based persistence"
  - "Threat hunting identifies a suspicious persistence mechanism"
prerequisites:
  - "Access to endpoint process telemetry"
  - "Access to persistence-related system telemetry"
  - "Access to authentication telemetry"
  - "Access to file and registry telemetry"
tags:
  - "persistence"
  - "triage"
  - "endpoint"
  - "investigation"
  - "windows"
references:
  - "https://attack.mitre.org/techniques/T1053/"
  - "https://attack.mitre.org/techniques/T1547/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Persistence Alert"
  action: "investigate"
  description: "Identify the alert source, affected host, timestamp, and suspected persistence mechanism."
  expected_result: "The persistence alert and affected asset are clearly identified."
- id: "identify-mechanism"
  order: 2
  name: "Identify Persistence Mechanism"
  action: "analyze"
  description: "Determine whether the persistence mechanism is a scheduled task, service, registry entry, startup item, or another mechanism."
  expected_result: "The persistence mechanism and its location are identified."
- id: "review-execution-context"
  order: 3
  name: "Review Execution Context"
  action: "analyze"
  description: "Review the executable, script, command line, account context, parent process, and execution privileges associated with the mechanism."
  expected_result: "The execution context is documented and assessed."
- id: "review-file-context"
  order: 4
  name: "Review File Context"
  action: "analyze"
  description: "Review referenced files, paths, hashes, signatures, timestamps, and file provenance."
  expected_result: "The referenced artifacts are identified and assessed."
- id: "review-related-events"
  order: 5
  name: "Review Related Events"
  action: "hunt"
  description: "Search for process creation, authentication, network activity, file changes, and other persistence-related events."
  expected_result: "Related activity is identified or ruled out."
- id: "determine-scope"
  order: 6
  name: "Determine Scope"
  action: "hunt"
  description: "Search the environment for the same persistence mechanism, artifact, hash, path, or command line."
  expected_result: "The number of affected hosts and accounts is determined."
- id: "assess-persistence"
  order: 7
  name: "Assess Persistence"
  action: "analyze"
  description: "Determine whether the mechanism is legitimate, suspicious, or malicious and whether it provides continued unauthorized execution."
  expected_result: "The persistence risk and confidence are documented."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the finding and document the supporting evidence and required next action."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "persistence-triage"
---

# Persistence Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspected persistence mechanisms on endpoint systems.

The objective is to determine whether a persistence mechanism is:

- legitimate and expected;
- suspicious and requiring additional investigation; or
- malicious and requiring incident response.

## MITRE ATT&CK

| Technique | Name                              | Relevance                                                                    |
| --------- | --------------------------------- | ---------------------------------------------------------------------------- |
| T1053     | Scheduled Task/Job                | Relevant when persistence is established through scheduled execution         |
| T1547     | Boot or Logon Autostart Execution | Relevant when persistence is established through startup or logon mechanisms |

Additional ATT&CK techniques should only be mapped when supported by the observed persistence behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint detection identifies a suspicious persistence mechanism.
- A new or unexpected scheduled task is created.
- An unexpected service is created or modified.
- An unusual registry-based startup entry is observed.
- An unknown executable is configured for automatic execution.
- A startup or logon mechanism references an unusual file.
- Threat hunting identifies an anomalous persistence artifact.
- Multiple systems contain the same suspicious persistence mechanism.

## Scope

The investigation should consider:

- affected host;
- associated user or service account;
- persistence mechanism;
- mechanism creation time;
- executable or script;
- command line;
- file path;
- file hash;
- digital signature;
- parent process;
- execution privileges;
- registry or task metadata;
- service configuration;
- startup configuration;
- network activity;
- authentication activity;
- related detections;
- additional affected hosts.

## Triage Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- affected user;
- detection severity;
- suspected persistence mechanism.

Record the original alert before making remediation changes.

### Step 2 — Identify the Persistence Mechanism

Determine the mechanism responsible for automatic execution.

Common categories include:

- scheduled tasks;
- Windows services;
- registry run keys;
- startup folders;
- logon-related execution;
- other approved persistence mechanisms.

Collect the mechanism name, location, configuration, creation time, and associated executable or script.

### Step 3 — Review Execution Context

Review:

- executable or script;
- command line;
- parent process where available;
- user or service account;
- execution privileges;
- integrity level;
- execution time;
- configured trigger.

Determine whether the configured execution context is expected for the affected host.

### Step 4 — Review File Context

For referenced files, collect:

- full path;
- filename;
- file size;
- SHA-256 hash where available;
- creation time;
- modification time;
- digital signature;
- signer;
- file provenance.

Pay particular attention to artifacts located in:

- temporary directories;
- user-writable directories;
- application data directories;
- download locations;
- unusual system locations.

### Step 5 — Review Configuration Context

For scheduled tasks, review:

- task name;
- trigger;
- action;
- run-as account;
- task creation time;
- task modification time;
- task history where available.

For services, review:

- service name;
- display name;
- binary path;
- service account;
- startup type;
- creation or modification time.

For registry or startup mechanisms, review:

- registry path;
- value name;
- value data;
- associated executable;
- modification time;
- associated user or installation activity.

### Step 6 — Review Related Events

Correlate the persistence event with:

- process creation;
- file creation;
- file modification;
- authentication;
- privilege changes;
- network connections;
- credential access;
- lateral movement;
- defense-evasion activity;
- other security alerts.

Determine whether the persistence mechanism appeared before or after other suspicious activity.

### Step 7 — Determine Environmental Scope

Search across the environment for:

- the same persistence name;
- the same executable path;
- the same file hash;
- the same command line;
- the same registry path;
- the same service configuration;
- the same scheduled task configuration.

Determine:

- number of affected hosts;
- number of affected accounts;
- first observed time;
- most recent observed time;
- whether the mechanism remains active.

### Step 8 — Assess Persistence

Determine whether the mechanism is:

- approved and documented;
- legitimate but unexpected;
- suspicious;
- confirmed malicious.

Consider:

- file reputation;
- signer;
- configuration;
- execution context;
- account context;
- relationship to other suspicious activity.

A persistence mechanism should not be classified as malicious solely because it uses a scheduled task, service, registry entry, or startup mechanism.

### Step 9 — Determine Investigation Outcome

Classify the finding as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the outcome.

## Evidence to Collect

| Evidence       | Description                                       |
| -------------- | ------------------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp         |
| Host           | Hostname, IP address, operating system            |
| User           | Associated user or service account                |
| Mechanism      | Persistence method and identifier                 |
| Configuration  | Task, service, registry, or startup configuration |
| Executable     | Referenced file or script                         |
| Command Line   | Complete execution command line                   |
| Path           | Artifact or executable location                   |
| Hash           | SHA-256 or available file hash                    |
| Signature      | Digital signature and signer                      |
| Process        | Related process metadata                          |
| Authentication | Related account activity                          |
| Network        | Related network activity                          |
| Scope          | Additional affected systems                       |
| Detections     | Related security alerts                           |

## Decision Criteria

### Benign

Classify the persistence as **benign** when:

- the mechanism is approved;
- the associated executable is known and trusted;
- the account is authorized;
- the configuration matches expected software or administration;
- no additional suspicious activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the persistence as **suspicious** when:

- the mechanism is unexpected;
- the executable is unrecognized;
- the configuration is unusual;
- the artifact is unsigned or difficult to attribute;
- related suspicious process or network activity exists;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the persistence as **malicious** when there is sufficient evidence of:

- unauthorized automatic execution;
- confirmed malicious executable or script;
- persistence associated with known malicious activity;
- suspicious execution combined with credential access, lateral movement, or command-and-control activity;
- persistence established as part of a confirmed compromise.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when there is insufficient evidence to determine the legitimacy of the persistence mechanism.

Document:

- evidence collected;
- missing evidence;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- confirmed malicious persistence is identified;
- a privileged account is associated with the mechanism unexpectedly;
- multiple hosts contain the same suspicious persistence;
- a business-critical host is affected;
- persistence is associated with malware;
- credential access is suspected;
- lateral movement is suspected;
- command-and-control activity is identified.

## Response Guidance

For confirmed malicious persistence:

1. Preserve relevant evidence.
2. Follow the organization's containment procedure.
3. Identify all related hosts and accounts.
4. Search for the same persistence indicators across the environment.
5. Review related processes, files, and network activity.
6. Remove or disable the persistence mechanism according to authorized incident-response procedures.
7. Investigate possible credential exposure.
8. Escalate to incident response.
9. Document the timeline and remediation actions.

Do not remove or modify persistence artifacts before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/sigma/lsass-access.yml`
- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/obfuscated-powershell.yar`
- `detection-rules/yara/yara-powershell-payload.yar`

## Related Playbooks

- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-powershell-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/persistence/scheduled-task-persistence.md`
- `playbooks/persistence/service-persistence.md`
- `playbooks/persistence/registry-run-keys.md`
- `playbooks/persistence/startup-folder.md`
- `playbooks/response/persistence-removal-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved persistence test data and controlled endpoint security datasets.

Validation should confirm that:

- persistence mechanisms can be identified;
- task, service, registry, and startup configurations can be investigated;
- associated files and processes can be correlated;
- related network and authentication activity can be investigated;
- environmental scope can be determined;
- legitimate persistence can be distinguished from suspicious activity;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Persistence removal, endpoint isolation, service changes, registry changes, and other remediation actions must follow applicable authorization, evidence-preservation, and change-management procedures.
