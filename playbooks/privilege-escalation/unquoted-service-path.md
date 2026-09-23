---
id: "unquoted-service-path"
name: "Unquoted Service Path"
category: "privilege-escalation"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-23T15:39:00Z"
updated_at: "2026-09-23T15:39:00Z"
description: "Unquoted Service Path abuse occurs when a Windows service executable path containing spaces is not enclosed in quotation marks and can be intercepted by an unintended executable."
objective: "Identify, investigate, and validate suspicious unquoted service paths and determine whether path interception could result in unauthorized execution, privilege escalation, persistence, or related malicious activity."
severity: "high"
mitre_attack:
  - "T1574.009"
triggers:
  - "Unquoted Windows service executable path"
  - "Service executable path contains spaces and is not quoted"
  - "Executable created in a parent directory of an unquoted service path"
  - "Unexpected service process execution"
  - "Suspicious service configuration associated with an unquoted path"
  - "Threat hunting identifies potentially vulnerable service paths"
prerequisites:
  - "Access to Windows service configuration telemetry"
  - "Access to process creation telemetry"
  - "Access to file and directory telemetry"
  - "Access to account and privilege telemetry"
tags:
  - "unquoted-service-path"
  - "privilege-escalation"
  - "execution"
  - "service"
  - "windows"
  - "path-interception"
  - "endpoint"
references:
  - "https://attack.mitre.org/techniques/T1574/009/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Unquoted Service Path Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, service, executable path, account, timestamp, and alert context."
  expected_result: "The suspicious service path condition and affected asset are identified."
- id: "identify-service-path"
  order: 2
  name: "Identify Service Path"
  action: "analyze"
  description: "Review the service name, executable path, startup configuration, service account, and whether the path contains spaces without quotation marks."
  expected_result: "The service configuration and potential path-interception condition are documented."
- id: "review-path-resolution"
  order: 3
  name: "Review Path Resolution"
  action: "analyze"
  description: "Determine the executable resolution order for the service path and identify directories where an unintended executable could be resolved."
  expected_result: "Potential interception points in the service path are identified."
- id: "review-file-activity"
  order: 4
  name: "Review File and Directory Activity"
  action: "analyze"
  description: "Review executable creation, modification, and placement in directories that could affect resolution of the unquoted service path."
  expected_result: "Suspicious file or directory activity associated with the service path is identified or ruled out."
- id: "review-process-activity"
  order: 5
  name: "Review Process Activity"
  action: "analyze"
  description: "Correlate service startup with process creation, executable path, parent-child relationships, account context, and execution timestamps."
  expected_result: "Service-related process activity is documented and correlated."
- id: "review-privilege-context"
  order: 6
  name: "Review Privilege Context"
  action: "analyze"
  description: "Determine the security context under which the service executes and assess whether intercepted execution could provide elevated privileges."
  expected_result: "The privilege impact of the service execution context is established."
- id: "determine-scope"
  order: 7
  name: "Determine Unquoted Path Scope"
  action: "hunt"
  description: "Search for the same service path pattern, service configuration, executable, file hash, or suspicious parent-directory artifact across the environment."
  expected_result: "The prevalence and scope of potentially vulnerable service paths are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the unquoted service path activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "unquoted-service-path"
---

# Unquoted Service Path

## Purpose

This playbook provides a structured workflow for investigating potentially vulnerable Windows service executable paths.

An unquoted service path containing spaces may allow an unintended executable in a higher-level directory to be resolved when the service starts. This can be abused for unauthorized execution, persistence, or privilege escalation when the affected service runs with elevated privileges.

The objective is to determine whether an unquoted service path represents an exploitable condition, whether path interception has occurred, and whether additional malicious activity is associated with the service.

## MITRE ATT&CK

| Technique | Name                                                      | Relevance                                                                                                       |
| --------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| T1574.009 | Hijack Execution Flow: Path Interception by Unquoted Path | Relevant when an unquoted Windows service path containing spaces can be intercepted by an unintended executable |

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An unquoted Windows service executable path is detected.
- A service path contains spaces and is not enclosed in quotation marks.
- An executable appears in a directory that could intercept an unquoted service path.
- A service launches an unexpected executable.
- A suspicious service configuration is associated with an unquoted path.
- Threat hunting identifies potentially vulnerable service configurations.

## Scope

The investigation should consider:

- affected host;
- service name;
- display name;
- service executable path;
- service arguments;
- startup type;
- service account;
- privilege context;
- service state;
- executable file;
- parent directories;
- file hashes;
- file creation time;
- file modification time;
- file ownership;
- file permissions;
- process creation;
- process tree;
- service configuration changes;
- related alerts;
- additional affected hosts.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- service name;
- service executable path;
- service account;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify the Service Path

Collect:

- service name;
- service path;
- executable path;
- command-line arguments;
- startup type;
- service account;
- service state;
- configuration timestamps where available.

Determine whether the executable path:

- contains spaces;
- is not enclosed in quotation marks;
- references a valid executable;
- includes additional arguments.

A path should not be treated as malicious solely because it is unquoted; determine whether the path is actually vulnerable to interception.

### Step 3 — Review Path Resolution

Analyze the path components and determine where Windows could resolve an executable before reaching the intended executable.

For example, investigate parent-directory locations implied by a path containing spaces.

Determine whether unexpected executables exist in those locations.

Document:

- candidate interception locations;
- executable names;
- file paths;
- file hashes;
- file timestamps;
- file ownership;
- file permissions.

Do not create test executables or modify production paths during investigation.

### Step 4 — Review File and Directory Activity

Review files located in potentially relevant parent directories.

Determine:

- whether the files are expected;
- when they were created;
- who created or modified them;
- whether their timestamps align with service configuration changes;
- whether their hashes or signatures are trusted;
- whether non-administrative users can write to the relevant directories.

Pay particular attention to recently created executables in locations that could affect path resolution.

### Step 5 — Review Process Activity

Correlate the service with:

- service start events;
- process creation;
- executable path;
- parent process;
- child processes;
- command line;
- process execution timestamps;
- account context;
- integrity level where available.

Determine whether the service started the expected executable or an unexpected executable.

### Step 6 — Review Privilege Context

Determine:

- service execution account;
- account type;
- group membership;
- assigned privileges;
- integrity level;
- expected service security context.

Assess whether an intercepted executable would execute with a more privileged context than the user who could place or modify the executable.

### Step 7 — Determine Activity Scope

Search across the environment for:

- the same unquoted service path;
- the same service name;
- the same executable path;
- the same executable hash;
- the same parent-directory artifact;
- the same service configuration pattern.

Determine:

- number of affected hosts;
- number of affected services;
- first observed vulnerable configuration;
- latest observed activity;
- whether suspicious executable placement is ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence         | Description                                    |
| ---------------- | ---------------------------------------------- |
| Alert            | Detection source, ID, severity, timestamp      |
| Host             | Hostname, IP address, operating system         |
| Service          | Name, path, state, startup type                |
| Service Account  | Account and privilege context                  |
| Service Path     | Complete executable path and arguments         |
| Resolution Paths | Potential executable interception locations    |
| Executables      | Files present at relevant path locations       |
| Hashes           | SHA-256 or available file hashes               |
| File Metadata    | Creation, modification, owner, and permissions |
| Process          | Related process activity                       |
| Process Tree     | Parent and child processes                     |
| Configuration    | Service configuration and change history       |
| Timeline         | Service, file, and process timestamps          |
| Scope            | Other affected hosts and services              |
| Detections       | Related security alerts                        |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the service configuration is known and approved;
- the unquoted path does not provide a practical interception opportunity;
- relevant directories are appropriately protected;
- the executable is trusted;
- no suspicious executable is present in a potential interception location;
- no unauthorized service activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the service path is unquoted and contains spaces;
- a potential interception location is writable by an unexpected user;
- an unexpected executable exists in a relevant parent directory;
- service configuration changes are unexplained;
- process execution is inconsistent with the expected service behavior;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- an attacker-controlled executable was placed in a path-interception location;
- the unintended executable was launched through the vulnerable service path;
- execution occurred under an unauthorized elevated security context;
- the activity is associated with confirmed privilege escalation or persistence;
- the service path was deliberately modified or abused as part of a broader compromise;
- other confirmed malicious behavior is present.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the unquoted path is benign or was abused.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- path interception is confirmed;
- unauthorized privileged execution is confirmed;
- an unexpected executable is found in a relevant path location;
- a privileged service account is involved;
- persistence is identified;
- multiple hosts are affected;
- credential access or lateral movement is observed.

## Response Guidance

For confirmed malicious unquoted service path abuse:

1. Preserve service, process, file, configuration, and account evidence.
2. Identify all affected hosts and services.
3. Follow the organization's endpoint containment procedure.
4. Determine whether an unintended executable was executed.
5. Search for the same service path, executable, hash, and parent-directory artifact across the environment.
6. Investigate persistence, privilege escalation, credential access, and lateral movement.
7. Remediate the vulnerable service configuration according to approved change procedures.
8. Remove unauthorized artifacts only after required evidence preservation.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Do not modify service paths, delete suspicious executables, or alter relevant evidence before required preservation and authorization have been considered.

## Related Detection Rules

No dedicated unquoted-service-path detection rule is currently available in the repository.

## Related Playbooks

- `playbooks/privilege-escalation/privileged-service-abuse.md`
- `playbooks/privilege-escalation/weak-service-permissions.md`
- `playbooks/privilege-escalation/service-permission-abuse.md`
- `playbooks/persistence/service-persistence.md`
- `playbooks/execution/scheduled-task-execution.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/response/persistence-removal-response.md`
- `playbooks/response/malware-response.md`

## Validation

The playbook should be validated against approved Windows service configurations, service telemetry, file metadata, process creation events, and controlled laboratory scenarios.

Validation should confirm that:

- unquoted service paths can be identified;
- paths containing spaces can be analyzed;
- potential interception locations can be determined;
- relevant file permissions and artifacts can be investigated;
- service execution can be correlated with process activity;
- service privilege context can be established;
- legitimate service configurations can be distinguished from exploitable or abused configurations;
- environmental scope can be determined;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Unquoted service paths should be investigated using approved telemetry and controlled environments. Do not create interception executables, modify service configurations, or perform unauthorized privilege-escalation testing on production systems.
