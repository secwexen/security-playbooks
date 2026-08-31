---
id: "suspicious-process-triage"
name: "Suspicious Process Triage"
category: "triage"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-08-30T00:00:00Z"
updated_at: "2026-08-31T00:00:00Z"
description: "Investigate suspicious process execution and determine whether the observed process activity is benign, suspicious, or malicious."
objective: "Determine the legitimacy, execution chain, scope, and potential impact of suspicious process activity and provide evidence for escalation or closure."
severity: "high"
mitre_attack:
  - "T1059"
  - "T1105"
triggers:
  - "Suspicious process execution alert"
  - "Unusual parent-child process relationship"
  - "Unexpected executable or script execution"
  - "Process execution from a suspicious path"
  - "Threat hunting identifies anomalous process activity"
prerequisites:
  - "Access to endpoint process telemetry"
  - "Access to command-line telemetry"
  - "Access to authentication telemetry"
  - "Access to file and network telemetry"
tags:
  - "process"
  - "triage"
  - "endpoint"
  - "execution"
  - "windows"
references:
  - "https://attack.mitre.org/techniques/T1059/"
  - "https://attack.mitre.org/techniques/T1105/"
steps:
  - id: "identify-host"
    order: 1
    name: "Identify Affected Host"
    action: "investigate"
    description: "Identify the affected endpoint and collect basic host context."
    expected_result: "The affected host and its operational context are identified."
  - id: "identify-user"
    order: 2
    name: "Identify Associated User"
    action: "investigate"
    description: "Determine which user account or service identity was associated with the process."
    expected_result: "The account associated with the process is identified."
  - id: "review-process-tree"
    order: 3
    name: "Review Process Tree"
    action: "analyze"
    description: "Review the suspicious process, parent process, child processes, and execution sequence."
    expected_result: "The complete process execution chain is documented."
  - id: "review-command-line"
    order: 4
    name: "Review Command Line"
    action: "analyze"
    description: "Inspect the process command line and execution parameters for suspicious behavior."
    expected_result: "Suspicious command-line characteristics are identified or ruled out."
  - id: "review-file-context"
    order: 5
    name: "Review File Context"
    action: "analyze"
    description: "Determine the executable path, file metadata, and related file activity."
    expected_result: "The origin and legitimacy of the executable are assessed."
  - id: "review-network-activity"
    order: 6
    name: "Review Network Activity"
    action: "analyze"
    description: "Review network connections associated with the suspicious process."
    expected_result: "Relevant network destinations and communication patterns are documented."
  - id: "correlate-related-events"
    order: 7
    name: "Correlate Related Events"
    action: "hunt"
    description: "Search for related authentication, persistence, credential access, lateral movement, and process activity."
    expected_result: "Related activity is identified or ruled out."
  - id: "determine-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the process activity and document the supporting evidence."
    expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "suspicious-process"
---

# Suspicious Process Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspicious process execution on endpoint systems.

The goal is to determine whether the observed process activity is:

- expected and legitimate;
- suspicious and requiring additional investigation; or
- confirmed malicious and requiring incident response.

## MITRE ATT&CK

| Technique | Name                              | Relevance                                                                  |
| --------- | --------------------------------- | -------------------------------------------------------------------------- |
| T1059     | Command and Scripting Interpreter | Relevant when process activity involves command or script execution        |
| T1105     | Ingress Tool Transfer             | Relevant when the suspicious process retrieves tools, scripts, or payloads |

Additional ATT&CK mappings should only be added when the observed process behavior supports them.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint detection identifies suspicious process execution.
- An unusual parent-child process relationship is observed.
- A process executes from a temporary, user-writable, or otherwise unexpected path.
- A process has an unusual command line or execution context.
- An unknown or unsigned executable is observed.
- Threat hunting identifies anomalous process behavior.
- A suspicious process is associated with authentication, network, or persistence activity.

## Scope

The investigation should consider:

- affected host;
- associated user or service account;
- process ID;
- parent process;
- child processes;
- full process tree;
- command line;
- executable path;
- file metadata;
- file hash;
- digital signature;
- process integrity level;
- process creation time;
- network connections;
- related authentication events;
- persistence mechanisms;
- related processes on other hosts.

## Triage Procedure

### Step 1 — Identify the Affected Host

Collect:

- hostname;
- IP address;
- operating system;
- asset owner;
- host criticality;
- current endpoint status.

Determine whether the endpoint is:

- a user workstation;
- a server;
- an administrative workstation;
- a domain controller; or
- another security-sensitive system.

### Step 2 — Identify the Associated User

Determine which account initiated or was associated with the process.

Collect:

- username;
- domain;
- account type;
- logon type;
- source workstation where available;
- recent authentication activity.

Determine whether the account is:

- a standard user;
- an administrator;
- a privileged account;
- a service account; or
- unexpected for the affected host.

### Step 3 — Review the Process Tree

Review:

- suspicious process;
- parent process;
- grandparent process where available;
- child processes;
- process creation order;
- process creation timestamps.

Pay particular attention to unexpected relationships such as:

- Microsoft Office applications spawning command interpreters;
- browsers spawning unusual executables;
- archive utilities spawning scripts;
- scripting engines spawning network-capable tools;
- system utilities spawning unsigned binaries;
- unusual processes executing from temporary directories.

A suspicious parent-child relationship should be investigated in context and should not be treated as malicious based on process names alone.

### Step 4 — Review Command Line

Inspect the command line for:

- unusual parameters;
- encoded data;
- obfuscated content;
- hidden execution;
- script interpreters;
- download or retrieval behavior;
- suspicious file paths;
- temporary directories;
- unusual execution flags;
- attempts to bypass normal security controls.

Capture the complete command line when available.

### Step 5 — Review Executable and File Context

Collect:

- executable path;
- filename;
- file creation time;
- modification time;
- file size;
- file hash;
- digital signature;
- signer information;
- file reputation where authorized tooling is available.

Pay particular attention to executables located in:

- user-writable directories;
- temporary directories;
- download directories;
- application data directories;
- unusual system paths.

Compare the observed executable with known-good software and approved administrative tooling.

### Step 6 — Review Process Metadata

Collect:

- process ID;
- parent process ID;
- process start time;
- integrity level;
- session ID;
- account context;
- executable path;
- command line;
- loaded modules where available.

Investigate unexpected privilege or integrity changes.

### Step 7 — Review Network Activity

Determine whether the process generated network activity.

Collect:

- destination IP;
- destination domain;
- destination port;
- protocol;
- connection timestamp;
- connection frequency;
- DNS activity;
- HTTP or HTTPS metadata where available.

Prioritize investigation when the process communicates with:

- previously unseen external destinations;
- suspicious domains;
- known malicious infrastructure;
- unusual ports or protocols;
- destinations unrelated to the expected application function.

### Step 8 — Correlate Related Events

Search for related activity involving:

- process creation;
- authentication;
- scheduled tasks;
- services;
- registry modifications;
- credential access;
- lateral movement;
- file creation;
- network connections;
- other detections.

Search across the environment for:

- the same executable hash;
- the same process name;
- the same command line;
- the same parent-child relationship;
- the same destination;
- the same user activity.

## Evidence to Collect

| Evidence       | Description                            |
| -------------- | -------------------------------------- |
| Host           | Hostname, IP address, operating system |
| User           | Account associated with process        |
| Process        | Process metadata and identifiers       |
| Parent         | Parent process details                 |
| Children       | Child process details                  |
| Process Tree   | Full execution chain                   |
| Command Line   | Complete process command line          |
| Executable     | Path and filename                      |
| Hash           | SHA-256 or available file hash         |
| Signature      | Digital signature and signer           |
| Network        | Related network connections            |
| Authentication | Related account activity               |
| Files          | Created or modified artifacts          |
| Detections     | Related alerts and rule IDs            |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the executable is known and approved;
- the parent-child relationship is expected;
- the associated account is authorized;
- the process location is normal;
- related network activity is expected;
- no additional suspicious indicators are identified.

Document the business or operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the process is unusual for the host;
- the parent-child relationship is unexpected;
- the executable originates from an unusual location;
- the command line contains suspicious characteristics;
- the process is unsigned or otherwise difficult to attribute;
- network activity is anomalous;
- related telemetry is incomplete.

Continue investigation and correlate additional evidence.

### Malicious

Classify the activity as **malicious** when evidence supports unauthorized activity, including:

- confirmed malicious executable or payload;
- confirmed unauthorized execution;
- malicious process chain;
- confirmed command-and-control activity;
- persistence;
- credential access;
- lateral movement;
- malware execution.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the process is benign or malicious.

Document:

- what evidence was collected;
- what evidence is missing;
- what additional telemetry is required.

## Escalation

Escalate the investigation when:

- a privileged account is involved unexpectedly;
- a security-sensitive host is affected;
- a suspicious process executes a payload;
- multiple hosts show the same process behavior;
- malicious infrastructure is contacted;
- persistence is identified;
- credential access is suspected;
- lateral movement is suspected;
- process tampering or defense evasion is suspected.

## Response Guidance

For confirmed malicious activity:

1. Preserve relevant evidence.
2. Follow the organization's endpoint isolation procedure when required.
3. Identify related accounts and hosts.
4. Search for the same process indicators across the environment.
5. Review persistence mechanisms.
6. Investigate possible credential exposure.
7. Escalate to incident response.
8. Record the investigation timeline and findings.

Do not delete suspicious artifacts before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/sigma/lsass-access.yml`
- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/obfuscated-powershell.yar`
- `detection-rules/yara/yara-powershell-payload.yar`
- `detection-rules/suricata/network-alert.rules`
- `detection-rules/suricata/powershell-alert.rules`

## Related Playbooks

- `playbooks/triage/suspicious-powershell-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/triage/persistence-triage.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`
- `playbooks/response/persistence-removal-response.md`

## Validation

The playbook should be validated against approved repository test data.

Validation should confirm that:

- suspicious process execution is detected;
- expected process trees can be identified;
- suspicious command lines can be investigated;
- suspicious executables can be attributed where possible;
- related network activity can be correlated;
- benign process activity can be distinguished from suspicious behavior;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Investigation and response actions must follow applicable authorization, evidence-preservation, and change-management procedures.
