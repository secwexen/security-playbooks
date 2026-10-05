---
id: "wmi-event-subscription"
name: "WMI Event Subscription"
category: "persistence"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-28T17:15:00Z"
updated_at: "2026-10-05T16:53:00Z"
description: "WMI Event Subscription persistence involves establishing Windows Management Instrumentation event filters, consumers, and bindings that trigger execution when defined system events occur."
objective: "Identify, investigate, and validate suspicious WMI event subscription activity and determine whether the mechanism establishes unauthorized persistence or related privilege escalation."
severity: "high"
mitre_attack:
  - "T1546.003"
triggers:
  - "Unexpected WMI event filter, consumer, or binding creation"
  - "Suspicious WMI subscription associated with executable or script execution"
  - "Unexpected mofcomp.exe activity or MOF compilation"
  - "Unexpected WmiPrvSE.exe child process activity"
  - "WMI event subscription changes identified during threat hunting"
  - "Persistence identified through WMI telemetry"
prerequisites:
  - "Access to Windows WMI and endpoint telemetry"
  - "Access to WMI object creation and modification events where available"
  - "Access to process creation and command-line telemetry"
  - "Access to file and authentication telemetry"
tags:
  - "wmi"
  - "persistence"
  - "event-triggered-execution"
  - "windows"
  - "endpoint"
  - "privilege-escalation"
  - "fileless"
references:
  - "https://attack.mitre.org/techniques/T1546/003/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify WMI Event Subscription Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, WMI namespace, subscription object, account, timestamp, and alert context."
    expected_result: "The suspicious WMI event subscription activity and affected asset are identified."
  - id: "identify-subscription"
    order: 2
    name: "Identify WMI Subscription"
    action: "analyze"
    description: "Review the WMI event filter, event consumer, FilterToConsumerBinding, namespace, and associated subscription configuration."
    expected_result: "The WMI subscription structure and associated execution mechanism are documented."
  - id: "review-consumer-action"
    order: 3
    name: "Review Consumer Action"
    action: "analyze"
    description: "Determine what action the consumer performs when the subscribed event occurs and identify associated commands, executables, scripts, or payloads."
    expected_result: "The consumer action and triggered execution behavior are characterized."
  - id: "review-process-activity"
    order: 4
    name: "Review Process Activity"
    action: "analyze"
    description: "Correlate WMI activity with WmiPrvSE.exe, mofcomp.exe, PowerShell, script interpreters, child processes, command lines, and related process execution."
    expected_result: "The process execution associated with the WMI subscription is identified and correlated."
  - id: "review-file-context"
    order: 5
    name: "Review File Context"
    action: "analyze"
    description: "Review files referenced by the subscription or consumer and investigate associated paths, hashes, timestamps, signatures, and creation or modification activity."
    expected_result: "Related files and payload artifacts are identified and assessed."
  - id: "review-related-events"
    order: 6
    name: "Review Related Events"
    action: "analyze"
    description: "Correlate authentication, WMI, process, file, network, persistence, and security telemetry surrounding the subscription activity."
    expected_result: "Related activity is identified and correlated with the WMI persistence mechanism."
  - id: "determine-subscription-scope"
    order: 7
    name: "Determine Subscription Scope"
    action: "hunt"
    description: "Search the environment for the same WMI subscription pattern, consumer, command, executable, hash, namespace, or related persistence behavior."
    expected_result: "The prevalence and environmental scope of the WMI event subscription are determined."
  - id: "determine-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the WMI event subscription activity and document the evidence supporting the final assessment."
    expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "wmi-event-subscription"
---

# WMI Event Subscription

## Purpose

This playbook provides a structured workflow for investigating suspicious Windows Management Instrumentation (WMI) event subscription activity associated with persistence.

WMI event subscriptions can use event filters, event consumers, and bindings to trigger execution when defined system events occur. The resulting execution may be proxied by the WMI Provider Host process and, depending on the configured context, may execute with elevated privileges.

The objective is to determine whether the observed subscription is legitimate, suspicious, or malicious and whether it established unauthorized persistence or contributed to related privilege escalation.

## MITRE ATT&CK

| Technique | Name                                                  | Relevance                                                                                                       |
| --------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| T1546.003 | Windows Management Instrumentation Event Subscription | Primary technique for persistence established through malicious WMI event subscriptions and triggered execution |

T1546.003 is a sub-technique of Event Triggered Execution. Is associated with the Persistence and Privilege Escalation tactics.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious WMI event filter, consumer, or binding is created or modified.
- An unexpected WMI subscription triggers executable or script execution.
- `mofcomp.exe` is used unexpectedly to compile MOF content associated with WMI persistence.
- `WmiPrvSE.exe` exhibits anomalous child process activity.
- Threat hunting identifies unusual WMI persistence artifacts.
- WMI telemetry indicates persistence-related object creation or modification.

MITRE's detection strategy for T1546.003 includes monitoring WMI `EventFilter`, `EventConsumer`, and `FilterToConsumerBinding` creation, MOF compilation, PowerShell `Register-WmiEvent` usage, and anomalous `WmiPrvSE.exe` child processes.

## Scope

The investigation should consider:

- affected host;
- WMI namespace;
- event filter;
- event consumer;
- `FilterToConsumerBinding`;
- subscribed event;
- consumer action;
- executable or script;
- command line;
- process tree;
- `WmiPrvSE.exe`;
- `mofcomp.exe`;
- PowerShell activity;
- referenced files;
- file hashes;
- digital signatures;
- account and privilege context;
- authentication activity;
- network activity;
- timestamps;
- related persistence mechanisms;
- additional affected hosts.

## Investigation Procedure

### Step 1 — Identify WMI Event Subscription Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- WMI namespace;
- subscription object;
- associated account;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify WMI Subscription

Collect and review:

- event filter name;
- event consumer name;
- binding configuration;
- WMI namespace;
- subscribed event condition;
- consumer type;
- creator or modifying account;
- creation time;
- modification time;
- configuration history where available.

Determine whether the subscription is expected for the affected host and application environment.

### Step 3 — Review Consumer Action

Determine what occurs when the subscribed event is triggered.

Review:

- executed command;
- executable path;
- script path;
- command-line arguments;
- interpreter;
- referenced payload;
- execution context;
- expected application relationship.

Pay particular attention to consumers that launch:

- executables from user-writable directories;
- temporary files;
- PowerShell;
- script interpreters;
- unsigned or unknown binaries;
- recently created artifacts.

Do not execute unknown payloads on production systems.

### Step 4 — Review Process Activity

Correlate the subscription with process telemetry.

Review:

- `WmiPrvSE.exe`;
- child processes;
- parent process relationships;
- process creation times;
- executable paths;
- command lines;
- process integrity levels;
- PowerShell execution;
- `mofcomp.exe` execution;
- script interpreter activity.

Determine whether the process chain is consistent with expected administrative or application activity.

### Step 5 — Review File Context

Investigate files associated with the WMI subscription.

Collect:

- file path;
- file name;
- file type;
- SHA-256 hash;
- creation time;
- modification time;
- digital signature;
- file owner;
- related scripts;
- MOF files;
- referenced payloads.

Determine whether the artifacts are expected and whether they were created or modified near the time of subscription creation.

### Step 6 — Review Related Events

Correlate the WMI subscription with:

- WMI object creation and modification events;
- process creation;
- authentication events;
- PowerShell activity;
- file creation and modification;
- network connections;
- persistence changes;
- related security alerts.

Review available WMI telemetry, including relevant object creation and modification events where supported by the monitoring environment. MITRE identifies WMI object creation and WMI event channels as relevant data sources for this technique.

### Step 7 — Determine Subscription Scope

Search the environment for:

- same WMI event filter;
- same consumer;
- same binding;
- same namespace;
- same command;
- same executable;
- same script;
- same file hash;
- same payload;
- same account;
- same persistence pattern.

Determine:

- number of affected hosts;
- first observed subscription;
- latest observed subscription;
- number of unique consumers;
- whether the subscription remains active;
- whether the same mechanism exists on additional systems.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence       | Description                                                |
| -------------- | ---------------------------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp                  |
| Host           | Hostname, IP address, operating system                     |
| WMI Namespace  | Namespace containing the subscription                      |
| Event Filter   | Filter name and trigger condition                          |
| Event Consumer | Consumer name and consumer type                            |
| Binding        | Filter-to-consumer binding configuration                   |
| Command        | Triggered command or execution action                      |
| Process        | Related process metadata                                   |
| Process Tree   | Parent-child process relationships                         |
| Files          | Referenced or created artifacts                            |
| Hashes         | SHA-256 or other available hashes                          |
| Account        | Associated account and privilege context                   |
| WMI Events     | Related WMI object creation or modification events         |
| Authentication | Related account activity                                   |
| Network        | Related network connections                                |
| Timeline       | Subscription, process, file, and authentication timestamps |
| Scope          | Other affected hosts and subscriptions                     |
| Detections     | Related security alerts                                    |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the WMI subscription is authorized;
- the subscription is associated with a known application or administrative workflow;
- the consumer action is expected;
- the executing file or script is known and trusted;
- the associated account and privilege context are appropriate;
- no suspicious related activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the subscription is unexpected;
- the creator or modifier is unknown;
- the consumer action is unusual;
- the executable or script is untrusted;
- the subscription uses an unusual namespace or event trigger;
- `mofcomp.exe` activity is unexplained;
- anomalous `WmiPrvSE.exe` child processes are observed;
- related authentication, file, or network activity is unusual;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized WMI subscription creation or modification;
- confirmed malicious payload execution through the subscription;
- WMI persistence associated with known malicious artifacts;
- execution of unauthorized code under a privileged security context;
- persistence combined with credential access, lateral movement, or command-and-control activity;
- the subscription is part of a confirmed compromise.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the WMI subscription is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required;
- limitations affecting the investigation.

## Escalation

Escalate the investigation when:

- unauthorized WMI subscription activity is confirmed;
- malicious code execution is identified;
- execution occurs under an unexpected privileged context;
- `mofcomp.exe` is used without an approved operational explanation;
- suspicious `WmiPrvSE.exe` child processes are observed;
- persistence is confirmed;
- multiple hosts contain the same suspicious subscription;
- credential access, lateral movement, or command-and-control activity is identified.

## Response Guidance

For confirmed malicious WMI event subscription activity:

1. Preserve WMI, process, file, account, and network evidence.
2. Identify all affected hosts, namespaces, consumers, and accounts.
3. Follow the organization's endpoint containment procedure.
4. Preserve the subscription configuration and associated artifacts before removal.
5. Identify related executable, script, MOF, hash, and command-line indicators.
6. Search the environment for the same WMI persistence pattern.
7. Remove unauthorized WMI subscription artifacts according to approved response procedures.
8. Investigate related persistence, privilege escalation, credential access, and lateral movement.
9. Review potentially exposed privileged accounts and affected systems.
10. Escalate confirmed compromise to incident response.
11. Document the investigation timeline, evidence, and remediation actions.

Do not delete WMI objects, payloads, logs, or related artifacts before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

## Related Playbooks

- `playbooks/execution/wmi-execution.md`
- `playbooks/triage/persistence-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/response/persistence-removal-response.md`

## Validation

The playbook should be validated against approved Windows WMI telemetry, WMI object creation and modification events, process creation data, file telemetry, and controlled laboratory scenarios.

Validation should confirm that:

- WMI event filters can be identified;
- WMI consumers can be identified;
- `FilterToConsumerBinding` relationships can be investigated;
- consumer execution actions can be determined;
- related process activity can be correlated;
- referenced files and payloads can be assessed;
- legitimate WMI subscriptions can be distinguished from unauthorized persistence;
- environmental scope can be determined;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

WMI event subscriptions, consumers, bindings, and associated payloads should be investigated using approved telemetry and controlled environments. Do not intentionally create malicious WMI persistence or execute unauthorized payloads on production systems.
