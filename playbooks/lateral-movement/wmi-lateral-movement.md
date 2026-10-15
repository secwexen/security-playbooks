---
id: "wmi-lateral-movement"
name: "WMI Lateral Movement"
category: "lateral-movement"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-15T18:55:00Z"
updated_at: "2026-10-15T18:55:00Z"
description: "Investigate suspected lateral movement involving remote Windows Management Instrumentation activity."
objective: "Determine whether WMI-related remote activity represents authorized administration or unauthorized lateral movement, identify affected hosts and accounts, and establish the scope of the activity."
severity: "high"
mitre_attack:
  - "T1047"
triggers:
  - "Unexpected WMI activity involving a remote Windows host"
  - "Unusual child process creation associated with WmiPrvSE.exe"
  - "Remote WMI activity involving an unexpected account or source host"
  - "WMI-related process execution correlated with suspicious network connections"
  - "Unexpected remote command execution identified during threat hunting"
prerequisites:
  - "Access to endpoint process creation telemetry"
  - "Access to Windows authentication and logon telemetry"
  - "Access to WMI Activity operational logs where available"
  - "Access to network connection and firewall telemetry"
  - "Access to asset inventory and authorized administration records"
tags:
  - "wmi"
  - "lateral-movement"
  - "execution"
  - "windows"
  - "remote-management"
  - "process-investigation"
references:
  - "https://attack.mitre.org/techniques/T1047/"
steps:
  - id: "identify-wmi-lateral-movement-alert"
    order: 1
    name: "Identify WMI Lateral Movement Alert"
    action: "investigate"
    description: "Identify the detection source, alert context, observed WMI activity, and initial indication of remote execution."
    expected_result: "The alert context and suspected WMI-related activity are documented."
  - id: "identify-source-and-target-hosts"
    order: 2
    name: "Identify Source and Target Hosts"
    action: "investigate"
    description: "Identify the originating host, destination host, associated accounts, and relevant timestamps."
    expected_result: "The source and target systems and their relationship are established."
  - id: "review-authentication-and-privilege-context"
    order: 3
    name: "Review Authentication and Privilege Context"
    action: "analyze"
    description: "Examine authentication events, account privileges, logon context, and authorization for remote WMI access."
    expected_result: "The authentication context and authorization status are assessed."
  - id: "review-wmi-activity"
    order: 4
    name: "Review WMI Activity"
    action: "analyze"
    description: "Review available WMI Activity logs, client information, operation details, namespaces, and remote access context."
    expected_result: "Relevant WMI operations and their execution context are documented."
  - id: "analyze-process-and-command-execution"
    order: 5
    name: "Analyze Process and Command Execution"
    action: "analyze"
    description: "Correlate WMI-related activity with process creation, command lines, parent-child relationships, and executable metadata."
    expected_result: "Associated process execution and potentially unauthorized command activity are identified or ruled out."
  - id: "correlate-network-and-related-activity"
    order: 6
    name: "Correlate Network and Related Activity"
    action: "analyze"
    description: "Correlate remote management connections with authentication, process, file, and related security events."
    expected_result: "Related network and endpoint activity is correlated with the suspected WMI execution."
  - id: "determine-lateral-movement-scope"
    order: 7
    name: "Determine Lateral Movement Scope"
    action: "hunt"
    description: "Search for related WMI activity, shared indicators, affected accounts, and additional target hosts across the environment."
    expected_result: "The prevalence and scope of the suspected lateral movement are determined."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity based on the collected evidence and document the rationale for the final assessment."
    expected_result: "The investigation outcome and supporting evidence are documented."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "wmi-lateral-movement"
---

# WMI Lateral Movement

## Purpose

This playbook provides a structured workflow for investigating suspected lateral movement involving Windows Management Instrumentation (WMI).

WMI is a legitimate Windows management technology that supports local and remote access to system information and management operations. Remote WMI activity may be used by authorized administrators and management platforms, but adversaries may also abuse it to execute commands on remote systems.

The objective is to determine whether the observed activity is authorized, suspicious, or malicious; identify the systems and accounts involved; and establish whether remote execution forms part of a broader attack chain.

WMI activity must not be classified as malicious solely because it involves remote access or a Windows management process. The investigation must consider authorization, execution context, process activity, and related evidence.

## MITRE ATT&CK

| Technique | Name                               | Relevance                                                                                         |
| --------- | ---------------------------------- | ------------------------------------------------------------------------------------------------- |
| T1047     | Windows Management Instrumentation | Primary technique when WMI is abused to execute commands or interact with remote Windows systems. |

MITRE ATT&CK classifies T1047 under the Execution tactic. This playbook focuses on investigating WMI activity when it is associated with suspected lateral movement.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Unexpected WMI activity involving a remote Windows host.
- WMI-related command execution from an unusual source system.
- Unexpected child processes associated with `WmiPrvSE.exe`.
- Remote WMI activity involving an unusual account or privilege context.
- WMI operations correlated with suspicious authentication events.
- Remote management connections followed by unusual process execution.
- Similar WMI-related activity observed across multiple hosts.
- Threat hunting identifies potential WMI abuse during lateral movement.

A single WMI event, remote connection, or `WmiPrvSE.exe` process is not sufficient to establish malicious activity.

## Scope

The investigation should consider:

- source host;
- target host;
- source and destination IP addresses;
- associated user accounts;
- account privileges;
- authentication events;
- logon context;
- WMI operation details;
- WMI namespace and provider information where available;
- WMI client process;
- process identifier;
- process parent-child relationships;
- process command lines;
- executable paths and file hashes;
- network connections;
- remote management protocols;
- timestamps and event correlation;
- additional affected hosts;
- related lateral movement activity;
- potential follow-on execution, persistence, or credential access.

Remote WMI may use DCOM/RPC or Windows Remote Management (WinRM). Network indicators should be interpreted in the context of the protocol, endpoint telemetry, and the organization's legitimate management architecture.

## Investigation Procedure

### Step 1 — Identify WMI Lateral Movement Alert

Record the original detection context before taking response actions.

Collect:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- suspected source host;
- suspected destination host;
- associated user account;
- observed process;
- command line where available;
- detection severity;
- reason for alert generation.

Determine whether the alert identifies an actual WMI operation, a process associated with WMI, a remote management connection, or only a behavioral indicator.

Preserve the original alert and associated event references.

### Step 2 — Identify Source and Target Hosts

Identify the systems involved in the suspected remote activity.

Collect:

- source hostname and IP address;
- target hostname and IP address;
- operating systems;
- asset owners;
- asset criticality;
- system roles;
- host management responsibilities;
- relevant connection timestamps.

Determine whether the source is an approved administrative workstation, management server, monitoring platform, or another expected management system.

Establish whether the target host is normally managed from the identified source.

Search for the same source-to-target relationship in historical telemetry to determine whether the activity is consistent with established administrative patterns.

### Step 3 — Review Authentication and Privilege Context

Identify the account associated with the remote activity.

Review:

- username and domain;
- account type;
- authentication timestamps;
- logon type where available;
- source workstation;
- account privilege level;
- group membership where relevant;
- recent authentication failures;
- successful logons preceding the activity;
- account use on other systems.

Determine whether the account was authorized to access the target host and perform the observed operation.

Investigate unusual administrative account use, unexpected source systems, anomalous logon times, or authentication activity inconsistent with the account's normal behavior.

A privileged account or successful authentication does not independently establish malicious activity.

### Step 4 — Review WMI Activity

Review available WMI Activity operational logs and associated endpoint telemetry.

Determine:

- whether a remote WMI operation occurred;
- the initiating client process where available;
- the associated user or security context;
- the WMI namespace or provider involved;
- operation timestamps;
- the target system;
- the requested operation;
- whether the activity matches approved management behavior.

Where relevant, investigate associated process activity involving `WmiPrvSE.exe`.

Do not assume that every WMI operation represents remote execution. WMI is also used for routine inventory, monitoring, configuration management, and system administration.

If WMI-specific telemetry is unavailable, document the limitation and use corroborating authentication, process, and network evidence.

### Step 5 — Analyze Process and Command Execution

Correlate the WMI activity with process creation and execution telemetry on the target host.

Review:

- process name and executable path;
- process identifier;
- parent process;
- child processes;
- command line and arguments;
- process creation timestamp;
- user and integrity context;
- executable hash;
- digital signature where available;
- related file activity.

Pay particular attention to unexpected command shells, script interpreters, or other processes appearing in temporal proximity to the remote WMI operation.

Assess whether the observed process activity is consistent with authorized administration or indicates unauthorized command execution.

Do not classify `WmiPrvSE.exe`, PowerShell, or another legitimate Windows component as malicious based on its name alone. Evaluate the process relationships, execution context, command line, and supporting evidence.

### Step 6 — Correlate Network and Related Activity

Correlate the suspected WMI operation with available network and security telemetry.

Review:

- source-to-target connections;
- relevant RPC/DCOM activity;
- WinRM connections where applicable;
- connection timestamps;
- associated authentication events;
- endpoint process creation;
- files created or modified;
- related security alerts;
- subsequent activity on the target host.

Investigate whether the source host accessed multiple systems in a short period or whether similar activity is associated with other suspicious events.

Determine whether the WMI operation was isolated or formed part of a broader sequence involving account compromise, remote execution, persistence, or additional lateral movement.

Network connections alone do not establish that WMI was used. Correlate network indicators with endpoint and authentication evidence.

### Step 7 — Determine Lateral Movement Scope

Search the environment for related activity using available identifiers and behavioral indicators.

Search for:

- the same source and destination hosts;
- the same user account;
- repeated WMI operations;
- similar process command lines;
- related executable hashes;
- similar process parent-child relationships;
- repeated remote management connections;
- additional affected systems;
- related authentication anomalies;
- subsequent suspicious execution.

Determine:

- number of affected hosts;
- number of affected accounts;
- first and last observed activity;
- whether the behavior is still occurring;
- whether privileged systems are affected;
- whether the activity is associated with other attack techniques.

Document any limitations caused by missing logs, incomplete endpoint coverage, or unavailable historical telemetry.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the classification and the evidence supporting the conclusion.

Identify whether containment, additional investigation, or incident-response escalation is required.

## Evidence to Collect

| Evidence           | Description                                                                  |
| ------------------ | ---------------------------------------------------------------------------- |
| Alert              | Detection source, alert identifier, severity, and timestamp                  |
| Source Host        | Hostname, IP address, asset role, and ownership                              |
| Target Host        | Hostname, IP address, asset role, and criticality                            |
| Account            | Username, domain, privileges, and account type                               |
| Authentication     | Logon events, timestamps, source host, and authentication context            |
| WMI Activity       | Relevant WMI operational logs and available operation details                |
| Process            | Executable, process identifier, parent-child relationships, and command line |
| File Artifacts     | Related files, executable paths, hashes, and signatures                      |
| Network            | Source-to-target connections, protocol, ports, and connection timestamps     |
| Timeline           | Correlated authentication, WMI, network, and process events                  |
| Scope              | Additional affected hosts, accounts, and related activity                    |
| Related Detections | Associated alerts and detection identifiers                                  |

Record relevant timestamps consistently and preserve original evidence according to the organization's evidence-handling procedures.

## Decision Criteria

### Benign

Classify the activity as **benign** when the collected evidence supports authorized administration.

Indicators may include:

- the source and target hosts have an established management relationship;
- the account is authorized to manage the target;
- the operation matches an approved administrative task;
- process execution is consistent with expected management activity;
- the activity occurs within an expected operational context;
- no suspicious follow-on execution is identified;
- no evidence links the operation to unauthorized access or broader compromise.

Document the administrative justification and any relevant change or maintenance records before closing the alert.

### Suspicious

Classify the activity as **suspicious** when the available evidence indicates anomalous behavior but is insufficient to confirm malicious activity.

Indicators may include:

- unexpected source or destination hosts;
- unusual use of a privileged account;
- WMI activity outside the account's normal operational pattern;
- unexpected child processes associated with WMI;
- command lines inconsistent with approved management tasks;
- remote access correlated with unusual authentication events;
- similar activity affecting multiple hosts;
- incomplete telemetry that prevents a reliable determination.

Continue the investigation and collect additional authentication, process, and network evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence establishes unauthorized WMI-related execution or its association with confirmed malicious activity.

Indicators may include:

- confirmed unauthorized remote command execution;
- malicious payload execution associated with WMI activity;
- a verified relationship between remote WMI execution and a compromised account;
- unauthorized execution across multiple hosts;
- WMI activity forming part of a confirmed lateral movement chain;
- corroborating evidence of persistence, credential access, or other malicious behavior.

Escalate to the appropriate incident-response workflow and assess whether containment is required.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the activity was authorized or malicious.

Examples include:

- missing WMI operational logs;
- incomplete process creation telemetry;
- unavailable authentication records;
- insufficient source-to-target network visibility;
- inability to establish the account's authorization;
- insufficient evidence to correlate WMI activity with observed process execution.

Document:

- evidence collected;
- evidence unavailable;
- unresolved questions;
- additional telemetry required;
- recommended investigation actions.

Do not classify activity as benign solely because malicious evidence is unavailable.

## Escalation

Escalate the investigation when:

- unauthorized remote execution is confirmed;
- a compromised or unexpectedly privileged account is involved;
- suspicious execution is observed on a critical system;
- multiple hosts are affected;
- malicious payload execution is identified;
- related persistence or credential access is detected;
- the activity is associated with a broader lateral movement chain;
- active compromise cannot be ruled out and the potential impact is significant.

Notify the appropriate incident-response personnel according to organizational procedures.

## Response Guidance

For confirmed malicious WMI-related lateral movement:

1. Preserve relevant WMI, authentication, process, file, and network evidence.
2. Identify the affected hosts, accounts, and remote execution relationships.
3. Follow the organization's approved endpoint containment procedures.
4. Assess whether the associated account or credentials require containment or remediation.
5. Search for related WMI activity, command lines, hashes, and process behaviors across the environment.
6. Investigate associated persistence, credential access, and additional lateral movement.
7. Remove unauthorized artifacts and remediate affected systems according to approved response procedures.
8. Restore affected systems only after appropriate validation and authorization.
9. Document the incident timeline, investigation findings, and remediation actions.

Do not indiscriminately terminate `WmiPrvSE.exe` processes or disable WMI across the environment. These components support legitimate Windows management operations, and unplanned changes may disrupt critical services.

Response actions must follow approved authorization, evidence-preservation, and change-management procedures.

## Related Detection Rules

## Related Playbooks

- `playbooks/execution/wmi-execution.md`
- `playbooks/triage/lateral-movement-triage.md`
- `playbooks/triage/suspicious-process-triage.md`

## Validation

The playbook should be validated against approved Windows endpoint telemetry, WMI Activity operational logs, authentication events, process creation data, network telemetry, and controlled laboratory scenarios.

Validation should confirm that:

- source and target systems can be identified;
- WMI-related activity can be correlated with authentication and process telemetry;
- associated process execution can be investigated;
- authorized administrative activity can be distinguished from suspicious behavior;
- related activity across multiple hosts can be identified;
- missing telemetry is documented appropriately;
- investigation outcomes are supported by collected evidence;
- escalation criteria produce consistent results.

The playbook must be validated in an authorized test environment before being considered operationally verified.

## Safety

This playbook is intended for defensive security operations, incident investigation, controlled laboratory validation, and authorized security testing.

Investigations must follow organizational access controls, evidence-preservation requirements, and incident-response procedures.

Do not execute unauthorized remote commands, introduce persistence, or perform disruptive WMI operations on production systems. Do not disable legitimate Windows management services without an approved operational decision.
