---
id: "winrm-lateral-movement"
name: "WinRM Lateral Movement"
category: "lateral-movement"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-14T17:05:00Z"
updated_at: "2026-10-14T17:05:00Z"
description: "Investigate suspicious Windows Remote Management (WinRM) activity to determine whether remote access and execution indicate unauthorized lateral movement."
objective: "Identify the source and destination systems, establish the authentication and execution context, determine the scope of suspicious WinRM activity, and support appropriate incident response decisions."
severity: "high"
mitre_attack:
  - "T1021.006"
triggers:
  - "Unexpected WinRM sessions between Windows systems"
  - "Remote PowerShell execution originating from an unusual host"
  - "WinRM activity associated with unexpected authentication events"
  - "Remote command execution involving privileged or unusual accounts"
  - "WinRM connections from systems that are not approved administrative hosts"
  - "Suspicious process creation following a remote WinRM session"
prerequisites:
  - "Access to Windows authentication and logon telemetry"
  - "Access to WinRM operational logs where available"
  - "Access to process creation and command-line telemetry"
  - "Access to network connection records"
  - "Access to asset inventory and approved remote administration records"
tags:
  - "winrm"
  - "lateral-movement"
  - "remote-services"
  - "windows"
  - "powershell"
  - "authentication"
  - "incident-response"
references:
  - "https://attack.mitre.org/techniques/T1021/006/"
  - "https://attack.mitre.org/detectionstrategies/DET0477/"
steps:
  - id: "identify-winrm-alert"
    order: 1
    name: "Identify WinRM Alert"
    action: "investigate"
    description: "Identify the detection source, alert timestamp, affected systems, associated accounts, and reason for investigating the WinRM activity."
    expected_result: "The original alert and the context that triggered the investigation are documented."
  - id: "identify-source-destination"
    order: 2
    name: "Identify Source and Destination"
    action: "investigate"
    description: "Determine the initiating host, destination host, relevant IP addresses, connection timestamps, and observed WinRM endpoints."
    expected_result: "The source and destination systems and their relationship are identified."
  - id: "review-authentication-context"
    order: 3
    name: "Review Authentication Context"
    action: "analyze"
    description: "Review the account, logon type, authentication events, source workstation, privilege context, and whether the remote access is consistent with approved administrative activity."
    expected_result: "The account identity, authentication context, and authorization status are assessed."
  - id: "review-winrm-session"
    order: 4
    name: "Review WinRM Session"
    action: "analyze"
    description: "Review available WinRM operational logs, session metadata, connection timestamps, destination endpoints, and listener configuration relevant to the observed activity."
    expected_result: "The WinRM session characteristics and relevant service activity are documented."
  - id: "review-process-execution"
    order: 5
    name: "Review Process Execution"
    action: "analyze"
    description: "Correlate the remote session with process creation events, command lines, parent-child relationships, PowerShell activity, and associated file or service changes."
    expected_result: "Processes and execution activity associated with the remote session are identified and assessed."
  - id: "correlate-related-activity"
    order: 6
    name: "Correlate Related Activity"
    action: "analyze"
    description: "Correlate WinRM activity with authentication anomalies, other remote administration protocols, suspicious process execution, persistence, credential access, and command-and-control indicators."
    expected_result: "Related activity is correlated to determine whether the WinRM session forms part of a broader attack chain."
  - id: "determine-lateral-movement-scope"
    order: 7
    name: "Determine Lateral Movement Scope"
    action: "hunt"
    description: "Search for related WinRM sessions, source and destination hosts, account usage, process patterns, and connection activity across the environment."
    expected_result: "The affected systems, accounts, time range, and potential lateral movement scope are documented."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity based on the collected evidence and document the findings, confidence, scope, and recommended next actions."
    expected_result: "The investigation has a documented outcome with evidence supporting the classification."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "winrm-lateral-movement"
---

# WinRM Lateral Movement

## Purpose

This playbook provides a structured workflow for investigating suspicious Windows Remote Management (WinRM) activity that may indicate lateral movement between Windows systems.

WinRM is a Windows remote management service and protocol used for authorized administration and remote interaction with Windows systems. It can also be abused by adversaries using valid accounts to access remote systems and execute commands in the context of the authenticated user.

The objective is to determine whether the observed activity is consistent with authorized administration, requires further investigation, or indicates unauthorized lateral movement.

A WinRM connection alone does not establish malicious activity. The investigation must consider authentication context, source and destination systems, process execution, timing, and related security events.

## MITRE ATT&CK

| Technique | Name                      | Relevance                                                                                           |
| --------- | ------------------------- | --------------------------------------------------------------------------------------------------- |
| T1021.006 | Windows Remote Management | Primary technique when WinRM is used to access a remote Windows system as part of lateral movement. |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A WinRM connection originates from an unexpected host.
- A user initiates a remote session to a system outside their normal administrative scope.
- WinRM activity is associated with suspicious or unexpected authentication events.
- A privileged account accesses a remote host without an identifiable operational justification.
- Remote PowerShell execution is followed by unusual process creation or command execution.
- WinRM activity occurs on a system that is not an approved management endpoint.
- Similar remote sessions appear across multiple systems within a short time window.
- Threat hunting identifies anomalous remote administration patterns.

## Scope

The investigation should consider:

- source hostname and IP address;
- destination hostname and IP address;
- source and destination asset roles;
- associated user account;
- account type and privilege level;
- authentication events and logon type;
- session establishment and termination timestamps;
- WinRM operational logs;
- remote management listener configuration;
- connection protocol and destination port;
- remote PowerShell activity;
- process creation events;
- process command lines;
- parent-child process relationships;
- files created or modified during the session;
- service or scheduled task modifications;
- related authentication anomalies;
- related network connections;
- other systems accessed by the same account;
- potential impact and environmental scope.

WinRM commonly uses TCP port 5985 for HTTP and TCP port 5986 for HTTPS, but environments may use different configurations. Validate the observed ports against the system's actual configuration.

## Investigation Procedure

### Step 1 — Identify WinRM Alert

Collect the original alert and establish why the activity requires investigation.

Record:

- detection source;
- alert identifier;
- detection timestamp;
- source host;
- destination host;
- associated account;
- observed connection details;
- detection severity;
- detection rationale.

Preserve the original alert context before changing system configurations or initiating containment.

Determine whether the alert originated from endpoint telemetry, authentication monitoring, network monitoring, or a threat-hunting investigation.

### Step 2 — Identify Source and Destination

Identify the systems involved in the remote session.

Collect:

- source hostname and IP address;
- destination hostname and IP address;
- destination asset role;
- source asset role;
- connection timestamp;
- destination port;
- observed protocol;
- session duration where available.

Determine whether the source is an approved administrative workstation, management server, automation host, or ordinary user endpoint.

Assess whether the destination is expected to accept remote management connections from the source.

Review asset inventory, administrative access records, and known management relationships.

An unfamiliar source-destination pair is an investigation indicator, not proof of malicious activity.

### Step 3 — Review Authentication Context

Review authentication activity associated with the WinRM session.

Collect:

- username and domain;
- account type;
- logon type;
- authentication timestamp;
- source workstation;
- available authentication package information;
- account privilege level;
- relevant successful and failed logon events.

Determine whether the account is authorized to access the destination system.

Investigate:

- privileged accounts accessing unusual destinations;
- service accounts used interactively or outside their expected scope;
- accounts authenticating from unfamiliar source hosts;
- unusual authentication timing;
- authentication events associated with other suspicious activity.

Correlate authentication events with the session timeline.

Do not classify an account as compromised solely because it has accessed a remote system through WinRM.

### Step 4 — Review WinRM Session

Review available WinRM operational telemetry and the configuration of the destination system.

Collect, where available:

- session establishment events;
- session timestamps;
- remote connection details;
- associated account;
- client and server information;
- WinRM operational events;
- listener configuration;
- configured authentication methods;
- relevant connection records.

Determine whether WinRM is expected to be enabled on the destination system.

Compare the observed activity with approved remote administration procedures and historical usage patterns.

Investigate sessions that originate from unauthorized hosts, involve unexpected accounts, or coincide with other suspicious behavior.

Do not assume that every WinRM session will generate the same event records across Windows versions and logging configurations.

### Step 5 — Review Process Execution

Correlate the WinRM session with process creation and execution activity on the destination system.

Review:

- process name and executable path;
- process identifier;
- parent process and child processes;
- command line;
- execution timestamp;
- associated account;
- file creation or modification;
- service configuration changes;
- scheduled task activity;
- PowerShell execution;
- related network connections.

Pay particular attention to process activity that occurs shortly after the remote session is established.

Investigate unexpected command execution, suspicious child processes, execution from unusual paths, and activity inconsistent with normal administrative operations.

Where available, correlate WinRM events with Windows process creation telemetry, including Sysmon Event ID 1 or Windows Security Event ID 4688.

A process event alone may not conclusively identify the remote protocol responsible for execution. Correlate it with session and authentication telemetry.

### Step 6 — Correlate Related Activity

Determine whether the WinRM session is associated with a broader attack sequence.

Search for:

- authentication anomalies involving the same account;
- additional source or destination systems;
- remote access through other management protocols;
- unexpected PowerShell execution;
- suspicious executable or script activity;
- credential access;
- persistence mechanisms;
- service or scheduled task creation;
- suspicious outbound network connections;
- command-and-control indicators;
- related security alerts.

Compare timestamps and process relationships to establish whether the events are meaningfully related.

Where multiple systems are involved, determine whether the activity represents an isolated administrative session or a sequence of remote accesses.

Document the evidence supporting each correlation. Temporal proximity alone does not establish causation.

### Step 7 — Determine Lateral Movement Scope

Assess the extent of the activity across the environment.

Search for:

- the same source host accessing other destinations;
- the same account authenticating to multiple systems;
- repeated WinRM sessions;
- similar command lines or process patterns;
- related activity involving privileged accounts;
- additional suspicious sessions within the investigation window.

Determine:

- number of affected systems;
- number of affected accounts;
- first and last observed activity;
- systems potentially accessed;
- whether unauthorized remote execution is supported by evidence;
- whether the account or source host may be compromised;
- whether the activity is ongoing.

Document confirmed findings separately from suspected or unverified activity.

If evidence indicates access beyond the initial destination, expand the investigation to the potentially affected systems and accounts.

### Step 8 — Determine Investigation Outcome

Classify the activity as one of the following:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the supporting evidence, investigation scope, unresolved questions, and recommended next actions.

## Evidence to Collect

| Evidence               | Description                                                                |
| ---------------------- | -------------------------------------------------------------------------- |
| Alert                  | Detection source, alert identifier, severity, and rationale                |
| Source Host            | Hostname, IP address, asset role, and ownership                            |
| Destination Host       | Hostname, IP address, asset role, and ownership                            |
| Account                | Username, domain, account type, and privilege level                        |
| Authentication         | Relevant logon events and authentication context                           |
| WinRM Session          | Session timestamps, connection details, and available operational events   |
| Listener Configuration | Relevant WinRM listener and authentication settings                        |
| Network                | Source, destination, port, protocol, and connection timestamps             |
| Process                | Process identifier, executable path, creation time, and associated account |
| Command Line           | Observed command line and execution context                                |
| Process Relationships  | Parent and child processes associated with remote activity                 |
| Files                  | Relevant created or modified files and available hashes                    |
| Services and Tasks     | Related service or scheduled task changes                                  |
| Related Events         | Correlated authentication, endpoint, and network detections                |
| Timeline               | Chronological record of the investigation events                           |
| Scope                  | Affected systems, accounts, and observed remote sessions                   |

## Decision Criteria

### Benign

Classify the activity as **benign** when the available evidence supports authorized remote administration.

Indicators may include:

- the source host is an approved management endpoint;
- the destination is within the account's authorized administrative scope;
- the account is expected to perform the observed activity;
- the session is consistent with documented maintenance or automation;
- the process execution matches the approved administrative task;
- authentication and network activity are consistent with historical patterns;
- no related suspicious activity is identified.

Document the operational justification before closing the investigation.

### Suspicious

Classify the activity as **suspicious** when the observed behavior deviates from the expected administrative baseline but evidence is insufficient to confirm malicious activity.

Indicators may include:

- an unexpected source-destination relationship;
- unusual remote access by a privileged or service account;
- an unfamiliar client or destination;
- unusual process execution following the session;
- suspicious command-line arguments;
- session timing inconsistent with established operations;
- related authentication anomalies;
- incomplete telemetry that prevents reliable attribution.

Continue the investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence supports unauthorized remote access or lateral movement.

Indicators may include:

- confirmed unauthorized use of an account to access a remote system;
- remote execution inconsistent with approved administrative activity and supported by corroborating evidence of compromise;
- WinRM activity linked to confirmed malicious process execution;
- unauthorized access across multiple systems;
- related credential theft, persistence, or other confirmed malicious behavior;
- remote activity attributed to a compromised account or host.

Escalate to the appropriate incident-response workflow and follow the organization's authorized containment procedures.

### Inconclusive

Classify the activity as **inconclusive** when available evidence is insufficient to determine whether the WinRM activity is legitimate or malicious.

Document:

- evidence collected;
- unavailable telemetry;
- unresolved source or destination attribution;
- authentication gaps;
- additional logging required;
- further investigation needed.

Do not classify the activity as benign solely because no additional suspicious events were found.

## Escalation

Escalate the investigation when:

- unauthorized remote access is confirmed;
- a privileged account is used unexpectedly;
- suspicious remote command execution is identified;
- multiple systems appear to be affected;
- evidence indicates credential compromise;
- the source host may be compromised;
- persistence or privilege escalation is identified;
- command-and-control activity is observed;
- the activity is ongoing or presents an immediate operational risk.

Coordinate with the incident-response team and system owners according to organizational procedures.

## Response Guidance

For confirmed malicious WinRM activity:

1. Preserve relevant authentication, WinRM, process, file, and network evidence.
2. Identify affected systems, accounts, and the timeline of remote activity.
3. Follow the organization's authorized endpoint containment procedure.
4. Assess whether the associated account requires restriction, credential reset, or additional investigation.
5. Investigate other systems accessed by the same account or source host.
6. Identify and investigate related process execution, persistence, credential access, and network activity.
7. Review WinRM exposure and access controls on affected systems.
8. Remove unauthorized changes or artifacts according to approved remediation procedures.
9. Validate the affected systems before returning them to normal operations.
10. Document containment, remediation, recovery, and lessons learned.

Do not disable WinRM indiscriminately across the environment. It may be required for legitimate administration and incident response. Changes to WinRM configuration, account permissions, or remote access controls must follow approved change and evidence-preservation procedures.

## Related Detection Rules

## Related Playbooks

- `playbooks/lateral-movement/wmi-lateral-movement.md`
- `playbooks/execution/powershell.md`
- `playbooks/execution/wmi-execution.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-login-triage.md`

## Validation

The playbook should be validated against approved Windows authentication telemetry, WinRM operational logs, process creation records, network connection data, and controlled laboratory scenarios.

Validation should confirm that:

- source and destination systems can be identified;
- authentication context can be correlated with WinRM sessions;
- available WinRM events can be collected and interpreted;
- remote process execution can be correlated with session activity;
- authorized administration can be distinguished from anomalous activity;
- related activity across multiple systems can be identified;
- the scope of suspicious remote access can be documented;
- investigation outcomes and escalation criteria produce consistent results.

Record the validation outcome and update the metadata when validation is completed.

## Safety

This playbook is intended for defensive security operations, incident investigation, controlled laboratory environments, and authorized security testing.

Use approved telemetry and access records to investigate remote management activity. Do not initiate unauthorized remote sessions, execute unapproved commands on production systems, or modify WinRM configuration before evidence preservation and appropriate authorization have been considered.
