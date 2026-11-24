---
id: "persistence-removal-response"
name: "Persistence Removal Response"
category: "response"
status: "active"
version: "1.0.1"
author: "Secwexen"
created_at: "2026-11-18T10:17:00Z"
updated_at: "2026-11-24T11:50:00Z"
description: "Persistence Removal Response provides a structured process for investigating unauthorized persistence, identifying associated access paths, containing affected assets, removing malicious persistence mechanisms, and validating that unauthorized access cannot continue."
objective: "Identify, investigate, contain, and remove unauthorized persistence mechanisms, determine the scope of affected systems and identities, remediate the conditions that enabled persistence, and verify that access has not been re-established."
severity: "high"
mitre_attack:
  - "T1547"
  - "T1053"
  - "T1543"
  - "T1546"
  - "T1098"
  - "T1136"
  - "T1574"
  - "T1037"
triggers:
  - "EDR or SIEM detection of an unauthorized startup entry, scheduled task, service, agent, daemon, or event subscription"
  - "Unexpected creation or modification of an account, group membership, credential, SSH key, token, or remote-access configuration"
  - "Suspicious changes to boot, logon, service, application, or system execution configuration"
  - "A persistence mechanism is identified during malware analysis, threat hunting, or incident investigation"
  - "Previously removed malicious activity or access reappears after restart, logon, or remediation"
  - "Unauthorized code or configuration is identified in a server, application, browser extension, cloud workload, or identity platform"
prerequisites:
  - "Access to endpoint, server, identity, and relevant cloud audit telemetry"
  - "Access to process, file, configuration-change, authentication, and network telemetry"
  - "Asset inventory and approved system or application configuration baselines"
  - "Authorized endpoint, identity, and infrastructure administration capabilities"
  - "Established evidence preservation, containment, change-control, and recovery procedures"
tags:
  - "persistence"
  - "persistence-removal"
  - "incident-response"
  - "eradication"
  - "endpoint"
  - "identity"
  - "containment"
  - "recovery"
references:
  - "https://attack.mitre.org/techniques/T1547/"
  - "https://attack.mitre.org/techniques/T1053/"
  - "https://attack.mitre.org/techniques/T1543/"
  - "https://attack.mitre.org/techniques/T1546/"
  - "https://attack.mitre.org/techniques/T1098/"
  - "https://attack.mitre.org/techniques/T1136/"
  - "https://attack.mitre.org/techniques/T1574/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify Persistence Alert"
    action: "investigate"
    description: "Identify the detection source, affected resource, suspected persistence type, detection timestamp, severity, and original alert context."
    expected_result: "The suspected persistence event and affected resource are identified."
  - id: "identify-mechanism"
    order: 2
    name: "Identify Persistence Mechanism"
    action: "analyze"
    description: "Identify the persistence object, mechanism type, name, location, referenced executable or script, trigger, execution account, privileges, timestamps, ownership, signature, and available hashes."
    expected_result: "The suspected persistence mechanism and its execution configuration are identified and documented."
  - id: "review-execution"
    order: 3
    name: "Review Persistence Execution Activity"
    action: "analyze"
    description: "Review service, task, startup, logon, event, and process activity. Correlate execution timestamps, command lines, parent-child relationships, execution accounts, and related configuration changes."
    expected_result: "The persistence mechanism's execution history and associated activity are established."
  - id: "investigate-origin-and-access"
    order: 4
    name: "Investigate Persistence Origin and Related Access"
    action: "investigate"
    description: "Identify the account or process responsible for creating or modifying the mechanism. Review authentication, administrative sessions, remote access, deployment activity, exploitation evidence, and alternative access paths."
    expected_result: "The likely persistence creation path, initial access method, and associated access mechanisms are identified."
  - id: "assess-scope"
    order: 5
    name: "Assess Environmental Scope"
    action: "investigate"
    description: "Search endpoints, servers, identity platforms, cloud environments, and applications for matching persistence objects, payloads, unauthorized accounts, credentials, permissions, and related activity."
    expected_result: "Affected systems, identities, applications, and additional persistence mechanisms are identified."
  - id: "contain-affected-assets"
    order: 6
    name: "Contain Affected Assets"
    action: "contain"
    description: "Preserve forensic evidence and apply approved containment to affected systems, accounts, credentials, sessions, and network access paths. Isolate affected assets or restrict access where authorized."
    expected_result: "Affected assets and access paths are contained and relevant evidence is preserved."
  - id: "remove-and-recover"
    order: 7
    name: "Remove Persistence and Recover"
    action: "respond"
    description: "Remove confirmed malicious persistence mechanisms, associated payloads, unauthorized accounts, and secondary access paths. Remediate exploited weaknesses, rotate exposed credentials, and restore affected systems from trusted configurations or sources."
    expected_result: "Malicious persistence is removed, enabling weaknesses are addressed, and affected systems are restored."
  - id: "determine-outcome"
    order: 8
    name: "Determine Response Outcome"
    action: "document"
    description: "Determine whether malicious persistence was successfully removed, classify the incident, document response actions, and record residual risks and follow-up requirements."
    expected_result: "Persistence removal is validated and the incident receives a documented response outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "Controlled persistence-removal exercise using approved benign test entries, test identities, endpoint and identity telemetry, configuration-change records, evidence preservation, containment, and recovery procedures in isolated test systems."
---

# Persistence Removal Response

## Purpose

This playbook provides a structured response workflow for suspected or confirmed unauthorized persistence across endpoints, servers, identity platforms, cloud environments, and applications.

Persistence allows an unauthorized actor to maintain access to organizational resources through startup entries, scheduled execution, services, accounts, credentials, and other execution or authentication mechanisms.

The objective is to identify malicious persistence, determine how it was introduced, establish the scope of affected resources, remove unauthorized access mechanisms, and verify that persistence cannot be re-established.

## MITRE ATT&CK

| Technique | Name                                 | Relevance                                                                                                  |
| --------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| T1547     | Boot or Logon Autostart Execution    | Relevant when unauthorized entries cause code to execute during system startup or user logon               |
| T1053     | Scheduled Task/Job                   | Relevant when scheduled tasks, cron jobs, timers, or similar mechanisms provide recurring execution        |
| T1543     | Create or Modify System Process      | Relevant when unauthorized services, daemons, or agents are created or modified                            |
| T1546     | Event Triggered Execution            | Relevant when system or application events trigger unauthorized execution                                  |
| T1098     | Account Manipulation                 | Relevant when existing accounts, credentials, keys, permissions, or roles are modified to preserve access  |
| T1136     | Create Account                       | Relevant when unauthorized local, domain, or cloud accounts are created to maintain access                 |
| T1574     | Hijack Execution Flow                | Relevant when execution paths, libraries, or service configurations are modified to load unauthorized code |
| T1037     | Boot or Logon Initialization Scripts | Relevant when unauthorized scripts are executed during boot or logon                                       |

## Trigger Conditions

Initiate this playbook when:

- EDR or SIEM detects an unauthorized startup entry, scheduled task, service, daemon, or agent.
- An unexpected account, group membership, credential, SSH key, token, or permission change is identified.
- Suspicious boot, logon, service, or application execution configuration is detected.
- Threat hunting or malware analysis identifies a persistence mechanism.
- Previously removed malicious activity reappears after restart, logon, or remediation.
- Unauthorized code or configuration is identified in a server, application, browser extension, or cloud workload.
- Suspicious event subscriptions or execution-flow modifications are detected.

## Scope

The investigation should consider:

- affected host, server, or cloud resource;
- affected user or service account;
- account type and privilege level;
- persistence mechanism type;
- persistence object name and location;
- referenced executable, script, or payload;
- file hash and digital signature;
- startup, logon, service, or scheduled execution trigger;
- creation and modification timestamps;
- object owner and creating process;
- execution account and privilege context;
- process creation and process lineage;
- service, task, timer, and event execution history;
- registry and configuration changes;
- authentication and administrative activity;
- remote-access and network activity;
- unauthorized accounts, credentials, keys, and tokens;
- related persistence mechanisms;
- initial access method and exploited weakness;
- affected systems, applications, and identities;
- evidence preservation and containment status;
- removal, recovery, and validation status.

## Investigation Procedure

### Step 1 - Identify Persistence Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host or resource;
- affected account;
- suspected persistence type;
- detection reason;
- original alert context.

Preserve the original alert, relevant logs, and associated telemetry before modifying the affected system or configuration.

### Step 2 - Identify Persistence Mechanism

Identify the unauthorized or suspicious persistence object.

Review:

- Windows services and scheduled tasks;
- registry autorun entries and startup folders;
- WMI event subscriptions;
- Linux systemd services and timers;
- cron jobs and initialization scripts;
- macOS LaunchAgents and LaunchDaemons;
- unauthorized accounts and group memberships;
- SSH authorized keys and authentication configurations;
- application plugins and browser extensions;
- cloud accounts, tokens, permissions, and role assignments.

Collect:

- object name and type;
- file path and referenced command;
- executable, script, or payload;
- execution trigger;
- execution account;
- privilege level;
- creation and modification timestamps;
- file hash and digital signature;
- object owner and configuration details.

Compare the identified object against approved software and known-good configuration baselines.

### Step 3 - Review Persistence Execution Activity

Determine whether the persistence mechanism executed or was activated.

Review:

- service start and stop events;
- scheduled task and cron execution history;
- system startup and user logon events;
- systemd timer and service activity;
- WMI and event-triggered execution;
- process creation events;
- command-line arguments;
- parent-child process relationships;
- execution account and privilege context;
- related file and configuration changes;
- endpoint security detections.

Correlate execution activity with persistence creation and modification timestamps. Determine whether additional processes or malicious payloads were launched.

### Step 4 - Investigate Persistence Origin and Related Access

Determine how the persistence mechanism was introduced.

Review:

- account or process responsible for creation;
- administrative and privileged sessions;
- authentication events preceding modification;
- remote-access activity;
- software deployment and configuration changes;
- PowerShell, shell, and scripting activity;
- suspicious downloads and file transfers;
- network communication;
- credential and permission modifications;
- exploitation and vulnerability evidence;
- associated malware and unauthorized code.

Identify the likely initial access method and determine whether the same access path could recreate persistence after removal.

### Step 5 - Assess Environmental Scope

Search the environment for:

- matching file hashes;
- suspicious filenames and file paths;
- identical commands and scripts;
- unauthorized startup entries;
- suspicious services and scheduled tasks;
- related event subscriptions;
- unauthorized accounts and group memberships;
- suspicious SSH keys and authentication methods;
- unauthorized tokens and application permissions;
- similar process execution patterns;
- related network indicators;
- evidence of lateral movement.

Determine:

- number of affected hosts;
- number of affected accounts;
- affected applications and services;
- affected cloud resources;
- earliest suspicious activity;
- latest suspicious activity;
- presence of multiple persistence mechanisms;
- whether unauthorized access is ongoing.

Document systems and identities that could not be examined.

### Step 6 - Contain Affected Assets

Based on incident severity and organizational procedures, consider:

- preserving forensic evidence;
- capturing volatile data when required;
- isolating affected endpoints and servers;
- restricting compromised accounts;
- revoking active sessions and exposed tokens;
- rotating compromised credentials and SSH keys;
- removing unauthorized authentication methods;
- blocking confirmed malicious network indicators;
- restricting suspicious remote-access activity;
- preventing lateral movement;
- coordinating containment with system and identity administrators.

Preserve the persistence configuration and associated evidence before disabling or removing the mechanism, unless immediate containment is required to prevent ongoing material impact.

### Step 7 - Remove Persistence and Recover

Determine and remove confirmed malicious persistence mechanisms.

Review for:

- unauthorized startup entries;
- malicious scheduled tasks and timers;
- unauthorized services and daemons;
- malicious scripts and event subscriptions;
- modified registry and execution configurations;
- malicious application components and plugins;
- unauthorized accounts and group memberships;
- compromised SSH keys, credentials, and tokens;
- unauthorized application permissions and role assignments;
- secondary persistence and remote-access mechanisms;
- exploited vulnerabilities and insecure configurations.

Restore affected systems using approved configurations and trusted sources. Rebuild or reimage systems when integrity cannot be established, particularly when boot, kernel, or firmware-level compromise is suspected.

### Step 8 - Determine Response Outcome

Classify the incident as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification, affected resources, containment and removal actions, recovery status, validation results, residual risks, and follow-up requirements.

## Evidence to Collect

| Evidence           | Description                                                                        |
| ------------------ | ---------------------------------------------------------------------------------- |
| Alert              | Detection source, alert ID, severity, timestamp                                    |
| Persistence Object | Mechanism type, object name, location, configuration                               |
| File               | Hash, signature, file path, timestamps, ownership                                  |
| Execution          | Trigger, command, execution account, privilege level                               |
| Process            | Process creation, command line, parent-child relationship                          |
| System             | Service, task, timer, startup, logon, and event records                            |
| Registry           | Autorun entries and configuration modifications                                    |
| Identity           | Account changes, group membership, credentials, keys, tokens, permissions          |
| Authentication     | Successful and failed logins, administrative sessions                              |
| Network            | DNS, HTTP/HTTPS, proxy, firewall, and remote-access activity                       |
| Origin             | Creating process, responsible account, deployment source, initial access evidence  |
| Scope              | Affected hosts, applications, cloud resources, and identities                      |
| Response           | Evidence preservation, containment, removal, recovery, and approvals               |
| Timeline           | Creation, modification, execution, detection, containment, and recovery timestamps |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the persistence mechanism belongs to an authorized operating system, application, or management component;
- the creating account or process is authorized;
- the configuration change is supported by approved administrative or deployment records;
- execution behavior matches the documented operational purpose;
- no related unauthorized access or suspicious activity is identified.

Document the operational justification and supporting evidence before closing the alert. Do not remove legitimate system or application components as a precaution.

### Suspicious

Classify the activity as **suspicious** when:

- the persistence mechanism is unexpected;
- ownership or operational purpose cannot be established;
- the creating account or process is unknown;
- configuration differs from the approved baseline;
- related authentication, process, or network activity is abnormal;
- additional affected systems cannot yet be ruled out.

Continue investigation, preserve evidence, and assess the need for containment according to confidence and potential impact.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- an unauthorized persistence mechanism was created or modified;
- a mechanism executed malicious code or enabled unauthorized access;
- unauthorized accounts, credentials, keys, tokens, or permissions were created or modified;
- persistence is associated with malware, exploitation, or lateral movement;
- multiple unauthorized persistence mechanisms are identified;
- persistence reappears after attempted removal.

Escalate to the appropriate incident-response workflow and complete containment, removal, recovery, and validation procedures.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the mechanism is authorized or malicious.

Document:

- evidence collected;
- evidence unavailable;
- telemetry and retention limitations;
- affected systems that could not be examined;
- additional analysis or access required;
- pending containment and remediation actions.

## Escalation

Escalate the investigation when:

- unauthorized persistence is confirmed;
- privileged or domain-level identities are affected;
- multiple hosts or applications are involved;
- persistence is associated with malware or exploitation;
- lateral movement or command-and-control activity is identified;
- boot, kernel, or firmware-level compromise is suspected;
- security controls or logging have been disabled;
- persistence reappears after removal;
- the initial access path remains unresolved;
- system integrity cannot be established.

## Response Guidance

For confirmed malicious persistence:

1. Preserve relevant endpoint, identity, application, and network telemetry.
2. Identify the persistence mechanism and its execution context.
3. Determine the account or process responsible for creating the mechanism.
4. Search for alternative persistence mechanisms and related access paths.
5. Determine the affected hosts, identities, applications, and cloud resources.
6. Apply approved containment procedures.
7. Revoke compromised credentials, sessions, keys, and tokens where necessary.
8. Remove confirmed malicious persistence and associated payloads.
9. Remediate the initial access path and exploited weaknesses.
10. Rebuild affected systems when system integrity cannot be established.
11. Validate removal after relevant restart, logon, service, task, and event triggers.
12. Monitor for recurrence and document the final response outcome.

Do not remove persistence artifacts or modify affected systems before required evidence preservation and authorization have been considered, except where immediate containment is necessary to prevent ongoing material impact.

## Related Playbooks

- `playbooks/persistence/registry-run-keys.md`
- `playbooks/persistence/scheduled-task-persistence.md`
- `playbooks/persistence/service-persistence.md`
- `playbooks/persistence/startup-folder.md`
- `playbooks/persistence/wmi-event-subscription.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/credential-access/credential-dumping.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/credential-compromise-response.md`

## Validation

The playbook should be validated against approved persistence-removal scenarios using benign test entries, test identities, endpoint and identity telemetry, configuration-change records, and documented containment and recovery procedures.

Validation should confirm that:

- unauthorized persistence can be identified;
- legitimate system components can be distinguished from unauthorized objects;
- persistence creation and execution activity can be reconstructed;
- the responsible account or process can be investigated;
- related access paths and affected systems can be identified;
- forensic evidence can be preserved before removal;
- containment and removal actions can be documented;
- initial access weaknesses can be remediated;
- system integrity and recovery status can be verified;
- persistence recurrence can be detected after restart or logon.

## Safety

This playbook is intended for defensive security operations, incident response, controlled laboratory environments, and authorized testing only.

Use approved test entries and test identities for validation. Perform configuration changes, credential revocation, containment, and system recovery only through authorized procedures. Do not indiscriminately delete system services, startup entries, accounts, or application components; validate ownership and operational dependencies before removal.

Preserve required evidence and coordinate disruptive actions with system owners and incident-response personnel.
