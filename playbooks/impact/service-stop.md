---
id: "service-stop"
name: "Service Stop"
category: "impact"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-30T17:03:00Z"
updated_at: "2026-09-30T17:03:00Z"
description: "Investigate suspicious service stop or disable activity that may disrupt system or application availability."
objective: "Determine whether service stop or disable activity was authorized, identify affected services and systems, assess operational impact, and determine whether the activity is associated with malicious impact or broader compromise."
severity: "high"
mitre_attack:
  - "T1489"
triggers:
  - "Unexpected service stop or disable activity"
  - "Critical security or application service becomes unavailable"
  - "Multiple services are stopped in a short time period"
  - "Service startup configuration is changed to disabled"
  - "Service stop activity occurs before data destruction or data encryption"
  - "Threat hunting identifies anomalous service termination activity"
prerequisites:
  - "Access to Windows, Linux, macOS, or applicable service-management telemetry"
  - "Access to process and command-line telemetry where available"
  - "Access to service configuration and status information"
  - "Access to asset and application criticality information"
tags:
  - "service-stop"
  - "impact"
  - "availability"
  - "service"
  - "windows"
references:
  - "https://attack.mitre.org/techniques/T1489/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Service Stop Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, service, account, timestamp, and alert context associated with the service stop or disable activity."
  expected_result: "The service stop activity and affected asset are identified."
- id: "identify-service"
  order: 2
  name: "Identify Affected Service"
  action: "analyze"
  description: "Determine which service was stopped or disabled and document its name, function, startup configuration, and business or security relevance."
  expected_result: "The affected service and its operational relevance are documented."
- id: "review-stop-activity"
  order: 3
  name: "Review Service Stop Activity"
  action: "analyze"
  description: "Review the service status change, execution time, initiating process, command line, account, and available service-management telemetry."
  expected_result: "The service stop or disable action and its execution context are characterized."
- id: "review-configuration"
  order: 4
  name: "Review Service Configuration"
  action: "analyze"
  description: "Determine whether service startup configuration, permissions, executable paths, or other service properties were changed around the time of the stop activity."
  expected_result: "Relevant service configuration changes are identified or ruled out."
- id: "review-impact"
  order: 5
  name: "Assess Availability Impact"
  action: "analyze"
  description: "Determine whether the service disruption affected security controls, business applications, data access, system functionality, or incident-response capabilities."
  expected_result: "The operational and security impact of the service disruption is assessed."
- id: "correlate-related-activity"
  order: 6
  name: "Correlate Related Activity"
  action: "hunt"
  description: "Correlate service stop activity with process execution, authentication, persistence, data destruction, data encryption, security-control changes, and other suspicious activity."
  expected_result: "Related activity is identified and the broader attack context is established."
- id: "determine-scope"
  order: 7
  name: "Determine Service Stop Scope"
  action: "hunt"
  description: "Search for the same service, account, command line, process behavior, or service configuration changes across other hosts and environments."
  expected_result: "The prevalence and scope of the service stop activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the activity and document the evidence supporting the final investigation outcome."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "service-stop"
---

# Service Stop

## Purpose

This playbook provides a structured workflow for investigating suspicious service stop or disable activity that may affect system or application availability.

Stopping or disabling services can be legitimate during maintenance, troubleshooting, deployment, or approved administrative activity. The investigation must therefore distinguish authorized service management from activity intended to disrupt availability, interfere with security controls, or support a broader attack sequence.

The objective is to determine whether the activity was authorized, identify affected services and systems, assess operational impact, and establish whether the activity is associated with malicious behavior.

### Service Stop Context

Service stop activity may be particularly significant when critical business applications, security controls, monitoring services, backup services, or other response-supporting components are affected.

A service being stopped is not, by itself, evidence of malicious activity. Investigation should consider the initiating account, process, command line, timing, service criticality, configuration changes, and related activity.

## MITRE ATT&CK

| Technique | Name         | Relevance                                                                                         |
| --------- | ------------ | ------------------------------------------------------------------------------------------------- |
| T1489     | Service Stop | Primary technique for stopping or disabling services to affect system or application availability |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A service is stopped unexpectedly.
- A critical service becomes unavailable without an approved maintenance explanation.
- Multiple services are stopped within a short period.
- A service startup configuration is changed to disabled.
- Service stop activity occurs before data destruction or data encryption.
- Security, monitoring, backup, or response-related services are unexpectedly stopped.
- Threat hunting identifies anomalous service termination activity.

## Scope

The investigation should consider:

- affected host;
- affected service;
- service state;
- startup configuration;
- service executable;
- service account;
- initiating account;
- initiating process;
- command line;
- process parent and child relationships;
- service configuration changes;
- service stop timestamp;
- related file activity;
- related authentication activity;
- security-control status;
- application availability;
- additional affected hosts;
- related security alerts.

## Investigation Procedure

### Step 1 — Identify Service Stop Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- affected service;
- associated account;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify Affected Service

Collect:

- service name;
- display name;
- service description;
- service state;
- startup type;
- service account;
- executable path;
- host role;
- application dependency;
- business or security criticality.

Determine whether the service is expected to run continuously and whether a maintenance or operational event explains the stop.

### Step 3 — Review Service Stop Activity

Review:

- stop timestamp;
- initiating account;
- initiating process;
- parent process;
- command line;
- service-management events;
- process creation events;
- remote administration activity where available.

Determine whether the activity is consistent with expected administrative operations.

Pay particular attention to:

- unusual administrative tools;
- unexpected privileged accounts;
- suspicious scripts;
- abnormal process chains;
- repeated service termination activity;
- service stops immediately following suspicious process execution.

### Step 4 — Review Service Configuration

Determine whether any service configuration changed around the time of the stop activity.

Review:

- startup type;
- executable path;
- service permissions;
- service account;
- service configuration history;
- related registry configuration where applicable.

A service being configured as disabled may indicate a broader attempt to prevent normal service operation and should be correlated with the surrounding activity.

### Step 5 — Assess Availability Impact

Determine whether the service disruption affected:

- application availability;
- security monitoring;
- endpoint protection;
- backup operations;
- authentication;
- data access;
- system functionality;
- incident-response capabilities.

Document the duration of the disruption and identify any dependent systems or applications affected by the service state change.

### Step 6 — Correlate Related Activity

Correlate service stop activity with:

- process creation;
- command-line execution;
- authentication activity;
- privilege changes;
- persistence activity;
- security-control modification;
- data destruction;
- data encryption;
- network activity;
- additional service stops;
- related alerts on other systems.

Determine whether the service stop forms part of a broader attack sequence.

### Step 7 — Determine Service Stop Scope

Search across the environment for:

- same service;
- same initiating account;
- same command line;
- same initiating process;
- same executable;
- same service configuration change;
- same timestamp pattern;
- additional affected hosts.

Determine:

- number of affected hosts;
- number of affected services;
- duration of service disruption;
- affected applications;
- whether security controls were impacted;
- whether the activity remains ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence       | Description                                           |
| -------------- | ----------------------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp             |
| Host           | Hostname, operating system, asset criticality         |
| Service        | Name, state, startup type, account                    |
| Process        | Initiating process and process metadata               |
| Command Line   | Full observed command line                            |
| Account        | Initiating account and privilege context              |
| Configuration  | Service configuration and change history              |
| Availability   | Service disruption and affected applications          |
| Authentication | Related account and authentication events             |
| Files          | Related created or modified artifacts                 |
| Network        | Related network connections                           |
| Timeline       | Service, process, authentication, and file timestamps |
| Scope          | Other affected hosts and services                     |
| Detections     | Related security alerts                               |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the service stop was authorized;
- the initiating account is expected;
- the activity corresponds to approved maintenance or administration;
- the service configuration is consistent with expected operations;
- no suspicious related activity is identified;
- the service was restored or intentionally disabled according to documented procedures.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the service stop was unexpected;
- the initiating account is unusual;
- the initiating process or command line is abnormal;
- the service is security-sensitive or operationally critical;
- multiple services are stopped without a clear explanation;
- service configuration changes are unexplained;
- related suspicious activity is present;
- available evidence is insufficient to establish malicious intent.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized service termination;
- intentional disruption of critical services;
- disabling of security or monitoring capabilities;
- service stop activity associated with data destruction;
- service stop activity associated with data encryption;
- coordinated service disruption across multiple hosts;
- confirmed malicious process or command responsible for the activity;
- service disruption forming part of a broader confirmed compromise.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the service activity was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required;
- unresolved investigation questions.

## Escalation

Escalate the investigation when:

- unauthorized service termination is confirmed;
- critical business or security services are affected;
- multiple services or hosts are impacted;
- endpoint protection, monitoring, backup, or response capabilities are disrupted;
- service stop activity precedes data destruction or encryption;
- privileged or unexpected accounts are involved;
- suspicious process or command-line activity is identified;
- broader compromise indicators are observed.

## Response Guidance

For confirmed malicious service stop activity:

1. Preserve service, process, account, configuration, and network evidence.
2. Identify all affected hosts, services, and applications.
3. Follow the organization's approved containment procedure.
4. Determine whether affected services can be safely restored.
5. Investigate related data destruction, encryption, persistence, and security-control modification.
6. Search for the same service-stop behavior across the environment.
7. Restore affected services according to approved recovery procedures.
8. Validate that security monitoring and protection capabilities are operational.
9. Review potentially exposed privileged accounts and administrative access.
10. Escalate confirmed compromise to incident response.
11. Document the investigation timeline, impact, containment, and recovery actions.

Do not restart, reconfigure, or otherwise modify affected services before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

## Related Playbooks

- `playbooks/impact/data-destruction.md`
- `playbooks/impact/ransomware.md`
- `playbooks/response/isolate-host-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/triage/suspicious-process-triage.md`

## Validation

The playbook should be validated against approved Windows, Linux, macOS, and applicable service-management telemetry, process creation data, service configuration events, and controlled laboratory scenarios.

Validation should confirm that:

- service stop activity can be identified;
- affected services and hosts can be determined;
- initiating accounts and processes can be identified;
- service configuration changes can be investigated;
- availability impact can be assessed;
- related data destruction or encryption activity can be correlated;
- environmental scope can be determined;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Service stop, disable, restart, or recovery actions should follow approved authorization, evidence-preservation, change-management, and business-continuity procedures. Do not intentionally disrupt production services or security controls outside authorized testing or incident-response procedures.
