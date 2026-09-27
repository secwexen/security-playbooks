---
id: "isolate-host-response"
name: "Host Isolation Response"
category: "response"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-27T16:40:00Z"
updated_at: "2026-09-27T16:40:00Z"
description: "Host Isolation Response provides a structured process for identifying affected systems, assessing active threats, applying authorized network isolation, preserving evidence, and validating containment."
objective: "Identify, contain, and validate isolation of affected hosts while preserving required evidence and minimizing operational impact."
severity: "high"
mitre_attack:
  - "T1078"
  - "T1021"
triggers:
  - "Confirmed or suspected malware activity requiring containment"
  - "Active command-and-control communication"
  - "Confirmed or suspected unauthorized remote access"
  - "Credential compromise associated with an affected endpoint"
  - "Lateral movement originating from or targeting an affected host"
  - "Endpoint detection indicating an active threat"
  - "Incident response requires immediate host containment"
prerequisites:
  - "Access to endpoint detection and response telemetry"
  - "Authorized host-isolation or network-containment capability"
  - "Access to endpoint, authentication, and network telemetry"
  - "Established incident-response and containment procedures"
  - "Authorized personnel available to perform containment actions"
tags:
  - "host-isolation"
  - "containment"
  - "incident-response"
  - "endpoint"
  - "network"
  - "malware"
  - "lateral-movement"
  - "response"
references:
  - "https://attack.mitre.org/techniques/T1078/"
  - "https://attack.mitre.org/techniques/T1021/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify Isolation Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, associated account, active threat indicators, timestamp, and initial containment context."
    expected_result: "The affected host and isolation requirement are identified."
  - id: "validate-affected-host"
    order: 2
    name: "Validate Affected Host"
    action: "analyze"
    description: "Confirm the host identity, network address, operating status, ownership, business role, and current security state before containment."
    expected_result: "The correct host is validated and its operational context is documented."
  - id: "assess-active-threat"
    order: 3
    name: "Assess Active Threat"
    action: "analyze"
    description: "Review process, authentication, file, and network telemetry to determine whether active malicious or unauthorized activity is present."
    expected_result: "The current threat state and urgency of containment are assessed."
  - id: "determine-containment-scope"
    order: 4
    name: "Determine Containment Scope"
    action: "hunt"
    description: "Identify additional hosts, accounts, services, or network paths that may require coordinated containment."
    expected_result: "The required host and related containment scope are documented."
  - id: "prepare-isolation"
    order: 5
    name: "Prepare Isolation"
    action: "contain"
    description: "Preserve required evidence, confirm authorization, identify expected operational impact, and prepare the approved host-isolation action."
    expected_result: "Isolation can be applied through an authorized and documented containment procedure."
  - id: "isolate-affected-host"
    order: 6
    name: "Isolate Affected Host"
    action: "contain"
    description: "Apply the organization's approved isolation control to restrict unauthorized network communication while preserving required endpoint access for investigation or management where supported."
    expected_result: "The affected host is isolated according to the approved containment procedure."
  - id: "validate-containment"
    order: 7
    name: "Validate Containment"
    action: "analyze"
    description: "Verify that unauthorized network communication has been restricted and confirm that required management, security, and investigative connectivity remains available where applicable."
    expected_result: "Host isolation is confirmed and containment effectiveness is documented."
  - id: "determine-outcome"
    order: 8
    name: "Determine Response Outcome"
    action: "document"
    description: "Classify the response outcome, document containment actions and evidence, and record remaining risks or required follow-up actions."
    expected_result: "The host-isolation response receives a documented outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "Controlled host-isolation exercise using approved endpoint telemetry, network controls, and documented containment procedures."
---

# Host Isolation Response

## Purpose

This playbook provides a structured response workflow for isolating endpoints or servers that may be involved in active malicious or unauthorized activity.

Host isolation is a containment action intended to restrict unauthorized network communication while preserving the ability to investigate, manage, and remediate the affected system where organizational controls support this capability.

The objective is to identify the correct affected host, assess the current threat, determine the required containment scope, apply authorized isolation, preserve evidence, and verify that containment is effective.

## MITRE ATT&CK

Host isolation is a defensive response action and is not itself an adversary technique in MITRE ATT&CK.

The following ATT&CK techniques represent adversary behaviors that may be associated with incidents requiring host isolation:

| Technique | Name                     | Relevance                                                                                                                        |
| --------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| T1078     | Valid Accounts           | Relevant when compromised or otherwise unauthorized credentials are used to access the affected host or organizational resources |
| T1021     | Remote Services          | Relevant when remote services are used for unauthorized access or lateral movement involving the affected host                   |

Additional ATT&CK techniques should only be mapped when supported by the observed incident behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Confirmed or suspected malware activity requires immediate containment.
- Active command-and-control communication is identified.
- Unauthorized remote access is confirmed or strongly suspected.
- Credential compromise is associated with an affected endpoint.
- Lateral movement is originating from or targeting the affected host.
- Endpoint telemetry indicates an active threat requiring containment.
- Incident-response procedures require host isolation.

## Scope

The response should consider:

- affected host;
- hostname;
- IP address;
- endpoint identifier;
- operating system;
- associated user or service account;
- business role;
- network segment;
- active processes;
- active network connections;
- authentication activity;
- security alerts;
- malware or suspicious artifacts;
- command-and-control activity;
- lateral movement indicators;
- dependent services;
- management connectivity;
- containment status;
- related hosts;
- related accounts;
- operational impact.

## Investigation Procedure

### Step 1 — Identify Isolation Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- endpoint identifier;
- associated user or service account;
- source and destination network context;
- active threat indicator;
- detection severity;
- detection reason.

Preserve the original alert context before containment actions are performed.

### Step 2 — Validate Affected Host

Confirm:

- hostname;
- endpoint identifier;
- IP address;
- operating system;
- host owner;
- business or technical role;
- current endpoint status;
- current user or service account;
- management status;
- critical business dependencies where known.

Verify that the containment action will be applied to the intended system.

### Step 3 — Assess Active Threat

Review available:

- process telemetry;
- process tree;
- command-line activity;
- endpoint security alerts;
- file activity;
- authentication events;
- network connections;
- DNS activity;
- remote-access activity;
- malware or suspicious-artifact indicators.

Determine whether the host is:

- actively communicating with suspicious infrastructure;
- executing suspicious or malicious processes;
- involved in unauthorized remote access;
- participating in lateral movement;
- associated with credential misuse;
- otherwise subject to an active security threat.

Prioritize immediate containment when ongoing malicious activity may cause additional material impact.

### Step 4 — Determine Containment Scope

Search the environment for:

- related hosts;
- related user or service accounts;
- shared network destinations;
- common malware or file indicators;
- related authentication events;
- lateral-movement activity;
- related alerts.

Determine:

- whether isolation is required for a single host or multiple hosts;
- whether associated accounts require additional containment;
- whether network or identity controls must be coordinated;
- whether critical services may be affected.

Containment scope should be based on available evidence and approved incident-response procedures.

### Step 5 — Prepare Isolation

Before applying isolation:

- preserve required process, file, authentication, and network evidence;
- confirm host identity;
- confirm authorization for containment;
- identify expected operational impact;
- verify that required security-management connectivity will remain available where supported;
- record the planned isolation time;
- document the containment method.

Do not apply destructive remediation as a substitute for isolation unless authorized by the incident-response procedure.

### Step 6 — Isolate Affected Host

Apply the organization's approved host-isolation control.

Depending on the available platform, isolation may restrict:

- inbound network communication;
- outbound network communication;
- peer-to-peer communication;
- unauthorized remote access;
- communication with unapproved infrastructure.

Maintain approved security-management and investigative connectivity where the organization's containment capability supports it.

Record:

- isolation timestamp;
- isolation mechanism;
- operator or automation source;
- host status before isolation;
- host status after isolation.

### Step 7 — Validate Containment

Verify:

- the host is reported as isolated;
- unauthorized network communication is restricted;
- known suspicious destinations are no longer reachable from the affected host;
- required security-management connectivity remains available where applicable;
- endpoint telemetry continues to be collected;
- containment actions are reflected in the relevant security systems.

Correlate host-isolation status with endpoint and network telemetry.

Document any containment limitations or exceptions.

### Step 8 — Determine Response Outcome

Classify the response outcome as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document:

- evidence reviewed;
- containment actions performed;
- isolation status;
- containment limitations;
- operational impact;
- remaining investigative requirements;
- required follow-up response actions.

## Evidence to Collect

| Evidence            | Description                                                   |
| ------------------- | ------------------------------------------------------------- |
| Alert               | Detection source, alert ID, severity, timestamp               |
| Host                | Hostname, endpoint identifier, IP address, operating system   |
| Account             | Associated user or service account                            |
| Threat Indicators   | Malware, process, file, network, or authentication indicators |
| Process             | Active process and execution context                          |
| Process Tree        | Parent and child process relationships                        |
| Network             | Active connections, destinations, and protocols               |
| DNS                 | Related DNS activity                                          |
| Authentication      | Related logon and authentication activity                     |
| Files               | Relevant files, hashes, and artifacts                         |
| Isolation           | Isolation mechanism, timestamp, and status                    |
| Management Access   | Security and management connectivity status                   |
| Scope               | Other affected hosts and accounts                             |
| Containment Actions | Actions performed and operator or automation source           |
| Timeline            | Detection, investigation, isolation, and validation events    |
| Detections          | Related security alerts                                       |

## Decision Criteria

### Benign

Classify the response as **benign** when:

- the containment trigger is explained by authorized activity;
- the affected host is determined to be operating normally;
- the observed security signal is attributable to approved testing or administration;
- no active unauthorized activity is identified;
- isolation is no longer required based on documented evidence.

Document the operational justification before closing the response.

### Suspicious

Classify the response as **suspicious** when:

- the host is associated with unexplained security activity;
- active threat indicators remain unconfirmed;
- suspicious process or network activity is present;
- the containment scope cannot yet be fully established;
- additional investigation is required.

Maintain appropriate containment controls while investigation continues.

### Malicious

Classify the response as **malicious** when sufficient evidence indicates:

- confirmed malicious activity on the host;
- confirmed command-and-control communication;
- confirmed unauthorized remote access;
- confirmed malware execution;
- confirmed lateral movement;
- confirmed credential misuse;
- broader compromise requiring continued incident response.

Maintain or expand containment according to the incident-response procedure.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the host is involved in malicious or unauthorized activity.

Document:

- evidence collected;
- evidence unavailable;
- containment status;
- telemetry limitations;
- additional investigation required.

## Escalation

Escalate the response when:

- active malicious activity is confirmed;
- command-and-control communication is identified;
- lateral movement is observed;
- credentials may have been exposed;
- privileged accounts are involved;
- multiple hosts require coordinated isolation;
- critical business systems are affected;
- host isolation fails or is incomplete;
- malicious activity continues after containment;
- additional incident-response capabilities are required.

## Response Guidance

For confirmed or high-confidence malicious activity requiring host isolation:

1. Preserve required endpoint, process, authentication, file, and network evidence.
2. Confirm the affected host and associated accounts.
3. Follow the organization's approved host-containment procedure.
4. Apply the authorized host-isolation control.
5. Verify that unauthorized network communication is restricted.
6. Maintain required security-management connectivity where supported.
7. Search for related hosts, accounts, indicators, and lateral-movement activity.
8. Investigate the underlying compromise and associated attack activity.
9. Coordinate credential containment or account response where exposure is suspected.
10. Continue remediation and recovery according to the applicable incident-response playbook.
11. Remove host isolation only after authorized validation confirms that containment is no longer required.
12. Document the investigation, isolation, validation, remediation, and recovery timeline.

Do not remove isolation solely to restore normal connectivity before required investigation and containment criteria have been satisfied.

## Related Detection Rules

## Related Playbooks

- `playbooks/response/malware-response.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/suspicious-login-triage.md`

## Validation

The playbook should be validated against controlled host-isolation scenarios, approved endpoint telemetry, network telemetry, endpoint management controls, and documented containment procedures.

Validation should confirm that:

- the correct host can be identified;
- host identity can be validated before containment;
- active threat indicators can be assessed;
- containment scope can be determined;
- host isolation can be applied through authorized controls;
- endpoint telemetry remains available where supported;
- unauthorized network communication is restricted;
- isolation status can be independently validated;
- operational impact can be documented;
- isolation can be safely removed only after authorized validation;
- escalation criteria produce consistent outcomes.

Validation should use isolated test systems and synthetic security events. Do not test host-isolation procedures against production systems without explicit authorization.

## Safety

This playbook is intended for defensive security operations, incident response, security validation, controlled laboratory environments, and authorized testing only.

Host-isolation actions can interrupt business services, administrative access, remote management, and network-dependent applications. Isolation should therefore be performed only by authorized personnel and according to approved incident-response and change-management procedures.

Preserve required forensic and security evidence before containment whenever operationally and safely possible. Do not remove host isolation or restore unrestricted connectivity outside approved response procedures.
