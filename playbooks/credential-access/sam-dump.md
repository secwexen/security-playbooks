---
id: "sam-dump"
name: "SAM Credential Access"
category: "credential-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-16T16:03:00Z"
updated_at: "2026-09-16T16:03:00Z"
description: "SAM credential access involves attempts to obtain local account authentication material from the Windows Security Account Manager database."
objective: "Identify, investigate, and validate suspicious access to the Security Account Manager and determine whether local account credentials may have been exposed."
severity: "critical"
mitre_attack:
  - "T1003.002"
triggers:
  - "Suspicious SAM access alert"
  - "Unexpected access to the Security Account Manager"
  - "Unexpected access to SAM-related registry data"
  - "Credential access activity involving local account stores"
  - "SAM access associated with privilege escalation or lateral movement"
  - "Threat hunting identifies anomalous SAM access"
prerequisites:
  - "Access to registry telemetry where available"
  - "Access to process creation telemetry"
  - "Access to endpoint security telemetry"
  - "Access to authentication telemetry"
tags:
  - "sam"
  - "credential-access"
  - "credential-dumping"
  - "windows"
  - "local-accounts"
  - "authentication"
  - "endpoint"
  - "detection"
references:
  - "https://attack.mitre.org/techniques/T1003/002/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify SAM Access Alert"
  action: "investigate"
  description: "Identify the detection source, affected host, account, initiating process, timestamp, and alert context."
  expected_result: "The suspicious SAM access event and affected asset are identified."
- id: "identify-access-target"
  order: 2
  name: "Identify SAM Access Target"
  action: "analyze"
  description: "Determine which SAM-related registry data, file, or supporting resource was accessed."
  expected_result: "The SAM access target and context are documented."
- id: "review-process-context"
  order: 3
  name: "Review Process Context"
  action: "analyze"
  description: "Review the initiating process, parent process, command line, account context, integrity level, privileges, and execution timeline."
  expected_result: "The process execution context is assessed."
- id: "review-registry-activity"
  order: 4
  name: "Review Registry Activity"
  action: "analyze"
  description: "Review available registry access events and correlate SAM-related activity with the initiating process and account."
  expected_result: "Relevant SAM-related registry activity is documented."
- id: "assess-account-impact"
  order: 5
  name: "Assess Potential Account Exposure"
  action: "analyze"
  description: "Identify local accounts that may have been exposed and determine their privilege, usage, and potential security impact."
  expected_result: "Potentially affected local accounts and their risk are documented."
- id: "review-follow-on-activity"
  order: 6
  name: "Review Follow-on Activity"
  action: "analyze"
  description: "Correlate SAM access with authentication events, privilege escalation, lateral movement, persistence, and suspicious network activity."
  expected_result: "Post-access activity and possible credential misuse are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine SAM Access Scope"
  action: "hunt"
  description: "Search for related processes, accounts, hosts, hashes, command lines, and SAM access indicators across the environment."
  expected_result: "The prevalence and scope of the SAM access activity are determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the SAM access activity and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "sam-dump"
---

# SAM Credential Access

## Purpose

This playbook provides a structured workflow for investigating suspicious access to the Windows Security Account Manager (SAM).

SAM is a Windows security component associated with local user account information. Unauthorized access to SAM-related data can expose authentication material and may contribute to subsequent account compromise, privilege escalation, or lateral movement.

The objective is to determine whether the observed activity is legitimate, suspicious, or malicious and whether local account credentials may have been targeted or exposed.

## MITRE ATT&CK

| Technique | Name                                            | Relevance                                                               |
| --------- | ----------------------------------------------- | ----------------------------------------------------------------------- |
| T1003.002 | OS Credential Dumping: Security Account Manager | Relevant when local account credential material is targeted through SAM |

MITRE ATT&CK identifies SAM credential dumping as sub-technique T1003.002.

Additional ATT&CK techniques should only be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A SAM credential-access detection is generated.
- An unexpected process accesses SAM-related data.
- SAM-related registry access occurs outside an approved administrative or security workflow.
- Credential access activity is observed on a Windows endpoint.
- SAM access is associated with suspicious privilege escalation.
- SAM access is followed by anomalous local authentication activity.
- Threat hunting identifies suspicious SAM access behavior.

## Scope

The investigation should consider:

- affected host;
- initiating account;
- potentially affected local accounts;
- initiating process;
- process path;
- parent process;
- child processes;
- command line;
- process integrity level;
- process privileges;
- SAM-related registry activity;
- file activity;
- authentication events;
- privilege escalation;
- lateral movement;
- persistence;
- network activity;
- related detections;
- other affected hosts.

## SAM Context

SAM-related information is associated with local Windows account authentication.

Commonly referenced registry locations include:

```text
HKLM\SAM
```

Access to this area should be investigated in context. Administrative, security, backup, or operating-system activity may legitimately interact with protected system resources.

Do not treat the presence of SAM access alone as conclusive evidence of malicious activity.

## Investigation Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- initiating account;
- initiating process;
- target resource;
- detection severity;
- detection reason.

Preserve the original alert context before taking remediation actions.

### Step 2 — Identify SAM Access Target

Determine which SAM-related resource was accessed.

Review available evidence for:

- protected registry access;
- SAM-related file access;
- suspicious supporting artifacts;
- access occurring during an unusual process chain.

Document the target and context without attempting to reproduce credential extraction.

### Step 3 — Review Process Context

Review:

- process name;
- executable path;
- file hash;
- digital signature;
- parent process;
- child processes;
- command line;
- user context;
- integrity level;
- available privileges;
- execution timestamp.

Determine whether the process belongs to approved security, administration, backup, recovery, or endpoint-management software.

### Step 4 — Review Registry Activity

Review available registry telemetry associated with SAM.

Determine:

- initiating process;
- initiating account;
- access time;
- related registry activity;
- nearby process events;
- relevant security detections.

Correlate SAM-related registry activity with the process execution timeline.

### Step 5 — Assess Potential Account Exposure

Identify local accounts that may have been exposed.

Consider:

- local administrators;
- privileged local accounts;
- service accounts;
- dormant accounts;
- accounts associated with subsequent suspicious activity.

Determine whether potentially exposed credentials could be reused on other systems.

### Step 6 — Review Follow-on Activity

Correlate the SAM access event with:

- successful and failed authentication;
- local logons;
- remote logons;
- privilege escalation;
- lateral movement;
- persistence;
- suspicious network connections;
- additional credential-access events.

Pay particular attention to activity occurring shortly after the suspected SAM access.

### Step 7 — Determine SAM Access Scope

Search the environment for:

- same initiating process;
- same executable hash;
- same command line;
- same account;
- same host;
- similar SAM access events;
- related authentication activity.

Determine:

- number of affected hosts;
- number of affected accounts;
- first observed activity;
- latest observed activity;
- whether suspicious activity is ongoing.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence         | Description                                             |
| ---------------- | ------------------------------------------------------- |
| Alert            | Detection source, ID, severity, timestamp               |
| Host             | Hostname, IP address, operating system                  |
| Account          | Initiating and potentially affected local accounts      |
| Process          | Process name, path, hash                                |
| Parent Process   | Process responsible for launching the activity          |
| Child Processes  | Processes created around the SAM access                 |
| Command Line     | Available command-line information                      |
| SAM Target       | SAM-related registry or file resource                   |
| Registry Access  | Relevant registry telemetry                             |
| Privileges       | Integrity level and privilege context                   |
| Authentication   | Related logon and authentication events                 |
| Lateral Movement | Related remote access activity                          |
| Persistence      | Related persistence indicators                          |
| Network          | Related network connections                             |
| Timeline         | Correlated process, registry, and authentication events |
| Scope            | Other affected hosts and accounts                       |
| Detections       | Related security alerts                                 |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the accessing process is approved security or administrative software;
- the account and host context are authorized;
- the operation is expected;
- the activity matches documented system or management behavior;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- an unexpected process accesses SAM-related data;
- the account context is unusual;
- the process path or signer is unexpected;
- registry activity occurs outside an established workflow;
- related authentication or network activity is anomalous;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized access to SAM credential material;
- confirmed credential-collection behavior;
- SAM access associated with malware;
- subsequent use of potentially compromised local credentials;
- lateral movement involving affected accounts;
- persistence or privilege escalation linked to the activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the SAM access was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- local credential exposure is confirmed;
- privileged local accounts may have been exposed;
- service-account credentials may have been exposed;
- suspicious authentication follows the SAM access;
- lateral movement is identified;
- multiple hosts or accounts are affected;
- the accessing process is associated with confirmed malware.

## Response Guidance

For confirmed malicious SAM credential access:

1. Preserve process, registry, authentication, and network evidence.
2. Identify potentially affected hosts and local accounts.
3. Follow the organization's credential-compromise response procedure.
4. Review and contain potentially compromised accounts according to policy.
5. Investigate authentication activity for evidence of credential reuse.
6. Search for lateral movement and additional persistence.
7. Follow authorized endpoint containment procedures.
8. Review possible exposure of privileged local credentials.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Credential resets, session invalidation, and account containment should follow approved organizational response procedures.

Do not extract, disclose, or reproduce real credentials during investigation or validation.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`

## Related Playbooks

- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/lsass-dump.md`
- `playbooks/credential-access/ntds-dump.md`
- `playbooks/credential-access/credentials-from-password-stores.md`
- `playbooks/credential-access/password-manager-credential-theft.md`
- `playbooks/credential-access/browser-credential-theft.md`
- `playbooks/credential-access/password-spraying.md`
- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/privilege-escalation/token-manipulation.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/lateral-movement-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved endpoint telemetry, registry-access events, authentication events, and controlled credential-access detection scenarios.

Validation should confirm that:

- suspicious SAM access can be identified;
- the accessing process can be determined;
- process ownership and execution context can be assessed;
- registry activity can be correlated;
- potentially affected local accounts can be identified;
- authentication activity can be correlated;
- related lateral movement can be investigated;
- legitimate administrative and security tooling can be distinguished from suspicious SAM access;
- escalation criteria produce consistent outcomes.

Validation should use controlled telemetry and synthetic scenarios rather than real credential extraction.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Do not extract, disclose, or handle real credentials during validation. Use synthetic accounts, sanitized telemetry, and isolated laboratory systems.

Credential-compromise response actions must follow approved organizational procedures and applicable access-control requirements.
