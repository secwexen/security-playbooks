---
id: "token-manipulation"
name: "Token Manipulation"
category: "privilege-escalation"
status: "active"
version: "1.0.1"
author: "Secwexen"
created_at: "2026-09-21T14:29:00Z"
updated_at: "2026-09-26T21:46:00Z"
description: "Token Manipulation involves abusing or modifying access tokens to impersonate users, obtain additional privileges, or execute processes under another security context."
objective: "Identify, investigate, and validate suspicious access-token manipulation and determine whether token activity is legitimate, suspicious, or malicious."
severity: "high"
mitre_attack:
  - "T1134"
triggers:
  - "Suspicious access-token manipulation alert"
  - "Unexpected process executing under another security context"
  - "Unexpected impersonation or token activity"
  - "Abnormal privilege assignment associated with a process"
  - "Token-related activity involving a privileged account"
  - "Threat hunting identifies anomalous token manipulation"
prerequisites:
  - "Access to process creation telemetry"
  - "Access to account and security-token telemetry where available"
  - "Access to endpoint security telemetry"
  - "Access to authentication and privilege telemetry"
tags:
  - "token-manipulation"
  - "privilege-escalation"
  - "access-token"
  - "impersonation"
  - "windows"
  - "endpoint"
references:
  - "https://attack.mitre.org/techniques/T1134/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify Token Manipulation Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, user or account, process, timestamp, and alert context."
    expected_result: "The suspicious token-manipulation event and affected asset are identified."
  - id: "identify-token-context"
    order: 2
    name: "Identify Token Context"
    action: "analyze"
    description: "Determine the token owner, security context, token type, integrity level, privileges, and associated process where telemetry is available."
    expected_result: "The access-token context and associated security identity are documented."
  - id: "review-process-activity"
    order: 3
    name: "Review Process Activity"
    action: "analyze"
    description: "Review the affected process, parent process, child processes, command line, executable path, and execution timestamps."
    expected_result: "The process execution chain associated with the token activity is assessed."
  - id: "review-account-context"
    order: 4
    name: "Review Account Context"
    action: "analyze"
    description: "Review the token-associated account, privileges, group membership, logon session, and expected administrative context."
    expected_result: "The account and privilege context is documented and assessed."
  - id: "review-security-context"
    order: 5
    name: "Review Security Context Changes"
    action: "analyze"
    description: "Review changes in user identity, privileges, integrity level, impersonation state, or process security context associated with the activity."
    expected_result: "Unexpected security-context changes are identified or ruled out."
  - id: "review-related-activity"
    order: 6
    name: "Review Related Activity"
    action: "analyze"
    description: "Correlate token activity with authentication events, process creation, file activity, network activity, and other privilege-escalation indicators."
    expected_result: "Related activity and potential post-escalation behavior are identified or ruled out."
  - id: "determine-scope"
    order: 7
    name: "Determine Token Manipulation Scope"
    action: "hunt"
    description: "Search for the same account, process pattern, token-related behavior, privilege change, or security context across the environment."
    expected_result: "The prevalence and scope of the token-manipulation activity are determined."
  - id: "determine-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the token-manipulation activity and document the evidence supporting the final assessment."
    expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "token-manipulation"
---

# Token Manipulation

## Purpose

This playbook provides a structured workflow for investigating suspicious access-token manipulation on Windows systems.

Access tokens define the security context under which processes and threads operate. Token manipulation may be abused to impersonate another security principal, obtain additional privileges, or execute activity under an unauthorized security context.

The objective is to determine whether token-related activity is legitimate, suspicious, or malicious and whether it resulted in unauthorized privilege escalation or access.

## MITRE ATT&CK

| Technique | Name                      | Relevance                                                                                |
| --------- | ------------------------- | ---------------------------------------------------------------------------------------- |
| T1134     | Access Token Manipulation | Relevant when access tokens are manipulated or abused to obtain another security context |

Additional T1134 sub-techniques should only be mapped when supported by the observed token behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspicious access-token manipulation alert is generated.
- A process executes under an unexpected user or security context.
- Unexpected impersonation or token activity is observed.
- A process receives unexpected privileges.
- A privileged security context appears without a corresponding administrative action.
- Token-related activity is associated with suspicious process execution.
- Threat hunting identifies anomalous token-manipulation behavior.

## Scope

The investigation should consider:

- affected host;
- affected user;
- token owner;
- process;
- parent process;
- child processes;
- token type;
- impersonation state;
- integrity level;
- privileges;
- group membership;
- logon session;
- security identifier;
- process creation time;
- authentication activity;
- file activity;
- network activity;
- related alerts;
- additional affected hosts.

## Investigation Procedure

### Step 1 — Identify Token Manipulation Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- affected process;
- suspected token activity;
- detection severity;
- detection reason.

Preserve the original alert context before making remediation changes.

### Step 2 — Identify Token Context

Determine, where telemetry is available:

- token-associated account;
- security identifier;
- token type;
- primary or impersonation context;
- integrity level;
- assigned privileges;
- associated process;
- associated logon session.

Compare the observed security context with the expected context for the process and account.

### Step 3 — Review Process Activity

Review:

- process creation;
- executable path;
- command line;
- parent process;
- child processes;
- process creation timestamps;
- user context;
- process integrity level.

Pay particular attention to processes that:

- run under a different identity than expected;
- unexpectedly transition into a privileged security context;
- launch privileged child processes;
- appear immediately after suspicious authentication or execution activity.

### Step 4 — Review Account Context

Determine:

- account owner;
- account type;
- group membership;
- administrative roles;
- expected privileges;
- logon session;
- normal process activity;
- expected host and application context.

Assess whether the token-associated account and privileges are consistent with the process's intended function.

### Step 5 — Review Security Context Changes

Review available telemetry for:

- privilege changes;
- integrity-level changes;
- identity changes;
- impersonation activity;
- unexpected privileged process creation;
- unexpected security-context transitions.

Determine whether the resulting process or thread security context differs from the context expected for the original execution.

### Step 6 — Review Related Activity

Correlate the token activity with:

- authentication events;
- process creation;
- command-line activity;
- file creation or modification;
- network connections;
- credential-access indicators;
- persistence;
- lateral movement;
- other privilege-escalation activity.

Determine whether token manipulation was an isolated event or part of a broader compromise.

### Step 7 — Determine Token Manipulation Scope

Search the environment for:

- same affected account;
- same process pattern;
- same executable;
- same command line;
- same security-context transition;
- same privilege pattern;
- related authentication activity.

Determine:

- number of affected hosts;
- number of affected accounts;
- first observed activity;
- latest observed activity;
- whether the activity is still occurring.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence         | Description                                   |
| ---------------- | --------------------------------------------- |
| Alert            | Detection source, ID, severity, timestamp     |
| Host             | Hostname, IP address, operating system        |
| User             | Associated user or service account            |
| Token            | Token type, identity, security context        |
| Privileges       | Assigned or observed privileges               |
| Integrity Level  | Process or token integrity level              |
| Process          | Process metadata                              |
| Process Tree     | Parent and child processes                    |
| Command Line     | Complete process command line                 |
| Authentication   | Related authentication and logon activity     |
| Account Context  | Account type, groups, and expected privileges |
| Security Changes | Identity or privilege changes                 |
| Files            | Related created or modified files             |
| Network          | Related network connections                   |
| Timeline         | Token, process, authentication timestamps     |
| Scope            | Other affected hosts and accounts             |
| Detections       | Related security alerts                       |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the security context is authorized;
- the token-associated account is expected;
- the privileges are appropriate;
- the process relationship is legitimate;
- the observed activity matches approved administrative or application behavior;
- no suspicious follow-on activity is identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the security context is unexpected;
- the token-associated account is unclear;
- unexpected privileges are observed;
- process identity differs from the expected execution context;
- impersonation activity cannot be explained;
- related process or authentication activity is abnormal;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized token manipulation;
- unauthorized impersonation;
- confirmed privilege escalation through token abuse;
- malicious processes executing under an unauthorized security context;
- token manipulation associated with confirmed credential access;
- lateral movement or persistence following the security-context change;
- other confirmed malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the token activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- unauthorized token manipulation is confirmed;
- a privileged security context is obtained unexpectedly;
- a privileged account is involved;
- credential access is suspected;
- lateral movement is identified;
- persistence is identified;
- multiple hosts are affected;
- command-and-control activity is observed.

## Response Guidance

For confirmed malicious token-manipulation activity:

1. Preserve relevant process, token, authentication, and endpoint evidence.
2. Identify all affected hosts, accounts, and security contexts.
3. Follow the organization's endpoint containment procedure.
4. Search for related processes, accounts, privileges, and execution patterns.
5. Investigate credential access, persistence, and lateral movement.
6. Review potentially exposed privileged accounts.
7. Follow authorized containment or remediation procedures.
8. Escalate confirmed compromise to incident response.
9. Document the investigation timeline and remediation actions.

Do not terminate or modify relevant processes, accounts, tokens, or logs before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

## Related Playbooks

- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/execution/powershell.md`
- `playbooks/execution/command-shell.md`
- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/lateral-movement/pass-the-ticket.md`
- `playbooks/response/isolate-host-response.md`

## Validation

The playbook should be validated against approved token-manipulation telemetry, process creation events, authentication data, privilege-context datasets, and controlled execution scenarios.

Validation should confirm that:

- token-related activity can be identified;
- token and security-context information can be investigated;
- process relationships can be correlated;
- privilege and identity changes can be identified;
- related authentication activity can be investigated;
- environmental scope can be determined;
- legitimate administrative token activity can be distinguished from unauthorized activity;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Token and privilege activity should be investigated using approved telemetry and controlled environments. Do not perform unauthorized token manipulation, impersonation, or privilege escalation on production systems.
