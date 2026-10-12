---
id: "rdp-lateral-movement"
name: "RDP Lateral Movement"
category: "lateral-movement"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-12T11:47:00Z"
updated_at: "2026-10-12T11:47:00Z"
description: "Investigate suspicious Remote Desktop Protocol (RDP) activity that may indicate lateral movement between systems."
objective: "Determine whether RDP activity is authorized, identify affected accounts and hosts, establish the scope of potential lateral movement, and support appropriate incident response."
severity: "high"
mitre_attack:
  - "T1021.001"
triggers:
  - "Unexpected successful RDP logon to a sensitive or previously unaccessed host"
  - "RDP authentication from an unusual source host or network segment"
  - "Repeated failed RDP logons followed by a successful authentication"
  - "RDP activity involving an unexpected privileged account"
  - "RDP sessions followed by suspicious process execution or system changes"
  - "Threat hunting identifies anomalous RDP sessions between internal systems"
prerequisites:
  - "Access to Windows Security Event Logs"
  - "Access to Remote Desktop Services event logs where available"
  - "Access to endpoint process and authentication telemetry"
  - "Access to network connection logs or equivalent network telemetry"
  - "Access to asset inventory and authorized remote administration records"
tags:
  - "rdp"
  - "remote-desktop"
  - "lateral-movement"
  - "windows"
  - "authentication"
  - "privileged-access"
references:
  - "https://attack.mitre.org/techniques/T1021/001/"
  - "https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624"
  - "https://learn.microsoft.com/windows/security/threat-protection/auditing/basic-audit-logon-events"
steps:
  - id: "identify-rdp-alert"
    order: 1
    name: "Identify RDP Alert"
    action: "investigate"
    description: "Identify the detection source, alert timestamp, affected system, associated account, and reason the RDP activity was flagged."
    expected_result: "The original alert context and suspected RDP activity are documented."
  - id: "identify-source-destination"
    order: 2
    name: "Identify Source and Destination"
    action: "investigate"
    description: "Identify the initiating host, destination host, source and destination addresses, account, and relevant network context."
    expected_result: "The source, destination, account, and associated asset context are identified."
  - id: "review-authentication-activity"
    order: 3
    name: "Review Authentication Activity"
    action: "analyze"
    description: "Review successful and failed authentication events, logon types, account privileges, and authentication activity preceding the RDP session."
    expected_result: "The authentication sequence and account context are documented."
  - id: "review-rdp-session"
    order: 4
    name: "Review RDP Session Details"
    action: "analyze"
    description: "Review available Remote Desktop Services events, session timestamps, source information, session identifiers, and the expected authorization for the connection."
    expected_result: "The RDP session characteristics and authorization context are established where telemetry permits."
  - id: "review-post-logon-activity"
    order: 5
    name: "Review Post-Logon Activity"
    action: "analyze"
    description: "Investigate process execution, command lines, file activity, service changes, scheduled tasks, and other relevant events occurring after the RDP session began."
    expected_result: "Potentially suspicious activity following the RDP logon is identified and correlated."
  - id: "correlate-related-activity"
    order: 6
    name: "Correlate Related Activity"
    action: "hunt"
    description: "Correlate the RDP session with preceding authentication anomalies, possible credential compromise, network connections, and related security alerts on the source and destination systems."
    expected_result: "Related authentication, endpoint, and network activity is correlated with the RDP session."
  - id: "determine-lateral-movement-scope"
    order: 7
    name: "Determine Lateral Movement Scope"
    action: "hunt"
    description: "Search available telemetry for related RDP sessions involving the same account, source host, destination host, or associated indicators across the environment."
    expected_result: "The known scope of potentially affected hosts, accounts, and RDP sessions is documented."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the RDP activity using the collected evidence and document the rationale, scope, and required follow-up actions."
    expected_result: "The investigation outcome and supporting evidence are documented."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "rdp-lateral-movement"
---

# RDP Lateral Movement

## Purpose

This playbook provides a structured workflow for investigating suspicious Remote Desktop Protocol (RDP) activity that may indicate lateral movement within an environment.

RDP is a legitimate remote administration capability. However, an adversary with access to valid credentials may use RDP to access additional systems and perform actions under the authenticated user's security context.

The objective is to determine whether the observed RDP activity is authorized, identify potentially compromised accounts and systems, establish the scope of suspicious access, and support appropriate incident response.

## MITRE ATT&CK

| Technique | Name                    | Relevance                                                                                           |
| --------- | ----------------------- | --------------------------------------------------------------------------------------------------- |
| T1021.001 | Remote Desktop Protocol | Primary technique associated with adversary use of RDP to access remote systems and move laterally. |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An RDP session originates from an unusual or unauthorized source host.
- A user authenticates to a destination system that is inconsistent with their normal access pattern.
- Repeated failed RDP authentication attempts are followed by a successful logon.
- A privileged account establishes an unexpected RDP session.
- RDP access occurs outside the expected administrative window.
- An RDP session is followed by suspicious process execution, service changes, scheduled task creation, or other anomalous activity.
- Related alerts indicate possible credential compromise or lateral movement.
- Threat hunting identifies unusual RDP connections between internal systems.

A single successful RDP logon does not establish malicious activity. Investigate the associated account, source, destination, timing, and post-logon behavior before reaching a conclusion.

## Scope

The investigation should consider:

- Source host and IP address.
- Destination host and IP address.
- Associated user and account domain.
- Account type and privilege level.
- Authentication outcome and logon type.
- RDP session start and end times.
- Available session identifiers and logon identifiers.
- Remote Desktop Services configuration and access permissions.
- Network segment and expected administrative access paths.
- Process execution and command-line activity on the destination.
- File, service, and scheduled task activity.
- Related authentication events and security alerts.
- Additional hosts accessed by the same account.
- Other sessions associated with the same source or destination.
- Potential credential compromise or broader lateral movement.

The investigation should cover the relevant time window before, during, and after the suspected RDP session.

## Investigation Procedure

### Step 1 — Identify RDP Alert

Review the original alert and preserve its context.

Collect:

- Detection source.
- Alert identifier.
- Detection timestamp.
- Alert severity.
- Source host and IP address.
- Destination host and IP address.
- Associated username and domain.
- Detection reason.
- Available network and endpoint indicators.

Determine why the activity was flagged and identify the initial investigative scope.

Do not classify the activity as malicious solely because the connection was generated outside normal working hours or originated from an unfamiliar host.

### Step 2 — Identify Source and Destination

Establish the systems involved in the RDP connection.

Collect:

- Source hostname and IP address.
- Destination hostname and IP address.
- Asset owner and criticality.
- Operating system.
- Associated account.
- Relevant network segment.
- Destination service and port where available.
- Whether the source is an approved administrative workstation or jump host.
- Whether the destination is expected to accept RDP connections from the source.

Determine whether the connection is consistent with documented administration, support, or operational activity.

Investigate unexpected connections involving domain controllers, critical servers, privileged administration systems, or systems outside the account's normal access scope.

### Step 3 — Review Authentication Activity

Examine authentication events associated with the suspected RDP session.

On Windows systems, review available Security Event Logs, including:

- Event ID 4624: successful logon.
- Event ID 4625: failed logon.
- Event ID 4648: logon using explicit credentials.
- Event ID 4778: terminal server session reconnected.
- Event ID 4779: terminal server session disconnected.

For Event ID 4624, examine the logon type. Logon Type 10 identifies a RemoteInteractive logon associated with Terminal Services or Remote Desktop.

Collect, where available:

- Account name and domain.
- Logon type.
- Logon ID.
- Source network address.
- Workstation name.
- Authentication package.
- Authentication timestamp.
- Failure status and substatus for unsuccessful attempts.
- Related account lockouts or authentication anomalies.

Determine whether the authentication sequence is consistent with expected activity.

Investigate repeated failures followed by success, unexpected use of privileged accounts, unusual source systems, or authentication activity involving potentially compromised credentials.

An authentication event alone does not establish whether the associated session was authorized or malicious.

### Step 4 — Review RDP Session Details

Review available Remote Desktop Services logs and other session telemetry.

Collect:

- Session start and end timestamps.
- Username and domain.
- Source address and hostname where available.
- Destination hostname.
- Session identifier.
- Logon identifier.
- Session reconnect and disconnect events.
- Relevant Remote Desktop Services authentication events.
- Available RDP connection metadata.
- RDP service configuration and authorized access groups.

Where available, review the Remote Desktop Services operational logs for events associated with connection establishment and authentication.

Correlate these records with the corresponding Windows Security Event Logs and network telemetry.

Determine whether the source, account, destination, and timing match the expected remote administration workflow.

Do not interpret a single Remote Desktop Services event as conclusive proof that a complete interactive session was established. Validate the event against other available session and authentication evidence.

### Step 5 — Review Post-Logon Activity

Investigate activity on the destination system during and after the RDP session.

Review:

- Process creation and parent-child process relationships.
- Command lines associated with newly created processes.
- PowerShell or command-shell execution.
- Executable and script activity.
- Service creation or modification.
- Scheduled task creation or modification.
- Changes to local group membership or account privileges.
- File creation, modification, or execution.
- Network connections initiated by the destination.
- Additional authentication events.
- Security alerts associated with the same account or host.

Pay particular attention to activity that is unusual for the authenticated account or destination system.

Determine whether the account performed expected administrative tasks or initiated activity consistent with unauthorized access or broader compromise.

A suspicious process occurring after an RDP logon should be correlated with the session timeline rather than automatically attributed to that session.

### Step 6 — Correlate Related Activity

Correlate the RDP session with activity observed before and after the connection.

Investigate:

- Authentication failures and successful logons involving the same account.
- Potential credential access or account compromise.
- Unusual access from the source host.
- Related alerts on the destination host.
- Process execution following the RDP session.
- Additional RDP connections to other hosts.
- Service or scheduled task changes.
- Suspicious network connections.
- Similar account and connection patterns elsewhere in the environment.

Determine whether the RDP session is an isolated administrative event or part of a broader activity sequence.

Use corroborating evidence to establish relationships between authentication, remote access, and subsequent actions.

### Step 7 — Determine Lateral Movement Scope

Search the available environment telemetry for related RDP activity.

Search using:

- Account name and domain.
- Source hostname and IP address.
- Destination hostname and IP address.
- Logon identifiers where applicable.
- Relevant timestamps.
- Related process names and command lines.
- Associated alert identifiers.
- Other available indicators identified during the investigation.

Determine:

- The first and most recent observed related sessions.
- The number of potentially affected systems.
- The number of associated accounts.
- Whether privileged accounts were involved.
- Whether the same source accessed multiple destinations.
- Whether additional systems exhibit related suspicious activity.
- Whether the observed activity remains ongoing.

Document the search period, data sources, identified systems, and relevant telemetry gaps.

Do not treat systems as confirmed compromised solely because they were contacted through RDP. Establish the extent of compromise from the available evidence.

### Step 8 — Determine Investigation Outcome

Classify the activity as one of the following:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification, the systems and accounts involved, the known scope, and any outstanding investigative questions.

## Evidence to Collect

| Evidence         | Description                                                                                          |
| ---------------- | ---------------------------------------------------------------------------------------------------- |
| Alert            | Detection source, alert identifier, severity, and timestamp.                                         |
| Source Host      | Hostname, IP address, owner, and asset criticality.                                                  |
| Destination Host | Hostname, IP address, operating system, and asset criticality.                                       |
| Account          | Username, domain, account type, and privilege level.                                                 |
| Authentication   | Relevant successful and failed logon events and authentication context.                              |
| RDP Session      | Session timestamps, identifiers, source information, and available connection metadata.              |
| Windows Logs     | Relevant Security and Remote Desktop Services events.                                                |
| Process Activity | Process identifiers, parent-child relationships, command lines, and execution timestamps.            |
| File Activity    | Relevant file paths, timestamps, hashes, and execution evidence.                                     |
| System Changes   | Service modifications, scheduled tasks, account changes, and privilege changes.                      |
| Network Activity | Relevant source and destination addresses, ports, connection times, and associated traffic metadata. |
| Related Alerts   | Associated authentication, endpoint, and network detections.                                         |
| Scope            | Related hosts, accounts, and sessions identified during investigation.                               |
| Timeline         | Chronological sequence of authentication, session, process, and related events.                      |

Preserve original logs and relevant telemetry according to organizational evidence-handling requirements.

## Decision Criteria

### Benign

Classify the activity as **benign** when the available evidence supports that:

- The RDP connection was authorized.
- The account was expected to access the destination.
- The source and destination relationship matches documented administration.
- Authentication and session activity are consistent with expected behavior.
- Post-logon activity matches authorized administrative or operational tasks.
- No corroborating evidence of unauthorized access or malicious activity is identified.

Document the operational justification before closing the investigation.

### Suspicious

Classify the activity as **suspicious** when one or more indicators require further investigation, including:

- An unexpected source or destination system.
- An account accessing a system outside its normal scope.
- Repeated authentication failures followed by a successful logon.
- Unusual activity involving a privileged account.
- RDP access outside expected operational patterns without an established explanation.
- Suspicious process execution following the session.
- Related network activity or system changes that cannot yet be explained.
- Incomplete telemetry that prevents reliable classification.

Continue investigation and correlate additional evidence before determining whether the activity is malicious.

### Malicious

Classify the activity as **malicious** when sufficient evidence establishes unauthorized RDP access or RDP use as part of a confirmed malicious operation.

Supporting evidence may include:

- Unauthorized access using compromised credentials.
- A confirmed malicious RDP session.
- RDP access followed by verified malicious code execution.
- Unauthorized account or privilege changes associated with the session.
- Confirmed lateral movement to additional systems.
- Corroborating evidence of persistence, credential access, or other malicious behavior.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when the available evidence is insufficient to determine whether the RDP activity was authorized or malicious.

Document:

- Evidence collected.
- Evidence unavailable.
- Systems and accounts reviewed.
- Investigative limitations.
- Additional telemetry required.
- Recommended follow-up actions.

Do not classify the activity as benign solely because no additional malicious indicators were found in incomplete telemetry.

## Escalation

Escalate the investigation when:

- Unauthorized RDP access is confirmed or strongly supported by corroborating evidence.
- A privileged or sensitive account is implicated.
- A domain controller or other critical system is involved.
- RDP activity is followed by confirmed malicious process execution.
- Additional systems show related unauthorized access.
- Evidence indicates credential compromise.
- Suspicious persistence or privilege changes are identified.
- The activity is ongoing or presents a significant operational risk.
- Available evidence indicates broader incident scope.

Notify the appropriate security operations and incident-response personnel according to organizational escalation procedures.

## Response Guidance

For confirmed malicious RDP activity:

1. Preserve relevant authentication, session, endpoint, and network evidence.
2. Identify affected accounts, source systems, destination systems, and related activity.
3. Determine whether unauthorized access remains active.
4. Apply approved containment procedures to affected systems where necessary.
5. Disable, restrict, or revoke compromised account access in accordance with incident-response authorization.
6. Restrict RDP access where required by the containment plan.
7. Investigate and remediate the underlying credential compromise or access-control weakness.
8. Search the environment for related sessions, account activity, process execution, and indicators.
9. Assess whether additional persistence, privilege escalation, credential access, or lateral movement occurred.
10. Restore affected systems and access according to approved recovery procedures.
11. Document containment, remediation, recovery, and validation results.

Do not terminate sessions, disable accounts, isolate hosts, or modify system configuration before considering evidence preservation and the operational impact of the action. Perform containment and remediation through authorized incident-response procedures.

## Related Detection Rules

## Related Playbooks

- `playbooks/triage/lateral-movement-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/response/account-compromise-response.md`

## Validation

The playbook should be validated against approved Windows authentication logs, Remote Desktop Services telemetry, endpoint process data, network connection records, and controlled RDP investigation scenarios.

Validation should confirm that:

- RDP-related authentication events can be identified.
- Source and destination systems can be established.
- Relevant successful and failed logons can be correlated.
- Session information can be examined where telemetry is available.
- Post-logon process and system activity can be investigated.
- Related RDP sessions can be identified across the environment.
- Authorized administrative activity can be distinguished from suspicious behavior.
- Investigation outcomes are supported by documented evidence.
- Escalation and response guidance can be applied consistently.

## Safety

This playbook is intended for defensive security operations, incident response, security validation, and authorized testing.

Investigations must comply with organizational access controls, evidence-preservation requirements, and applicable privacy policies.

Do not attempt unauthorized access to remote systems, test credentials against production systems without authorization, or modify RDP configuration outside approved change-management and incident-response procedures.
