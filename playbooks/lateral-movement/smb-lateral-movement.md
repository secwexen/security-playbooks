---
id: "smb-lateral-movement"
name: "SMB Lateral Movement"
category: "lateral-movement"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-13T10:48:00Z"
updated_at: "2026-10-13T10:48:00Z"
description: "Investigate suspicious SMB activity involving remote network shares, Windows administrative shares, and potential lateral movement between systems."
objective: "Determine whether SMB-based remote access represents legitimate administrative activity or unauthorized lateral movement, identify affected systems and accounts, and establish the scope of the activity."
severity: "high"
mitre_attack:
  - "T1021.002"
triggers:
  - "Unexpected SMB authentication from a user or host"
  - "Unusual access to Windows administrative shares"
  - "Suspicious remote file access or transfer over SMB"
  - "Remote file creation followed by unexpected process execution"
  - "Unusual SMB connections between workstations or server segments"
  - "Repeated SMB access attempts involving multiple internal systems"
  - "Threat hunting identifies suspicious SMB activity"
prerequisites:
  - "Access to Windows authentication and security event telemetry"
  - "Access to SMB server and network share auditing"
  - "Access to endpoint process creation telemetry"
  - "Access to network connection and firewall telemetry"
  - "Access to asset inventory and account ownership information"
tags:
  - "smb"
  - "lateral-movement"
  - "windows"
  - "network-shares"
  - "administrative-shares"
  - "authentication"
  - "incident-response"
references:
  - "https://attack.mitre.org/techniques/T1021/002/"
steps:
  - id: "identify-smb-lateral-movement-alert"
    order: 1
    name: "Identify SMB Lateral Movement Alert"
    action: "investigate"
    description: "Identify the detection source, affected systems, associated accounts, observed SMB activity, and alert context."
    expected_result: "The initial SMB activity and potentially affected assets are identified."
  - id: "identify-source-and-destination"
    order: 2
    name: "Identify Source and Destination"
    action: "investigate"
    description: "Determine the originating host, destination host, relevant network addresses, SMB service, and connection timeline."
    expected_result: "The source and destination systems and their relationship are documented."
  - id: "review-authentication-activity"
    order: 3
    name: "Review Authentication Activity"
    action: "analyze"
    description: "Examine authentication events, account context, logon type, explicit credential use, and the legitimacy of access to the destination system."
    expected_result: "The account and authentication context associated with the SMB activity are assessed."
  - id: "review-smb-share-access"
    order: 4
    name: "Review SMB Session and Share Access"
    action: "analyze"
    description: "Review SMB sessions, accessed shares, file operations, access permissions, and administrative share usage."
    expected_result: "The scope and nature of SMB share access are documented."
  - id: "review-remote-execution-activity"
    order: 5
    name: "Review Remote Execution Activity"
    action: "analyze"
    description: "Determine whether SMB access was followed by suspicious file creation, service activity, scheduled task activity, or remote process execution."
    expected_result: "Related execution activity is identified and correlated with the SMB access."
  - id: "correlate-related-events"
    order: 6
    name: "Correlate Related Events"
    action: "hunt"
    description: "Correlate SMB activity with authentication, endpoint, network, file, and security detection events across the environment."
    expected_result: "Related activity and potential attack-chain relationships are established."
  - id: "determine-lateral-movement-scope"
    order: 7
    name: "Determine Lateral Movement Scope"
    action: "hunt"
    description: "Identify additional source and destination systems, affected accounts, repeated share-access patterns, and the earliest and latest observed activity."
    expected_result: "The potential extent of SMB-based lateral movement is determined."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the observed activity using the available evidence and document the investigation findings and required follow-up actions."
    expected_result: "The investigation outcome, supporting evidence, and escalation requirements are documented."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "smb-lateral-movement"
---

# SMB Lateral Movement

## Purpose

This playbook provides a structured workflow for investigating suspicious SMB activity that may indicate lateral movement between systems.

Server Message Block (SMB) is commonly used for legitimate file sharing and Windows administration. However, unauthorized use of SMB sessions, remote network shares, and Windows administrative shares may enable an adversary to access additional systems, transfer files, and support remote execution.

The objective is to determine whether the observed SMB activity is legitimate, suspicious, or malicious; identify the systems and accounts involved; and establish whether the activity is part of a broader compromise.

## MITRE ATT&CK

| Technique | Name                     | Relevance                                                                                  |
| --------- | ------------------------ | ------------------------------------------------------------------------------------------ |
| T1021.002 | SMB/Windows Admin Shares | Primary technique when SMB or Windows administrative shares are used for lateral movement. |

T1021.002 belongs to the Remote Services technique family and is associated with the Lateral Movement tactic.

The mapping should be retained only when the observed activity supports SMB-based remote access or administrative share abuse.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Unexpected SMB authentication from a user account or source host.
- Unusual access to administrative shares such as `ADMIN$`, `C$`, or `IPC$`.
- SMB connections between systems that do not normally communicate.
- Unexpected remote file creation or modification through an SMB share.
- File transfers followed by suspicious process or service activity on the destination host.
- Repeated SMB access involving multiple internal systems.
- Use of a privileged account to access an unusual destination.
- SMB activity associated with suspected credential compromise.
- Threat hunting identifies anomalous internal SMB traffic.

An SMB connection or administrative share access alone does not establish malicious activity. The investigation must consider the account, source and destination systems, timing, accessed resources, and related execution activity.

## Scope

The investigation should consider:

- Source host and IP address.
- Destination host and IP address.
- Associated user and domain.
- Account type and privilege level.
- Authentication method and logon type.
- SMB session details.
- Destination port and network protocol.
- Accessed network shares.
- Administrative share usage.
- Accessed, created, modified, or transferred files.
- File hashes and digital signatures where available.
- Process creation and process lineage.
- Service creation or modification.
- Scheduled task activity.
- Related WMI or other remote execution activity.
- Network connections and firewall events.
- Related security alerts.
- Additional potentially affected systems.
- Earliest and latest observed activity.

The investigation should include sufficient historical context to distinguish expected administrative behavior from anomalous remote access.

## Investigation Procedure

### Step 1 — Identify SMB Lateral Movement Alert

Collect:

- Detection source.
- Alert identifier.
- Alert timestamp.
- Detection severity.
- Source hostname and IP address.
- Destination hostname and IP address.
- Associated account.
- Observed SMB activity.
- Accessed share, where available.
- Detection reason.

Determine whether the activity was reported by endpoint monitoring, Windows security auditing, network monitoring, or a correlation rule.

Preserve the original alert context before taking response actions.

### Step 2 — Identify Source and Destination

Determine which system initiated the SMB connection and which system received it.

Collect:

- Source hostname and IP address.
- Destination hostname and IP address.
- Destination port.
- Connection timestamp and duration.
- Source and destination asset roles.
- Network segment information.
- System criticality.
- Expected communication relationship.
- Relevant firewall or network monitoring events.

Review whether the source and destination normally communicate over SMB.

Investigate connections involving unusual workstation-to-workstation communication, unexpected access to servers, or administrative access originating from systems that are not normally used for administration.

A connection to TCP port 445 is not inherently malicious. Assess it in conjunction with authentication, share access, and endpoint activity.

### Step 3 — Review Authentication Activity

Review the authentication associated with the SMB session.

When available, examine:

- Windows Security Event ID 4624 for successful logons.
- Windows Security Event ID 4648 for logons using explicit credentials.
- Logon type and authentication package.
- Account name and domain.
- Source network address and workstation.
- Authentication timestamp.
- Privilege context.
- Related failed authentication attempts.
- Concurrent or subsequent sessions involving the same account.

Assess whether the account is authorized to access the destination host and whether the observed logon is consistent with its normal behavior.

Investigate:

- Administrative accounts accessing unexpected systems.
- Service accounts used outside their normal operating context.
- First-time authentication from an unusual source.
- Authentication activity outside expected operational periods.
- The same account accessing multiple systems in a short period.
- Evidence suggesting credential compromise.

Do not conclude that an account is compromised solely because it successfully authenticated to an unfamiliar system.

### Step 4 — Review SMB Session and Share Access

Determine which shares and resources were accessed during the investigation window.

Review relevant information, including:

- Share name and share path.
- Source account.
- Source and destination systems.
- Access timestamp.
- Requested access rights.
- File names and paths where available.
- File creation and modification events.
- Administrative share access.
- Related access-denied events.
- SMB server audit records.

When available, examine:

- Windows Security Event ID 5140 for network share access.
- Windows Security Event ID 5145 for detailed file share access checks.
- Endpoint file telemetry.
- SMB server logs.
- Network monitoring records.

Pay particular attention to unusual use of administrative shares such as:

- `ADMIN$`
- `C$`
- `IPC$`

Administrative shares are legitimate Windows functionality. Their use should be evaluated in the context of the initiating account, source host, destination host, accessed resources, and subsequent activity.

Determine whether file access or transfer activity is consistent with approved administration, software deployment, backup operations, or routine application behavior.

### Step 5 — Review Remote Execution Activity

Determine whether the SMB session was followed by activity indicating that the destination system was used to execute unauthorized code or perform additional operations.

Review:

- Process creation events on the destination host.
- New or modified executable files and scripts.
- File creation in unusual directories.
- Service creation or configuration changes.
- Scheduled task creation or modification.
- Related WMI activity.
- Unexpected child processes.
- Unusual command lines.
- Execution of recently transferred files.
- Network connections initiated by newly observed processes.

Where available, correlate endpoint process creation records, including Sysmon Event ID 1, with file activity and the SMB session timeline.

Establish whether the sequence of events is consistent with legitimate remote administration or indicates unauthorized access followed by execution.

A remote service, scheduled task, or WMI event does not independently prove that SMB was used for lateral movement. Confirm the relationship through timestamps, account context, file activity, and other available evidence.

### Step 6 — Correlate Related Events

Correlate the identified SMB activity with other security events.

Search for:

- Additional SMB sessions from the same source host.
- The same account accessing multiple destinations.
- Repeated access to administrative shares.
- Similar file names or hashes on multiple systems.
- Authentication anomalies involving the same account.
- Unexpected service or scheduled task activity.
- Related PowerShell, command shell, or WMI execution.
- Suspicious process creation on destination systems.
- Additional alerts involving the source or destination.
- Signs of credential access or broader compromise.

Build a timeline connecting authentication, SMB access, file activity, and any subsequent execution.

Where appropriate, use the available network and endpoint telemetry to determine whether the activity is isolated or part of a broader sequence of related events.

### Step 7 — Determine Lateral Movement Scope

Determine the potential scope of the activity across the environment.

Search for:

- Additional source hosts associated with the same account.
- Additional destination hosts accessed over SMB.
- Repeated connections to administrative shares.
- The same transferred files or hashes on other systems.
- Similar authentication and process activity.
- Related service or scheduled task activity.
- Repeated behavior within the same network segment.
- Evidence of activity involving privileged systems.

Document:

- Number of potentially affected hosts.
- Number of associated accounts.
- First observed activity.
- Most recent observed activity.
- Systems with confirmed suspicious access.
- Systems requiring further investigation.
- Whether the activity remains ongoing.
- Unavailable telemetry or unresolved investigative gaps.

Differentiate confirmed observations from inferred scope. Do not classify every host with an SMB connection as compromised.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

Record the affected assets, accounts, timestamps, relevant events, scope assessment, and required follow-up actions.

## Evidence to Collect

| Evidence            | Description                                                               |
| ------------------- | ------------------------------------------------------------------------- |
| Alert               | Detection source, alert identifier, severity, and timestamp               |
| Source Host         | Hostname, IP address, asset role, and ownership                           |
| Destination Host    | Hostname, IP address, asset role, and criticality                         |
| Account             | Username, domain, account type, and privilege context                     |
| Authentication      | Logon events, logon type, authentication package, and source address      |
| SMB Session         | Session details, connection timestamps, source, and destination           |
| Share Access        | Share name, accessed resources, access rights, and relevant audit events  |
| Files               | File paths, names, timestamps, and observed operations                    |
| Hashes              | Available file hashes and reputation information                          |
| Process Activity    | Process identifiers, executable paths, command lines, and process lineage |
| Remote Execution    | Related service, scheduled task, WMI, or other execution evidence         |
| Network             | SMB connections, destination ports, firewall events, and related traffic  |
| Related Alerts      | Other detections associated with the same accounts or systems             |
| Timeline            | Correlated authentication, SMB, file, process, and network events         |
| Scope               | Additional affected or potentially affected hosts and accounts            |
| Investigation Notes | Findings, evidence gaps, classification, and escalation decisions         |

Preserve relevant evidence according to organizational retention, access control, and incident-handling requirements.

## Decision Criteria

### Benign

Classify the activity as **benign** when the available evidence establishes that:

- The source and destination systems have an expected operational relationship.
- The account is authorized to access the destination.
- The authentication context is consistent with legitimate activity.
- The accessed shares and resources are appropriate for the operational task.
- File and process activity is consistent with approved administration or application behavior.
- No suspicious follow-on activity is identified.
- No contradictory evidence indicates unauthorized access.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when one or more of the following conditions are observed:

- SMB communication occurs between systems without an established operational relationship.
- An account accesses unfamiliar administrative shares.
- The source host, destination host, or account context is unusual.
- File access or transfer activity is unexpected.
- SMB activity is followed by suspicious file or process activity.
- Authentication patterns differ from established behavior.
- Related telemetry is incomplete and malicious activity cannot yet be ruled out.
- Additional systems or accounts may be involved.

Continue investigation and collect additional evidence before determining the final outcome.

### Malicious

Classify the activity as **malicious** when sufficient evidence demonstrates unauthorized SMB-based remote access or lateral movement.

Supporting evidence may include:

- Confirmed unauthorized access to remote administrative shares.
- SMB activity associated with a compromised or unauthorized account.
- Unauthorized file transfer followed by confirmed malicious execution.
- Correlated SMB access and remote execution on a destination host.
- Confirmed lateral movement involving multiple systems.
- Related malicious activity consistent with the observed SMB sessions.
- Additional evidence establishing that the access was part of a broader compromise.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when the available evidence is insufficient to determine whether the SMB activity is legitimate or malicious.

Document:

- Evidence collected.
- Evidence that is unavailable.
- Unresolved authentication or share-access questions.
- Systems and accounts requiring further investigation.
- Additional telemetry required to reach a defensible conclusion.

Do not classify the activity as benign solely because malicious behavior has not been confirmed.

## Escalation

Escalate the investigation when:

- Unauthorized remote access is confirmed.
- A compromised or unauthorized account is used to access remote systems.
- Suspicious administrative share access is followed by unexpected execution.
- A privileged account accesses multiple unexpected systems.
- Evidence indicates lateral movement across multiple hosts.
- Malicious files are transferred to remote systems.
- Related credential access, persistence, or command-and-control activity is identified.
- Critical infrastructure, identity systems, or other high-value assets are potentially affected.
- The activity remains ongoing or its scope cannot be reliably established.

Use the organization's incident classification and escalation procedures to determine response priority.

## Response Guidance

For confirmed malicious SMB-based lateral movement:

1. Preserve relevant authentication, SMB, file, process, and network evidence.
2. Identify affected hosts, source systems, destination systems, and associated accounts.
3. Determine whether the activity is ongoing.
4. Follow the organization's authorized endpoint containment procedure when containment is warranted.
5. Search for related SMB sessions, transferred artifacts, and suspicious execution on other systems.
6. Coordinate account containment or credential rotation with the identity and incident-response teams when compromise is suspected or confirmed.
7. Review unnecessary SMB exposure and administrative share access according to approved security policies.
8. Investigate related credential access, persistence, and remote execution activity.
9. Restore affected systems only after the incident-response team has established an appropriate recovery plan.
10. Document containment, investigation, remediation, and recovery actions.

Do not disable SMB globally, remove files, terminate processes, or modify services without evaluating operational impact and following approved incident-response procedures.

## Related Detection Rules

## Related Playbooks

- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/lateral-movement/pass-the-ticket.md`
- `playbooks/lateral-movement/rdp-lateral-movement.md`
- `playbooks/lateral-movement/winrm-lateral-movement.md`
- `playbooks/lateral-movement/wmi-lateral-movement.md`
- `playbooks/triage/lateral-movement-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/malware-response.md`

## Validation

The playbook should be validated against approved Windows authentication telemetry, SMB server auditing, endpoint process events, file activity, and controlled investigation scenarios.

Validation should confirm that:

- The source and destination systems can be identified.
- Authentication activity can be correlated with SMB sessions.
- Administrative share access can be investigated.
- Relevant file operations can be reconstructed where telemetry is available.
- SMB activity can be correlated with subsequent execution.
- Legitimate administrative activity can be distinguished from suspicious remote access.
- Potentially affected systems and accounts can be identified.
- Decision criteria produce consistent and evidence-based outcomes.
- Escalation and response guidance align with organizational procedures.

Validation metadata must be updated only after the required validation activities have been completed.

## Safety

This playbook is intended for defensive security operations, authorized incident response, security validation, and controlled laboratory environments.

Investigations must comply with organizational access controls, evidence-preservation requirements, privacy obligations, and change-management procedures.

SMB connections and administrative shares are legitimate components of many Windows environments. Their presence alone does not establish malicious activity. Decisions must be based on corroborating evidence, operational context, and the applicable investigation criteria.
