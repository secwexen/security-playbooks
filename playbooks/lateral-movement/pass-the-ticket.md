---
id: "pass-the-ticket"
name: "Pass the Ticket"
category: "lateral-movement"
status: "active"
version: "1.0.1"
author: "Secwexen"
created_at: "2026-10-11T07:21:00Z"
updated_at: "2026-10-30T14:52:00Z"
description: "Investigate suspected abuse of Kerberos tickets to authenticate to systems or services without using the account's plaintext password."
objective: "Determine whether Kerberos ticket use is legitimate or unauthorized, identify affected accounts and systems, establish the scope of lateral movement, and preserve evidence for response."
severity: "high"
mitre_attack:
  - "T1550.003"
triggers:
  - "An alert identifies suspicious Kerberos ticket use or possible ticket injection."
  - "Kerberos authentication is observed from an unusual host, account context, or time."
  - "Remote access succeeds without an expected interactive logon or supporting authentication context."
  - "Ticket-granting or service-ticket activity is inconsistent with the account's normal behavior."
  - "Credential-access activity is followed by anomalous Kerberos authentication or remote access."
prerequisites:
  - "Access to domain controller Security event logs, including Kerberos authentication events."
  - "Access to endpoint authentication, process, and security telemetry where available."
  - "Access to asset, identity, and account ownership information."
  - "Authorization to investigate affected accounts and systems."
tags:
  - "pass-the-ticket"
  - "kerberos"
  - "lateral-movement"
  - "authentication"
  - "windows"
references:
  - "https://attack.mitre.org/techniques/T1550/003/"
  - "https://attack.mitre.org/detectionstrategies/DET0352/"
steps:
  - id: "identify-pass-the-ticket-alert"
    order: 1
    name: "Identify Pass-the-Ticket Alert"
    action: "investigate"
    description: "Identify the alert source, timestamp, detection rationale, associated identity, source host, destination host, and relevant Kerberos service."
    expected_result: "The initial alert and the available authentication context are documented."
  - id: "identify-accounts-and-hosts"
    order: 2
    name: "Identify Accounts and Hosts"
    action: "investigate"
    description: "Identify the account associated with the ticket activity, the originating host, destination systems, account privileges, and expected ownership or administrative role."
    expected_result: "The identities, source and destination systems, and relevant privilege context are identified."
  - id: "review-kerberos-ticket-activity"
    order: 3
    name: "Review Kerberos Ticket Activity"
    action: "analyze"
    description: "Review available domain controller events for ticket-granting ticket requests, service-ticket requests, ticket renewals, and related authentication activity. Correlate events by identity, host, service, and time; consider telemetry gaps before drawing conclusions."
    expected_result: "Relevant Kerberos ticket activity is reconstructed and anomalies are recorded."
  - id: "review-authentication-context"
    order: 4
    name: "Review Authentication Context"
    action: "analyze"
    description: "Correlate Kerberos events with successful logons, explicit-credential logons, logon type, source address, destination service, and the account's normal access patterns."
    expected_result: "The observed authentication sequence is assessed against expected account and host behavior."
  - id: "correlate-credential-access-indicators"
    order: 5
    name: "Correlate Credential Access Indicators"
    action: "analyze"
    description: "Review endpoint telemetry for suspicious access to LSASS, credential-dumping alerts, unusual security-tool execution, or other preceding activity that could explain how ticket material was obtained."
    expected_result: "Related credential-access indicators are identified or no supporting evidence is found."
  - id: "review-lateral-movement-activity"
    order: 6
    name: "Review Lateral Movement Activity"
    action: "hunt"
    description: "Review remote logons and subsequent activity on destination systems, including remote service access, process creation, administrative actions, and connections to additional hosts."
    expected_result: "Potential lateral movement and related post-authentication activity are documented."
  - id: "determine-activity-scope"
    order: 7
    name: "Determine Activity Scope"
    action: "hunt"
    description: "Search across available telemetry for the same account, source host, destination host, service, ticket-related indicators, and time pattern to identify additional affected systems or identities."
    expected_result: "The likely scope, timeline, affected identities, and affected systems are established."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity based on correlated authentication, endpoint, and lateral-movement evidence, and document the reasoning and any telemetry limitations."
    expected_result: "The investigation has a supported outcome and documented next steps."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "pass-the-ticket"
---

# Pass the Ticket

## Purpose

This playbook provides a structured workflow for investigating suspected Kerberos ticket abuse in a Windows environment.

Pass-the-ticket activity involves using stolen or otherwise unauthorized Kerberos ticket material to authenticate to systems or services without entering the associated account's plaintext password. A ticket-related anomaly alone does not prove compromise; the investigation must correlate authentication records with endpoint activity, account context, and the target resource.

The objective is to determine whether the observed activity is legitimate, suspicious, or malicious, and to establish whether it enabled unauthorized lateral movement.

## MITRE ATT&CK

| Technique | Name                                                   | Relevance                                                                         |
| --------- | ------------------------------------------------------ | --------------------------------------------------------------------------------- |
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | Primary technique when Kerberos tickets are used for unauthorized authentication. |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint or identity detection reports possible Kerberos ticket injection or reuse.
- Kerberos authentication occurs from a host or at a time inconsistent with the account's normal activity.
- Service-ticket requests are inconsistent with the user's role, destination, or recent authentication history.
- A successful remote logon lacks expected supporting context in the available telemetry.
- Possible credential access is followed by unusual Kerberos authentication or remote administrative activity.
- Threat hunting identifies a suspicious relationship between ticket activity, account use, and remote access.

## Scope

The investigation should consider:

- affected user and service accounts;
- account privilege level and normal usage;
- source and destination hosts;
- domain controller and Kerberos service activity;
- ticket-granting ticket (TGT) and ticket-granting service (TGS) events where available;
- authentication timestamps and logon types;
- source addresses and target services;
- endpoint process and LSASS access telemetry;
- remote logons and post-authentication activity;
- related credential-access and lateral-movement alerts;
- other potentially affected identities or systems.

## Investigation Procedure

### Step 1 — Identify Pass-the-Ticket Alert

Review the original alert and preserve its context.

Collect:

- alert identifier;
- detection source and rule name;
- detection timestamp and time zone;
- alert severity and confidence;
- associated account and domain;
- source and destination hostnames and IP addresses;
- Kerberos service or target resource;
- original detection evidence and relevant event references.

Preserve the original alert and relevant event details before containment or remediation actions alter the available evidence.

### Step 2 — Identify Accounts and Hosts

Determine which identity was used and which systems participated in the activity.

Collect:

- account name, domain, and account type;
- account privileges and expected administrative responsibilities;
- source and destination hostnames and IP addresses;
- target service or resource;
- asset owner and business criticality;
- whether the source host is normally used by the account.

Identify unexpected use of privileged, service, or sensitive accounts. An account's privilege level alone is not evidence of malicious activity.

### Step 3 — Review Kerberos Ticket Activity

Review available domain controller Security logs for relevant Kerberos authentication activity:

- Review Domain Controller Security logs for Kerberos events 4768, 4769, and 4770.
- Correlate ticket activity by account, source IP, destination host, service, and timestamp.
- Identify unusual ticket requests and authentication patterns.
- Compare observed activity with the account's normal behavior.
- Identify service-ticket requests originating from unusual hosts or IP addresses.
- Check for the same account requesting Kerberos tickets from multiple hosts within a short time period.

Review event results and available ticket-related fields in the context of the account's expected behavior. Do not treat an individual event or an absent event as conclusive evidence of Pass-the-Ticket activity.

### Step 4 — Review Authentication Context

Correlate Kerberos activity with available logon records.

Collect:

- event ID and timestamp;
- account name, domain, and logon identifier where available;
- logon type;
- source network address and workstation;
- destination host;
- authentication package;
- process information associated with the logon where available;
- related Kerberos events;
- relevant account history and expected access patterns.

Review logon type, source address, destination host, account history, normal access hours, and the service being accessed. Determine whether the sequence is consistent with approved administration, service operation, or a known application workflow.

Document gaps between ticket activity and observed logons, but assess them alongside collection coverage and other evidence rather than using them as a standalone verdict.

### Step 5 — Correlate Credential Access Indicators

Review endpoint telemetry around the relevant time window for:

- unusual process access to LSASS;
- credential-dumping or ticket-manipulation alerts from approved security tools;
- unexpected privileged process execution;
- suspicious scripts or binaries;
- related credential-access activity involving the same account or host.

Correlate process events, command lines, file metadata, user context, and detection details where available. Do not execute suspicious files or attempt to extract tickets as part of routine triage.

### Step 6 — Review Lateral Movement Activity

On the destination system, review remote logons and subsequent activity for signs that the authentication was used to perform unauthorized actions.

Consider:

- remote service or administrative access;
- unexpected process creation or command execution;
- access to sensitive shares or resources;
- changes to services, scheduled tasks, or other persistence mechanisms;
- additional authentication from the destination host to other systems;
- related endpoint or identity alerts.

Correlate activity across systems to determine whether the suspected ticket use was isolated or part of a broader intrusion.

### Step 7 — Determine Activity Scope

Search available telemetry for related use of the same account, source host, destination host, service, and activity pattern.

Determine:

- first and last observed activity;
- identities and systems involved;
- services and resources accessed;
- whether privileged or sensitive systems were reached;
- evidence of credential access or additional lateral movement;
- telemetry gaps that limit confidence in the scope.

Document the search window and data sources used so that another analyst can reproduce the scope assessment.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the selected classification.

Identify whether incident escalation, credential remediation, endpoint containment, or further investigation is required.

## Evidence to Collect

| Evidence             | Description                                                                                                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Alert                | Detection source, identifier, severity, timestamp, and detection rationale                                                                                                      |
| Identity             | Account name, domain, account type, privileges, and expected role                                                                                                               |
| Hosts                | Source and destination hostnames, IP addresses, and asset context                                                                                                               |
| Kerberos Events      | Windows Security events 4768 (TGT requests), 4769 (service-ticket requests), and 4770 (service-ticket renewals), including relevant fields and event outcomes                   |
| Logon Records        | Event 4624, including logon type and source context; event 4648, including explicit-credential use, associated accounts, process information, and target server where available |
| Endpoint Telemetry   | Process creation, process lineage, command-line data, and relevant endpoint security alerts                                                                                     |
| LSASS Access         | Available telemetry identifying unusual process access to LSASS, including Sysmon Event ID 10 where configured                                                                  |
| Module Load Activity | Relevant module-load telemetry, including Sysmon Event ID 7 where configured                                                                                                    |
| Credential Access    | Related credential-dumping, ticket-manipulation, and endpoint security alerts                                                                                                   |
| Remote Activity      | Remote logons, service access, process creation, and administrative activity on destination systems                                                                             |
| Timeline             | Correlated timestamps and the sequence of authentication, endpoint, and remote-access activity                                                                                  |
| Scope                | Other potentially affected accounts, hosts, services, and resources                                                                                                             |
| Data Limitations     | Missing logs, collection gaps, retention limits, and unavailable telemetry                                                                                                      |

## Decision Criteria

### Benign

Classify the activity as **benign** when evidence supports an authorized explanation, such as:

- the account and source host are expected for the observed access;
- ticket requests and logons align with normal account and service behavior;
- the destination service and access time have a documented operational explanation;
- related endpoint activity is consistent with approved administration or application behavior;
- no corroborating signs of credential access or unauthorized lateral movement are found.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when one or more indicators require further investigation, such as:

- ticket requests originate from an unusual host or source address;
- service-ticket activity is inconsistent with the account's role or access history;
- the available ticket and logon sequence is anomalous or unexplained;
- privileged accounts access unexpected systems or services;
- related LSASS access, suspicious process execution, or remote activity is observed;
- telemetry is insufficient to rule out unauthorized ticket use.

Continue investigation, preserve evidence, and increase monitoring of the affected identities and systems.

### Malicious

Classify the activity as **malicious** when correlated evidence supports unauthorized use of Kerberos ticket material or related compromise, such as:

- a security investigation confirms unauthorized ticket injection or use;
- ticket activity is linked to confirmed credential theft or ticket-manipulation tooling;
- an account is used from an unauthorized host to access systems outside its approved role;
- the authentication sequence is followed by confirmed unauthorized remote execution or administrative activity;
- multiple systems show a consistent pattern of unauthorized ticket-based lateral movement.

Escalate to incident response and follow approved identity and endpoint containment procedures.

### Inconclusive

Use **inconclusive** when the available evidence cannot reliably distinguish legitimate Kerberos activity from ticket abuse.

Document:

- evidence collected and evidence that supports or contradicts the hypothesis;
- missing logs, collection limitations, and retention gaps;
- additional identity, domain controller, or endpoint telemetry required;
- the next investigative actions and responsible team.

## Escalation

Escalate the investigation when:

- unauthorized Kerberos ticket use is confirmed or strongly suspected;
- a privileged or sensitive account is involved;
- suspicious authentication is followed by remote execution or administrative activity;
- credential theft or LSASS access is identified;
- multiple hosts, accounts, or services may be affected;
- domain controller or other high-value infrastructure is implicated;
- available telemetry is insufficient to assess a potentially high-impact compromise.

## Response Guidance

For confirmed malicious activity:

1. Preserve relevant identity, domain controller, endpoint, and network evidence.
2. Notify the incident-response and identity-management teams according to the organization's escalation process.
3. Assess containment options for affected hosts and accounts with the system and identity owners.
4. Revoke or invalidate relevant sessions or ticket material where supported by the environment's response procedures; coordinate any domain-wide or privileged-account actions with authorized identity administrators.
5. Investigate how the ticket material was obtained and address the underlying credential-access path.
6. Hunt for related account use, remote access, persistence, and lateral movement across the environment.
7. Reset credentials or rotate secrets when evidence and response procedures indicate they may be compromised; handle privileged and service accounts with appropriate dependency planning.
8. Restore affected systems and identities only after remediation and validation are complete.
9. Document containment decisions, evidence, recovery actions, and residual risks.

Do not purge logs, indiscriminately reset service-account credentials, or perform disruptive domain-wide actions without authorization and impact assessment.

## Related Detection Rules

## Related Playbooks

- `playbooks/lateral-movement/pass-the-hash.md`
- `playbooks/triage/lateral-movement-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/credential-access/credential-dumping.md`
- `playbooks/credential-access/lsass-dump.md`

## Validation

Validate this playbook using approved Windows authentication telemetry, domain controller Security events, endpoint process telemetry, and controlled laboratory scenarios.

Validation should confirm that:

- Kerberos ticket and logon events can be correlated by identity, host, service, and time;
- expected authentication patterns can be distinguished from unexplained anomalies;
- relevant credential-access and endpoint activity can be investigated;
- lateral movement and affected scope can be assessed across available telemetry;
- missing data is documented without treating absence of evidence as proof of malicious activity;
- escalation and response decisions follow approved procedures.

The playbook has not been operationally validated until the repository's required validation process is completed and its metadata is updated accordingly.

## Safety

This playbook is intended for defensive security operations, authorized incident response, security validation, and controlled laboratory environments only.

Investigations must follow organizational access controls, evidence-preservation requirements, privacy obligations, and change-management procedures. Do not attempt ticket extraction, ticket injection, or unauthorized authentication against production systems as part of routine triage.
