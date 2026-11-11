---
id: "lateral-movement-response"
name: "Lateral Movement Response"
category: "response"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-11-11T14:00:00Z"
updated_at: "2026-11-11T14:12:00Z"
description: "Lateral Movement Response provides a structured process for identifying unauthorized movement between systems, investigating compromised accounts and remote access activity, determining the affected environment scope, applying authorized containment, and validating response effectiveness."
objective: "Identify, investigate, contain, and validate suspected or confirmed lateral movement while preserving evidence, limiting further compromise, and minimizing operational impact."
severity: "critical"
mitre_attack:
  - "T1021"
  - "T1078"
  - "T1210"
  - "T1550"
  - "T1570"
triggers:
  - "Confirmed or suspected unauthorized access between internal systems"
  - "Unusual remote service authentication activity"
  - "Suspicious use of RDP, SMB, SSH, WinRM, or other remote services"
  - "Compromised account accessing multiple systems"
  - "Suspicious administrative activity originating from an unexpected host"
  - "Detection of remote execution or lateral movement behavior"
  - "Unauthorized transfer of tools or files between internal systems"
  - "Confirmed or suspected credential reuse across multiple hosts"
prerequisites:
  - "Access to endpoint detection and response telemetry"
  - "Access to authentication and identity-provider logs"
  - "Access to network and remote-access telemetry"
  - "Authorized host-isolation and network-containment capabilities"
  - "Established incident-response and containment procedures"
  - "Access to relevant asset inventory and system ownership information"
  - "Authorized personnel available to perform investigation and containment actions"
tags:
  - "lateral-movement"
  - "incident-response"
  - "containment"
  - "network"
  - "endpoint"
  - "authentication"
  - "credential-compromise"
  - "remote-access"
  - "active-directory"
  - "privilege-abuse"
  - "response"
references:
  - "https://attack.mitre.org/techniques/T1021/"
  - "https://attack.mitre.org/techniques/T1078/"
  - "https://attack.mitre.org/techniques/T1210/"
  - "https://attack.mitre.org/techniques/T1550/"
  - "https://attack.mitre.org/techniques/T1570/"
steps:
  - id: "identify-lateral-movement-alert"
    order: 1
    name: "Identify Lateral Movement Alert"
    action: "investigate"
    description: "Identify the detection source, alert details, suspected source and destination hosts, associated accounts, remote services, timestamps, and initial indicators of lateral movement."
    expected_result: "The suspected lateral movement activity and its initial investigation context are identified."
  - id: "validate-source-and-destination"
    order: 2
    name: "Validate Source and Destination"
    action: "analyze"
    description: "Validate the source and destination systems, endpoint identities, network addresses, ownership, business roles, expected communication patterns, and authorization context."
    expected_result: "The source and destination systems and their operational context are validated."
  - id: "review-remote-access-events"
    order: 3
    name: "Review Remote Access Events"
    action: "analyze"
    description: "Review successful and failed authentication events, remote logons, source and destination addresses, remote service activity, authentication protocols, privileged account usage, and suspicious authentication patterns."
    expected_result: "Remote access activity and suspicious authentication patterns are identified and assessed."
  - id: "review-post-authentication-activity"
    order: 4
    name: "Review Post-Authentication Activity"
    action: "analyze"
    description: "Correlate successful authentication events with process creation, remote execution, administrative actions, file access, network connections, account changes, and other post-authentication activity."
    expected_result: "Actions performed on destination systems after authentication are identified and documented."
  - id: "determine-lateral-movement-scope"
    order: 5
    name: "Determine Lateral Movement Scope"
    action: "hunt"
    description: "Search and correlate endpoint, authentication, identity, and network telemetry to identify affected hosts, accounts, services, remote sessions, lateral movement paths, and the overall incident scope."
    expected_result: "The confirmed and suspected lateral movement scope is documented."
  - id: "contain-lateral-movement"
    order: 6
    name: "Contain Lateral Movement"
    action: "contain"
    description: "Apply authorized containment controls to restrict unauthorized remote access, isolate affected hosts, restrict compromised accounts, and block suspicious communication paths while preserving required security-management connectivity where supported."
    expected_result: "Unauthorized lateral movement paths and associated access are restricted according to the approved containment procedure."
  - id: "eradicate-and-recover"
    order: 7
    name: "Eradicate and Recover"
    action: "contain"
    description: "Address the identified source of lateral movement, remediate affected systems, remove unauthorized access and persistence mechanisms, restore affected identities and systems to a trusted state, and verify security controls before authorized recovery."
    expected_result: "Affected systems and identities are remediated, restored to a trusted state, and validated for recovery."
  - id: "determine-response-outcome"
    order: 8
    name: "Determine Response Outcome"
    action: "document"
    description: "Classify the incident as benign, suspicious, malicious, or inconclusive, document supporting evidence, and record investigation, containment, eradication, recovery, and follow-up actions."
    expected_result: "The lateral movement response receives a documented outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "Controlled lateral movement investigation and containment exercise using approved endpoint telemetry, authentication events, network monitoring, and documented incident-response procedures."
---

# Lateral Movement Response

## Purpose

This playbook provides a structured incident-response workflow for investigating and containing suspected or confirmed lateral movement within an organization's environment.

Lateral movement occurs when an adversary accesses or moves between systems, accounts, or network resources after obtaining an initial foothold.

The activity may involve compromised credentials, unauthorized remote access, exploitation of remote services, abuse of administrative tools, or the transfer of malicious tools between systems.

The objective is to identify the origin and destination of suspicious activity, validate associated identities and remote access behavior, determine the affected environment scope, apply authorized containment, preserve relevant evidence, and verify that further unauthorized movement has been restricted.

## MITRE ATT&CK

| Technique | Name                                  | Relevance                                                                                              |
| --------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| T1021     | Remote Services                       | Remote services such as RDP, SMB, SSH, and WinRM are used to access additional systems.                |
| T1078     | Valid Accounts                        | Compromised or unauthorized accounts are used to access internal systems.                              |
| T1210     | Exploitation of Remote Services       | Vulnerabilities in remote services are exploited to gain access to additional systems.                 |
| T1550     | Use Alternate Authentication Material | Authentication material such as tokens or other authentication artifacts is misused to access systems. |
| T1570     | Lateral Tool Transfer                 | Tools or files are transferred between systems during unauthorized movement.                           |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Unauthorized access between internal systems is identified.
- Unusual or unexpected remote service authentication activity is detected.
- RDP, SMB, SSH, WinRM, or other remote services are used in suspicious circumstances.
- A compromised account accesses multiple systems within an unusual timeframe.
- An administrative account performs unexpected operations on multiple endpoints or servers.
- Suspicious remote execution or process creation is detected.
- An unexpected system initiates administrative connections to other internal hosts.
- Unauthorized tools or files are transferred between internal systems.
- Credential reuse or abnormal authentication patterns are associated with multiple endpoints.

## Scope

The response should consider:

- suspected source and destination hosts;
- hostname and endpoint identifier;
- IP addresses and network segments;
- operating systems and asset information;
- source and destination ports;
- remote services and protocols;
- associated user, service, and privileged accounts;
- authentication methods, results, and logon types;
- process execution, parent and child processes, and remote execution indicators;
- network connections and DNS activity;
- file transfers and suspicious tools;
- credential-related indicators;
- directory-service and administrative activity;
- affected business services;
- related hosts, accounts, and lateral movement paths;
- containment status;
- operational impact;
- remaining security risks.

## Investigation Procedure

### Step 1 — Identify Lateral Movement Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- alert severity;
- suspected source host;
- suspected destination host;
- source IP address;
- destination IP address;
- associated user or service account;
- remote service or protocol;
- authentication result;
- detection reason.

Preserve the original alert context before containment actions are performed.

### Step 2 — Validate Source and Destination

Determine whether the observed communication is consistent with expected system behavior.

Review:

- hostname;
- endpoint identifier;
- operating system;
- host ownership;
- business or technical role;
- network segment;
- asset criticality;
- expected source and destination relationships;
- authorized administrative access;
- normal remote service usage;
- known system dependencies.

A single unusual connection should not automatically be treated as confirmed lateral movement. Correlate endpoint, authentication, and network signals before assigning the final classification.

### Step 3 — Review Remote Access Events

Review:

- successful authentication events;
- failed authentication events;
- remote logon events;
- source and destination IP addresses;
- RDP activity;
- SMB activity;
- SSH activity;
- WinRM activity;
- RPC and DCOM activity;
- authentication protocols;
- privileged account usage;
- service account activity;
- remote session creation and termination;
- suspicious authentication patterns.

Construct a timeline covering the period immediately before and after the suspected lateral movement.

### Step 4 — Review Post-Authentication Activity

Correlate successful authentication with:

- process creation;
- process execution;
- parent and child processes;
- command-line activity;
- remote execution;
- administrative actions;
- file access and transfer;
- network connections;
- DNS activity;
- administrative share access;
- security configuration changes;
- account-management changes;
- additional remote authentication events.

Determine what actions were performed on the destination systems after authentication.

### Step 5 — Determine Lateral Movement Scope

Search the environment for:

- suspected source hosts;
- destination hosts;
- associated user accounts;
- associated service accounts;
- related authentication events;
- remote sessions;
- remote service connections;
- suspicious processes;
- transferred files and tools;
- privileged administrative activity;
- related security alerts;
- additional affected systems.

Determine:

- number of affected hosts;
- number of affected accounts;
- number of affected network segments;
- remote services involved;
- earliest suspicious activity;
- latest suspicious activity;
- whether privileged systems are affected;
- whether unauthorized access is ongoing.

### Step 6 — Contain Lateral Movement

Based on incident severity and organizational procedures, consider:

- isolating affected hosts;
- restricting unauthorized remote access;
- blocking suspicious source-to-destination communication;
- restricting affected network segments;
- disabling or restricting compromised accounts;
- revoking active sessions or authentication tokens where supported;
- restricting unauthorized administrative access;
- coordinating host, network, and identity containment;
- preserving required security-management connectivity.

Containment actions should be coordinated with endpoint, network, and identity-management teams to prevent further unauthorized access while minimizing operational impact.

### Step 7 — Eradicate and Recover

Determine and address the likely source of lateral movement.

Review for:

- compromised credentials;
- unauthorized remote access;
- exploitation of remote services;
- malicious process execution;
- credential dumping;
- unauthorized administrative tools;
- malware or suspicious files;
- unauthorized persistence mechanisms;
- compromised endpoints;
- affected privileged accounts;
- additional compromised systems.

Restore affected systems and identities to a trusted state and verify:

- unauthorized access paths were removed;
- affected systems were appropriately remediated;
- compromised credentials were addressed;
- unauthorized accounts or authentication methods were removed;
- remote access permissions remain appropriate;
- security controls are operational;
- endpoint and network telemetry are available;
- containment can be safely removed through authorized procedures.

### Step 8 — Determine Response Outcome

Classify the incident as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification and record all investigation, containment, eradication, recovery, and follow-up actions.

## Evidence to Collect

| Evidence               | Description                                                                                                                            |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Alert & Detections     | Detection source, alert ID, severity, timestamp, detection reason, and related security alerts                                         |
| Hosts                  | Source and destination hostnames, endpoint identifiers, IP addresses, and operating systems                                            |
| Accounts & Identity    | Associated user, service, and privileged accounts, account privileges, session information, and identity-related changes               |
| Authentication         | Successful and failed logons, authentication methods, protocols, logon types, and timestamps                                           |
| Remote Access          | RDP, SMB, SSH, WinRM, RPC, and other remote service activity                                                                           |
| Process Activity       | Active processes, process trees, parent and child relationships, command-line activity, and execution metadata                         |
| Network & DNS          | Source and destination addresses, ports, protocols, connection records, DNS queries, and resolved destinations                         |
| Files & Tool Transfer  | Relevant files, hashes, suspicious artifacts, and unauthorized file or tool transfers                                                  |
| Privileged Activity    | Administrative operations, privileged access events, and unauthorized system-management activity                                       |
| Lateral Movement Scope | Additional affected hosts, accounts, services, and identified communication paths                                                      |
| Containment Status     | Host-isolation status, isolation timestamps, and applied network or identity restrictions                                              |
| Containment Actions    | Isolation mechanisms, firewall and access-control changes, account restrictions, session revocation, and operator or automation source |
| Timeline               | Initial detection, authentication, lateral movement, investigation, containment, and validation events                                 |
| Operational Impact     | Affected business services, system dependencies, operational impact, and approved exceptions                                           |

## Decision Criteria

### Benign

Classify the response as **benign** when:

- the observed remote access activity is associated with an authorized user or service;
- the source and destination systems have a documented operational relationship;
- authentication activity is consistent with approved administrative procedures;
- the observed remote service usage is expected;
- suspicious indicators are explained by authorized maintenance, testing, or system administration;
- no evidence of unauthorized access or lateral movement is identified.

Document the operational justification and supporting evidence before closing the response.

### Suspicious

Classify the response as **suspicious** when:

- remote access activity is unexplained;
- unusual authentication behavior is present;
- an account accesses systems outside its expected operational scope;
- administrative activity differs from established baselines;
- suspicious processes or network connections are detected;
- potential credential misuse is identified but not confirmed;
- the full scope of affected systems cannot yet be established;
- additional investigation is required.

Maintain appropriate containment controls while the investigation continues.

### Malicious

Classify the response as **malicious** when sufficient evidence indicates:

- confirmed unauthorized access between internal systems;
- confirmed use of compromised credentials;
- confirmed malicious remote service activity;
- confirmed exploitation of remote services;
- confirmed unauthorized remote execution;
- confirmed lateral transfer of malicious tools or files;
- confirmed use of compromised privileged accounts;
- confirmed movement across multiple endpoints or servers;
- continued unauthorized access attempts involving compromised systems;
- broader compromise requiring coordinated incident response.

Maintain or expand containment according to the incident-response procedure.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the observed activity represents malicious lateral movement.

Document:

- evidence collected;
- evidence unavailable;
- systems under investigation;
- associated accounts;
- observed authentication activity;
- remote services involved;
- containment status;
- telemetry limitations;
- unresolved investigation questions;
- additional investigation required.

Maintain appropriate security monitoring and containment controls based on the assessed risk.

## Escalation

Escalate the response when:

- active lateral movement is confirmed;
- multiple endpoints or servers are affected;
- privileged accounts are involved;
- domain or directory-service infrastructure may be compromised;
- credential compromise is confirmed or strongly suspected;
- remote access to critical business systems is unauthorized;
- exploitation of remote services is identified;
- malicious tools or files are transferred between systems;
- activity continues after initial containment;
- containment controls fail or are incomplete;
- additional network segments require coordinated restrictions;
- critical business services may be affected;
- identity infrastructure or privileged access systems require investigation;
- additional incident-response capabilities are required.

Ensure that containment decisions, authorization, and operational impact are documented.

## Response Guidance

For confirmed or high-confidence lateral movement:

1. Preserve relevant endpoint, authentication, identity, process, file, and network evidence.
2. Identify and validate the suspected source and destination systems, including associated user, service, and privileged accounts.
3. Determine the remote services, authentication methods, and suspicious activities involved.
4. Correlate endpoint, identity, authentication, and network telemetry to establish the lateral movement timeline.
5. Identify additional affected hosts, accounts, services, and communication paths to determine the required containment scope.
6. Follow the organization's approved host, network, and identity-containment procedures.
7. Restrict unauthorized remote access and lateral movement paths, and isolate affected hosts when required and authorized.
8. Coordinate credential containment, account restrictions, and session revocation where compromise is suspected.
9. Verify that unauthorized access and communication have been restricted and that required security-management connectivity remains available where supported.
10. Investigate the initial compromise, possible persistence mechanisms, and any additional systems or identities that may remain exposed.
11. Perform remediation and recovery according to the applicable incident-response procedures. Remove containment restrictions only after authorized validation confirms that recovery criteria have been satisfied.
12. Document the investigation, evidence, containment actions, validation results, remediation, recovery, and response timeline.

Do not restore unrestricted access solely because the initial suspicious activity has stopped. Maintain appropriate containment until authorized recovery criteria have been satisfied.

## Related Detection Rules

## Related Playbooks

- `playbooks/response/malware-response.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`

## Validation

The playbook should be validated against controlled lateral movement investigation and containment scenarios using approved endpoint telemetry, authentication logs, network monitoring, identity data, and documented incident-response procedures.

Validation should confirm that:

- suspicious source and destination systems can be identified and their identities validated;
- remote service activity and authentication events can be investigated and correlated;
- potentially compromised user, service, and privileged accounts can be identified;
- suspicious process execution and network activity can be analyzed;
- the lateral movement scope and additional affected systems can be established;
- containment requirements can be determined based on available evidence;
- authorized host-isolation controls can be applied and unauthorized remote access paths can be restricted;
- identity-containment actions can be coordinated and required security-management connectivity can be maintained where supported;
- containment effectiveness can be independently verified;
- operational impact and escalation requirements can be documented and assessed consistently;
- required evidence and investigation timelines can be preserved;
- recovery and containment removal follow approved authorization and validation procedures.

Validation should use isolated test systems, synthetic security events, approved administrative accounts, and controlled network environments.

Do not test lateral movement or containment procedures against production systems without explicit authorization.

## Safety

This playbook is intended for defensive security operations, incident response, security validation, controlled laboratory environments, and authorized testing only.

Lateral movement investigation and containment may involve privileged accounts, critical servers, directory services, network infrastructure, and business-critical applications.

Containment actions can interrupt remote administration, system management, authentication, application connectivity, and other operational services.
