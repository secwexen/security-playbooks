---
id: "ransomware-response"
name: "Ransomware Response"
category: "response"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-11-26T12:06:00Z"
updated_at: "2026-11-26T12:06:00Z"
description: "Ransomware Response provides a structured process for investigating ransomware incidents, identifying affected systems, containing malicious activity, preventing further encryption and lateral movement, and restoring affected services."
objective: "Identify, investigate, contain, and remediate ransomware incidents, determine the scope of affected systems and identities, prevent further encryption and unauthorized access, preserve forensic evidence, eradicate malicious activity, and restore affected services safely."
severity: "critical"
mitre_attack:
  - "T1486"
  - "T1490"
  - "T1489"
  - "T1059"
  - "T1021"
  - "T1078"
triggers:
  - "EDR, antivirus, or SIEM detects ransomware behavior"
  - "Files are unexpectedly encrypted, renamed, or become inaccessible"
  - "A ransom note is discovered on an endpoint or file server"
  - "Multiple systems exhibit similar suspicious encryption behavior"
  - "Backup files or recovery services are unexpectedly modified or deleted"
  - "Suspicious administrative or remote access activity precedes suspected ransomware activity"
  - "A user reports a ransomware message or suspected data encryption"
  - "Unexpected service termination or security tool impairment is detected"
prerequisites:
  - "Access to endpoint detection and response telemetry"
  - "Access to SIEM, system, authentication, and network logs"
  - "Access to endpoint and server administration capabilities"
  - "Access to backup infrastructure and recovery documentation"
  - "Access to network segmentation and isolation controls"
  - "Access to malware analysis and forensic investigation tools"
  - "Established incident escalation, evidence preservation, and recovery procedures"
tags:
  - "ransomware"
  - "incident-response"
  - "malware"
  - "encryption"
  - "containment"
  - "eradication"
  - "recovery"
  - "backup-security"
  - "endpoint-security"
  - "business-continuity"
references:
  - "https://attack.mitre.org/techniques/T1486/"
  - "https://attack.mitre.org/techniques/T1490/"
  - "https://attack.mitre.org/techniques/T1489/"
  - "https://attack.mitre.org/techniques/T1059/"
  - "https://attack.mitre.org/techniques/T1021/"
  - "https://attack.mitre.org/techniques/T1078/"
steps:
  - id: "identify-ransomware-alert"
    order: 1
    name: "Identify Ransomware Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, alert timestamp, suspicious process, encryption activity, ransom note, and initial incident context. Preserve the original alert and relevant telemetry."
    expected_result: "The suspected ransomware incident and initial affected assets are identified."
  - id: "analyze-ransomware-activity"
    order: 2
    name: "Analyze Ransomware Activity"
    action: "analyze"
    description: "Examine suspicious processes, file modifications, ransom notes, executable files, process trees, persistence mechanisms, command execution, and endpoint security detections. Analyze suspicious binaries in an approved isolated environment."
    expected_result: "Ransomware indicators, suspicious execution activity, and relevant evidence are documented."
  - id: "investigate-initial-access"
    order: 3
    name: "Investigate Initial Access"
    action: "investigate"
    description: "Review authentication events, remote access activity, exposed services, phishing reports, vulnerability exploitation indicators, suspicious scripts, and administrative activity. Determine the likely initial access method and execution path."
    expected_result: "The suspected initial access method and associated accounts or systems are identified."
  - id: "assess-incident-scope"
    order: 4
    name: "Assess Incident Scope"
    action: "investigate"
    description: "Search endpoint, identity, server, and network telemetry for related indicators. Identify encrypted systems, affected users, suspicious remote sessions, lateral movement, data access, backup impact, and potential data exfiltration."
    expected_result: "Affected systems, identities, services, and potential business impact are documented."
  - id: "contain-ransomware-activity"
    order: 5
    name: "Contain Ransomware Activity"
    action: "contain"
    description: "Apply approved containment measures to prevent additional encryption and lateral movement. Isolate affected endpoints and servers, restrict compromised accounts, revoke suspicious sessions, block confirmed malicious indicators, and protect backup infrastructure. Preserve evidence where operationally feasible."
    expected_result: "Ransomware activity is contained and further spread is restricted."
  - id: "eradicate-ransomware"
    order: 6
    name: "Eradicate Ransomware"
    action: "respond"
    description: "Remove confirmed malicious files, persistence mechanisms, unauthorized accounts, scheduled tasks, services, and remote access configurations. Remediate exploited vulnerabilities, compromised credentials, and other identified entry points. Rebuild systems when integrity cannot be established."
    expected_result: "Confirmed ransomware components and identified persistence or access mechanisms are removed or eliminated through approved rebuild procedures."
  - id: "restore-and-validate-systems"
    order: 7
    name: "Restore and Validate Systems"
    action: "respond"
    description: "Restore affected systems and data from verified clean backups or approved recovery sources. Validate backup integrity, system configuration, endpoint security controls, identity security, network connectivity, and application functionality before returning systems to production."
    expected_result: "Affected systems and services are safely restored and validated."
  - id: "determine-response-outcome"
    order: 8
    name: "Determine Response Outcome"
    action: "document"
    description: "Confirm containment, eradication, recovery, and security monitoring results. Document affected assets, incident timeline, root cause, evidence, business impact, recovery status, residual risks, and follow-up actions."
    expected_result: "The ransomware incident is assessed, recovery is validated, and the final response outcome is documented."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "Controlled ransomware-response exercise using isolated test systems, benign simulation artifacts, test identities, protected backup copies, endpoint and network telemetry, evidence preservation, containment, eradication, and recovery procedures."
---

# Ransomware Response

## Purpose

This playbook provides a structured incident-response workflow for suspected or confirmed ransomware attacks affecting organizational endpoints, servers, identity infrastructure, and business-critical services.

Ransomware is malicious activity that can encrypt files, disrupt services, disable recovery mechanisms, and prevent organizations from accessing critical information. Some ransomware operations also involve data theft, extortion, and threats to disclose sensitive information.

A ransomware incident may affect a single endpoint or develop into a wider compromise involving multiple systems, privileged accounts, file servers, virtualization infrastructure, and backup environments.

## MITRE ATT&CK

| Technique | Name                              | Relevance                                                                             |
| --------- | --------------------------------- | ------------------------------------------------------------------------------------- |
| T1486     | Data Encrypted for Impact         | Relevant when ransomware encrypts files or data to disrupt availability.              |
| T1490     | Inhibit System Recovery           | Relevant when recovery mechanisms, backups, or shadow copies are disabled or deleted. |
| T1489     | Service Stop                      | Relevant when services are stopped to facilitate encryption or disrupt operations.    |
| T1059     | Command and Scripting Interpreter | Relevant when command interpreters or scripts are used during ransomware activity.    |
| T1021     | Remote Services                   | Relevant when remote services are abused to access additional systems.                |
| T1078     | Valid Accounts                    | Relevant when legitimate accounts are abused to access organizational resources.      |

## Trigger Conditions

Initiate this playbook when:

- EDR, antivirus, or SIEM detects ransomware behavior.
- Files are unexpectedly encrypted, renamed, or become inaccessible.
- A ransom note appears on an endpoint or file server.
- Unusual file modification activity is detected across multiple directories.
- Multiple systems exhibit similar encryption behavior.
- Backup files, shadow copies, or recovery services are unexpectedly modified or deleted.
- Suspicious administrative activity precedes encryption.
- Unexpected remote access or authentication activity is identified.
- Security tools or endpoint protection services are disabled unexpectedly.
- A user reports a suspected ransomware infection.
- Critical business services become unavailable following suspicious endpoint activity.

## Scope

The investigation should consider:

- affected endpoints and servers;
- encrypted files and directories;
- ransom notes and file extensions;
- suspicious executables and process trees;
- file modification and encryption timestamps;
- process execution and command-line activity;
- persistence mechanisms;
- scheduled tasks and suspicious services;
- local and domain accounts;
- privileged account activity;
- remote access and lateral movement;
- authentication and session activity;
- network connections and communication with external infrastructure;
- backup repositories and recovery infrastructure;
- shadow copies and recovery configuration;
- file servers and shared storage;
- virtualization and cloud workloads;
- potential data staging or exfiltration;
- affected business applications;
- incident timeline and operational impact;
- containment, eradication, and recovery status.

## Investigation Procedure

### Step 1 - Identify Ransomware Alert

Identify the initial detection and establish the incident context.

Review:

- detection source;
- alert identifier;
- detection timestamp;
- affected hostname;
- affected user;
- endpoint operating system;
- suspicious process name;
- process identifier;
- parent process;
- file modification activity;
- ransom note location;
- suspicious file extensions;
- EDR or antivirus detection details;
- related alerts from other systems.

Preserve the original alert and relevant endpoint telemetry.

Determine whether the alert represents:

- confirmed file encryption;
- suspected ransomware execution;
- suspicious mass file modification;
- a ransom note without confirmed encryption;
- security control impairment;
- an unrelated or false-positive detection.

Do not assume that a ransom note alone proves successful encryption.

### Step 2 - Analyze Ransomware Activity

Examine the suspicious activity and identify indicators associated with ransomware execution.

Review:

- suspicious executable files;
- process creation events;
- parent-child process relationships;
- command-line arguments;
- PowerShell and command prompt activity;
- file creation, modification, and deletion events;
- unusual file extensions;
- ransom note contents;
- encryption-related behavior;
- scheduled tasks;
- suspicious services;
- registry modifications;
- security tool impairment;
- backup and recovery configuration changes;
- suspicious network connections.

Collect relevant indicators:

- file hashes;
- filenames and paths;
- process names;
- command-line arguments;
- IP addresses;
- domains;
- URLs;
- ransom note filenames;
- suspicious file extensions;
- timestamps.

Analyze suspicious binaries only in approved isolated environments.

Determine whether the observed activity is consistent with ransomware, another destructive malware family, or legitimate administrative activity.

### Step 3 - Investigate Initial Access

Determine how the attacker may have gained access to the environment.

Review:

- successful and failed authentication events;
- VPN and remote access logs;
- RDP and other remote service activity;
- exposed internet-facing services;
- suspicious email and phishing reports;
- endpoint exploitation alerts;
- vulnerability exploitation indicators;
- suspicious script execution;
- newly created accounts;
- privilege escalation activity;
- unusual administrative sessions;
- suspicious OAuth or application access;
- authentication from unfamiliar devices or locations.

Investigate whether the initial access involved:

- phishing;
- compromised credentials;
- exposed remote services;
- exploitation of vulnerable software;
- abuse of legitimate accounts;
- malicious scripts or executables;
- unauthorized remote administration.

Correlate authentication, endpoint, and network events to establish the likely intrusion timeline.

Document the initial access method as confirmed, suspected, or unknown.

### Step 4 - Assess Incident Scope

Determine how far the ransomware activity has spread and which organizational resources are affected.

Search endpoint, identity, server, and network telemetry for:

- matching file hashes;
- suspicious process names;
- ransom note filenames;
- unusual file extensions;
- mass file modification activity;
- suspicious command execution;
- unauthorized remote sessions;
- abnormal authentication events;
- newly created accounts;
- privileged account usage;
- suspicious scheduled tasks;
- unusual service creation;
- connections to known malicious infrastructure;
- backup modification or deletion;
- suspicious data staging or transfer.

Identify:

- affected endpoints;
- affected servers;
- affected user accounts;
- affected privileged accounts;
- affected file shares;
- affected databases;
- affected business applications;
- affected virtualization infrastructure;
- affected cloud workloads;
- affected backup systems;
- systems potentially accessed by the attacker;
- systems showing evidence of lateral movement.

Determine whether sensitive information may have been accessed or exfiltrated.

Record systems that cannot be examined because of unavailable telemetry or operational restrictions.

### Step 5 - Contain Ransomware Activity

Apply approved containment measures to prevent additional encryption, unauthorized access, and lateral movement.

Depending on incident severity, consider:

- isolating infected endpoints from the network;
- isolating affected servers where operationally feasible;
- restricting compromised user accounts;
- disabling compromised privileged accounts;
- revoking suspicious authentication sessions;
- rotating exposed credentials;
- blocking confirmed malicious IP addresses and domains;
- restricting suspicious remote access;
- disabling unauthorized remote administration;
- preventing access to affected file shares;
- protecting backup infrastructure;
- restricting unnecessary administrative access;
- preventing further malicious communication;
- coordinating containment across affected network segments.

Prioritize protecting:

- domain controllers;
- identity infrastructure;
- backup repositories;
- virtualization platforms;
- file servers;
- critical business applications;
- privileged administrative accounts.

Preserve forensic evidence before making changes where operationally feasible.

If encryption is actively spreading, prioritize immediate isolation to prevent additional impact.

### Step 6 - Eradicate Ransomware

Remove confirmed malicious components and eliminate the mechanisms used to maintain unauthorized access.

Investigate and remediate:

- malicious executables;
- unauthorized scheduled tasks;
- malicious services;
- persistence mechanisms;
- unauthorized accounts;
- compromised credentials;
- exposed authentication tokens;
- suspicious remote access configurations;
- unauthorized administrative permissions;
- malicious scripts;
- exploited vulnerabilities;
- unauthorized startup entries;
- compromised management tools;
- malicious endpoint modifications.

Perform the following actions where applicable:

- Remove confirmed malicious files using approved security procedures.
- Disable unauthorized accounts and access paths.
- Reset compromised credentials.
- Revoke exposed sessions and tokens.
- Remove unauthorized scheduled tasks and services.
- Remediate exploited vulnerabilities.
- Restore security controls that were disabled.
- Rebuild systems when integrity cannot be established.
- Verify that attacker access has been removed.
- Review connected systems for additional compromise.

Do not assume that deleting the ransomware executable is sufficient.

If a system's integrity cannot be established, rebuild it using trusted installation media and approved configuration baselines.

### Step 7 - Restore and Validate Systems

Restore affected systems and business services using verified clean recovery sources.

Review for:

- confirm that ransomware activity is contained;
- verify that malicious persistence has been removed;
- confirm that compromised credentials have been addressed;
- validate backup integrity;
- identify clean backup recovery points;
- verify that backup repositories have not been compromised;
- confirm that the initial access path has been remediated.

Recovery and validation:

- Restore affected files, applications, databases, and file shares from verified clean backups.
- Rebuild compromised endpoints and servers when system integrity cannot be established.
- Restore approved system configurations and identity access controls.
- Re-enable endpoint protection and security monitoring.
- Validate network segmentation, authentication, and backup services.
- Verify endpoint security status, system integrity, and account permissions.
- Confirm application availability, network connectivity, and security monitoring coverage.
- Ensure no suspicious processes or persistence mechanisms remain.

Restore critical business services according to the organization's recovery priorities and business continuity procedures.

Do not reconnect systems to production until required security validation is complete.

### Step 8 - Determine Response Outcome

Classify the incident as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the final incident classification, outstanding risks, and required follow-up actions.

## Evidence to Collect

| Evidence         | Description                                                     |
| ---------------- | --------------------------------------------------------------- |
| Alert            | Detection source, alert ID, severity, timestamp                 |
| Endpoint         | Hostname, operating system, affected user, EDR telemetry        |
| Process          | Process name, PID, parent process, command-line arguments       |
| Files            | Encrypted files, file extensions, filenames, file hashes        |
| Ransom Note      | Note filename, location, contents, timestamps                   |
| Malware          | Suspicious binaries, hashes, analysis results                   |
| Authentication   | Successful and failed logins, account activity, session records |
| Identity         | Privileged account activity, credential changes, token usage    |
| Network          | DNS, proxy, firewall, remote access, and connection logs        |
| Lateral Movement | Remote sessions, administrative activity, affected systems      |
| Persistence      | Scheduled tasks, services, startup entries, registry changes    |
| Backup           | Backup status, repository integrity, recovery points            |
| Data Access      | Suspicious file access, staging, and potential exfiltration     |
| Timeline         | Initial access, execution, encryption, containment, recovery    |
| Response         | Isolation, account restrictions, eradication, restoration       |
| Recovery         | Backup validation, restored systems, service validation         |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- file modifications are associated with verified legitimate processes;
- the activity has an approved operational purpose;
- no malicious execution or unauthorized access is identified;
- endpoint and network telemetry support legitimate activity;
- no evidence of unauthorized encryption or recovery impairment exists.

Do not classify unusual mass file modification as benign without investigating its source and operational context.

### Suspicious

Classify the activity as **suspicious** when:

- unusual file modifications are detected;
- suspicious scripts or executables are identified;
- unexpected administrative activity is observed;
- backup or recovery configurations change unexpectedly;
- security controls are impaired;
- remote access activity cannot be verified;
- available evidence is insufficient to confirm ransomware execution.

Continue investigation and assess whether containment is required.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- files have been encrypted by unauthorized activity;
- confirmed ransomware is executed;
- ransom notes are associated with malicious encryption;
- recovery mechanisms are deliberately impaired;
- multiple systems show coordinated ransomware behavior;
- compromised accounts are used to access additional systems;
- malicious activity disrupts organizational services;
- unauthorized data access or exfiltration is identified.

Escalate to the appropriate incident-response process and complete containment, eradication, and recovery activities.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to establish the incident scope or determine whether ransomware activity occurred.

Document:

- evidence collected;
- evidence unavailable;
- affected systems that could not be examined;
- missing endpoint or network telemetry;
- backup verification limitations;
- unresolved access paths;
- outstanding containment actions;
- additional investigation requirements.

## Escalation

Escalate the incident immediately when:

- ransomware execution is confirmed;
- multiple endpoints or servers are affected;
- domain controllers or identity infrastructure are compromised;
- privileged accounts are involved;
- backup infrastructure is affected;
- critical business services become unavailable;
- sensitive information may have been exfiltrated;
- lateral movement is identified;
- security controls are disabled;
- recovery cannot be completed using verified backups;
- the incident has a significant operational, financial, or regulatory impact.

Coordinate with incident response, security operations, infrastructure, identity, legal, privacy, and business continuity teams as appropriate.

## Response Guidance

For confirmed ransomware incidents:

1. Preserve relevant alerts, endpoint telemetry, ransom notes, and forensic evidence.
2. Identify affected endpoints, servers, identities, and business services.
3. Determine the likely initial access method.
4. Investigate suspicious execution, persistence, and lateral movement.
5. Determine whether data access or exfiltration may have occurred.
6. Isolate affected systems to prevent additional encryption.
7. Restrict compromised accounts and revoke suspicious sessions.
8. Protect backup infrastructure and verify recovery sources.
9. Remove confirmed malicious components and persistence mechanisms.
10. Remediate vulnerabilities and compromised access paths.
11. Restore affected systems from verified clean backups or trusted sources.
12. Validate system integrity and security controls before reconnecting systems.
13. Monitor the environment for recurring malicious activity.
14. Document the incident outcome, business impact, and follow-up requirements.

Do not assume that paying a ransom will restore systems, prevent data disclosure, or eliminate attacker access. Follow organizational policy and obtain appropriate legal and executive guidance for extortion-related decisions.

## Related Playbooks

- `playbooks/response/malware-response.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/persistence-removal-response.md`
- `playbooks/initial-access/phishing.md`

## Validation

The playbook should be validated through controlled ransomware-response exercises using isolated test systems, benign simulation artifacts, test identities, protected backup copies, endpoint telemetry, and documented recovery procedures.

Validation should confirm that:

- ransomware alerts can be identified and investigated;
- suspicious processes and file modifications can be analyzed;
- initial access can be investigated;
- affected systems and identities can be identified;
- lateral movement can be assessed;
- potential data exfiltration can be investigated;
- affected systems can be isolated;
- compromised accounts and sessions can be secured;
- backup infrastructure can be protected;
- malicious persistence can be identified and removed;
- clean recovery sources can be verified;
- affected systems can be restored safely;
- endpoint and network security controls can be validated;
- business services can be recovered;
- residual risks and response outcomes can be documented.

## Safety

This playbook is intended for defensive security operations, incident response, controlled security exercises, and authorized testing only. Use isolated test systems and benign simulation artifacts during validation.

Do not execute live ransomware in production environments or on systems containing organizational data. Preserve forensic evidence and coordinate destructive or disruptive containment actions with authorized incident-response personnel.

Validate backup integrity before initiating recovery. Never assume that a backup is clean solely because it completed successfully.
