---
id: "browser-data"
name: "Browser Data Collection"
category: "collection"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-27T18:56:00Z"
updated_at: "2026-10-27T18:56:00Z"
description: "Investigate suspicious access to web browser profiles and the collection of browser-related information."
objective: "Determine whether browser data was accessed or collected without authorization, identify the affected users and systems, establish the scope of activity, and support appropriate incident response."
severity: "medium"
mitre_attack:
  - "T1005"
  - "T1217"
triggers:
  - "Unexpected access to browser profile directories or browser data files"
  - "Suspicious enumeration of browser history, bookmarks, downloads, or extensions"
  - "Unusual processes reading browser profile databases"
  - "Unexpected copying, staging, or archiving of browser-related artifacts"
  - "Browser data access associated with suspicious process or network activity"
prerequisites:
  - "Access to endpoint process creation and command-line telemetry"
  - "Access to available file access and file creation telemetry"
  - "Access to browser profile and endpoint inventory information"
  - "Access to relevant network telemetry when data transfer is suspected"
  - "Authorization to examine browser artifacts and associated user data"
tags:
  - "browser-data"
  - "collection"
  - "browser"
  - "endpoint"
  - "data-access"
  - "windows"
  - "linux"
  - "macos"
references:
  - "https://attack.mitre.org/techniques/T1005/"
  - "https://attack.mitre.org/techniques/T1217/"
steps:
  - id: "identify-browser-data-alert"
    order: 1
    name: "Identify Browser Data Alert"
    action: "investigate"
    description: "Identify the alert, detection source, observed browser data access, associated process, and event timestamp."
    expected_result: "The reported activity and its initial investigation context are documented."
  - id: "identify-affected-host-user"
    order: 2
    name: "Identify Affected Host and User"
    action: "investigate"
    description: "Identify the affected endpoint, associated user, asset criticality, and relevant account context."
    expected_result: "The affected host, user, and relevant asset context are identified."
  - id: "identify-browser-profiles"
    order: 3
    name: "Identify Browser Profiles"
    action: "analyze"
    description: "Identify the browser application, relevant user profiles, profile locations, and browser versions where available."
    expected_result: "The potentially affected browser applications and profiles are identified."
  - id: "review-browser-artifacts"
    order: 4
    name: "Review Browser Artifacts"
    action: "analyze"
    description: "Review authorized telemetry concerning access to browser history, bookmarks, downloads, extension inventory, profile configuration, and related local databases."
    expected_result: "Relevant browser artifacts and access activity are documented without unnecessarily exposing sensitive user data."
  - id: "review-process-file-activity"
    order: 5
    name: "Review Process and File Activity"
    action: "analyze"
    description: "Correlate browser artifact access with process lineage, command-line arguments, file creation, file copying, and the associated user context."
    expected_result: "The process and file activity associated with browser data access is characterized."
  - id: "review-collection-staging"
    order: 6
    name: "Review Collection and Staging Activity"
    action: "analyze"
    description: "Determine whether browser-related artifacts were copied, consolidated, compressed, staged, or transferred in a manner inconsistent with authorized activity."
    expected_result: "Potential collection, staging, or transfer activity is identified and correlated with available evidence."
  - id: "determine-collection-scope"
    order: 7
    name: "Determine Collection Scope"
    action: "hunt"
    description: "Search for related activity across affected users and endpoints using relevant process, file, profile, and timeline indicators."
    expected_result: "The affected profiles, endpoints, time range, and potential extent of browser data collection are documented."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity using the available evidence and document the rationale, scope, and required follow-up actions."
    expected_result: "The investigation outcome and supporting evidence are documented."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "browser-data-collection"
---

# Browser Data Collection

## Purpose

This playbook provides a structured workflow for investigating suspicious access to web browser profiles and the collection of browser-related information.

Browser profiles may contain browsing history, bookmarks, download records, extension information, configuration data, and locally stored databases. These artifacts may reveal user activity, sensitive personal information, and details about internal resources.

The objective is to determine whether browser data was accessed or collected for an authorized purpose, establish the scope of suspicious activity, and identify whether additional incident response is required.

This playbook focuses on browser information and associated artifacts. Suspected extraction of saved credentials or misuse of session tokens must also be assessed through the appropriate credential-access investigation workflow.

## MITRE ATT&CK

| Technique | Name                          | Relevance                                                                                             |
| --------- | ----------------------------- | ----------------------------------------------------------------------------------------------------- |
| T1005     | Data from Local System        | Relevant when browser-related data is collected from local files, databases, or other system sources. |
| T1217     | Browser Information Discovery | Relevant when browser profiles, history, bookmarks, or other browser information are enumerated.      |

Technique mappings must reflect observed behavior. Browser data access alone does not establish malicious intent.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An unexpected process accesses browser profile directories or browser data files.
- Browser history, bookmarks, or extension information is enumerated by an unusual process.
- Browser-related databases are accessed by an unapproved script or utility.
- Browser artifacts are copied or staged in an unexpected location.
- Browser data access is associated with suspicious archiving or outbound transfer activity.
- Threat hunting identifies anomalous access to browser profile data.
- Endpoint telemetry indicates possible browser data collection associated with a broader incident.

## Scope

The investigation should consider:

- affected host;
- associated user account;
- browser application and version;
- browser profile identifiers and locations;
- browsing history;
- bookmarks;
- download records;
- extension inventory;
- browser profile configuration;
- relevant local browser databases;
- processes accessing browser artifacts;
- process lineage and command-line arguments;
- file access, creation, and modification events;
- copying, archiving, or staging activity;
- related network connections;
- relevant authentication events;
- related alerts;
- additional affected users or endpoints.

Saved passwords, authentication tokens, cookies, and other session-related secrets require additional protection and, where appropriate, a separate credential-access investigation.

## Investigation Procedure

### Step 1 — Identify Browser Data Alert

Record the detection source, alert identifier, timestamp, affected endpoint, observed process, and reported browser data access.

Collect:

- alert identifier;
- detection rule name and identifier, where available;
- detection source;
- alert severity and confidence;
- event timestamp and first observed time;
- affected hostname and associated user;
- process name and executable path;
- process identifier and parent process, where available;
- observed command-line arguments;
- browser application or profile associated with the activity;
- initial evidence indicating browser artifact access.

Determine what triggered the investigation and preserve the original alert context.

### Step 2 — Identify Affected Host and User

Identify the endpoint and user account associated with the activity.

Collect:

- hostname and IP address;
- operating system and version;
- endpoint identifier and asset type;
- asset owner and business criticality, where available;
- username and account identifier;
- domain or identity provider;
- account type and privilege level;
- relevant logon session and authentication context;
- browser application and associated user profile;
- process execution timestamp and associated security context;
- endpoint isolation status, where applicable;
- related alerts involving the same host or user.

Collect the hostname, asset type, operating system, user identifier, account type, and asset criticality where available.

Determine whether the activity occurred on a workstation, server, administrative endpoint, or another sensitive system.

### Step 3 — Identify Browser Profiles

Identify the browser applications and profiles relevant to the investigation.

Review available endpoint inventory and authorized telemetry to establish:

- browser name and version;
- affected user profile;
- profile location;
- relevant browser processes;
- profile ownership and access context;
- expected browser usage for the account.

Do not assume that every browser profile on the endpoint was accessed or affected.

### Step 4 — Review Browser Artifacts

Determine which browser-related artifacts were accessed and whether that access was expected.

Review available telemetry concerning:

- history and bookmark databases;
- download records;
- extension inventory and configuration;
- browser profile settings;
- relevant local database files;
- file access timestamps and associated processes.

Correlate the observed activity with normal browser operation, approved administration, endpoint security tools, and documented investigation activity.

Do not classify activity as malicious solely because a process reads a browser profile.

### Step 5 — Review Process and File Activity

Review the process responsible for accessing browser-related artifacts.

Collect and correlate:

- process name and executable path;
- process identifier and parent process;
- process lineage;
- command-line arguments;
- execution timestamp;
- associated user and security context;
- files read, created, copied, or modified;
- file hashes and digital signatures where relevant;
- related process and endpoint alerts.

Assess whether the process and its behavior are consistent with approved administrative or security activity.

### Step 6 — Review Collection and Staging Activity

Determine whether browser-related data was collected beyond ordinary browser operation.

Review available evidence for:

- unexpected copying of browser artifacts;
- aggregation of data from multiple profiles;
- creation of archives containing browser-related files;
- staging in temporary or user-writable directories;
- transfer to unexpected destinations;
- related command execution or suspicious process activity.

Correlate any suspected transfer with network telemetry and other available evidence. Do not infer successful data exfiltration from file access or archive creation alone.

### Step 7 — Determine Collection Scope

Establish the scope and timeline of the suspected activity.

Search for related indicators across relevant endpoints and users, including:

- the same executable or process behavior;
- repeated access to browser profile locations;
- the same file hashes or staging paths;
- related archive creation;
- similar activity involving other browser applications;
- related network connections or alerts.

Document the first and last observed events, affected profiles, affected endpoints, relevant artifacts, and any uncertainty caused by missing telemetry.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Record the evidence supporting the classification, the scope of activity, and any required escalation or remediation.

## Evidence to Collect

| Evidence          | Description                                                      |
| ----------------- | ---------------------------------------------------------------- |
| Alert             | Detection source, identifier, severity, and timestamp            |
| Host              | Hostname, operating system, asset type, and criticality          |
| User              | Associated account and relevant security context                 |
| Browser           | Browser application, version, and relevant profile               |
| Browser Artifacts | Types of browser data accessed                                   |
| Process           | Executable path, process ID, command line, and timestamp         |
| Process Lineage   | Parent process, child processes, and related execution activity  |
| File Activity     | Relevant file access, creation, modification, and copying events |
| File Metadata     | File paths, timestamps, hashes, and signatures where applicable  |
| Staging           | Evidence of data aggregation, archive creation, or staging       |
| Network           | Relevant connections and destinations                            |
| Timeline          | Correlated process, file, and network events                     |
| Scope             | Affected users, profiles, and endpoints                          |
| Detections        | Related alerts and detection identifiers                         |

Collect only the information necessary for the investigation. Sensitive browser contents should be handled according to approved evidence-handling and data-protection procedures.

## Decision Criteria

### Benign

Classify the activity as **benign** when available evidence supports an authorized explanation, such as:

- the process is associated with an approved browser, administration, backup, or security workflow;
- the user and endpoint context are expected;
- the observed access matches documented operational activity;
- no unauthorized collection or staging behavior is identified;
- no suspicious related process or network activity is observed.

Document the justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when one or more unexplained indicators are present, such as:

- an unexpected process accesses browser profile artifacts;
- browser data is copied to an unusual location;
- multiple browser profiles are accessed without an established operational reason;
- archive creation follows unexplained browser artifact access;
- process lineage or command-line arguments are inconsistent with expected activity;
- related telemetry suggests possible transfer or staging;
- insufficient evidence is available to establish a legitimate purpose.

Continue the investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence establishes unauthorized browser data collection or its association with confirmed malicious behavior, such as:

- confirmed unauthorized collection of browser information;
- browser artifact collection by a verified malicious process;
- browser data staging associated with a confirmed compromise;
- browser data transfer to an unauthorized destination supported by corroborating evidence;
- browser data collection associated with credential theft, session compromise, or other confirmed malicious activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether browser data access was authorized.

Document:

- evidence collected;
- relevant telemetry that is unavailable;
- unresolved access or ownership questions;
- additional endpoint or network evidence required;
- the reason a definitive classification cannot be made.

## Escalation

Escalate the investigation when:

- unauthorized browser data collection is suspected or confirmed;
- sensitive browser information may have been exposed;
- activity affects multiple user profiles or endpoints;
- browser artifact access is associated with suspicious staging or transfer;
- evidence indicates possible credential theft or session compromise;
- the activity is associated with malware, persistence, or broader endpoint compromise;
- required evidence is unavailable and the potential impact is significant.

Use the appropriate credential-access or incident-response playbook when the investigation identifies activity outside the scope of browser information collection.

## Response Guidance

For confirmed malicious browser data collection:

1. Preserve relevant process, file, browser profile, and network evidence.
2. Identify affected endpoints, users, browser profiles, and time ranges.
3. Follow the organization's endpoint containment and incident-response procedures.
4. Determine whether browser data was copied, staged, or transferred.
5. Investigate related credential access, session misuse, persistence, and lateral movement.
6. Assess potential exposure of personal information and organizational data.
7. Coordinate any browser profile remediation or credential/session invalidation with the appropriate system and identity owners.
8. Remove unauthorized artifacts only after evidence preservation and required authorization.
9. Document the investigation timeline, scope, findings, and remediation actions.

Do not indiscriminately delete browser profiles or reset user data before the impact and evidence-preservation requirements have been assessed.

## Related Detection Rules

## Related Playbooks

- `playbooks/credential-access/browser-credential-theft.md`
- `playbooks/credential-access/credentials-from-password-stores.md`
- `playbooks/collection/archive-collected-data.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/data-exfiltration-triage.md`

## Validation

The playbook should be validated against authorized browser profile access scenarios, endpoint process telemetry, file access records, and controlled data-collection simulations.

Validation should confirm that:

- relevant browser applications and profiles can be identified;
- browser artifact access can be correlated with process activity;
- expected browser operation can be distinguished from anomalous access;
- copying, staging, and archive creation can be investigated;
- related network activity can be correlated where telemetry is available;
- the scope of suspected collection can be established;
- investigation outcomes and escalation criteria are applied consistently;
- sensitive browser data is handled according to evidence-preservation and privacy requirements.

The playbook must not be considered validated until the required validation has been completed and documented.

## Safety

This playbook is intended for defensive security operations, authorized investigations, security validation, and controlled laboratory testing.

Browser profiles may contain personal information, saved credentials, session tokens, and other sensitive data. Access browser artifacts only when authorized and collect the minimum information necessary for the investigation.

Do not expose passwords, session tokens, cookies, or other authentication secrets in tickets, reports, logs, or public issue trackers. Preserve evidence using approved procedures and follow applicable privacy, retention, and access-control requirements.
