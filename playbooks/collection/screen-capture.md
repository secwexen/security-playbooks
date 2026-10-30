---
id: "screen-capture"
name: "Screen Capture Collection"
category: "collection"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-30T18:18:00Z"
updated_at: "2026-10-30T18:18:00Z"
description: "Investigate suspicious screen capture activity and the unauthorized collection of screenshots or displayed visual information."
objective: "Determine whether screen content was captured or collected without authorization, identify the affected users and systems, establish the scope of activity, and support appropriate incident response."
severity: "medium"
mitre_attack:
  - "T1113"
triggers:
  - "Unexpected screen capture activity on an endpoint"
  - "Suspicious processes accessing screen capture or desktop recording functionality"
  - "Unexpected creation of screenshot or screen recording files"
  - "Screen capture activity associated with suspicious process execution"
  - "Unexpected collection, staging, or transfer of captured screen content"
  - "Screen recording activity occurring outside approved business or support workflows"
prerequisites:
  - "Access to endpoint process creation and command-line telemetry"
  - "Access to available file creation and file access telemetry"
  - "Access to endpoint application and process inventory"
  - "Access to relevant network telemetry when data transfer is suspected"
  - "Authorization to investigate screen capture activity and associated user data"
tags:
  - "screen-capture"
  - "collection"
  - "screenshots"
  - "screen-recording"
  - "endpoint"
  - "data-collection"
  - "windows"
  - "linux"
  - "macos"
references:
  - "https://attack.mitre.org/techniques/T1113/"
steps:
  - id: "identify-screen-capture-alert"
    order: 1
    name: "Identify Screen Capture Alert"
    action: "investigate"
    description: "Identify the alert, detection source, observed screen capture activity, associated process, and event timestamp."
    expected_result: "The reported activity and its initial investigation context are documented."
  - id: "identify-affected-host-user"
    order: 2
    name: "Identify Affected Host and User"
    action: "investigate"
    description: "Identify the affected endpoint, associated user, asset criticality, and relevant account context."
    expected_result: "The affected host, user, and relevant asset context are identified."
  - id: "identify-capture-mechanism"
    order: 3
    name: "Identify Capture Mechanism"
    action: "analyze"
    description: "Identify the application, process, API, or operating system functionality associated with screen capture activity."
    expected_result: "The suspected screen capture mechanism and associated application are identified."
  - id: "review-capture-artifacts"
    order: 4
    name: "Review Capture Artifacts"
    action: "analyze"
    description: "Review authorized telemetry concerning screenshot files, screen recordings, file metadata, and associated creation events."
    expected_result: "Relevant capture artifacts and their associated activity are documented without unnecessarily exposing sensitive visual information."
  - id: "review-process-activity"
    order: 5
    name: "Review Process Activity"
    action: "analyze"
    description: "Correlate screen capture activity with process lineage, command-line arguments, execution context, and related endpoint events."
    expected_result: "The process activity associated with screen capture is characterized."
  - id: "review-collection-staging"
    order: 6
    name: "Review Collection and Staging Activity"
    action: "analyze"
    description: "Determine whether captured screen content was copied, consolidated, compressed, staged, or transferred in a manner inconsistent with authorized activity."
    expected_result: "Potential collection, staging, or transfer activity is identified and correlated with available evidence."
  - id: "determine-capture-scope"
    order: 7
    name: "Determine Capture Scope"
    action: "hunt"
    description: "Search for related activity across affected users and endpoints using relevant process, file, application, and timeline indicators."
    expected_result: "The affected endpoints, users, capture artifacts, time range, and potential extent of screen capture activity are documented."
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
  scenario: "screen-capture-collection"
---

# Screen Capture Collection

## Purpose

This playbook provides a structured workflow for investigating suspicious screen capture activity and the unauthorized collection of screenshots or displayed visual information.

Screen captures may contain sensitive information, including business documents, internal applications, customer information, authentication prompts, administrative interfaces, and other confidential data visible on an endpoint.

Screen capture activity may be performed by legitimate applications, remote support utilities, accessibility tools, collaboration software, monitoring solutions, or malicious processes.

The objective is to determine whether screen content was captured for an authorized purpose, establish the scope of suspicious activity, and identify whether additional incident response is required.

This playbook focuses on screenshot and screen recording collection. Suspected keylogging, credential theft, or session hijacking must also be assessed through the appropriate credential-access investigation workflow.

## MITRE ATT&CK

| Technique | Name                 | Relevance                                                                                         |
| --------- | -------------------- | ------------------------------------------------------------------------------------------------- |
| T1113     | Screen Capture       | Relevant when an application or process captures screenshots or records displayed screen content. |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An unexpected process performs screen capture operations.
- Screenshot files are created in unusual directories.
- Screen recording functionality is accessed by an unapproved application.
- Repeated screen capture activity occurs without an established operational purpose.
- Captured screen content is collected or staged unexpectedly.
- Screen capture activity is associated with suspicious process execution.
- Screen recording activity is followed by unexpected outbound network connections.
- Threat hunting identifies anomalous screenshot or screen recording behavior.
- Endpoint telemetry indicates possible screen capture associated with a broader incident.

## Scope

The investigation should consider:

- affected host;
- associated user account;
- operating system and version;
- application performing the capture;
- capture mechanism and relevant operating system functionality;
- screenshot files;
- screen recording files;
- file creation and modification timestamps;
- capture frequency and execution timeline;
- process lineage and command-line arguments;
- associated user and security context;
- file access, creation, copying, and modification events;
- temporary and staging directories;
- archive creation and data aggregation;
- related network connections;
- relevant authentication events;
- related alerts;
- additional affected users or endpoints.

Captured images and recordings may contain confidential information, personal information, or authentication-related content. Their contents must be handled according to approved evidence-handling and data-protection procedures.

## Investigation Procedure

### Step 1 — Identify Screen Capture Alert

Record the detection source, alert identifier, timestamp, affected endpoint, observed process, and reported screen capture activity.

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
- suspected capture application or mechanism;
- initial evidence indicating screenshot or screen recording activity.

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
- process execution timestamp and associated security context;
- endpoint isolation status, where applicable;
- related alerts involving the same host or user.

Determine whether the activity occurred on a workstation, server, administrative endpoint, or another sensitive system.

Identify whether the affected user was actively logged in during the observed capture activity.

### Step 3 — Identify Capture Mechanism

Identify the application, process, or operating system functionality associated with screen capture activity.

Review available endpoint inventory and authorized telemetry to establish:

- application name and version;
- executable path;
- process identifier;
- parent process;
- process execution context;
- relevant screen capture functionality;
- associated operating system APIs or services, where telemetry is available;
- application publisher and digital signature;
- application installation and execution history;
- expected use of screen capture functionality.

Determine whether the application is associated with approved remote support, collaboration, accessibility, monitoring, or administrative operations.

Do not assume that every application using screen capture functionality is malicious.

### Step 4 — Review Capture Artifacts

Determine whether screenshot or screen recording artifacts were created and whether their creation was expected.

Review available telemetry concerning:

- screenshot files;
- screen recording files;
- image and video file formats;
- file creation timestamps;
- file modification timestamps;
- file sizes;
- file ownership and permissions;
- file hashes where applicable;
- storage locations;
- associated processes;
- temporary or staging directories.

Correlate the observed activity with normal application operation, approved monitoring tools, remote support sessions, and documented business workflows.

Do not unnecessarily open or distribute captured images. Where possible, use file metadata and endpoint telemetry to establish the nature and scope of the activity.

### Step 5 — Review Process Activity

Review the process responsible for performing screen capture operations.

Collect and correlate:

- process name and executable path;
- process identifier and parent process;
- process lineage;
- command-line arguments;
- execution timestamp;
- associated user and security context;
- process integrity level, where available;
- application publisher and digital signature;
- relevant child processes;
- files created or modified;
- related process and endpoint alerts.

Assess whether the process and its behavior are consistent with approved application functionality or documented administrative activity.

Determine whether screen capture activity occurred as part of normal application execution or an unexpected process workflow.

### Step 6 — Review Collection and Staging Activity

Determine whether captured screen content was collected beyond ordinary application operation.

Review available evidence for:

- repeated screenshot creation;
- continuous or unexpected screen recording;
- aggregation of multiple captured images;
- copying of screenshots to unusual directories;
- creation of archives containing captured content;
- staging in temporary or user-writable directories;
- unexpected synchronization or upload activity;
- transfer to unexpected destinations;
- related command execution or suspicious process activity.

Correlate any suspected transfer with network telemetry and other available evidence.

Do not infer successful data exfiltration from screenshot creation, file copying, or archive creation alone.

### Step 7 — Determine Capture Scope

Establish the scope and timeline of the suspected activity.

Search for related indicators across relevant endpoints and users, including:

- the same executable or process behavior;
- repeated screen capture operations;
- similar screenshot or recording file creation;
- identical file hashes;
- common staging locations;
- related archive creation;
- similar activity involving other applications;
- related network connections or alerts.

Document:

- first and last observed events;
- affected endpoints;
- affected users;
- capture application and mechanism;
- number and types of capture artifacts, where available;
- relevant file locations;
- suspected collection and transfer activity;
- related security events;
- uncertainty caused by missing telemetry.

Determine whether the activity was limited to one endpoint or represents a broader collection operation.

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
| Application       | Capture application, version, executable path, and publisher     |
| Capture Mechanism | Relevant capture functionality and associated process            |
| Capture Artifacts | Screenshot and screen recording files                            |
| File Metadata     | File paths, timestamps, sizes, hashes, and permissions           |
| Process           | Executable path, process ID, command line, and timestamp         |
| Process Lineage   | Parent process, child processes, and related execution activity  |
| File Activity     | Relevant file access, creation, modification, and copying events |
| Staging           | Evidence of data aggregation, archive creation, or staging       |
| Network           | Relevant connections and destinations                            |
| Timeline          | Correlated process, file, and network events                     |
| Scope             | Affected users, endpoints, and capture artifacts                 |
| Detections        | Related alerts and detection identifiers                         |

## Decision Criteria

### Benign

Classify the activity as **benign** when available evidence supports an authorized explanation, such as:

- the process is associated with an approved screen recording, remote support, collaboration, accessibility, or monitoring application;
- the user and endpoint context are expected;
- the observed capture activity matches documented operational activity;
- the capture files are stored in expected application directories;
- no unauthorized collection or staging behavior is identified;
- no suspicious related process or network activity is observed.

Document the justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when one or more unexplained indicators are present, such as:

- an unexpected process performs screen capture operations;
- screenshots are created in unusual directories;
- repeated capture activity occurs without an established operational reason;
- screen recording occurs outside an approved workflow;
- multiple captured images are collected or consolidated unexpectedly;
- archive creation follows unexplained screen capture activity;
- process lineage or command-line arguments are inconsistent with expected activity;
- related telemetry suggests possible transfer or staging;
- insufficient evidence is available to establish a legitimate purpose.

Continue the investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence establishes unauthorized screen capture collection or its association with confirmed malicious behavior, such as:

- confirmed unauthorized screenshot or screen recording collection;
- screen capture performed by a verified malicious process;
- captured content staged as part of a confirmed compromise;
- screen recording or screenshots transferred to an unauthorized destination with corroborating evidence;
- screen capture activity associated with confirmed espionage, credential theft, or broader malicious activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether screen capture activity was authorized.

Document:

- evidence collected;
- relevant telemetry that is unavailable;
- unresolved application or ownership questions;
- additional endpoint or network evidence required;
- the reason a definitive classification cannot be made.

## Escalation

Escalate the investigation when:

- unauthorized screen capture is suspected or confirmed;
- sensitive visual information may have been exposed;
- activity affects multiple users or endpoints;
- captured content is associated with suspicious staging or transfer;
- screen capture activity is associated with malware or broader endpoint compromise;
- captured information may include authentication prompts, confidential documents, or sensitive organizational information;
- the activity is associated with persistence, surveillance, or other malicious behavior;
- required evidence is unavailable and the potential impact is significant.

Use the appropriate credential-access, surveillance, or incident-response playbook when the investigation identifies activity outside the scope of screen capture collection.

## Response Guidance

For confirmed malicious screen capture collection:

1. Preserve relevant process, file, application, and network evidence.
2. Identify affected endpoints, users, capture applications, and time ranges.
3. Follow the organization's endpoint containment and incident-response procedures.
4. Determine whether screenshots or recordings were copied, staged, archived, or transferred.
5. Investigate related keylogging, credential access, persistence, and lateral movement.
6. Assess potential exposure of personal information, authentication-related content, and organizational data.
7. Coordinate any required account protection or session invalidation with the appropriate system and identity owners.
8. Remove unauthorized capture software or artifacts only after evidence preservation and required authorization.
9. Document the investigation timeline, scope, findings, and remediation actions.

Do not indiscriminately delete screenshot files, recordings, or associated applications before the impact and evidence-preservation requirements have been assessed.

## Related Detection Rules

## Related Playbooks

- `playbooks/collection/archive-collected-data.md`
- `playbooks/collection/keylogging.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/data-exfiltration-triage.md`

## Validation

The playbook should be validated against authorized screen capture applications, endpoint process telemetry, file creation records, and controlled screen capture simulations.

Validation should confirm that:

- relevant capture applications and processes can be identified;
- screen capture activity can be correlated with process execution;
- expected screen capture operations can be distinguished from anomalous behavior;
- screenshot and recording artifacts can be investigated through file metadata;
- copying, staging, and archive creation can be investigated;
- related network activity can be correlated where telemetry is available;
- the scope of suspected collection can be established;
- investigation outcomes and escalation criteria are applied consistently;
- sensitive captured content is handled according to evidence-preservation and privacy requirements.

The playbook must not be considered validated until the required validation has been completed and documented.

## Safety

This playbook is intended for defensive security operations, authorized investigations, security validation, and controlled laboratory testing.

Screen captures and recordings may contain personal information, confidential documents, authentication prompts, internal communications, and other sensitive visual information.

Access captured content only when authorized and collect the minimum information necessary for the investigation.

Do not expose passwords, authentication tokens, session information, personal information, or confidential screenshots in tickets, reports, logs, or public issue trackers.

Preserve evidence using approved procedures and follow applicable privacy, retention, and access-control requirements.
