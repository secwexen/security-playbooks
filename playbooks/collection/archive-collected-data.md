---
id: "archive-collected-data"
name: "Archive Collected Data"
category: "collection"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-26T16:32:00Z"
updated_at: "2026-10-26T16:32:00Z"
description: "Investigate suspicious compression, archiving, or encryption of collected data that may indicate preparation for unauthorized data transfer."
objective: "Determine whether observed archiving activity is authorized, suspicious, or malicious; identify the affected data, associated processes, and potential relationship to data exfiltration."
severity: "high"
mitre_attack:
  - "T1560"
  - "T1560.001"
  - "T1560.002"
  - "T1560.003"
triggers:
  - "Unexpected creation of compressed or encrypted archives"
  - "Archiving activity involving sensitive or restricted data"
  - "Unusual use of compression or archiving utilities"
  - "Script or application execution followed by archive creation"
  - "Archive creation in temporary, staging, or user-writable directories"
  - "Archiving activity associated with suspicious network connections"
prerequisites:
  - "Access to endpoint process and command-line telemetry"
  - "Access to file creation and modification telemetry"
  - "Access to relevant file metadata and hashes"
  - "Access to authentication and account activity"
  - "Access to network telemetry where available"
  - "Access to data classification and authorized administrative activity records"
tags:
  - "collection"
  - "data-archiving"
  - "compression"
  - "encryption"
  - "exfiltration"
  - "endpoint"
references:
  - "https://attack.mitre.org/techniques/T1560/"
  - "https://attack.mitre.org/techniques/T1560/001/"
  - "https://attack.mitre.org/techniques/T1560/002/"
  - "https://attack.mitre.org/techniques/T1560/003/"
steps:
  - id: "identify-archive-alert"
    order: 1
    name: "Identify Archive Activity Alert"
    action: "investigate"
    description: "Identify the detection source, affected host, associated account, event timestamp, and indicators that triggered the investigation."
    expected_result: "The archive-related activity and initial detection context are documented."
  - id: "identify-archive-artifact"
    order: 2
    name: "Identify the Archive Artifact"
    action: "analyze"
    description: "Identify the created or modified archive, its path, file type, size, timestamps, and available cryptographic hashes."
    expected_result: "The archive artifact and its relevant metadata are identified."
  - id: "review-archiving-process"
    order: 3
    name: "Review the Archiving Process"
    action: "analyze"
    description: "Examine the process, command line, parent-child relationships, execution context, and application or library activity associated with archive creation."
    expected_result: "The process and execution context responsible for archiving are characterized."
  - id: "inspect-archive-metadata"
    order: 4
    name: "Inspect Archive Contents and Metadata"
    action: "analyze"
    description: "Determine the archive format, available file listing, contained data categories, encryption indicators, and potential sensitivity of the archived information using approved evidence-handling procedures."
    expected_result: "The archive's observable characteristics and potential data sensitivity are documented."
  - id: "review-source-data"
    order: 5
    name: "Review Source Data and Collection Context"
    action: "analyze"
    description: "Identify the original files or data sources, their locations, ownership, access permissions, and the activity preceding archive creation."
    expected_result: "The source data and the context of its collection are established where available."
  - id: "correlate-exfiltration-activity"
    order: 6
    name: "Correlate Network and Exfiltration Activity"
    action: "hunt"
    description: "Correlate archive creation with outbound connections, file uploads, cloud storage activity, removable media use, and other potential data-transfer events."
    expected_result: "Related transfer activity is identified or assessed against available telemetry."
  - id: "determine-archive-scope"
    order: 7
    name: "Determine Archive Activity Scope"
    action: "hunt"
    description: "Search for related archives, similar process activity, recurring collection patterns, affected accounts, and additional hosts within the relevant investigation window."
    expected_result: "The prevalence and scope of the archive-related activity are determined."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity using the available evidence and document the rationale, limitations, affected data, and required escalation."
    expected_result: "The investigation outcome and supporting evidence are documented."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "archive-collected-data"
---

# Archive Collected Data

## Purpose

This playbook provides a structured workflow for investigating suspicious data archiving, compression, or encryption activity.

Archiving can be part of legitimate system administration, application workflows, backup operations, and routine data transfers. It can also be used to package collected information before unauthorized transfer.

The objective is to determine whether the observed activity is legitimate, suspicious, or malicious, identify the affected data, and establish whether the activity is associated with data staging or potential exfiltration.

### Investigation Considerations

The investigation should distinguish between:

- authorized archiving and backup operations;
- unexpected archive creation involving sensitive information;
- archive creation associated with suspicious process execution;
- archiving followed by unexplained data-transfer activity.

Archive creation alone does not establish malicious intent or confirm data exfiltration.

## MITRE ATT&CK

| Technique | Name                      | Relevance                                                                                            |
| --------- | ------------------------- | ---------------------------------------------------------------------------------------------------- |
| T1560     | Archive Collected Data    | Primary technique covering compression or encryption of collected data before potential exfiltration |
| T1560.001 | Archive via Utility       | Relevant when archiving is performed using system or third-party utilities                           |
| T1560.002 | Archive via Library       | Relevant when an application or script uses an archiving library                                     |
| T1560.003 | Archive via Custom Method | Relevant when data is archived or encrypted using a custom implementation                            |

All mappings should be evaluated against observed behavior. The presence of an archive file alone is not sufficient to establish a particular ATT&CK technique.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Unexpected compressed or encrypted files are created.
- Large volumes of files are archived outside approved maintenance windows.
- Archiving utilities execute with unusual arguments or from unexpected process contexts.
- Scripts or applications create archives containing sensitive information.
- Archives appear in temporary directories, user-writable locations, or previously unused staging locations.
- Archive creation follows unusual file-access or data-collection activity.
- Archive creation coincides with suspicious outbound network connections or upload activity.
- Similar archiving patterns are observed across multiple hosts or accounts.

## Scope

The investigation should consider:

- affected host;
- associated user or service account;
- archive path and filename;
- archive format and size;
- file hashes;
- creation and modification timestamps;
- archiving process;
- parent and child processes;
- command-line arguments;
- executable path and signature;
- loaded modules or libraries where available;
- original data sources;
- file ownership and permissions;
- data classification and sensitivity;
- archive contents where safely accessible;
- encryption indicators;
- related file-access events;
- network connections and upload activity;
- cloud storage activity;
- removable media activity;
- related detections;
- other affected hosts or accounts.

## Investigation Procedure

### Step 1 — Identify Archive Activity Alert

Collect:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated account;
- reported archive path;
- process identifier;
- detection severity;
- reason for detection.

Preserve the original alert and relevant event context.

Determine whether the activity was associated with an approved backup, software deployment, administrative task, or documented data-processing workflow.

### Step 2 — Identify the Archive Artifact

Identify the archive file or other packaged data artifact.

Collect:

- full file path;
- filename and extension;
- detected file type;
- file size;
- creation timestamp;
- modification timestamp;
- file owner;
- SHA-256 hash where available;
- digital signature information where applicable;
- archive metadata available through approved analysis tools.

Do not rely exclusively on file extensions to determine file type. Compare the available metadata with the actual file characteristics.

Preserve the artifact in accordance with organizational evidence-handling procedures.

### Step 3 — Review the Archiving Process

Identify the process responsible for creating or modifying the archive.

Review:

- process name and identifier;
- executable path;
- command line and arguments;
- process creation time;
- parent process;
- child processes;
- associated user;
- process integrity and privilege context;
- digital signature;
- application or library activity where available.

Determine whether archiving was performed by an approved application, a standard utility, a script, or an unfamiliar executable.

Assess whether the process execution context is consistent with expected administrative or application activity.

Do not classify a process as malicious solely because it is capable of compression or encryption.

### Step 4 — Inspect Archive Contents and Metadata

Determine what can be established about the archive without unnecessarily exposing sensitive data.

Review:

- archive format;
- available file listing;
- number of contained files;
- contained file types;
- names and paths of contained files;
- encryption or password-protection indicators;
- total archive size;
- compression characteristics where relevant;
- available file metadata and hashes.

Where authorized and operationally safe, inspect archive contents in a controlled analysis environment.

Determine whether the archive appears to contain:

- business documents;
- authentication or credential-related files;
- configuration files;
- application data;
- database exports;
- logs;
- source code;
- other sensitive or restricted information.

If the archive is encrypted or cannot be safely inspected, document the limitation rather than assuming its contents.

### Step 5 — Review Source Data and Collection Context

Identify the original files or data sources included in the archive where possible.

Review:

- source directories;
- file access events;
- file ownership;
- access permissions;
- data classification;
- changes to source files;
- unusual bulk file access;
- preceding data-access and collection activity;
- user or application authorization.

Establish whether the associated account was authorized to access and archive the data.

Look for evidence that files were collected from multiple locations or accessed outside the account's normal responsibilities.

Consider whether the activity is consistent with an approved backup, export, migration, or data-processing operation.

### Step 6 — Correlate Network and Exfiltration Activity

Determine whether archive creation was followed by data-transfer activity.

Review available telemetry for:

- outbound network connections;
- file upload events;
- HTTP or HTTPS transfers;
- cloud storage activity;
- removable media usage;
- transfer destinations;
- transfer timestamps and volume;
- related authentication events;
- suspicious connections from the archiving process or associated applications.

Correlate the archive creation timeline with network and file-transfer events.

Determine whether the archive remained local, was moved to another internal location, or was transferred outside the expected environment.

Do not classify an archive as exfiltrated solely because outbound network activity occurred nearby in time. Establish a defensible relationship between the archived data and the observed transfer wherever possible.

### Step 7 — Determine Archive Activity Scope

Search across available endpoint and security telemetry for:

- the same archive filename;
- matching archive hashes;
- the same executable or script;
- similar command-line patterns;
- comparable archive creation activity;
- the same associated account;
- repeated access to the same source data;
- similar activity on other hosts;
- additional data-transfer events.

Determine:

- the number of affected hosts;
- the number of associated accounts;
- the source locations involved;
- the types of data potentially affected;
- the time range of the activity;
- whether the behavior is recurring;
- whether unauthorized transfer is suspected or confirmed.

Document gaps in coverage and any limitations affecting scope determination.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification, affected systems, data sensitivity, potential transfer activity, and recommended next actions.

## Evidence to Collect

| Evidence         | Description                                                                 |
| ---------------- | --------------------------------------------------------------------------- |
| Alert            | Detection source, alert identifier, severity, timestamp                     |
| Host             | Hostname, IP address, operating system, asset owner                         |
| Account          | Associated username, account type, authorization context                    |
| Archive          | Path, name, format, size, timestamps, hash                                  |
| Process          | Process identifier, executable path, command line                           |
| Process Lineage  | Parent and child processes and execution sequence                           |
| File Metadata    | File ownership, timestamps, type, and available signature information       |
| Archive Contents | File listing, data categories, and sensitivity where ascertainable          |
| Source Data      | Original paths, file-access events, and ownership                           |
| Network          | Destination, protocol, transfer timestamps, and available transfer metadata |
| Cloud Activity   | Relevant upload, storage, or sharing events                                 |
| Timeline         | Archive creation, source-data access, process, and transfer events          |
| Scope            | Affected hosts, accounts, archives, and potential data exposure             |
| Detections       | Related security alerts, rule identifiers, and investigation references     |

Evidence collection must comply with organizational authorization, privacy, retention, and data-handling requirements.

## Decision Criteria

### Benign

Classify the activity as **benign** when the evidence establishes that:

- the archiving operation was authorized;
- the application, utility, or script is approved for the observed task;
- the associated account has an appropriate business or administrative role;
- the data sources and archive contents are consistent with the documented purpose;
- archive creation occurred within an expected workflow or maintenance window;
- subsequent file movement or network activity is consistent with approved operations;
- no additional indicators of unauthorized collection or transfer are identified.

Document the operational justification before closing the investigation.

### Suspicious

Classify the activity as **suspicious** when one or more of the following conditions are observed:

- the archive is unexpected or has no identified business purpose;
- sensitive files are included in the archive;
- the archiving process or execution context is unusual;
- files from multiple locations are packaged without an established justification;
- the associated account's activity is inconsistent with its normal responsibilities;
- archives are created in unusual staging locations;
- archive creation is followed by unexplained network or file-transfer activity;
- encryption or unavailable contents prevent adequate assessment;
- available telemetry is insufficient to rule out unauthorized collection or transfer.

Continue the investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence establishes unauthorized behavior, such as:

- deliberate archiving of restricted data without authorization;
- archive creation as part of confirmed malicious collection activity;
- unauthorized staging of collected data for transfer;
- confirmed transfer of archived sensitive data to an unauthorized destination;
- archiving associated with confirmed account compromise or malicious process execution;
- coordinated archiving and data-transfer behavior consistent with an established incident.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when the available evidence is insufficient to determine whether the activity is legitimate or malicious.

Examples include:

- unavailable process or file telemetry;
- inaccessible archive contents;
- insufficient information about the associated account;
- incomplete network or cloud activity records;
- inability to establish whether the archive was transferred.

Document:

- evidence collected;
- evidence unavailable;
- unresolved questions;
- remaining scope uncertainty;
- additional telemetry or authorization required.

Do not treat the absence of evidence as proof that the activity was benign.

## Escalation

Escalate the investigation when:

- unauthorized archiving of sensitive data is suspected or confirmed;
- the archive contains restricted or regulated information;
- the associated account appears compromised;
- malicious script or executable activity is identified;
- archive creation is linked to suspicious outbound transfers;
- confirmed or suspected data exfiltration requires incident response;
- multiple hosts or accounts are involved;
- the activity affects critical systems or high-value data;
- evidence indicates a broader collection or exfiltration operation.

Notify the appropriate security, incident-response, data-protection, or system-owner personnel in accordance with organizational procedures.

## Response Guidance

For confirmed malicious archive-related activity:

1. Preserve the relevant alert, process, file, account, and network evidence.
2. Identify affected systems, accounts, source locations, and potentially exposed data.
3. Follow the organization's authorized endpoint containment procedures when warranted.
4. Determine whether the archive remains local, has been transferred internally, or has reached an external destination.
5. Search for related archives, hashes, command lines, processes, and transfer activity across the environment.
6. Assess whether credentials, sensitive business information, or regulated data may have been exposed.
7. Coordinate data-exposure assessment with the appropriate internal teams.
8. Remove unauthorized artifacts or remediate affected systems only after required evidence preservation and authorization.
9. Address compromised accounts, malicious processes, or related access mechanisms through the applicable response procedures.
10. Validate that the unauthorized activity has stopped and that appropriate monitoring remains in place.
11. Investigate file-access and data-collection activity preceding archive creation.

Do not delete archives, modify source data, or disrupt legitimate backup and business processes before considering evidence preservation and operational impact.

## Related Detection Rules

## Related Playbooks

- `playbooks/collection/browser-data.md`
- `playbooks/collection/clipboard-theft.md`
- `playbooks/collection/keylogging.md`
- `playbooks/collection/screen-capture.md`
- `playbooks/exfiltration/data-exfiltration.md`
- `playbooks/triage/data-exfiltration-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/suspicious-process-triage.md`

## Validation

The playbook should be validated against approved archiving workflows, endpoint telemetry, file metadata, process execution records, and controlled investigation scenarios.

Validation should confirm that:

- archive creation events can be identified;
- archiving processes and execution contexts can be reviewed;
- archive metadata and available contents can be assessed safely;
- source-data access can be correlated with archive creation;
- related network and transfer activity can be investigated;
- authorized backup and administrative activity can be distinguished from suspicious behavior;
- investigation scope can be established within available telemetry;
- decision criteria produce consistent outcomes;
- escalation requirements are clear and actionable.

The playbook remains unvalidated until the required validation process has been completed and documented.

## Safety

This playbook is intended for defensive security operations, incident investigation, controlled security validation, and authorized testing.

Do not access, extract, decrypt, copy, or transfer sensitive data beyond the scope of approved investigative authorization. Handle potentially sensitive archives in accordance with organizational evidence-preservation and data-protection procedures.

Do not execute unknown files or scripts contained in an archive on production systems. Use an appropriately controlled analysis environment when deeper inspection is necessary.

All containment, evidence acquisition, remediation, and recovery actions must follow the organization's authorization and change-management requirements.
