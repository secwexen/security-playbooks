---
id: "clipboard-theft"
name: "Clipboard Theft"
category: "collection"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-28T16:53:00Z"
updated_at: "2026-10-28T16:53:00Z"
description: "Investigate suspected unauthorized access to clipboard data and determine whether sensitive information was collected."
objective: "Identify suspicious clipboard access, assess potential exposure of sensitive information, determine the scope of the activity, and provide evidence for escalation or incident response."
severity: "medium"
mitre_attack:
  - "T1115"
triggers:
  - "An alert identifies suspicious clipboard access or monitoring."
  - "An unexpected process accesses clipboard data through operating system APIs."
  - "Clipboard access is associated with suspicious scripting or process execution."
  - "Clipboard activity is followed by suspicious file creation, data staging, or network communication."
  - "A user reports unexpected clipboard monitoring or unauthorized clipboard access."
prerequisites:
  - "Access to endpoint process creation telemetry."
  - "Access to process command-line and process lineage information."
  - "Access to endpoint security logs and relevant operating system telemetry."
  - "Access to network and file activity telemetry where available."
  - "Authorization to investigate potentially sensitive clipboard-related evidence."
tags:
  - "clipboard"
  - "clipboard-theft"
  - "collection"
  - "data-theft"
  - "sensitive-data"
  - "endpoint"
  - "windows"
  - "linux"
  - "macos"
references:
  - "https://attack.mitre.org/techniques/T1115/"
  - "https://attack.mitre.org/detectionstrategies/DET0341/"
steps:
  - id: "identify-clipboard-alert"
    order: 1
    name: "Identify Clipboard Access Alert"
    action: "investigate"
    description: "Identify the alert source, detection timestamp, affected endpoint, associated account, and observed clipboard-related activity."
    expected_result: "The reported clipboard access activity and its initial investigation context are documented."
  - id: "identify-host-and-user"
    order: 2
    name: "Identify Affected Host and User"
    action: "investigate"
    description: "Identify the affected endpoint, user session, account context, operating system, and asset criticality."
    expected_result: "The affected host, associated user, and relevant execution context are identified."
  - id: "review-access-process"
    order: 3
    name: "Review Clipboard Access Process"
    action: "analyze"
    description: "Examine the process associated with clipboard access, including its executable path, signature, parent process, child processes, command line, and execution context."
    expected_result: "The process responsible for or associated with clipboard access is identified and assessed."
  - id: "review-access-method"
    order: 4
    name: "Review Clipboard Access Method"
    action: "analyze"
    description: "Determine whether clipboard access occurred through operating system APIs, scripting interfaces, command-line utilities, or application-specific functionality."
    expected_result: "The observed clipboard access method and its operational context are documented."
  - id: "assess-data-exposure"
    order: 5
    name: "Assess Potential Data Exposure"
    action: "analyze"
    description: "Determine whether the observed activity could have exposed credentials, authentication tokens, personal information, financial information, or other sensitive content without unnecessarily collecting the actual clipboard contents."
    expected_result: "The potential sensitivity, exposure, and confidentiality impact of the activity are assessed."
  - id: "correlate-related-activity"
    order: 6
    name: "Correlate Related Activity"
    action: "analyze"
    description: "Correlate clipboard access with process execution, authentication events, file creation, data staging, persistence indicators, and network activity."
    expected_result: "Related activity is correlated and potential collection or exfiltration behavior is identified or ruled out."
  - id: "determine-collection-scope"
    order: 7
    name: "Determine Collection Scope"
    action: "hunt"
    description: "Search available telemetry for similar clipboard access behavior, related process identifiers, executable hashes, command lines, accounts, and affected endpoints."
    expected_result: "The observed activity's prevalence, duration, affected assets, and potential scope are documented."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity using the available evidence, document identified gaps, and determine whether further investigation or incident response is required."
    expected_result: "The investigation outcome, supporting evidence, and required follow-up actions are documented."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "clipboard-data-collection"
---

# Clipboard Theft

## Purpose

This playbook provides a structured workflow for investigating suspected unauthorized access to clipboard data.

The operating system clipboard may temporarily contain sensitive information copied between applications. Such information can include credentials, authentication tokens, personal information, financial data, confidential documents, and other business-sensitive content.

Malicious software or unauthorized processes may access or monitor clipboard contents to collect information for subsequent misuse.

The objective is to determine whether the observed activity represents legitimate application behavior, suspicious clipboard access, or confirmed malicious data collection.

Clipboard access alone does not establish malicious intent. The investigation must consider the process identity, user context, access method, surrounding activity, and available evidence.

## MITRE ATT&CK

| Technique | Name           | Tactic     | Relevance                                                    |
| --------- | -------------- | ---------- | ------------------------------------------------------------ |
| T1115     | Clipboard Data | Collection | Adversaries may collect information stored in the clipboard. |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An endpoint security alert identifies suspicious clipboard access.
- A process accesses clipboard data in an unexpected execution context.
- A script or executable repeatedly accesses clipboard contents without an established operational requirement.
- Clipboard access occurs in association with suspicious process execution or potentially malicious software.
- Clipboard-related activity is followed by suspicious file creation, data staging, or outbound network communication.
- A user reports unexpected clipboard monitoring or unauthorized access to copied information.
- Threat hunting identifies clipboard access behavior inconsistent with normal application activity.

The presence of a clipboard-related process or API call alone is not sufficient to classify the activity as malicious.

## Scope

The investigation should consider:

- affected host;
- associated user account;
- active user session;
- operating system and version;
- process name;
- process identifier;
- executable path;
- file hash;
- digital signature;
- command line;
- parent process;
- child processes;
- process execution time;
- clipboard access method;
- relevant application context;
- clipboard monitoring behavior;
- available file and data staging activity;
- associated authentication events;
- network connections;
- potentially affected credentials or sensitive information;
- related alerts;
- additional affected endpoints.

The investigation must minimize exposure of clipboard contents that may contain credentials, authentication tokens, personal information, or confidential business data.

## Investigation Procedure

### Step 1 — Identify Clipboard Access Alert

Review the original alert and record:

- detection source;
- alert identifier;
- detection timestamp;
- affected host;
- associated user;
- process name;
- process identifier;
- executable path;
- detection severity;
- detection rationale.

Determine why the activity was identified as suspicious.

Preserve the original alert context and relevant event records before taking remediation actions.

### Step 2 — Identify Affected Host and User

Identify the endpoint on which the activity occurred.

Collect:

- hostname;
- IP address;
- operating system;
- asset owner;
- asset criticality;
- username;
- account type;
- user session information;
- logon context;
- process execution timestamp.

Determine whether the activity occurred in an interactive user session, a background process, a service context, or another execution context.

Assess whether clipboard access is expected for the application and the user's normal workflow.

### Step 3 — Review Clipboard Access Process

Examine the process associated with the observed activity.

Collect:

- executable name;
- executable path;
- process identifier;
- parent process identifier;
- process creation time;
- command line;
- file hash;
- digital signature;
- file creation and modification timestamps;
- process integrity level or privilege context where available;
- associated user account;
- child-process activity.

Review the process lineage to determine whether the process originated from an expected application or an unusual execution chain.

Investigate unexpected relationships involving script interpreters, downloaded executables, temporary directories, or untrusted applications.

A legitimate executable name or valid digital signature does not independently establish that the observed activity is authorized.

### Step 4 — Review Clipboard Access Method

Determine how the process accessed or monitored clipboard data.

Relevant evidence may include:

- Windows clipboard API activity, such as `OpenClipboard` and `GetClipboardData`;
- PowerShell clipboard access through `Get-Clipboard`;
- clipboard access through application frameworks or libraries;
- macOS clipboard access through utilities such as `pbpaste`;
- Linux clipboard access through utilities such as `xclip` or `xsel`;
- repeated clipboard access associated with an unexpected process;
- suspicious command-line arguments or dynamically executed scripts;
- application behavior that monitors or modifies clipboard contents.

Review the available command-line, API, process, and endpoint telemetry.

Distinguish clipboard reads from clipboard writes or replacement behavior where the available telemetry permits this distinction.

Do not classify a utility or API call as malicious solely because it can interact with the clipboard. Determine whether its use is consistent with the application's purpose and the user's normal activity.

### Step 5 — Assess Potential Data Exposure

Assess the potential sensitivity of the information accessible to the process.

Consider whether the clipboard may have contained:

- passwords or authentication secrets;
- session tokens or access tokens;
- personal information;
- financial information;
- confidential business information;
- source code or intellectual property;
- customer or organizational data.

Correlate clipboard access timestamps with application activity and other available telemetry to determine what information may have been exposed.

Where clipboard contents are unavailable, do not assume that sensitive data was collected. Document the evidence that supports or limits the assessment.

### Step 6 — Correlate Related Activity

Correlate the clipboard access event with surrounding endpoint and network activity.

Review:

- process creation events;
- parent and child process activity;
- script execution;
- file creation and modification;
- suspicious temporary files;
- authentication events;
- credential-related activity;
- data staging or archive creation;
- outbound network connections;
- suspicious destination domains or IP addresses;
- persistence indicators;
- related endpoint alerts.

Determine whether clipboard access was isolated or occurred as part of a broader activity chain.

Investigate whether the observed behavior is associated with unauthorized collection, subsequent data staging, or possible exfiltration.

Do not conclude that data was exfiltrated unless supported by available evidence.

### Step 7 — Determine Collection Scope

Establish the prevalence and potential scope of the activity.

Search available telemetry for:

- the same executable hash;
- the same process name and command line;
- similar clipboard access behavior;
- the same parent-child process relationship;
- related user accounts;
- related endpoints;
- repeated access at similar intervals;
- associated file and network indicators.

Determine:

- the first and last observed activity;
- the number of affected endpoints;
- the number of potentially affected accounts;
- whether the behavior remains active;
- whether similar activity exists elsewhere in the environment;
- whether potential data exposure extends beyond the original host.

Document telemetry gaps and identify any additional investigation required to establish scope.

### Step 8 — Determine Investigation Outcome

Classify the activity as one of the following:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Record the evidence supporting the classification, the scope assessment, and any required escalation or response actions.

## Evidence to Collect

| Evidence            | Description                                                           |
| ------------------- | --------------------------------------------------------------------- |
| Alert               | Detection source, identifier, severity, and timestamp                 |
| Host                | Hostname, IP address, operating system, and asset criticality         |
| User                | Associated account and session context                                |
| Process             | Process identifier, executable path, command line, and execution time |
| Process Lineage     | Parent and child processes and their relationships                    |
| File Metadata       | File hash, signature, path, and relevant timestamps                   |
| Access Method       | Available clipboard API, command-line, or application telemetry       |
| Application Context | Application associated with the clipboard operation                   |
| Timeline            | Clipboard access and correlated event timestamps                      |
| Data Exposure       | Potentially affected data categories and supporting evidence          |
| Network             | Related connections and destination metadata                          |
| Related Activity    | Associated authentication, staging, persistence, or collection events |
| Scope               | Additional affected endpoints, accounts, and indicators               |
| Evidence Gaps       | Missing telemetry and unresolved investigative questions              |

## Decision Criteria

### Benign

Classify the activity as benign when the available evidence supports the following:

- the process belongs to an expected application;
- clipboard access is consistent with the application's documented functionality;
- the associated user and session context are expected;
- the process execution context is consistent with legitimate activity;
- no suspicious follow-on activity is identified;
- no evidence supports unauthorized collection or misuse.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as suspicious when one or more of the following are observed:

- clipboard access occurs in an unexpected execution context;
- the responsible process is unknown or untrusted;
- a script or executable repeatedly accesses clipboard data without a clear business justification;
- process lineage or command-line arguments are unusual;
- clipboard access coincides with suspicious file activity;
- related authentication, process, or network activity requires further investigation;
- telemetry is insufficient to determine whether the activity is authorized.

Continue the investigation and collect additional evidence using approved telemetry sources.

### Malicious

Classify the activity as malicious when sufficient evidence indicates unauthorized clipboard data collection or related malicious behavior, such as:

- confirmed clipboard monitoring by unauthorized software;
- clipboard access associated with a confirmed malicious process;
- unauthorized collection of sensitive information;
- clipboard-related activity linked to confirmed credential theft;
- clipboard access followed by confirmed unauthorized data staging or exfiltration;
- clipboard monitoring incorporated into an identified malicious execution chain.

Escalate to the appropriate incident-response workflow.

Assess potential exposure of credentials, authentication tokens, and other sensitive information.

### Inconclusive

Use the inconclusive classification when available evidence is insufficient to distinguish legitimate clipboard functionality from unauthorized collection.

Document:

- evidence collected;
- telemetry sources reviewed;
- evidence unavailable;
- unresolved questions;
- potential data exposure;
- additional telemetry or authorization required.

Do not classify the activity as benign solely because no malicious follow-on behavior was observed.

## Escalation

Escalate the investigation when:

- unauthorized clipboard monitoring is confirmed;
- sensitive information may have been collected;
- credential or authentication token exposure is suspected;
- the activity is associated with a confirmed malicious executable or script;
- suspicious data staging or exfiltration is identified;
- similar activity appears across multiple endpoints;
- the activity involves privileged accounts or security-sensitive systems;
- the scope or impact cannot be established with available telemetry.

Notify the appropriate incident-response team and follow organizational requirements for security incidents involving sensitive information or potential data exposure.

## Response Guidance

For confirmed malicious clipboard collection:

1. Preserve relevant endpoint, process, authentication, file, and network evidence.
2. Identify the affected hosts, accounts, and relevant execution timeline.
3. Follow the organization's approved endpoint containment procedure.
4. Stop or isolate the responsible process only through authorized response procedures.
5. Investigate associated collection, credential access, persistence, and exfiltration activity.
6. Determine whether credentials, access tokens, or other sensitive information may have been exposed.
7. Revoke or rotate potentially compromised credentials and tokens according to established procedures.
8. Identify related indicators across the environment.
9. Assess notification and reporting requirements for potentially exposed personal or business-sensitive information.
10. Remove malicious components and restore affected systems in accordance with incident-response procedures.
11. Document the investigation, containment, remediation, and recovery actions.

Do not terminate legitimate applications, clear clipboard contents, delete artifacts, or modify system state before considering evidence preservation and operational impact.

## Related Detection Rules

## Related Playbooks

- `playbooks/collection/browser-data.md`
- `playbooks/collection/keylogging.md`
- `playbooks/collection/screen-capture.md`
- `playbooks/collection/archive-collected-data.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/triage/data-exfiltration-triage.md`

## Validation

The playbook should be validated using approved endpoint telemetry, controlled clipboard-access scenarios, process execution records, and representative benign application workflows.

Validation should confirm that:

- the initiating process and user context can be identified;
- available telemetry can establish the clipboard access method;
- legitimate clipboard activity can be distinguished from suspicious behavior;
- process lineage and related activity can be investigated;
- potential sensitive-data exposure can be assessed without unnecessary collection of raw clipboard contents;
- related staging and network activity can be correlated;
- the scope of the activity can be established;
- the decision criteria produce consistent investigation outcomes;
- evidence-handling requirements are followed throughout the investigation.

## Safety

This playbook is intended for defensive security operations, authorized investigations, controlled security validation, and approved testing.

Clipboard contents may include passwords, authentication tokens, personal information, and confidential business data. Investigators must minimize data collection, apply appropriate redaction, and protect retained evidence.

Do not collect, store, transmit, or disclose sensitive clipboard contents without appropriate authorization. All containment, remediation, credential rotation, and recovery actions must follow established organizational procedures.
