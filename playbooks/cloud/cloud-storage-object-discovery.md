---
id: "cloud-storage-object-discovery"
name: "Cloud Storage Object Discovery"
category: "cloud"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-25T14:25:00Z"
updated_at: "2026-10-25T14:26:00Z"
description: "Investigate suspicious enumeration of cloud storage objects and determine whether the activity represents legitimate administration, unauthorized reconnaissance, or part of a broader security incident."
objective: "Identify the cloud identity, storage resources, enumeration activity, and associated access patterns; determine the scope of the discovery activity; and establish whether escalation or incident response is required."
severity: "medium"
mitre_attack:
  - "T1619"
triggers:
  - "Unusual cloud storage object enumeration"
  - "Unexpected ListObjectsV2 API activity in AWS CloudTrail"
  - "Unusual List Blobs activity in Azure Storage logs"
  - "Unexpected storage.objects.list activity in Google Cloud audit logs"
  - "Large-scale object listing by an unfamiliar identity"
  - "Repeated enumeration across multiple storage resources"
  - "Cloud storage discovery associated with suspicious authentication or permission changes"
prerequisites:
  - "Access to relevant cloud audit logs"
  - "Access to cloud identity and authentication records"
  - "Access to storage resource inventories and access policies"
  - "Access to cloud role assignments and permission-change history"
  - "Knowledge of approved administrative and automated storage operations"
tags:
  - "cloud"
  - "discovery"
  - "storage"
  - "object-enumeration"
  - "aws"
  - "azure"
  - "gcp"
  - "cloud-security"
references:
  - "https://attack.mitre.org/techniques/T1619/"
  - "https://attack.mitre.org/detectionstrategies/DET0578/"
steps:
  - id: "identify-cloud-storage-alert"
    order: 1
    name: "Identify Cloud Storage Discovery Alert"
    action: "investigate"
    description: "Identify the detection source, alert timestamp, cloud provider, affected storage resource, and observed enumeration activity."
    expected_result: "The alert context and potentially affected cloud storage resources are identified."
  - id: "identify-cloud-identity"
    order: 2
    name: "Identify Cloud Identity and Session"
    action: "investigate"
    description: "Identify the user, service account, role, session, source address, and authentication context associated with the observed activity."
    expected_result: "The identity and execution context associated with the enumeration are documented."
  - id: "review-enumeration-activity"
    order: 3
    name: "Review Enumeration API Activity"
    action: "analyze"
    description: "Examine cloud audit events for object-listing operations, request frequency, pagination, resource scope, result patterns, and available request metadata."
    expected_result: "The enumeration behavior, timing, and requested resource scope are characterized."
  - id: "review-storage-resources"
    order: 4
    name: "Review Storage Resources and Object Scope"
    action: "analyze"
    description: "Identify the affected buckets, containers, object prefixes, resource ownership, data sensitivity, and relevant access policies."
    expected_result: "The affected storage resources and potential exposure of sensitive data are documented."
  - id: "correlate-identity-permissions"
    order: 5
    name: "Correlate Authentication and Permission Changes"
    action: "analyze"
    description: "Correlate enumeration events with recent logins, session creation, role assumption, privilege changes, access-key activity, and policy modifications."
    expected_result: "Related identity activity and potentially unauthorized access changes are identified or ruled out."
  - id: "review-follow-on-access"
    order: 6
    name: "Review Follow-on Object Access"
    action: "analyze"
    description: "Determine whether enumeration was followed by object reads, downloads, copies, unusual data transfers, or access to sensitive objects."
    expected_result: "Related object-access activity is identified and assessed separately from enumeration."
  - id: "determine-discovery-scope"
    order: 7
    name: "Determine Discovery Scope"
    action: "hunt"
    description: "Search across available cloud audit records for related identities, sessions, storage resources, object prefixes, and repeated enumeration patterns."
    expected_result: "The affected resources, identities, time range, and broader activity scope are documented."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity using the available evidence and document the findings, unresolved questions, and required follow-up actions."
    expected_result: "The investigation outcome and supporting evidence are recorded."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "cloud-storage-object-discovery"
---

# Cloud Storage Object Discovery

## Purpose

This playbook provides a structured workflow for investigating suspicious enumeration of objects stored in cloud storage services.

Cloud storage platforms provide APIs that allow authorized identities to list storage objects and retrieve associated metadata. These operations are common in legitimate administrative workflows, inventory processes, backup operations, and application activity.

Adversaries may also enumerate cloud storage objects to identify valuable information, locate sensitive data, and identify targets for subsequent collection or exfiltration.

The objective is to determine whether the observed enumeration is legitimate, suspicious, or malicious, establish the scope of the activity, and identify whether additional investigation or incident response is required.

## MITRE ATT&CK

| Technique | Name                           | Relevance                                                                              |
| --------- | ------------------------------ | -------------------------------------------------------------------------------------- |
| T1619     | Cloud Storage Object Discovery | Primary technique associated with enumerating objects in cloud storage infrastructure. |

The technique applies to object enumeration activity across supported cloud storage environments. The presence of an object-listing event alone does not establish malicious intent.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Cloud audit logs record unexpected object enumeration.
- A user or service account lists objects in storage resources outside its normal operational scope.
- A large number of object-listing requests occur within a short period.
- Enumeration spans multiple buckets, containers, projects, or storage accounts unexpectedly.
- A newly observed identity performs broad storage discovery.
- Object enumeration follows suspicious authentication activity or unexpected permission changes.
- Storage discovery is followed by unusual object retrieval or data transfer activity.
- Threat hunting identifies anomalous cloud storage access patterns.

## Scope

The investigation should consider:

- cloud provider and account, subscription, or project;
- affected storage account, bucket, or container;
- object prefixes and enumeration scope;
- cloud identity and associated role;
- service account or assumed role;
- authentication and session context;
- source IP address and available network metadata;
- API operation and request timestamps;
- request frequency and pagination behavior;
- object metadata exposed through enumeration;
- storage access policies and effective permissions;
- recent identity and policy changes;
- subsequent object-read or download activity;
- related cloud alerts;
- additional affected storage resources;
- potential access to sensitive information.

The investigation should distinguish object enumeration from subsequent object retrieval, modification, and exfiltration. These activities may occur in the same incident but represent different behaviors and require separate supporting evidence.

## Investigation Procedure

### Step 1 — Identify Cloud Storage Discovery Alert

Collect:

- alert identifier;
- detection source;
- event timestamp;
- cloud provider;
- account, subscription, or project identifier;
- storage resource identifier;
- API operation;
- event outcome;
- detection severity;
- available request and session metadata.

Establish the time range surrounding the initial activity.

Preserve the original alert and associated audit records before taking response actions.

### Step 2 — Identify Cloud Identity and Session

Determine which identity initiated the observed requests.

Collect, where available:

- username or principal identifier;
- service account;
- assumed role;
- session identifier;
- access-key identifier;
- source IP address;
- user agent;
- authentication method;
- authentication timestamp;
- session creation time;
- privilege level;
- associated identity provider events.

Determine whether the identity is expected to enumerate the affected resources.

Review whether the activity originated from a known administrative workflow, approved automation, backup service, inventory process, or application.

An unfamiliar identity or unusual source address should increase investigation priority but does not independently confirm compromise.

### Step 3 — Review Enumeration API Activity

Review provider audit logs for object-enumeration operations.

Examples include:

- **AWS:** `ListObjects` and `ListObjectsV2` events recorded in CloudTrail when the relevant data-event logging is enabled.
- **Azure:** `List Blobs` operations recorded in available Azure Storage logs.
- **Google Cloud:** `storage.objects.list` activity recorded in Cloud Audit Logs.

Evaluate:

- request frequency;
- number of affected storage resources;
- object prefixes requested;
- pagination and continuation-token patterns;
- successful and unsuccessful requests;
- unusual enumeration volume;
- activity outside expected operating hours;
- changes from the identity's normal behavior;
- repeated requests across unrelated resources.

Determine whether the request pattern is consistent with documented administrative or application activity.

Object enumeration may be legitimate even when the request volume is high. Assess the observed pattern against the identity's role, expected workload, and historical activity.

### Step 4 — Review Storage Resources and Object Scope

Determine which storage resources and object namespaces were enumerated.

Review:

- bucket, container, or storage account identifiers;
- project and regional context;
- object prefixes and naming patterns;
- resource ownership;
- access-control policies;
- effective identity permissions;
- public-access configuration where relevant;
- classification of potentially exposed information;
- presence of sensitive filenames or metadata.

Establish whether the identity was authorized to enumerate the affected resources.

Assess the potential sensitivity of the discovered objects without assuming that listing an object confirms that its contents were accessed.

### Step 5 — Correlate Authentication and Permission Changes

Correlate the enumeration activity with identity and access-management events.

Review:

- recent successful and failed logins;
- new sessions or role assumptions;
- unexpected access-key use;
- credential changes;
- new role assignments;
- policy modifications;
- privilege escalation;
- unusual access from new locations;
- authentication activity preceding enumeration;
- related discovery activity involving other cloud services.

Determine whether the identity's permissions or authentication context changed shortly before the activity.

A permission change or unusual login is supporting evidence only. Establish its relationship to the storage enumeration before classifying the incident.

### Step 6 — Review Follow-on Object Access

Determine whether the enumeration was followed by additional storage operations.

Review available audit records for:

- object reads;
- object downloads;
- copy operations;
- access to sensitive objects;
- repeated retrieval from enumerated prefixes;
- unusual data-transfer volume;
- access from unfamiliar locations;
- subsequent storage modifications;
- related collection or exfiltration indicators.

Correlate the activity by identity, session, source address, storage resource, and time.

Distinguish the ability to enumerate objects from evidence that their contents were retrieved.

If unauthorized object access or suspected data transfer is identified, escalate to the appropriate investigation and response workflows.

### Step 7 — Determine Discovery Scope

Search available cloud audit records for the same:

- identity or service account;
- session or access-key identifier;
- source address;
- API operation;
- storage resource;
- object prefix;
- request pattern;
- related alert or incident identifier.

Determine:

- number of affected storage resources;
- number of identities involved;
- earliest and latest observed activity;
- duration and approximate volume of enumeration;
- whether the activity spread across accounts, subscriptions, or projects;
- whether sensitive resources were identified;
- whether object retrieval or other follow-on behavior occurred.

Document logging gaps that prevent reliable determination of the full scope.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Record the supporting evidence and any remaining uncertainties.

## Evidence to Collect

| Evidence            | Description                                                                         |
| ------------------- | ----------------------------------------------------------------------------------- |
| Alert               | Detection source, identifier, severity, and timestamp                               |
| Cloud Context       | Provider, account, subscription, project, and region                                |
| Identity            | Principal, username, service account, or assumed role                               |
| Session             | Session identifier, authentication context, and access-key metadata where available |
| API Activity        | Operation names, event outcomes, request timestamps, and available request metadata |
| Storage Resources   | Bucket, container, account, and object-prefix identifiers                           |
| Enumeration Pattern | Request frequency, pagination, scope, and observed volume                           |
| Access Policies     | Relevant identity permissions, storage policies, and recent modifications           |
| Authentication      | Related logins, session creation, and identity-provider events                      |
| Object Access       | Related reads, downloads, copies, or modifications                                  |
| Network Context     | Source address, user agent, and available connection metadata                       |
| Timeline            | Sequence of discovery, authentication, permission changes, and subsequent activity  |
| Scope               | Affected identities, storage resources, and time range                              |
| Correlated Alerts   | Related cloud security findings and incident identifiers                            |
| Limitations         | Missing logs, unavailable fields, and other investigative constraints               |

## Decision Criteria

### Benign

Classify the activity as **benign** when evidence supports that:

- the identity is authorized to enumerate the affected resources;
- the activity is attributable to an approved administrative or automated process;
- the request pattern is consistent with documented operational behavior;
- the timing and scope are consistent with the expected workload;
- no unexplained authentication or permission changes are identified;
- no related unauthorized object access or suspicious follow-on activity is observed.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when one or more indicators require further investigation, including:

- unexpected enumeration volume;
- enumeration across unrelated resources;
- unfamiliar identities or source addresses;
- activity outside expected operational patterns;
- repeated requests inconsistent with the identity's normal behavior;
- unusual authentication or session context;
- unexplained permission changes;
- enumeration followed by potentially sensitive object-access attempts;
- incomplete telemetry preventing a reliable assessment.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence supports unauthorized discovery or identifies the enumeration as part of a confirmed malicious sequence, such as:

- enumeration performed through a confirmed compromised identity;
- unauthorized use of credentials or an assumed role;
- deliberate discovery of sensitive storage resources in a confirmed intrusion;
- enumeration associated with unauthorized object retrieval;
- storage discovery correlated with confirmed malicious collection or exfiltration;
- repeated enumeration associated with other confirmed adversary activity.

Escalate to the appropriate incident-response workflow.

Do not classify activity as malicious solely because an identity listed a large number of objects.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the enumeration was authorized or malicious.

Document:

- evidence collected;
- relevant logs that are unavailable;
- identities or resources that remain unverified;
- unresolved questions about subsequent object access;
- additional telemetry required;
- recommended investigative actions.

Keep the case open or escalate according to the organization's incident-handling procedures.

## Escalation

Escalate the investigation when:

- unauthorized cloud identity activity is confirmed or strongly suspected;
- suspicious enumeration involves sensitive storage resources;
- unauthorized access to object contents is identified;
- enumeration is associated with unexpected role or policy changes;
- suspicious activity spans multiple accounts, subscriptions, projects, or storage resources;
- object retrieval or potential data exfiltration is identified;
- the investigation indicates a broader cloud compromise;
- available telemetry is insufficient to assess a potentially significant incident.

Notify the appropriate cloud security, identity security, or incident-response team according to organizational procedures.

## Response Guidance

For confirmed malicious cloud storage discovery:

1. Preserve relevant cloud audit events, identity records, storage metadata, and associated alert context.
2. Identify affected identities, sessions, and storage resources.
3. Determine whether credential compromise or unauthorized role use occurred.
4. Follow approved procedures to revoke or restrict compromised credentials and sessions when appropriate.
5. Review and remediate excessive permissions using the organization's access-management process.
6. Determine whether object retrieval, copying, or data exfiltration occurred.
7. Search for related enumeration and access activity across the cloud environment.
8. Engage the appropriate response team when sensitive data or additional cloud resources may be affected.
9. Document containment decisions, remediation actions, and the final investigation outcome.

Do not automatically revoke legitimate service identities or disrupt production workloads solely because object enumeration occurred. Validate the context and coordinate disruptive response actions with the responsible teams.

## Related Detection Rules

## Related Playbooks

- `playbooks/exfiltration/cloud-exfiltration.md`
- `playbooks/triage/data-exfiltration-triage.md`

## Validation

The playbook should be validated against approved cloud audit logs, storage-access telemetry, identity records, and controlled enumeration scenarios.

Validation should confirm that:

- supported cloud object-enumeration events can be identified;
- the initiating identity and available session context can be established;
- request frequency and enumeration scope can be assessed;
- storage resources and relevant permissions can be investigated;
- enumeration can be correlated with authentication and permission changes;
- subsequent object-access activity can be distinguished from enumeration;
- legitimate administrative activity can be differentiated from suspicious behavior;
- investigation outcomes are supported by documented evidence;
- escalation criteria produce consistent results.

Validate the workflow using authorized test environments and provider-supported audit events. Do not enumerate production data outside approved operational or testing procedures.

The `validated` metadata field must be updated only after the required validation has been completed and documented.

## Safety

This playbook is intended for defensive cloud security operations, authorized investigation, security validation, and controlled testing.

Use read-only access wherever practical during investigation. Preserve relevant audit records and follow organizational authorization, privacy, and data-handling requirements.

Do not access, download, copy, or disclose sensitive storage contents merely to confirm that they exist. Any containment, credential revocation, or permission change must follow approved response procedures.
