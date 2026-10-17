---
id: "cloud-account-discovery"
name: "Cloud Account Discovery"
category: "cloud"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-17T15:47:00Z"
updated_at: "2026-10-17T15:47:00Z"
description: "Investigate suspicious enumeration of cloud user accounts, service accounts, roles, and identity resources across cloud platforms and identity providers."
objective: "Determine whether cloud account discovery activity is authorized, suspicious, or malicious; identify the identities and resources involved; establish the scope; and provide evidence for escalation or closure."
severity: "medium"
mitre_attack:
  - "T1087.004"
triggers:
  - "Unusual enumeration of cloud user accounts or service accounts"
  - "Unexpected API requests listing cloud users, roles, or identity resources"
  - "Bulk directory queries from an unfamiliar identity or source"
  - "Cloud account enumeration by an unexpected automation account"
  - "Identity discovery activity following a suspicious authentication event"
  - "Threat hunting identifies anomalous cloud identity enumeration"
prerequisites:
  - "Access to cloud identity and audit logs"
  - "Access to authentication and sign-in telemetry"
  - "Access to cloud account, role, and service-account inventory"
  - "Access to identity and access management configuration"
  - "Ability to correlate activity across relevant cloud accounts, subscriptions, projects, or tenants"
tags:
  - "cloud"
  - "discovery"
  - "identity"
  - "account-enumeration"
  - "iam"
  - "cloud-security"
references:
  - "https://attack.mitre.org/techniques/T1087/004/"
steps:
  - id: "identify-cloud-account-discovery-alert"
    order: 1
    name: "Identify Cloud Account Discovery Alert"
    action: "investigate"
    description: "Identify the detection source, event timestamp, affected cloud environment, initiating identity, source context, and reason for the alert."
    expected_result: "The detection context, affected environment, and initial account discovery activity are documented."
  - id: "identify-actor-and-session"
    order: 2
    name: "Identify Actor and Session"
    action: "investigate"
    description: "Determine which user, service principal, workload identity, or automation account initiated the activity and review the associated authentication session."
    expected_result: "The initiating identity, session context, authentication method, and relevant source attributes are identified."
  - id: "review-account-enumeration"
    order: 3
    name: "Review Account Enumeration Activity"
    action: "analyze"
    description: "Review API calls, directory queries, console actions, and other events associated with listing or inspecting cloud accounts and identity resources."
    expected_result: "The account enumeration operations, queried resources, and observed sequence of activity are documented."
  - id: "assess-api-console-context"
    order: 4
    name: "Assess API and Console Context"
    action: "analyze"
    description: "Compare the observed operations with approved administrative workflows, normal identity management activity, expected API clients, and established automation patterns."
    expected_result: "The operational context of the enumeration is assessed against expected administrative and application behavior."
  - id: "correlate-authentication-activity"
    order: 5
    name: "Correlate Authentication Activity"
    action: "analyze"
    description: "Correlate account enumeration with preceding and subsequent sign-ins, authentication failures, token usage, session changes, and unusual source activity."
    expected_result: "Related authentication events and potential indicators of unauthorized session use are identified."
  - id: "review-permissions-targeted-accounts"
    order: 6
    name: "Review Permissions and Targeted Accounts"
    action: "analyze"
    description: "Determine the permissions available to the initiating identity and identify the accounts, privileged roles, service identities, or administrative groups examined."
    expected_result: "The initiating identity's effective access and the scope of the enumerated identity resources are documented."
  - id: "determine-discovery-scope"
    order: 7
    name: "Determine Discovery Scope"
    action: "hunt"
    description: "Search relevant cloud audit records for related enumeration activity by the same identity, session, application, source, or behavioral pattern."
    expected_result: "The timeframe, affected cloud environments, identities, resources, and related activity are established."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the account discovery activity using the available evidence and document the investigation outcome, outstanding uncertainties, and required follow-up actions."
    expected_result: "The activity receives a documented classification supported by collected evidence."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "cloud-account-discovery"
---

# Cloud Account Discovery

## Purpose

This playbook provides a structured workflow for investigating suspicious cloud account enumeration across cloud platforms and identity providers.

Cloud account discovery involves identifying user accounts, service accounts, roles, identity groups, and other account-related resources. These activities may be part of legitimate identity administration, security auditing, inventory management, or application operations. They may also provide an unauthorized actor with information needed to identify privileged identities and plan further activity.

The objective is to determine whether the observed enumeration is legitimate, suspicious, or malicious, establish its scope, and identify whether it is associated with account compromise or additional unauthorized activity.

## MITRE ATT&CK

| Technique | Name                             | Relevance                                                                                    |
| --------- | -------------------------------- | -------------------------------------------------------------------------------------------- |
| T1087.004 | Account Discovery: Cloud Account | Primary technique when an actor enumerates cloud accounts and associated identity resources. |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A cloud identity alert identifies unusual account or service-account enumeration.
- An identity performs bulk account queries outside its expected operational pattern.
- Cloud directory APIs are queried by an unfamiliar user, application, or workload identity.
- An automation account performs identity discovery outside its approved scope.
- Account enumeration follows an anomalous sign-in, suspicious token use, or unexpected privilege change.
- Threat hunting identifies unusual access to identity directories, user inventories, or role membership information.

Account enumeration alone does not establish malicious intent. The initiating identity, permissions, expected business activity, and related events must be evaluated together.

## Scope

The investigation should consider:

- cloud provider and service;
- tenant, organization, account, subscription, or project;
- initiating user or workload identity;
- service principal or application identity;
- authentication session;
- source IP address and geolocation where available;
- user agent and client application;
- API operations and console actions;
- queried accounts and identity resources;
- role and group membership information;
- assigned permissions;
- activity timestamp and duration;
- related authentication events;
- related privilege changes;
- additional affected cloud environments.

## Investigation Procedure

### Step 1 — Identify Cloud Account Discovery Alert

Collect:

- alert identifier;
- detection source;
- event timestamp;
- cloud provider;
- affected tenant or account;
- initiating identity;
- source IP address;
- application or client identifier;
- detection reason.

Preserve the original alert context and associated event records.

Determine whether the event reflects account enumeration, role discovery, service-account listing, or another identity-related operation.

### Step 2 — Identify Actor and Session

Identify the identity associated with the observed activity.

Collect:

- user or service identity;
- identity type;
- authentication method;
- session identifier where available;
- application or client identifier;
- source IP address;
- user agent;
- sign-in timestamp;
- authentication result;
- relevant conditional access or authentication policy results.

Determine whether the identity and session are expected for the affected environment.

A valid account or successful sign-in does not, by itself, establish that the activity was authorized.

### Step 3 — Review Account Enumeration Activity

Review the cloud audit events and identify the operations performed.

Determine:

- which API operations or console actions were observed;
- whether the activity enumerated users, service accounts, roles, groups, or other identity objects;
- which cloud environments were queried;
- whether the queries were isolated or repeated;
- whether the activity covered an unusually broad set of identities;
- whether the queried information included privileged accounts or administrative roles.

Record the relevant event identifiers, timestamps, target resources, and results available in the audit logs.

### Step 4 — Assess API and Console Context

Compare the observed activity with expected operational behavior.

Review:

- approved identity administration procedures;
- scheduled inventory or audit jobs;
- known management applications;
- expected automation identities;
- source network and device context;
- normal query volume and frequency;
- recent changes to the identity or application configuration.

Determine whether the observed operations are consistent with the identity's assigned responsibilities.

An unfamiliar source or high query volume should be investigated in context rather than treated as conclusive evidence of malicious activity.

### Step 5 — Correlate Authentication Activity

Review authentication events associated with the identity and session.

Investigate:

- unusual successful sign-ins;
- repeated authentication failures;
- unfamiliar source addresses;
- unexpected authentication methods;
- new or unusual application sessions;
- token use inconsistent with established behavior;
- session activity following credential or permission changes.

Correlate the timeline with account enumeration to determine whether discovery occurred during a potentially compromised session.

### Step 6 — Review Permissions and Targeted Accounts

Determine the effective permissions available to the initiating identity at the time of the activity.

Review:

- assigned roles;
- inherited permissions;
- service-principal permissions;
- administrative group membership;
- privileges to list or inspect identity resources;
- accounts or roles of particular interest;
- recent role assignments or permission changes.

Establish whether the activity remained within the identity's authorized scope.

Do not infer privilege escalation solely from the discovery of privileged accounts. Additional evidence is required to establish subsequent unauthorized access or privilege changes.

### Step 7 — Determine Discovery Scope

Search the relevant audit records for related activity.

Correlate by:

- initiating identity;
- application or client identifier;
- session identifier;
- source IP address;
- queried resource;
- API operation;
- time window;
- repeated behavioral patterns.

Determine:

- first and last observed activity;
- number of cloud environments involved;
- number and type of identities enumerated;
- whether privileged identities were targeted;
- whether subsequent authentication or resource-access activity occurred;
- whether other identities show comparable behavior.

Document the scope and any limitations caused by unavailable or incomplete telemetry.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Record the evidence supporting the classification and identify any necessary follow-up investigation.

## Evidence to Collect

| Evidence            | Description                                                    |
| ------------------- | -------------------------------------------------------------- |
| Alert               | Detection source, identifier, severity, and timestamp          |
| Cloud Environment   | Provider, tenant, account, subscription, or project            |
| Initiating Identity | User, service account, service principal, or workload identity |
| Session             | Authentication method, session identifier, and client context  |
| Source              | IP address, user agent, and relevant network information       |
| API Activity        | Operations, requests, timestamps, and target resources         |
| Identity Inventory  | Enumerated users, service accounts, roles, and groups          |
| Permissions         | Effective access and role assignments                          |
| Authentication      | Related sign-ins, failures, and session activity               |
| Timeline            | Sequence of discovery and subsequent events                    |
| Scope               | Affected environments and identities                           |
| Correlation         | Related alerts and suspicious follow-on activity               |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the initiating identity is authorized to perform the observed queries;
- the activity is consistent with approved administration, inventory, or auditing;
- the application or automation job is recognized;
- source and session attributes are expected;
- query volume and scope are consistent with the documented task;
- no corroborating indicators of unauthorized access are identified.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- the initiating identity performs unexpected enumeration;
- the source or application context is unfamiliar;
- query volume or scope deviates materially from normal behavior;
- privileged identities are enumerated without an established business justification;
- the activity follows anomalous authentication or token use;
- related telemetry is incomplete and unauthorized activity cannot be ruled out.

Continue investigation and correlate additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence establishes unauthorized identity discovery, such as:

- account enumeration performed through a confirmed compromised session;
- identity discovery by an unauthorized application or workload identity;
- enumeration that forms part of a confirmed attack sequence;
- discovery followed by unauthorized access to accounts or resources;
- corroborating evidence of malicious activity by the initiating identity.

Escalate to the appropriate cloud incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the activity was authorized.

Document:

- evidence collected;
- evidence unavailable;
- unresolved questions;
- additional cloud audit or identity telemetry required.

Do not classify discovery as malicious solely because a large number of accounts were queried.

## Escalation

Escalate the investigation when:

- account enumeration is linked to a suspected or confirmed compromised identity;
- unauthorized access to privileged identity information is established;
- an unrecognized application or workload identity performs discovery;
- discovery is followed by suspicious role changes or resource access;
- activity spans multiple cloud environments;
- the affected identity has extensive administrative permissions;
- evidence suggests broader account compromise.

Notify the relevant cloud security, identity security, or incident-response team according to organizational procedures.

## Response Guidance

For confirmed malicious cloud account discovery:

1. Preserve cloud audit records, authentication logs, session details, and relevant alert evidence.
2. Identify the affected cloud environments and identities.
3. Review the initiating identity's effective permissions and recent changes.
4. Investigate related authentication, token, resource-access, and privilege-change activity.
5. Determine whether the initiating identity or application is compromised.
6. Revoke sessions or restrict the identity only when justified by the evidence and authorized response procedures.
7. Review access policies if excessive permissions contributed to the exposure.
8. Search for the same enumeration pattern across other cloud environments.
9. Follow the cloud account-compromise response procedure when unauthorized account access is suspected or confirmed.
10. Document containment, remediation, and recovery actions.

Do not disable legitimate administrative identities solely because they performed account enumeration. Validate the activity and coordinate any access restrictions with the responsible team.

## Related Detection Rules

## Related Playbooks

- `playbooks/cloud/cloud-account-compromise.md`
- `playbooks/cloud/cloud-service-discovery.md`
- `playbooks/cloud/cloud-infrastructure-discovery.md`
- `playbooks/cloud/cloud-credential-access.md`

## Validation

The playbook should be validated against approved cloud identity audit records, authentication events, account enumeration scenarios, and controlled cloud laboratory environments.

Validation should confirm that:

- cloud account enumeration can be identified;
- initiating identities and sessions can be determined;
- API and console activity can be investigated;
- expected administrative behavior can be distinguished from anomalous activity;
- relevant permissions and queried resources can be identified;
- related authentication and subsequent resource access can be correlated;
- the scope of discovery can be established;
- investigation outcomes and escalation criteria are applied consistently.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Investigations must comply with organizational access controls, privacy requirements, and cloud provider policies. Do not access unrelated accounts or collect unnecessary personal information. Preserve audit evidence and perform containment actions only through approved procedures.
