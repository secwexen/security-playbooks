---
id: "cloud-service-dashboard"
name: "Cloud Service Dashboard"
category: "cloud"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-23T16:59:00Z"
updated_at: "2026-10-23T16:59:00Z"
description: "Investigate suspicious use of cloud service dashboards and administrative portals to identify unauthorized access and cloud resource discovery."
objective: "Determine whether cloud dashboard access and subsequent resource exploration are legitimate, suspicious, or malicious, establish the scope of the activity, and support appropriate escalation or response."
severity: "medium"
mitre_attack:
  - "T1538"
triggers:
  - "An alert identifies suspicious access to a cloud service dashboard or administrative portal."
  - "A cloud dashboard session originates from an unfamiliar location, device, IP address, or user agent."
  - "A privileged cloud account accesses dashboards or administrative interfaces outside its normal activity pattern."
  - "A cloud dashboard session is followed by unusual resource enumeration or configuration review."
  - "Cloud audit logs identify unexpected browsing of sensitive cloud resources or administrative information."
  - "Threat hunting identifies anomalous GUI-based access to cloud management services."
prerequisites:
  - "Access to cloud identity and authentication logs."
  - "Access to cloud audit logs and dashboard activity records where available."
  - "Access to cloud account, role, and permission information."
  - "Access to relevant source IP, device, and user agent information where available."
tags:
  - "cloud"
  - "cloud-dashboard"
  - "discovery"
  - "identity"
  - "cloud-audit"
references:
  - "https://attack.mitre.org/techniques/T1538/"
  - "https://attack.mitre.org/detectionstrategies/DET0291/"
steps:
  - id: "identify-dashboard-alert"
    order: 1
    name: "Identify Cloud Dashboard Alert"
    action: "investigate"
    description: "Identify the alert source, cloud provider, affected tenant, dashboard, event timestamp, and reason for investigation."
    expected_result: "The cloud dashboard activity and the reason for investigation are documented."
  - id: "identify-cloud-session"
    order: 2
    name: "Identify Cloud Account and Session"
    action: "investigate"
    description: "Identify the account, session, identity provider, cloud tenant, assigned roles, and session context associated with the activity."
    expected_result: "The cloud identity, session context, and effective access privileges are identified."
  - id: "review-authentication-context"
    order: 3
    name: "Review Authentication Context"
    action: "analyze"
    description: "Review authentication events, MFA outcomes, source IP addresses, device information, user agent, geolocation, and recent account activity."
    expected_result: "The authentication context is assessed against the account's established activity patterns."
  - id: "review-dashboard-activity"
    order: 4
    name: "Review Dashboard Activity"
    action: "analyze"
    description: "Review available dashboard navigation, resource enumeration, metadata retrieval, administrative page access, and associated audit events."
    expected_result: "The observed dashboard activity and its relevance to cloud resource discovery are documented."
  - id: "review-cloud-resources"
    order: 5
    name: "Review Accessed Cloud Resources"
    action: "analyze"
    description: "Identify the services, resources, configurations, asset inventories, security findings, and administrative information accessed during the session."
    expected_result: "The accessed cloud resources and the sensitivity of the retrieved information are identified."
  - id: "correlate-cloud-events"
    order: 6
    name: "Correlate Related Activity"
    action: "hunt"
    description: "Correlate dashboard activity with identity provider events, cloud audit records, role assignments, credential changes, API activity, and subsequent resource access where available."
    expected_result: "Related authentication, discovery, and follow-on activity is correlated with the dashboard session."
  - id: "determine-dashboard-scope"
    order: 7
    name: "Determine Activity Scope"
    action: "hunt"
    description: "Determine the affected accounts, sessions, tenants, services, resources, and time range. Search for comparable activity across the environment."
    expected_result: "The scope, duration, and potential impact of the dashboard activity are documented."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity using the available authentication, dashboard, resource-access, and correlation evidence."
    expected_result: "The investigation outcome and supporting evidence are documented, with escalation initiated where required."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "cloud-service-dashboard"
---

# Cloud Service Dashboard

## Purpose

This playbook provides a structured workflow for investigating suspicious use of cloud service dashboards and administrative portals.

Cloud management interfaces provide authorized users with visibility into cloud services, resource inventories, configurations, and security information. Unauthorized access to these interfaces may allow an adversary to discover cloud resources and identify opportunities for subsequent activity.

The objective is to determine whether the observed dashboard access is legitimate, suspicious, or malicious and to establish the scope and potential impact of unauthorized resource discovery.

## MITRE ATT&CK

| Technique | Name                    | Relevance                                                                                                                        |
| --------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| T1538     | Cloud Service Dashboard | Primary technique for investigating suspicious dashboard use to discover cloud services, resources, and operational information. |

The technique applies when the observed behavior supports cloud service dashboard discovery. A suspicious login alone does not establish that T1538 activity occurred.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An alert identifies suspicious access to a cloud management dashboard or administrative portal.
- A cloud account accesses a dashboard from an unfamiliar location, device, IP address, or user agent.
- A privileged account accesses cloud dashboards or administrative interfaces outside its expected activity pattern.
- Dashboard navigation is followed by unusual resource enumeration or metadata retrieval.
- An account accesses sensitive cloud inventory, security findings, or administrative information without an established business justification.
- Authentication and audit logs indicate potentially unauthorized GUI-based access to cloud management services.
- Threat hunting identifies anomalous dashboard activity that warrants further investigation.

An unfamiliar location, unusual browser session, or privileged account does not independently establish malicious activity. Evaluate the complete session and its surrounding context.

## Scope

The investigation should consider:

- cloud provider;
- cloud tenant or organization;
- affected account;
- identity provider;
- account type and assigned roles;
- authentication method;
- MFA outcome;
- session identifier;
- source IP address;
- source geolocation;
- device and user agent;
- dashboard or administrative portal;
- session start and end times;
- accessed services;
- viewed resources and metadata;
- resource inventory and security findings;
- configuration pages accessed;
- related API activity;
- role or permission changes;
- associated alerts;
- other potentially affected accounts or tenants.

The available scope depends on the cloud provider, audit configuration, identity platform, and retention of relevant telemetry.

## Investigation Procedure

### Step 1 — Identify Cloud Dashboard Alert

Collect:

- detection source;
- alert identifier;
- event timestamp;
- cloud provider;
- tenant or organization;
- dashboard or portal;
- associated account;
- source IP address;
- detection reason;
- alert severity.

Determine which event initiated the investigation and preserve the original alert details.

### Step 2 — Identify Cloud Account and Session

Identify the account and session associated with the observed dashboard activity.

Collect:

- username or principal identifier;
- account type;
- tenant identifier;
- identity provider;
- session identifier;
- assigned cloud roles;
- effective permissions;
- authentication method;
- session creation time;
- session termination time, where available.

Determine whether the account and its privileges are expected for the affected cloud environment.

Distinguish human user sessions from service principals, service accounts, and other non-human identities where the platform supports this distinction.

### Step 3 — Review Authentication Context

Review the authentication events associated with the dashboard session.

Investigate:

- successful and failed sign-ins;
- MFA completion or failure;
- source IP and geolocation;
- device identity and compliance status;
- browser and user agent;
- unfamiliar authentication patterns;
- concurrent or overlapping sessions;
- recent password or credential changes;
- identity provider risk signals;
- activity inconsistent with the account's historical behavior.

Correlate the authentication timestamp with the dashboard activity.

An unfamiliar source or unusual login pattern should be treated as an investigative indicator rather than conclusive evidence of compromise.

### Step 4 — Review Dashboard Activity

Review the dashboard and administrative portal activity available in the relevant audit logs.

Determine whether the session involved:

- navigation across cloud management services;
- resource inventory enumeration;
- retrieval of resource metadata;
- review of security findings;
- access to administrative information;
- examination of account or application configuration;
- unusual browsing of sensitive management pages;
- activity inconsistent with the user's normal responsibilities.

Where telemetry permits, distinguish GUI-based dashboard activity from API, CLI, automation, and other access methods.

Identify gaps in dashboard navigation or audit records that limit the investigation.

### Step 5 — Review Accessed Cloud Resources

Identify the cloud resources and information accessed during the session.

Review:

- cloud services and resource types;
- resource names and identifiers;
- asset inventories;
- public IP addresses and exposed services;
- resource configuration metadata;
- security findings and posture information;
- identity and permission information;
- sensitive administrative interfaces;
- data-access events associated with the session.

Determine whether the accessed information was necessary for the user's role or an approved operational task.

If evidence indicates data access, configuration modification, credential activity, or other behavior beyond discovery, document those actions separately and initiate the applicable investigation or response workflow.

### Step 6 — Correlate Related Activity

Correlate dashboard activity with other available security telemetry.

Review:

- identity provider sign-in events;
- cloud audit logs;
- account and role changes;
- credential or token changes;
- API and CLI activity;
- access to sensitive resources;
- application or service principal activity;
- security alerts involving the same account;
- subsequent activity from the same source IP or device;
- comparable activity affecting other accounts or tenants.

Determine whether the dashboard session forms part of a wider sequence of potentially unauthorized activity.

Do not attribute API or CLI activity to the dashboard session solely because the events occurred close together. Use session identifiers, principal identifiers, timestamps, and other available correlation fields.

### Step 7 — Determine Activity Scope

Establish the full scope of the investigated activity.

Determine:

- first and last observed activity;
- number of affected accounts;
- number of affected sessions;
- affected tenants or organizations;
- cloud services and resources accessed;
- sensitivity of the information viewed;
- whether privileged access was involved;
- whether related unauthorized activity occurred;
- whether activity continued after the initial alert;
- whether comparable activity occurred elsewhere in the environment.

Document confirmed findings separately from inferred or unverified activity.

Identify missing telemetry and explain how it affects confidence in the assessment.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the final classification, supporting evidence, investigation limitations, and required follow-up actions.

## Evidence to Collect

| Evidence                | Description                                                                       |
| ----------------------- | --------------------------------------------------------------------------------- |
| Alert                   | Detection source, alert identifier, severity, timestamp, and detection rationale  |
| Cloud Tenant            | Provider, tenant or organization identifier, and affected environment             |
| Account                 | Principal identifier, account type, assigned roles, and effective permissions     |
| Authentication          | Sign-in events, authentication method, MFA outcome, and identity provider records |
| Session                 | Session identifier, creation time, duration, and associated activity              |
| Source Context          | Source IP, geolocation, device, browser, and user agent                           |
| Dashboard Activity      | Portal accessed, navigation events, metadata queries, and relevant audit records  |
| Cloud Resources         | Resource identifiers, types, metadata, and sensitivity                            |
| Administrative Activity | Role changes, configuration access, and other related actions                     |
| Correlation             | Related identity, API, CLI, resource-access, and security events                  |
| Timeline                | Authentication, dashboard, resource-access, and subsequent activity timestamps    |
| Scope                   | Affected accounts, sessions, tenants, services, and resources                     |
| Investigation Record    | Analyst findings, classification, evidence gaps, and escalation decisions         |

## Decision Criteria

### Benign

Classify the activity as **benign** when the available evidence supports legitimate, authorized dashboard usage.

Indicators may include:

- the account and session are recognized;
- authentication behavior is consistent with the user's established pattern;
- the device and source context are expected;
- dashboard access is consistent with the user's responsibilities;
- accessed resources have a documented operational purpose;
- the activity is consistent with approved administration or security review;
- no additional suspicious or unauthorized activity is identified.

Document the justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when the observed behavior deviates from expected activity but evidence is insufficient to confirm malicious intent.

Indicators may include:

- dashboard access from an unfamiliar device or location;
- unusual activity involving a privileged account;
- unexpected resource inventory enumeration;
- access to administrative information outside the user's normal responsibilities;
- inconsistent authentication or session activity;
- unexplained access to sensitive cloud resources;
- related events that cannot yet be attributed to legitimate operations.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence demonstrates unauthorized dashboard use or adversarial resource discovery.

Indicators may include:

- confirmed use of a compromised account to access the cloud dashboard;
- unauthorized enumeration of cloud resources or sensitive operational information;
- a dashboard session linked to confirmed malicious authentication activity;
- verified unauthorized access associated with broader compromise;
- corroborating evidence of adversarial activity during or after the dashboard session.

Escalate to the appropriate incident-response workflow.

Do not classify dashboard access as malicious solely because the account is privileged or the source is unfamiliar.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- missing authentication or audit records;
- unresolved questions about account ownership or session attribution;
- additional telemetry required;
- recommended follow-up actions.

Escalate when the investigation cannot establish the legitimacy of potentially sensitive or privileged access.

## Escalation

Escalate the investigation when:

- unauthorized cloud dashboard access is confirmed;
- a compromised or high-privilege account is involved;
- sensitive resource inventories or administrative information were accessed without authorization;
- access extends across multiple cloud services or tenants;
- related account, credential, or permission manipulation is identified;
- unauthorized resource access or data transfer is observed;
- the activity forms part of a broader cloud compromise;
- insufficient telemetry prevents the assessment of potentially high-impact activity.

Notify the appropriate cloud security, identity security, or incident-response team according to organizational procedures.

## Response Guidance

For confirmed malicious cloud dashboard activity:

1. Preserve relevant identity provider, cloud audit, session, and resource-access evidence.
2. Identify all affected accounts, sessions, tenants, and resources.
3. Follow the organization's approved identity and cloud containment procedures.
4. Revoke affected sessions or credentials where compromise is confirmed and the response is authorized.
5. Review account roles, permissions, credentials, and authentication settings for unauthorized changes.
6. Investigate related resource access, API activity, configuration changes, and potential data exposure.
7. Search for similar activity involving other accounts and cloud environments.
8. Apply appropriate access restrictions and remediation based on confirmed findings.
9. Verify that containment and remediation actions have taken effect.
10. Document the timeline, evidence, decisions, and recovery actions.

Avoid unnecessary disruption to legitimate cloud operations. Preserve evidence and coordinate containment with the appropriate cloud and identity owners.

If data exfiltration, persistence, or other attack behaviors are identified, use the applicable response playbooks to address those findings.

## Related Detection Rules

## Related Playbooks

- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/triage/data-exfiltration-triage.md`

## Validation

The playbook should be validated against authorized cloud dashboard access scenarios, identity provider logs, cloud audit records, and controlled resource-discovery activity.

Validation should confirm that:

- cloud dashboard sessions can be identified;
- account and authentication context can be established;
- dashboard activity can be distinguished from API or CLI activity where telemetry permits;
- resource enumeration and metadata access can be investigated;
- related authentication and cloud audit events can be correlated;
- legitimate administrative activity can be distinguished from suspicious activity;
- the scope of affected accounts, sessions, and resources can be determined;
- decision and escalation criteria produce consistent outcomes.

Validation must use authorized test accounts and controlled cloud environments.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Investigations must comply with organizational access policies, cloud provider requirements, evidence-handling procedures, and applicable privacy obligations.

Do not access, modify, export, or disclose cloud resources beyond the scope of the investigation and the permissions granted to the investigator.
