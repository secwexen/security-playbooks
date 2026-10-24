---
id: "cloud-service-discovery"
name: "Cloud Service Discovery"
category: "cloud"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-24T07:40:00Z"
updated_at: "2026-10-24T07:40:00Z"
description: "Investigate suspicious cloud service enumeration and determine whether the activity represents legitimate administration, reconnaissance, or malicious discovery."
objective: "Identify the cloud services and resources enumerated during suspicious activity, determine the associated identity and session context, establish the scope of discovery, and assess whether the activity is associated with unauthorized access or a broader security incident."
severity: "medium"
mitre_attack:
  - "T1526"
triggers:
  - "Unusual enumeration of cloud services through provider APIs."
  - "Unexpected volume of cloud service listing or description requests."
  - "Cloud service discovery performed by an identity that does not normally access the queried services."
  - "Enumeration across multiple cloud services, projects, subscriptions, accounts, or tenants."
  - "Cloud resource discovery associated with a suspicious authentication session."
  - "Unexpected discovery of identity services, applications, security controls, logging services, or CI/CD resources."
prerequisites:
  - "Access to relevant cloud audit logs and API activity records."
  - "Access to identity provider authentication and session telemetry."
  - "Access to cloud account, subscription, project, and resource inventory."
  - "Access to role assignments, permissions, and service authorization records."
  - "Knowledge of approved cloud administration workflows and expected service discovery activity."
tags:
  - "cloud"
  - "discovery"
  - "cloud-service-discovery"
  - "cloud-audit"
  - "identity"
  - "reconnaissance"
references:
  - "https://attack.mitre.org/techniques/T1526/"
steps:
  - id: "identify-cloud-discovery-alert"
    order: 1
    name: "Identify Cloud Discovery Alert"
    action: "investigate"
    description: "Identify the alert, detection source, affected cloud environment, observed discovery activity, and initial event context."
    expected_result: "The alert, relevant cloud environment, discovery activity, and initial investigation scope are identified."
  - id: "identify-cloud-identity-session"
    order: 2
    name: "Identify Cloud Identity and Session"
    action: "investigate"
    description: "Identify the user, service principal, workload identity, or role associated with the observed API activity and establish the relevant authentication and session context."
    expected_result: "The initiating identity, session context, authentication source, and applicable permissions are documented."
  - id: "review-service-enumeration"
    order: 3
    name: "Review Service Enumeration"
    action: "analyze"
    description: "Review cloud audit events and API requests to identify the services, resources, and configuration objects queried during the investigation period."
    expected_result: "The observed enumeration operations, requested resource types, timestamps, and associated API activity are documented."
  - id: "inventory-discovered-services"
    order: 4
    name: "Inventory Discovered Services"
    action: "analyze"
    description: "Identify the cloud services and resource categories accessed during enumeration, including compute, storage, databases, identity services, security controls, logging services, applications, and CI/CD resources where applicable."
    expected_result: "The discovered services and resources are categorized and their potential security relevance is assessed."
  - id: "review-access-context"
    order: 5
    name: "Review Access Context"
    action: "analyze"
    description: "Compare the observed activity with the identity's assigned permissions, normal administrative responsibilities, historical API usage, approved automation, source context, and expected operating patterns."
    expected_result: "The legitimacy of the identity's access and the observed discovery pattern is assessed against available baseline evidence."
  - id: "correlate-related-activity"
    order: 6
    name: "Correlate Related Activity"
    action: "hunt"
    description: "Correlate cloud service enumeration with recent authentication anomalies, role changes, credential activity, resource access, security control modifications, and other potentially related events."
    expected_result: "Related activity is identified and the presence of indicators associated with unauthorized access or a broader attack chain is assessed."
  - id: "determine-discovery-scope"
    order: 7
    name: "Determine Discovery Scope"
    action: "hunt"
    description: "Determine the identities, sessions, cloud accounts, subscriptions, projects, tenants, services, and resources involved in the observed discovery activity."
    expected_result: "The known scope, timeline, affected identities, and discovered resources are documented."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity using the available evidence, document the rationale, and determine whether additional investigation or incident response is required."
    expected_result: "The investigation outcome, supporting evidence, identified scope, and required follow-up actions are documented."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "cloud-service-discovery"
---

# Cloud Service Discovery

## Purpose

This playbook provides a structured workflow for investigating suspicious cloud service discovery activity across infrastructure, identity, application, and software-as-a-service environments.

Cloud service enumeration is a legitimate administrative activity used to inventory resources, manage cloud infrastructure, troubleshoot services, and assess security configurations. However, an unauthorized user or compromised identity may enumerate available services to identify valuable resources, understand the environment, locate security controls, or prepare subsequent attack activity.

The objective is to determine whether the observed enumeration is consistent with authorized operations, represents suspicious reconnaissance, or forms part of a confirmed security incident.

Service enumeration alone does not establish malicious intent. The investigation must consider identity context, authorization, activity patterns, environmental baselines, and related security events.

## MITRE ATT&CK

| Technique | Name                    | Relevance                                                                          |
| --------- | ----------------------- | ---------------------------------------------------------------------------------- |
| T1526     | Cloud Service Discovery | Primary technique associated with the enumeration of cloud services and resources. |

The investigation should focus on discovery activity across applicable cloud services and identity environments. Additional ATT&CK techniques should only be mapped when supported by observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An unusual number of cloud service enumeration requests originates from a user, service principal, or workload identity.
- An identity accesses services outside its normal administrative responsibilities.
- API requests enumerate resources across multiple cloud accounts, subscriptions, projects, or tenants without an established operational justification.
- Cloud discovery follows an unusual login, suspicious token use, or unexpected role assumption.
- An identity queries security monitoring, logging, identity management, or CI/CD services in an unusual context.
- Cloud audit telemetry identifies repeated service listing or resource description requests from an unexpected source.
- Threat hunting identifies service enumeration associated with other suspicious cloud activity.

A single listing request or an unfamiliar service query should not automatically be classified as malicious.

## Scope

The investigation should consider:

- Cloud provider and environment.
- Cloud account, subscription, project, or tenant.
- User, service principal, workload identity, or assumed role.
- Authentication session and access token context where available.
- Source IP address and relevant network context.
- API operation names and request timestamps.
- Enumerated services and resource categories.
- Queried resource identifiers and metadata.
- Assigned roles, permissions, and authorization context.
- User agent, client application, and originating workload where available.
- Related authentication and authorization events.
- Security monitoring and logging services accessed.
- Related resource access or configuration changes.
- Additional identities, accounts, or environments involved.

The investigation scope should be expanded when evidence indicates that the discovery activity extends beyond a single identity or cloud environment.

## Investigation Procedure

### Step 1 — Identify Cloud Discovery Alert

Collect the initial alert and associated event information:

- Detection source and alert identifier.
- Cloud provider and environment.
- Event timestamp and timezone.
- Initiating identity.
- API operation or activity type.
- Affected cloud account, subscription, project, or tenant.
- Source IP address and client information where available.
- Detection reason and severity.
- Related alerts or investigation references.

Preserve the original event details before taking containment actions.

Determine whether the alert represents a single enumeration request, a sequence of related requests, or activity spanning multiple services.

### Step 2 — Identify Cloud Identity and Session

Identify the principal responsible for the observed activity.

Determine whether the activity originated from:

- A human user account.
- A service principal or application identity.
- A workload identity.
- An assumed role or delegated identity.
- An approved automation or management service.

Review the available authentication and session context, including:

- Identity identifier and account type.
- Authentication timestamp.
- Session or correlation identifier.
- Source IP address.
- Client application or user agent.
- Role assumption or delegation events.
- Assigned permissions and effective authorization context.
- Recent authentication failures or anomalies.
- Relevant identity or role changes.

Determine whether the observed identity, session, and authorization context are consistent with the expected use of the environment.

An unfamiliar identity or privileged role does not independently confirm malicious activity.

### Step 3 — Review Service Enumeration

Examine the cloud audit records associated with the discovery activity.

Identify:

- API operation names.
- Requested services and resource types.
- Event timestamps and request frequency.
- Request results and authorization outcomes.
- Number of distinct services or resource categories queried.
- Accounts, subscriptions, projects, or tenants targeted.
- Source address and client metadata.
- Successful and unsuccessful requests.
- Relevant request or correlation identifiers.

Look for patterns such as rapid enumeration across unrelated services, repeated listing operations, unusual access to service metadata, or activity inconsistent with the identity's normal responsibilities.

Where supported by available telemetry, distinguish successful resource enumeration from failed requests or denied access attempts.

### Step 4 — Inventory Discovered Services

Determine which services and resource categories were queried.

Depending on the environment, examine:

- Compute and application hosting services.
- Storage and database services.
- Serverless functions and application platforms.
- Identity providers, applications, and service principals.
- CI/CD services and deployment infrastructure.
- Security monitoring and threat detection services.
- Audit logging and observability services.
- Resource management and configuration services.
- Connected SaaS applications and integrations.

For each relevant service or resource, document its identifier, environment, sensitivity, ownership, and security relevance where those details are available.

Prioritize resources that could expose sensitive data, credentials, privileged access, deployment capabilities, or information about defensive controls.

Discovery of a security service is not, by itself, evidence that the service was disabled or bypassed. Investigate any such action separately.

### Step 5 — Review Access Context

Assess whether the observed enumeration is consistent with the initiating identity's expected behavior.

Review:

- Assigned roles and permissions.
- Administrative responsibilities.
- Approved inventory or security assessment activities.
- Scheduled automation and service integrations.
- Historical API usage and established behavioral baselines.
- Source address and client application.
- Recent account or credential changes.
- Related session or role assumption activity.
- Change-management records where applicable.

Determine whether the identity had a legitimate reason to enumerate the observed services and whether the activity was performed through an expected execution context.

A valid identity and authorized API request can still be used for unauthorized reconnaissance. Evaluate the complete activity pattern instead of relying exclusively on authentication success.

### Step 6 — Correlate Related Activity

Correlate the discovery timeline with relevant cloud and identity events.

Investigate whether the enumeration occurred alongside:

- Suspicious authentication or session establishment.
- Unexpected role assignment or privilege changes.
- Unusual access to secrets or credential stores.
- Access to sensitive storage or database resources.
- Unexpected application or service principal changes.
- Attempts to modify security monitoring or audit logging.
- Unusual resource configuration changes.
- Other discovery activity across the environment.
- Evidence of unauthorized activity involving the same identity or source.

Determine whether the events can be linked through identity, session, source address, timestamps, resource identifiers, or other reliable correlation fields.

Do not infer a complete attack chain from temporal proximity alone. Record the evidence supporting each correlation.

### Step 7 — Determine Discovery Scope

Establish the known scope of the activity.

Search relevant audit sources for the same:

- Identity and session.
- Source IP address and client application.
- API operation pattern.
- Resource identifiers and service categories.
- Account, subscription, project, or tenant.
- Time window and related event sequence.

Determine:

- First and last observed activity.
- Number and types of services enumerated.
- Number of affected cloud environments.
- Identities and sessions involved.
- Whether sensitive resources were accessed beyond metadata enumeration.
- Whether additional unauthorized activity was identified.
- Whether the activity remains ongoing.

Document telemetry limitations and distinguish confirmed activity from suspected or unverified scope.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification and identify any required escalation or follow-up actions.

The classification must reflect the observed behavior and available evidence, not simply the presence of cloud service enumeration.

## Evidence to Collect

| Evidence              | Description                                                                          |
| --------------------- | ------------------------------------------------------------------------------------ |
| Alert                 | Detection source, alert identifier, severity, and timestamp.                         |
| Cloud Environment     | Provider, account, subscription, project, or tenant identifiers.                     |
| Identity              | User, service principal, workload identity, or assumed role.                         |
| Session               | Available session identifiers, authentication context, and correlation fields.       |
| API Activity          | Operation names, request timestamps, results, and request frequency.                 |
| Source Context        | Source IP address, client application, and user agent where available.               |
| Enumerated Services   | Service names, resource categories, and relevant identifiers.                        |
| Permissions           | Assigned roles, effective permissions, and role assumption context.                  |
| Authentication        | Related login, token, and identity events.                                           |
| Related Activity      | Correlated resource access, configuration changes, and security alerts.              |
| Timeline              | Chronological sequence of discovery and related activity.                            |
| Scope                 | Affected identities, sessions, services, and cloud environments.                     |
| Investigation Outcome | Classification, supporting evidence, outstanding questions, and escalation decision. |

## Decision Criteria

### Benign

Classify the activity as **benign** when the available evidence supports legitimate administrative or automated operations, including:

- The initiating identity is authorized to perform the observed discovery.
- The activity corresponds to an approved inventory, maintenance, deployment, or security assessment workflow.
- The requested services are consistent with the identity's responsibilities.
- Request frequency and scope are consistent with established behavior or documented operational changes.
- Source, session, and client context are expected.
- No corroborating evidence of unauthorized access or malicious follow-on activity is identified.

Document the operational justification and supporting evidence before closing the alert.

### Suspicious

Classify the activity as **suspicious** when one or more unexplained indicators remain, including:

- Enumeration exceeds the identity's normal scope or frequency.
- An identity accesses unrelated services without a clear operational justification.
- Discovery spans multiple accounts, subscriptions, projects, or tenants unexpectedly.
- The source address, client application, or session context is unusual.
- Sensitive services, identity resources, or security controls are queried unexpectedly.
- The activity follows suspicious authentication or privilege changes.
- Available telemetry is insufficient to establish the legitimacy of the activity.

Continue the investigation and collect additional evidence. Escalate according to the organization's cloud security procedures when risk warrants it.

### Malicious

Classify the activity as **malicious** when sufficient evidence establishes unauthorized discovery or connects the observed enumeration to confirmed malicious activity, such as:

- Cloud service enumeration performed through a confirmed compromised identity or unauthorized session.
- Discovery associated with confirmed unauthorized access to sensitive resources.
- Enumeration that forms part of a corroborated attack chain involving credential access, privilege abuse, unauthorized resource modification, or other malicious actions.
- Confirmed reconnaissance conducted by an unauthorized actor.

Escalate to the appropriate incident-response workflow and follow approved containment procedures.

Do not classify discovery as malicious solely because a large number of APIs or services were queried.

### Inconclusive

Use **inconclusive** when the available evidence is insufficient to distinguish legitimate administration from unauthorized discovery.

Document:

- Evidence collected and its reliability.
- Missing or unavailable audit sources.
- Unresolved identity or session context.
- Services and resources that could not be fully assessed.
- Additional telemetry or investigation required.

Keep the case open or escalate according to the organization's investigation policy when the remaining uncertainty presents material risk.

## Escalation

Escalate the investigation when:

- Unauthorized cloud access is suspected or confirmed.
- Discovery activity is associated with a compromised identity or unexpected privileged session.
- Sensitive services, credentials, or high-value resources are involved.
- Enumeration spans multiple cloud environments or identities.
- Security monitoring or audit logging services are targeted in suspicious circumstances.
- Related privilege escalation, data access, persistence, or other malicious activity is identified.
- The investigation cannot establish the scope of potentially unauthorized activity.
- The affected environment is business-critical or subject to specific regulatory obligations.

Notify the relevant cloud security, identity, and incident-response teams according to the organization's escalation procedures.

## Response Guidance

For confirmed malicious cloud service discovery:

1. Preserve relevant cloud audit records, identity events, API activity, and session context.
2. Identify the affected identities, sessions, cloud accounts, and discovered resources.
3. Escalate to the designated cloud incident-response team.
4. Investigate how the initiating identity or session obtained access.
5. Assess whether sensitive resources were accessed or modified beyond service enumeration.
6. Hunt for related activity across connected cloud environments and identities.
7. Revoke sessions, rotate credentials, or restrict identity permissions when justified by the evidence and authorized incident-response procedures.
8. Review security monitoring and audit logging to determine whether relevant telemetry remains available and trustworthy.
9. Apply targeted containment measures that account for business and service dependencies.
10. Document the timeline, evidence, scope, containment decisions, and recovery requirements.

Do not disable cloud services, revoke broad permissions, or remove resources solely because they were enumerated. Such actions may disrupt legitimate operations and should be based on confirmed risk and approved response procedures.

## Related Detection Rules

## Related Playbooks

- `playbooks/execution/wmi-execution.md`
- `playbooks/triage/persistence-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/response/persistence-removal-response.md`

## Validation

The playbook should be validated against approved cloud audit datasets, identity telemetry, controlled service enumeration scenarios, and documented administrative workflows.

Validation should confirm that:

- Cloud service enumeration can be identified from available audit records.
- The initiating identity and relevant session context can be established.
- Queried services and resource categories can be determined.
- Unusual enumeration patterns can be distinguished from documented administrative activity.
- Related authentication and authorization events can be correlated.
- The scope of discovery can be determined across relevant cloud environments.
- Investigation outcomes are supported by documented evidence.
- Escalation criteria produce consistent results.
- Response guidance preserves evidence and accounts for operational impact.

Validation must use authorized environments and controlled scenarios. The playbook's `validated` metadata must only be updated after the required validation has been completed and recorded.

## Safety

This playbook is intended for defensive security operations, authorized cloud security assessments, incident response, and controlled validation.

Investigations must comply with organizational authorization, privacy, evidence-preservation, and cloud access policies.

Use approved read-only access where possible. Do not access sensitive resources, modify cloud configurations, revoke identities, disable services, or alter audit settings unless the action is authorized and justified by the investigation.

Preserve relevant evidence before performing containment or remediation when operationally feasible.
