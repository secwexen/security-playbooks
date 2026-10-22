---
id: "cloud-secrets-access"
name: "Cloud Secrets Access"
category: "cloud"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-22T17:45:00Z"
updated_at: "2026-10-22T17:45:00Z"
description: "Investigate suspicious or unauthorized access to cloud-based secrets management services and determine whether sensitive credentials may have been exposed."
objective: "Identify unauthorized cloud secrets access, assess potential credential exposure, determine the affected identities and resources, and provide evidence for containment and remediation."
severity: "high"
mitre_attack:
  - "T1555.006"
triggers:
  - "Unexpected access to a cloud secrets management service"
  - "Secret retrieval by an unfamiliar identity or workload"
  - "Unusual volume or frequency of secret retrieval operations"
  - "Secret access from an unexpected IP address, region, or device"
  - "Secret retrieval following suspicious authentication or privilege changes"
  - "Access to secrets outside established operational patterns"
prerequisites:
  - "Access to cloud authentication and audit logs"
  - "Access to secrets management audit events"
  - "Access to cloud identity and access management records"
  - "Access to secret ownership and classification metadata"
  - "An established process for handling potentially exposed credentials"
tags:
  - "cloud"
  - "credential-access"
  - "secrets-management"
  - "identity"
  - "access-control"
  - "secret-exposure"
references:
  - "https://attack.mitre.org/techniques/T1555/006/"
  - "https://attack.mitre.org/detectionstrategies/DET0130/"
steps:
  - id: "identify-cloud-secrets-access-alert"
    order: 1
    name: "Identify Cloud Secrets Access Alert"
    action: "investigate"
    description: "Identify the detection source, affected cloud account, secret resource, accessing identity, operation, timestamp, and alert context."
    expected_result: "The suspicious secret access event and its associated cloud resources are identified."
  - id: "identify-cloud-identity-and-secret-store"
    order: 2
    name: "Identify Cloud Identity and Secret Store"
    action: "investigate"
    description: "Identify the cloud provider, secret management service, secret resource identifier, owning team, associated workload, and identity responsible for the request."
    expected_result: "The secret store, affected resource, responsible identity, and ownership context are documented."
  - id: "review-authentication-and-session-context"
    order: 3
    name: "Review Authentication and Session Context"
    action: "analyze"
    description: "Review authentication events, session creation, role assumptions, workload identity activity, source network information, and relevant identity or access policy changes."
    expected_result: "The authentication context and legitimacy of the accessing identity are assessed."
  - id: "review-secret-retrieval-activity"
    order: 4
    name: "Review Secret Retrieval Activity"
    action: "analyze"
    description: "Review available secret access events, requested operations, access results, retrieval frequency, access volume, and deviations from expected usage patterns."
    expected_result: "The nature, timing, frequency, and apparent legitimacy of the secret access activity are established."
  - id: "assess-secret-sensitivity-and-exposure"
    order: 5
    name: "Assess Secret Sensitivity and Exposure"
    action: "analyze"
    description: "Determine the secret classification, intended purpose, affected applications, associated privileges, and potential impact if the secret was exposed or misused."
    expected_result: "The sensitivity of the affected secrets and the potential consequences of unauthorized access are documented."
  - id: "correlate-related-cloud-activity"
    order: 6
    name: "Correlate Related Cloud Activity"
    action: "hunt"
    description: "Correlate secret access with authentication anomalies, privilege changes, identity creation, other secret access events, workload activity, and potential downstream use of the credentials."
    expected_result: "Related activity is correlated and evidence of possible credential misuse or broader cloud compromise is identified or ruled out."
  - id: "determine-exposure-scope"
    order: 7
    name: "Determine Exposure Scope"
    action: "hunt"
    description: "Search available audit records for related activity involving the same identity, session, source, secret resources, and relevant investigation time window."
    expected_result: "The number of affected secrets, identities, workloads, and cloud resources is determined where available."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity using the available evidence, document the potential exposure and affected resources, and determine whether escalation is required."
    expected_result: "The investigation outcome, supporting evidence, exposure scope, and recommended next actions are documented."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "cloud-secrets-access"
---

# Cloud Secrets Access

## Purpose

This playbook provides a structured workflow for investigating suspicious or unauthorized access to cloud-based secrets management services.

Cloud secrets management services centrally store sensitive authentication material, including passwords, API keys, access tokens, connection strings, and cryptographic credentials. Examples include AWS Secrets Manager, Google Cloud Secret Manager, Azure Key Vault, and HashiCorp Vault.

Although these services are designed to protect sensitive information, excessive permissions, compromised identities, abused workload credentials, or unauthorized role assumptions may allow secrets to be retrieved outside approved operational processes.

The objective is to determine whether the observed access was authorized, identify potentially exposed credentials, assess the impact on affected resources, and establish whether containment or incident response is required.

## MITRE ATT&CK

| Technique | Name                                                              | Relevance                                                                                                                 |
| --------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | Primary technique when cloud-native secrets management services are accessed to obtain credentials without authorization. |

This mapping applies when the observed behavior involves acquiring credentials from a cloud secrets management store. Suspicious authentication, privilege changes, or subsequent use of exposed credentials should be mapped separately only when supported by the investigation evidence.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A secret is accessed by an unfamiliar user, service principal, role, or workload identity.
- Secret retrieval occurs from an unexpected network location or cloud region.
- A principal retrieves an unusual number of secrets or performs repeated retrieval operations outside its normal pattern.
- Secret access follows a suspicious login, session creation, role assumption, or privilege modification.
- A workload accesses secrets unrelated to its documented function.
- Access attempts target sensitive secrets that the associated identity does not normally use.
- Cloud audit records indicate potentially unauthorized retrieval of secret values.
- Threat hunting identifies suspicious activity involving cloud secret stores.

A single successful secret access event does not establish malicious activity. Assess the identity, resource, authorization context, and surrounding events before reaching a conclusion.

## Scope

The investigation should consider:

- cloud provider;
- cloud account, project, subscription, or tenant;
- region;
- secrets management service;
- secret resource identifier;
- secret version;
- secret classification;
- secret owner;
- associated application or workload;
- accessing identity;
- identity type;
- role and effective permissions;
- authentication method;
- session identifier;
- source IP address;
- source region;
- user agent or client application where available;
- requested operation;
- access result;
- event timestamp;
- retrieval frequency and volume;
- relevant identity and policy changes;
- potential downstream use of exposed credentials;
- other affected secrets and cloud resources.

The investigation should use the available cloud audit and identity telemetry. The exact fields and event names depend on the provider and the services deployed in the environment.

## Investigation Procedure

### Step 1 — Identify Cloud Secrets Access Alert

Collect the initial alert context:

- detection source;
- alert identifier;
- event timestamp;
- cloud provider;
- account, project, subscription, or tenant;
- secret resource identifier;
- accessing identity;
- requested operation;
- access result;
- source IP address;
- detection severity;
- detection rationale.

Record the original event and preserve relevant identifiers before making changes to the affected identity or secret.

Determine whether the event represents an attempted access, a successful metadata operation, or a successful retrieval operation. These outcomes have different implications for potential credential exposure.

### Step 2 — Identify Cloud Identity and Secret Store

Identify the affected secret management service and its associated resources.

Review:

- cloud account or tenant;
- secret store or vault;
- secret identifier;
- secret version where available;
- resource owner;
- owning application or service;
- classification and sensitivity;
- authorized identities;
- documented consumers of the secret;
- applicable access policies.

Determine whether the accessing identity is expected to retrieve the secret and whether the resource is relevant to that identity's documented responsibilities.

Avoid retrieving secret values solely to establish their identity or ownership. Use resource metadata, access records, and approved inventory sources wherever possible.

### Step 3 — Review Authentication and Session Context

Determine how the accessing identity obtained its authentication context.

Review available records for:

- successful and failed authentication events;
- identity type and authentication method;
- session creation time;
- role assumption or privilege elevation;
- service principal or workload identity activity;
- multi-factor authentication context where applicable;
- source IP address and network location;
- device or client information;
- recent identity configuration changes;
- recent permission or access policy changes.

Assess whether the source, session, and role are consistent with the identity's normal behavior.

Pay particular attention to secret access following an unusual login, unexpected role assumption, newly created credential, or modification to the permissions of a user or workload.

### Step 4 — Review Secret Retrieval Activity

Examine available audit events associated with the affected secret and accessing identity.

Determine:

- which operations were requested;
- whether the requests succeeded or failed;
- which secret resources were accessed;
- whether secret values were requested;
- the number and frequency of retrieval events;
- whether access involved multiple secrets;
- whether the activity deviated from normal usage;
- whether the same identity accessed unrelated resources;
- whether access was preceded by enumeration or permission changes.

Compare the events with documented application behavior, scheduled processes, deployment activity, and expected administrative operations.

Do not classify access as malicious based solely on retrieval volume or time of day. Correlate these indicators with authorization, resource ownership, identity behavior, and additional evidence.

### Step 5 — Assess Secret Sensitivity and Exposure

Determine the potential impact of access to each affected secret.

Consider whether the secret contains or provides access to:

- application authentication;
- cloud service credentials;
- API authentication;
- database connections;
- privileged service accounts;
- deployment systems;
- signing or encryption operations;
- other sensitive infrastructure.

Review the secret's intended use, privilege level, applicable access boundaries, and dependent systems.

Determine whether the audit evidence confirms successful retrieval or only indicates an attempted operation. Where logs do not establish whether secret material was returned or subsequently used, document that uncertainty explicitly.

Do not copy secret values into investigation tickets, chat messages, general-purpose logs, or reports. Access actual secret material only when explicitly authorized and necessary for the investigation, following approved evidence-handling procedures.

### Step 6 — Correlate Related Cloud Activity

Correlate the suspected access with surrounding identity and cloud activity.

Review available records for:

- suspicious authentication events;
- role assignments or permission changes;
- creation or modification of identities;
- new access keys, tokens, or credentials;
- access to other secret stores;
- unusual API activity;
- changes to workload configuration;
- unexpected compute or application execution;
- use of potentially exposed credentials against other services;
- related alerts from cloud security tooling.

Determine whether the secret access is an isolated event or part of a broader compromise.

Where relevant, coordinate with the owners of the affected applications, identities, and cloud resources to establish whether the observed access corresponds to an approved operational task.

### Step 7 — Determine Exposure Scope

Establish the scope of potentially unauthorized access by searching the available audit records.

Search for:

- the same accessing identity;
- the same session or role;
- the same source IP address;
- the same secret identifier;
- other secrets accessed by the identity;
- repeated access patterns;
- related identity or permission changes;
- downstream activity associated with potentially exposed credentials.

Determine:

- the first and last observed event;
- the number of potentially affected secrets;
- the number of affected identities and workloads;
- the cloud accounts or projects involved;
- whether sensitive applications were potentially exposed;
- whether suspicious access remains ongoing;
- whether credential misuse is supported by available evidence.

Document gaps in logging or visibility that prevent the scope from being established conclusively.

### Step 8 — Determine Investigation Outcome

Classify the observed activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the supporting evidence, potentially exposed resources, affected identities, investigation limitations, and required follow-up actions.

Escalate to the appropriate incident response process when the evidence indicates unauthorized secret retrieval, potential credential compromise, or subsequent misuse.

## Evidence to Collect

| Evidence             | Description                                                                        |
| -------------------- | ---------------------------------------------------------------------------------- |
| Alert                | Detection source, alert ID, severity, and timestamp                                |
| Cloud Resource       | Provider, account, project, subscription, tenant, and region                       |
| Secret Resource      | Secret identifier, version, owner, classification, and intended purpose            |
| Identity             | User, service principal, role, or workload identity                                |
| Authentication       | Authentication events, session context, source IP, and relevant client details     |
| Access Event         | Requested operation, event result, timestamp, and associated resource              |
| Access Policy        | Applicable permissions, role assignments, and relevant policy changes              |
| Retrieval Pattern    | Frequency, volume, resource coverage, and deviation from expected activity         |
| Related Activity     | Associated identity, workload, API, and cloud resource events                      |
| Exposure Scope       | Potentially affected secrets, identities, applications, and cloud resources        |
| Timeline             | Chronological sequence of authentication, secret access, and related activity      |
| Investigation Record | Classification, supporting evidence, limitations, escalation, and response actions |

Evidence collection must follow the organization's data handling, access control, and evidence preservation requirements.

## Decision Criteria

### Benign

Classify the activity as **benign** when the available evidence consistently indicates authorized use.

Examples include:

- the accessing identity is authorized to retrieve the secret;
- the secret is associated with the identity's documented responsibilities;
- the access corresponds to an approved deployment, application operation, or administrative task;
- the timing, volume, and resource selection are consistent with established behavior;
- authentication and session context are expected;
- no corroborating evidence of credential misuse or unauthorized activity is identified.

Document the operational justification before closing the investigation.

### Suspicious

Classify the activity as **suspicious** when one or more indicators require additional investigation but malicious activity is not yet established.

Examples include:

- an unfamiliar identity accesses a sensitive secret;
- retrieval frequency or volume differs significantly from the established baseline;
- secret access follows an unusual authentication event;
- the source location or session context is unexpected;
- an identity accesses secrets outside its documented responsibilities;
- recent permissions or role assignments are unexplained;
- incomplete audit records prevent reliable verification of authorization.

Continue investigation and obtain additional evidence before making a final determination.

### Malicious

Classify the activity as **malicious** when sufficient evidence supports unauthorized access or credential acquisition.

Examples include:

- an unauthorized identity successfully retrieves sensitive secret material;
- secret access is linked to a confirmed compromised account or workload;
- an attacker-controlled session is used to retrieve secrets;
- unauthorized access is followed by confirmed misuse of the affected credentials;
- secret retrieval is part of a verified cloud compromise;
- access policies or identities were deliberately modified to facilitate unauthorized retrieval.

Escalate to incident response and initiate authorized containment and credential remediation procedures.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the activity was authorized or malicious.

Document:

- evidence collected;
- required evidence that is unavailable;
- gaps in cloud audit or identity telemetry;
- access events whose results cannot be confirmed;
- remaining uncertainty about potential credential exposure;
- additional investigation or authorization required.

Do not classify the activity as benign merely because the investigation lacks evidence of malicious behavior.

## Escalation

Escalate the investigation when:

- unauthorized retrieval of sensitive secret material is confirmed;
- a privileged cloud identity or workload identity may be compromised;
- secret access is associated with an anomalous authentication session;
- access extends across multiple secrets, accounts, projects, subscriptions, or tenants;
- potentially exposed credentials are associated with critical applications or infrastructure;
- the same identity exhibits suspicious activity across multiple cloud services;
- evidence indicates downstream use of potentially exposed credentials;
- the access remains active or the scope cannot be contained within the initial investigation;
- required evidence is unavailable and the potential impact is high.

Notify the cloud security team, identity and access management team, resource owner, and incident response team according to the organization's escalation procedures.

## Response Guidance

For confirmed malicious or unauthorized cloud secrets access:

1. Preserve relevant cloud audit events, identity records, access policy history, and investigation timestamps.
2. Identify the affected secrets, identities, workloads, applications, and cloud resources.
3. Contain the compromised identity or session using the organization's approved procedures.
4. Revoke or invalidate compromised sessions, tokens, or credentials when supported by the evidence and operational authorization.
5. Rotate or revoke potentially exposed secrets according to their ownership, sensitivity, and dependency requirements.
6. Verify that dependent applications and workloads receive updated credentials through approved mechanisms.
7. Review and remediate excessive permissions or unauthorized access policy changes.
8. Investigate whether potentially exposed credentials were used against other cloud services or external systems.
9. Monitor for repeated secret retrieval, continued unauthorized access, and related authentication anomalies.
10. Document containment, credential remediation, service impact, and recovery verification.

Do not indiscriminately disable production identities or rotate shared credentials without evaluating dependencies and following the appropriate change or incident response procedure. Preserve required evidence before making changes whenever operationally feasible.

## Related Detection Rules

## Related Playbooks

- `playbooks/credential-access/credential-access.md`
- `playbooks/credential-access/credentials-from-password-stores.md`
- `playbooks/response/account-compromise-response.md`

## Validation

The playbook should be validated against approved cloud audit logs, secrets management access events, identity activity, access policy records, and controlled test scenarios.

Validation should confirm that:

- secret access events can be identified and interpreted;
- accessing identities and applicable permissions can be established;
- successful retrieval can be distinguished from failed access attempts where telemetry supports this distinction;
- unusual retrieval patterns can be compared with expected operational behavior;
- related authentication and permission changes can be correlated;
- potentially exposed secrets and dependent resources can be identified;
- the scope of suspicious activity can be established from available records;
- escalation and credential remediation criteria produce consistent outcomes;
- evidence is collected without unnecessarily exposing secret values.

Record the validation results, telemetry limitations, and any environment-specific requirements before marking the playbook as validated.

## Safety

This playbook is intended for defensive security operations, cloud security investigations, controlled validation, and authorized testing.

Use read-only audit and metadata sources wherever possible. Do not expose, copy, or disclose secret values unless access is authorized and necessary for the investigation. Credential revocation, rotation, identity containment, and access policy changes must follow approved authorization, evidence preservation, and change management procedures.

Testing must use approved non-production resources or explicitly authorized scenarios. Do not access secrets belonging to unrelated users, applications, or tenants.
