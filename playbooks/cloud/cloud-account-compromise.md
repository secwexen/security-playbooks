---
id: "cloud-account-compromise"
name: "Cloud Account Compromise"
category: "cloud"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-16T19:48:00Z"
updated_at: "2026-10-16T19:48:00Z"
description: "Investigate suspected compromise or unauthorized use of cloud accounts and determine the scope, impact, and persistence of the activity."
objective: "Identify compromised cloud identities, establish the extent of unauthorized access, preserve relevant evidence, and coordinate containment and recovery."
severity: "high"
mitre_attack:
  - "T1078.004"
triggers:
  - "Unusual or unauthorized cloud account authentication"
  - "Successful sign-in following suspicious authentication attempts"
  - "Unexpected authentication from an unfamiliar device, location, or network"
  - "Unexpected changes to cloud account privileges or role assignments"
  - "Suspicious token issuance, session activity, or credential modification"
  - "Unauthorized access to cloud resources or administrative interfaces"
  - "Identity provider alert indicating a potentially compromised account"
prerequisites:
  - "Access to cloud identity and authentication logs"
  - "Access to cloud audit and administrative activity logs"
  - "Access to account, role, and permission information"
  - "Access to relevant session, token, and credential activity records"
  - "An approved process for account containment and credential recovery"
tags:
  - "cloud"
  - "identity"
  - "account-compromise"
  - "authentication"
  - "incident-response"
  - "iam"
references:
  - "https://attack.mitre.org/techniques/T1078/004/"
  - "https://attack.mitre.org/detectionstrategies/DET0546/"
steps:
  - id: "identify-cloud-account-compromise-alert"
    order: 1
    name: "Identify Cloud Account Compromise Alert"
    action: "investigate"
    description: "Identify the originating alert, cloud environment, affected account, detection timestamp, and reason for investigation."
    expected_result: "The alert context, affected cloud environment, and initial indicators are documented."
  - id: "identify-cloud-identity-account"
    order: 2
    name: "Identify the Cloud Identity and Account"
    action: "investigate"
    description: "Identify the affected tenant, account, identity provider, account type, assigned roles, and relevant identity relationships."
    expected_result: "The affected identity and its normal administrative and access context are established."
  - id: "review-authentication-session-activity"
    order: 3
    name: "Review Authentication and Session Activity"
    action: "analyze"
    description: "Analyze sign-in events, authentication outcomes, MFA activity, session metadata, source networks, devices, and deviations from the account's baseline."
    expected_result: "Authentication anomalies and potentially unauthorized sessions are identified and documented."
  - id: "review-privilege-role-changes"
    order: 4
    name: "Review Privilege and Role Changes"
    action: "analyze"
    description: "Review changes to role assignments, group membership, IAM policies, administrative permissions, and other access-control settings."
    expected_result: "Unexpected privilege changes and potentially unauthorized access grants are identified."
  - id: "review-token-credential-activity"
    order: 5
    name: "Review Token and Credential Activity"
    action: "analyze"
    description: "Investigate token issuance, session refreshes, credential changes, access-key activity, MFA modifications, and other authentication-related changes."
    expected_result: "Potentially compromised credentials, tokens, sessions, and authentication methods are identified."
  - id: "review-cloud-resource-activity"
    order: 6
    name: "Review Cloud Resource Activity"
    action: "analyze"
    description: "Correlate the affected identity's activity with cloud API operations, administrative actions, resource access, configuration changes, and potentially sensitive data access."
    expected_result: "Potentially unauthorized resource operations and affected cloud services are documented."
  - id: "determine-compromise-scope"
    order: 7
    name: "Determine Compromise Scope"
    action: "hunt"
    description: "Search for related activity across identities, sessions, credentials, cloud resources, and connected environments to establish the extent and duration of the incident."
    expected_result: "The affected accounts, resources, privileges, and relevant investigation timeline are established."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Assess all available evidence, classify the activity, document confidence and unresolved questions, and determine whether incident response is required."
    expected_result: "A documented investigation outcome and appropriate escalation decision are produced."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "cloud-account-compromise"
---

# Cloud Account Compromise

## Purpose

This playbook provides a structured workflow for investigating suspected compromise or unauthorized use of cloud accounts.

Cloud account compromise may involve stolen credentials, abuse of valid accounts, unauthorized sessions, compromised authentication tokens, or misuse of excessive privileges. Such activity can affect cloud infrastructure, identity providers, SaaS applications, and environments connected through federation or synchronization.

The objective is to determine whether the observed activity is legitimate, suspicious, or malicious; establish the scope of unauthorized access; preserve relevant evidence; and coordinate appropriate containment and recovery.

A successful authentication alone does not establish account compromise. Findings must be evaluated in the context of account behavior, authentication controls, privileges, resource activity, and corroborating evidence.

## MITRE ATT&CK

| Technique | Name                           | Relevance                                                                                         |
| --------- | ------------------------------ | ------------------------------------------------------------------------------------------------- |
| T1078.004 | Valid Accounts: Cloud Accounts | Primary technique when valid cloud accounts are abused to obtain or maintain unauthorized access. |

The technique is associated with Initial Access, Persistence, Privilege Escalation, and Stealth. Additional technique mappings should only be added when the observed behavior supports them.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An identity provider reports suspicious cloud account authentication.
- A successful sign-in follows unusual or suspicious authentication attempts.
- Authentication occurs from an unfamiliar device, network, or location and deviates from the account's established baseline.
- MFA settings or authentication methods change unexpectedly.
- An account receives unexpected administrative privileges.
- Unfamiliar sessions, tokens, or access keys appear.
- Cloud API activity deviates significantly from the account's normal usage.
- An account accesses sensitive resources that are outside its expected operational responsibilities.
- A cloud security alert indicates possible unauthorized account access.

A single indicator, such as an unfamiliar IP address or unusual location, should not independently be treated as proof of compromise.

## Scope

The investigation should consider:

- cloud provider and service;
- tenant, subscription, project, or organization;
- affected user or service identity;
- account type and identity provider;
- account privileges and role assignments;
- authentication events and outcomes;
- MFA and conditional access activity;
- source IP addresses and network information;
- device and session metadata;
- access tokens and credential changes;
- cloud API operations;
- administrative and configuration changes;
- resource access and data operations;
- connected or federated identities;
- other potentially affected accounts and resources;
- first observed and most recent suspicious activity.

The investigation must account for provider-specific logging capabilities and retention limitations.

## Investigation Procedure

### Step 1 — Identify Cloud Account Compromise Alert

Collect the original alert and establish the initial investigation context.

Record:

- alert identifier;
- detection source;
- detection timestamp;
- cloud provider or service;
- affected account identifier;
- associated tenant or organization;
- detection severity;
- reported suspicious behavior;
- available event and correlation identifiers.

Preserve the original alert data before performing containment or account changes.

Determine whether the alert concerns a successful sign-in, failed authentication attempts, a privilege change, suspicious resource activity, or another identity-related event.

### Step 2 — Identify the Cloud Identity and Account

Establish the identity and its expected operating context.

Collect:

- username or principal identifier;
- tenant or organization identifier;
- identity provider;
- account type;
- account owner;
- assigned roles and permissions;
- group memberships;
- federation or synchronization relationships;
- expected administrative responsibilities;
- account status and applicable authentication policies.

Determine whether the account is a standard user, privileged administrator, service identity, application identity, or another identity type.

Compare its access and responsibilities with the affected environment's established configuration.

Do not assume that a privileged account is compromised solely because it has extensive permissions.

### Step 3 — Review Authentication and Session Activity

Review authentication logs and session information surrounding the suspicious activity.

Collect:

- authentication timestamps;
- authentication outcome;
- source IP address;
- source network or ASN where available;
- geographic information where available;
- device identity and compliance status;
- client application;
- authentication protocol;
- MFA results;
- conditional access decisions;
- session identifiers;
- sign-in risk indicators;
- relevant preceding and subsequent authentication events.

Compare the activity against the account's normal usage patterns.

Investigate:

- successful access following suspicious authentication attempts;
- unfamiliar devices or client applications;
- unexpected authentication protocols;
- authentication patterns inconsistent with normal working hours or responsibilities;
- suspicious session reuse;
- authentication activity inconsistent with established access policies.

Correlate multiple indicators before concluding that authentication was unauthorized. Geographic anomalies and unusual IP addresses may also result from VPNs, proxies, mobile networks, or legitimate travel.

### Step 4 — Review Privilege and Role Changes

Determine whether the account or related identities experienced unexpected permission changes.

Review:

- role assignments and removals;
- administrative group membership;
- IAM policy changes;
- permission grants;
- changes to privileged access settings;
- changes to service or application identities;
- modifications to access-control policies;
- changes affecting federated identities;
- relevant administrative audit events.

Identify the actor responsible for each change, the associated timestamp, the target identity or resource, and the resulting permissions.

Determine whether the changes were approved and consistent with documented administrative activity.

If unauthorized privilege escalation is suspected, preserve the relevant audit events and escalate according to the organization's incident-response procedures.

### Step 5 — Review Token and Credential Activity

Investigate changes and activity involving credentials, tokens, and authentication methods.

Review:

- access-token and refresh-token activity where available;
- session issuance and renewal;
- access-key creation or rotation;
- password changes or resets;
- addition or removal of MFA methods;
- changes to recovery methods;
- creation of additional credentials;
- service identity credential changes;
- authentication activity following credential modification.

Determine whether the observed activity can be attributed to an authorized user, administrator, application, or automation process.

Identify credentials or sessions that may require revocation through approved containment procedures.

Do not copy passwords, secret values, private keys, or bearer tokens into incident notes. Record relevant identifiers and metadata without unnecessarily exposing sensitive authentication material.

### Step 6 — Review Cloud Resource Activity

Correlate the account's identity activity with operations performed in the cloud environment.

Review available audit logs for:

- resource enumeration;
- administrative operations;
- IAM and security configuration changes;
- access to sensitive storage or secrets;
- data download or export operations;
- creation of unfamiliar resources;
- changes to logging or monitoring configurations;
- modification of network or access policies;
- activity involving connected services;
- unusual API request volume or operation patterns.

Determine whether the activity was expected for the account and whether the operations were authorized.

Record the affected resources, operation types, timestamps, initiating identity, and available request or correlation identifiers.

Investigate suspicious resource activity in conjunction with authentication and credential evidence. A successful API operation alone does not establish malicious intent.

### Step 7 — Determine Compromise Scope

Establish the extent and duration of the suspected compromise.

Search for related activity involving:

- the affected account;
- associated identities and administrative accounts;
- shared or federated identities;
- related sessions and credentials;
- recently modified role assignments;
- associated application identities;
- affected cloud resources;
- other accounts showing similar authentication patterns;
- potentially affected connected environments.

Determine:

- first known suspicious activity;
- most recent suspicious activity;
- confirmed affected accounts;
- affected sessions and credentials;
- unauthorized privileges or access grants;
- affected resources and data;
- whether unauthorized access is ongoing;
- whether the incident extends beyond the original cloud environment.

Separate confirmed findings from suspected relationships. Document limitations caused by unavailable telemetry or insufficient log retention.

### Step 8 — Determine Investigation Outcome

Classify the activity using the following outcomes:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the selected classification and supporting evidence.

Determine whether the activity requires additional investigation, incident-response escalation, account containment, or closure.

Record unresolved questions and identify any additional evidence needed to support the final assessment.

## Evidence to Collect

| Evidence       | Description                                                                       |
| -------------- | --------------------------------------------------------------------------------- |
| Alert          | Detection source, alert identifier, severity, and timestamp                       |
| Identity       | Account identifier, account type, tenant, and identity provider                   |
| Authentication | Sign-in events, authentication outcomes, MFA results, and access-policy decisions |
| Session        | Session identifiers, device information, and relevant session metadata            |
| Network        | Source IP addresses, network context, and available geographic information        |
| Privileges     | Role assignments, group membership, permissions, and relevant changes             |
| Credentials    | Credential metadata, token events, and authentication-method changes              |
| Audit Logs     | Cloud API operations and administrative events                                    |
| Resources      | Affected cloud services, resources, and relevant data-access events               |
| Timeline       | First observed activity, subsequent events, and most recent suspicious activity   |
| Scope          | Other affected accounts, identities, sessions, and resources                      |
| Response       | Containment actions, approvals, credential resets, and recovery activities        |

Evidence should be collected from the relevant identity provider and cloud audit sources, subject to their availability and retention policies.

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- authentication can be attributed to an authorized user or service;
- the device and session context are consistent with expected activity;
- privilege assignments and credential changes are authorized;
- resource operations match documented business or administrative activity;
- no corroborating evidence of unauthorized access is identified.

Document the justification and any relevant exceptions before closing the investigation.

### Suspicious

Classify the activity as **suspicious** when:

- authentication deviates from the account's normal behavior;
- unexpected devices, sessions, or client applications are observed;
- privilege or credential changes cannot yet be verified;
- resource access falls outside expected account responsibilities;
- related events suggest possible unauthorized access;
- important telemetry is missing and compromise cannot be ruled out.

Continue the investigation, preserve evidence, and escalate when the potential impact or risk warrants it.

### Malicious

Classify the activity as **malicious** when sufficient evidence establishes unauthorized account use or compromise.

Examples include:

- confirmed unauthorized access using the affected identity;
- confirmed use of compromised credentials or sessions;
- unauthorized privilege assignments;
- unauthorized authentication-method or credential modifications;
- confirmed unauthorized cloud resource operations;
- use of the affected identity to access resources outside approved authorization;
- correlated evidence of malicious actions following unauthorized authentication.

Escalate to the appropriate incident-response workflow and initiate approved containment procedures.

### Inconclusive

Use **inconclusive** when the available evidence is insufficient to determine whether the activity is legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- unresolved findings;
- remaining uncertainties;
- additional telemetry or validation required.

Do not classify an account as compromised solely because evidence is incomplete.

## Escalation

Escalate the investigation when:

- unauthorized cloud account access is confirmed;
- a privileged identity may be compromised;
- unauthorized privilege escalation is identified;
- suspicious sessions or credentials may remain active;
- unauthorized access to sensitive data is confirmed or reasonably suspected;
- logging or security controls may have been modified;
- multiple identities or cloud resources are affected;
- the activity extends to connected or federated environments;
- the potential business or operational impact exceeds the triage team's authority.

Notify the appropriate cloud security, identity, and incident-response teams according to organizational procedures.

## Response Guidance

For confirmed or high-confidence cloud account compromise:

1. Preserve relevant authentication, audit, session, credential, and resource evidence.
2. Identify the affected identities, privileges, sessions, and resources.
3. Coordinate containment with the responsible cloud and identity administrators.
4. Disable or restrict the affected account when justified and authorized.
5. Revoke affected sessions, refresh tokens, credentials, or access keys through approved provider-specific procedures.
6. Reset compromised credentials and review authentication methods.
7. Remove unauthorized permissions, role assignments, and credentials after preserving the relevant evidence.
8. Review recent cloud administrative activity and investigate potentially affected resources.
9. Assess whether connected identities, application identities, or additional accounts are affected.
10. Restore required access using verified credentials and approved permissions.
11. Validate that unauthorized access has stopped and that relevant security controls are functioning.
12. Document containment, recovery, and validation results.

Response actions must account for service dependencies, privileged access requirements, and potential operational impact. Coordinate disruptive changes with authorized owners unless emergency procedures explicitly permit immediate action.

Do not assume that changing a password alone invalidates every existing session, token, access key, or application credential. Validate revocation and containment using the applicable provider's capabilities and audit evidence.

## Related Detection Rules

## Related Playbooks

- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/cloud/application-access-token-abuse.md`
- `playbooks/cloud/cloud-credential-access.md`
- `playbooks/cloud/cloud-secrets-access.md`

## Validation

The playbook should be validated against approved cloud identity telemetry, authentication events, audit logs, role-assignment records, session information, and controlled investigation scenarios.

Validation should confirm that:

- the affected cloud identity and account can be identified;
- authentication and session activity can be correlated;
- privilege and credential changes can be investigated;
- cloud resource activity can be associated with the initiating identity;
- the scope of suspicious activity can be established;
- legitimate administrative behavior can be distinguished from unauthorized activity;
- escalation and containment decisions follow approved procedures;
- investigation evidence and conclusions can be documented consistently.

The playbook must be reviewed when cloud identity architecture, authentication controls, audit-log capabilities, or response procedures materially change.

## Safety

This playbook is intended for defensive security operations, authorized incident response, security validation, and controlled testing.

Account containment, session revocation, credential rotation, and permission changes must follow approved authorization and incident-response procedures.

Preserve relevant evidence before modifying affected accounts or resources when operational circumstances permit. Avoid exposing credentials, tokens, or other secrets in logs, reports, or incident documentation.

Do not conduct unauthorized account-access tests or disruptive containment actions against production environments.
