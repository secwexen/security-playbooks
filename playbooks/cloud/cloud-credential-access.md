---
id: "cloud-credential-access"
name: "Cloud Credential Access"
category: "cloud"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-20T14:15:00Z"
updated_at: "2026-10-20T14:15:00Z"
description: "Investigate suspicious access to cloud credentials, application tokens, service credentials, and secrets stored or exposed within cloud environments."
objective: "Determine whether cloud credential access or exposure is authorized, identify affected identities and resources, establish the scope of potential compromise, and support appropriate containment and remediation."
severity: "high"
mitre_attack:
  - "T1555.006"
  - "T1528"
  - "T1552.005"
  - "T1552.001"
triggers:
  - "An alert identifies suspicious access to a cloud secrets management service."
  - "An application access token or refresh token is suspected of being stolen or exposed."
  - "Unexpected access to cloud instance metadata endpoints is observed."
  - "Cloud access keys, service credentials, or API tokens are discovered in an exposed file or configuration."
  - "Unusual access to credentials associated with a cloud workload or service principal is detected."
  - "A cloud identity performs unexpected authentication or API activity following suspected credential exposure."
prerequisites:
  - "Access to cloud identity and authentication logs."
  - "Access to cloud control-plane audit logs."
  - "Access to relevant secrets management and credential access audit records."
  - "Access to workload, endpoint, or network telemetry where available."
  - "An approved process for credential revocation, rotation, and incident escalation."
tags:
  - "cloud"
  - "credential-access"
  - "identity"
  - "secrets-management"
  - "access-token"
  - "incident-response"
references:
  - "https://attack.mitre.org/techniques/T1555/006/"
  - "https://attack.mitre.org/techniques/T1528/"
  - "https://attack.mitre.org/techniques/T1552/005/"
  - "https://attack.mitre.org/techniques/T1552/001/"
steps:
  - id: "identify-cloud-credential-alert"
    order: 1
    name: "Identify Cloud Credential Alert"
    action: "investigate"
    description: "Identify the alert source, affected cloud environment, suspected credential, associated identity, timestamp, and initial detection context."
    expected_result: "The alert, affected environment, suspected credential type, and initial investigation scope are documented."
  - id: "identify-credential-type"
    order: 2
    name: "Identify the Credential Type"
    action: "analyze"
    description: "Determine whether the suspected credential is a cloud access key, API token, application access token, refresh token, service principal credential, workload identity token, or secret stored in a secrets management service."
    expected_result: "The credential category, intended purpose, associated service, and relevant lifecycle characteristics are identified without unnecessarily exposing the secret value."
  - id: "review-identity-access-context"
    order: 3
    name: "Review Identity and Access Context"
    action: "analyze"
    description: "Review the associated user, service principal, workload identity, cloud account, assigned roles, effective permissions, authentication method, source IP, device context, and expected access patterns."
    expected_result: "The identity, privilege level, access context, and expected credential usage are documented."
  - id: "review-credential-acquisition-activity"
    order: 4
    name: "Review Credential Acquisition Activity"
    action: "analyze"
    description: "Investigate access to secrets stores, credential files, token storage locations, cloud instance metadata endpoints, and relevant application or workload resources. Correlate observed activity with the suspected credential exposure."
    expected_result: "Potential credential retrieval, exposure, or unauthorized access activity is identified and assessed against available evidence."
  - id: "review-cloud-api-activity"
    order: 5
    name: "Review Cloud API Activity"
    action: "analyze"
    description: "Review cloud authentication events and API requests associated with the affected identity or credential. Identify unusual services, resource access, permission changes, token usage, geographic patterns, and unexpected operations."
    expected_result: "Potential unauthorized use of the credential and related cloud operations are identified or reasonably ruled out."
  - id: "correlate-related-events"
    order: 6
    name: "Correlate Related Events"
    action: "hunt"
    description: "Correlate identity, secrets management, workload, endpoint, network, and cloud audit events. Investigate related application consent, credential modification, role assignment, and data access activity where supported by evidence."
    expected_result: "Related activity is correlated into a timeline, and potential follow-on compromise is identified."
  - id: "determine-credential-exposure-scope"
    order: 7
    name: "Determine Credential Exposure Scope"
    action: "hunt"
    description: "Determine the affected cloud accounts, identities, subscriptions, projects, tenants, workloads, secrets, and resources. Establish the earliest known exposure, latest observed use, potential privilege boundaries crossed, and other potentially affected credentials."
    expected_result: "The known and potential scope of credential exposure and unauthorized access is documented."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the observed activity based on the available evidence, document the investigation findings, and determine whether containment, credential rotation, or incident response escalation is required."
    expected_result: "The activity receives a documented classification, with supporting evidence, residual uncertainty, and recommended next actions."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "cloud-credential-access"
---

# Cloud Credential Access

## Purpose

This playbook provides a structured workflow for investigating suspected cloud credential access, credential exposure, and unauthorized use of cloud authentication material.

Cloud credentials may include access keys, API tokens, application access tokens, refresh tokens, service principal credentials, workload identity tokens, and secrets stored in cloud secrets management services.

Credential exposure does not automatically establish account compromise. The investigation must establish what was accessed, how the credential could be used, whether unauthorized use occurred, and which identities or resources may be affected.

## MITRE ATT&CK

| Technique | Name                                                              | Relevance                                                                                                            |
| --------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | Relevant when credentials or secrets are obtained from cloud secrets management services.                            |
| T1528     | Steal Application Access Token                                    | Relevant when application access tokens are obtained or used without authorization.                                  |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API                | Relevant when cloud instance metadata endpoints are accessed to obtain credentials or other sensitive information.   |
| T1552.001 | Unsecured Credentials: Credentials In Files                       | Relevant when cloud credentials are exposed in files, configuration artifacts, or other insecurely stored locations. |

Apply each technique only when the observed behavior supports the mapping. Credential exposure, token theft, and subsequent abuse of a valid cloud account are related but distinct activities.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An alert identifies unusual access to a cloud secrets management service.
- An application access token, refresh token, cloud access key, or service credential may have been exposed.
- A cloud instance or container accesses a metadata endpoint in an unexpected context.
- A credential is discovered in an exposed configuration file, source repository, build artifact, or workload environment.
- An identity accesses a secret outside its expected operational pattern.
- An application or workload requests or uses a token unexpectedly.
- Suspicious cloud API activity follows a suspected credential exposure.
- Cloud identity telemetry indicates unexpected authentication or resource access associated with a potentially compromised credential.

A single unusual event should be investigated in context. It does not independently confirm credential theft or malicious activity.

## Scope

The investigation should consider:

- affected cloud provider, tenant, account, subscription, or project;
- affected user, service principal, application, or workload identity;
- credential type and intended purpose;
- secret, token, or key identifier where available;
- secrets management service and associated resource;
- cloud instance or container associated with the activity;
- source IP address and relevant network context;
- authentication method and authentication result;
- multifactor authentication and conditional access results where applicable;
- assigned roles, permissions, and effective privileges;
- access key, token, and secret creation or modification events;
- cloud API requests and affected resources;
- application consent and service principal changes where relevant;
- associated workload, endpoint, or CI/CD activity;
- potential data access or exfiltration;
- other identities and credentials potentially affected.

Do not copy raw credential values into tickets, investigation reports, or general-purpose logs. Use identifiers and redacted evidence wherever possible.

## Investigation Procedure

### Step 1 — Identify Cloud Credential Alert

Identify the source and context of the alert.

Collect:

- alert identifier;
- detection source;
- detection timestamp;
- affected cloud provider and account;
- suspected identity;
- suspected credential category;
- associated resource or service;
- source IP address where available;
- detection severity and reason.

Preserve the original alert and relevant event records before taking remediation actions.

Determine whether the alert concerns suspected credential retrieval, credential exposure, token theft, or subsequent credential use.

### Step 2 — Identify the Credential Type

Determine which authentication material may have been exposed or accessed.

Consider:

- cloud access keys;
- API tokens;
- application access tokens;
- refresh tokens;
- service principal credentials;
- workload identity tokens;
- secrets stored in a cloud secrets management service;
- credentials stored in configuration files or deployment artifacts;
- temporary credentials obtained through cloud instance metadata services.

Establish the credential's intended owner, associated identity, permissions, and expected usage.

Where possible, collect a credential identifier or metadata record rather than the credential value itself.

Do not attempt to validate a suspected stolen credential by using it against production services without explicit authorization.

### Step 3 — Review Identity and Access Context

Review the identity associated with the credential.

Determine:

- whether the identity is a user, application, service principal, or workload;
- whether the identity is expected in the affected environment;
- assigned and effective roles;
- privileged access and role-assumption capabilities;
- expected source networks and access locations;
- normal authentication times and frequency;
- expected services and API operations;
- authentication and conditional access results;
- recent changes to credentials, roles, or identity configuration.

Compare the observed activity with established operational baselines.

A valid identity or successful authentication does not establish that the activity was authorized.

### Step 4 — Review Credential Acquisition Activity

Investigate how the credential may have been accessed or exposed.

Review available evidence relating to:

- secrets management read operations;
- credential file access;
- token retrieval or storage;
- cloud instance metadata requests;
- workload or container activity;
- CI/CD jobs and deployment artifacts;
- application or service principal credential changes;
- unexpected access to configuration or environment data;
- relevant endpoint and network activity.

Correlate credential access events with process execution, authentication, application activity, and cloud audit records where available.

Assess whether the access was performed by an authorized administrator, application, or workload.

Treat a missing log record as an evidence limitation rather than proof that the activity did not occur.

### Step 5 — Review Cloud API Activity

Review authentication and cloud API activity associated with the suspected credential or identity.

Examine:

- authentication attempts and results;
- source IP addresses and access patterns;
- access to previously unused cloud services;
- unexpected resource enumeration;
- access to sensitive storage, databases, or secrets;
- privilege or role changes;
- creation or modification of application credentials;
- unusual token usage;
- unexpected resource configuration changes;
- activity outside the identity's established operational pattern.

Determine whether observed operations are consistent with the identity's documented responsibilities.

Identify any unauthorized access that may have occurred after the suspected exposure.

### Step 6 — Correlate Related Events

Correlate the investigation timeline across relevant sources.

Consider:

- cloud identity and authentication logs;
- cloud control-plane audit logs;
- secrets management audit records;
- workload and container telemetry;
- endpoint process and file activity;
- network and DNS telemetry;
- CI/CD and deployment logs;
- application consent and permission changes;
- data access and exfiltration alerts;
- related detections involving the same identity, source, or resource.

Determine whether credential access was isolated or part of a broader attack chain.

If multiple identities or credentials may be involved, document their relationships and investigate each affected scope separately.

### Step 7 — Determine Credential Exposure Scope

Establish the known and potential scope of the incident.

Determine:

- which credentials or tokens may have been exposed;
- which identities are associated with those credentials;
- which cloud accounts, projects, subscriptions, or tenants are affected;
- which resources were accessed;
- whether elevated permissions were obtained or abused;
- whether the credential was used from unexpected sources;
- the earliest and latest known suspicious activity;
- whether additional credentials may have been exposed;
- whether data was accessed, modified, or exfiltrated;
- whether suspicious access is ongoing.

Distinguish confirmed activity from plausible but unverified exposure.

Document relevant evidence gaps and any additional telemetry required to establish the full impact.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Record the classification and supporting evidence.

Identify whether credential revocation, token invalidation, secret rotation, identity containment, or incident response escalation is required.

Do not close the investigation solely because no unauthorized API request was observed if credential exposure remains unresolved.

## Evidence to Collect

| Evidence            | Description                                                                           |
| ------------------- | ------------------------------------------------------------------------------------- |
| Alert               | Detection source, alert identifier, severity, and timestamp                           |
| Cloud Environment   | Provider, tenant, account, subscription, or project                                   |
| Identity            | User, service principal, application, or workload identity                            |
| Credential Metadata | Credential type, identifier, owner, and associated service; exclude raw secret values |
| Authentication      | Authentication events, results, source IPs, and relevant policy outcomes              |
| Secrets Access      | Secret identifiers, access records, and relevant audit events                         |
| Workload            | Relevant instance, container, application, or CI/CD execution context                 |
| Cloud API Activity  | API operations, affected resources, and timestamps                                    |
| Permissions         | Relevant roles, effective privileges, and permission changes                          |
| Network             | Source and destination addresses and related connection metadata                      |
| Timeline            | Credential access, authentication, API usage, and related event timestamps            |
| Impact              | Affected identities, resources, and confirmed or suspected data access                |
| Scope               | Related credentials, identities, accounts, and workloads                              |
| Response            | Credential revocation, rotation, containment, and recovery actions                    |

Preserve evidence according to organizational retention and incident-handling requirements. Redact credential material and other sensitive values before sharing investigation results.

## Decision Criteria

### Benign

Classify the activity as **benign** when the available evidence establishes that:

- credential access was performed by an authorized identity or workload;
- the access is consistent with documented operational activity;
- the source and authentication context are expected;
- the associated permissions and API operations are appropriate;
- no unexplained credential exposure is identified;
- no suspicious follow-on activity is observed.

Document the operational justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- credential access is unusual or lacks a clear operational justification;
- a secret or token may have been exposed;
- authentication originates from an unexpected source;
- an identity accesses unfamiliar services or resources;
- token or secret usage deviates from the established baseline;
- relevant audit records are missing or incomplete;
- related application, workload, or permission changes require further investigation.

Continue investigation, collect additional evidence, and assess whether preventive containment is warranted.

### Malicious

Classify the activity as **malicious** when sufficient evidence establishes unauthorized credential acquisition, exposure, or use, such as:

- confirmed theft or unauthorized retrieval of credentials or application tokens;
- unauthorized access to cloud secrets or credential stores;
- confirmed misuse of credentials obtained through an instance metadata endpoint;
- unauthorized cloud API activity attributable to the exposed credential;
- unauthorized privilege changes or access to protected resources;
- confirmed data access or exfiltration associated with the credential;
- credential misuse associated with broader account or workload compromise.

Escalate to the appropriate incident response process and initiate authorized containment and remediation.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the credential access or exposure was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- unresolved questions;
- affected identities and resources that cannot yet be ruled out;
- additional telemetry or access required;
- recommended investigative actions.

Do not treat an inconclusive result as confirmation that the credential is safe.

## Escalation

Escalate the investigation when:

- unauthorized credential access or use is confirmed;
- privileged cloud credentials may be exposed;
- application access tokens or refresh tokens are suspected of being stolen;
- a workload identity or service principal may be compromised;
- unauthorized access to sensitive cloud resources is identified;
- unexpected role assignments or permission changes occur;
- multiple identities, cloud accounts, or environments may be affected;
- data access or exfiltration is suspected or confirmed;
- suspicious activity remains active;
- the incident may affect production services or critical business operations.

Engage the relevant cloud security, identity, incident response, and service-owner teams according to organizational procedures.

## Response Guidance

For confirmed malicious cloud credential access:

1. Preserve relevant identity, authentication, secrets management, workload, network, and cloud audit evidence.
2. Identify the affected credentials, identities, resources, and privilege boundaries.
3. Determine whether unauthorized access is ongoing.
4. Revoke or invalidate affected credentials and tokens using approved provider procedures.
5. Rotate exposed secrets and replace compromised credentials where necessary.
6. Revoke relevant sessions or refresh tokens where supported and appropriate.
7. Restrict or disable compromised identities when authorized and necessary to prevent further access.
8. Review and remediate unauthorized role assignments, application permissions, and credential additions.
9. Investigate related resource access, configuration changes, persistence, and potential data exfiltration.
10. Search for the same credential identifier, identity, source pattern, or related indicators across the environment.
11. Restore affected workloads and credentials through approved recovery procedures.
12. Validate that unauthorized access has stopped and that legitimate services continue to function.
13. Document containment, rotation, recovery, and verification results.

Credential rotation and identity containment can affect production workloads. Coordinate disruptive actions with the relevant service owners and incident response team unless immediate action is required by the organization's emergency procedures.

Do not delete evidence or modify relevant resources before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

## Related Playbooks

- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/initial-access/valid-account-compromise.md`

## Validation

The playbook should be validated against approved cloud identity telemetry, authentication records, secrets management audit logs, cloud API activity, workload telemetry, and controlled test scenarios.

Validation should confirm that:

- credential types and associated identities can be identified;
- access to secrets and credential stores can be investigated;
- relevant instance metadata access can be reviewed;
- authentication and cloud API events can be correlated;
- authorized administrative access can be distinguished from suspicious behavior;
- potentially affected identities and resources can be scoped;
- credential revocation and rotation procedures can be executed through approved workflows;
- evidence is preserved without unnecessarily exposing secret values;
- escalation and response decisions are documented consistently.

Update the validation status only after the required scenarios have been executed and the results documented.

## Safety

This playbook is intended for defensive security operations, incident response, authorized security validation, and controlled testing.

Investigations must use approved access and evidence-handling procedures. Do not intentionally expose credentials, use suspected stolen tokens against production resources, or modify cloud identities and permissions without appropriate authorization.

Never include raw passwords, access keys, private keys, API tokens, refresh tokens, or secret values in public issues, source control, or general-purpose investigation reports.

Credential rotation, token revocation, account restriction, and workload containment must follow authorized incident response procedures and applicable change-management requirements.
