---
id: "cloud-incident-response"
name: "Cloud Incident Response"
category: "response"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-11-07T11:30:00Z"
updated_at: "2026-11-07T11:30:00Z"
description: "Cloud security incidents involve unauthorized access, malicious activity, compromised identities, exposed resources, or abuse of cloud infrastructure, services, and configurations."
objective: "Identify, investigate, contain, and remediate cloud security incidents while determining the scope of affected identities, workloads, resources, applications, and cloud services."
severity: "high"
mitre_attack:
  - "T1078.004"
  - "T1098.001"
  - "T1098.003"
  - "T1530"
triggers:
  - "Suspicious authentication activity involving cloud identities"
  - "Confirmed or suspected compromise of cloud credentials"
  - "Unauthorized cloud resource creation or modification"
  - "Unexpected privilege escalation or IAM policy changes"
  - "Suspicious access to cloud storage or sensitive data"
  - "Unusual API activity or administrative operations"
  - "Unexpected exposure of cloud resources or services"
  - "Cloud workload or container security alerts"
  - "Cloud provider threat detection identifying malicious activity"
  - "Threat hunting identifies anomalous cloud activity"
prerequisites:
  - "Access to cloud audit and activity logs"
  - "Access to cloud identity and access management services"
  - "Access to cloud security monitoring and detection systems"
  - "Access to network, workload, and application telemetry"
  - "Access to cloud resource inventory and configuration data"
  - "Authorized access to cloud account and resource management capabilities"
  - "Documented cloud incident-response and escalation procedures"
tags:
  - "cloud-security"
  - "cloud-incident"
  - "incident-response"
  - "cloud-compromise"
  - "iam"
  - "credential-access"
  - "privilege-escalation"
  - "data-exfiltration"
  - "aws"
  - "azure"
  - "gcp"
  - "mitre-attack"
references:
  - "https://attack.mitre.org/techniques/T1078/004/"
  - "https://attack.mitre.org/techniques/T1098/001/"
  - "https://attack.mitre.org/techniques/T1098/003/"
  - "https://attack.mitre.org/techniques/T1530/"
steps:
  - id: "identify-cloud-alert"
    order: 1
    name: "Identify Cloud Security Alert"
    action: "investigate"
    description: "Identify the detection source, affected cloud provider, account, subscription, project, resource, identity, timestamp, and initial alert context."
    expected_result: "The suspected cloud security incident and affected cloud environment are identified."
  - id: "validate-cloud-activity"
    order: 2
    name: "Validate Cloud Activity"
    action: "analyze"
    description: "Determine whether observed cloud activity is consistent with expected administrative operations, identity behavior, resource usage, deployment activity, and organizational change records."
    expected_result: "The legitimacy of the observed cloud activity is assessed."
  - id: "review-cloud-audit-events"
    order: 3
    name: "Review Cloud Audit Events"
    action: "analyze"
    description: "Review cloud control-plane and data-plane events, authentication activity, API calls, IAM modifications, resource changes, and administrative operations."
    expected_result: "A cloud activity timeline is established, including suspicious identities, operations, and affected resources."
  - id: "review-cloud-resource-activity"
    order: 4
    name: "Review Cloud Resource Activity"
    action: "analyze"
    description: "Correlate suspicious cloud activity with compute workloads, storage services, databases, containers, network configurations, serverless functions, and application activity."
    expected_result: "Potential unauthorized actions and affected cloud resources are identified."
  - id: "determine-cloud-scope"
    order: 5
    name: "Determine Cloud Incident Scope"
    action: "hunt"
    description: "Search for related identities, sessions, API activity, resources, workloads, network connections, data access, and cloud accounts associated with the suspected incident."
    expected_result: "The scope, impact, and potential cross-resource or cross-account impact are determined."
  - id: "contain-cloud-incident"
    order: 6
    name: "Contain Cloud Incident"
    action: "contain"
    description: "Apply approved containment controls such as credential rotation, session revocation, access restriction, IAM policy correction, workload isolation, or temporary resource restriction based on incident severity and organizational procedures."
    expected_result: "Unauthorized cloud access and malicious activity are contained while critical evidence and required operational availability are preserved."
  - id: "eradicate-and-recover-cloud"
    order: 7
    name: "Eradicate and Recover"
    action: "respond"
    description: "Remove unauthorized access mechanisms, remediate compromised resources and configurations, restore trusted cloud identities and workloads, and verify security controls."
    expected_result: "Affected cloud resources and identities are restored to a trusted and secure state."
  - id: "determine-cloud-outcome"
    order: 8
    name: "Determine Response Outcome"
    action: "document"
    description: "Classify the incident, document collected evidence, affected resources, containment and recovery actions, business impact, and remaining risks."
    expected_result: "The cloud security incident receives a documented response outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "cloud-incident-response"
---

# Cloud Incident Response

## Purpose

This playbook provides a structured response workflow for investigating, containing, and remediating suspected or confirmed security incidents involving cloud infrastructure, identities, applications, workloads, storage services, and management platforms.

Cloud security incidents may involve compromised credentials, unauthorized access, privilege escalation, malicious resource modifications, data exposure, exfiltration, or workload compromise. This playbook supports incident investigations across AWS, Microsoft Azure, Google Cloud Platform (GCP), and other cloud environments.

## MITRE ATT&CK

| Technique | Name                           | Relevance                                                                                                                                  |
| --------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| T1078.004 | Valid Accounts: Cloud Accounts | Relevant when compromised or unauthorized cloud credentials are used to access cloud resources.                                            |
| T1098.001 | Additional Cloud Credentials   | Relevant when adversaries add unauthorized credentials, access keys, or authentication material to cloud accounts to maintain persistence. |
| T1098.003 | Additional Cloud Roles         | Relevant when adversaries add unauthorized cloud roles or permissions to maintain access or escalate privileges.                           |
| T1530     | Data from Cloud Storage        | Relevant when adversaries access or collect sensitive information from cloud storage services.                                             |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Suspicious authentication activity involving cloud identities.
- A cloud credential, access key, service principal, or workload identity is confirmed or suspected to have been compromised.
- Unexpected administrative or privileged activity occurs within a cloud environment.
- Unauthorized IAM policies, roles, permissions, or trust relationships are created or modified.
- Sensitive cloud storage resources become publicly accessible or accessible to unauthorized identities.
- Unusual API activity or resource-management operations are detected.
- Unexpected compute instances, containers, serverless functions, or other cloud resources are created.
- Cloud security monitoring identifies suspicious network or workload activity.
- Unexpected data access, transfer, deletion, or modification is detected.
- Threat hunting identifies anomalous cloud resource or identity behavior.

## Scope

The investigation should consider:

- affected cloud provider;
- cloud account;
- subscription or project;
- affected identity;
- IAM roles and permissions;
- authentication method;
- source IP address;
- management-plane operations;
- compute instances;
- storage services;
- network configurations;
- secrets and credentials;
- data access and transfer;
- logging and monitoring configurations;
- related alerts.

## Investigation Procedure

### Step 1 — Identify Cloud Security Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- cloud provider;
- organization identifier;
- affected account;
- subscription or project;
- affected region;
- affected resource;
- affected identity;
- identity type;
- source IP address;
- operation or API call;
- detection reason.

Identify whether the alert originated from cloud-native security monitoring, SIEM, EDR, CSPM, CIEM, workload protection, or another detection source.

Preserve the original alert context and relevant cloud audit events before performing containment actions.

### Step 2 — Validate Cloud Activity

Determine whether the observed cloud activity is consistent with expected organizational operations.

Review:

- expected administrative activities;
- known cloud administrators;
- approved deployment pipelines;
- infrastructure-as-code operations;
- expected source locations;
- known devices;
- normal API usage patterns;
- service account responsibilities;
- workload identities;
- scheduled automation;
- approved maintenance windows;
- recent configuration changes;
- change-management records.

Determine whether the observed activity can be attributed to an authorized administrator, application, automation process, or workload.

A single unusual cloud API operation should not automatically be classified as a confirmed compromise.

Correlate identity, resource, network, and workload telemetry before assigning the final incident classification.

### Step 3 — Review Cloud Audit Events

Review cloud-native audit and activity logs.

Investigate:

- successful and failed authentication events;
- interactive and non-interactive sign-ins;
- API authentication and access-key usage;
- token issuance and session creation or termination;
- IAM role assumptions;
- privilege changes;
- policy modifications;
- credential creation and rotation;
- resource creation, modification, and deletion;
- storage access;
- network configuration changes;
- security control modifications;
- logging configuration changes.

Correlate events using:

- identity identifiers;
- access-key identifiers;
- session identifiers;
- request identifiers;
- source IP addresses;
- user agents;
- resource identifiers;
- timestamps;
- API operation names.

Construct a timeline covering the period immediately before and after the suspected incident.

Cloud audit logging should be evaluated for completeness, retention, integrity, and possible tampering.

### Step 4 — Review Cloud Resource Activity

Correlate suspicious identities and API operations with affected cloud resources.

Review:

- compute instance creation and modification;
- container deployment activity;
- Kubernetes API activity;
- serverless function creation and execution;
- object storage access;
- database access;
- snapshot creation;
- backup operations;
- security group modifications;
- firewall changes;
- routing configuration changes;
- DNS modifications;
- load balancer changes;
- secret and key management activity;
- application deployment activity;
- cloud-native administrative operations.

Determine whether unauthorized changes were introduced into the environment.

Investigate whether cloud resources were used for:

- unauthorized computation;
- persistence;
- credential collection;
- data staging;
- data exfiltration;
- lateral movement;
- destructive operations;
- unauthorized external communication.

### Step 5 — Determine Cloud Incident Scope

Search the environment for:

- affected cloud identities;
- related service accounts;
- access keys and tokens;
- suspicious source IP addresses;
- unusual API calls;
- unexpected IAM modifications;
- newly created resources;
- modified security configurations;
- exposed storage resources;
- unusual data access;
- unexpected network connections;
- additional affected accounts;
- cross-account access;
- related cloud regions;
- compromised workloads.

Determine:

- number of affected cloud accounts;
- number of affected subscriptions or projects;
- number of affected identities;
- number of affected resources;
- number of affected workloads;
- number of affected applications;
- amount and sensitivity of potentially exposed data;
- earliest suspicious activity;
- latest suspicious activity;
- whether unauthorized access is ongoing;
- whether other cloud environments are affected.

Determine whether the incident is limited to a single resource, cloud account, subscription, project, or broader cloud organization.

### Step 6 — Contain Cloud Incident

Based on incident severity and organizational procedures, consider:

- disabling or restricting compromised cloud identities;
- rotating compromised access keys and credentials;
- revoking active sessions and authentication tokens where supported;
- removing unauthorized IAM permissions;
- restricting suspicious role assumptions;
- removing unauthorized trust relationships;
- isolating compromised workloads;
- restricting suspicious network access;
- disabling exposed access paths;
- restricting public access to affected storage resources;
- protecting secrets and encryption keys;
- suspending malicious automation;
- preventing unauthorized resource creation;
- preserving relevant audit and workload evidence.

Containment actions should be prioritized according to the affected identity, resource criticality, data sensitivity, and operational impact.

Avoid indiscriminate resource deletion or account suspension before understanding dependencies and preserving required evidence.

Coordinate containment with cloud platform owners, identity-management teams, application owners, and incident-response personnel.

### Step 7 — Eradicate and Recover

Determine and address the underlying source of compromise.

Investigate:

- exposed cloud credentials;
- compromised access keys;
- phishing-related identity compromise;
- unauthorized service principals;
- compromised workload identities;
- excessive IAM permissions;
- malicious trust relationships;
- unauthorized authentication methods;
- compromised CI/CD pipelines;
- exposed secrets;
- compromised containers;
- vulnerable workloads;
- malicious cloud functions;
- unauthorized persistence mechanisms;
- compromised management systems;
- logging and monitoring tampering.

Remove unauthorized access mechanisms and remediate affected configurations.

### Step 8 — Determine Response Outcome

Classify the incident as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification and record all containment, eradication, recovery, and follow-up actions.

## Evidence to Collect

| Evidence       | Description                                                       |
| -------------- | ----------------------------------------------------------------- |
| Alert          | Detection source, alert ID, severity, and timestamp               |
| Cloud Provider | Provider, organization, account, subscription, or project         |
| Identity       | Username, service account, role, identity type, and permissions   |
| Authentication | Successful and failed authentication events                       |
| API Activity   | API calls, operation names, request IDs, and timestamps           |
| Source         | Source IP, device, user agent, and network context                |
| Resources      | Affected compute, storage, database, and application resources    |
| IAM            | Roles, policies, permissions, and trust relationships             |
| Sessions       | Active and historical sessions, tokens, and access keys           |
| Network        | Security groups, firewall rules, routing, and network connections |
| Storage        | Object access, bucket permissions, and data access events         |
| Workloads      | Compute, containers, Kubernetes, and serverless telemetry         |
| Secrets        | Secret access, key management, and credential modifications       |
| Configuration  | Resource configuration and security control changes               |
| Data Activity  | Data access, transfer, modification, and deletion                 |
| Audit Logs     | Cloud management-plane and data-plane events                      |
| Monitoring     | SIEM, CSPM, CIEM, EDR, and cloud-native detections                |
| Timeline       | Authentication, API, resource, and network activity               |
| Scope          | Other affected accounts, regions, identities, and resources       |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- cloud activity is verified as authorized;
- the identity and source context are expected;
- API operations correspond to documented administrative activities;
- resource modifications are associated with approved deployments or changes;
- no evidence of unauthorized access is identified;
- no suspicious post-authentication or resource activity is observed.

Document the operational justification before closing the incident.

### Suspicious

Classify the activity as **suspicious** when:

- cloud authentication or API activity is anomalous;
- the identity cannot immediately be attributed to an authorized user or service;
- unusual IAM or resource modifications are observed;
- cloud storage access deviates from expected behavior;
- unexpected resource creation or configuration changes occur;
- cloud activity requires additional investigation;
- compromise cannot yet be confirmed.

Continue investigation and maintain appropriate containment controls.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- unauthorized access to cloud accounts or resources;
- confirmed compromise of cloud credentials;
- unauthorized use of cloud identities;
- unauthorized privilege escalation;
- malicious IAM or trust relationship modifications;
- confirmed unauthorized access to sensitive cloud data;
- unauthorized data exfiltration or destruction;
- malicious workload deployment or execution;
- unauthorized security control or logging modifications;
- broader compromise involving multiple cloud resources or accounts.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to establish whether the cloud activity was authorized or unauthorized.

Document:

- evidence collected;
- evidence unavailable;
- cloud logging limitations;
- affected resources;
- additional data required;
- containment status;
- remaining investigation requirements.

## Escalation

Escalate the incident when:

- cloud account compromise is confirmed;
- privileged cloud identities are affected;
- multiple accounts, subscriptions, or projects are involved;
- unauthorized IAM changes occurred;
- sensitive data may have been accessed or exposed;
- cloud storage resources were publicly exposed;
- unauthorized workloads or resources were deployed;
- persistence mechanisms are identified;
- lateral movement or cross-account access is identified;
- security logging or monitoring was disabled or modified;
- encryption keys or secrets are compromised;
- destructive cloud activity is detected;
- business-critical cloud services are affected;
- the source of compromise remains active.

## Response Guidance

For confirmed cloud security incidents:

1. Preserve cloud audit, identity, network, workload, and application telemetry.
2. Identify affected cloud providers, accounts, subscriptions, projects, identities, and resources.
3. Establish the incident timeline and determine the earliest known suspicious activity.
4. Follow the organization's cloud incident-containment procedure.
5. Rotate compromised credentials and revoke applicable sessions and tokens.
6. Review IAM roles, permissions, policies, and trust relationships.
7. Investigate unauthorized resource creation, modification, and deletion.
8. Identify potentially exposed or accessed sensitive data.
9. Review network configurations and suspicious external communication.
10. Investigate workload compromise, persistence, and unauthorized execution.
11. Verify cloud logging, monitoring, and security controls remain operational.
12. Restore affected resources and services only after required containment and validation actions are complete.
13. Monitor restored cloud environments for recurring suspicious activity.

Do not delete compromised resources, disable critical logging, or remove relevant cloud artifacts before required forensic evidence has been preserved.

## Related Detection Rules

## Related Playbooks

- `playbooks/cloud/cloud-account-compromise.md`
- `playbooks/cloud/cloud-credential-access.md`
- `playbooks/cloud/cloud-secrets-access.md`
- `playbooks/cloud/application-access-token-abuse.md`
- `playbooks/cloud/cloud-storage-object-discovery.md`
- `playbooks/exfiltration/cloud-exfiltration.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/data-exfiltration-response.md`

## Validation

The playbook should be validated against controlled cloud audit datasets, identity-provider events, IAM activity, API telemetry, storage access logs, workload telemetry, and authorized cloud incident-response laboratory scenarios.

Validation should confirm that:

- suspicious cloud authentication activity can be identified;
- unauthorized API activity can be detected;
- legitimate administrative operations can be distinguished from anomalous behavior;
- cloud audit timelines can be reconstructed;
- IAM changes and privilege escalation can be investigated;
- unauthorized resource creation and modification can be identified;
- suspicious cloud storage access can be detected;
- compromised identities and resources can be scoped across cloud environments;
- containment actions are documented and reproducible;
- cloud resource recovery can be validated;
- logging and monitoring integrity can be assessed;
- escalation criteria produce consistent outcomes.

Validation should cover relevant AWS, Microsoft Azure, and Google Cloud Platform environments where supported by the organization's infrastructure.

## Safety

This playbook is intended for defensive security operations, cloud incident response, security validation, and authorized testing only.

Cloud containment and remediation actions must be performed by authorized personnel according to approved organizational procedures.

Preserve forensic evidence, audit logging, evidence integrity, and chain of custody throughout the investigation. Avoid destructive remediation before assessing operational dependencies.
