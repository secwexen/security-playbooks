---
id: "cloud-infrastructure-discovery"
name: "Cloud Infrastructure Discovery"
category: "cloud"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-10-21T17:16:00Z"
updated_at: "2026-10-21T17:16:00Z"
description: "Investigate suspicious enumeration of cloud infrastructure resources, including virtual machines, disks, snapshots, storage services, databases, and network components across cloud environments."
objective: "Determine whether cloud infrastructure discovery is authorized, identify the identities and resources involved, establish the scope of suspicious enumeration, and identify potential follow-on malicious activity."
severity: "medium"
mitre_attack:
  - "T1580"
  - "T1526"
  - "T1538"
  - "T1619"
triggers:
  - "A cloud identity performs unusual or excessive enumeration of infrastructure resources."
  - "An unfamiliar identity lists virtual machines, disks, snapshots, databases, or storage resources."
  - "Cloud API discovery requests originate from an unexpected IP address, location, device, or workload."
  - "An identity enumerates resources across multiple regions, subscriptions, projects, or accounts without an established operational reason."
  - "Unusual infrastructure discovery occurs shortly after suspicious authentication or suspected credential compromise."
  - "Resource enumeration is followed by unexpected snapshot creation, permission changes, resource modification, or data access."
  - "A cloud management console or command-line interface is used to inspect infrastructure outside the expected administrative pattern."
prerequisites:
  - "Access to cloud identity and authentication logs."
  - "Access to cloud control-plane audit logs, such as AWS CloudTrail, Azure Activity Logs, or Google Cloud Audit Logs."
  - "Access to relevant infrastructure inventory and resource metadata."
  - "Access to resource management, permission, and configuration change records."
  - "Known administrative identities, service accounts, automation processes, and expected inventory activity."
  - "An approved process for incident escalation, identity containment, and cloud resource protection."
tags:
  - "cloud"
  - "infrastructure-discovery"
  - "reconnaissance"
  - "cloud-audit"
  - "identity"
  - "threat-hunting"
  - "incident-response"
references:
  - "https://attack.mitre.org/techniques/T1580/"
  - "https://attack.mitre.org/techniques/T1526/"
  - "https://attack.mitre.org/techniques/T1538/"
  - "https://attack.mitre.org/techniques/T1619/"
steps:
  - id: "identify-infrastructure-discovery-alert"
    order: 1
    name: "Identify Infrastructure Discovery Alert"
    action: "investigate"
    description: "Identify the alert source, cloud provider, affected account or project, initiating identity, discovery operations, timestamps, and initial detection context."
    expected_result: "The alert, affected environment, initiating identity, observed operations, and initial investigation scope are documented."
  - id: "identify-enumerated-resources"
    order: 2
    name: "Identify Enumerated Resource Types"
    action: "analyze"
    description: "Determine whether the activity involves compute instances, virtual machines, disks, snapshots, storage resources, databases, network components, or other infrastructure metadata."
    expected_result: "The resource categories, relevant services, discovery operations, and affected cloud environment are identified."
  - id: "review-identity-and-access-context"
    order: 3
    name: "Review Identity and Access Context"
    action: "analyze"
    description: "Review the initiating user, role, service principal, workload identity, or service account, including authentication context, effective permissions, source IP, user agent, and expected operational responsibilities."
    expected_result: "The initiating identity, privilege level, access context, and expected resource discovery behavior are documented."
  - id: "analyze-discovery-pattern"
    order: 4
    name: "Analyze Resource Discovery Pattern"
    action: "analyze"
    description: "Assess the frequency, volume, sequence, geographic distribution, and scope of resource enumeration. Compare observed activity with established administrative and automation baselines."
    expected_result: "The discovery pattern is characterized, and deviations from normal infrastructure inventory activity are identified."
  - id: "review-cloud-audit-events"
    order: 5
    name: "Review Cloud Audit Events"
    action: "investigate"
    description: "Examine cloud control-plane audit records for resource listing, description, metadata retrieval, authentication, and related configuration operations. Validate the event source and available logging coverage."
    expected_result: "Relevant audit events are collected, correlated, and assessed for suspicious infrastructure discovery behavior."
  - id: "correlate-follow-on-activity"
    order: 6
    name: "Correlate Follow-on Activity"
    action: "hunt"
    description: "Investigate activity preceding and following resource enumeration, including suspicious authentication, credential access, permission changes, snapshot creation, resource modification, storage access, and potential data exfiltration."
    expected_result: "Related events are correlated into a timeline, and evidence of possible follow-on compromise is identified or assessed."
  - id: "determine-discovery-scope"
    order: 7
    name: "Determine Discovery Scope"
    action: "hunt"
    description: "Establish which accounts, regions, subscriptions, projects, resources, and privilege boundaries were involved. Determine whether the activity was read-only or accompanied by unauthorized changes or resource access."
    expected_result: "The known and potential scope of discovery and related unauthorized activity is documented."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Classify the activity using available evidence, document the investigation findings and uncertainty, and determine whether monitoring, containment, or incident response escalation is required."
    expected_result: "The activity receives a documented classification with supporting evidence, identified gaps, and recommended next actions."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "cloud-infrastructure-discovery"
---

# Cloud Infrastructure Discovery

## Purpose

This playbook provides a structured workflow for investigating suspicious discovery of cloud infrastructure resources.

Cloud infrastructure discovery involves enumerating and inspecting resources available within an infrastructure-as-a-service (IaaS) environment. These resources may include virtual machines, compute instances, disks, snapshots, storage services, databases, and network components.

Cloud administrators, security teams, inventory systems, and deployment automation regularly perform resource discovery. However, an attacker operating with compromised credentials or an unauthorized identity may use similar operations to identify valuable infrastructure, locate sensitive assets, and prepare subsequent actions.

## MITRE ATT&CK

| Technique | Name                           | Relevance                                                                                                                                                |
| --------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T1580     | Cloud Infrastructure Discovery | Primary technique covering the enumeration of cloud infrastructure components, including compute instances, snapshots, storage resources, and databases. |
| T1526     | Cloud Service Discovery        | Relevant when activity expands from infrastructure components to identifying available cloud services, platforms, and service capabilities.              |
| T1538     | Cloud Service Dashboard        | Relevant when an identity uses a cloud management console or dashboard to inspect infrastructure and resource information.                               |
| T1619     | Cloud Storage Object Discovery | Relevant when activity progresses from identifying cloud storage resources to enumerating objects stored within them.                                    |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An identity performs an unusual number of cloud resource listing or description operations.
- A previously unseen user, role, service principal, or workload identity enumerates infrastructure resources.
- Resource discovery occurs from an unexpected IP address, geographic location, device, or user agent.
- Infrastructure enumeration spans multiple regions, subscriptions, projects, or accounts without an established operational justification.
- Resource discovery occurs shortly after a suspicious login, suspected credential exposure, or unexpected identity change.
- Discovery operations are followed by snapshot creation, resource modification, permission changes, or suspicious data access.
- A cloud management console or command-line interface is used to inspect infrastructure in an unusual context.
- Resource inventory activity occurs outside expected maintenance windows or deviates from the behavior of known automation systems.

## Scope

The investigation should consider:

- affected cloud provider, tenant, account, subscription, or project;
- initiating user, role, service principal, workload identity, or service account;
- authentication method and session context;
- source IP address, geographic location, and user agent where available;
- cloud services and API operations involved;
- resource types enumerated;
- compute instances and virtual machines;
- disks, images, and snapshots;
- storage services and their configuration metadata;
- database instances and associated infrastructure;
- virtual networks, network interfaces, and security groups;
- resource enumeration across regions or administrative boundaries;
- effective permissions and relevant role assignments;
- discovery frequency, volume, and sequence;
- related authentication, identity, and credential events;
- subsequent resource access or configuration changes;
- potential data access, collection, or exfiltration;
- other identities and resources that may be affected.

Do not assume that a read-only API operation is harmless. Resource metadata can reveal asset names, network topology, deployment patterns, backup locations, database configurations, and information useful for subsequent attacks.

## Investigation Procedure

### Step 1 — Identify Infrastructure Discovery Alert

Identify the source and context of the alert.

Collect:

- alert identifier;
- detection source;
- alert timestamp;
- affected cloud provider;
- account, tenant, subscription, or project identifier;
- initiating identity;
- source IP address and user agent where available;
- relevant API operations or console actions;
- affected resource identifiers;
- detection severity and reason;
- associated authentication or security alerts.

### Step 2 — Identify Enumerated Resource Types

Determine which cloud infrastructure resources were accessed or enumerated.

- Compute instances and virtual machines.
- Disks, snapshots, and machine images.
- Storage services and storage account metadata.
- Database instances and configurations.
- Virtual networks, subnets, and network interfaces.
- Security groups, firewall rules, and routing configurations.
- Resources across multiple regions, subscriptions, projects, or accounts.
- Relevant API operation names and resource identifiers.
- The cloud provider and affected environment.

### Step 3 — Review Identity and Access Context

Identify the identity responsible for the observed activity.

Determine:

- whether the identity belongs to a human user, application, service, or workload;
- whether the identity is expected to administer or inventory the affected resources;
- assigned roles and effective permissions;
- recent role assignments or permission changes;
- use of temporary credentials or assumed roles where applicable;
- authentication time and session characteristics;
- source IP address and expected access locations;
- user agent, API client, or cloud console context where available;
- whether multifactor authentication or applicable access policies were satisfied;
- whether the identity has recently exhibited suspicious behavior.

### Step 4 — Analyze Discovery Pattern

Assess how resource enumeration was performed.

Review:

- the number of listing and description operations;
- the rate of requests within the investigation window;
- the range of services and resource types accessed;
- the sequence of API operations;
- the number of regions, subscriptions, accounts, or projects involved;
- whether the activity was initiated through an API, CLI, SDK, automation process, or web console;
- source IP and user-agent consistency;
- whether the activity is associated with known inventory jobs;
- whether the discovery pattern differs from the identity's established baseline.

Look for patterns such as:

- rapid enumeration of multiple resource categories;
- repeated listing operations across many regions;
- access to resource types the identity does not normally inspect;
- discovery performed by a newly observed or unusual identity;
- enumeration immediately following an unusual authentication event;
- discovery followed by activity directed at specific high-value resources.

### Step 5 — Review Cloud Audit Events

Review cloud audit logs to identify who performed the discovery operations, when they occurred, and which resources were involved.

- **AWS:** Review CloudTrail events, including `DescribeInstances`, `DescribeVolumes`, `DescribeSnapshots`, and `DescribeDBInstances`.
- **Azure:** Review Activity Logs for virtual machine, disk, snapshot, storage, database, and network resource operations.
- **GCP:** Review Cloud Audit Logs for Compute Engine, persistent disk, snapshot, Cloud SQL, and network resource operations.
- Identify the initiating user, role, service principal, or service account.
- Review event timestamps, source IP addresses, API operation names, regions, and resource identifiers.
- Determine whether the operations succeeded or failed.
- Correlate discovery events with authentication activity and subsequent resource changes.
- Verify audit logging coverage and document missing or incomplete records.

### Step 6 — Correlate Follow-on Activity

Determine whether the discovery activity was followed by additional actions that may indicate an attack.

Correlate the timeline with:

- suspicious authentication or session activity;
- potential credential access or exposure;
- role assignments and permission changes;
- creation or modification of access keys and application credentials;
- assumed-role or delegated access activity;
- snapshot or image creation;
- changes to storage access policies;
- database or storage access;
- security group, firewall, or network configuration changes;
- compute instance modification or creation;
- changes to logging or security controls;
- unusual data transfer or exfiltration alerts;
- other suspicious cloud API activity.

### Step 7 — Determine Discovery Scope

Establish the known and potential scope of the activity.

Determine:

- which cloud accounts, tenants, subscriptions, and projects were involved;
- which regions were queried;
- which resource categories were enumerated;
- which resource identifiers were returned or accessed, where available;
- whether the activity remained read-only;
- whether sensitive metadata was retrieved;
- whether storage objects or database contents were subsequently accessed;
- whether any resources were modified;
- whether permissions were changed;
- whether other identities were involved;
- whether the activity is associated with suspected credential compromise;
- the earliest known and latest observed activity;
- whether the activity is ongoing;
- which relevant logs or evidence remain unavailable.

### Step 8 — Determine Investigation Outcome

Classify the observed activity using the available evidence.

Possible outcomes are:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence           | Description                                                                                    |
| ------------------ | ---------------------------------------------------------------------------------------------- |
| Alert              | Detection source, alert identifier, severity, and initial investigation context                |
| Cloud Environment  | Provider, tenant, account, subscription, project, and relevant region                          |
| Identity           | Initiating user, role, service principal, workload identity, or service account                |
| Authentication     | Sign-in records, session context, authentication results, and source IP                        |
| API Activity       | Operation names, event timestamps, request parameters, results, and relevant response metadata |
| Resource Inventory | Enumerated resource categories, resource identifiers, and relevant configuration metadata      |
| Discovery Pattern  | Request volume, frequency, sequence, region coverage, and resource categories                  |
| Permissions        | Assigned roles, effective privileges, role assumptions, and relevant permission changes        |
| Network Context    | Source IP, geographic information, user agent, and other available connection metadata         |
| Related Activity   | Credential events, snapshots, resource changes, storage access, and other related operations   |
| Timeline           | Chronological sequence of authentication, discovery, and follow-on activity                    |
| Scope              | Affected accounts, projects, subscriptions, regions, identities, and resources                 |
| Logging Coverage   | Relevant audit sources, retention periods, missing records, and known visibility limitations   |
| Response           | Investigation decisions, escalation details, containment actions, and verification results     |

## Decision Criteria

### Benign

Classify the activity as **benign** when the available evidence establishes that:

- the initiating identity is authorized to perform the observed discovery;
- the operations are consistent with documented administrative or inventory responsibilities;
- the source and authentication context are expected;
- the resource categories and regions are within the identity's operational scope;
- the volume and sequence are consistent with approved workflows;
- no unexplained follow-on activity is observed;
- relevant audit evidence supports the operational explanation.

Document the operational justification and any baseline adjustments before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- resource enumeration deviates from the identity's expected behavior;
- a previously unseen or unusual identity enumerates infrastructure;
- discovery occurs from an unexpected IP address, device, or access context;
- multiple resource categories or regions are queried without a clear justification;
- the activity follows a suspicious authentication event;
- resource discovery precedes unusual permission changes or resource access;
- potentially relevant audit records are missing or incomplete;
- no confirmed malicious action has been identified, but the activity remains unexplained.

Continue investigation, collect additional evidence, and assess whether preventive containment or heightened monitoring is warranted.

### Malicious

Classify the activity as **malicious** when sufficient evidence establishes that unauthorized infrastructure discovery occurred as part of malicious activity.

Supporting evidence may include:

- confirmed unauthorized use of a compromised cloud identity;
- infrastructure enumeration inconsistent with the identity's authorized purpose and corroborated by other compromise indicators;
- discovery linked to unauthorized credential access or privilege escalation;
- resource discovery followed by unauthorized snapshot creation, configuration changes, or access to sensitive resources;
- a confirmed malicious sequence involving infrastructure reconnaissance and subsequent unauthorized operations;
- corroborating security alerts or forensic evidence establishing malicious intent.

Escalate to the appropriate incident response process and initiate authorized containment and remediation.

### Inconclusive

Classify the activity as **inconclusive** when available evidence is insufficient to determine whether the resource discovery was authorized.

Document:

- evidence collected;
- evidence that remains unavailable;
- unresolved questions about the initiating identity or activity;
- affected resources that cannot be ruled out;
- relevant logging and retention limitations;
- additional telemetry or access required;
- recommended investigative actions.

Do not treat an inconclusive result as confirmation that the activity was safe.

## Escalation

Escalate the investigation when:

- unauthorized use of a cloud identity is suspected or confirmed;
- discovery is associated with a potentially compromised privileged identity;
- infrastructure enumeration spans multiple accounts, subscriptions, projects, or tenants without authorization;
- sensitive databases, backups, snapshots, or storage resources are targeted;
- resource discovery is followed by suspicious permission changes or resource modification;
- the activity is associated with suspected credential theft or account compromise;
- unauthorized data access or exfiltration is suspected;
- security controls or audit logging may have been disabled or modified;
- suspicious activity remains active;
- the incident may affect production services or critical business operations.

## Response Guidance

For confirmed malicious infrastructure discovery:

1. Preserve relevant cloud audit records, identity events, resource metadata, and related evidence.
2. Identify the initiating identity and determine whether unauthorized access remains active.
3. Establish the scope of resource enumeration across affected accounts, subscriptions, projects, and regions.
4. Investigate associated authentication events and determine whether credential compromise is suspected.
5. Review recent role assignments, permission changes, and delegated access associated with the identity.
6. If compromise is confirmed or strongly supported by evidence, apply authorized identity containment measures.
7. Investigate resource modifications, snapshot creation, storage access, and other operations that followed discovery.
8. Search for related activity across other identities and cloud environments.
9. Remediate unauthorized permissions, configuration changes, or access paths identified during the investigation.
10. Validate logging coverage and address relevant detection gaps.
11. Confirm that unauthorized activity has stopped and that required cloud resources remain available.
12. Document containment, remediation, and verification results.

Do not delete resources, revoke access, or modify cloud configurations before considering evidence preservation and appropriate authorization.

## Related Detection Rules

## Related Playbooks

- `playbooks/cloud/cloud-credential-access.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/response/account-compromise-response.md`

## Validation

The playbook should be validated against approved cloud audit telemetry, identity logs, infrastructure inventory records, and controlled test scenarios.

Validation should confirm that:

- the initiating identity can be identified from available audit records;
- relevant infrastructure enumeration operations can be detected and investigated;
- resource types and affected cloud boundaries can be determined;
- unusual discovery patterns can be compared with expected administrative behavior;
- activity across multiple regions, subscriptions, projects, or accounts can be investigated where applicable;
- authentication and infrastructure discovery events can be correlated;
- follow-on resource changes and access can be identified;
- known inventory automation can be distinguished from suspicious activity;
- missing audit records and logging limitations can be documented;
- investigation outcomes and escalation decisions are recorded consistently.

## Safety

This playbook is intended for defensive security operations, authorized cloud monitoring, incident response, and controlled security validation.

Investigations must use approved access and evidence-handling procedures. Do not access unrelated resources, enumerate environments outside the approved scope, or modify infrastructure without appropriate authorization.

Protect cloud resource metadata, identity information, and other sensitive operational details when storing or sharing investigation evidence.
Identity containment, permission changes, and cloud resource modifications must follow authorized incident response procedures and applicable change-management requirements.
