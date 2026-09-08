---
id: "application-consent-abuse"
name: "Application Consent Abuse"
category: "initial-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-08T11:11:00Z"
updated_at: "2026-09-08T11:11:00Z"
description: "Investigate suspicious application consent, OAuth grants, and delegated access that may allow unauthorized access to user or organizational resources."
objective: "Determine whether an application consent or delegated-access event was legitimate, identify affected accounts and permissions, establish scope, and determine whether containment or incident response is required."
severity: "high"
mitre_attack:
  - "T1098"
triggers:
  - "Unexpected application consent"
  - "Suspicious OAuth application grant"
  - "Unexpected delegated permission"
  - "User reports an unfamiliar application"
  - "Application gains access to mail, files, or other organizational resources"
  - "Threat intelligence identifies a suspicious application or consent event"
prerequisites:
  - "Access to identity provider audit logs"
  - "Access to application and OAuth consent logs"
  - "Access to account authentication telemetry"
  - "Access to cloud resource audit logs where available"
tags:
  - "application-consent"
  - "oauth"
  - "initial-access"
  - "identity"
  - "cloud"
  - "account-compromise"
references:
  - "https://attack.mitre.org/techniques/T1098/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Consent Alert"
  action: "investigate"
  description: "Identify the alert source, affected account, application, timestamp, and consent event."
  expected_result: "The application consent event and affected account are clearly identified."
- id: "identify-application"
  order: 2
  name: "Identify Application"
  action: "analyze"
  description: "Identify the application, publisher, application identifier, tenant context, and ownership information."
  expected_result: "The application and its ownership context are documented."
- id: "review-permissions"
  order: 3
  name: "Review Granted Permissions"
  action: "analyze"
  description: "Review the permissions and scopes granted to the application and determine whether they are appropriate."
  expected_result: "Granted permissions and associated risk are documented."
- id: "review-consent-context"
  order: 4
  name: "Review Consent Context"
  action: "investigate"
  description: "Review who granted consent, when consent occurred, source information, and associated authentication activity."
  expected_result: "The consent context and initiating identity are understood."
- id: "review-application-activity"
  order: 5
  name: "Review Application Activity"
  action: "analyze"
  description: "Review resource access performed by the application after consent, including mail, files, directory, or other cloud resources."
  expected_result: "Potential post-consent resource access is identified or ruled out."
- id: "correlate-account-activity"
  order: 6
  name: "Correlate Account Activity"
  action: "hunt"
  description: "Correlate consent activity with sign-ins, MFA events, password changes, mailbox activity, and other suspicious account behavior."
  expected_result: "Related account compromise indicators are identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Scope"
  action: "hunt"
  description: "Search for the same application, permissions, consent pattern, or application identifier across other accounts and tenants."
  expected_result: "The number of affected accounts and related consent events is determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the consent event and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "application-consent-abuse"
---

# Application Consent Abuse

## Purpose

This playbook provides a structured workflow for investigating suspicious application consent and delegated-access activity.

The objective is to determine whether an application was legitimately granted access or whether the consent event may have enabled unauthorized access to user or organizational resources.

## MITRE ATT&CK

| Technique | Name                 | Relevance                                                                                                              |
| --------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| T1098     | Account Manipulation | Relevant when an adversary modifies account access or grants additional permissions through account-related mechanisms |

Additional ATT&CK techniques should only be mapped when supported by the observed application-consent behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An unexpected application consent event is detected.
- A user grants an unfamiliar application access to organizational resources.
- An OAuth application receives suspicious permissions.
- A delegated permission is unexpectedly assigned.
- An application gains access to mail, files, directory data, or other organizational resources.
- Threat intelligence identifies a suspicious application or consent event.
- Multiple accounts grant consent to the same suspicious application.

## Scope

The investigation should consider:

- affected account;
- application name;
- application ID;
- publisher;
- tenant;
- consent timestamp;
- granting identity;
- source IP;
- source device;
- authentication method;
- MFA activity;
- granted permissions;
- OAuth scopes;
- delegated permissions;
- application activity;
- accessed resources;
- related accounts;
- related alerts.

## Triage Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected account;
- application;
- consent event;
- alert severity;
- detection reason.

Preserve the original alert context before removing permissions or modifying the account.

### Step 2 — Identify the Application

Collect:

- application name;
- application ID;
- publisher;
- publisher verification status where available;
- tenant;
- application ownership;
- registration details.

Determine whether the application is:

- approved;
- known but unexpected;
- unfamiliar;
- suspicious.

An unfamiliar application should be investigated further but should not be classified as malicious solely because it is unknown.

### Step 3 — Review Granted Permissions

Identify all permissions and scopes granted to the application.

Pay particular attention to access involving:

- email;
- files;
- directory information;
- user profiles;
- calendar data;
- administrative resources;
- other sensitive organizational resources.

Determine whether the requested access is consistent with the application's documented purpose.

### Step 4 — Review Consent Context

Determine:

- who granted consent;
- when consent occurred;
- source IP;
- source device;
- authentication method;
- MFA result;
- preceding sign-in activity.

Look for:

- unusual sign-in locations;
- unfamiliar devices;
- suspicious MFA activity;
- consent occurring immediately after another suspicious event.

### Step 5 — Review Application Activity

Where application audit telemetry is available, review:

- resource access;
- mailbox access;
- file access;
- directory queries;
- API activity;
- access timestamps;
- affected resources.

Determine whether the application actually used the granted permissions.

### Step 6 — Correlate Account Activity

Review the affected account for:

- successful sign-ins;
- failed sign-ins;
- password changes;
- MFA changes;
- mailbox changes;
- suspicious outbound email;
- endpoint activity;
- other application consent events.

Determine whether the consent event is isolated or part of a broader account compromise.

### Step 7 — Determine Scope

Search for:

- same application ID;
- same application name;
- same publisher;
- same permission set;
- same consent pattern;
- same source infrastructure.

Determine:

- number of affected accounts;
- number of consent events;
- first observed event;
- most recent event;
- whether the application currently retains access.

### Step 8 — Determine Investigation Outcome

Classify the event as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence             | Description                                         |
| -------------------- | --------------------------------------------------- |
| Alert                | Detection source, ID, severity, timestamp           |
| Account              | User or service account                             |
| Application          | Name, ID, publisher, tenant                         |
| Consent              | Consent timestamp and granting identity             |
| Permissions          | Granted scopes and permissions                      |
| Source               | IP address and source device                        |
| Authentication       | Sign-in and MFA context                             |
| Application Activity | API and resource access                             |
| Resources            | Mail, files, directory, or other accessed resources |
| Scope                | Other accounts using the application                |
| Detections           | Related security alerts                             |

## Decision Criteria

### Benign

Classify the consent event as **benign** when:

- the application is approved;
- the publisher is trusted;
- permissions are appropriate;
- the granting user or administrator is authorized;
- the application use matches its documented purpose;
- no additional suspicious activity is identified.

Document the business or operational justification before closing the alert.

### Suspicious

Classify the event as **suspicious** when:

- the application is unfamiliar;
- permissions are broader than expected;
- publisher information cannot be confidently verified;
- the granting context is unusual;
- application activity is unexpected;
- related account activity requires further investigation.

Continue investigation and collect additional evidence.

### Malicious

Classify the event as **malicious** when sufficient evidence indicates:

- unauthorized application consent;
- malicious or deceptive application use;
- unauthorized access to protected resources;
- application consent associated with confirmed account compromise;
- coordinated consent activity across multiple compromised accounts.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the consent event was authorized.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- high-risk permissions were granted unexpectedly;
- sensitive resources were accessed;
- privileged accounts are affected;
- multiple accounts granted consent to the same suspicious application;
- account compromise is suspected;
- suspicious application activity is confirmed.

## Response Guidance

For confirmed malicious application consent:

1. Preserve identity, consent, and application audit evidence.
2. Identify all affected accounts and applications.
3. Follow the organization's application-access containment procedure.
4. Revoke unauthorized application permissions according to authorized procedures.
5. Review active sessions and authentication activity where applicable.
6. Investigate affected mailbox, file, directory, and other cloud resources.
7. Review related account compromise indicators.
8. Search the environment for the same application and consent pattern.
9. Escalate confirmed compromise to incident response.
10. Document the investigation timeline and remediation actions.

Do not revoke access or delete application registrations before required evidence preservation and appropriate authorization have been considered.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`

## Related Playbooks

- `playbooks/triage/email-compromise-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/initial-access/phishing.md`
- `playbooks/cloud/cloud-account-compromise.md`
- `playbooks/cloud/application-access-token-abuse.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`

## Validation

The playbook should be validated against approved identity, application, OAuth, and cloud-audit datasets.

Validation should confirm that:

- suspicious consent events can be identified;
- applications and publishers can be investigated;
- granted permissions can be assessed;
- consent and authentication activity can be correlated;
- application resource access can be investigated;
- affected accounts can be identified;
- legitimate application consent can be distinguished from abuse;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Application permission changes, session termination, account containment, and access revocation must follow applicable authorization, evidence-preservation, privacy, and change-management procedures.
