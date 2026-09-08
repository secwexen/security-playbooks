---
id: "phishing"
name: "Phishing"
category: "initial-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-08T15:49:00Z"
updated_at: "2026-09-08T15:49:00Z"
description: "Phishing is a social engineering technique used to obtain access, credentials, or user interaction through deceptive messages and content."
objective: "Identify, analyze, and validate phishing activity and determine whether the technique resulted in credential exposure, malicious execution, or unauthorized access."
severity: "high"
mitre_attack:
  - "T1566"
triggers:
  - "Suspected phishing campaign"
  - "Malicious or deceptive email detected"
  - "Credential phishing attempt"
  - "Suspicious link or attachment delivery"
  - "User-reported phishing message"
  - "Threat intelligence identifies phishing infrastructure"
prerequisites:
  - "Access to email security telemetry"
  - "Access to identity and authentication logs"
  - "Access to endpoint telemetry"
  - "Access to URL, domain, and attachment analysis"
tags:
  - "phishing"
  - "initial-access"
  - "social-engineering"
  - "email"
  - "credentials"
  - "identity"
references:
  - "https://attack.mitre.org/techniques/T1566/"
steps:
- id: "identify-phishing"
  order: 1
  name: "Identify Phishing Activity"
  action: "investigate"
  description: "Identify the message, delivery channel, affected user, timestamp, and suspected phishing technique."
  expected_result: "The phishing event and affected user are clearly identified."
- id: "review-message"
  order: 2
  name: "Review Message Context"
  action: "analyze"
  description: "Review sender information, subject, headers, message content, links, and attachments."
  expected_result: "The message context and phishing indicators are documented."
- id: "analyze-indicators"
  order: 3
  name: "Analyze Phishing Indicators"
  action: "analyze"
  description: "Analyze domains, URLs, sender infrastructure, attachment hashes, and other available indicators."
  expected_result: "Relevant phishing indicators are identified and classified."
- id: "review-user-interaction"
  order: 4
  name: "Review User Interaction"
  action: "investigate"
  description: "Determine whether the recipient opened the message, followed a link, opened an attachment, or submitted information."
  expected_result: "User interaction with the phishing content is established."
- id: "review-account-activity"
  order: 5
  name: "Review Account Activity"
  action: "analyze"
  description: "Review authentication events, MFA activity, password changes, and other identity events following user interaction."
  expected_result: "Potential account compromise is identified or ruled out."
- id: "review-endpoint-activity"
  order: 6
  name: "Review Endpoint Activity"
  action: "analyze"
  description: "Review process execution, file creation, browser activity, and network connections associated with the phishing event."
  expected_result: "Potential endpoint impact is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Campaign Scope"
  action: "hunt"
  description: "Search for related messages, senders, domains, URLs, attachments, and affected users across the environment."
  expected_result: "The phishing campaign scope is established."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the phishing activity and document the evidence supporting the final assessment."
  expected_result: "The phishing event receives a documented outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "phishing"
---

# Phishing

## Purpose

This playbook provides a structured workflow for investigating phishing activity used to influence users, deliver malicious content, obtain credentials, or facilitate unauthorized access.

The objective is to identify the phishing technique, determine whether the user interacted with the content, assess potential account or endpoint impact, and establish the scope of the activity.

## MITRE ATT&CK

| Technique | Name     | Relevance                                                                                               |
| --------- | -------- | ------------------------------------------------------------------------------------------------------- |
| T1566     | Phishing | Relevant when an adversary uses deceptive messages or content to gain access or influence user behavior |

Additional phishing sub-techniques should be mapped when supported by the observed behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A suspected phishing campaign is identified.
- A malicious or deceptive email is detected.
- Credential phishing is suspected.
- A suspicious link or attachment is delivered.
- A user reports a suspicious message.
- Threat intelligence identifies phishing infrastructure.
- Multiple users receive messages with similar suspicious characteristics.

## Scope

The investigation should consider:

- sender;
- recipient;
- subject;
- message headers;
- sender domain;
- reply-to address;
- URLs;
- attachments;
- attachment hashes;
- delivery timestamps;
- user interaction;
- browser activity;
- authentication activity;
- MFA events;
- endpoint activity;
- related messages;
- related recipients;
- campaign infrastructure.

## Investigation Procedure

### Step 1 — Identify Phishing Activity

Determine:

- detection source;
- alert identifier;
- message timestamp;
- affected recipient;
- delivery channel;
- suspected phishing technique;
- detection severity.

Preserve the original message and alert context before making changes.

### Step 2 — Review Message Context

Review:

- sender address;
- display name;
- reply-to address;
- subject;
- message headers;
- sender authentication results;
- message body;
- URLs;
- attachments.

Look for:

- impersonation;
- urgency;
- credential requests;
- financial requests;
- unexpected business requests;
- misleading sender information.

### Step 3 — Analyze Phishing Indicators

Assess:

- sender domain;
- URLs;
- destination domains;
- redirect behavior where available;
- attachment hashes;
- sender infrastructure;
- domain reputation;
- known threat intelligence.

Do not access suspicious links from production systems.

### Step 4 — Review User Interaction

Determine whether the recipient:

- opened the message;
- clicked a link;
- opened an attachment;
- downloaded content;
- submitted credentials;
- entered sensitive information;
- replied to the sender.

Record relevant timestamps to establish the event sequence.

### Step 5 — Review Account Activity

When interaction occurred, review:

- successful sign-ins;
- failed sign-ins;
- source IP addresses;
- devices;
- MFA activity;
- password changes;
- authentication-factor changes;
- suspicious mailbox activity.

Determine whether phishing interaction was followed by account compromise indicators.

### Step 6 — Review Endpoint Activity

Investigate:

- browser activity;
- downloaded files;
- process creation;
- file creation;
- script execution;
- endpoint detections;
- network connections.

Correlate endpoint activity with the phishing event timeline.

### Step 7 — Determine Campaign Scope

Search across the environment for:

- sender address;
- sender domain;
- URLs;
- attachment hashes;
- subject;
- message patterns;
- related infrastructure.

Determine:

- number of affected recipients;
- number of delivered messages;
- number of users who interacted;
- earliest observed activity;
- most recent observed activity.

### Step 8 — Determine Investigation Outcome

Classify the activity as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Compromise Suspected**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence       | Description                                  |
| -------------- | -------------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp    |
| Message        | Original message and metadata                |
| Sender         | Sender address, domain, reply-to             |
| Recipient      | Affected user                                |
| Headers        | Relevant email headers                       |
| URLs           | Links and destination domains                |
| Attachments    | Names, types, and hashes                     |
| User Activity  | Recipient interaction                        |
| Authentication | Related account and MFA activity             |
| Endpoint       | Browser, process, file, and network activity |
| Campaign       | Related messages and recipients              |
| Indicators     | Domains, URLs, hashes, and infrastructure    |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the message is legitimate;
- sender information is verified;
- the content is expected;
- links and attachments are legitimate;
- no suspicious user, account, or endpoint activity is identified.

Document the justification before closing the alert.

### Suspicious

Classify the activity as **suspicious** when:

- sender identity is unclear;
- message content is unusual;
- URLs or attachments require further analysis;
- phishing indicators are present;
- the recipient interacted with suspicious content;
- additional investigation is required.

Continue investigation and collect additional evidence.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- confirmed phishing infrastructure;
- credential phishing;
- malicious payload delivery;
- confirmed malicious attachment or URL;
- coordinated phishing activity;
- confirmed post-delivery malicious activity.

Escalate to the appropriate incident-response workflow.

### Compromise Suspected

Use **compromise suspected** when the recipient interacted with phishing content and there is credible evidence that credentials, sessions, or endpoint security may have been affected, but compromise has not yet been confirmed.

Continue account and endpoint investigation.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine the nature or impact of the phishing activity.

Document:

- evidence collected;
- evidence unavailable;
- additional telemetry required.

## Escalation

Escalate the investigation when:

- credentials may have been submitted;
- a privileged account interacted with the phishing content;
- malicious payload execution is observed;
- multiple users are affected;
- account compromise is suspected;
- endpoint compromise is suspected;
- sensitive information may have been exposed.

## Response Guidance

For confirmed malicious phishing:

1. Preserve the original message and investigation evidence.
2. Identify all affected recipients.
3. Remove or quarantine malicious messages according to organizational procedures.
4. Investigate users who interacted with the content.
5. Follow account-containment procedures when credential compromise is suspected.
6. Review authentication and endpoint activity.
7. Search for related phishing indicators across the environment.
8. Escalate confirmed compromise to incident response.
9. Document the investigation timeline and remediation actions.

Do not delete relevant email, endpoint, or authentication evidence before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/yara-powershell-payload.yar`
- `detection-rules/suricata/network-alert.rules`

## Related Playbooks

- `playbooks/triage/phishing-alert-triage.md`
- `playbooks/triage/email-compromise-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/initial-access/malicious-attachment.md`
- `playbooks/initial-access/application-consent-abuse.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/response/phishing-response.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`

## Validation

The playbook should be validated against approved phishing simulations, email-security datasets, identity telemetry, and controlled endpoint scenarios.

Validation should confirm that:

- phishing messages can be identified;
- message and header information can be investigated;
- URLs and attachments can be assessed;
- user interaction can be determined;
- account and endpoint activity can be correlated;
- campaign scope can be established;
- legitimate messages can be distinguished from malicious phishing;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Suspicious links, attachments, and credential-collection pages must be handled through approved analysis environments and procedures.
