---
id: "phishing-alert-triage"
name: "Phishing Alert Triage"
category: "triage"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-02T00:00:00Z"
updated_at: "2026-09-02T00:00:00Z"
description: "Investigate suspected phishing emails and determine whether the message is benign, malicious, or part of a broader account or security incident."
objective: "Determine the legitimacy, scope, and impact of a suspected phishing message and identify required containment, investigation, or escalation actions."
severity: "high"
mitre_attack:
  - "T1566"
triggers:
  - "Phishing email alert"
  - "User-reported suspicious email"
  - "Malicious attachment detection"
  - "Suspicious URL or link detection"
  - "Credential phishing detection"
  - "Threat intelligence identifies a suspicious sender, domain, URL, or attachment"
prerequisites:
  - "Access to email security telemetry"
  - "Access to message headers and email metadata"
  - "Access to URL and attachment analysis capabilities"
  - "Access to identity and endpoint telemetry"
tags:
  - "phishing"
  - "triage"
  - "email"
  - "initial-access"
  - "social-engineering"
references:
  - "https://attack.mitre.org/techniques/T1566/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Phishing Alert"
  action: "investigate"
  description: "Identify the detection source, affected recipient, message timestamp, and alert context."
  expected_result: "The suspected phishing message and affected recipient are identified."
- id: "review-message"
  order: 2
  name: "Review Message Metadata"
  action: "analyze"
  description: "Review sender, recipient, subject, headers, authentication results, and delivery information."
  expected_result: "The message origin and delivery context are documented."
- id: "analyze-content"
  order: 3
  name: "Analyze Message Content"
  action: "analyze"
  description: "Review message content, social-engineering indicators, links, attachments, and requested actions."
  expected_result: "Suspicious content and social-engineering indicators are identified or ruled out."
- id: "analyze-indicators"
  order: 4
  name: "Analyze Indicators"
  action: "analyze"
  description: "Investigate sender addresses, domains, URLs, attachment hashes, and other indicators."
  expected_result: "Relevant indicators are classified and documented."
- id: "review-recipient-activity"
  order: 5
  name: "Review Recipient Activity"
  action: "investigate"
  description: "Determine whether the recipient opened the message, followed a link, opened an attachment, submitted credentials, or performed another requested action."
  expected_result: "Recipient interaction with the phishing message is established."
- id: "correlate-account-endpoint"
  order: 6
  name: "Correlate Account and Endpoint Activity"
  action: "hunt"
  description: "Review authentication, endpoint, browser, and network activity following interaction with the message."
  expected_result: "Potential post-delivery compromise activity is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Campaign Scope"
  action: "hunt"
  description: "Search for the same sender, domain, URL, attachment, subject, or message pattern across the environment."
  expected_result: "The number of affected recipients and related messages is determined."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the message and document the supporting evidence and required next action."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "phishing-alert"
---

# Phishing Alert Triage

## Purpose

This playbook provides a structured SOC workflow for investigating suspected phishing messages.

The objective is to determine whether the message is:

- legitimate;
- suspicious;
- malicious; or
- part of a broader account or security incident.

## MITRE ATT&CK

| Technique | Name     | Relevance                                                                              |
| --------- | -------- | -------------------------------------------------------------------------------------- |
| T1566     | Phishing | Relevant when an adversary uses phishing to deliver malicious content or obtain access |

Additional sub-techniques should be mapped when the observed phishing behavior clearly supports them.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A phishing detection is generated.
- A user reports a suspicious email.
- A malicious attachment is detected.
- A suspicious URL is identified.
- Credential phishing is suspected.
- Threat intelligence identifies a malicious sender, domain, URL, or attachment.
- Multiple users receive messages with the same suspicious characteristics.

## Scope

The investigation should consider:

- sender;
- recipient;
- subject;
- message timestamp;
- message headers;
- sender domain;
- reply-to address;
- authentication results;
- URLs;
- attachments;
- attachment hashes;
- message delivery information;
- recipient interaction;
- browser activity;
- authentication activity;
- endpoint activity;
- related messages;
- additional affected recipients.

## Triage Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected recipient;
- detection severity;
- detection reason.

Record the original alert information before making changes to the message or recipient account.

### Step 2 — Review Message Metadata

Review:

- sender address;
- sender display name;
- recipient;
- subject;
- date and time;
- reply-to address;
- return-path;
- message ID;
- originating IP where available;
- email authentication results;
- delivery path.

Pay particular attention to inconsistencies between sender identity and message infrastructure.

### Step 3 — Analyze Message Content

Review:

- message wording;
- urgency or pressure;
- requests for credentials;
- requests for payment or sensitive information;
- suspicious links;
- attachments;
- impersonation indicators;
- unusual branding;
- unexpected business requests.

A suspicious characteristic alone should not establish malicious intent. Correlate content with technical indicators and recipient activity.

### Step 4 — Analyze URLs and Attachments

For URLs, collect:

- full URL;
- domain;
- hostname;
- redirect information where available;
- reputation;
- first-seen information where available.

For attachments, collect:

- filename;
- file type;
- SHA-256 hash;
- file size;
- embedded links;
- execution behavior where applicable.

Use approved analysis and sandboxing capabilities when required.

Do not open suspicious content on production endpoints outside approved analysis procedures.

### Step 5 — Review Recipient Activity

Determine whether the recipient:

- opened the message;
- followed a link;
- opened an attachment;
- submitted credentials;
- downloaded content;
- replied to the sender;
- forwarded the message.

Review associated timestamps to establish the sequence of events.

### Step 6 — Correlate Account and Endpoint Activity

When interaction occurred, investigate:

- authentication events;
- MFA events;
- password changes;
- browser activity;
- process execution;
- downloaded files;
- endpoint alerts;
- network connections.

Determine whether the phishing message was followed by suspicious account or endpoint activity.

### Step 7 — Determine Campaign Scope

Search across the environment for:

- sender address;
- sender domain;
- reply-to address;
- URL;
- attachment hash;
- attachment filename;
- subject;
- message ID;
- similar message content.

Determine:

- number of recipients;
- number of delivered messages;
- number of users who interacted;
- earliest observed message;
- latest observed message.

### Step 8 — Determine Investigation Outcome

Classify the message as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification.

## Evidence to Collect

| Evidence           | Description                                          |
| ------------------ | ---------------------------------------------------- |
| Alert              | Detection source, ID, severity, timestamp            |
| Sender             | Sender address and display name                      |
| Recipient          | Affected recipient                                   |
| Subject            | Email subject                                        |
| Headers            | Relevant message headers                             |
| Authentication     | SPF, DKIM, DMARC and related results where available |
| URLs               | Links and destination domains                        |
| Attachments        | Names, types, and hashes                             |
| Recipient Activity | User interaction with the message                    |
| Authentication     | Related account activity                             |
| Endpoint           | Related process and file activity                    |
| Network            | Related network connections                          |
| Campaign           | Related messages and affected recipients             |

## Decision Criteria

### Benign

Classify the message as **benign** when:

- the sender is verified;
- the message is expected;
- authentication results are consistent with legitimate delivery;
- links and attachments are expected;
- no suspicious recipient activity is identified.

Document the reason before closing the alert.

### Suspicious

Classify the message as **suspicious** when:

- sender identity is unclear;
- message content is unusual;
- links or attachments require further analysis;
- authentication results are abnormal or incomplete;
- the recipient interacted with suspicious content;
- additional investigation is required.

Continue investigation and correlate additional evidence.

### Malicious

Classify the message as **malicious** when sufficient evidence indicates:

- credential phishing;
- malicious attachment delivery;
- malicious link delivery;
- impersonation associated with malicious activity;
- confirmed malicious infrastructure;
- confirmed post-delivery compromise activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to establish whether the message is benign or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional analysis required.

## Escalation

Escalate the investigation when:

- credentials may have been submitted;
- a privileged account interacted with the message;
- malicious attachments were executed;
- multiple recipients are affected;
- confirmed malicious infrastructure is identified;
- suspicious authentication follows the phishing event;
- endpoint compromise is suspected;
- the phishing campaign targets sensitive personnel or systems.

## Response Guidance

For confirmed malicious phishing:

1. Preserve the relevant email and investigation evidence.
2. Remove or quarantine malicious messages according to organizational procedures.
3. Identify all affected recipients.
4. Investigate users who clicked links or opened attachments.
5. Follow account-containment procedures when credential compromise is suspected.
6. Review active sessions and authentication activity where applicable.
7. Search for related indicators across the environment.
8. Escalate confirmed compromise to incident response.
9. Document the timeline and remediation actions.

Do not delete relevant evidence before required preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/yara-powershell-payload.yar`
- `detection-rules/suricata/network-alert.rules`

## Related Playbooks

- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/initial-access/phishing.md`
- `playbooks/initial-access/malicious-attachment.md`
- `playbooks/initial-access/application-consent-abuse.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`

## Validation

The playbook should be validated against approved phishing messages, simulated phishing scenarios, and related authentication and endpoint datasets.

Validation should confirm that:

- phishing messages can be identified;
- message metadata and headers can be investigated;
- URLs and attachments can be assessed;
- recipient interaction can be determined;
- related account and endpoint activity can be correlated;
- campaign scope can be established;
- benign messages can be distinguished from malicious phishing;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Suspicious links, attachments, and credential-collection pages should be handled only through approved analysis environments and procedures.
