---
id: "malicious-attachment"
name: "Malicious Attachment"
category: "initial-access"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-09-07T09:50:00Z"
updated_at: "2026-09-07T09:50:00Z"
description: "Investigate and assess malicious or suspicious email attachments that may deliver malware or enable unauthorized access."
objective: "Determine whether a delivered attachment is malicious, identify recipient and endpoint impact, establish scope, and determine whether incident response is required."
severity: "high"
mitre_attack:
  - "T1566.001"
triggers:
  - "Malicious attachment detection"
  - "Suspicious email attachment reported by a user"
  - "Endpoint alert associated with an email attachment"
  - "Suspicious document or archive delivered by email"
  - "Threat intelligence identifies a malicious attachment hash"
prerequisites:
  - "Access to email security telemetry"
  - "Access to message headers and attachment metadata"
  - "Access to endpoint process and file telemetry"
  - "Access to malware analysis capabilities where authorized"
tags:
  - "malicious-attachment"
  - "initial-access"
  - "phishing"
  - "email"
  - "malware"
  - "triage"
references:
  - "https://attack.mitre.org/techniques/T1566/001/"
steps:
- id: "identify-alert"
  order: 1
  name: "Identify Attachment Alert"
  action: "investigate"
  description: "Identify the detection source, affected recipient, message timestamp, and attachment involved."
  expected_result: "The suspicious attachment and affected recipient are identified."
- id: "collect-attachment-metadata"
  order: 2
  name: "Collect Attachment Metadata"
  action: "analyze"
  description: "Collect the attachment filename, type, size, hash, and delivery information."
  expected_result: "The attachment metadata is documented."
- id: "review-message-context"
  order: 3
  name: "Review Message Context"
  action: "analyze"
  description: "Review sender, recipient, subject, headers, authentication results, and message content."
  expected_result: "The email delivery context and sender legitimacy are assessed."
- id: "analyze-attachment"
  order: 4
  name: "Analyze Attachment"
  action: "analyze"
  description: "Assess the attachment for suspicious content, embedded objects, macros, scripts, links, or other malicious indicators."
  expected_result: "Relevant attachment characteristics and indicators are identified."
- id: "review-recipient-activity"
  order: 5
  name: "Review Recipient Activity"
  action: "investigate"
  description: "Determine whether the recipient opened, downloaded, extracted, or executed the attachment."
  expected_result: "Recipient interaction with the attachment is established."
- id: "review-endpoint-activity"
  order: 6
  name: "Review Endpoint Activity"
  action: "analyze"
  description: "Review process creation, file activity, command lines, network connections, and endpoint detections following attachment interaction."
  expected_result: "Potential endpoint impact is identified or ruled out."
- id: "determine-scope"
  order: 7
  name: "Determine Campaign Scope"
  action: "hunt"
  description: "Search for the same attachment hash, filename, sender, subject, or message pattern across the environment."
  expected_result: "Affected recipients, hosts, and related messages are identified."
- id: "determine-outcome"
  order: 8
  name: "Determine Investigation Outcome"
  action: "document"
  description: "Classify the attachment and document the evidence supporting the final assessment."
  expected_result: "The alert receives a documented investigation outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "malicious-attachment"
---

# Malicious Attachment

## Purpose

This playbook provides a structured workflow for investigating suspicious or malicious email attachments.

The objective is to determine whether the attachment represents a malicious delivery mechanism, establish whether the recipient interacted with it, identify any resulting endpoint activity, and determine the scope of the event.

## MITRE ATT&CK

| Technique | Name                               | Relevance                                                                                   |
| --------- | ---------------------------------- | ------------------------------------------------------------------------------------------- |
| T1566.001 | Phishing: Spearphishing Attachment | Relevant when an adversary uses a malicious or suspicious attachment to gain initial access |

Additional ATT&CK techniques should only be mapped when supported by the observed attachment or post-delivery behavior.

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- A malicious attachment detection is generated.
- A user reports a suspicious attachment.
- An email security product identifies a suspicious attachment.
- An endpoint alert is associated with an email-delivered file.
- A suspicious document, archive, script, or executable is delivered by email.
- Threat intelligence identifies a malicious attachment hash.

## Scope

The investigation should consider:

- sender;
- recipient;
- subject;
- message headers;
- attachment filename;
- attachment type;
- attachment size;
- attachment hash;
- message timestamp;
- delivery status;
- recipient interaction;
- downloaded files;
- extracted files;
- child processes;
- command line;
- network connections;
- endpoint detections;
- related recipients;
- related hosts.

## Triage Procedure

### Step 1 — Identify the Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected recipient;
- message identifier;
- attachment identifier;
- detection severity.

Preserve the original alert and message context before making remediation changes.

### Step 2 — Collect Attachment Metadata

Collect:

- filename;
- file extension;
- MIME type where available;
- file size;
- SHA-256 hash;
- creation or delivery timestamp;
- archive contents where appropriate;
- digital signature where applicable.

Record the metadata before opening or executing the attachment.

### Step 3 — Review Message Context

Review:

- sender address;
- display name;
- reply-to address;
- recipient;
- subject;
- message headers;
- sender authentication results;
- message content;
- delivery path.

Determine whether the message is consistent with legitimate business communication.

### Step 4 — Analyze the Attachment

Assess the attachment for:

- macros;
- embedded scripts;
- embedded objects;
- suspicious hyperlinks;
- unusual file types;
- executable content;
- archive nesting;
- obfuscated content;
- suspicious metadata.

Use approved malware-analysis or sandboxing capabilities when required.

Do not execute suspicious attachments on production systems.

### Step 5 — Review Recipient Activity

Determine whether the recipient:

- opened the attachment;
- downloaded it;
- extracted archive contents;
- enabled active content;
- executed a file;
- followed an embedded link.

Establish the event sequence and timestamps where telemetry is available.

### Step 6 — Review Endpoint Activity

When interaction occurred, investigate:

- process creation;
- parent-child process relationships;
- command lines;
- file creation;
- script execution;
- browser activity;
- network connections;
- endpoint detections.

Pay particular attention to unexpected processes launched after the attachment was opened.

### Step 7 — Determine Campaign Scope

Search across the environment for:

- attachment SHA-256 hash;
- filename;
- sender address;
- sender domain;
- subject;
- message ID;
- related URLs;
- related message content.

Determine:

- number of recipients;
- number of affected hosts;
- number of users who interacted;
- first observed activity;
- latest observed activity.

### Step 8 — Determine Investigation Outcome

Classify the attachment as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the outcome.

## Evidence to Collect

| Evidence      | Description                                 |
| ------------- | ------------------------------------------- |
| Alert         | Detection source, ID, severity, timestamp   |
| Sender        | Sender address and domain                   |
| Recipient     | Affected recipient                          |
| Subject       | Email subject                               |
| Headers       | Relevant email headers                      |
| Attachment    | Filename, type, and size                    |
| Hash          | SHA-256 or available file hash              |
| Content       | Embedded objects, macros, scripts, or links |
| Delivery      | Message delivery information                |
| User Activity | Recipient interaction with attachment       |
| Endpoint      | Related process and file activity           |
| Network       | Related network connections                 |
| Scope         | Other affected recipients and hosts         |
| Detections    | Related security alerts                     |

## Decision Criteria

### Benign

Classify the attachment as **benign** when:

- the sender is legitimate;
- the attachment is expected;
- the file type and content are consistent with normal business activity;
- the attachment is associated with approved software or documents;
- no suspicious endpoint or network activity is identified.

Document the business justification before closing the alert.

### Suspicious

Classify the attachment as **suspicious** when:

- the sender or message context is unusual;
- the attachment origin cannot be confidently established;
- the file contains suspicious characteristics;
- the recipient interacted with the attachment;
- endpoint telemetry is incomplete;
- additional analysis is required.

Continue investigation and correlate additional evidence.

### Malicious

Classify the attachment as **malicious** when sufficient evidence indicates:

- confirmed malicious content;
- confirmed malware delivery;
- malicious executable or script execution;
- malicious post-delivery endpoint activity;
- confirmed malicious infrastructure associated with the attachment;
- multiple users received the same confirmed malicious attachment.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the attachment is benign or malicious.

Document:

- evidence collected;
- evidence unavailable;
- additional analysis required.

## Escalation

Escalate the investigation when:

- the attachment was executed;
- malware is confirmed;
- credentials may have been exposed;
- multiple recipients are affected;
- endpoint compromise is suspected;
- malicious infrastructure is contacted;
- a privileged account interacted with the attachment;
- the affected system is business-critical.

## Response Guidance

For confirmed malicious attachments:

1. Preserve the original email and attachment evidence.
2. Identify all affected recipients.
3. Remove or quarantine the malicious message according to organizational procedures.
4. Investigate users who opened or executed the attachment.
5. Search for the attachment hash and related indicators across the environment.
6. Investigate related endpoint and authentication activity.
7. Follow account-containment procedures when credential compromise is suspected.
8. Escalate confirmed compromise to incident response.
9. Document the investigation timeline and remediation actions.

Do not delete relevant email, attachment, endpoint, or network evidence before required evidence preservation has been completed.

## Related Detection Rules

- `detection-rules/sigma/suspicious-login.yml`
- `detection-rules/sigma/sigma-powershell-exec.yml`
- `detection-rules/yara/malware-sample.yar`
- `detection-rules/yara/obfuscated-powershell.yar`
- `detection-rules/yara/yara-powershell-payload.yar`
- `detection-rules/suricata/network-alert.rules`

## Related Playbooks

- `playbooks/triage/phishing-alert-triage.md`
- `playbooks/triage/email-compromise-triage.md`
- `playbooks/triage/malware-detection-triage.md`
- `playbooks/triage/suspicious-file-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/initial-access/phishing.md`
- `playbooks/initial-access/application-consent-abuse.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`

## Validation

The playbook should be validated against approved phishing attachments, simulated email-delivery scenarios, endpoint telemetry, and controlled malware-analysis datasets.

Validation should confirm that:

- malicious attachments can be identified;
- attachment metadata can be collected;
- message context can be investigated;
- recipient interaction can be determined;
- endpoint activity can be correlated;
- campaign scope can be established;
- benign attachments can be distinguished from malicious attachments;
- escalation criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, security validation, controlled laboratory environments, and authorized testing only.

Suspicious attachments must be handled through approved analysis and evidence-preservation procedures. Do not execute unknown attachments on production systems.
