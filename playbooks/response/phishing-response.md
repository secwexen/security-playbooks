---
id: "phishing-response"
name: "Phishing Response"
category: "response"
status: "active"
version: "1.0.1"
author: "Secwexen"
created_at: "2026-11-20T09:37:00Z"
updated_at: "2026-11-24T11:52:00Z"
description: "Phishing Response provides a structured process for investigating phishing campaigns, identifying affected users and systems, containing malicious messages, mitigating compromised accounts, and preventing further unauthorized access."
objective: "Identify, investigate, contain, and remediate phishing incidents, determine the scope of affected users and resources, mitigate compromised credentials and sessions, remove malicious messages and payloads, and prevent further exploitation."
severity: "high"
mitre_attack:
  - "T1566"
  - "T1566.001"
  - "T1566.002"
  - "T1204.001"
  - "T1204.002"
triggers:
  - "User reports a suspicious email, attachment, link, or message"
  - "Email security gateway or SIEM detects a phishing message"
  - "A malicious URL, attachment, or sender domain is identified"
  - "A user clicks a suspicious link or opens a potentially malicious attachment"
  - "Credentials are submitted to a suspected phishing website"
  - "Unexpected authentication activity follows a suspected phishing incident"
  - "A compromised internal account sends suspicious messages to other users"
  - "A phishing campaign targets multiple organizational users"
prerequisites:
  - "Access to email security gateway and mail server telemetry"
  - "Access to email headers, message content, URL, and attachment analysis"
  - "Access to identity provider and authentication logs"
  - "Access to endpoint detection and response telemetry"
  - "Access to network, DNS, proxy, and firewall logs"
  - "Authorized email administration and account remediation capabilities"
  - "Established evidence preservation, containment, and incident escalation procedures"
tags:
  - "phishing"
  - "email-security"
  - "incident-response"
  - "credential-compromise"
  - "malicious-email"
  - "containment"
  - "eradication"
  - "identity-security"
references:
  - "https://attack.mitre.org/techniques/T1566/"
  - "https://attack.mitre.org/techniques/T1566/001/"
  - "https://attack.mitre.org/techniques/T1566/002/"
  - "https://attack.mitre.org/techniques/T1204/001/"
  - "https://attack.mitre.org/techniques/T1204/002/"
steps:
  - id: "identify-phishing-alert"
    order: 1
    name: "Identify Phishing Alert"
    action: "investigate"
    description: "Identify the detection source, affected recipient, sender, subject, message timestamp, suspected phishing type, and original alert context."
    expected_result: "The suspected phishing message and initial incident context are identified."
  - id: "analyze-phishing-message"
    order: 2
    name: "Analyze Phishing Message"
    action: "analyze"
    description: "Examine email headers, sender information, authentication results, message content, embedded URLs, attachments, domains, and relevant indicators. Determine whether the message is spoofed, malicious, or legitimate."
    expected_result: "The phishing message is analyzed and relevant malicious indicators are documented."
  - id: "investigate-user-interaction"
    order: 3
    name: "Investigate User Interaction"
    action: "investigate"
    description: "Determine whether recipients opened the message, clicked links, downloaded attachments, executed files, submitted credentials, or approved authentication requests. Correlate user activity with endpoint, browser, and identity telemetry."
    expected_result: "Affected users and their interaction with the phishing message are identified."
  - id: "investigate-compromise"
    order: 4
    name: "Investigate Related Compromise"
    action: "analyze"
    description: "Review authentication activity, suspicious sessions, mailbox rules, forwarding configurations, OAuth permissions, account modifications, endpoint execution, and network activity. Determine whether credentials, accounts, or systems were compromised."
    expected_result: "Potential account compromise, malicious execution, and related unauthorized activity are established."
  - id: "assess-campaign-scope"
    order: 5
    name: "Assess Phishing Campaign Scope"
    action: "investigate"
    description: "Search email systems and security telemetry for matching sender addresses, domains, URLs, attachment hashes, subjects, message identifiers, and related indicators. Identify additional recipients, compromised accounts, and affected systems."
    expected_result: "The scope of the phishing campaign and affected organizational resources are identified."
  - id: "contain-phishing-threat"
    order: 6
    name: "Contain Phishing Threat"
    action: "contain"
    description: "Preserve relevant evidence and apply approved containment measures. Quarantine or remove confirmed malicious messages, block malicious indicators, restrict compromised accounts, revoke suspicious sessions, and prevent further delivery or interaction."
    expected_result: "The phishing campaign is contained and affected users, accounts, and resources are protected."
  - id: "remediate-and-recover"
    order: 7
    name: "Remediate and Recover"
    action: "respond"
    description: "Reset compromised credentials, revoke exposed tokens, remove unauthorized mailbox rules and permissions, investigate and remediate malicious attachments or executed payloads, restore affected systems, and address the initial compromise path."
    expected_result: "Confirmed phishing-related compromise is remediated and affected accounts and systems are restored."
  - id: "determine-response-outcome"
    order: 8
    name: "Determine Response Outcome"
    action: "document"
    description: "Validate message removal, account security, session revocation, endpoint remediation, and the absence of further malicious activity. Classify the incident, document response actions, and record residual risks and follow-up requirements."
    expected_result: "The phishing incident is assessed, remediation is validated, and the response outcome is documented."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "Controlled phishing-response exercise using approved simulation messages, test identities, benign attachments and URLs, email security telemetry, identity logs, endpoint monitoring, evidence preservation, containment, and recovery procedures."
---

# Phishing Response

## Purpose

This playbook provides a structured response workflow for suspected or confirmed phishing incidents across organizational email systems, collaboration platforms, endpoints, and identity environments.

Phishing is a social engineering technique used to deceive users into disclosing sensitive information, opening malicious attachments, visiting malicious websites, or approving unauthorized authentication requests.

Successful phishing attacks can result in credential theft, account compromise, malware execution, unauthorized access, and further activity within the affected environment.

## MITRE ATT&CK

| Technique | Name                     | Relevance                                                              |
| --------- | ------------------------ | ---------------------------------------------------------------------- |
| T1566     | Phishing                 | Covers phishing activity used to obtain initial access                 |
| T1566.001 | Spearphishing Attachment | Relevant when malicious files are delivered through targeted messages  |
| T1566.002 | Spearphishing Link       | Relevant when messages contain links to malicious websites or payloads |
| T1204.001 | Malicious Link           | Relevant when a user interacts with a malicious link                   |
| T1204.002 | Malicious File           | Relevant when a user opens or executes a malicious file                |

## Trigger Conditions

Initiate this playbook when:

- A user reports a suspicious email or message.
- An email security gateway detects a phishing attempt.
- A suspicious sender, domain, URL, or attachment is identified.
- A user clicks a suspicious link or opens an unexpected attachment.
- Credentials are submitted to a suspected phishing website.
- Suspicious authentication activity follows a phishing incident.
- An internal account sends unexpected messages to other employees.
- Multiple users receive messages associated with the same phishing campaign.
- A suspicious email results in unauthorized account or application access.

## Scope

The investigation should consider:

- sender email address and display name;
- sender domain and originating IP address;
- recipient addresses;
- email subject and message identifier;
- email headers and authentication results;
- SPF, DKIM, and DMARC results;
- embedded URLs and redirect destinations;
- attachment names, types, hashes, and signatures;
- email delivery and quarantine status;
- number of affected recipients;
- message opening and link-click activity;
- attachment downloads and execution;
- credential submission activity;
- authentication and session activity;
- mailbox forwarding rules and inbox rules;
- OAuth applications and delegated permissions;
- account and privilege modifications;
- endpoint and browser activity;
- DNS, proxy, and network connections;
- malicious domains and infrastructure;
- related phishing messages and campaigns;
- containment and remediation status.

## Investigation Procedure

### Step 1 - Identify Phishing Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected recipient;
- sender address;
- email subject;
- message identifier;
- suspected phishing type;
- detection reason;
- original alert context.

Preserve the original email and associated security telemetry.

When available, retain the original message in its native format, including full email headers and attachments.

### Step 2 - Analyze Phishing Message

Examine the suspicious message and identify indicators of malicious activity.

Review:

- sender address and display name;
- sender domain;
- originating mail server information;
- email authentication results;
- SPF, DKIM, and DMARC results;
- Return-Path and Reply-To fields;
- Received headers;
- message subject and content;
- embedded hyperlinks;
- URL redirect chains;
- attachment names and file types;
- attachment hashes;
- suspicious HTML and scripts;
- impersonated organizations and individuals;
- unusual requests for credentials or payments.

Use approved email and malware analysis tools to examine suspicious attachments and URLs.

Do not treat a successful SPF, DKIM, or DMARC result as proof that a message is safe. A legitimate sender account or domain may itself be compromised.

Determine whether the message is:

- sender spoofing;
- impersonation;
- malicious attachment delivery;
- malicious link delivery;
- credential harvesting;
- business email compromise;
- internal phishing;
- legitimate but suspicious communication.

Document all confirmed indicators of compromise.

### Step 3 - Investigate User Interaction

Determine which recipients interacted with the phishing message.

Review:

- message delivery records;
- message read or access events, where available;
- URL click telemetry;
- browser history and security logs;
- attachment download activity;
- file creation events;
- process execution records;
- endpoint security detections;
- authentication events;
- reported credential submissions;
- MFA approval activity.

Determine whether users:

- received the message;
- opened the message;
- clicked embedded links;
- visited suspicious websites;
- downloaded attachments;
- opened or executed downloaded files;
- entered credentials;
- approved unexpected authentication requests;
- provided sensitive information;
- performed requested financial or administrative actions.

Correlate user interaction timestamps with endpoint, network, and identity telemetry.

A delivered or opened message alone does not establish account or endpoint compromise.

### Step 4 - Investigate Related Compromise

Determine whether the phishing attempt resulted in unauthorized access or execution.

Review:

- successful and failed authentication events;
- unusual login locations and IP addresses;
- unfamiliar devices and browser sessions;
- suspicious MFA activity;
- session token usage;
- mailbox inbox and forwarding rules;
- automatic forwarding configurations;
- suspicious OAuth applications;
- delegated mailbox permissions;
- unauthorized account modifications;
- password and authentication changes;
- suspicious email-sending activity;
- endpoint process execution;
- downloaded files and malware detections;
- suspicious DNS and network connections;
- activity involving other organizational accounts.

Investigate whether compromised accounts were used to send additional phishing messages.

Determine whether the incident resulted in:

- credential compromise;
- unauthorized mailbox access;
- unauthorized application access;
- malicious file execution;
- malware infection;
- unauthorized data access;
- business email compromise;
- internal phishing activity.

Document the evidence supporting each finding.

### Step 5 - Assess Phishing Campaign Scope

Search the environment for matching phishing indicators.

Review:

- sender addresses;
- sender domains;
- message identifiers;
- email subjects;
- attachment filenames;
- attachment hashes;
- embedded URLs;
- redirect domains;
- originating IP addresses;
- suspicious email templates;
- related authentication activity;
- similar user reports;
- internal messages sent from compromised accounts.

Identify:

- total messages delivered;
- total recipients targeted;
- messages quarantined or rejected;
- users who interacted with the message;
- users who submitted credentials;
- accounts with suspicious authentication activity;
- endpoints with downloaded or executed payloads;
- additional phishing messages;
- related compromised identities.

Determine whether the campaign is isolated or part of a broader attack.

Document systems and identities that could not be examined.

### Step 6 - Contain Phishing Threat

Based on incident severity and organizational procedures, consider:

- preserving original messages and headers;
- quarantining confirmed malicious messages;
- removing malicious messages from recipient mailboxes;
- blocking malicious sender addresses and domains;
- blocking malicious URLs;
- restricting malicious attachments;
- preventing further email delivery;
- disabling or restricting compromised accounts;
- revoking active sessions and refresh tokens;
- blocking unauthorized OAuth applications;
- restricting suspicious mailbox forwarding;
- coordinating with affected users and administrators.

If an internal account is compromised, investigate and contain its outbound messaging activity to prevent further phishing distribution.

Preserve relevant evidence before deleting messages or modifying account configurations, unless immediate containment is necessary to prevent ongoing material impact.

### Step 7 - Remediate and Recover

Address confirmed phishing-related compromise.

Review for:

- compromised user credentials;
- exposed authentication tokens;
- unauthorized mailbox rules;
- malicious forwarding configurations;
- unauthorized delegated permissions;
- suspicious OAuth grants;
- unauthorized MFA changes;
- malicious attachments and downloaded files;
- executed malware;
- unauthorized endpoint modifications;
- suspicious browser extensions;
- unauthorized remote-access configurations;
- secondary phishing activity.

Perform the following actions where applicable:

- Reset compromised passwords.
- Revoke active sessions and exposed refresh tokens.
- Secure compromised authentication methods.
- Remove unauthorized mailbox rules and forwarding configurations.
- Revoke malicious OAuth grants and application permissions.
- Remove confirmed malicious messages from affected mailboxes.
- Quarantine or remove malicious attachments.
- Isolate and remediate infected endpoints.
- Rebuild affected systems when integrity cannot be established.
- Remediate the initial compromise path.

If financial information or payment instructions were involved, coordinate with finance and relevant fraud-response personnel.

Restore affected accounts and systems using approved recovery procedures.

### Step 8 - Determine Response Outcome

Classify the incident as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Close the incident only when required response activities have been completed or outstanding risks have been formally accepted and documented.

## Evidence to Collect

| Evidence       | Description                                                             |
| -------------- | ----------------------------------------------------------------------- |
| Alert          | Detection source, alert ID, severity, timestamp                         |
| Email          | Original message, sender, recipients, subject, message ID               |
| Headers        | Received headers, Return-Path, Reply-To, authentication results         |
| Authentication | SPF, DKIM, DMARC results                                                |
| URL            | Embedded links, redirect chains, destination domains                    |
| Attachment     | Filename, file type, hash, signature, analysis results                  |
| User Activity  | Message access, link clicks, downloads, credential submission           |
| Endpoint       | File creation, process execution, browser activity, EDR detections      |
| Identity       | Authentication events, sessions, tokens, MFA activity                   |
| Mailbox        | Inbox rules, forwarding configurations, delegated permissions           |
| Application    | OAuth grants, application permissions, suspicious integrations          |
| Network        | DNS, proxy, firewall, HTTP/HTTPS activity                               |
| Campaign       | Matching senders, subjects, URLs, hashes, recipients                    |
| Response       | Quarantine, message removal, account restrictions, remediation          |
| Timeline       | Delivery, interaction, compromise, containment, and recovery timestamps |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the message is associated with a verified legitimate sender;
- sender and message characteristics are consistent with expected communication;
- embedded links and attachments are verified as legitimate;
- no malicious behavior or unauthorized access is identified;
- the communication has a documented operational purpose.

Do not classify a message as benign solely because its sender domain passes SPF, DKIM, or DMARC validation.

### Suspicious

Classify the activity as **suspicious** when:

- sender identity cannot be verified;
- the message contains unexpected links or attachments;
- the message uses unusual urgency or impersonation;
- URL destinations cannot be established;
- authentication activity is abnormal;
- the message resembles a known phishing campaign;
- available telemetry is insufficient to establish whether compromise occurred.

Continue investigation and assess the need for containment.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- the message contains confirmed malicious URLs or attachments;
- the message is part of a confirmed phishing campaign;
- credentials were collected through a fraudulent website;
- unauthorized account access occurred;
- a malicious attachment was executed;
- malware was delivered through the message;
- a compromised account was used for internal phishing;
- unauthorized mailbox rules or application permissions were created;
- sensitive information was disclosed through phishing.

Escalate to the appropriate incident-response workflow and complete containment, remediation, and recovery procedures.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to determine whether the message or related activity is malicious.

Document:

- evidence collected;
- evidence unavailable;
- missing email or endpoint telemetry;
- authentication log limitations;
- affected users that could not be examined;
- additional investigation requirements;
- pending containment and remediation actions.

## Escalation

Escalate the investigation when:

- credential theft is confirmed;
- privileged or administrative accounts are affected;
- multiple organizational users are targeted;
- unauthorized mailbox access is identified;
- internal phishing activity is detected;
- malware execution is confirmed;
- sensitive information may have been disclosed;
- financial fraud or payment manipulation is suspected;
- OAuth applications or identity permissions are abused;
- phishing activity results in lateral movement;
- unauthorized access continues after initial containment.

## Response Guidance

For confirmed malicious phishing incidents:

1. Preserve the original email, headers, attachments, and related telemetry.
2. Identify malicious senders, URLs, attachments, and campaign indicators.
3. Determine which users received and interacted with the message.
4. Establish whether credentials or sensitive information were disclosed.
5. Investigate potentially compromised accounts and endpoints.
6. Search for additional recipients and related phishing messages.
7. Quarantine or remove confirmed malicious messages.
8. Block confirmed malicious indicators through approved security controls.
9. Reset compromised credentials and revoke exposed sessions and tokens.
10. Remove unauthorized mailbox rules, forwarding configurations, and application permissions.
11. Investigate and remediate malicious endpoint activity.
12. Validate account security and monitor for recurring phishing activity.
13. Document the incident classification and final response outcome.

Do not assume that deleting a phishing email resolves the incident. Investigate whether users interacted with the message and whether credentials, accounts, or endpoints were compromised.

## Related Playbooks

- `playbooks/initial-access/phishing.md`
- `playbooks/credential-access/credential-dumping.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/malware-response.md`
- `playbooks/response/persistence-removal-response.md`
- `playbooks/identity/account-compromise-response.md`

## Validation

The playbook should be validated against controlled phishing-response scenarios using approved simulation messages, test identities, benign attachments and URLs, email security telemetry, and documented containment and recovery procedures.

Validation should confirm that:

- phishing messages can be identified and investigated;
- email headers and authentication results can be analyzed;
- malicious URLs and attachments can be identified;
- affected recipients can be established;
- user interaction can be reconstructed;
- credential compromise can be investigated;
- suspicious authentication and mailbox activity can be identified;
- phishing campaign scope can be determined;
- evidence can be preserved before remediation;
- malicious messages can be quarantined or removed;
- compromised accounts and sessions can be secured;
- affected endpoints can be investigated and recovered;
- remediation results can be validated;
- phishing recurrence can be detected.

## Safety

This playbook is intended for defensive security operations, incident response, controlled phishing simulations, and authorized security testing only.

Use approved simulation messages, benign attachments, and controlled test identities during validation.

Analyze suspicious attachments and URLs using approved isolated analysis environments. Do not open potentially malicious content on production systems.
