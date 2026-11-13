---
id: "business-email-compromise-response"
name: "Business Email Compromise Response"
category: "response"
status: "active"
version: "1.0.2"
author: "Secwexen"
created_at: "2026-10-31T19:01:00Z"
updated_at: "2026-11-13T13:33:00Z"
description: "Business Email Compromise (BEC) is a social-engineering and email-fraud attack in which an adversary impersonates a trusted person or organization, or abuses a compromised email account, to induce unauthorized payments, disclosure of sensitive information, or other business actions."
objective: "Identify, investigate, contain, and remediate suspected or confirmed BEC activity; determine whether email accounts or business processes were abused; limit financial and data loss; and identify related compromise activity across the organization and its external contacts."
severity: "high"
mitre_attack:
  - "T1656"
  - "T1657"
triggers:
  - "An employee reports a suspicious payment, invoice, payroll, or bank-account change request"
  - "An email impersonates an executive, employee, supplier, customer, or other trusted business contact"
  - "A message requests an urgent or unusual transfer of funds, gift cards, credentials, or sensitive information"
  - "A supplier or customer reports receiving suspicious messages from an organizational email account"
  - "Unexpected mailbox access, sign-in activity, MFA changes, or authentication from an unusual source is detected"
  - "Unexpected inbox rules, forwarding settings, mailbox delegates, or OAuth application permissions are identified"
  - "Outbound email activity indicates possible mailbox abuse, thread hijacking, or internal spearphishing"
  - "Email security, identity protection, SIEM, or user reporting indicates suspected BEC or email fraud"
  - "A payment recipient or bank-account detail is changed outside the established verification process"
prerequisites:
  - "Access to email security, message trace, mail-flow, and message-header telemetry"
  - "Access to mailbox audit logs and email administration capabilities"
  - "Access to identity-provider, authentication, MFA, and session telemetry"
  - "Access to endpoint, DNS, proxy, and network telemetry where applicable"
  - "Access to approved financial, procurement, payroll, and payment-verification procedures"
  - "Authorized contacts and escalation procedures for finance, legal, privacy, banking, and external partners"
  - "Authorized access to quarantine, message search and purge, session revocation, and mailbox-containment capabilities"
tags:
  - "business-email-compromise"
  - "bec"
  - "email-security"
  - "email-fraud"
  - "impersonation"
  - "phishing"
  - "mailbox-compromise"
  - "financial-fraud"
  - "incident-response"
  - "identity-security"
  - "mitre-attack"
references:
  - "https://attack.mitre.org/techniques/T1656/"
  - "https://attack.mitre.org/techniques/T1567/"
  - "https://www.cyber.gov.au/guidance/recover-from-business-email-compromise"
steps:
  - id: "identify-bec-alert"
    order: 1
    name: "Identify Business Email Compromise Alert"
    action: "investigate"
    description: "Identify the detection or reporting source, affected sender and recipient, message subject and timestamp, sender and reply-to addresses, message identifier, requested business action, and initial financial or data-loss context. Preserve the original alert and reported message details before modifying mailbox or email-security state."
    expected_result: "The suspected BEC event, involved identities, message, business process, and initial impact are identified."
  - id: "preserve-and-analyze-message"
    order: 2
    name: "Preserve and Analyze Email Evidence"
    action: "analyze"
    description: "Preserve the original message in an appropriate native format with complete headers, attachments, URLs, and available delivery metadata. Examine sender, reply-to, return-path, envelope sender, message ID, received headers, sending infrastructure, SPF, DKIM, and DMARC results. Assess display-name and domain similarity, reply-chain manipulation, suspicious links or attachments, and message trace information. Do not open suspicious attachments or visit links outside an approved analysis environment."
    expected_result: "The message's origin, authenticity indicators, delivery path, content, and likely impersonation or compromise method are assessed with evidence preserved."
  - id: "validate-request-and-user-impact"
    order: 3
    name: "Validate Business Request and User Impact"
    action: "validate"
    description: "Determine whether the requested payment, bank-detail change, payroll update, purchase, data disclosure, or other business action is legitimate. Verify the request through a previously established and independently trusted contact method; do not use phone numbers, links, or contact details supplied in the suspicious message. Establish whether recipients replied, clicked links, opened attachments, submitted credentials, approved MFA prompts, disclosed information, changed payment details, or initiated a transaction."
    expected_result: "The legitimacy of the request and the actions taken by affected personnel are established or explicitly recorded as unknown."
  - id: "investigate-mailbox-and-identity"
    order: 4
    name: "Investigate Mailbox and Identity Activity"
    action: "analyze"
    description: "For potentially compromised organizational accounts, review successful and failed sign-ins, source addresses, devices, authentication methods, MFA events, session activity, password and recovery changes, OAuth application consent, app passwords, mailbox access, inbox and forwarding rules, transport rules, delegates, Send As, and Send on Behalf permissions. Correlate mailbox activity with sent, deleted, moved, and accessed messages, including suspicious activity in existing email threads. Distinguish external sender spoofing from actual compromise of an internal or partner mailbox."
    expected_result: "Compromised identities, unauthorized mailbox changes, suspicious sessions, and persistence mechanisms are identified or reasonably excluded."
  - id: "determine-scope-and-impact"
    order: 5
    name: "Determine Compromise Scope and Business Impact"
    action: "hunt"
    description: "Search mail-flow and security telemetry for copies of the message, related sender domains and addresses, similar subjects, URLs, attachment hashes, recipients, outbound messages, thread hijacking, and additional affected mailboxes. Correlate recipient click activity with browser, DNS, proxy, endpoint, identity, and authentication events. Determine whether credentials or tokens were exposed, whether internal spearphishing occurred, whether sensitive information was accessed or disclosed, and whether a payment or bank-detail change was submitted, processed, or settled. Identify affected employees, customers, suppliers, systems, accounts, and external organizations."
    expected_result: "The affected users, mailboxes, messages, systems, external contacts, financial exposure, data exposure, and ongoing attack paths are scoped."
  - id: "contain-bec-activity"
    order: 6
    name: "Contain Business Email Compromise Activity"
    action: "contain"
    description: "Apply approved containment measures based on the findings. Quarantine or remove malicious messages after required evidence preservation; block confirmed malicious sender infrastructure, URLs, and attachment indicators using appropriately scoped controls; and notify affected recipients through trusted channels. For compromised accounts, reset credentials, revoke sessions and refresh tokens where supported, remove unauthorized authentication methods and OAuth grants, disable malicious forwarding rules and delegates, and temporarily restrict the account when necessary. Coordinate immediately with finance and the relevant financial institution through verified contact channels when funds may have been transferred; request a stop, recall, or fraud investigation where available. Pause or independently re-verify affected payments and vendor or payroll changes."
    expected_result: "Known malicious messages and unauthorized access paths are contained, and urgent financial or operational loss-mitigation actions are initiated."
  - id: "eradicate-and-recover"
    order: 7
    name: "Eradicate and Recover"
    action: "respond"
    description: "Remove unauthorized mailbox rules, forwarding destinations, delegates, application grants, authentication factors, and other persistence mechanisms. Address compromised endpoints or credential-theft activity where identified. Restore affected accounts and business workflows only after identity, mailbox, endpoint, and payment controls have been reviewed. Verify trusted MFA enrollment, session state, recovery information, mailbox permissions, forwarding configuration, mail-flow protections, and account privileges. Reconcile payment and bank-detail changes with verified counterparties, notify affected customers or suppliers through approved channels, and implement additional monitoring for related messages and access attempts."
    expected_result: "Affected identities and business processes are restored to an authorized state, unauthorized access mechanisms are removed, and recovery actions are verified."
  - id: "determine-bec-outcome"
    order: 8
    name: "Determine Response Outcome"
    action: "document"
    description: "Classify the event, document the evidence and timeline, identify affected users and external parties, record financial and data impact, and summarize containment, eradication, recovery, notification, and follow-up actions. Record whether the event involved sender spoofing, social-engineering impersonation, a compromised mailbox, credential theft, payment diversion, or a combination of these behaviors."
    expected_result: "The BEC incident receives a documented classification, impact assessment, response outcome, and tracked follow-up requirements."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "business-email-compromise-response"
---

# Business Email Compromise Response

## Purpose

This playbook provides a structured response workflow for suspected or confirmed Business Email Compromise (BEC), including executive impersonation, supplier or customer impersonation, invoice and payment diversion, payroll redirection, thread hijacking, and abuse of compromised organizational mailboxes.

BEC is a form of social engineering and email fraud in which an adversary impersonates a trusted person or organization, or uses a compromised email account, to persuade a victim to transfer funds, change payment details, disclose sensitive information, or perform another unauthorized business action. A BEC incident may involve domain or display-name spoofing without compromising an organizational account; it may also involve the takeover of a legitimate mailbox and abuse of its trusted relationships.

## MITRE ATT&CK

| Technique | Name            | Relevance                                                                                                                                                                      |
| --------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| T1656     | Impersonation   | Directly relevant when an adversary impersonates an executive, employee, supplier, customer, or trusted organization to induce a business action or financial transfer.        |
| T1657     | Financial Theft | Directly relevant when an adversary uses business email compromise, fraudulent payment instructions, invoice manipulation, or social engineering to steal financial resources. |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- An employee reports an unusual or suspicious request for a payment, invoice settlement, payroll change, or bank-account update.
- An email impersonates an executive, employee, supplier, customer, legal representative, or other trusted business contact.
- A message requests an urgent transfer of funds, purchase of gift cards, disclosure of credentials, or release of sensitive information.
- A supplier, customer, or business partner reports receiving suspicious messages from an organizational email address.
- A message appears to continue a legitimate email conversation but contains an unexpected payment instruction, attachment, link, or change of recipient bank details.
- An identity or email-security alert indicates unusual mailbox access, suspicious sign-in activity, unauthorized forwarding, or unexpected outbound messages.
- Unexpected inbox rules, forwarding settings, delegates, Send As permissions, or OAuth application permissions are identified.
- A payment or payroll destination is changed without following the organization's established independent verification procedure.
- Threat hunting identifies suspicious email patterns, sender-domain lookalikes, thread hijacking, or internal messages sent from a potentially compromised account.

## Scope

The investigation should consider:

- affected sender and recipient addresses;
- sender display name and sending domain;
- reply-to address and return-path;
- source IP address and mail infrastructure;
- message ID and complete email headers;
- message subject, body, attachments, and URLs;
- SPF, DKIM, and DMARC results;
- email gateway and message trace data;
- affected mailbox and account type;
- authentication method and sign-in context;
- MFA activity and active sessions;
- OAuth applications and consent grants;
- inbox, forwarding, and transport rules;
- mailbox delegates and Send As or Send on Behalf permissions;
- sent, received, deleted, moved, and accessed messages;
- internal and external recipients;
- clicked links and opened attachments;
- endpoint, browser, DNS, and proxy activity;
- payment instructions and bank-account details;
- transaction status and potential financial loss;
- personal, financial, or confidential information exposed;
- affected employees, customers, suppliers, and partner organizations;
- related alerts, accounts, hosts, and incidents.

## Investigation Procedure

### Step 1 - Identify Business Email Compromise Alert

Determine:

- detection or reporting source;
- alert identifier and severity;
- detection or report timestamp;
- affected sender and recipient addresses;
- sender display name and domain;
- reply-to address and return-path;
- email subject and message ID;
- affected mailbox, user, or business unit;
- requested payment, account change, or other business action;
- known financial or data-loss context;
- initial reason for suspecting BEC.

Preserve the original alert and reported message details before quarantining, deleting, modifying, or otherwise changing the relevant email or mailbox state. Record the reporting employee and the method through which the message was received.

### Step 2 - Preserve and Analyze Email Evidence

Preserve the original message in an appropriate native format, such as `.eml` or `.msg`, including complete headers, attachments, URLs, and available delivery metadata.

Review:

- `From`, `Reply-To`, and `Return-Path` values;
- envelope sender and actual sending infrastructure;
- complete `Received` header chain;
- message ID and timestamp information;
- SPF, DKIM, and DMARC authentication results;
- sender-domain spelling and lookalike characteristics;
- display-name and domain inconsistencies;
- unexpected reply-chain or conversation changes;
- suspicious URLs, redirects, and attachments;
- mail gateway verdicts and message trace information;
- whether the message was delivered, quarantined, forwarded, or re-sent.

Determine whether the message was sent from an external spoofed domain, a lookalike domain, a compromised external account, or a potentially compromised organizational mailbox.

### Step 3 - Validate Business Request and User Impact

Determine whether the requested business action is legitimate and whether any user acted on the message.

Review:

- whether the payment, invoice, purchase, or payroll event is expected;
- whether the sender is an established business contact;
- whether bank details or payment instructions changed;
- whether the request follows approved procurement or finance procedures;
- whether the message introduces unusual urgency, secrecy, or process exceptions;
- whether the recipient replied or provided information;
- whether the recipient clicked a link or opened an attachment;
- whether credentials were entered or MFA prompts were approved;
- whether payment information was changed in a business system;
- whether a transfer was prepared, approved, submitted, or completed.

Verify requests for payment or account changes through a previously established and independently trusted contact method, such as a known telephone number or approved vendor contact record.

### Step 4 - Investigate Mailbox and Identity Activity

For potentially compromised internal or partner accounts, review identity and mailbox activity before and after the suspicious message was sent or received.

Review:

- successful and failed sign-in events;
- source IP addresses, devices, locations, and timestamps;
- authentication protocols and methods;
- MFA prompts, approvals, failures, and configuration changes;
- password resets and account-recovery changes;
- session creation, revocation, and token activity;
- OAuth application consent and connected applications;
- app passwords and other alternate authentication methods;
- inbox rules and automatic forwarding configuration;
- organization-level mail-flow or transport rules;
- mailbox delegates and Send As or Send on Behalf permissions;
- suspicious access to mailbox contents;
- sent, deleted, moved, and recoverable email items;
- unusual outbound messages and replies in existing conversations.

Determine whether an unauthorized user accessed the mailbox, modified its configuration, created persistence, monitored business communications, or used the account to send fraudulent messages.

### Step 5 - Determine Compromise Scope and Business Impact

Search the environment for related email, identity, endpoint, and financial activity.

Search for:

- identical or similar message subjects and bodies;
- sender addresses and lookalike domains;
- reply-to addresses and sending IP addresses;
- message IDs and related campaign identifiers;
- URLs, redirect destinations, and attachment hashes;
- other recipients of the same or similar messages;
- suspicious outbound messages from internal accounts;
- hijacked email threads and unusual reply patterns;
- unauthorized forwarding rules and mailbox delegates;
- suspicious OAuth grants and application access;
- related authentication and session activity;
- click events, browser activity, and endpoint execution;
- payment instructions and modified beneficiary details.

Determine:

- number of affected users and mailboxes;
- number of internal and external recipients;
- number of affected suppliers, customers, and partner organizations;
- earliest and latest known suspicious activity;
- whether an account or token was compromised;
- whether credentials or sensitive information were disclosed;
- whether malicious links or attachments were accessed;
- whether the adversary sent additional messages;
- whether payment or payroll changes were made;
- whether funds were transferred and whether recovery is possible;
- whether unauthorized access or fraud is ongoing.

Record confirmed impact separately from suspected or potential impact. Do not report a financial loss as confirmed unless the transaction or loss has been verified.

### Step 6 - Contain Business Email Compromise Activity

Based on incident severity, evidence, and organizational procedures, consider:

- preserving original messages, headers, logs, and mailbox audit data;
- quarantining or removing confirmed malicious messages from affected mailboxes;
- identifying and notifying all recipients through trusted communication channels;
- blocking confirmed malicious sender addresses, domains, URLs, and attachment indicators;
- resetting credentials for compromised accounts;
- revoking active sessions and authentication tokens where supported;
- removing unauthorized MFA methods and recovery options;
- revoking malicious OAuth application grants and connected applications;
- removing unauthorized inbox rules, forwarding destinations, and delegates;
- temporarily restricting or suspending a compromised mailbox when necessary;
- reviewing and restricting suspicious sign-in sources;
- pausing affected payments or payment-detail changes;
- requesting a payment stop, recall, or fraud investigation from the financial institution;
- notifying affected suppliers, customers, or partners using independently verified contact details.

Coordinate containment with identity-management, messaging, finance, legal, privacy, and incident-response functions as appropriate. Use approved financial-institution contact details, not information supplied by the suspected adversary.

### Step 7 - Eradicate and Recover

Determine and address the likely source and enabling conditions of the incident.

Review for:

- credential phishing or credential reuse;
- compromised internal or external mailboxes;
- stolen authentication tokens or session abuse;
- malicious OAuth applications or consent grants;
- unauthorized inbox or forwarding rules;
- unauthorized mailbox delegates and permissions;
- compromised endpoints or credential-stealing malware;
- malicious links and attachments;
- weak or bypassed payment-verification procedures;
- unauthorized changes to vendor, customer, or payroll records;
- additional accounts or business processes affected by the same campaign.

Restore affected accounts and business workflows only after required containment and validation actions are complete. Verify:

- compromised credentials have been reset or rotated;
- active sessions and applicable tokens have been revoked;
- MFA methods and recovery information are trusted;
- unauthorized OAuth grants and connected applications are removed;
- mailbox forwarding, inbox rules, and transport rules are legitimate;
- delegates and Send As permissions are authorized;
- mailbox access and account privileges are appropriate;
- affected endpoints are clean or have been remediated;
- business payment and vendor-change procedures are restored and independently verified;
- affected internal and external parties have received appropriate notifications;
- monitoring is in place for recurrence or related activity.

Coordinate financial recovery and external notifications with the appropriate finance, legal, privacy, and management functions. Preserve transaction records and communications that may be required for a financial institution, insurer, regulator, or law-enforcement report.

### Step 8 - Determine Response Outcome

Classify the incident as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification, whether an account was compromised, the business action requested, whether the request was acted upon, the confirmed or potential financial and data impact, and all containment, eradication, recovery, notification, and follow-up actions.

## Evidence to Collect

| Evidence              | Description                                                                                                 |
| --------------------- | ----------------------------------------------------------------------------------------------------------- |
| Alert                 | Detection source, alert ID, severity, timestamp, and initial context                                        |
| Original Message      | Native email file, complete headers, body, attachments, URLs, and message ID                                |
| Sender Identity       | Display name, sender address, reply-to, return-path, domain, and sending infrastructure                     |
| Email Authentication  | SPF, DKIM, DMARC, gateway verdicts, and authentication details                                              |
| Message Trace         | Delivery, routing, forwarding, quarantine, and recipient information                                        |
| Recipients            | Internal and external recipients, distribution lists, and affected contacts                                 |
| User Activity         | Replies, clicks, attachment access, credential submission, and reported actions                             |
| Mailbox Audit         | Mailbox access, sent items, deleted items, rule changes, and configuration activity                         |
| Identity              | Sign-ins, source IPs, devices, MFA activity, sessions, and credential changes                               |
| OAuth and Permissions | Connected applications, consent grants, delegates, and Send As permissions                                  |
| Forwarding and Rules  | Inbox rules, external forwarding, transport rules, and unauthorized destinations                            |
| Endpoint and Network  | Browser, process, DNS, proxy, and network telemetry associated with message interaction                     |
| Financial Activity    | Invoice, beneficiary, bank-detail changes, transaction ID, amount, currency, and payment status             |
| Business Process      | Procurement, vendor verification, payroll, approval, and payment records                                    |
| External Parties      | Supplier, customer, bank, partner, insurer, or law-enforcement communications where applicable              |
| Scope                 | Affected users, mailboxes, hosts, applications, systems, and external organizations                         |
| Timeline              | Message delivery, user interaction, authentication, mailbox changes, payment activity, and response actions |
| Related Detections    | SIEM, email-security, identity, endpoint, and fraud-monitoring alerts                                       |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- the sender and business request are independently verified as legitimate;
- the payment or account change follows established business procedures;
- message and authentication evidence do not indicate unauthorized access or malicious manipulation;
- recipients confirm the request through trusted channels;
- no unauthorized mailbox, identity, or financial activity is identified.

Document the independent verification and operational justification before closing the incident. Do not classify a request as benign only because its sender display name or email authentication checks appear valid.

### Suspicious

Classify the activity as **suspicious** when:

- the message contains unusual payment instructions, urgency, secrecy, or process exceptions;
- sender identity, reply-to, domain, or message context is inconsistent;
- the business request cannot yet be independently verified;
- unexpected mailbox, forwarding, delegate, or authentication activity is observed;
- recipients may have interacted with suspicious content;
- potential financial or data impact is still being investigated;
- available evidence does not yet confirm or exclude malicious activity.

Continue investigation, preserve evidence, and maintain appropriate containment and payment-verification controls.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- deliberate impersonation or sender spoofing intended to induce an unauthorized business action;
- confirmed compromise or unauthorized use of an email account;
- fraudulent payment, invoice, payroll, or bank-detail instructions;
- unauthorized access to or manipulation of mailbox contents or configuration;
- malicious forwarding rules, delegates, OAuth grants, or session activity;
- confirmed credential or sensitive-information disclosure;
- fraudulent outbound messages or internal spearphishing;
- an attempted or completed unauthorized financial transaction.

A BEC attempt may be malicious even when no mailbox was compromised and no payment was completed. Record account compromise and financial loss as separate impact findings.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to establish whether the message, account activity, or business request was legitimate or malicious.

Document:

- evidence collected;
- evidence unavailable;
- telemetry and retention limitations;
- business or financial verification still pending;
- potentially affected users and systems;
- confirmed and potential financial or data exposure;
- containment and payment status;
- additional data and follow-up actions required.

## Escalation

Escalate the incident when:

- a payment, payroll, or bank-account change may have been unauthorized;
- funds have been transferred or financial loss is suspected;
- an executive, finance, payroll, procurement, or privileged mailbox is affected;
- an organizational mailbox is confirmed compromised;
- multiple employees, mailboxes, suppliers, customers, or partner organizations are involved;
- sensitive, regulated, personal, or confidential information may have been disclosed;
- unauthorized forwarding, mailbox delegation, OAuth access, or persistence is identified;
- internal spearphishing or broader credential compromise is observed;
- the adversary remains active or the source of compromise has not been contained;
- legal, privacy, regulatory, insurance, banking, or law-enforcement notification may be required.

Financial institutions should be contacted immediately through verified channels when a fraudulent transfer may have occurred. Follow the organization's incident, fraud, legal, privacy, and regulatory escalation procedures.

## Response Guidance

For suspected or confirmed BEC:

1. Preserve the original email, complete headers, attachments, URLs, message trace, mailbox audit, identity, and relevant endpoint evidence.
2. Independently verify the business request using a previously established trusted contact method.
3. Determine whether the recipient replied, clicked a link, opened an attachment, disclosed information, submitted credentials, or initiated a payment.
4. Notify finance and the incident-response team when payment instructions or financial transfers may be affected.
5. Contact the relevant financial institution immediately through a verified channel when funds may have been transferred; request a stop, recall, or fraud investigation where available.
6. Search for the same message and related indicators across internal and external recipients.
7. Determine whether the event involved spoofing, a lookalike domain, a compromised mailbox, or another access method.
8. Reset compromised credentials, revoke active sessions and applicable tokens, and remove unauthorized MFA methods or recovery settings.
9. Remove malicious forwarding rules, delegates, OAuth grants, and other unauthorized mailbox configuration.
10. Quarantine or remove malicious messages after required evidence preservation and notify affected recipients through trusted channels.
11. Investigate endpoint, identity, mailbox, and business-system activity for additional compromise, persistence, or data exposure.
12. Restore affected accounts and business processes only after verification and required containment actions are complete.
13. Document the timeline, confirmed and potential impact, evidence, financial recovery actions, notifications, and residual risks.

Do not rely on the suspicious email thread or contact details contained within it to verify payment instructions or communicate with the purported sender. Do not delete original messages or authentication evidence before required preservation has been completed.

## Related Detection Rules

## Related Playbooks

- `playbooks/triage/email-compromise-triage.md`
- `playbooks/triage/phishing-alert-triage.md`
- `playbooks/triage/suspicious-login-triage.md`
- `playbooks/initial-access/phishing.md`
- `playbooks/initial-access/valid-account-compromise.md`
- `playbooks/initial-access/application-consent-abuse.md`
- `playbooks/response/account-compromise-response.md`
- `playbooks/response/credential-compromise-response.md`
- `playbooks/response/phishing-response.md`
- `playbooks/response/malicious-oauth-app-consent-response.md`

## Validation

The playbook should be validated against controlled BEC email samples, spoofed and lookalike sender scenarios, compromised mailbox datasets, message trace records, mailbox audit events, identity-provider telemetry, financial-process simulations, and authorized incident-response laboratory scenarios.

Validation should confirm that:

- suspicious BEC messages and impersonation attempts can be identified;
- original messages and complete headers can be preserved;
- sender spoofing can be distinguished from actual mailbox compromise;
- SPF, DKIM, and DMARC results can be interpreted in context;
- suspicious URLs and attachments can be analyzed safely;
- recipient actions and business-process impact can be established;
- mailbox, identity, OAuth, forwarding, and delegate activity can be investigated;
- related messages and affected recipients can be scoped across the environment;
- financial exposure and transaction status can be identified and escalated promptly;
- containment actions are authorized, documented, and reproducible;
- account, mailbox, and business-process recovery can be validated;
- escalation and notification criteria produce consistent outcomes.

## Safety

This playbook is intended for defensive security operations, incident response, security validation, controlled laboratory environments, and authorized testing only.

Mailbox containment, credential resets, session revocation, message quarantine or purge, payment holds, and access restrictions should be performed only by authorized personnel and according to approved organizational procedures.

Coordinate financial recovery, external communications, and required notifications with the appropriate finance, legal, privacy, and management functions. Avoid destructive remediation until required email, identity, endpoint, and financial evidence has been preserved.
