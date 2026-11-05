---
id: "credential-compromise-response"
name: "Credential Compromise Response"
category: "response"
status: "active"
version: "1.0.0"
author: "Secwexen"
created_at: "2026-11-02T12:00:00Z"
updated_at: "2026-11-02T12:00:00Z"
description: "Respond to suspected or confirmed compromise of user, service, or application credentials, including passwords, MFA, tokens, and service-account secrets."
objective: "Contain unauthorized access, validate the scope of compromise, invalidate exposed credentials, restore trusted access, and document the effective response and recovery actions."
severity: "critical"
mitre_attack:
  - "T1078"
  - "T1552"
  - "T1110"
  - "T1621"
triggers:
  - "Successful sign-in from an unknown device or location"
  - "Multiple failed sign-in attempts followed by successful access"
  - "MFA prompt fatigue or unexpected MFA registration activity"
  - "Password reset or recovery request not initiated by the legitimate user"
  - "API key, access token, or service account credential suspected to be exposed"
  - "Alert that a privileged account or service account has been abused"
  - "Threat hunting identifies suspicious credential usage or token activity"
prerequisites:
  - "Access to identity and access management logs"
  - "Access to MFA and authentication telemetry"
  - "Access to endpoint, VPN, RDP, or cloud audit logs where available"
  - "Authorized capability to revoke active sessions and authentication tokens"
  - "Authorized capability to reset passwords and remove unauthorized MFA authentication methods"
tags:
  - "credential"
  - "response"
  - "identity"
  - "authentication"
  - "mfa"
  - "token"
references:
  - "https://attack.mitre.org/techniques/T1078/"
  - "https://attack.mitre.org/techniques/T1110/"
  - "https://attack.mitre.org/techniques/T1552/"
  - "https://attack.mitre.org/techniques/T1621/"
steps:
  - id: "identify-validate-alert"
    order: 1
    name: "Identify Validate Compromise Signal"
    action: "investigate"
    description: "Confirm whether the alert reflects a real authentication event, suspicious activity, or a false positive."
    expected_result: "The suspected credential compromise is validated and the affected identity is identified."
  - id: "review-contain-access"
    order: 2
    name: "Review Contain Current Access"
    action: "contain"
    description: "Immediately suspend or restrict active sessions, access tokens, and network paths associated with the compromised identity."
    expected_result: "Unauthorized access is blocked and active sessions are terminated."
  - id: "review-reset-credentials"
    order: 3
    name: "Review Reset Credentials"
    action: "remediate"
    description: "Reset passwords, revoke tokens, rotate API keys, and replace service-account or SSH credentials as required."
    expected_result: "The compromised credentials are invalidated and replaced with trusted replacements."
  - id: "review-activity"
    order: 4
    name: "Review Authentication Activity"
    action: "analyze"
    description: "Examine sign-in history, device posture, IP reputation, MFA events, and session activity to determine scope."
    expected_result: "The activity timeline and evidence of compromise are documented."
  - id: "review-assess-impact"
    order: 5
    name: "Review Assess Impact"
    action: "analyze"
    description: "Identify which systems, applications, data, or privileged access were reachable using the compromised identity."
    expected_result: "The impact and scope of the compromise are clearly defined."
  - id: "review-correlate-related-activity"
    order: 6
    name: "Review Correlate Related Activity"
    action: "hunt"
    description: "Search for related phishing, credential harvesting, malware, token theft, or lateral movement using the same identity or indicators."
    expected_result: "Related attack activity is identified or ruled out."
  - id: "determine-restore-access"
    order: 7
    name: "Determine Restore Secure Access"
    action: "recover"
    description: "Reissue valid credentials, re-enable access under hardened controls, and confirm the user or service account can operate securely."
    expected_result: "Access is restored only after verification and hardening."
  - id: "determine-investigation-outcome"
    order: 8
    name: "Determine Investigation Outcome"
    action: "document"
    description: "Record actions taken, evidence, final assessment, and follow-up monitoring requirements."
    expected_result: "The case is documented with a clear outcome and remediation record."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "credential-compromise"
---

# Credential Compromise Response

## Purpose

This playbook provides a structured response workflow for suspected or confirmed compromise of user, service, or application credentials. The objective is to contain unauthorized access, validate the attacker path, reduce exposure, invalidate the compromised materials, and restore secure access without causing unnecessary operational disruption.

Credential compromise may result from phishing, password spraying, token theft, malware, exposed secrets, or misuse of valid accounts. This playbook supports fast triage, containment, credential reset, impact assessment, and secure recovery actions across user, service, and application identities.

## MITRE ATT&CK

| Technique | Name                     | Relevance                                                                        |
| --------- | ------------------------ | -------------------------------------------------------------------------------- |
| T1078     | Valid Accounts           | Relevant when an attacker uses valid credentials to access systems or services   |
| T1110     | Brute Force              | Relevant when password guessing, spraying, or credential stuffing is used        |
| T1552     | Unsecured Credentials    | Relevant when secrets, token material, or passwords are exposed or harvested     |
| T1621     | MFA Request Generation   | Relevant when MFA fatigue or repeated push notification attacks occur            |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Successful sign-in from an unknown location, device, or network source.
- Multiple failed sign-ins followed by a successful login.
- An MFA request or enrollment change not initiated by the legitimate user.
- A password reset, password recovery, or account recovery action is unexpectedly requested.
- An API key, token, password, or secret is suspected to be exposed or used outside the approved environment.
- A privileged, administrative, or service account is used outside normal behavior.
- Threat hunting identifies unusual authentication or token activity.
- A user reports an account takeover or suspicious sign-in activity.

## Scope

The investigation should consider:

- affected user, service account, or application identity;
- associated device or endpoint;
- source IP, VPN address, or network source;
- sign-in method and MFA method;
- user or service privileges and role assignments;
- corporate or cloud platform involved;
- API keys, tokens, passwords, certificates, or secrets impacted;
- active sessions and session token usage;
- data or systems accessible with the compromised identity;
- persistence changes such as mailbox rules, tokens, or access grants;
- related phishing, malware, or endpoint activity.

## Investigation Procedure

### Step 1 — Identify Validate Compromise Signal

Determine:

- the source of the alert;
- the identity affected;
- the time of the suspicious event;
- whether the activity is confirmed or suspected;
- the user or asset reporting the issue;
- whether the event is isolated or part of a broader access issue;
- whether the activity is associated with a known user device, browser, or network;
- whether the event aligns with expected user behavior, role, and normal access pattern.

Preserve the original alert context before making administrative changes.

### Step 2 — Review Contain Current Access

Immediately:

- disable the account or restrict it from signing in;
- revoke active sessions and invalidate refresh tokens;
- sign out the user from all active devices and sessions;
- block access at VPN, identity provider, app gateway, and cloud control layers where applicable;
- disable the associated service account or reset its credentials if needed;
- restrict access from unknown or untrusted networks and device types;
- escalate containment to the responsible administrator if the account is privileged or high-risk.

If the user is a privileged account, take additional precautions and escalate to the responsible administrator quickly.

### Step 3 — Review Reset Credentials

Reset or rotate the following materials when relevant:

- password;
- MFA method or registration;
- recovery codes;
- API keys;
- OAuth tokens;
- client secrets;
- SSH keys;
- certificates or access keys;
- service account passwords or application credentials;
- associated app-specific secrets or tokens used by the compromised identity;
- dependent service credentials that may have been exposed through the same account.

Use secure distribution channels. Do not re-use prior credentials or copies from the compromised account.

### Step 4 — Review Authentication Activity

Review:

- sign-in timestamps;
- IP addresses and geolocation;
- device IDs and browser fingerprints;
- security events and MFA outcomes;
- successful and failed authentication events;
- session duration and token issuance;
- privilege changes or access grants;
- unusual login times, login types, or access locations;
- any authentication attempts that occurred before or after the suspected compromise.

Determine whether the activity is consistent with normal user behavior or indicates an attacker using the account.

### Step 5 — Review Assess Impact

Determine:

- which systems the compromised identity could access;
- which applications or services were reachable;
- what data or configuration the account could view or modify;
- whether privileged roles were used;
- whether the account could be used for lateral movement;
- whether mailbox, cloud storage, code repositories, or infrastructure access was exposed;
- whether any sensitive or regulated data was exposed or modified;
- whether any operational services were disrupted or delayed.

Assess whether the compromise created an operational outage, confidentiality risk, integrity risk, or availability risk.

### Step 6 — Review Correlate Related Activity

Search for:

- phishing or social engineering attempts;
- password spray or brute force events;
- malware or credential harvesting on endpoints;
- suspicious browser extensions or scripts;
- suspicious token or cookie theft;
- mailbox rule changes;
- privilege escalation or account manipulation;
- changes to role assignments, group memberships, or policy grants;
- proxy, DNS, VPN, or cloud telemetry connected to the same user or device;
- related persistence mechanisms or unauthorized configuration changes;
- any additional host, account, or service activity linked to the same identity.

Also review evidence that the attacker may have obtained data before or after compromise.

### Step 7 — Determine Restore Secure Access

After containment and remediation:

- create a replacement credential set;
- re-enable the account only after verification;
- re-establish MFA under trusted conditions;
- confirm the user or service account can access only the required systems and scopes;
- re-validate device trust and network access controls;
- ensure that unauthorized tokens, cookies, and app grants were removed;
- verify that the account’s role, group membership, and permissions match the expected posture.

If the account was a privileged identity, ensure the restore path includes tighter controls, monitoring, and owner approval.

### Step 8 — Determine Investigation Outcome

Classify the activity as one of the following:

- Benign
- Suspicious
- Malicious
- Inconclusive

Document the case as benign, suspicious, malicious, or inconclusive and record the timeline, actions, affected systems, users, and follow-up monitoring needs.

## Evidence to Collect

| Evidence           | Description                                                                           |
| ------------------ | ------------------------------------------------------------------------------------- |
| Alert              | Detection source, ID, severity, timestamp                                             |
| Identity           | Username, account type, role, privileged status                                       |
| Authentication     | Login source, device, MFA event, sign-in method                                       |
| IP and Network     | Source IP, VPN, ASN, geolocation, proxy logs                                          |
| Endpoint           | Hostname, EDR alerts, process activity, malware telemetry                             |
| Tokens             | OAuth tokens, refresh tokens, session IDs, API keys                                   |
| Account Changes    | Password changes, MFA changes, privilege assignments                                  |
| Mailbox / Cloud    | Email rules, cloud app access, drive or storage access                                |
| Timeline           | Initial compromise, validation, remediation, and recovery                             |
| Related Activity   | Phishing, malware, lateral movement, data access                                      |
| Remediation        | Password reset, account disablement, recovery actions                                 |
| User Report        | User-reported symptoms, suspicious notifications, and recovery requests               |
| Secret Exposure    | Leaked secrets, credentials, config files, vault entries, or code repos               |
| Session Data       | Active sessions, device trust status, idle sessions, and revoked tokens               |
| Access Grants      | New OAuth apps, app roles, API permissions, or delegated access                       |
| Recovery Actions   | Password reset events, recovery code generation, and MFA re-registration              |
| Persistence        | New service accounts, backdoors, mailbox rules, or unauthorized configuration changes |
| Source of Exposure | Phishing email, malware, leaked dump, exposed config, or password spray source        |
| Privilege Scope    | Effective privileges, role assignments, and whether admin access was abused           |

## Decision Criteria

### Benign

Classify the activity as benign when:

- the sign-in is from a known and approved source;
- no unauthorized changes or privilege abuse are detected;
- the alert is a false positive or a short-lived system artifact;
- the account activity is consistent with approved behavior;
- no unexpected MFA enrollment, password reset, or recovery action was observed;
- no token, session, or credential reuse is associated with the account.

Document the reason for closure before returning the account to normal operations.

### Suspicious

Classify the activity as suspicious when:

- sign-ins are unusual but not yet proven malicious;
- MFA prompts or registration events do not align with the user’s normal pattern;
- the identity had access to sensitive systems or privileged roles;
- the incident requires additional hunting or forensic review;
- unusual token issuance, session creation, or device trust changes are observed;
- the activity could be explained by a phishing attempt, credential stuffing, or unverified device access.

Continue investigation and validate all relevant evidence before returning to service.

### Malicious

Classify the activity as malicious when sufficient evidence supports:

- live unauthorized access by an attacker;
- confirmed token theft, credential reuse, or MFA bypass;
- unauthorized changes to account configuration or access rights;
- data access or modification linked to the compromised identity;
- a broader attack path involving phishing, malware, or persistence;
- password, MFA, or recovery settings were changed without the legitimate user’s approval;
- the compromised identity was used to access restricted systems, applications, or sensitive data.

Escalate immediately to the appropriate incident-response workflow.

### Inconclusive

Use inconclusive when evidence is insufficient to determine whether the identity was genuinely compromised.

Document:

- what evidence was collected;
- what remains unknown;
- what additional telemetry or validation is required;
- whether missing IdP, MFA, endpoint, or VPN logs prevent a reliable assessment;
- whether continued monitoring is required before a final classification;
- whether the observed behavior could be explained by a legitimate but unusual user action, device, or network condition.

## Escalation

Escalate the investigation when:

- privileged or domain-admin accounts are involved;
- the account has access to sensitive or regulated data;
- multiple accounts or systems are impacted;
- token theft or MFA bypass is suspected;
- the user or service account appears tied to a wider intrusion;
- the event is associated with malicious infrastructure or malware;
- an external stakeholder or regulator must be informed.

## Response Guidance

For confirmed credential compromise:

1. Disable or restrict active access immediately.
2. Preserve relevant authentication and telemetry evidence.
3. Reset all affected credentials and revoke tokens.
4. Reissue access only through secure and approved processes.
5. Validate identity and device trust before restoring access.
6. Review underlying causes such as phishing, malware, or configuration weakness.
7. Check for additional affected accounts, tokens, or service credentials.
8. Continue monitoring for suspicious sign-ins or lateral movement.
9. Document the timeline, response actions, and final risk assessment.
10. Review account permissions, admin roles, and access grants for unauthorized changes.
11. Verify whether the compromised identity was used to access sensitive data, cloud services, or downstream systems.

Do not restore service access before the authentication path has been validated and the risk of re-use is mitigated.

## Related Detection Rules

## Related Playbooks

- `playbooks/triage/data-exfiltration-triage.md`
- `playbooks/triage/suspicious-process-triage.md`
- `playbooks/response/isolate-host-response.md`
- `playbooks/response/data-exfiltration-response.md`

## Validation

The playbook should be validated against representative authentication scenarios, real sign-in telemetry, and controlled security exercises.

Validation should confirm that:

- compromised identities are quickly identified;
- valid access is removed before attacker persistence grows;
- credential reset and token revocation processes are effective;
- MFA and identity controls are properly reviewed after recovery;
- scope and impact are consistently assessed;
- escalation criteria produce correct operational responses.

## Safety

This playbook is intended for defensive security operations, controlled security testing, and authorized investigations only.

Credential resets, session termination, and access restriction must follow the organization’s operational approval, data-protection, and incident-response procedures, especially for privileged accounts or regulated systems.
