# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

# Release v0.1.0 – 2026-03-21

## Security Playbooks — Initial Open Source Pre-Release

This is the first Pre-release of the Security Playbooks project.

It includes foundational detection content, incident response playbooks, and hands‑on lab scenarios designed to support SOC analysts, blue teamers, and cybersecurity experts.

## Included in This Release  

### Detection Rules

- Sigma rules for common attack techniques  
- MITRE ATT&CK–aligned detection logic  
- Example log sources and mappings  

### Incident Response Playbooks

- Step‑by‑step response procedures  
- Containment, eradication, and recovery guidelines  
- Analyst checklists and decision trees  

### Lab Scenarios

- Practical exercises for testing detections  
- Simulated attack chains  
- Walkthroughs for hands‑on learning  

## What's Changed

* Potential fix for code scanning alert no. 1: Workflow does not contain permissions by @secwexen in https://github.com/secwexen/security-playbooks/pull/1
* Bump the pip group across 1 directory with 2 updates by @dependabot[bot] in https://github.com/secwexen/security-playbooks/pull/10

## New Contributors

* @secwexen made their first contribution in https://github.com/secwexen/security-playbooks/pull/1
* @dependabot[bot] made their first contribution in https://github.com/secwexen/security-playbooks/pull/10

**Full Changelog**: https://github.com/secwexen/security-playbooks/commits/v0.1.0

# Release v0.2.1 – 2026-07-08

## Security Playbooks — Operational Expansion Release

This release expands the **Security Playbooks** project from a foundational security repository into a broader defensive security framework covering detection engineering, threat hunting, security operations, threat intelligence, and validation workflows.

## Included in This Release

### Detection Engineering

- Expanded detection engineering documentation
- Rule lifecycle documentation
- Sigma development guidance
- Detection validation workflow documentation
- Detection rule examples for Sigma, YARA, and Suricata
- Detection metadata schema and rule management structure

### Threat Hunting

- MITRE ATT&CK–aligned hunting methodology
- Hypothesis-driven hunting documentation
- Hunting process documentation
- Hunting queries for:
  - KQL
  - SPL
  - Elastic

### Threat Intelligence

- Threat actor documentation structure
- Malware intelligence resources
- Campaign tracking structure
- IOC analysis resources
- MITRE actor mapping support
- TLP classification documentation

### Security Operations

- SOC workflow documentation
- Alert triage procedures
- Incident handling guidance
- Incident response lifecycle documentation

### Validation Framework

- Expanded validation structure
- Detection test cases
- Validation reports
- Scenario-based testing resources

### Repository Improvements

- Detection rule metadata support
- Detection examples
- Expanded integrations documentation
- Improved documentation organization
- Expanded wiki content

## What's Changed

* Bump orjson from 3.10.7 to 3.11.6 in the pip group across 1 directory by @dependabot[bot] in https://github.com/secwexen/security-playbooks/pull/14
* Bump black from 24.4.2 to 26.3.1 in the pip group across 1 directory by @dependabot[bot] in https://github.com/secwexen/security-playbooks/pull/15
* Bump requests from 2.32.4 to 2.33.0 in the pip group across 1 directory by @dependabot[bot] in https://github.com/secwexen/security-playbooks/pull/16
* Bump pytest from 8.2.0 to 9.0.3 in the pip group across 1 directory by @dependabot[bot] in https://github.com/secwexen/security-playbooks/pull/18
* Bump lxml from 5.2.1 to 6.1.0 in the pip group across 1 directory by @dependabot[bot] in https://github.com/secwexen/security-playbooks/pull/19
* Add missing metadata fields to suspicious_login Sigma rule by @manish01-hash in https://github.com/secwexen/security-playbooks/pull/20
* Potential fix for code scanning alert no. 2: Workflow does not contain permissions by @secwexen in https://github.com/secwexen/security-playbooks/pull/21
* Potential fix for code scanning alert no. 3: Workflow does not contain permissions by @secwexen in https://github.com/secwexen/security-playbooks/pull/22

## New Contributors

* @manish01-hash made their first contribution in https://github.com/secwexen/security-playbooks/pull/20

**Full Changelog**: https://github.com/secwexen/security-playbooks/compare/v0.1.0...v0.2.1
