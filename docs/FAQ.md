# Frequently Asked Questions (FAQ)

This document provides answers to the most frequently asked questions about Security Playbooks.

## 1. What is Security Playbooks?

Security Playbooks is an educational cybersecurity repository focused on:

- Detection engineering
- Threat hunting
- Incident response
- MITRE ATT&CK–aligned attack simulations
- Security operations workflows

The project is designed to help users gain practical, hands-on experience in controlled environments.

## 2. Is this tool safe to use on real systems?

No. Security Playbooks is strictly intended for controlled, authorized lab environments only.

It simulates adversary behavior and detection pipelines (e.g., MITRE ATT&CK techniques), which can generate alerts, modify logs, or trigger defensive actions (isolation, blocking, etc.) in a SOAR-like environment. Running these scenarios outside a lab or without authorization can cause operational disruption, detection noise, or unintended security impacts.

## 3. What skills do I need before using it?

You don’t need advanced expertise, but you should be familiar with:

- Basic Windows/Linux administration
- Log sources (especially Windows Event Logs / Sysmon)
- Introductory networking concepts (TCP/IP, DNS, HTTP)
- Basic cybersecurity concepts (threats, malware, phishing)

Advanced use cases (detection engineering, rule tuning) benefit from knowledge of:

- MITRE ATT&CK framework
- Sigma rules
- YARA signatures
- SIEM platforms (Splunk, Elastic, Sentinel, etc.)

## 4. Can this project run in cloud environments?

Yes, Security Playbooks can be used in cloud-based lab environments, provided they are properly isolated.

Supported setups include:

- Docker-based deployments
- SIEM-integrated lab environments (e.g., Microsoft Sentinel, Elastic Cloud)

## 5. What detection rule formats are supported?

Security Playbooks supports multiple detection rule formats to accommodate different SIEM platforms and security tools:

- Sigma Rules – Platform-agnostic detection rules that can be translated to various SIEM formats
- YARA Rules – Malware and file-based detection signatures
- Suricata Rules – Network-based intrusion detection rules for IDS/IPS systems

All rules are mapped to MITRE ATT&CK techniques for standardized threat coverage. Rules are stored in the [Detection Rules](../detection-rules/) directory and can be integrated with your existing security tooling.

## 6. Is this for offensive security or red teaming?

No. Security Playbooks is strictly for defensive security, blue team operations, and authorized security testing only.

While the repository contains attack scenarios and adversary emulation procedures for validation purposes, these are exclusive for controlled lab environments and require explicit authorization before execution. This is not a tool for unauthorized offensive testing, exploitation, or adversary simulation against production networks.

Red teamers should only use this repository in isolated labs for learning and skill development, never against real systems or organizations without written authorization.

See [Ethics & Responsible Use Guidelines](legal/ethics.md) for details.

## 7. How can I contribute to Security Playbooks?

Contributions are welcome.

See the [Contributing Guide](../CONTRIBUTING.md) for contribution guidelines.

## 8. How do I verify if a playbook execution was successfully detected?

After executing an authorized test scenario, verify detection by following these steps:

1. Verify Event Generation: Confirm expected events and log collection.
2. Verify Log Ingestion: Ensure events reach the SIEM with correct timestamps, hosts, and fields.
3. Verify Detection Rules: Confirm rules are enabled and match the expected activity.
4. Verify Alerts: Check generated alerts, rule IDs, timestamps, affected hosts, and severity.
5. Validate Detection Coverage:
   - Sigma: Verify log event matches.
   - YARA: Verify test file matches.
   - Suricata: Verify network traffic triggers an alert.
6. Confirm Expected Results: Compare observed results with expected outcomes and check for false positives.
7. Document the Results: Record test details, alerts, rule IDs, failures, and missing telemetry.

Important: Successful scenario execution does not necessarily mean successful detection. A detection validation is successful only when the expected telemetry and detection results have been verified against the test objectives.

## 9. Where should I start if I am new to the project?

Start with the repository README and the documentation in the `docs/` directory to understand the project structure, supported workflows, and example scenarios. For a first lab, begin with a simple detection or hunting scenario and validate the expected telemetry before moving to more advanced ATT&CK-aligned simulations.

## 10. Can I use these playbooks with my own SIEM or security stack?

Yes, provided your environment can collect the relevant logs and support the rule formats used by the project. Security Playbooks is designed to be compatible with common SIEM and detection platforms, including Sigma-based workflows, YARA-based file detections, and Suricata network detections. The most important requirement is that your lab environment is isolated, authorized, and able to ingest the telemetry needed for validation.
