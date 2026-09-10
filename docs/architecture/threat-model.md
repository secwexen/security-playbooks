# Threat Model

Security Playbooks assumes a realistic enterprise environment and adversary behavior. This model is designed for educational and lab purposes only.

## Target Environment

- **Platform:** Windows Active Directory (Enterprise Network)
- **Scope:** User workstations, domain controllers, endpoints
- **Log Sources:**
  - Windows Event Logs (Security, Application, System)
  - Sysmon (Enhanced process and network monitoring)
  - Network Traffic (PCAP files)
  - EDR telemetry (Endpoint Detection & Response)

## Adversary Profile

- **Type:** APT-like threat actor
- **Capability:** Advanced techniques with persistence and lateral movement
- **Behavior:** Common enterprise attack patterns
- **Motivation:** Data exfiltration, credential theft, system compromise

## Attack Surface

- **Primary Targets:** User workstations, domain controllers
- **Secondary Targets:** File servers, network infrastructure
- **Access Methods:** Phishing, malware, credential compromise

## Attack Vectors Covered

- **Initial Access:** Phishing, watering hole, credential exposure (T1566, T1566.002)
- **Execution:** Script-based execution, malware deployment (T1059, T1106)
- **Persistence:** Registry modification, scheduled tasks (T1547, T1053)
- **Privilege Escalation:** Token impersonation, UAC bypass (T1134, T1088)
- **Defense Evasion:** Process injection, living-off-the-land (T1055, T1202)
- **Lateral Movement:** SMB exploitation, credential reuse (T1570, T1550)
- **Exfiltration:** Data staging, encrypted channels (T1020, T1041)

## Assumptions

- Logging and monitoring are enabled (Sysmon, Security Logs)
- SIEM or log aggregation system is available
- Scenarios run in isolated, controlled lab environments only
- No connection to production networks
- All testing is authorized and documented

## Lab Goals

- Demonstrate detection engineering workflows
- Practice threat hunting methodologies
- Validate SIEM and EDR alerts
- Improve incident response capabilities
- Develop security operations skills

## Defensive Assumption

All scenarios assume **defensive security operations**. Offensive techniques are simulated for validation purposes only in authorized lab environments.
