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

- **Initial Access:** Phishing, watering hole, credential compromise  
  - Phishing: T1566
  - Watering hole / Drive-by Compromise: T1189
  - Valid Accounts: T1078

- **Execution:** Script-based execution, native API usage
  - Command and Scripting Interpreter: T1059
  - Native API: T1106

- **Persistence:** Registry modification, scheduled tasks
  - Modify Registry: T1112
  - Scheduled Task/Job: T1053
  - Registry Run Keys / Startup Folder: T1547.001 where applicable

- **Privilege Escalation:** Token manipulation, UAC bypass
  - Access Token Manipulation: T1134
  - Bypass User Account Control: T1548.002

- **Defense Evasion:** Process injection, indirect command execution
  - Process Injection: T1055
  - Indirect Command Execution: T1202

- **Lateral Movement:** Remote services, lateral tool transfer, alternate authentication material
  - Remote Services: T1021
  - Lateral Tool Transfer: T1570
  - Use Alternate Authentication Material: T1550

- **Exfiltration:** Automated exfiltration, exfiltration over C2 channel
  - Automated Exfiltration: T1020
  - Exfiltration Over C2 Channel: T1041

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
