# Threat Model

This playbook assumes a realistic enterprise environment and adversary behavior. It is designed for educational and lab purposes only.

- **Target Environment:** Windows Active Directory (Enterprise Network)
- **Log Sources:** 
  - Windows Event Logs (Security, Sysmon)
  - Network Traffic (PCAP)
  - Endpoint Detection & Response (EDR) telemetry
- **Adversary Profile:** APT-like actor executing common enterprise attacks
- **Attack Surface:** Endpoints, domain controllers, user workstations
- **Attack Vectors Covered:** 
  - Command & scripting interpreter execution (T1059)
  - Phishing and social engineering (T1566)
  - Malware execution and lateral movement
- **Assumptions:**
  - Logging and monitoring are enabled (Sysmon, Security Logs)
  - SIEM or log aggregation is available
  - Scenarios run in isolated lab environments only
- **Goals:** 
  - Demonstrate detection engineering and threat hunting workflows
  - Provide hands-on lab exercises for portfolio and learning purposes
