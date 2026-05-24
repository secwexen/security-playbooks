# Demo

This folder contains sample data designed to test the core workflow of the Security Playbooks project.

## How to Run

From the project root directory, execute the following commands

## IOC Detection Demo

```bash
python demo/ioc_detection_demo.py
```

### Output Example

```text
[INFO] Generating simulated network logs...
[INFO] Running detection pipeline...

========== ALERT ==========
Title         : Malicious IOC Communication Detected
Severity      : HIGH
Hostname      : WIN10-LAB
DestinationIP : 45.133.1.10
Domain        : 1.example-domains.com
Technique     : T1071
ATT&CK        : Application Layer Protocol

[SOAR] IOC Enrichment Started
[THREAT INTEL] Reputation Score: MALICIOUS
[THREAT INTEL] Confidence: HIGH
[SOAR] Host isolation queued: WIN10-LAB
[SLACK] Alert notification sent for WIN10-LAB
\security-playbooks\> python demo/ioc_detection_demo.py
[INFO] Generating simulated network logs...
[INFO] Running detection pipeline...

========== ALERT ==========
Title         : Malicious IOC Communication Detected
Severity      : HIGH
Hostname      : WIN10-LAB
DestinationIP : 185.220.101.45
Domain        : 2.example-domains.net
Technique     : T1071
ATT&CK        : Application Layer Protocol

[SOAR] IOC Enrichment Started
[THREAT INTEL] Reputation Score: MALICIOUS
[THREAT INTEL] Confidence: HIGH
[SOAR] Host isolation queued: WIN10-LAB
[SLACK] Alert notification sent for WIN10-LAB
```

> [!NOTE]
> This IP/hostname is an example target.
