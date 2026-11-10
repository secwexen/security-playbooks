# Command and Control

## Overview

Command and Control (TA0011) is a MITRE ATT&CK tactic that describes adversary activities involving communication between compromised systems and attacker-controlled infrastructure.

After gaining access to an environment, adversaries may establish communication channels to remotely control compromised endpoints, execute commands, transfer information, and coordinate additional malicious activities.

These communications may use legitimate network protocols, encrypted connections, DNS requests, web services, cloud platforms, or compromised external infrastructure to blend in with normal network traffic.

Command-and-control activity can be difficult to identify because adversaries frequently attempt to disguise malicious communications as legitimate application or user activity.

From a defensive security perspective, monitoring outbound connections, DNS activity, network traffic patterns, TLS metadata, and endpoint communication behavior is essential for identifying potential C2 infrastructure.

This tactic is particularly relevant to network security monitoring, intrusion detection, threat intelligence, and endpoint detection and response (EDR).
