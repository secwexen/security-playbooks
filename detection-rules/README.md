# Detection Rules

The Detection Rules directory contains detection engineering content used to identify suspicious activity, adversary behaviors, and security threats in controlled environments.

This module provides structured, testable detection logic aligned with adversary tradecraft and common defensive workflows. It supports multiple rule formats and is intended for use by SOC analysts, threat hunters, blue team engineers, and detection engineers.

## Purpose

Detection rules help defenders translate known malicious behaviors into operational signals. They are used to identify suspicious events, anomalous activity, and adversary TTPs across endpoint, network, and identity telemetry.

This repository focuses on practical detection content designed for:

- Signal generation
- Threat hunting support
- Alert validation
- Detection engineering workflows
- Security content testing

## Rule Types

The repository includes the following detection formats:

- `sigma/` - Sigma rules for SIEM and log analytics platforms
- `suricata/` - Suricata rules for network intrusion detection
- `yara/` - YARA rules for malware and suspicious file analysis
- `metadata/` - detection metadata and contextual enrichment
- `mappings/` - ATT&CK and coverage mapping resources
- `examples/` - sample detection content and reference patterns
- `registry.yaml` - central registry for detection metadata and ownership tracking
