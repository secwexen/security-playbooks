# Architecture

The Security Playbooks is structured to provide a clear, modular, and professional layout for cybersecurity research, lab simulations. The architecture is designed for educational, hands-on use while maintaining real-world workflow relevance.

## Project Structure

```text
security-playbooks/
├── assets
│   └── images/
├── automation
│   ├── workflows/
├── config/
├── dashboards/
├── detection-rules/
│   ├── mappings/
│   ├── sigma/
│   ├── suricata/
│   └── yara/
├── docs/
│   ├── architecture/
│   ├── contributing/
│   ├── getting-started/
│   ├── legal/
│   ├── playbooks/
│   ├── product/
│   └── reference/
├── playbooks/
│   ├── exfiltration/
│   ├── initial-access/
│   └── lateral-movement/
├── samples/
│   ├── benign/
│   ├── iocs/
│   ├── logs/
│   └── malicious/
├── schemas/
├── tests/
│   ├── detection_tests/
│   ├── integration_tests/
│   ├── playbook_tests/
│   └── security_tests/
├── tools/
│   └── parsers/
├── utils/
├── validation/
│   ├── sigma/
│   └── yara/
├── CHANGELOG.md
├── CITATION.cff
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── DISCLAIMER.md
├── ETHICS.md
├── LICENSE
├── MAINTAINERS
├── MANIFEST.in
├── README.md
├── SECURITY.md
├── SUPPORT.md
├── dev-requirements.txt
├── pyproject.toml
├── requirements.txt
└── trivyignore
```

## Key Components

### 1. Detection Rules

- Purpose: Identify suspicious activities and simulate detection in lab environments.
- Formats: Sigma, YARA, and Suricata.
- Use Case: Threat hunting, SIEM integration, or educational analysis.

### 2. Scenarios

- Purpose: Provide realistic attack simulations based on MITRE ATT&CK.
- Examples: Phishing campaigns, malware propagation, lateral movement.
- Use Case: Red/Blue team exercises, understanding attacker tactics.

### 3. Labs

- Purpose: Hands-on exercises with scripts and walkthroughs.
- Languages: Python primarily, with optional Bash or PowerShell scripts.
- Use Case: Practice detection, incident response, or research in isolated environments.

### 4. Examples

- Purpose: Visualize outputs of detection rules and scenario executions.
- Contents: Screenshots, log extracts, and sample alerts.

### 5. Docs

- Purpose: Provide Quick Start guides, architecture overview, and usage instructions.
- File Example: [architecture.md](docs/architecture/architecture.md), [Quick Start.md](docs/getting-started/quick-start.md).

### 6. Tools

- Purpose: Helper scripts to parse, validate, or simulate scenarios (e.g., Sigma parser).

## SOC Detection Pipeline

```bash
[Data Sources]
  - Sysmon Logs
  - Windows Event Logs
  - Network Traffic (PCAP)
  - Threat Intelligence Feeds
        ↓
[Ingestion & Parsing Layer]
  - log_loader.py
  - sysmon_parser.py
        ↓
[Detection Engine]
  - Sigma / YARA / Suricata Rules
  - rule_loader.py
        ↓
[Detection Pipeline]
  - detection_pipeline.py
  - pipeline.yaml
        ↓
[Enrichment Layer]
  - VirusTotal / AbuseIPDB integrations
        ↓
[SOAR / Response Engine]
  - isolate_host.py
  - block_ip.py
  - disable_user.py
        ↓
[Playbook Execution Engine]
  - playbook_parser.py
  - executor.py
        ↓
[Outputs & Reporting]
  - reports/
  - metrics/
  - dashboards/
```

## Design Principles

1. **Modularity:** Each component is independent and reusable.  
2. **Educational Focus:** Scripts and scenarios are safe to run in isolated labs.  
3. **Realistic Simulations:** Scenarios mimic real-world attacks without targeting production systems.  
4. **Extensible:** Users can add new rules, scenarios, or labs easily.

## Recommended Usage

1. Start with [quickstart.md](docs/getting-started/quickstart.md) to set up your lab environment.  
2. Explore detection rules in [detection-rules/](detection-rules/).  
3. Run scenarios in [scenarios/](scenarios/) with labs as guided exercises.  
4. Reference [examples/](examples/) to validate your results.  
5. Extend repository content with new scripts or detection rules as needed.
