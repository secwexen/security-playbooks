# Architecture

The Security Playbooks is structured to provide a clear, modular, and professional layout for cybersecurity research, lab simulations. The architecture is designed for educational, hands-on use while maintaining real-world workflow relevance.

## Project Structure

```text
security-playbooks/
├── ACKNOWLEDGEMENTS.md
├── CHANGELOG.md
├── CITATION.cff
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── DISCLAIMER.md
├── Dockerfile
├── LICENSE
├── MAINTAINERS
├── Makefile
├── README.md
├── ROADMAP.md
├── SECURITY.md
├── SUPPORT.md
├── docker-compose.yml
├── requirements-dev.txt
├── requirements.txt
│
├── assets/
│   └── images/
│
├── config/
│
├── detection-rules/
│   ├── mappings/
│   ├── sigma/
│   ├── suricata/
│   └── yara/
│
├── docs/
│   ├── architecture/
│   ├── contributing/
│   ├── detection-engineering/
│   ├── getting-started/
│   ├── legal/
│   ├── playbooks/
│   ├── product/
│   └── reference/
│
├── integrations/
│
├── iocs/
│   └── feeds/
│
├── labs/
│   ├── datasets/
│   │   ├── linux/
│   │   ├── network
│   │   │   └── pcaps/
│   │   └── windows/
│   │       └── pcaps/
│   ├── logs/
│   ├── samples/
│   │   ├── benign/
│   │   └── events/
│   └── scenarios/
│
├── playbooks/
│   ├── collection/
│   ├── credential-access/
│   ├── defense-evasion/
│   ├── discovery/
│   ├── exfiltration/
│   ├── impact/
│   ├── initial-access/
│   ├── lateral-movement/
│   ├── persistence/
│   ├── privilege-escalation/
│   └── templates/
│
├── reports/
│
├── schemas/
│
├── scripts/
│
├── templates/
│
├── tests/
│   └── sigma/
│
├── tools/
│   ├── parsers/
│   ├── reports/
│   └── utils/
│
└── validation/
    ├── sigma/
    └── yara/
        ├── suricata/
        │   └── test_pcaps/
        └── test_samples/
```
