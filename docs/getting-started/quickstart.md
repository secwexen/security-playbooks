# Quick Start

This quickstart file helps you run your first Security Playbooks request in under 5 minutes.

## 1. Clone & Setup

```bash
# Clone repository
git clone https://github.com/secwexen/security-playbooks.git
cd security-playbooks

# Create virtual environment
python -m venv .venv
source .venv/bin/activate     # Linux/Mac
.\.venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt
```

## 2. Run Detection Tests

The project includes automated tests for Sigma, YARA, and Suricata detection rules.

```python
# Run Sigma detection tests
python -m scripts.run_sigma_tests

# Run YARA tests
python -m scripts.run_yara_tests

# Run Suricata tests
python -m scripts.run_suricata_tests

# Run the full pytest suite
python -m pytest -v
```

The Suricata fixtures are real PCAP files generated with Scapy. Scapy is included as a project dependency. [Development Requirements](requirements-dev.txt).

If the PCAP fixtures need to be regenerated:

```python
python tests/suricata/generate_fixtures.py
```