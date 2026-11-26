# Quick Start

This quickstart file helps you run your first Security Playbooks request in under 5 minutes.

## 1. Clone & Setup

```bash
# Clone repository
git clone https://github.com/secwexen/security-playbooks.git
cd security-playbooks

# Create virtual environment
python -m venv .venv

# Activate virtual environment
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

# Run centralized validation for all detection rules
python -m scripts.validate_all_rules
```

The Suricata fixtures are real PCAP files generated with Scapy. Scapy is included as a project dependency. [Development Requirements](requirements-dev.txt).

If the PCAP fixtures need to be regenerated:

```python
python tests/suricata/generate_fixtures.py
```

## 3. Generate Coverage Reports

The project provides automated MITRE ATT&CK coverage reporting based on the detection rule registry and mapping files.

Generate coverage reports:

```python
python -m tools.reports.coverage_report
```

This command generates:

- `detection-rules/mappings/coverage_report.json`
- `detection-rules/mappings/attack-coverage.json`
- `detection-rules/mappings/rule_coverage_map.json`

The reports include:

- Total registered detection rules
- Mapped and unmapped rule counts
- MITRE ATT&CK technique coverage
- Rule-to-technique relationships

> [!NOTE]
> Coverage figures represent the repository's current MITRE ATT&CK mapping dataset. They do not represent coverage of the entire ATT&CK Enterprise framework.

## 4. Run Tests

Run the full pytest suite:

```python
python -m pytest -v
```
