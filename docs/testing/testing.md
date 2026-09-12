# Security Playbooks Testing

This guide describes how to run, validate, and maintain the automated tests for the Security Playbooks project.

## Testing Requirements

Before running the test suite, install the project and development

dependencies:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

The project requires Python 3.11.

Suricata must be installed separately and available in the system `PATH` for Suricata detection tests.

Verify the installation:

```bash
suricata --build-info
```

## Running the Test Suite

Run the complete pytest suite:

```bash
python -m pytest -v
```
