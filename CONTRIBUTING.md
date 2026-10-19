# Contributing to Security Playbooks

Thank you for your interest in contributing to this project!

We welcome high‑quality contributions that improve the functionality, documentation, detection rules, scenarios, and overall quality of the repository.

## Project Overview

For planned features and project direction, see [ROADMAP](ROADMAP.md).

## Contribution Types Accepted

You may contribute in several ways:

- Code Contributions
- Detection Rules
- Documentation
- Issues & Suggestions

## Before You Start

### 1. Open an Issue First

Before submitting a Pull Request, please open an issue describing:
- What you want to add or fix
- Why it is needed
- How you plan to implement it

This helps maintain project structure and prevents duplicate work.

## Getting Started

### 1. Clone the Repository

Clone the repository and move into the project directory:

```bash
git clone https://github.com/secwexen/security-playbooks.git
cd security-playbooks
```

### 2. Create a new branch from `main`

```bash
git checkout -b feature/feature-name
```

### 3. Review the Repository Structure

The main project components are organized as follows:

```text
playbooks/            # Security investigation and response playbooks
detection-rules/      # Sigma, YARA, and Suricata detection rules
docs/                 # Project documentation
labs/                 # Training datasets, logs, PCAPs, and scenarios
integrations/         # SIEM and security-tool integrations
scripts/              # Automation and utility scripts
reports/              # Validation and test reports
tests/                # Automated tests
```

Review the relevant documentation before using playbooks, detection rules, or lab materials.

### 4. Install Python

The project requires Python 3.13 or later.

Check the installed version:

```python
python --version
```

or:

```python
python3 --version
```

Install Python 3.13+ if the required version is not available.

### 5. Install Dependencies

Create a virtual environment:

```python
python -m venv .venv
```

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the project dependencies:

```bash
pip install -r requirements.txt
```

Install the project development dependencies:

```bash
pip install -r requirements-dev.txt
```

### 6. Run the Test Suite

Run the automated tests before making changes:

```python
pytest -m pytest -v
```

Alternatively, use the Makefile target:

```bash
make test
```

The test command uses the project's configured pytest options, including coverage reporting.

Use the test results to identify validation, metadata, schema, detection-rule, or playbook issues before contributing changes.

## Code & Rule Quality Guidelines

### General Guidelines

- Keep code clean, readable, and well‑commented
- Follow Python best practices (PEP8 recommended)
- Use meaningful filenames and commit messages
- Avoid breaking existing functionality

### Detection Rules

- Include MITRE ATT&CK technique IDs
- Add clear descriptions and references
- Test rules on sample logs if possible
- Follow Sigma/YARA/Suricata syntax standards

### Documentation

- Include examples, screenshots, or logs when helpful
- Keep formatting consistent

## Pull Request Process

### 1. PR Submission

- Ensure your branch is up to date with `main`
- Submit a PR with a clear title and description
- Link the related issue (required)

### 2. Automated Checks

- All CI/CD checks must pass before manual review

### 3. Code Review

- One or more maintainers will review your PR
- Feedback will be provided for any necessary changes
- Reviewers may request additional tests or documentation

### 4. Changes & Approval

- Requested changes (if any) must be completed
- Re-request review after making changes
- Once approved by maintainers, PR will be merged

### 5. Merge

- PRs are merged using "Squash and merge" strategy
- Commit message follows Conventional Commits format

## CI/CD Requirements

All pull requests **must pass the following CI/CD checks** before merging:

### Tests

```bash
# All tests must pass
python -m pytest -v
```

### Code Quality

```bash
# Code formatting check
black --check .

# Linting checks
flake8 .

# Import sorting
isort --check-only .

# Type checking (recommended)
mypy src/
```

### Detection Rule Tests

```bash
# Sigma rules
python -m scripts.run_sigma_tests

# YARA rules
python -m scripts.run_yara_tests

# Suricata rules
python -m scripts.run_suricata_tests
```

## Code of Conduct

By contributing, you agree to follow the project’s [Code of Conduct](CODE_OF_CONDUCT.md).
Respectful and professional communication is expected at all times.

## License

By submitting a contribution, you agree that your work will be licensed under the project’s license:

For full license details, see [LICENSE](LICENSE).

## Thank You

Your contributions help improve this project and support the cybersecurity community.
We appreciate your time, effort, and expertise.
