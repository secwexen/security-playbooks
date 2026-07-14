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

### 1. Fork the repository

```bash
git clone https://github.com/secwexen/security-playbooks.git
cd security-playbooks
```

### 2. Create a new branch from `main`

```bash
git checkout -b feature/your-feature-name
```

### 3. Set up a local development environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

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

1. Ensure your branch is up to date with `main`
2. Submit a PR with a clear title and description
3. Link the related issue (required)
4. The maintainer will review your PR
5. Requested changes (if any) must be completed
6. Once approved, your PR will be merged

## Code of Conduct

By contributing, you agree to follow the project’s [Code of Conduct](CODE_OF_CONDUCT.md).  
Respectful and professional communication is expected at all times.

## License

By submitting a contribution, you agree that your work will be licensed under the project’s license:

For full license details, see [LICENSE](LICENSE).

## Thank You

Your contributions help improve this project and support the cybersecurity community.  
We appreciate your time, effort, and expertise.
