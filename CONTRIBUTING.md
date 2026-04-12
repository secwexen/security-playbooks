# Contributing to This Project

Thank you for your interest in contributing to this project!  
We welcome high‑quality contributions that improve the functionality, documentation, detection rules, scenarios, and overall quality of the repository.

This document explains the contribution process, guidelines, and expectations.

## Contribution Types Accepted

You may contribute in several ways:

### Code Contributions

- Python scripts  
- Detection engineering logic  
- Automation improvements  
- Lab enhancements  

### Detection Rules

- Sigma rules  
- YARA rules  
- Suricata rules  
- MITRE ATT&CK mappings  

### Documentation

- Playbook improvements  
- Lab walkthroughs  
- Threat‑hunting guides  
- Architecture explanations  

### Issues & Suggestions

- Bug reports  
- Feature requests  
- Scenario ideas  
- Detection improvements  

## Before You Start

### 1. **Open an Issue First**

Before submitting a Pull Request, please open an issue describing:
- What you want to add or fix  
- Why it is needed  
- How you plan to implement it  

This helps maintain project structure and prevents duplicate work.

### 2. **Fork the Repository**

Create your own fork and work on a dedicated branch:
```
feature/my-new-feature
fix/bug-description
rule/sigma-rule-name
```

### 3. **Follow the Project Structure**

Please keep files in their correct directories:
```
detection-rules/
scenarios/
labs/
docs/
tools/
examples/
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

> [!NOTE]
> Large or complex PRs may require additional review time.

## Code of Conduct

By contributing, you agree to follow the project’s **Code of Conduct**.  
Respectful and professional communication is expected at all times.

## License

By submitting a contribution, you agree that your work will be licensed under the project’s license:
 
- **Security‑Playbooks:** [MIT License](https://github.com/secwexen/security-playbooks/blob/main/LICENSE)  

## Thank You

Your contributions help improve this project and support the cybersecurity community.  
We appreciate your time, effort, and expertise.
