# Support

Thank you for your interest in the **Security Playbooks** project.

This document explains how to get help, report issues, and request improvements.

## Where to Get Help

### GitHub Issues

Use the **Issues** tab for:

- Bug reports  
- Documentation problems  
- Broken links or missing files  
- Incorrect detection rules (Sigma, YARA, Suricata)  
- Scenario or lab errors  
- Feature requests  
- General questions about repository usage  

Create an issue here: [Issues](https://github.com/secwexen/security-playbooks/issues)

Please include:

- Clear description of the problem  
- Steps to reproduce  
- Logs, screenshots, or error messages  
- Environment details (OS, Python version, tools used)

### GitHub Discussions

Join community discussions for general questions and knowledge sharing:

- [GitHub Discussions](https://github.com/secwexen/security-playbooks/discussions)

## Security & Vulnerability Reports

If you discover a **security issue**, do **NOT** open a public GitHub issue.

Instead, follow the instructions in:

- Open a [Private GitHub Security Advisory](https://github.com/secwexen/security-playbooks/security/advisories/new)

This ensures responsible disclosure and safe handling.

## Issue Tracking & Status

All issues are tracked using GitHub's native issue system and organized with labels for easy categorization:

- **Labels**: `bug`, `enhancement`, `documentation`, `help-wanted`, `good-first-issue`
- **Milestones**: Issues are assigned to project milestones for release planning
- **Projects**: Use the [Project Board](https://github.com/secwexen/security-playbooks/projects) to track progress

You can view the status of your issue and track its progress through the project board.

## Response Commitments

- **General Issues**: We aim to respond within 24 business hours.  
- **Critical Bugs**: Security or production-impacting bugs are prioritized and reviewed immediately.  
- **Community Contributions**: Pull requests are reviewed within 3 business days.

## Frequently Asked Questions (FAQ)

### How long does it take to fix a reported bug?

Bug fix timelines depend on severity:

- **Critical**: 24-48 hours
- **High**: 3-7 days
- **Medium**: 1-2 weeks
- **Low**: As resources allow

### Can I contribute detection rules?

Yes! We welcome contributions. Please see [CONTRIBUTING](CONTRIBUTING.md) for guidelines.

### Which Python versions are supported?

Currently, we support **Python 3.11+**. See [CONTRIBUTING](CONTRIBUTING.md) for setup instructions.

### How do I test my changes locally?

Follow the setup instructions in [CONTRIBUTING](CONTRIBUTING.md). Use `pytest` to run the automated test suite:

```bash
python -m pytest -v
```

### Where can I find examples of detection rules?

Check the [Detection Rules](detection-rules/) directory for Sigma, YARA, and Suricata rule examples.

### Is this project suitable for production use?

This project is designed primarily for **educational, testing, and lab environments**. Review the [Security Policy](SECURITY.md) for best practices.

### How do I report a bug responsibly?

1. Check existing issues to avoid duplicates
2. Provide clear steps to reproduce
3. Include relevant logs, error messages, and environment details
4. For security issues, use [Private Security Advisories](https://github.com/secwexen/security-playbooks/security/advisories/new)

## Contributing

If you want to contribute:

- New detection rules  
- New MITRE ATT&CK scenarios  
- Lab improvements  
- Documentation updates  

Please read:

- [CONTRIBUTING](CONTRIBUTING.md)  
- [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md)

Pull requests are welcome.

## Thank You

Your feedback helps improve the project and supports the cybersecurity community.  
We appreciate your interest and contributions!
